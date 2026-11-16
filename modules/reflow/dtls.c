/*
* Wire
* Copyright (C) 2016 Wire Swiss GmbH
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <re.h>
#include <rew.h>
#include "avs_log.h"
#include "avs_cert.h"
#include "avs_uuid.h"
#include "avs_zapi.h"
#include "avs_service.h"
#include "priv_reflow.h"


int dtls_print_sha256_fingerprint(struct re_printf *pf, const struct tls *tls)
{
	uint8_t md[32];
	unsigned int i;
	int err = 0;

	if (!tls)
		return EINVAL;

	err = tls_fingerprint(tls, TLS_FINGERPRINT_SHA256, md, sizeof(md));
	if (err)
		return err;

	for (i=0; i<sizeof(md); i++) {
		err |= re_hprintf(pf, "%s%02X", i==0 ? "" : ":", md[i]);
	}

	return err;
}



static const char *cipherv[] = {

	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES256-GCM-SHA384",

};


/* Groups that DTLS 1.2 can use. BoringSSL offers the post-quantum
 * groups (X25519MLKEM768, MLKEM1024, ...) in DTLS 1.3 only. */
static const struct {
	const char *name;
	uint16_t id;
} v12_groupv[] = {
	{"P-256",      SSL_GROUP_SECP256R1},
	{"prime256v1", SSL_GROUP_SECP256R1},
	{"P-384",      SSL_GROUP_SECP384R1},
	{"secp384r1",  SSL_GROUP_SECP384R1},
	{"P-521",      SSL_GROUP_SECP521R1},
	{"secp521r1",  SSL_GROUP_SECP521R1},
	{"X25519",     SSL_GROUP_X25519},
	{"x25519",     SSL_GROUP_X25519},
};

/* A set of DTLS 1.2 groups: bit n is the group with ID n */
#define V12_GROUP_BIT(id) ((id) > 0 && (id) < 32 ? (uint32_t)1 << (id) : 0)

/* ex_data of the DTLS context: the DTLS 1.2 groups of -g.
 * ex_data of a connection: set if the client offers none of them. */
static int ctx_exidx = -1;
static int conn_exidx = -1;


static bool is_space(char c)
{
	return c == ' ' || c == '\t';
}


/* Returns the ID of a group that DTLS 1.2 can use, or 0 */
static uint16_t v12_group_id(const struct pl *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(v12_groupv); i++) {
		if (0 == pl_strcmp(name, v12_groupv[i].name))
			return v12_groupv[i].id;
	}

	return 0;
}


/* Converts a comma separated group list to the colon separated form
 * used by TLS, checking each name against the TLS library. Returns the
 * groups that DTLS 1.2 can use in v12. */
static int set_groups(struct tls *dtls, const char *groups, uint32_t *v12)
{
	const char *p = groups;
	struct mbuf *mb;
	int err = 0;

	*v12 = 0;

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	for (;;) {
		const char *end = strchr(p, ',');
		struct pl name;
		char *str;

		name.p = p;
		name.l = end ? (size_t)(end - p) : strlen(p);
		while (name.l && is_space(name.p[0])) {
			++name.p;
			--name.l;
		}
		while (name.l && is_space(name.p[name.l - 1]))
			--name.l;

		if (!name.l || pl_strchr(&name, ':')) {
			warning("reflow: invalid DTLS group list (-g): '%s'\n",
				groups);
			err = EINVAL;
			goto out;
		}

		err = pl_strdup(&str, &name);
		if (err)
			goto out;

		err = tls_set_groups(dtls, str);
		mem_deref(str);
		if (err) {
			warning("reflow: unsupported DTLS group (-g): '%r'\n",
				&name);
			err = EINVAL;
			goto out;
		}

		*v12 |= V12_GROUP_BIT(v12_group_id(&name));

		err = mbuf_printf(mb, "%s%r", mb->end ? ":" : "", &name);
		if (err)
			goto out;

		if (!end)
			break;
		p = end + 1;
	}

	err = mbuf_write_u8(mb, '\0');
	if (err)
		goto out;

	err = tls_set_groups(dtls, (const char *)mb->buf);
	if (err) {
		warning("reflow: invalid DTLS group list (-g): '%s'\n", groups);
		err = EINVAL;
		goto out;
	}

	info("reflow: DTLS groups %s\n", mb->buf);

 out:
	mem_deref(mb);

	return err;
}


/* Notes on the connection if the client offers none of the DTLS 1.2
 * groups of sftd. Without one, a DTLS 1.2 handshake fails with
 * SSL_R_NO_SHARED_CIPHER, because all cipher suites of sftd are ECDHE. */
static enum ssl_select_cert_result_t select_cert_handler(
	const SSL_CLIENT_HELLO *ch)
{
	void *v12 = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ch->ssl), ctx_exidx);
	const uint32_t groups = (uint32_t)(uintptr_t)v12;
	const uint8_t *p = NULL;
	size_t len = 0, i;
	bool shared = false;

	if (SSL_early_callback_ctx_extension_get(ch,
			TLSEXT_TYPE_supported_groups, &p, &len) && len >= 2) {

		/* a 2-byte length, then 2 bytes per group */
		len = min(len, 2 + (((size_t)p[0] << 8) | p[1]));
		for (i = 2; i + 1 < len; i += 2) {
			const uint16_t id = ((uint16_t)p[i] << 8) | p[i + 1];

			if (groups & V12_GROUP_BIT(id))
				shared = true;
		}
	}

	(void)SSL_set_ex_data(ch->ssl, conn_exidx, shared ? NULL : ch->ssl);

	return ssl_select_cert_success;
}


/* Logs and counts the handshakes that fail because the peer has no key
 * exchange group or no DTLS version in common with sftd. It runs when
 * sftd sends a fatal alert; the error queue then still holds the reason.
 * Alerts that sftd receives are not counted: the peer decided those. */
static void info_handler(const SSL *ssl, int where, int value)
{
	enum avs_service_dtls_reject reason;
	uint32_t e;

	if ((where & SSL_CB_WRITE_ALERT) != SSL_CB_WRITE_ALERT ||
	    (value >> 8) != SSL3_AL_FATAL)
		return;

	e = ERR_peek_last_error();
	if (ERR_GET_LIB(e) != ERR_LIB_SSL)
		return;

	switch (ERR_GET_REASON(e)) {

	case SSL_R_NO_SHARED_CIPHER:
		/* In DTLS 1.3, or with a group in common, the cipher
		 * suites do not match */
		if (SSL_version(ssl) != DTLS1_2_VERSION ||
		    !SSL_get_ex_data(ssl, conn_exidx))
			return;
		/* fall through */

	case SSL_R_NO_SHARED_GROUP:
		warning("reflow: DTLS handshake rejected: no key exchange"
			" group in common with the peer (see -g)\n");
		reason = AVS_SERVICE_DTLS_REJECT_GROUP;
		break;

	case SSL_R_UNSUPPORTED_PROTOCOL:
		warning("reflow: DTLS handshake rejected: no DTLS version"
			" in common with the peer (see -D and -g)\n");
		reason = AVS_SERVICE_DTLS_REJECT_VERSION;
		break;

	default:
		return;
	}

	avs_service_dtls_rejected(reason);
}


int reflow_init_dtls(struct tls **dtlsp, bool dtls13_only,
		     const char *groups)
{
	struct tls *dtls = NULL;
	SSL_CTX *ctx;
	uint32_t v12;
	int err;

	if (!dtlsp)
		return EINVAL;

	if (ctx_exidx < 0)
		ctx_exidx = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	if (conn_exidx < 0)
		conn_exidx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	if (ctx_exidx < 0 || conn_exidx < 0)
		return ENOMEM;

	if (!groups)
		groups = DEFAULT_DTLS_GROUPS;

	err = tls_alloc(&dtls, TLS_METHOD_DTLS, NULL, NULL);
	if (err) {
		warning("reflow: failed to create DTLS context (%m)\n",
			err);
		goto out;
	}

	err = set_groups(dtls, groups, &v12);
	if (err)
		goto out;

	ctx = tls_openssl_context(dtls);

	/* The group is picked in the order above, not in the client's */
	SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

	if (!SSL_CTX_set_ex_data(ctx, ctx_exidx, (void *)(uintptr_t)v12)) {
		err = ENOMEM;
		goto out;
	}
	SSL_CTX_set_select_certificate_cb(ctx, select_cert_handler);
	SSL_CTX_set_info_callback(ctx, info_handler);

	if (!dtls13_only && !v12) {
		warning("reflow: no DTLS group in '%s' works with DTLS 1.2,"
			" accepting DTLS 1.3 only\n", groups);
		dtls13_only = true;
	}

	err = tls_set_min_proto_version(dtls, dtls13_only ? DTLS1_3_VERSION
							  : DTLS1_2_VERSION);
	if (!err)
		err = tls_set_max_proto_version(dtls, DTLS1_3_VERSION);
	if (err) {
		warning("reflow: failed to set DTLS versions (%m)\n", err);
		goto out;
	}
	info("reflow: DTLS versions %s\n",
	     dtls13_only ? "1.3" : "1.2, 1.3");

	err = cert_enable_ecdh(dtls);
	if (err)
		goto out;

	info("msystem: setting %zu ciphers for DTLS\n", ARRAY_SIZE(cipherv));
	err = tls_set_ciphers(dtls, cipherv, ARRAY_SIZE(cipherv));
	if (err)
		goto out;

	info("msystem: generating ECDSA certificate\n");
	err = cert_tls_set_selfsigned_ecdsa(dtls, "prime256v1");
	if (err) {
		warning("msystem: failed to generate ECDSA"
			" certificate"
			" (%m)\n", err);
		goto out;
	}

	tls_set_verify_client(dtls);

	err = tls_set_srtp(dtls,
			   "SRTP_AEAD_AES_256_GCM:"
			   "SRTP_AEAD_AES_128_GCM");
	if (err) {
		warning("flowmgr: failed to enable SRTP profile (%m)\n",
			err);
		goto out;
	}

	*dtlsp = dtls;

 out:
	if (err)
		mem_deref(dtls);

	return err;
}


/* Creates the DTLS socket of a flow, which sends datagrams of at most
 * DTLS_MTU bytes */
int reflow_dtls_listen(struct dtls_sock **sockp, const struct sa *laddr,
		       dtls_conn_h *connh, void *arg)
{
	int err;

	err = dtls_listen(sockp, laddr, NULL, 2, LAYER_DTLS, connh, arg);
	if (err)
		return err;

	dtls_set_mtu(*sockp, DTLS_MTU);

	return 0;
}


int dtls_print_session(struct re_printf *pf, const struct tls_conn *tc)
{
	const char *name;
	int version = 0;
	uint16_t group = 0;
	int err;

	(void)tls_conn_version(tc, &version);
	err = re_hprintf(pf, "DTLS version=0x%04x", version);

	if (tls_conn_group(tc, &group))
		return err | re_hprintf(pf, " group=unknown");

	name = SSL_get_group_name(group);

	return err | re_hprintf(pf, " group=0x%04x (%s)", group,
				name ? name : "?");
}
