/*
 * Wire
 * Copyright (C) 2026 Wire Swiss GmbH
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

/* DTLS handshakes between the sftd DTLS context and libre peers. */

#include <string.h>
#include <openssl/ssl.h>
#include <re.h>
#include <avs_log.h>
#include <avs_cert.h>
#include <avs_service.h>
#include "priv_reflow.h"

#define V12 DTLS1_2_VERSION
#define V13 DTLS1_3_VERSION

/* The largest datagram sftd may send: it fits a 1280 byte IPv6 path
 * and a 1500 byte path with TURN framing */
#define MAX_DATAGRAM 1200

struct dtls_case {
	const char *name;
	bool dtls13_only;         /* -D */
	const char *groups;       /* -g, NULL: sftd default */
	bool sft_is_client;       /* sftd connects, as towards another SFT */
	int peer_version;         /* highest DTLS version of the peer */
	const char *peer_groups;
	int version;              /* 0: the handshake fails */
	uint16_t group;
	bool peer_cm_only;        /* the peer offers SRTP_AES128_CM_SHA1_80 only */
};

static const struct dtls_case cases[] = {
	{.name = "default: DTLS 1.2 client",
	 .peer_version = V12, .peer_groups = "X25519:P-256",
	 .version = V12, .group = SSL_GROUP_X25519},
	{.name = "default: DTLS 1.3 client",
	 .peer_version = V13, .peer_groups = "X25519MLKEM768:X25519:P-256",
	 .version = V13, .group = SSL_GROUP_X25519_MLKEM768},
	/* the group order of sftd wins */
	{.name = "default: client preferring X25519",
	 .peer_version = V13, .peer_groups = "X25519:P-256:X25519MLKEM768",
	 .version = V13, .group = SSL_GROUP_X25519_MLKEM768},
	{.name = "default: DTLS 1.3 client with MLKEM1024 only",
	 .peer_version = V13, .peer_groups = "MLKEM1024",
	 .version = V13, .group = SSL_GROUP_MLKEM1024},
	{.name = "-D: DTLS 1.2 client is rejected", .dtls13_only = true,
	 .peer_version = V12, .peer_groups = "X25519:P-256"},
	{.name = "-D: DTLS 1.3 client is accepted", .dtls13_only = true,
	 .peer_version = V13, .peer_groups = "X25519MLKEM768:X25519:P-256",
	 .version = V13, .group = SSL_GROUP_X25519_MLKEM768},
	{.name = "-g P-256: client preferring other groups", .groups = "P-256",
	 .peer_version = V13, .peer_groups = "X25519MLKEM768:X25519:P-256",
	 .version = V13, .group = SSL_GROUP_SECP256R1},
	{.name = "-g X25519MLKEM768: client without it is rejected",
	 .groups = "X25519MLKEM768",
	 .peer_version = V13, .peer_groups = "X25519:P-256"},
	/* an older SFT supports DTLS 1.2 only */
	{.name = "SFT link: DTLS 1.2 SFT", .sft_is_client = true,
	 .peer_version = V12, .peer_groups = "X25519:P-256",
	 .version = V12, .group = SSL_GROUP_X25519},
	/* a current SFT, with the groups of DEFAULT_DTLS_GROUPS */
	{.name = "SFT link: DTLS 1.3 SFT", .sft_is_client = true,
	 .peer_version = V13,
	 .peer_groups = "X25519MLKEM768:X25519:P-256:MLKEM1024",
	 .version = V13, .group = SSL_GROUP_X25519_MLKEM768},
	/* reflow.c fails such a flow; that is not tested here */
	{.name = "client offering SRTP_AES128_CM_SHA1_80 only gets no SRTP "
		 "profile",
	 .peer_version = V12, .peer_groups = "X25519:P-256",
	 .version = V12, .group = SSL_GROUP_X25519, .peer_cm_only = true},
};

struct test {
	struct tls *srv_tls;
	struct dtls_sock *srv_sock;
	struct dtls_sock *cli_sock;
	struct tls_conn *srv_conn;
	struct tls_conn *cli_conn;
	struct udp_helper *uh;
	size_t sft_datagram_max;  /* largest datagram sent by sftd */
	bool srv_estab;
	bool cli_estab;
	int err;
	bool timeout;
	struct tmr tmr;
};

static void srv_estab_handler(void *arg)
{
	struct test *t = arg;

	t->srv_estab = true;
	if (t->cli_estab)
		re_cancel();
}

static void cli_estab_handler(void *arg)
{
	struct test *t = arg;

	t->cli_estab = true;
	if (t->srv_estab)
		re_cancel();
}

static void close_handler(int err, void *arg)
{
	struct test *t = arg;

	t->err = err ? err : -1;
	re_cancel();
}

static void conn_handler(const struct sa *peer, void *arg)
{
	struct test *t = arg;
	(void)peer;

	if (t->srv_conn)
		return;

	t->err = dtls_accept(&t->srv_conn, t->srv_tls, t->srv_sock,
			     srv_estab_handler, NULL, close_handler, t);
}

static bool send_handler(int *err, struct sa *dst, struct mbuf *mb,
			 void *arg)
{
	struct test *t = arg;
	(void)err;
	(void)dst;

	if (mbuf_get_left(mb) > t->sft_datagram_max)
		t->sft_datagram_max = mbuf_get_left(mb);

	return false;
}

static void timeout_handler(void *arg)
{
	struct test *t = arg;

	t->timeout = true;
	re_cancel();
}

/* A libre DTLS peer: a WebRTC client, or another SFT */
static int peer_tls(struct tls **tlsp, const struct dtls_case *tc)
{
	struct tls *tls = NULL;
	int err;

	err = tls_alloc(&tls, TLS_METHOD_DTLS, NULL, NULL);
	if (!err)
		err = tls_set_min_proto_version(tls, V12);
	if (!err)
		err = tls_set_max_proto_version(tls, tc->peer_version);
	if (!err)
		err = tls_set_groups(tls, tc->peer_groups);
	if (!err)
		err = cert_tls_set_selfsigned_ecdsa(tls, "prime256v1");
	if (!err)
		err = tls_set_srtp(tls, tc->peer_cm_only ?
				   "SRTP_AES128_CM_SHA1_80" :
				   "SRTP_AES128_CM_SHA1_80:"
				   "SRTP_AEAD_AES_256_GCM");

	if (err)
		mem_deref(tls);
	else
		*tlsp = tls;

	return err;
}

static bool check_conn(const struct tls_conn *conn,
		       const struct dtls_case *tc)
{
	int version = 0;
	uint16_t group = 0;
	enum srtp_suite suite;
	uint8_t key[64];
	bool srtp;

	srtp = !tls_srtp_keyinfo(conn, &suite, key, sizeof(key),
				 key, sizeof(key));
	if (tc->peer_cm_only ? srtp : !srtp || suite != SRTP_AES_256_GCM) {
		re_printf("    SRTP profile %s, expected %s\n",
			  srtp ? srtp_suite_name(suite) : "none",
			  tc->peer_cm_only ? "none" :
			  srtp_suite_name(SRTP_AES_256_GCM));
		return false;
	}

	if (tls_conn_version(conn, &version) ||
	    tls_conn_group(conn, &group) ||
	    version != tc->version || group != tc->group) {
		re_printf("    version=0x%04x group=0x%04x, expected "
			  "0x%04x 0x%04x\n", version, group,
			  tc->version, tc->group);
		return false;
	}

	return true;
}

static bool run_case(const struct dtls_case *tc)
{
	struct test t;
	struct tls *sft_tls = NULL, *peer = NULL;
	struct dtls_sock **sft_sock;
	struct sa laddr, srv_addr;
	bool ok = false;
	int err;

	memset(&t, 0, sizeof(t));
	sa_set_str(&laddr, "127.0.0.1", 0);
	sft_sock = tc->sft_is_client ? &t.cli_sock : &t.srv_sock;

	err = reflow_init_dtls(&sft_tls, tc->dtls13_only, tc->groups);
	if (!err)
		err = peer_tls(&peer, tc);
	if (err)
		goto out;

	t.srv_tls = tc->sft_is_client ? peer : sft_tls;

	/* the socket of sftd as reflow creates it, with its MTU */
	err = reflow_dtls_listen(sft_sock, &laddr,
				 tc->sft_is_client ? NULL : conn_handler, &t);
	if (!err) {
		err = dtls_listen(tc->sft_is_client ? &t.srv_sock : &t.cli_sock,
				  &laddr, NULL, 2, 2,
				  tc->sft_is_client ? conn_handler : NULL, &t);
	}
	if (!err)
		err = udp_local_get(dtls_udp_sock(t.srv_sock), &srv_addr);
	if (!err)
		err = udp_register_helper(&t.uh, dtls_udp_sock(*sft_sock), 1,
					  send_handler, NULL, &t);
	if (!err)
		err = dtls_connect(&t.cli_conn,
				   tc->sft_is_client ? sft_tls : peer,
				   t.cli_sock, &srv_addr, cli_estab_handler, NULL,
				   close_handler, &t);
	if (err)
		goto out;

	tmr_start(&t.tmr, 10000, timeout_handler, &t);
	re_main(NULL);
	tmr_cancel(&t.tmr);

	if (tc->version) {
		ok = t.srv_estab && t.cli_estab && !t.timeout &&
			check_conn(t.srv_conn, tc) &&
			check_conn(t.cli_conn, tc);
	}
	else {
		ok = !t.srv_estab && !t.cli_estab && t.err && !t.timeout;
	}
	if (!ok) {
		re_printf("    estab: server=%d client=%d, error: %m, "
			  "timeout: %d\n", t.srv_estab, t.cli_estab, t.err,
			  t.timeout);
	}

	if (t.sft_datagram_max > MAX_DATAGRAM) {
		re_printf("    sftd sent a %zu byte datagram\n",
			  t.sft_datagram_max);
		ok = false;
	}

 out:
	if (err) {
		re_printf("    setup failed (%m)\n", err);
		ok = false;
	}
	mem_deref(t.cli_conn);
	mem_deref(t.srv_conn);
	mem_deref(t.uh);
	mem_deref(t.cli_sock);
	mem_deref(t.srv_sock);
	mem_deref(peer);
	mem_deref(sft_tls);

	re_printf("[ %s ] %s\n", ok ? " OK " : "FAIL", tc->name);

	return ok;
}

int main(void)
{
	unsigned failed = 0;
	size_t i;
	int err;

	err = libre_init();
	if (err)
		return err;

	avs_log_set_min_level(LOG_LEVEL_WARN);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		if (!run_case(&cases[i]))
			++failed;
	}

	libre_close();

	re_printf("%u of %zu tests failed\n", failed, ARRAY_SIZE(cases));

	return failed ? 1 : 0;
}
