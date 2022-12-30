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

#include <ctype.h>
#include <string.h>
#include <re.h>
#include <rew.h>
#include "avs_log.h"
#include "avs_zapi.h"
#include "avs_network.h"
#include "avs_service.h"
#include "avs_service_turn.h"

enum {
	TURNPING_INTERVAL = 15,  /* seconds, must be less than 29 */
};

struct lookup_entry {
	struct turn_conn *tc;
	struct zapi_ice_server turn;
	char *host;
	int port;
	int proto;
	bool secure;
	uint64_t ts;
	
	struct le le;
};


/* NOTE: incoming data is bridged from TURN/TCP --> UDP-socket */
static void turntcp_recv_data(struct turn_conn *tc,
			      const struct sa *src, struct mbuf *mb)
{
	if (tc->datah)
		tc->datah(tc, src, mb, tc->arg);
}


static void stun_mapped_addr_handler(int err, const struct sa *map, void *arg)
{
	struct turn_conn *conn = arg;
	(void)conn;

	if (err) {
		warning("turnconn(%p): [alloced=%u, turnc=%p, sock=%p]"
			" stun keepalive handler failed (%m)\n",
			conn, conn->turn_allocated, conn->turnc, conn->us_turn,
			err);
		return;
	}

	info("turnconn(%p): STUN mapped address %J\n", conn, map);
}


static void turnc_handler(int err, uint16_t scode, const char *reason,
			  const struct sa *relay_addr,
			  const struct sa *mapped_addr,
			  const struct stun_msg *msg,
			  void *arg)
{
	struct turn_conn *tc = arg;
	struct stun_attr *attr;
	struct stun_attr *chan;
	
	(void)mapped_addr;  /* NOTE: TCP-mapped address unused */

	if (err) {
		warning("turnconn(%p): [allocated=%d] TURN-%s %J"
			" client error (%m)\n",
			tc,
			tc->turn_allocated,
			turnconn_proto_name(tc),
			&tc->turn_srv,
			err);
		goto error;
	}
	if (scode) {
		warning("turnconn(%p): [allocated=%d] TURN-%s %J client error"
			" on method '%s' (%u %s)\n",
			tc,
			tc->turn_allocated,
			turnconn_proto_name(tc),
			&tc->turn_srv,
			stun_method_name(stun_msg_method(msg)),
			scode, reason);

#if 1
		/* XXX: attempt to find reason for some 441 responses */
		if (scode == 441) {
			err = EAUTH;
			warning("turnconn(%p): got 441 on username='%s'\n",
				tc, tc->username);
		}
#endif
		goto error;
	}

	tc->turn_allocated = true;
	tc->ts_turn_resp = tmr_jiffies();

	attr = stun_msg_attr(msg, STUN_ATTR_SOFTWARE);

	info("turnconn(%p): TURN-%s allocation OK in %dms"
	     " (relay=%J, mapped=%J) [%s]\n",
	     tc,
	     turnconn_proto_name(tc),
	     (int)(tc->ts_turn_resp - tc->ts_turn_req),
	     relay_addr, mapped_addr,
	     attr ? attr->v.software : "");

	tc->relay_addr = *relay_addr;
	tc->mapped_addr = *mapped_addr;


	/* Start a STUN keepalive timer from the client to
	   the TURN-server, to make sure that the NAT bindings
	   are kept open.

	   the Request/Response scheme is important, to increase
	   the NAT timeout from around 30 to 180 seconds
	*/
	if (tc->proto == IPPROTO_UDP && !tc->ska) {

		debug("turnconn: enable STUN keepalive to TURN-server "
		      " (sock=%p, layer=%d, srv=%J)\n",
		      tc->us_turn, tc->layer_stun, &tc->turn_srv);

		err = stun_keepalive_alloc(&tc->ska, IPPROTO_UDP,
					   tc->us_turn,
					   tc->layer_stun, &tc->turn_srv, NULL,
					   stun_mapped_addr_handler, tc);
		if (err) {
			warning("turnconn(%p): stun_keepalive_alloc error (%m)\n",
				tc, err);
			goto error;
		}
		stun_keepalive_enable(tc->ska, TURNPING_INTERVAL);
	}

	chan = stun_msg_attr(msg, STUN_ATTR_CHANNEL_NUMBER);
	if (chan) {
		tc->lcid = chan->v.channel_number;
		info("turnconn(%p): local cid: %d\n", tc, tc->lcid);
	}
	
	tc->estabh(tc, relay_addr, mapped_addr, msg, tc->arg);

	return;

 error:
	tc->failed = true;
	tc->errorh(err ? err : EPROTO, tc->arg);
}


static void tmr_delay_handler(void *arg)
{
       struct turn_conn *conn = arg;
       int err = 0;

       if (turnconn_is_one_allocated(conn->le.list)) {
               info("turnconn(%p): one TURN conn already"
		    " -- skipping new allocation\n",
		    conn);

               mem_deref(conn);

               return;
       }

       err = turnc_alloc(&conn->turnc, NULL, IPPROTO_UDP, conn->us_turn,
                         conn->layer_turn, &conn->turn_srv,
                         conn->username, conn->password,
                         TURN_DEFAULT_LIFETIME, turnc_handler, conn);
       if (err) {
               warning("turnconn(%p): turnc_alloc UDP failed (%m)\n",
                       conn, err);
               goto error;
       }

       return;

 error:
       if (conn->errorh)
	       conn->errorh(err ? err : EPROTO, conn->arg);
}


static void tcp_estab(void *arg)
{
	struct turn_conn *tl = arg;
	int err;

	if (tl->tlsc) {
		info("turnconn(%p): TLS established with cipher %s\n",
		     tl, tls_cipher_name(tl->tlsc));
	}

	tl->mb = (struct mbuf *)mem_deref(tl->mb);

	err = turnc_alloc(&tl->turnc, NULL, IPPROTO_TCP,
			  tl->tc, tl->layer_turn,
			  &tl->turn_srv, tl->username, tl->password,
			  TURN_DEFAULT_LIFETIME, turnc_handler, tl);
	if (err) {
		warning("turnconn(%p): turnc_alloc failed (%m)\n", tl, err);
	}
}


static void tcp_recv(struct mbuf *mb, void *arg)
{
	struct turn_conn *tl = arg;
	int err = 0;

	mem_ref(tl);

	if (tl->mb) {
		size_t pos;

		pos = tl->mb->pos;

		tl->mb->pos = tl->mb->end;

		err = mbuf_write_mem(tl->mb, mbuf_buf(mb),
				     mbuf_get_left(mb));
		if (err)
			goto out;

		tl->mb->pos = pos;
	}
	else {
		tl->mb = mem_ref(mb);
	}

	for (;;) {

		size_t len, pos, end;
		struct sa src;
		uint16_t typ;

		if (mbuf_get_left(tl->mb) < 4)
			break;

		typ = ntohs(mbuf_read_u16(tl->mb));
		len = ntohs(mbuf_read_u16(tl->mb));

		if (typ < 0x4000)
			len += STUN_HEADER_SIZE;
		else if (typ < 0x8000)
			len += 4;
		else {
			err = EBADMSG;
			goto out;
		}

		tl->mb->pos -= 4;

		if (mbuf_get_left(tl->mb) < len)
			break;

		pos = tl->mb->pos;
		end = tl->mb->end;

		tl->mb->end = pos + len;

		err = turnc_recv(tl->turnc, &src, tl->mb);
		if (err)
			goto out;

		if (mbuf_get_left(tl->mb))
			turntcp_recv_data(tl, &src, tl->mb);

		/* 4 byte alignment */
		while (len & 0x03)
			++len;

		tl->mb->pos = pos + len;
		tl->mb->end = end;

		if (tl->mb->pos >= tl->mb->end) {
			tl->mb = mem_deref(tl->mb);
			break;
		}
	}

 out:
	mem_deref(tl);
	if (err) {
		warning("turnconn(%p): turn tcp_recv error (%m)\n", tl, err);
		mem_deref(tl);
	}
}


static void tcp_close(int err, void *arg)
{
	struct turn_conn *tc = arg;

	info("turnconn(%p): TURN-%s connection: %J closed (%m)\n",
	     tc, turnconn_proto_name(tc), &tc->turn_srv, err);

	tc->turn_allocated = false;
	tc->turnc = mem_deref(tc->turnc);

	if (tc->errorh)
		tc->errorh(err ? err : EPROTO, tc->arg);
}


static void turnconn_destructor(void *data)
{
	struct turn_conn *tc = data;

	list_unlink(&tc->le);

	tmr_cancel(&tc->tmr_delay);

	mem_deref(tc->uh_app);   /* note: deref before us_app */
	mem_deref(tc->us_app);
	mem_deref(tc->ska);      /* note: deref before socket */
	mem_deref(tc->turnc);    /* note: deref before socket */
	mem_deref(tc->us_turn);
	mem_deref(tc->tlsc);
	mem_deref(tc->tc);
	mem_deref(tc->tls);
	mem_deref(tc->mb);
	mem_deref(tc->username);
	mem_deref(tc->password);
}

static void recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct turn_conn *tc = arg;

	info("tc(%p): recv handler: %zu bytes\n", tc, mbuf_get_left(mb));
}



int turnconn_start(struct turn_conn *tc, struct list *connl,
		   const struct sa *turn_srv, int proto, bool secure,
		   const char *username, const char *password,
		   int af, struct udp_sock *sock,
		   int layer_stun, int layer_turn,
		   turnconn_estab_h *estabh, turnconn_data_h *datah,
		   turnconn_error_h *errorh, void *arg)
{
	struct sa laddr;
	int err = 0;

	if (layer_stun > layer_turn) {
		warning("turnconn(%p): stun layer (%d) higher than turn layer (%d)\n",
			tc, layer_stun, layer_turn);
	}

	/* the first TURN server has short delay */
	if (list_isempty(connl)) {
		tc->delay = 1;
	}
	else {
		tc->delay = 100 + rand_u32() % 100;
	}

	tc->turn_srv = *turn_srv;
	tc->proto = proto;
	tc->secure = secure;
	tc->af = af;
	tc->layer_stun = layer_stun;
	tc->layer_turn = layer_turn;
	tc->estabh = estabh;
	tc->datah = datah;
	tc->errorh = errorh;
	tc->arg = arg;

	tc->username = mem_deref(tc->username);
	err |= str_dup(&tc->username, username);

	tc->password = mem_deref(tc->password);
	err |= str_dup(&tc->password, password);
	if (err)
		goto out;

	switch (proto) {

	case IPPROTO_UDP:

		switch (af) {

		case AF_INET:
			/* Need a common UDP-socket for STUN/TURN traffic */
			sa_set_str(&laddr, "0.0.0.0", 0);
			break;

		case AF_INET6:
			err = net_default_source_addr_get(AF_INET6,
							  &laddr);
			if (err) {
				warning("turnconn(%p): no local AF_INET6"
					" address (%m)\n", tc, err);
				goto out;
			}
			info("turnconn(%p): laddr turn is v6 (%j)\n",
			     tc, &laddr);
			break;

		default:
			warning("turnconn(%p): invalid af in laddr sdp\n", tc);
			err = EAFNOSUPPORT;
			goto out;
		}

		if (sock) {
			struct udp_helper *uh;

			uh = udp_helper_find(sock, layer_turn);
			if (uh) {
				warning("turnconn(%p): udp-socket helper"
					" already registered for layer %d\n",
					tc, layer_turn);
				err = EPROTO;
				goto out;
			}
			tc->us_turn = mem_ref(sock);
		}
		else {
			err = udp_listen(&tc->us_turn, &laddr,
					 recv_handler, tc);
			if (err)
				goto out;

			err = udp_local_get(tc->us_turn, &laddr);
			if (err)
				goto out;

		}

		tmr_start(&tc->tmr_delay, tc->delay, tmr_delay_handler, tc);
		break;

	case IPPROTO_TCP:
		err = tcp_connect(&tc->tc, turn_srv, tcp_estab,
				  tcp_recv, tcp_close, tc);
		if (err) {
			warning("turnconn(%p): could not connect to %J (%m)\n",
				tc, turn_srv, err);
			goto out;
		}

		if (secure) {
			// XXX: NOTE, this one can be shared globally
			err = tls_alloc(&tc->tls, TLS_METHOD_SSLV23,
					NULL, NULL);
			if (err)
				goto out;

			err = tls_start_tcp(&tc->tlsc, tc->tls, tc->tc, 0);
			if (err) {
				warning("turnconn(%p): failed to start TLS"
					" (%m)\n", tc, err);
				goto out;
			}
		}
		break;

	default:
		err = EPROTONOSUPPORT;
		goto out;
	}

	tc->ts_turn_req = tmr_jiffies();

	debug("turnconn: alloc: TURN-%s srv=%J (%s/%s)\n",
	      turnconn_proto_name(tc), turn_srv, username, password);

	list_append(connl, &tc->le, tc);

 out:

	return err;
}


static void turnc_perm_handler(void *arg)
{
	struct turn_conn *conn = arg;

	info("turnconn(%p): <%J>: TURN permission added OK\n",
	     conn, &conn->turn_srv);

	++conn->n_permh;
}


int turnconn_add_permission(struct turn_conn *conn, const struct sa *peer)
{
	if (!conn || !peer)
		return EINVAL;

	info("turnconn(%p): <%J> adding TURN permission to remote address %j\n",
	     conn, &conn->turn_srv, peer);

	if (sa_af(peer) != AF_INET) {
		warning("turnconn(%p): add_permission: must be IPv4 address\n", conn);
		return EAFNOSUPPORT;
	}

	if (!conn->turn_allocated) {
		warning("turnconn(%p): not allocated, cannot add permission\n", conn);
		return EINTR;
	}

	return turnc_add_perm(conn->turnc, peer, turnc_perm_handler, conn);
}


static void turnc_chan_handler(void *arg)
{
	struct turn_conn *conn = arg;

	info("turnconn(%p): <%J> TURN channel added OK\n", conn, &conn->turn_srv);
}


int turnconn_add_channel(struct turn_conn *conn, const struct sa *peer)
{
	if (!conn || !peer)
		return EINVAL;

	info("turnconn(%p): <%J> adding TURN channel to remote address %J\n",
	     conn, &conn->turn_srv, peer);

	if (sa_af(peer) != AF_INET) {
		warning("turnconn(%p): add_channel: must be IPv4 address\n", conn);
		return EAFNOSUPPORT;
	}

	if (!conn->turn_allocated) {
		warning("turnconn(%p): not allocated, cannot add channel\n", conn);
		return EINTR;
	}

	return turnc_add_chan(conn->turnc, peer,
			      turnc_chan_handler, conn);
}


struct turn_conn *turnconn_find_allocated(const struct list *turnconnl,
					  int proto)
{
	struct le *le;

	for (le = list_head(turnconnl); le; le = le->next) {
		struct turn_conn *conn = le->data;

		if (conn->proto == proto && conn->turn_allocated)
			return conn;
	}

	return NULL;
}


bool turnconn_is_one_allocated(const struct list *turnconnl)
{
	struct le *le;

	for (le = list_head(turnconnl); le; le = le->next) {
		struct turn_conn *conn = le->data;

		if (conn->turn_allocated)
			return true;
	}

	return false;
}


bool turnconn_are_all_allocated(const struct list *turnconnl)
{
	struct le *le;

	if (list_isempty(turnconnl))
		return false;

	for (le = list_head(turnconnl); le; le = le->next) {
		struct turn_conn *conn = le->data;

		if (!conn->turn_allocated)
			return false;
	}

	return true;
}


bool turnconn_are_all_failed(const struct list *turnconnl)
{
	struct le *le;

	if (list_isempty(turnconnl))
		return false;

	for (le = list_head(turnconnl); le; le = le->next) {
		struct turn_conn *conn = le->data;

		if (!conn->failed)
			return false;
	}

	return true;
}


const char *turnconn_proto_name(const struct turn_conn *conn)
{
	if (!conn)
		return "???";

	if (conn->secure)
		return "TLS";
	else
		return net_proto2name(conn->proto);
}


int turnconn_debug(struct re_printf *pf, const struct turn_conn *conn)
{
	int32_t alloc_time;
	int err = 0;

	if (!conn)
		return 0;

	if (conn->ts_turn_req && conn->ts_turn_resp) {
		alloc_time = (int32_t)(conn->ts_turn_resp - conn->ts_turn_req);
	}
	else {
		alloc_time = -1;
	}

	err |= re_hprintf(pf,
			  "...[%c] delay=%3ums af=%s  proto=%s srv=%J(%J/%J)"
			  "  turnc=<%p>  (%d ms)\n",
			  conn->turn_allocated ? 'A' : ' ',
			  conn->delay,
			  net_af2name(conn->af),
			  turnconn_proto_name(conn),
			  &conn->turn_srv,
			  &conn->relay_addr,
			  &conn->mapped_addr,
			  conn->turnc,
			  alloc_time);

#if 0
	if (conn->turnc) {

		err |= turnc_debug(pf, conn->turnc);
	}
#endif

	return err;
}

int stun_uri_encode(struct re_printf *pf, const struct stun_uri *uri)
{
	const char *scheme;
	uint16_t dport;
	int err;

	if (!uri)
		return 0;

	dport = uri->secure ? 5349 : 3478;

	switch (uri->scheme) {

	case STUN_SCHEME_STUN:
		scheme = "stun";
		break;

	case STUN_SCHEME_TURN:
		scheme = "turn";
		break;

	default:
		return EINVAL;
	}

	err = re_hprintf(pf, "%s%s:%j", scheme, uri->secure ? "s" : "",
			 &uri->addr);
	if (err)
		return err;

	if (sa_port(&uri->addr) != dport) {
		err |= re_hprintf(pf, ":%u", sa_port(&uri->addr));
	}

	if (uri->proto == IPPROTO_TCP)
		err |= re_hprintf(pf, "?transport=tcp");

	return err;
}


int stun_uri_decode(struct stun_uri *stun_uri, const char *str)
{
	struct uri uri;
	struct pl pl_uri;
	uint16_t port;
	struct pl transp;
	int err;

	if (!stun_uri || !str)
		return EINVAL;

	pl_set_str(&pl_uri, str);

	err = uri_decode(&uri, &pl_uri);
	if (err) {
		warning("cannot decode URI (%r)\n", &pl_uri);
		return err;
	}

	if (0 == pl_strcasecmp(&uri.scheme, "stun") ||
	    0 == pl_strcasecmp(&uri.scheme, "stuns")) {

		stun_uri->scheme = STUN_SCHEME_STUN;
	}
	else if (0 == pl_strcasecmp(&uri.scheme, "turn") ||
		 0 == pl_strcasecmp(&uri.scheme, "turns")) {

		stun_uri->scheme = STUN_SCHEME_TURN;
	}
	else {
		warning("unsupported stun scheme (%r)\n", &uri.scheme);
		return ENOTSUP;
	}

	stun_uri->secure = 's' == tolower(uri.scheme.p[uri.scheme.l-1]);

	if (uri.port)
		port = uri.port;
	else if (stun_uri->secure)
		port = 5349;
	else
		port = 3478;

	if (0 == re_regex(str, strlen(str), "?transport=[a-z]+", &transp)) {

		if (0 == pl_strcasecmp(&transp, "udp"))
			stun_uri->proto = IPPROTO_UDP;
		else if (0 == pl_strcasecmp(&transp, "tcp"))
			stun_uri->proto = IPPROTO_TCP;
		else {
			warning("unsupported stun transport (%r)\n", &transp);
			return ENOTSUP;
		}

	}
	else {
		stun_uri->proto = IPPROTO_UDP;
	}

	pl_strcpy(&uri.host, stun_uri->host, sizeof(stun_uri->host));

	stun_uri->port = port;
	err = sa_set(&stun_uri->addr, &uri.host, port);
	if (err)
		return err;
	
	return 0;
}

static void dns_handler(int dns_err, const struct sa *srv, void *arg)
{
	struct lookup_entry *lent = arg;
	struct turn_conn *tc = lent->tc;
	struct sa turn_srv;
	char addr[32];
	size_t i;
	int err;

	//if (tc->closed)
	//	goto out;

	sa_cpy(&turn_srv, srv);
	sa_set_port(&turn_srv, lent->port);

	re_snprintf(addr, sizeof(addr), "%J", &turn_srv);
	for (i = 0; i < strlen(addr); ++i) {
		if (addr[i] == '.')
			addr[i] = '-';
	}

	info("turnconn(%p): dns_handler: err=%d [%s] -> [%s] took: %dms\n",
	     tc, dns_err, lent->host, addr,
	     (int)(tmr_jiffies() - lent->ts));

	if (dns_err)
		goto out;

	if (tc->readyh) {
		tc->readyh(tc, &turn_srv,
			   tc->username, tc->password,
			   lent->proto, lent->secure, tc->arg);
	}
	else {
		err = turnconn_start(tc, tc->connl,
				     &turn_srv, lent->proto, lent->secure,
				     lent->turn.username, lent->turn.credential,
				     AF_INET, NULL,
				     LAYER_STUN, LAYER_TURN,
				     tc->estabh,
				     tc->datah,
				     tc->errorh,
				     tc->arg);
	}
	
 out:
	mem_deref(lent);
}

static void lent_destructor(void *arg)
{
	struct lookup_entry *lent = arg;

	mem_deref(lent->host);
	mem_deref(lent->tc);
}

static int turn_dns_lookup(struct turn_conn *tc,
			   struct zapi_ice_server *turn,
			   struct stun_uri *uri)
{
	struct lookup_entry *lent;
	int err = 0;

	lent = mem_zalloc(sizeof(*lent), lent_destructor);
	if (!lent)
		return ENOMEM;

	lent->tc = mem_ref(tc);
	lent->turn = *turn;
	lent->ts = tmr_jiffies();
	lent->proto = uri->proto;
	lent->secure = uri->secure;
	lent->port = uri->port;
	err = str_dup(&lent->host, uri->host);
	if (err)
		goto out;

	info("turnconn(%p): dns_lookup for: %s:%d\n",
	     tc, lent->host, lent->port);
	
	err = dns_lookup(lent->host, dns_handler, lent);
	if (err) {
		warning("turnconn(%p): dns_lookup failed\n", tc);
		goto out;
	}
 out:
	if (err)
		mem_deref(lent);

	return err;
}


int turnconn_alloc(struct turn_conn **connp,
		   struct list *connl,
		   struct zapi_ice_server *turn,
		   turnconn_ready_h *readyh,
		   turnconn_estab_h *estabh,
		   turnconn_data_h *datah,
		   turnconn_error_h *errorh,
		   void *arg)
{
	struct stun_uri uri;
	struct turn_conn *tc;
	int err = 0;
	
	tc = mem_zalloc(sizeof(*tc), turnconn_destructor);
	if (!tc)
		return ENOMEM;

	str_dup(&tc->username, turn->username);
	str_dup(&tc->password, turn->credential);
	tc->connl = connl;
	tc->readyh = readyh;
	tc->estabh = estabh;
	tc->datah = datah;
	tc->errorh = errorh;
	tc->arg = arg;
	
	err = stun_uri_decode(&uri, turn->url);
	if (err) {
		info("turnconn(%p): resolving turn uri (%s)\n",
		     tc, turn->url);

		turn_dns_lookup(tc, turn, &uri);
		err = EAGAIN;
		goto out;
	}

	if (STUN_SCHEME_TURN != uri.scheme) {
		warning("turnconn(%p): ignoring scheme %d\n",
			tc, uri.scheme);
		err = EINVAL;
		goto out;
	}

	/* If we are here it means we already have a numeric IP
	 * and a correct scheme
	 */
	if (tc->readyh) {
		tc->readyh(tc, &uri.addr,
			   turn->username, turn->credential,
			   uri.proto, uri.secure, tc->arg);
	}
	else {
		err = turnconn_start(tc, connl,
				     &uri.addr, uri.proto, false,
				     turn->username, turn->credential,
				     AF_INET, NULL,
				     LAYER_STUN, LAYER_TURN,
				     estabh, datah, errorh, arg);
	}

 out:
	if (err && err != EAGAIN)
		mem_deref(tc);
	else {
		if (connp)
			*connp = tc;
	}

	return err;
}

int turnconn_send(struct turn_conn *tc, struct sa *dst, struct mbuf *mb)
{
	int err = 0;
	
	if (!tc || !mb || !dst)
		return EINVAL;

	err = turnc_send(tc->turnc, dst, mb);
	if (err) {
		warning("turnconn_send(%p): turnc_send failed: %m\n",
			tc, err);
	}

	return err;
}

int turnconn_add_cid(struct turn_conn *tc, uint16_t cid)
{
	if (!tc)
		return EINVAL;

	tc->rcid = cid;

	return 0;
}

uint16_t turnconn_lcid(struct turn_conn *tc)
{
	return tc ? tc->lcid : 0;
}

uint16_t turnconn_rcid(struct turn_conn *tc)
{
	return tc ? tc->rcid : 0;
}
