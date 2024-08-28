/*
 * Wire
 * Copyright (C) 2024 Wire Swiss GmbH
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

#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <wordexp.h>
#include <re.h>
#include <avs_log.h>
#include <avs_base.h>
#include <avs_version.h>
#include <pthread.h>

#include <avs_service.h>
#include "score.h"
#include "avs.h"

#define TIMEOUT_INACTIVE   (5*3600000) /* 5 hours in ms */

struct lb {
	struct httpd *httpd;
	struct httpd *httpd_stats;

	struct dict *groups;

	int nprocs;

	uint64_t start_ts;
	struct http_cli *httpc;	
} g_lb;

struct group {
	struct sa anchorsa;
	struct sa anchor_sftsa;
	uint32_t anchorid;

	struct dict *calls;

	struct tmr tmr_inactive;

	char *id;
};

struct call {
	char *id;
	uint32_t sftid;
	struct sa sftsa;
	struct sa anchorsa;
};

struct req_ctx {
	void *arg;
	struct mbuf *mb_body;
	struct http_req *http_req;
	struct http_conn *hconn;
};


static struct group *find_group(struct lb *lb, const char *groupid)
{
	struct group *group;
	
	group = dict_lookup(lb->groups, groupid);

	return group;
}

static void group_destructor(void *arg)
{
	struct group *group = arg;

	tmr_cancel(&group->tmr_inactive);

	mem_deref(group->id);
	mem_deref(group->calls);
}


static void timeout_group_inactive(void *arg)
{
	struct group *group = arg;

	info("lb: group(%p): inactive timeout\n");

	dict_remove(g_lb.groups, group->id);	
}

static uint32_t make_sftid(const char *hid)
{
	uint32_t sftid;
	
	sftid = hash_fast_str(hid);
	sftid = sftid % g_lb.nprocs;

	return sftid;
}

static int alloc_group(struct group **groupp, struct lb *lb, const char *groupid)
{
	struct group *group;
	int err = 0;

	group = mem_zalloc(sizeof(*group), group_destructor);
	if (!group)
		return ENOMEM;

	err = dict_alloc(&group->calls);
	if (err)
		goto out;

	str_dup(&group->id, groupid);
	
	group->anchorid = make_sftid(groupid);
	sa_cpy(&group->anchorsa, avs_service_get_req_addr(group->anchorid));
	sa_cpy(&group->anchor_sftsa, avs_service_get_sft_addr(group->anchorid));

	info("lb: alloc_group: group=%p anchorid=%d(%J)(%J)\n", group, group->anchorid, &group->anchorsa, &group->anchor_sftsa);
	

 out:
	if (err)
		mem_deref(group);
	else
		*groupp = group;

	return err;
}

static void call_destructor(void *arg)
{
	struct call *call = arg;

	mem_deref(call->id);
}

static int alloc_call(struct call **callp, struct group *group, const char *callid)
{
	struct call *call;
	int err = 0;

	if (!callp || !group)
		return EINVAL;
	
	call = mem_zalloc(sizeof(*call), call_destructor);
	if (!call)
		return ENOMEM;

	str_dup(&call->id, callid);

	if (err)
		goto out;
	
 out:
	if (err)
		mem_deref(call);
	else
		*callp = call;

	return err;
	
}

static int sft_data_handler(const uint8_t *buf, size_t size,
			    const struct http_msg *msg, void *arg)
{
	struct req_ctx *rctx = arg;
	bool chunked;
	int err = 0;

	chunked = http_msg_hdr_has_value(msg, HTTP_HDR_TRANSFER_ENCODING,
					 "chunked");
	if (!rctx->mb_body) {
		rctx->mb_body = mbuf_alloc(1024);
		if (!rctx->mb_body) {
			err = ENOMEM;
			goto out;
		}
	}

	(void)chunked;

	/* append data to the body-buffer */
	err = mbuf_write_mem(rctx->mb_body, buf, size);
	if (err)
		return err;


 out:
	return err;
}


static void sft_resp_handler(int err, const struct http_msg *msg,
			     void *arg)
{
	struct req_ctx *rctx = arg;
	const uint8_t *buf = NULL;
	char *reason;
	char ctype[256];
	char *cmtype = NULL;
	char *cstype = NULL;
	
	int sz = 0;

	info("lb: rctx(%p): sft_resp: done err=%d(%m), %d bytes received\n",
	     rctx, err, err, rctx->mb_body ? (int)rctx->mb_body->end : 0);
	if (err)
		goto error;

	if (rctx->mb_body) {
		mbuf_write_u8(rctx->mb_body, 0);
		rctx->mb_body->pos = 0;

		buf = mbuf_buf(rctx->mb_body);
		sz = mbuf_get_left(rctx->mb_body);
	}


	pl_strdup(&reason, &msg->reason);
	pl_strdup(&cmtype, &msg->ctyp.type);
	pl_strdup(&cstype, &msg->ctyp.subtype);

	re_snprintf(ctype, sizeof(ctype), "%s/%s", cmtype, cstype);

#if 1
	if (buf) {
		info("lb: sft_resp: rctx(%p) hconn=%p ctype=%s msg=%s\n", rctx, rctx->hconn, ctype, buf);
	}
#endif
	
	err = http_creply(rctx->hconn, msg->scode, reason, ctype, "%s", buf);
	if (err) {
		warning("lb: sft_resp: rctx(%p): failed to send reply: %m\n", rctx, err);
	}

	mem_deref(reason);
	mem_deref(cmtype);
	mem_deref(cstype);

 error:
	mem_deref(rctx);
}

static void rctx_destructor(void *arg)
{
	struct req_ctx *rctx = arg;

	mem_deref(rctx->mb_body);
	mem_deref(rctx->http_req);
	mem_deref(rctx->hconn);
}



static void http_req_handler(struct http_conn *hc,
			     const struct http_msg *msg,
			     void *arg)
{
	struct lb *lb = arg;
	struct econn_message *cmsg = NULL;
	char *paths[2];
	char *url = NULL;
	char *orig_url = NULL;
	char sfturl[256];
	char *params;
	char *convid = NULL;
	char *userid = NULL;
	char *clientid = NULL;
	char *callid = NULL;
	struct group *group = NULL;
	struct call *call = NULL;
	const struct sa *sa;
	bool group_created = false;
	bool call_created = false;
	char *body = NULL;
	size_t bodysz = 0;
	int n;
	struct req_ctx *rctx;
	int err = 0;

	pl_strdup(&url, &msg->path);
	pl_strdup(&params, &msg->prm);

	str_dup(&orig_url, url);

	sa = http_conn_peer(hc);
	info("lb: incoming HTTP from: %J URL=%s\n", sa, url);
	
	n = helper_split_paths(url, paths, ARRAY_SIZE(paths));
	if (n != 2) {
		warning("lb: path missmatch expecting 2 got %d\n", n);
		err = EINVAL;
		goto bad_req;
	}

	convid = paths[1];

	if (streq(convid, "status")) {
		http_creply(hc, 200, "OK", "text/plain", "Debug\n");
		goto out;
	}

	if (streq(convid, "url")) {
		http_creply(hc, 200, "OK", "text/plain",
			    "%s\r\n", avs_service_url());
		goto out;
	}	

	if (msg->mb) {
		body = (char *)mbuf_buf(msg->mb);
		bodysz = mbuf_get_left(msg->mb);
	}

	if (!body || !bodysz) {
		err = ENOSYS;
		goto bad_req;
	}

	err = econn_message_decode(&cmsg, 0, 0, body, bodysz);
	if (err)
		goto bad_req;
	
	userid = cmsg->src_userid;
	clientid = cmsg->src_clientid;

	group = find_group(lb, convid);

	info("lb: req for %s.%s for convid=%s %H\n",
	     userid, clientid, convid, econn_message_brief, cmsg);

	if (!group) {
		err = alloc_group(&group, lb, convid);
		if (err)
			goto out;

		dict_add(lb->groups, group->id, group);
		/* Group is now owned by groups dictionary */
		mem_deref(group);

		group_created = true;
	}
	
	tmr_start(&group->tmr_inactive, TIMEOUT_INACTIVE,
		  timeout_group_inactive, group);

	callid = helper_make_callid(convid, userid, clientid);
	
	call = dict_lookup(group->calls, callid);
	if (!call) {
		err = alloc_call(&call, group, callid);
		if (err)
			goto out;

		err = dict_add(group->calls, call->id, call);
		if (err) {
			warning("lb: call(%p): incoming req call already in group\n");
			goto out;
		}

		call_created = true;

		/* Call is now owned by the group's call dictionary */
		mem_deref(call);

		if (group_created) {
			call->sftid = group->anchorid;
			sa_cpy(&call->sftsa, &group->anchorsa);
		}
		else {
			call->sftid = make_sftid(callid);
#if 0
			/* XXX TEST */
			if (call->sftid == group->anchorid) {
				call->sftid = (call->sftid + 1) % g_lb.nprocs;
			}
#endif
				
			sa_cpy(&call->sftsa, avs_service_get_req_addr(call->sftid));
		}
	
		
	}

	info("lb: call=%p anchorid=%d(%J) sftid=%d(%J)\n",
	     call, group->anchorid, &group->anchor_sftsa,
	     call->sftid, &call->sftsa);
	
	if (cmsg->msg_type == ECONN_CONF_CONN
	    && call->sftid != group->anchorid) {		
		char sft_url[256];

		re_snprintf(sft_url, sizeof(sft_url),
			    "http://%J", &group->anchor_sftsa);

		info("lb: call(%p): setting sft_url=%s\n", call, sft_url);
		
		str_dup(&cmsg->u.confconn.sft_url, sft_url);

		econn_message_encode(&body, cmsg);
		bodysz = str_len(body);
	}
	
	rctx = mem_zalloc(sizeof(*rctx), rctx_destructor);
	if (!rctx) {
		err = ENOMEM;
		goto out;
	}
			
	rctx->hconn = mem_ref(hc);

	re_snprintf(sfturl, sizeof(sfturl), "http://%J%s", &call->sftsa, orig_url);

	info("rctx(%p): sending request: %s on hconn: %p\n", rctx, sfturl, rctx->hconn);
	
	err = http_request(&rctx->http_req, g_lb.httpc,
			   "POST", sfturl, sft_resp_handler, sft_data_handler, rctx, 
			   "Accept: application/json\r\n"
			   "Content-Type: application/json\r\n"
			   "Content-Length: %zu\r\n"
			   "User-Agent: sft-lb\r\n"
			   "\r\n"
			   "%b",
			   bodysz, body, bodysz);
	if (err) {
		warning("lb(%p): sft_handler failed to send request: %m\n", rctx, err);
		goto out;
	}


 out:
 bad_req:
	mem_deref(url);
	mem_deref(orig_url);
	mem_deref(cmsg);
	
	if (err) {
		if (group_created) {
			dict_remove(lb->groups, convid);
		}
		if (call_created) {
			if (group && callid)
				dict_remove(group->calls, callid);
		}
		else {
			if (call) {
				mem_deref(call);
			}
		}
		
		/* If there was a sending error, maybe send a 5xx response? */
		mem_deref(rctx);
			
		http_ereply(hc, 400, "Bad request");
	}
}

struct sft_metrics {
	uint32_t ncalls;
	uint32_t nparts;
	uint32_t total_calls;
	uint32_t total_parts;

	int nresp;
	int err;

	struct http_conn *hconn;
};

struct metrics_ctx {
	struct sft_metrics *smx;
	struct http_req *req;
	struct mbuf *body;
};


static void mctx_destructor(void *arg)
{
	struct metrics_ctx *mctx = arg;

	mem_deref(mctx->body);
	mem_deref(mctx->req);
	mem_deref(mctx->smx);
}

static void smx_destructor(void *arg)
{
	struct sft_metrics *smx = arg;

	mem_deref(smx->hconn);
}

static int metrics_data_handler(const uint8_t *buf, size_t size,
				const struct http_msg *msg, void *arg)
{
	struct metrics_ctx *mctx = arg;
	int err = 0;

	if (!mctx->body) {
		mctx->body = mbuf_alloc(1024);
		if (!mctx->body) {
			err = ENOMEM;
			goto out;
		}
	}

	/* append data to the body-buffer */
	err = mbuf_write_mem(mctx->body, buf, size);
	if (err)
		return err;


 out:
	return err;
}

static void send_stats(struct sft_metrics *smx)
{
	struct mbuf *mb = NULL;
	char *stats = NULL;
	uint64_t now;
	int err = 0;;

	if (smx->err) {
		err = smx->err;
		goto out;
	}
	
	mb = mbuf_alloc(512);
	now = tmr_jiffies();

	mbuf_printf(mb, "# HELP sft_uptime "
		    "Uptime in [seconds] of the SFT service\n");
	mbuf_printf(mb, "# TYPE sft_uptime counter\n");
	mbuf_printf(mb, "sft_uptime %llu\n", (now - g_lb.start_ts)/1000);
	mbuf_printf(mb, "\n");

	mbuf_printf(mb, "# HELP sft_build_info "
		    "Build information\n");
	mbuf_printf(mb, "# TYPE sft_build_info gauge\n");
	mbuf_printf(mb, "sft_build_info{version=\"%s\"} 1\n", SFT_VERSION);
	mbuf_printf(mb, "\n");
	
	mbuf_printf(mb, "# HELP sft_participants "
		    "Current number of participants\n");
	mbuf_printf(mb, "# TYPE sft_participants gauge\n");
	mbuf_printf(mb, "sft_participants %zu\n", smx->nparts);
	mbuf_printf(mb, "\n");

	mbuf_printf(mb, "# HELP sft_calls Current number of calls\n");
	mbuf_printf(mb, "# TYPE sft_calls gauge\n");
	mbuf_printf(mb, "sft_calls %zu\n", smx->ncalls);
	mbuf_printf(mb, "\n");

	mbuf_printf(mb, "# HELP sft_participants_total "
		    "Total number of participants\n");
	mbuf_printf(mb, "# TYPE sft_participants_total counter\n");
	mbuf_printf(mb, "sft_participants_total %llu\n", smx->total_parts);
	mbuf_printf(mb, "\n");

	mbuf_printf(mb, "# HELP sft_calls_total Total number of calls\n");
	mbuf_printf(mb, "# TYPE sft_calls_total counter\n");
	mbuf_printf(mb, "sft_calls_total %llu\n", smx->total_calls);
	mbuf_printf(mb, "\n");

	mb->pos = 0;
	mbuf_strdup(mb, &stats, mb->end);
	http_creply(smx->hconn, 200, "OK", "text/plain", "%s", stats);

 out:
	mem_deref(stats);
	mem_deref(mb);

	if (err)
		http_ereply(smx->hconn, 400, "Bad request");
	mem_deref(smx->hconn);
}


static void metrics_resp_handler(int rerr, const struct http_msg *msg,
				 void *arg)
{
	struct metrics_ctx *mctx = arg;
	struct sft_metrics *smx = mctx->smx;
	struct json_object *jobj = NULL;
	struct mbuf *body = NULL;
	int err = 0;
       	
	info("metrics_resp_handler: done err=%d msg=%p(%p)\n", rerr, msg, msg ? msg->mb : NULL);
	
	if (rerr)
		goto out;	

	if (!msg) {
		goto out;
	}
	body = mctx->body ? mctx->body : msg->mb;
	if (!body) {
		err = ENOENT;
		goto out;
	}
	
	mbuf_write_u8(body, 0);
	body->pos = 0;

	err = jzon_decode(&jobj, (const char *)body->buf, body->end);
	if (err) {
		warning("metrics_resp_handler: cannot decode json: %m\n", err);
	}
	else {
		uint32_t nparts;
		uint32_t ncalls;
		uint32_t total_parts;
		uint32_t total_calls;
		
		err |= jzon_u32(&nparts, jobj, "sft_participants");
		err |= jzon_u32(&ncalls, jobj, "sft_calls");
		err |= jzon_u32(&total_parts, jobj, "sft_participants_total");
		err |= jzon_u32(&total_calls, jobj, "sft_calls_total");
		if (err) {
			warning("metrics_resp_handler: failed to collect data\n");
		}
		else {
			smx->nparts += nparts;
			smx->ncalls += ncalls;
			smx->total_parts += total_parts;
			smx->total_calls += total_calls;
		}
	}

 out:
	mem_deref(jobj);
	mem_deref(mctx);

	smx->nresp++;
	smx->err |= err;
	if (smx->nresp >= g_lb.nprocs) {
		send_stats(smx);
		mem_deref(smx);
	}
}


static void http_stats_handler(struct http_conn *hc,
			       const struct http_msg *msg,
			       void *arg)
{
	struct sft_metrics *smx = NULL;
	char *url = NULL;
	int err;
	int i;
	
	err = pl_strdup(&url, &msg->path);
	info("http_stats_req: URL=%s\n", url);
	if (err)
		goto out;

	if (!streq(url, "/metrics")) {
		err = ENOENT;
		goto out;
	}

	smx = mem_zalloc(sizeof(*smx), smx_destructor);
	if (!smx) {
		err = ENOMEM;
		goto out;
	}
	smx->hconn = mem_ref(hc);
	
	for (i = 0; i < g_lb.nprocs; ++i) {
		char local_url[256];
		struct sa *msa = avs_service_get_metrics_addr(i);
		struct metrics_ctx *mctx;
		
		re_snprintf(local_url, sizeof(local_url), "http://127.0.0.1:%d/jmetrics", sa_port(msa));
		mctx = mem_zalloc(sizeof(*mctx), mctx_destructor);
		if (!mctx) {
			err = ENOMEM;
			goto out;
		}
		
		mctx->smx = mem_ref(smx);

		info("http_stats_req: metrics request to: %s\n", local_url);
		err = http_request(NULL, g_lb.httpc,
				   "POST", local_url, metrics_resp_handler, metrics_data_handler, mctx, 
				   "Accept: application/json\r\n"
				   "Content-Type: application/json\r\n"
				   "Content-Length: 0\r\n"
				   "User-Agent: sft-lb\r\n"
				   "\r\n");
		if (err) {
			warning("lb(%p): metrics_handler failed to send request: %m\n", mctx, err);
			goto out;
		}
	}
 out:
	mem_deref(url);
	if (err) {
		http_ereply(hc, 400, "Bad request");
		mem_deref(smx);
	}
}

int lb_init(int nprocs)
{
	struct sa *laddr = avs_service_req_addr();
	int err = 0;

	g_lb.nprocs = nprocs;
	g_lb.start_ts = tmr_jiffies();
	
	err = dict_alloc(&g_lb.groups);
	if (err) {
		warning("lb: failed to alloc groups\n");
		goto out;
	}

	err = http_client_alloc(&g_lb.httpc, avs_service_dnsc());
	if (err) {
		warning("lb: failed to alloc http-client\n");
		goto out;
	}

	err = httpd_alloc(&g_lb.httpd, laddr, http_req_handler, &g_lb);
	if (err) {
		error("sft: could not alloc httpd: %m\n", err);
		goto out;
	}
	
	laddr = avs_service_metrics_addr();
	err = httpd_alloc(&g_lb.httpd_stats, laddr, http_stats_handler, &g_lb);
	if (err) {
		error("sft: could not alloc stats httpd: %m\n", err);
		goto out;
	}

	
 out:
	return err;
}

static bool group_flush_handler(char *key, void *val, void *arg)
{
	struct group *group = val;
	
	mem_deref(group->calls);

	return false;
}

void lb_close(void)
{
	dict_apply(g_lb.groups, group_flush_handler, NULL);
	mem_deref(g_lb.groups);

	mem_deref(g_lb.httpc);
	mem_deref(g_lb.httpd);
	mem_deref(g_lb.httpd_stats);
}

