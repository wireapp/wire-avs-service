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

	struct dict *groups;

	int nprocs;
	
} g_lb;

struct group {
	struct http_cli *httpc;
	struct sa anchorsa;
	uint32_t anchorid;

	struct dict *calls;

	struct tmr tmr_inactive;
};

struct call {
	uint32_t id;
	char *callid;
	int sftid;
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
	
	mem_deref(group->httpc);
	mem_deref(group->calls);
}


static void timeout_group_inactive(void *arg)
{
	struct group *group = arg;

	info("lb: group(%p): inactive timeout\n");

	mem_deref(group);
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

	err = http_client_alloc(&group->httpc, avs_service_dnsc());
	if (err)
		goto out;

	err = dict_alloc(&group->calls);
	if (err)
		goto out;
	
	group->anchorid = make_sftid(groupid);
	sa_cpy(&group->anchorsa, avs_service_get_req_addr(group->anchorid));

	info("lb: alloc_group: group=%p anchorid=%d(%J)\n", group, group->anchorid, &group->anchorsa);
	
	tmr_start(&group->tmr_inactive, TIMEOUT_INACTIVE, timeout_group_inactive, group);	

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

	mem_deref(call->callid);
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

	str_dup(&call->callid, callid);

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

	info("lb: sft_resp: done err=%d(%m), %d bytes to send\n",
	     err, err, rctx->mb_body ? (int)rctx->mb_body->end : 0);
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

#if 0
	if (buf) {
		info("lb: sft_resp: ctype=%s msg=%s\n", ctype, buf);
	}
#endif
	
	http_creply(rctx->hconn, msg->scode, reason, ctype, "%s", buf);

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
	int i;
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

	printf("URL has %d paths\n", n);
	for (i = 0; i < n; ++i) {
		printf("path[%d]=%s\n", i, paths[i]);
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
		group_created = true;
	}

	callid = helper_make_callid(convid, userid, clientid);
	
	call = dict_lookup(group->calls, callid);
	if (!call) {
		err = alloc_call(&call, group, callid);
		if (err)
			goto out;

		dict_add(group->calls, callid, call);
		/* Call is now owned by the group's call dictionary */
		mem_deref(call);

		call_created = true;

		if (group_created) {
			call->sftid = group->anchorid;
			sa_cpy(&call->sftsa, &group->anchorsa);
		}
		else {
			call->sftid = make_sftid(callid);
			sa_cpy(&call->sftsa, avs_service_get_req_addr(call->sftid));
		}
	
		
	}
	
	rctx = mem_zalloc(sizeof(*rctx), rctx_destructor);
	if (!rctx) {
		err = ENOMEM;
		goto out;
	}
			
	rctx->hconn = hc;

	re_snprintf(sfturl, sizeof(sfturl), "http://%J%s", &call->sftsa, orig_url);

	info("sending request: %s\n", sfturl);
	
	err = http_request(&rctx->http_req, group->httpc,
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

	tmr_start(&group->tmr_inactive, TIMEOUT_INACTIVE, timeout_group_inactive, group);

 out:
 bad_req:
	mem_deref(url);
	mem_deref(orig_url);
	mem_deref(cmsg);
	
	if (err) {
		if (group_created) {
			dict_remove(lb->groups, convid);
			mem_deref(group);
		}
		if (call_created) {
			if (group && callid)
				dict_remove(group->calls, callid);
			mem_deref(call);
		}
		
		/* If there was a sending error, maybe send a 5xx response? */
		mem_deref(rctx);
			
		http_ereply(hc, 400, "Bad request");
	}
}

int lb_init(int nprocs)
{
	struct sa *laddr = avs_service_req_addr();
	int err = 0;

	g_lb.nprocs = nprocs;
	
	err = dict_alloc(&g_lb.groups);
	if (err) {
		warning("lb: failed to alloc groups\n");
		goto out;
	}

	err = httpd_alloc(&g_lb.httpd, laddr, http_req_handler, &g_lb);
	if (err) {
		error("sft: could not alloc httpd: %m\n", err);
		goto out;
	}

 out:
	return err;
}

static bool group_flush_handler(char *key, void *val, void *arg)
{
	struct group *group = val;
	
	mem_deref(group->calls);
}

void lb_close(void)
{
	mem_deref(g_lb.httpd);

	dict_apply(g_lb.groups, group_flush_handler, NULL);
	mem_deref(g_lb.groups);
}

