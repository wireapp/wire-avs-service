/*
* Wire
* Copyright (C) 2019 Wire Swiss GmbH
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
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/time.h>
#include <sodium.h>

#include <re.h>

#include <avs_log.h>
#include <avs_string.h>
#include <avs_zapi.h>
#include <avs_icall.h>
#include <avs_econn.h>
#include <avs_econn_fmt.h>
#include <avs_msystem.h>
#include <avs_dict.h>
#include <avs_keystore.h>
#include <avs_ecall.h>
#include <avs_uuid.h>
#include <avs_service.h>
#include <avs_service_turn.h>
#include <avs_audio_level.h>

#if USE_RTX
#include "jbuf.h"
#endif

#include "zauth.h"
#include "gnack.h"
#include "dep_desc.h"


#define SFT_TOKEN "sft-"

/* Use libre internal rtcp function */
#define	RTCP_PSFB_FIR  4   /* FULL INTRA-FRAME */

#define RTCP_RTPFB_TRANS_CC  15
#define RTCP_RTPFB_REMB      15

#define EXTMAP_AULEVEL 1
#define EXTMAP_VIDEO_WSEQ  3
#define EXTMAP_VIDEO_RID 4
#define EXTMAP_VIDEO_DD 6
#define EXTMAP_VIDEO_GFH 11


#define AUDIO_LEVEL_SILENCE 110
#define AUDIO_LEVEL_ABS_SILENCE 127

#define RTP_LEVELK 0.5f

#define DEBUG_PACKET 0

#define VIDEO_JBUF_MIN  6
#define VIDEO_JBUF_MAX 24

#define PT_VP8 100
#define PT_RTX 101

#define RID_HI "h"
#define RID_LO "l"

#define GFH_MASK_SOF 0x80
#define GFH_MASK_DEP 0x08


#define TEST_QUALITY_SWITCH 0


enum select_mode {
	SELECT_MODE_NONE = 0x0,
	SELECT_MODE_LEVEL = 0x1,
	SELECT_MODE_LIST = 0x2		  
};

extern int rtcp_rr_encode(struct mbuf *mb, const struct rtcp_rr *rr);

#define SFTLOG(level, fmt,  ...) \
	loglv(level, "sft:%s(%p): "fmt, __FUNCTION__, __VA_ARGS__)


#define SFT_USERID "sft"
#define SFT_PORT 8585
#define SFT_STATS_PORT 49090
//#define SFT_PORT 8282
//#define SFT_STATS_PORT 49091

#define ENTROPY_LENGTH 16

struct sft {
	struct msystem *msys;
	struct httpd *httpd;
	struct httpd *httpd_stats;
	struct httpd *httpd_sft_req;
	struct dict *calls;
	struct dict *groups;
	struct {
		struct dict *calls;
		struct list ecalls;
	} provisional;
	struct sa mediasa;
	char uuid[64];
	const char *url;
	uint32_t seqno;

	struct {
		uint64_t call_cnt;
		uint64_t group_cnt;
	} stats;
	
	struct list ecalls;

	struct list cbl; /* client blacklist */

	struct {
		char username[256];
		char credential[256];
	} fed_turn;

	uint64_t start_ts;

	size_t workerc;
	struct worker *workerv;

	struct lock *lock;

	struct tmr tmr_terminate;
};

static struct sft *g_sft = NULL;

struct sft_conn {
	struct http_conn *hc;
	char *memberid;

	struct le le;
};

struct query_param {
	char *key;
	char *val;
};

struct call;
struct group {
	char *id;	
	struct list calll; /* list of calls in this group */
	struct list remotel; /* list of remote participants */
	bool started;
	uint32_t seqno;
	uint32_t part_ix;
	uint64_t start_ts;
	bool isfederated;
	struct {
		struct call *call;
		bool ishost;
	} sft;
	struct {
		bool isready;
		struct turn_conn *tc;
		struct list tcl;
		struct udp_helper *uh;
		struct sa relay_addr;
		char relay_str[128];
		struct list pendingl;		
	} federate;
};

typedef int (sft_task_h) (struct call *call, void *arg);

struct task_arg {
	sft_task_h *h;
	struct call *call;
	void *arg;
};

struct sft_req_ctx {
	struct call *call;
	void *arg;
	struct mbuf *mb_body;
	struct http_req *http_req;
};

struct pending_msg {
	char *msg;
	struct call *call;
	struct le le;
};

struct nack_entry {
	uint32_t ssrc;
	uint16_t seq;
	int nlost;
};

struct ssrcv_update {
	struct call *call;
	struct call *rcall;
};

#define TIMEOUT_SETUP 10000
#define TIMEOUT_CONN 45000
#define TIMEOUT_RR 500
#define TIMEOUT_TWCC 64
#define TIMEOUT_PROVISIONAL 10000
#define TIMEOUT_VIDEO_HI_FRAME 800
#define TIMEOUT_SCREENSHARE_HI_FRAME 3000


/* Moved to avs_service as cmdline param or default
 * #define TIMEOUT_FIR 3000
 */

#define TIMEOUT_FB 400

#define RTP_SEQ_MOD (1<<16)

#define SSRC_MIN_SEQUENTIAL 2
#define SSRC_MAX_DROPOUT    30
#define SSRC_MAX_MISORDER   10

struct ssrc_stats {
	uint32_t ssrc;
	
	bool isset;
	uint64_t first_ts;
	uint32_t first_rtp_ts;
	int freq_ms;
	
	uint32_t cycles;
	uint32_t received;
	uint32_t received_prior;
	uint32_t expected_prior;

	uint16_t max_seq;
	uint32_t base_seq;
	uint32_t bad_seq;

	uint32_t probation;      /* sequ. packets till source is valid */
	uint32_t transit;        /* relative trans time for prev pkt */
	uint32_t jitter;         /* estimated jitter */	
};


struct transpkt {
	uint16_t seqno;
	uint64_t ts;

	struct le le;
};


struct twcc_arg {
	struct call *call;
	struct twcc *twcc;
	uint32_t rssrc;
};

struct twcc {
	uint64_t refts;
	uint64_t fbcnt;
	//uint8_t fbcnt;
	int seqno;
	uint64_t now;
	uint64_t prevts;
	struct list pktl;

	uint32_t lssrc;
	uint32_t rssrc;

	struct tmr tmr;

	bool running;
	
	struct twcc_arg ta;
	struct lock *lock;
};

#define NUM_RTP_STREAMS 5

//#define NUM_RTP_STREAMS_AUDIO 2
//#define NUM_RTP_STREAMS_VIDEO 2

enum rtp_stream_type {
        RTP_STREAM_TYPE_NONE  = 0,
        RTP_STREAM_TYPE_AUDIO = 1,
        RTP_STREAM_TYPE_VIDEO = 2,
	RTP_STREAM_TYPE_ANY = 3
};

enum video_stream_q {
	VIDEO_STREAM_Q_ANY = 0,
	VIDEO_STREAM_Q_LO = 1,
	VIDEO_STREAM_Q_HI = 2,
};

struct rtp_stream {
	enum rtp_stream_type type;

	uint32_t ssrc;
	uint16_t seq;
	uint32_t ts;

	uint8_t level;

	uint32_t current_ssrc;
	uint16_t last_seq;
	uint32_t last_ts;

	enum video_stream_q q;
	enum video_stream_q old_q;
	bool change;

	struct gnack_rtx_stream rtx;
};

struct video_stream {
	char *userid;
	uint32_t ssrc;
	int ix;
	enum video_stream_q q;

	struct le le;
};

struct call {
	struct http_conn *hconn;
	
	char *sft_url;
	struct sa sft_tuple;
	uint16_t sft_cid;
	char *origin_url;
	char *userid;
	char *clientid;
	char *callid;
	char *sessid;

	struct ver_elem ver;

	struct zapi_ice_server *turnv;
	size_t turnc;
	
	struct {
		struct {
			struct rtp_stream *v;
			int c;
		} rtps;
		
		uint32_t ssrc;
		struct ssrc_stats stats;

		int level;

		bool is_selective;
		uint32_t *ssrcv;
		int ssrcc;
	} audio;
	struct {
		uint32_t ssrc;
		struct {
			struct rtp_stream *v;
			int c;
		} rtps;

		struct {
			enum select_mode mode;
			struct list streaml;
		} select;
		
		struct {
			uint32_t ssrc;			
			struct dep_desc *dd;
			uint8_t fir_seq;
			struct ssrc_stats stats;
			uint64_t ts;
		} hi;

		struct {
			uint32_t ssrc;
			struct dep_desc *dd;
			uint8_t fir_seq;
			struct ssrc_stats stats;
		} lo;

		bool started;
		bool is_selective;
		uint32_t *ssrcv;
		uint32_t *rtx_ssrcv;
		int ssrcc;
#if USE_RTX
		struct jb *jb;
#endif
		uint64_t last_ts;
		struct tmr tmr_ssrcv;
	} video;

	struct sft *sft;
	struct group *group;
	//uint64_t join_ts;
	uint32_t part_ix;
	struct icall *icall;
	struct mediaflow *mf;
	struct econn_props *props;

	bool muted;
	bool screenshare;
	bool update;
	bool dc_estab;
	bool active;
	bool alive;

	struct list partl;
	struct list sft_partl;

	struct le group_le;

	struct tmr tmr_setup;
	struct tmr tmr_conn;
	struct tmr tmr_rr;
	struct tmr tmr_fir;
	struct tmr tmr_q;

	struct worker *worker;
	struct lock *lock;

	bool issft;
	bool isprov;
	struct http_cli *http_cli;

	struct twcc twcc;

	struct {
		bool isready;
		struct turn_conn *tc;
		struct list tcl;
		char *url;
		char *dstid;
	} federate;
};

struct participant {
	struct group *group;
	struct call *call;

	uint32_t ix;
	uint32_t ssrca;
	uint32_t ssrcv;
	bool auth;
	struct list authl;

	bool remote;
	char *userid;
	char *clientid;

	struct {
		uint32_t ssrcv_hi;
		uint32_t ssrcv_lo;
	} simulcast;

	struct le le;
};

struct auth_part {
	char *userid;
	uint32_t ssrca;
	uint32_t ssrcv;
	bool auth;

	struct le le;
};

/* TURN Channels */
enum {
	TURN_CHAN_HDR_SIZE = 4,
};

struct turn_chan_hdr {
	uint16_t nr;
	uint16_t len;
};


static int alloc_call(struct call **callp, struct sft *sft,
		      const char *toolver,
		      struct zapi_ice_server *turnv, size_t turnc,
		      struct group *group,
		      const char *userid, const char *clientid,
		      const char *callid, const char *sessid,
		      bool selective_audio, bool selective_video,
		      int astreams, int vstreams,
		      bool locked);
static void deauth_call(struct call *call, bool reset_estab);

static int start_icall(struct call *call);
static int remove_participant(struct call *call, void *arg);
static int send_dce_msg(struct call *call, void *arg);
static int send_sft_msg(struct call *call, struct econn_message *msg,
			int status);
static void sft_send_conf_part(struct group *group,
			       uint8_t *entropy, size_t entropylen,
			       bool ishost, bool resp);

static int alloc_icall(struct call *call,
		       struct zapi_ice_server *turnv, size_t turnc,
		       const char *cid,
		       bool provisional);
static void setup_timeout_handler(void *arg);
static char *make_callid(const char *convid,
			 const char *userid,
			 const char *clientid);
static void ecall_confmsg_handler(struct ecall *ecall,
				  const struct econn_message *msg,
				  void *arg);
static int ecall_propsync_handler(struct ecall *ecall,
				  struct econn_message *msg,
				  void *arg);
static void part_destructor(void *arg);

static void call_close_handler(struct call *call, bool locked);

static void tc_estab_handler(struct turn_conn *tc,
			     const struct sa *relay_addr,
			     const struct sa *mapped_addr,
			     const struct stun_msg *msg, void *arg);
static void tc_data_handler(struct turn_conn *tc, const struct sa *src,
			    struct mbuf *mb, void *arg);
static void tc_err_handler(int err, void *arg);

static void reflow_rtp_recv(struct mbuf *mb, void *arg);

static void send_rtcp_rr(struct call *call, uint32_t ssrc, uint32_t last_ntp);


static void ref_locked(void *ref)
{
	lock_write_get(g_sft->lock);
	mem_ref(ref);
	lock_rel(g_sft->lock);
	
}

static void deref_locked(void *ref)
{
	lock_write_get(g_sft->lock);
	mem_deref(ref);
	lock_rel(g_sft->lock);
	
}

struct start_fed_arg {
	struct group *group;
	struct zapi_ice_server turn;
};

static int start_federation_task(void *arg)
{
	struct start_fed_arg *f = arg;
	int err = 0;

	turnconn_alloc(&f->group->federate.tc,
		       &f->group->federate.tcl,
		       &f->turn,
		       NULL,
		       tc_estab_handler,
		       tc_data_handler,
		       tc_err_handler,
		       f->group);

	mem_deref(f);
	
	return err;
}

static void task_destructor(void *arg)
{
	struct task_arg *task = arg;

#if 0
	info("task_destructor(%p): call=%p[%u] arg=%p[%u]\n",
	     task,
	     task ? task->call : NULL, mem_nrefs(task->call),
	     task ? task->arg : NULL, mem_nrefs(task->arg));
#endif

	lock_write_get(g_sft->lock);
	mem_deref(task->call);
	mem_deref(task->arg);
	lock_rel(g_sft->lock);
}

static int task_handler(void *arg)
{
	struct task_arg *task = arg;
	struct call *call = task->call;
	int err = 0;

	(void)call;

	if (task && task->h)
		err = task->h(task->call, task->arg);

	mem_deref(task);

	
	return err;
}

static int assign_task(struct call *call, sft_task_h *taskh, void *arg, bool lock)
{
	struct task_arg *task;
	bool locked = false;
	int err = 0;

	if (lock) {
		lock_write_get(g_sft->lock);
		locked = true;
	}

	if (!call->worker) {
		if (call->group) 
			call->worker = worker_get(call->group->id);
		else
			call->worker = worker_main();
	}
	if (!call->worker) {
		err = ENOENT;
		goto out;
	}
	
	task = mem_zalloc(sizeof(*task), task_destructor);
	if (!task) {
		err = ENOMEM;
		goto out;
	}

#if 0
	info("sft: assign_task(%p): call: %p[%u]\n", task, call, mem_nrefs(call));
#endif
	task->h = taskh;
	task->call = mem_ref(call);
	task->arg = mem_ref(arg);

 out:
	if (locked)
		lock_rel(g_sft->lock);

	if (!err)
		worker_assign_task(call->worker, task_handler, task);

	return err;
}

static int append_group(struct group *group, struct call *call);

static int split_paths(char *path, char **parts, int max_parts)
{
	int i = 0;

	if (!path || !(*path))
		return -1;

	do {
		/* Move forward to after slashes */
		while (*path == '/')
			++path;

		if (*path == '\0')
			break;

		parts[i++] = path;

		path = strchr(path, '/');
		if (!path)
			break;

		*(path++) = '\0';
	}
	while (i < max_parts);

	return i;
}


static void calc_rr(struct rtcp_rr *rr, struct ssrc_stats *s)
{
	uint32_t expected;
	uint32_t expected_interval;
	uint32_t received_interval;
	int lost_interval;
	int lost;
	
	rr->last_seq = s->cycles + s->max_seq;
	expected = rr->last_seq - s->base_seq + 1;
	lost = expected - s->received;

	/* Since this signed number is carried in 24 bits, it should be clamped
	 * at 0x7fffff for positive loss or 0x800000 for negative loss rather
	 * than wrapping around.
	 */
	if (lost > 0x7fffff)
		lost = 0x7fffff;
	else if (lost < 0)
		lost = 0x800000;

	rr->lost = lost;
	
	/*
	 * The fraction of packets lost during the last reporting interval
	 * (since the previous SR or RR packet was sent) is calculated from
	 * differences in the expected and received packet counts across the
	 * interval, where expected_prior and received_prior are the values
	 * saved when the previous reception report was generated:
	 */
	expected_interval = expected - s->expected_prior;
	s->expected_prior = expected;
	received_interval = s->received - s->received_prior;
	s->received_prior = s->received;
	lost_interval = expected_interval - received_interval;
	if (expected_interval == 0 || lost_interval <= 0)
		rr->fraction = 0;
	else
		rr->fraction = (lost_interval << 8) / expected_interval;

	rr->jitter = s->jitter;
}

static struct group *find_group(struct sft *sft, const char *groupid)
{
	struct group *group;

	lock_write_get(sft->lock);
	group = dict_lookup(sft->groups, groupid);
	if (!group) {
		warning("find_group: no group for groupid: %s\n", groupid);
		goto out;
	}

	mem_ref(group);

 out:
	lock_rel(sft->lock);

	return group;
}
	
static struct call *find_call(struct sft *sft, const char *callid)
{
	struct call *call;

	lock_write_get(sft->lock);
	call = (struct call *)dict_lookup(sft->calls, callid);
	if (!call) {
		warning("find_call: no call for callid: %s found\n", callid);
		goto out;
	}
	call = mem_ref(call);
	
 out:
	lock_rel(sft->lock);

	return call;
}

static void rtp_stream_destroy(struct rtp_stream *rs, int ssrcc)
{
	int i;

	for (i = 0; i < ssrcc; ++i) {
		list_flush(&(rs[i].rtx.l));
	}

	mem_deref(rs);
}

static void rtp_stream_create(struct call *call,
			      uint32_t *ssrcv,
			      uint32_t *rtx_ssrcv,
			      int ssrcc,
			      enum rtp_stream_type rst)
{
	struct rtp_stream *rs;
	int i;

	rs = mem_zalloc(ssrcc * sizeof(*rs), NULL);
	if (!rs)
		ssrcc = 0;

	for (i = 0; i < ssrcc; ++i) {

		rs[i].level = AUDIO_LEVEL_ABS_SILENCE;
		rs[i].type = rst;
		rs[i].ssrc = ssrcv[i];

		list_init(&rs[i].rtx.l);
		rs[i].rtx.seq = rand_u16();
		if (rtx_ssrcv) {
			rs[i].rtx.ssrc = rtx_ssrcv[i];
		}
	}

	switch(rst) {
	case RTP_STREAM_TYPE_AUDIO:
		rtp_stream_destroy(call->audio.rtps.v,
				   call->audio.rtps.c);
		call->audio.rtps.v = rs;
		call->audio.rtps.c = ssrcc;
		break;

	case RTP_STREAM_TYPE_VIDEO:
		rtp_stream_destroy(call->video.rtps.v,
				   call->video.rtps.c);
		call->video.rtps.v = rs;
		call->video.rtps.c = ssrcc;
		break;

	default:
		break;
	}
}


static void reflow_alloc_handler(struct mediaflow *mf, void *arg)
{
	struct call *call = arg;
	struct worker *w;
	int err = 0;

	call->mf = mf;

	info("reflow_alloc_handler(%p): assrcc: %d vssrcc: %d\n",
	     mf, call->audio.ssrcc, call->video.ssrcc);

	err = mediaflow_assign_streams(mf,
				       &call->audio.ssrcv,
				       call->audio.ssrcc,
				       &call->video.ssrcv,
				       &call->video.rtx_ssrcv,
				       call->video.ssrcc);
	if (err)
		warning("reflow_alloc_handler: failed to assign streams: %m\n", err);

	if (call->audio.ssrcc) {
		rtp_stream_create(call,
				  call->audio.ssrcv,
				  NULL,
				  call->audio.ssrcc,
				  RTP_STREAM_TYPE_AUDIO);
	}
	if (call->video.ssrcc) {
		rtp_stream_create(call,
				  call->video.ssrcv,
				  call->video.rtx_ssrcv,
				  call->video.ssrcc,
				  RTP_STREAM_TYPE_VIDEO);
	}

	w = NULL;
	if (call->worker)
		w = call->worker;
	else {
		if (call->group) {
			w = worker_get(call->group->id);
		}
		else {
			w = worker_main();
		}
		call->worker = w;
	}

	info("reflow_alloc_handler: call(%p)->flow(%p) worker=%p\n",
	     call, mf, w);

	if (w)
		mediaflow_assign_worker(mf, w);
	else {
		error("reflow_alloc_handler: call(%p) has no worker\n", call);
	}
}

static void reflow_close_handler(struct mediaflow *mf, void *arg)
{
	struct call *call = arg;

	info("reflow_close_handler: call(%p)->mf(%p) mf: %p\n", call, call->mf, mf);
	lock_write_get(call->lock);
	if (mf == call->mf)
		call->mf = NULL;
	lock_rel(call->lock);
}

static void reflow_version_handler(struct ver_elem *vel, void *arg)
{
	struct call *call = arg;

	if (call->issft) {
		vel->major = SFT_VERSION_MARK; /* indicate SFT */
		vel->minor = 0;
	}
	else {
		*vel = call->ver;
	}
}


static void reflow_dc_recv(struct mbuf *mb, void *arg)
{
	struct call *call = arg;

	(void)call;
	SFTLOG(LOG_LEVEL_INFO, "dc packet: %zu bytes\n", call, mbuf_get_left(mb));
}

static void init_seq(struct ssrc_stats *s, uint16_t seq)
{
	s->base_seq = seq;
	s->max_seq = seq;
	s->bad_seq = RTP_SEQ_MOD + 1;   /* so seq == bad_seq is false */
	s->cycles = 0;
	s->received = 0;
	s->received_prior = 0;
	s->expected_prior = 0;
}

static void update_seq(struct ssrc_stats *s, uint16_t seq)
{
	uint16_t d = seq - s->max_seq;

       /*
        * Source is not valid until MIN_SEQUENTIAL packets with
        * sequential sequence numbers have been received.
        */
       if (s->probation) {
	       /* packet is in sequence */
	       if (seq == s->max_seq + 1) {
		       s->probation--;
		       s->max_seq = seq;
		       if (s->probation == 0) {
			       init_seq(s, seq);
			       s->received++;
			       return;
		       }
	       }
	       else {
		       s->probation = SSRC_MIN_SEQUENTIAL - 1;
		       s->max_seq = seq;
	       }
	       return;
       }
       else if (d < SSRC_MAX_DROPOUT) {
	       /* in order, with permissible gap */
	       if (seq < s->max_seq) {
		       /*
			* Sequence number wrapped - count another 64K cycle.
			*/
		       s->cycles += RTP_SEQ_MOD;
	       }
	       s->max_seq = seq;
       }
       else if (d <= RTP_SEQ_MOD - SSRC_MAX_MISORDER) {
	       /* the sequence number made a very large jump */
	       if (seq == s->bad_seq) {
		       /*
			* Two sequential packets -- assume that the other side
			* restarted without telling us so just re-sync
			* (i.e., pretend this was the first packet).
			*/
		       init_seq(s, seq);
	       }
	       else {
		       s->bad_seq = (seq + 1) & (RTP_SEQ_MOD-1);
		       return;
	       }
       }
       else {
	       /* duplicate or reordered packet */
       }
       
       s->received++;
}	

static int calc_arrival(struct ssrc_stats *s, uint64_t now)
{
	int d = (int)(now - s->first_ts);

	return d * s->freq_ms + s->first_rtp_ts;
}

static void update_jitter(struct ssrc_stats *s, uint32_t ts, uint64_t now)
{
	int arrival = calc_arrival(s, now);
	int transit = arrival - ts;
	int d = transit - s->transit;
	
	s->transit = transit;
	if (d < 0)
		d = -d;
	s->jitter += (1.0/16.0) * ((double)d - s->jitter);	
}

#if 0
static int ssrc_stats_debug(struct re_printf *pf, const struct ssrc_stats *s)
{
	int err;
	
	err = re_hprintf(pf, "isset=%d ", s->isset);
	err = re_hprintf(pf, "freq_ms=%d ", s->freq_ms);
	err = re_hprintf(pf, "cycles=%08x ", s->cycles);
	err = re_hprintf(pf, "received=%d ", s->received);
	err = re_hprintf(pf, "rprior=%d ", s->received_prior);
	err = re_hprintf(pf, "eprior=%d ", s->expected_prior);
	err = re_hprintf(pf, "max_seq=%d ", s->max_seq);
	err = re_hprintf(pf, "base_seq=%d ", s->base_seq);
	err = re_hprintf(pf, "bad_seq=%d ", s->bad_seq);
	err = re_hprintf(pf, "transit=%d ", s->transit);

	return err;
}
#endif


static void update_ssrc_stats(struct ssrc_stats *s, struct rtp_header *rtp,
			      uint64_t now)
{
	if (!s->isset) {
		s->first_ts = now;
		s->first_rtp_ts = rtp->ts;
		init_seq(s, rtp->seq);
		s->max_seq = rtp->seq - 1;
		s->probation = SSRC_MIN_SEQUENTIAL;
		s->isset = true;
		return;
	}

	update_seq(s, rtp->seq);
	update_jitter(s, rtp->ts, now);
}

static struct participant *call2part(struct call *call, const char *userid, const char *clientid)
{
	struct participant *part;
	bool found = false;
	struct le *le;

	if (!call)
		return NULL;

	for(le = call->partl.head; !found && le; le = le->next) {
		struct call *pcall;

		part = le->data;
		pcall = part ? part->call : NULL;		

		found = pcall
		     && streq(pcall->userid, userid)
		     && streq(pcall->clientid, clientid);
	}
	return found ? part : NULL;
}

#if USE_TWCC
/** Is x less than y? */
static inline bool seq_less(uint16_t x, uint16_t y)
{
	return ((int16_t)(x - y)) < 0;
}

static void add_twcc_pkt(struct twcc *twcc, struct transpkt *tp)
{
	bool found = false;
	struct le *le;

	for (le = twcc->pktl.head; !found && le; le = le->next) {
		struct transpkt *p = le->data;

		found = seq_less(tp->seqno, p->seqno);
	}
	if (found)
		list_insert_before(&twcc->pktl, le, &tp->le, tp);
	else
		list_append(&twcc->pktl, &tp->le, tp);
}
#endif

static void vel_destructor(void *arg)
{
	struct ver_elem *vel = arg;

	(void)vel;
}

#if USE_TWCC

static void transpkt_destructor(void *arg)
{
	(void)arg;
}

static int twcc_encode_handler(struct mbuf *mb, void *arg)
{
	struct twcc *twcc = arg;
	struct le *le;
	uint16_t seqno;
	uint32_t refcnt;
	uint32_t refts;	
	uint64_t prevts;

	/*
	  0                   1                   2                   3
	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |V=2|P|  FMT=15 |    PT=205     |           length              |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                     SSRC of packet sender                     |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                      SSRC of media source                     |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |      base sequence number     |      packet status count      |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                 reference time                | fb pkt. count |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |          packet chunk         |         packet chunk          |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  .                                                               .
	  .                                                               .
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |         packet chunk          |  recv delta   |  recv delta   |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  .                                                               .
	  .                                                               .
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |           recv delta          |  recv delta   | zero padding  |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/

	seqno = (uint16_t)twcc->seqno;
	mbuf_write_u16(mb, htons(seqno));

	le = twcc->pktl.head;
	while(le) {
		struct transpkt *tp = le->data;
		struct le *cur_le;
		
		cur_le = le;
		le = le->next;
		while(seq_less(seqno, tp->seqno)) {
			struct transpkt *p;
			p = mem_zalloc(sizeof(*p), transpkt_destructor);
			p->seqno = seqno;
			list_insert_before(&twcc->pktl, cur_le, &p->le, p);
			++seqno;
		}
		seqno = tp->seqno + 1;
	}
	twcc->seqno = seqno;
	
	mbuf_write_u16(mb, htons((uint16_t)list_count(&twcc->pktl)));

	/* reference time is in multiples of 64ms */
	refts = ((uint32_t)twcc->refts & 0xffffffLL);
	refcnt = ((refts/64) << 8) | (uint8_t)twcc->fbcnt;

	mbuf_write_u32(mb, htonl(refcnt));

	/* Use status chunk 
	   0                   1
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |T|S|       symbol list         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   T: Always 1 for status chunk
	   S: 0 for 1-bit format 1 for 2-bit format
	*/
	le = twcc->pktl.head;
	while(le) {
		//uint16_t p = 0x8000;
		uint16_t p = 0xC000;
		int i = 0;

#if 0
		while(i < 15 && le) {
			struct transpkt *tp = le->data;

			if (tp->ts) {
				p = p | (0x1 << (14 - i));
			}
			++i;
			le = le->next;
		}
#endif
		while(i < 7 && le) {
                        struct transpkt *tp = le->data;
 
                        if (tp->ts) {
				p = p | (0x2 << (13 - i*2 - 1));
			}
				
			++i;
			le = le->next;
		}

		mbuf_write_u16(mb, htons(p));
	}

	// Add delta
	prevts = twcc->refts;
	LIST_FOREACH(&twcc->pktl, le) {
		struct transpkt *tp = le->data;

		if (tp->ts) {
			int64_t delta = tp->ts - prevts;
			//uint8_t delta8;
			uint16_t delta16;

#if DEBUG_TWCC
			info("twcc(%u): S=%d refcnt=%llu ts=%llu D=%lldms\n",
			     twcc->rssrc, tp->seqno, refcnt, tp->ts, delta);
#endif
			delta *= 4; /* small delta in 250us */

			//delta8 = delta & 0xFF;
			delta16 = delta & 0xFFFFLL;
			
			mbuf_write_u16(mb, htons(delta16));
			//mbuf_write_u8(mb, delta8);

			prevts = tp->ts;
		}
	}

	twcc->refts = twcc->now;

	return 0;
}
#endif

#if USE_RTX
static int gnack_encode_handler(struct mbuf *mb, struct nack_entry *ne)
{
	uint16_t seq = ne->seq;
	uint16_t blm = 0;
	int i;

	for (i = 0; i < ne->nlost - 1; ++i) {
		blm = blm | (1 << i);
	}

	mbuf_write_u16(mb, htons(seq));
	mbuf_write_u16(mb, htons(blm));

	return 0;
}

static void send_gnack(struct call *call, struct nack_entry *ne)
{
	struct mbuf *mb;
	int err;

	mb = mbuf_alloc(1024);
	if (!mb)
		return;
	
	err = rtcp_encode(mb,
			  RTCP_RTPFB,
			  1,
			  call->video.hi.ssrc,
			  ne->ssrc,
			  gnack_encode_handler,
			  ne);

	mediaflow_send_rtcp(call->mf, mb->buf, mb->end);

	mem_deref(mb);
}
#endif

#if 0
static void rr_handler(void *arg)
{
	struct call *call = arg;

	send_rtcp_rr(call, true);
}
#endif


static void send_rtcp_rr(struct call *call, uint32_t ssrc, uint32_t last_ntp)
{
	struct mbuf *mb;
	int err;
	uint32_t lssrc;
	struct ssrc_stats *stats = NULL;
	struct rtcp_rr rr;
	bool is_audio = false;

	if (call->audio.ssrc == 0 && call->video.hi.ssrc == 0 && call->video.lo.ssrc == 0) {
		warning("send_rtcp_rr: call(%p): no ssrc set\n", call);
		return;
	}

	if (call->audio.ssrc && ssrc == call->audio.ssrc) {
		stats = &call->audio.stats;

		is_audio = true;
	}
	else if (call->video.hi.ssrc && ssrc == call->video.hi.ssrc) {
		stats = &call->video.hi.stats;
	}
	else if (call->video.lo.ssrc && ssrc == call->video.lo.ssrc) {
		stats = &call->video.lo.stats;
	}
	if (!stats) {
		warning("send_rtcp_rr: call(%p): no stats\n", call);
		return;
	}

	lssrc = mediaflow_get_ssrc(call->mf, is_audio ? "audio" : "video", true);
		
	mb = mbuf_alloc(1024);
	if (!mb)
		return;

	calc_rr(&rr, stats);
	rr.ssrc = ssrc;
	rr.lsr = last_ntp;
	rr.dlsr = 0;

#if 0
	info("send_rtcp_rr: call(%p): lssrc=%u(ssrc=%u) "
	     "last_ntp=%08x last_seq=%d lost=%d.%d jitter=%d\n",
	     call, lssrc, ssrc, stats,
	     last_ntp, rr.last_seq, rr.fraction, rr.lost, rr.jitter);
#endif
	
	err = rtcp_encode(mb,
			  RTCP_RR,
			  1,
			  lssrc,
			  rtcp_rr_encode,
			  &rr);

	mediaflow_send_rtcp(call->mf, mb->buf, mb->end);

	mem_deref(mb);
}

#if USE_REMB
static int remb_encode_handler(struct mbuf *mb, void *arg)
{
	struct call *call = arg;

   /*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P| FMT=15  |   PT=206      |             length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  SSRC of packet sender                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  SSRC of media source                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Unique identifier 'R' 'E' 'M' 'B'                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Num SSRC     | BR Exp    |  BR Mantissa                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   SSRC feedback                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  ...                                                          |
   */
	/* REMB */
	mbuf_write_u8(mb, 'R');
	mbuf_write_u8(mb, 'E');
	mbuf_write_u8(mb, 'M');
	mbuf_write_u8(mb, 'B');

	/* 2 ssrcs with 1000kbit bandwidth */
	mbuf_write_u32(mb, htonl(0x0271312d));
	mbuf_write_u32(mb, htonl(call->twcc.rssrc));

	return 0;
}

static void remb_handler(void *arg)
{
	struct call *call = arg;
	struct mbuf *mb = NULL;
	int err;

	mb = mbuf_alloc(256);
	if (!mb) {
		SFTLOG(LOG_LEVEL_WARN, "remb_handler mbuf failed\n", call);
		goto out;
	}


	err = rtcp_encode(mb, RTCP_PSFB, RTCP_RTPFB_REMB,
			  call->twcc.lssrc,
			  0,
			  remb_encode_handler, call);
	if (err) {
		warning("remb_handler: RTCP-encode failed: %m\n", err);
		goto out;
	}

	//re_printf("mbuf(%d): %w\n", (int)mb->end, mb->buf, mb->end);

	if (call->mf)
		mediaflow_send_rtcp(call->mf, mb->buf, mb->end);

 out:
	mem_deref(mb);
	tmr_start(&call->twcc.tmr, TIMEOUT_FB, remb_handler, call);
}
#endif


#if USE_TWCC
static void twcc_handler(void *arg)	
{
	struct twcc_arg *ta = (struct twcc_arg *)arg;
	struct call *call = ta->call;
	struct twcc *twcc = ta->twcc;
	struct mbuf *mb = NULL;
	uint32_t lssrc;
	int err;

	lock_write_get(twcc->lock);

	if (list_count(&twcc->pktl) == 0) {
		//SFTLOG(LOG_LEVEL_WARN, "no twcc packets\n", call);
		goto out;
	}
	
	mb = mbuf_alloc(256);
	if (!mb) {
		SFTLOG(LOG_LEVEL_WARN, "twcc buf failed\n", call);
		goto out;
	}

	if (!ta->rssrc) {
		if (call->video.lo.ssrc) {
			ta->rssrc = call->video.lo.ssrc;
			info("twcc_handler(%p): assigning rid-lo as source: %u\n", call, ta->rssrc);
		}
		else if (call->video.hi.ssrc) {
			ta->rssrc = call->video.hi.ssrc;
			info("twcc_handler(%p): assigning rid-ho as source: %u\n", call, ta->rssrc);
		}
		else {
			ta->rssrc = call->audio.ssrc;
			info("twcc_handler(%p): assigning audio as source: %u\n", call, ta->rssrc);
		}
	}
	
	if (!ta->rssrc) {
		warning("twcc_handler(%p): no valid ssrc yet\n");
		goto out;
	}

	lssrc = mediaflow_get_ssrc(call->mf, "audio", true);
	twcc->now = tmr_jiffies();
	err = rtcp_encode(mb, RTCP_RTPFB, RTCP_RTPFB_TRANS_CC,
			  lssrc,
			  ta->rssrc,
			  twcc_encode_handler, twcc);
	if (err) {
		warning("twcc: RTCP-encode failed: %m\n", err);
		goto out;
	}

#if 0
	info("twcc_handler(%p): ssrc(%u): %w\n", call, ta->rssrc, mb->buf, mb->end);
#endif
	
	if (call->mf)
		mediaflow_send_rtcp(call->mf, mb->buf, mb->end);

 out:
	list_flush(&twcc->pktl);
	twcc->fbcnt++;

	mem_deref(mb);
	if (twcc->running)
		tmr_start(&twcc->tmr, TIMEOUT_TWCC, twcc_handler, ta);
	lock_rel(twcc->lock);
}


static void update_twcc(struct twcc *twcc,
			uint64_t ts,
			int wseq)
{
	struct transpkt *tp;

	lock_write_get(twcc->lock);
	if (!twcc->running)
		goto out;

	if (twcc->refts == 0)
		twcc->refts = ts;

	if (twcc->seqno == -1)
		twcc->seqno = wseq;

	tp = mem_zalloc(sizeof(*tp), transpkt_destructor);
	tp->seqno = wseq;
	tp->ts = ts;

	add_twcc_pkt(twcc, tp);

 out:
	lock_rel(twcc->lock);
}

#endif

static bool ssrc_isauth(struct participant *part, uint32_t ssrc)
{
	bool found = false;
	struct le *le;

	if (!ssrc)
		return false;
	
	for(le = part->authl.head; !found && le; le = le->next) {
		struct auth_part *aup = le->data;

		if (aup->ssrca && ssrc == aup->ssrca)
			found = aup->auth;
		else if (aup->ssrcv && ssrc == aup->ssrcv)
			found = aup->auth;
	}

	return found;
}

static struct participant *ssrc2part(struct list *partl, bool issft, uint32_t ssrc)
{
	struct le *le;
	bool found = false;
	struct participant *p = NULL;

	le = partl->head;
	while(le && !found) {
		p = le->data;
		le = le->next;

		found = ssrc == p->ssrca
		     || ssrc == p->ssrcv
		     || ssrc == p->simulcast.ssrcv_hi
		     || ssrc == p->simulcast.ssrcv_lo;
	}

	return found ? p : NULL;
}

static const char *ssrc2userid(struct list *partl, bool issft, uint32_t ssrc)
{
	const char *userid = NULL;
	struct le *le;
	bool found = false;

	if (issft) {
		struct participant *p = ssrc2part(partl, issft, ssrc);

		return p ? p->userid : NULL;
	}

	le = partl->head;
	while(le && !found) {
		struct participant *p = le->data;
		struct le *ale = p->authl.head;

		le = le->next;

		while(ale && !found) {
			struct auth_part *aup = ale->data;

			ale = ale->next;

			found = ssrc == aup->ssrca
			     || ssrc == aup->ssrcv;
			if (found)
				userid = aup->userid;
		}
	}

	return userid;
}


#if USE_RTX
static struct rtp_stream *video_rtx_find(struct call *call, uint32_t ssrc)
{
	struct rtp_stream *rs = NULL;
	bool found = false;
	int i;

	for(i = 0; i < call->video.rtps.c && !found; ++i) {
		rs = &call->video.rtps.v[i];
		found = ssrc == rs->ssrc;
	}

	return found ? rs : NULL;
}
#endif

static struct rtp_stream *video_stream_find(struct call *fcall,
					    struct call *call,
					    uint32_t ssrc)
{
	struct rtp_stream *rs = NULL;
	struct video_stream *vs;
	bool found = false;
	struct le *le;
	const char *userid;

	lock_write_get(call->lock);

	for(le = call->video.select.streaml.head; !found && le; le = le->next) {
		vs = le->data;

		found = ssrc == vs->ssrc;
	}
	if (!found && fcall) {
		if (!fcall->issft) {
			userid = ssrc2userid(&fcall->partl, false, ssrc);
		}
		else {
			userid = ssrc2userid(&fcall->partl, true, ssrc);
			if (!userid) {
				userid = ssrc2userid(&fcall->sft_partl,
						     true,
						     ssrc);
			}
		}
		if (!userid) {
			warning("video_stream_find(%p): no userid "
				"for ssrc=%u\n",
				call, ssrc);

			goto out;
		}
		found = false;
		for(le = call->video.select.streaml.head;
		    !found && le;
		    le = le->next) {
			vs = le->data;
			found = streq(vs->userid, userid);
		}
	}

	
	if (found) {
		vs->ssrc = ssrc; /* save off ssrc for faster lookup */
		
		if (vs->ix < call->video.rtps.c)
			rs = &call->video.rtps.v[vs->ix];

		if (rs && rs->q != vs->q) {
			rs->change = true;
			rs->old_q = rs->q;
			rs->q = vs->q;
		}
	}
 out:
	lock_rel(call->lock);

	return rs;
}


static struct rtp_stream *rtp_stream_find(struct call *call,
					  uint32_t ssrc,
					  enum rtp_stream_type rst,
					  bool kg,
					  uint8_t level)
{
	struct rtp_stream *rtpsv = NULL;
	int rtpsc = 0;
	struct rtp_stream *rs;
	enum select_mode mode;
	bool found = false;
	bool uses_kg = true;
	int i;

	switch (rst) {
	case RTP_STREAM_TYPE_AUDIO:
		rtpsv = call->audio.rtps.v;
		rtpsc = call->audio.rtps.c;
		mode = SELECT_MODE_LEVEL;
		break;

	case RTP_STREAM_TYPE_VIDEO:
		uses_kg = false;
		rtpsv = call->video.rtps.v;
		rtpsc = call->video.rtps.c;
		mode = call->video.select.mode;
		break;

	default:
		break;
	}

#if 0
	info("rtp_stream_find(%p): v=%p c=%d kg=%d uses_kg=%d\n",
	     call, rtpsv, rtpsc, kg, uses_kg);
#endif
	
	/* Key generator should always be the first stream */
	if (uses_kg && kg) {
		return &rtpsv[0];
	}

	/* Are we already sending for this ssrc? 
	 * if we are; use that stream, and update its audio level.
	 */

	for(i = uses_kg ? 1 : 0; !found && i < rtpsc; i++) {
		rs = &rtpsv[i];
		
		found = ssrc == rs->current_ssrc;
	}
	if (found)
		return rs;
	
	/* No current ssrc found check which stream to populate with */

	switch(mode) {
	case SELECT_MODE_LEVEL:
		/*
		 * NOTE: level is in -dB so lower value is HIGHER level.
		 */
		for(i = uses_kg ? 1 : 0; !found && i < rtpsc; i++) {
			rs = &rtpsv[i];
			found = level < rs->level;
		}
		break;

	default:
		break;
	}

	return found ? rs : NULL;
}

static void rtp_stream_update(struct rtp_stream *rs,
			      struct rtp_header *rtp,
			      uint8_t level)
{
	int tsdiff;
	
	switch(rs->type) {
	case RTP_STREAM_TYPE_AUDIO:
		tsdiff = 1920;
		break;

	case RTP_STREAM_TYPE_VIDEO:
		tsdiff = 9000;
		break;

	default:
		return;
	}

	if (rs->current_ssrc && rtp->ssrc == rs->current_ssrc) {
		int seqdiff = (int)rtp->seq - (int)rs->last_seq;
		rs->seq = (int)rs->seq + seqdiff;
		
		tsdiff = (int)((int64_t)rtp->ts - (int64_t)rs->last_ts);	       
		rs->ts = (uint32_t)((int64_t)rs->ts + (int64_t)tsdiff);
	}
	else {
		rs->current_ssrc = rtp->ssrc;
		rs->seq++;
		rs->ts += tsdiff;		
	}

	rs->last_seq = rtp->seq;
	rs->last_ts = rtp->ts;

	rs->level = level;
}

#if 0
static int lookup_ix(struct group *group, struct call *call)
{
	struct le *le;
	bool found = false;
	int ix = 0;

	for(le = group->calll.head; !found && le; le = le->next) {
		found = le->data == call;
		if (!found)
			ix++;
	}

	return found ? ix : 0;
}
#endif

static inline bool is_selective_stream(enum rtp_stream_type rst,
				       struct call *rcall)
{
	bool is_selective = false;

	switch(rst) {
	case RTP_STREAM_TYPE_AUDIO:
		is_selective = rcall->audio.is_selective;
		break;

	case RTP_STREAM_TYPE_VIDEO:
		is_selective = rcall->video.is_selective;
		break;

	default:
		break;
	}
	
	return is_selective;
}

#if 0
static int send_rtp(struct call *call, void *arg)
{
	struct mbuf *mb = arg;

	if (!call || !call->mf)
		return ENOSYS;
	
	mediaflow_send_rtp(call->mf, mbuf_buf(mb), mbuf_get_left(mb));

	return 0;
}
#endif

static bool exist_ssrc(struct call *call, bool ishost, uint32_t ssrc,
		       enum rtp_stream_type rst)
{
	struct le *le;
	bool found = false;

	le = ishost ? call->partl.head : call->sft_partl.head;
	while(le && !found) {
		struct participant *part = le->data;

		switch(rst) {
		case RTP_STREAM_TYPE_AUDIO:
			found = ssrc == part->ssrca;
			break;

		case RTP_STREAM_TYPE_VIDEO:
			found = ssrc == part->ssrcv
			     || ssrc == part->simulcast.ssrcv_hi
			     || ssrc == part->simulcast.ssrcv_lo;
			break;

		case RTP_STREAM_TYPE_ANY:
			found = ssrc == part->ssrca
			     || ssrc == part->ssrcv
			     || ssrc == part->simulcast.ssrcv_hi
			     || ssrc == part->simulcast.ssrcv_lo;
			break;

		default:
			break;
		}
		le = le->next;
	}

	return found;
}

static int tc_send(struct turn_conn *tc,
		   struct sa *dst, uint16_t cid,
		   uint8_t *data, size_t len)
{
	struct mbuf *mb = NULL;
	size_t hdr_len;
	int err = 0;
	
	if (!sa_isset(dst, SA_ALL)) {
		err = EINVAL;
		goto out;
	}

	hdr_len = cid ? 4 : 0;
	
	mb = mbuf_alloc(len + TURN_HEADROOM + hdr_len);
	if (!mb)
		goto out;
	
	mb->pos = TURN_HEADROOM;
	if (hdr_len > 0) {
		mbuf_write_u16(mb, htons(cid));
		mbuf_write_u16(mb, htons(len));
	}
	mbuf_write_mem(mb, data, len);
	mb->pos = TURN_HEADROOM;

#if DEBUG_PACKET
	info("tc_send(%p): sending %zu bytes to: %J(cid=%u)\n",
	     tc, len, dst, cid);
#endif
	//err = udp_send_anon(&dst, &mb);
	err = turnconn_send(tc, dst, mb);
	if (err) {
		info("tc_send: sending to: %J(cid=%u) failed: %m\n",
		     dst, cid, err);
		goto out;
	}

 out:
	mem_deref(mb);

	return err;
}


#if USE_RTX
static void jbuf_lost_handler(uint32_t ssrc, uint16_t seq, int nlost, void *arg)
{
	struct call *call = arg;
	struct nack_entry ne;

	info("jbuf_lost_handler(%p): ssrc: %u seq=%u lost=%d\n",
	     call, ssrc, seq, nlost);
	
	ne.ssrc = ssrc;
	ne.seq = seq;
	ne.nlost = nlost;
	
	send_gnack(call, &ne);
}
#endif

static void process_dd(struct call *call,
		       struct dep_desc **dd,
		       struct dep_desc_frame **frame,
		       uint8_t *buf, size_t sz)
{
	int err;
	
	err = dep_desc_read(dd, frame, buf, sz);
	if (err) {
		warning("call(%p): failed to read dd\n", call);
	}
}

static void ssrcv_timeout_handler(void *arg)
{
	struct ssrcv_update *ssu = arg;
	struct econn_message *msg = NULL;
	struct econn_stream_info *sinfo = NULL;
	struct call *call = ssu->call;
	struct call *rcall = ssu->rcall;
	int err = 0;

	msg = econn_message_alloc();
	if (!msg) {
		warning("call(%p): ssrcv_timeout_handler no message\n", call);
		goto out;
	}
	econn_message_init(msg, ECONN_CONF_STREAMS,
			   call->group ? call->group->id : "sft");
	str_ncpy(msg->dest_userid, rcall->federate.dstid,
		 ARRAY_SIZE(msg->dest_userid));
	msg->resp = true;
	sinfo = mem_zalloc(sizeof(*sinfo), NULL);
	if (!sinfo) {
		warning("call(%p): ssrcv_timeout: cannot allocate sinfo\n",
			call);
		goto out;
	}
	str_ncpy(sinfo->userid, call->userid,
		 ARRAY_SIZE(sinfo->userid));
	sinfo->quality = 0;
	str_ncpy(sinfo->ssrcv.clientid, call->clientid,
		 sizeof(sinfo->ssrcv.clientid));
	sinfo->ssrcv.hi = call->video.hi.ssrc;
	sinfo->ssrcv.lo = call->video.lo.ssrc;
	list_append(&msg->u.confstreams.streaml, &sinfo->le, sinfo);

	info("call(%p): ssrcv_timeout: hi:%u lo:%u\n", call, sinfo->ssrcv.hi, sinfo->ssrcv.lo);

	if (rcall->dc_estab) {
		err = send_dce_msg(rcall, msg);
		if (err) {
			warning("call(%p): ssrcv_timeout_handler: "
				"send_dce failed: %m\n",
				call, err);
			goto out;
		}
	}
	else if (rcall->sft_cid) {
		char *mstr;

		err = econn_message_encode(&mstr, msg);
		if (err) {
			warning("call(%p): ssrcv_timeout: failed to "
				"encode message: %m\n", call, err);
		}
		else {
			tc_send(rcall->federate.tc,
				&rcall->sft_tuple, rcall->sft_cid,
				(uint8_t *)mstr, str_len(mstr));
			mem_deref(mstr);
		}
	}

 out:
	mem_deref(msg);
	mem_deref(ssu);
}

static void ssu_destructor(void *arg)
{
	struct ssrcv_update *ssu = arg;

	mem_deref(ssu->call);
	mem_deref(ssu->rcall);
}

static void process_rtp(struct call *call,
			struct rtp_header *rtp,
			struct mbuf *mb,
			size_t hdrpos)
{
	struct group *group;
	struct le *le = NULL;
	struct rtp_header rrtp;
	size_t pos;
	size_t plpos;
	int rtpxlen;
	size_t hdrlen;
	struct ssrc_stats *stats = NULL;
	uint64_t now = tmr_jiffies();
	uint32_t ssrc = 0;
	uint8_t *rdata = NULL;
	size_t rlen = 0;
	bool kg = false;
	enum rtp_stream_type rst = RTP_STREAM_TYPE_NONE;
	//int s_ix;
	struct mbuf rmb;
	size_t len;
	uint8_t aulevel;
	bool have_parts = true;
	struct dep_desc_frame *dd_frame = NULL;
	char *rid = NULL;
	uint16_t wseq = 0;
	int err = 0;
	bool is_keyframe = false;
	bool has_gfh = false;
	struct dep_desc *dd = NULL;
	bool update_ssrcv = false;
	bool ispadding = false;
	

	group = call->group;
	//s_ix = lookup_ix(group, call);
	call->active = true;
	
	/* Clients are assumed to be alive only if they send PINGs */
	/* call->alive = true; */
	
	pos = mb->pos;
	len = mbuf_get_left(mb);
	ssrc = rtp->ssrc;

	rtpxlen = rtp->x.len * sizeof(uint32_t);
	hdrlen = hdrpos - mb->pos;
	if ((size_t)rtpxlen > hdrlen) {
		warning("process_rtp(%p): invalid extension header length\n", call);
		goto process_rtp;
	}
	mb->pos = hdrpos - rtpxlen;

#if DEBUG_PACKET
	info("RTP: %s-call(%p) len=%d hdrlen=%d m=%d ssrc=%u ts:%u seq: %d ext(%s): type=0x%04X len=%d\n",
	     call->issft ? "SFT" : "CLI", call,
	     (int)len, (int)hdrlen,
	     rtp->m, rtp->ssrc, rtp->ts, rtp->seq,
	     rtp->ext ? "yes" : "no",
	     rtp->x.type, rtpxlen);
#endif

	//info("RTP>>> %w\n", data, hdrlen + 16);
	if (rtp->x.type != 0xbede && rtp->x.type != 0x1000) {
		mbuf_advance(mb, rtpxlen);
		goto process_rtp;
	}

	/* Parse RTP extension headers (if any) */
	while(rtpxlen > 0 && mb->pos < hdrlen && mb->pos < mb->end) {
		uint8_t xid = 0;
		uint8_t xlen = 0;
		int hlen = 0;
		if (rtp->x.type == 0xbede) {
			uint8_t idlen = mbuf_read_u8(mb);
			xid = (idlen & 0xf0) >> 4;
			xlen = (idlen & 0x0f) + 1;
			hlen = sizeof(uint8_t);
		}
		else if (rtp->x.type == 0x1000) {
			xid = mbuf_read_u8(mb);
			xlen = mbuf_read_u8(mb);
			hlen = sizeof(uint16_t);
		}

		/*
		  info("RTP mpos=%d idlen=0x%02x xid=%d xlen=%d\n",
		  (int)mb.pos, idlen, xid, xlen);
		*/

		switch(xid) {
		case EXTMAP_AULEVEL:
			if (xlen == 1) {
				uint8_t a = mbuf_read_u8(mb);
				
				call->audio.level =
					audio_level_smoothen_withk(
						call->audio.level,
						(int)(a & 0x7f),
						RTP_LEVELK);
			}
			else
				mb->pos += xlen;
			break;

		case EXTMAP_VIDEO_DD: {
			struct dep_desc **pd = NULL;

			if (call->video.hi.ssrc && call->video.hi.ssrc == rtp->ssrc)
				pd = &call->video.hi.dd;
			else if (call->video.lo.ssrc && call->video.lo.ssrc == rtp->ssrc)
				pd = &call->video.lo.dd;				

			if (!pd)
				pd = &dd;

			process_dd(call, pd, &dd_frame, &mb->buf[mb->pos], xlen);
			if (dd_frame) {
#if 0
				info("call(%p): t=%d sof=%d dti.c=%d SVC [%d/%d] -> %dx%d\n",
				     call,
				     dd_frame->has_template,
				     dd_frame->sof,
				     dd_frame->dti.c,
				     dd_frame->s, dd_frame->t,
				     dd_frame->resolution.w, dd_frame->resolution.h);
#endif

				if (!is_keyframe)
					is_keyframe = dd_frame->has_template && dd_frame->sof;
			}
			dd_frame = mem_deref(dd_frame);
			mb->pos += xlen;

		}
			break;

		case EXTMAP_VIDEO_RID:
			mbuf_strdup(mb, &rid, xlen);
			break;

		case EXTMAP_VIDEO_GFH: {
			has_gfh = true;
			uint8_t gfh = mb->buf[mb->pos];

			if (!is_keyframe) {
				is_keyframe = (gfh & (GFH_MASK_SOF | GFH_MASK_DEP)) == GFH_MASK_SOF;
			}

			if (is_keyframe) {
#ifdef GFH_DEBUG				
				uint16_t frame_w = 0;
				uint16_t frame_h = 0;
				
				if (xlen >= 8)  {
					frame_w = ntohs(*(uint16_t*)((void*)&mb->buf[mb->pos + 4]));
					frame_h = ntohs(*(uint16_t*)((void*)&mb->buf[mb->pos + 6]));
				}
				info("call(%p): GFH: ssrc=%u keyframe=%d len=%d res=%dx%d\n",
				     call, ssrc, (int)is_keyframe, xlen, frame_w, frame_h);
#endif
			}
			mb->pos += xlen;
			
		}
                       break;

			
#if USE_TWCC	
		case EXTMAP_VIDEO_WSEQ:
			wseq = ntohs(mbuf_read_u16(mb));
			break;

#endif

		default:
			mb->pos += xlen;
			break;
		}
		/* 1- or 2-byte header */
		rtpxlen -= xlen + hlen;
	}

	
 process_rtp:

	if (rtp->pad) {
		size_t mbleft = mbuf_get_left(mb);
		size_t padlen = (size_t)mb->buf[len - 1];
		//info("call(%p): process_rtp_pad: len=%d pos=%d pad is %d bytes left=%d\n",
		//     call, (int)len, (int)mb->pos, (int)padlen, (int)mbleft);
		if (mbleft <= padlen)
			ispadding = true;
	}

	if (call->audio.ssrc && rtp->ssrc == call->audio.ssrc) {
		rst = RTP_STREAM_TYPE_AUDIO;

		stats = &call->audio.stats;
	}
	else if (!call->issft) {
		if (0 == call->video.hi.ssrc ) {
			//info("call(%p): no hi video current rid=%s\n", call, rid ? rid : "???");
			if (rid && streq(rid, RID_HI)) {
				info("call(%p): assigning ssrc=%u to rid-hi\n", call, rtp->ssrc);
				call->video.hi.ssrc = rtp->ssrc;
				if (0 == call->twcc.rssrc)
					call->twcc.rssrc = rtp->ssrc;
				update_ssrcv = true;
			}
			if (dd) {
				call->video.hi.dd = mem_ref(dd);
			}
		}
		if (0 == call->video.lo.ssrc) {
			//info("call(%p): no lo video current rid=%s\n", call, rid ? rid : "???");
			if (rid && streq(rid, RID_LO)) {
				info("call(%p): assigning ssrc=%u to rid-lo\n", call, rtp->ssrc);
				call->video.lo.ssrc = rtp->ssrc;
				if (0 == call->twcc.rssrc)
					call->twcc.rssrc = rtp->ssrc;
				update_ssrcv = true;
			}
			if (dd) {
				call->video.lo.dd = mem_ref(dd);
			}
		}
		
		if (call->video.hi.ssrc && rtp->ssrc == call->video.hi.ssrc) {
			call->video.started = true;
			rst = RTP_STREAM_TYPE_VIDEO;
			stats = &call->video.hi.stats;
			if (!ispadding)
				call->video.hi.ts = now;
		} else if (call->video.lo.ssrc && rtp->ssrc == call->video.lo.ssrc) {
			call->video.started = true;
			rst = RTP_STREAM_TYPE_VIDEO;
			stats = &call->video.lo.stats;
		}
	}

#if USE_TWCC
	if (!call->twcc.running && !call->issft) {
		call->twcc.ta.call = call;
		call->twcc.ta.twcc = &call->twcc;
		call->twcc.ta.rssrc = 0;
		call->twcc.running = true;
		tmr_start(&call->twcc.tmr, TIMEOUT_TWCC,
			  twcc_handler, &call->twcc.ta);
	}
	if (wseq && !call->issft) {
		update_twcc(&call->twcc, now, wseq);
	}
#endif

	mem_deref(dd);
	
	if (call->issft) {
		bool ishost = group ? group->sft.ishost : false;
		
		if (exist_ssrc(call, ishost, rtp->ssrc,
			       RTP_STREAM_TYPE_AUDIO)) {
		    rst = RTP_STREAM_TYPE_AUDIO;
		}
		else {
			/* Assume it is video, since it can be multiple
			 * ssrcs due to simulcast
			 */
		    rst = RTP_STREAM_TYPE_VIDEO;
		}
	}

	
	if (!call->issft && stats) {
		update_ssrc_stats(stats, rtp, now);
	}

#if USE_REMB
	if (rst == RTP_STREAM_TYPE_VIDEO) {
		if (!tmr_isrunning(&twcc->tmr)) {
			tmr_start(&twcc->tmr, TIMEOUT_FB,
				  remb_handler, call);
		}
	}
#endif

	/* Don't forward packets that contain only padding */
	if (ispadding) {
		goto out;
	}
	
	/* If we are the first in the group list (aka KeyGenerator)
	 * always forward packet iregardless of audio level.
	 */
	if (group && call == list_ledata(group->calll.head)) {
		if (!call->issft)
			kg = true;
		/* continue forwarding */
	}

	aulevel = call->audio.level;

	/* make buffer that will have 1 CSRC */
	rlen = len + sizeof(uint32_t);	 		
	rdata = mem_alloc(rlen, NULL);

	/* Copy fixed part of header */
	plpos = mb->pos + sizeof(uint32_t);
	mb->pos = pos;
	err = mbuf_read_mem(mb, rdata, RTP_HEADER_SIZE);
	if (err)
		goto out;

	/* Set CC to 1 */
	rdata[0] = rdata[0] | 0x1;
	err = mbuf_read_mem(mb,
			    rdata + RTP_HEADER_SIZE + sizeof(uint32_t),
			    len - RTP_HEADER_SIZE);
	if (err)
		goto out;

	rmb.buf = rdata;
	rmb.pos = 0;
	rmb.size = rlen;
	rmb.end = rmb.size;

	err = rtp_hdr_decode(&rrtp, &rmb);
	if (err)
		goto out;

	/* Reset data to start of packet */
	mb->pos = pos;

	// Send same packet to all members of this group
	have_parts = true;
	
#if DEBUG_PACKET
	info("forwarding %u RTP packet to %d parts\n",
	     ssrc, list_count(&call->partl));
#endif

	while(have_parts) {
		struct participant *part;
		struct participant *rpart;
		struct call *rcall;
		bool is_selective;

		lock_write_get(g_sft->lock);
		{
			
			if (!le)
				le = call->partl.head;
			else
				le = le->next;
			if (!le) {
				have_parts = false;
				lock_rel(g_sft->lock);
				continue;
			}
			part = le->data;
			rcall = part ? mem_ref(part->call) : NULL;
		}
		lock_rel(g_sft->lock);

		if (!part || !rcall)
			continue;

		is_selective = is_selective_stream(rst, rcall);

#if DEBUG_PACKET
		info("ssrc(%u): sel: %d aulevel: %d %s-rcall: %p[%p]\n",
		     ssrc, is_selective, aulevel,
		     rcall->issft ? "SFT" : "CLI", rcall, rcall->mf);
#endif
		if (rcall->issft) {
			if (update_ssrcv) {
				struct ssrcv_update *ssu;

				ssu = mem_zalloc(sizeof(*ssu), ssu_destructor);
				if (ssu) {
					ssu->call = mem_ref(call);
					ssu->rcall = mem_ref(rcall);
					tmr_start(&call->video.tmr_ssrcv, 0,
						  ssrcv_timeout_handler, ssu);
				}
			}
		}

		if (is_selective) {
			if ((rst == RTP_STREAM_TYPE_AUDIO && !kg)
			 || (rst == RTP_STREAM_TYPE_VIDEO
			    && rcall->video.select.mode == SELECT_MODE_LEVEL)) {
				if (aulevel >= AUDIO_LEVEL_SILENCE) {
					if (RTP_STREAM_TYPE_AUDIO == rst) {
						struct rtp_stream *rs;

						/* The level from this user has gone below the
						 * silence level, we should remove them from the
						 * streams, if one is assigned to them
						 */
						rs = rtp_stream_find(rcall, ssrc, rst, kg, aulevel);
						if (rs) {
							rs->current_ssrc = 0;
							rs->level = AUDIO_LEVEL_ABS_SILENCE;
						}
					}
					deref_locked(rcall);
					continue;
				}
			}
		}

		if (!call->issft && !rcall->issft) {
			/* Lookup this participant in remote list,
			 * so we are sure that both sides have
			 * authorized each other
			 */
			rpart = call2part(part->call,
					  call->userid, call->clientid);
			if (!rpart) {
				warning("part: %s.%s not found for part: "
					"%s.%s\n",
					call->userid, call->clientid,
					part->call->userid,
					part->call->clientid);

				deref_locked(rcall);
				continue;
			}

			if (!part->auth || !rpart->auth
			    || !ssrc_isauth(part, rst == RTP_STREAM_TYPE_VIDEO ? call->video.ssrc : ssrc)) {
				deref_locked(rcall);
				continue;
			}
		}

		if (!is_selective) {
#if DEBUG_PACKET			
			info("RTP_RX: to-%s non-selective: "
			     "sending rcall=%p[%p]\n",
			     rcall->issft ? "SFT" : "CLI", rcall, rcall->mf);
#endif
			if (rcall->mf) {
				mediaflow_send_rtp(rcall->mf,
						   mbuf_buf(mb), len);
			}
			else if (rcall->issft
				 && sa_isset(&rcall->sft_tuple, SA_ADDR)
				 && rcall->sft_cid) {
#if DEBUG_PACKET
				info("RTP_RX: sending to SFT-tc: "
				     "%p --> %J/%u\n",
				     rcall->federate.tc,
				     &rcall->sft_tuple,
				     rcall->sft_cid);
#endif

				tc_send(rcall->federate.tc,
					&rcall->sft_tuple, rcall->sft_cid,
					mbuf_buf(mb), len);
			}
		}
		else {
			struct rtp_stream *rs;
			bool skip = false;
			uint32_t ssrcv;
			uint32_t ssrcv_hi;
			uint32_t ssrcv_lo;
			bool has_hi = false;
			uint64_t fdiff;

			if (call->issft) {
				bool ishost = group ? group->sft.ishost : false;
				struct list *partl = ishost ? &call->partl : &call->sft_partl;
				struct participant *p;

				p = ssrc2part(partl, call->issft, ssrc);
				if (p) {
					ssrcv = p->ssrcv;
					ssrcv_hi = p->simulcast.ssrcv_hi;
					ssrcv_lo = p->simulcast.ssrcv_lo;
				}
			}
			else {
				ssrcv = call->video.ssrc;
				ssrcv_hi = call->video.hi.ssrc;
				ssrcv_lo = call->video.lo.ssrc;
				fdiff = call->screenshare ? TIMEOUT_SCREENSHARE_HI_FRAME
					                  : TIMEOUT_VIDEO_HI_FRAME;
				has_hi = (now - call->video.hi.ts) < fdiff;
			}

			if (rst == RTP_STREAM_TYPE_VIDEO
			    && rcall->video.select.mode == SELECT_MODE_LIST) {

				rs = video_stream_find(call, rcall, ssrcv);

				if (!rs) {
					warning("process_rtp: call(%p): no video ssrc=%u\n", call, ssrc);
				}
				else {
					enum video_stream_q q = rs->q;
					
					if (rs->change) {
						if (!has_gfh || is_keyframe) {
							q = rs->q;
							rs->change = false;
						}
						else {
							q = rs->old_q;
						}
					}

					switch (q) {
					case VIDEO_STREAM_Q_ANY:
					case VIDEO_STREAM_Q_HI:
						if (has_hi) {
							if (ssrcv_hi && ssrc != ssrcv_hi)
								skip = true;
							else {
								//info("process_rtp: rcall(%p) hi-res ssrc=%u\n", rcall, ssrc);
							}
						}
						else {
							if (ssrcv_lo && ssrc != ssrcv_lo)
								skip = true;
							else {
								info("process_rtp: rcall(%p) reverting to lo-res fdiff=%llu ssrc=%u\n",
								     rcall, fdiff, ssrc);
							}

						}
						break;

					case VIDEO_STREAM_Q_LO:
						if (ssrcv_lo && ssrc != ssrcv_lo)
							skip = true;
						break;

					}

					//info("process_rtp(%p): change=%d q=%d ssrc=%u skip=%d\n", call, rs->change, q, ssrc, skip);
				}
			}
			else {
				rs = rtp_stream_find(rcall, ssrc, rst,
						     kg, aulevel);
			}
			
			if (!rs || skip) {
				deref_locked(rcall);
				continue;
			}

			rtp_stream_update(rs, rtp, aulevel);
					
			/* Modify the RTP header with the
			 * RTP stream info
			 */
			rrtp.seq = rs->seq;
			rrtp.ts = rs->ts;

#if DEBUG_PACKET
			info("ssrc: %u/%08x -> %u/%08x type=%d seq=%u ts=%u\n",
			     rs->ssrc, rs->ssrc, ssrc, ssrc, rst,
			     rrtp.seq, rrtp.ts);
#endif
				
			rrtp.ssrc = rs->ssrc;
			/* Add this packet's ssrc as the
			 * contributing source
			 */
			rrtp.cc = 1;
			if (rst == RTP_STREAM_TYPE_AUDIO) {
				rrtp.csrc[0] = ssrc;
			}
			else {
				rrtp.csrc[0] = ssrcv;
			}

			rmb.pos = 0;
			err = rtp_hdr_encode(&rmb, &rrtp);
			if (err)
				continue;

			rmb.pos = 0;

#if DEBUG_PACKET
			info("RTP_RX: selective: sending rcall=%p[%p] issft:%d\n",
			     rcall, rcall->mf, rcall->issft);
#endif
			if (rcall->issft
			    && sa_isset(&rcall->sft_tuple, SA_ADDR)
			    && rcall->sft_cid) {
#if DEBUG_PACKET
				info("RTP_RX: sending to tc: %p --> %J/%u\n",
				     rcall->federate.tc, &rcall->sft_tuple, rcall->sft_cid);
#endif
				tc_send(rcall->federate.tc,
					&rcall->sft_tuple, rcall->sft_cid,
					(uint8_t *)rdata, rlen);
			}
			else if (rcall->mf) {
				if (!rcall->issft && rst == RTP_STREAM_TYPE_VIDEO) {
#if USE_RTX
					gnack_add_payload(rcall, &rs->rtx, rtp,
							  rdata, rlen, plpos - pos);
#endif
				}

				mediaflow_send_rtp(rcall->mf, rdata, rlen);
			}
		}
		deref_locked(rcall);
	}

 out:
	mem_deref(rid);
	mem_deref(rdata);
}

 static void process_rtx(struct call *call, struct rtp_header *rtp, struct mbuf *mb, size_t hdrpos)
 {
	 /* We need to re-construct the real RTP packet */
	 struct mbuf *real_mb;
	 struct rtp_header real_rtp;
	 size_t hdrlen;
	 uint16_t seq = ntohs(*(uint16_t *)((void*)&mb->buf[hdrpos]));
	 int err = 0;

	 info("process_rtx(%p): ssrc=%u seq=%u\n", call, rtp->ssrc, seq);

	 rtp->pt = PT_VP8;
	 rtp->ssrc = call->video.hi.ssrc;
	 rtp->seq = seq;
	 hdrlen = hdrpos - mb->pos;
	 
	 real_mb = mbuf_alloc(mbuf_get_left(mb));
	 err = rtp_hdr_encode(real_mb, rtp);
	 if (err) {
		 warning("process_rtx(%p): failed to encode RTP header: %m\n",
			 call, err);
		 goto out;
	 }
	 mbuf_write_mem(real_mb,
			&mb->buf[mb->pos + RTP_HEADER_SIZE],
			hdrlen - RTP_HEADER_SIZE);
	 mbuf_write_mem(real_mb,
			&mb->buf[hdrpos + sizeof(uint16_t)],
			mb->end - (hdrpos + sizeof(uint16_t)));
	 
	 real_mb->pos = 0;
	 err = rtp_hdr_decode(&real_rtp, real_mb);
	 if (err) {
		 warning("process_rtx(%p): could not decode real header: %m\n",
			 call, err);
		 goto out;
	 }
	 real_mb->pos = 0;

	 process_rtp(call, &real_rtp, real_mb, hdrlen);

 out:
	 mem_deref(real_mb);
 }

 
static void reflow_rtp_recv(struct mbuf *mb, void *arg)
{
	struct call *call = arg;
	struct rtp_header rtp;
	size_t pos;
	size_t hdrpos;
	bool has_frames = true;	
	int err = 0;

	if (!mb)
		return;

	pos = mb->pos;
	err = rtp_hdr_decode(&rtp, mb);
	if (err)
		return;

	hdrpos = mb->pos;
	mb->pos = pos;

	if (rtp.pt == PT_RTX)  {
		process_rtx(call, &rtp, mb, hdrpos);
		return;
	}
	else { 
		process_rtp(call, &rtp, mb, hdrpos);
		return;
	}

#if USE_RTX
	jb_put(call->video.jb, &rtp, mb);
	while(has_frames) {
		struct mbuf *new_mb;

		err = jb_get(call->video.jb, &rtp,
			     jbuf_lost_handler,
			     (void **)&new_mb, call);
		has_frames = err == 0;
		if (!err)  {
			process_rtp(call, &rtp, new_mb, hdrpos);
			mem_deref(new_mb);
		}
	}
#else
	(void)has_frames;
#endif
}

#if USE_RTX
static void rtx_send_handler(struct call *call,
			     struct gnack_rtx_stream *rs,
			     struct list *rtxl)
{
	struct le *le;

	LIST_FOREACH(rtxl, le) {
		struct gnack_rtx *rtx = le->data;
		struct mbuf mb;
		struct rtp_header rtp;

		mb.buf = rtx->plb;
		mb.pos = 0;
		mb.end = mb.size = rtx->pllen;
		rtp_hdr_decode(&rtp, &mb);

#if 0
		info("rtx_send: pt=%d seq=%d ssrc=%u ts=%u len=%u OSN[%d]=%d\n",
		     rtp.pt, rtp.seq, rtp.ssrc, rtp.ts, rtx->pllen,
		     rtx->plpos, ntohs(*(uint16_t *)((void*)&rtx->plb[rtx->plpos])));
#endif

		mediaflow_send_rtp(call->mf, rtx->plb, rtx->pllen);
	}
}
#endif


static void reflow_rtcp_recv(struct mbuf *mb, void *arg)
{
	struct call *call = arg;
	struct rtcp_msg *rtcp;
	int err;

	err = rtcp_decode(&rtcp, mb);
	if (err) {
		SFTLOG(LOG_LEVEL_WARN, "cannot decode RTCP packet\n", call);
		goto out;
	}

#if DEBUG_PACKET
	SFTLOG(LOG_LEVEL_INFO, "RTCP %H\n", call, rtcp_msg_print, rtcp);
#endif

	switch (rtcp->hdr.pt) {
	case RTCP_RTPFB:
		switch (rtcp->hdr.count) {				
#if USE_RTX
		case RTCP_RTPFB_GNACK: {
			struct rtp_stream *rs;
			uint32_t ssrc = rtcp->r.fb.ssrc_media;

			rs = video_rtx_find(call, ssrc);
			if (rs) {
				gnack_handler(call, &rs->rtx, rtx_send_handler, rtcp);
			}
			else {
				warning("rtcp(%p): gnack on unknown stream: ssrc=%u\n", call, ssrc);
			}
		}
			break;
#endif
		default:
			break;
		}
		break;

	case RTCP_SR: {
		struct rtcp_rr *sr;
		uint32_t srsrc = rtcp->r.sr.ssrc;
		uint32_t last_ntp;

		sr = rtcp->r.sr.rrv;
#if 0
		info("call(%p): RTCP-SR on ssrc: %u/%u ntp=%08x:%08x\n",
		     call, rtcp->r.sr.ssrc, sr->ssrc, rtcp->r.sr.ntp_sec, rtcp->r.sr.ntp_frac);
#endif
		last_ntp = ((rtcp->r.sr.ntp_sec & 0xffff) << 16)
			| ((rtcp->r.sr.ntp_frac & 0xffff0000) >> 16);
		
		send_rtcp_rr(call, srsrc, last_ntp);
	}
		break;
	}

	mem_deref(rtcp);

 out:
	return;

}


static void sft_http_resp_handler(int err, const struct http_msg *msg,
				  void *arg)
{
	struct sft_req_ctx *ctx = arg;
	const uint8_t *buf = NULL;
	int sz = 0;

	info("sft_resp: done err %d, %d bytes to send\n",
	     err, ctx->mb_body ? (int)ctx->mb_body->end : 0);
	if (err == ECONNABORTED)
		goto error;

	if (ctx->mb_body) {
		mbuf_write_u8(ctx->mb_body, 0);
		ctx->mb_body->pos = 0;

		buf = mbuf_buf(ctx->mb_body);
		sz = mbuf_get_left(ctx->mb_body);
	}

	if (buf) {
		info("sft_resp: msg %s\n", buf);
		if (buf[0] == '<') {
			uint8_t *c = (uint8_t*)strstr((char*)buf, "<title>");
			int errcode = 0;

			if (c) {
				c += 7;
				while (c - buf < sz && *c >= '0' && *c <= '9') {
					errcode *= 10;
					errcode += *c - '0';
					c++;
				}

				warning("sft_resp_handler: HTML error code %d\n", errcode);
				err = EPROTO;
				goto error;
			}
		}
	}
#if 0
	err = econn_message_decode(&cmsg, 0, 0, buf, sz);
	if (err) {
		warning("sft_http_resp_handler: failed to parse message: %m\n",
			err);
		goto error;
	}

	ecall_msg_recv((struct ecall *)call->provisional.icall,
		       0, 0,
		       cmsg->src_userid,
		       cmsg->src_clientid,
		       cmsg);
#endif
	
 error:
	if (!err)
		ctx->call->isprov = false;
	
	mem_deref(ctx);
}


static int sft_http_data_handler(const uint8_t *buf, size_t size,
				 const struct http_msg *msg, void *arg)
{
	struct sft_req_ctx *ctx = arg;
	bool chunked;
	int err = 0;

	chunked = http_msg_hdr_has_value(msg, HTTP_HDR_TRANSFER_ENCODING,
					 "chunked");
	if (!ctx->mb_body) {
		ctx->mb_body = mbuf_alloc(1024);
		if (!ctx->mb_body) {
			err = ENOMEM;
			goto out;
		}
	}

	/* append data to the body-buffer */
	err = mbuf_write_mem(ctx->mb_body, buf, size);
	if (err)
		return err;


 out:
	return err;
}

static void ctx_destructor(void *arg)
{
	struct sft_req_ctx *ctx = arg;

	mem_deref(ctx->call);
	mem_deref(ctx->mb_body);
	mem_deref(ctx->http_req);
}


static int send_provisional_http(struct call *call,
				 const uint8_t *data, size_t len)
{
	struct sft_req_ctx *ctx;
	const char *base_url;
	char url[256];
	char origin[256];
	int err;

	if (!call->http_cli) {
		err = http_client_alloc(&call->http_cli, avs_service_dnsc());
		if (err) {
			warning("send_provisional: HTTP client failed: %m.\n",
				err);
			goto out;
		}
	}

	ctx = mem_zalloc(sizeof(*ctx), ctx_destructor);
	if (!ctx) {
		err = ENOMEM;
		goto out;
	}

	ctx->call = mem_ref(call);
	base_url = call->origin_url ? call->origin_url
		                    : avs_service_federation_url();
	snprintf(url, sizeof(url), "%s/sft/%s", base_url, call->callid);

	info("send_provisional_http: sending HTTP request to "
	     "%s on client: %p\n", url, call->http_cli);

	re_snprintf(origin, sizeof(origin),
		    "http://%J",
		    avs_service_sft_req_addr());
	err = http_request(&ctx->http_req,
			   call->http_cli,
			   "POST",
			   url,
			   sft_http_resp_handler,
			   sft_http_data_handler,
			   ctx, 
			   "Accept: application/json\r\n"
			   "Origin: %s\r\n"
			   "Content-Type: application/json\r\n"
			   "Content-Length: %zu\r\n"
			   "User-Agent: sft\r\n"
			   "\r\n"
			   "%b",
			   origin,
			   len, data, len);
	if (err) {
		warning("send_provisional_http: failed to send request: %m\n",
			err);
	}

 out:
	return err;
}

static int send_provisional(struct call *call,
			    struct econn_message *msg)
{
	struct group *group;
	char *data;
	int err;

	info("send_provisional(%p): prov=%d sessid=%s sft_url=%s sft_tuple=%j(cid=%u) msg=%H\n",
	     call, call->isprov, call->sessid, call->sft_url, &call->sft_tuple, call->sft_cid,
	     econn_message_brief, msg);

	if (call->sessid) {
		str_ncpy(msg->sessid_sender, call->sessid,
			 ARRAY_SIZE(msg->sessid_sender));
	}
		
	err = econn_message_encode(&data, msg);
	if (err)
		return err;

	group = call->group;
	if (call->isprov) {
		if (sa_isset(&call->sft_tuple, SA_ADDR)) {
			tc_send(call->federate.tc,
				&call->sft_tuple, call->sft_cid,
				(uint8_t *)data, str_len(data));
		}
		else {
			send_provisional_http(call,
					      (const uint8_t *)data,
					      str_len(data));
		}
	}
	else {
		assign_task(call, send_dce_msg, data, true);
	}
	
	mem_deref(data);

	return err;
}

static void pm_destructor(void *arg)
{
	struct pending_msg *pm = arg;

	list_unlink(&pm->le);
	mem_deref(pm->msg);
	mem_deref(pm->call);
}

static char *sft_tuple(struct call *call, struct group *group)
{
	const size_t slen = 512;
	char *tuple;
	uint16_t cid;

	cid = turnconn_lcid(group->federate.tc);

	if (!cid)
		str_dup(&tuple, group->federate.relay_str);
	else {		
		tuple = mem_zalloc(slen, NULL);
		info("sft_tuple: tuple=%p cid=%u\n", tuple, cid);
		if (!tuple)
			return NULL;

		re_snprintf(tuple, slen, "%s/%u",
			    group->federate.relay_str,
			    cid);
	}

	return tuple;
}


static int icall_send_handler(struct icall *icall,
			      const char *userid_sender,
			      struct econn_message *msg,
			      struct list *targets,
			      bool my_clients_only,
			      void *arg)
{
	struct call *call = arg;
	struct group *group;
	const char *convid;
	int err = 0;

	(void)targets;
	(void)my_clients_only;

	group = call ? call->group : NULL;

	SFTLOG(LOG_LEVEL_INFO,
	       "icall: %p/%p(issft:%d/isprov:%d) userid: %s "
	       "sft_tuple: %J(cid=%u) msg: %H\n",
	       call,
	       icall, call->icall, call->issft, call->isprov,
	       userid_sender,
	       &call->sft_tuple,
	       call->sft_cid,
	       econn_message_brief, msg);

	/* Override the sessid with the convid associated
	 * with this client's group
	 */
	convid = call->group ? call->group->id : NULL;
	if (convid) {
		str_ncpy(msg->sessid_sender, convid,
			 ARRAY_SIZE(msg->sessid_sender));
	}
	if (msg->msg_type == ECONN_SETUP) {
		if (call->sft->url) {
			msg->u.setup.url = mem_deref(msg->u.setup.url);
			str_dup(&msg->u.setup.url, call->sft->url);
		}
		if (group && group->federate.tc && group->federate.isready) {
			msg->u.setup.sft_tuple =
				mem_deref(msg->u.setup.sft_tuple);

			msg->u.setup.sft_tuple = sft_tuple(call, group);

			info("call(%p): setting tuple: %s\n", call, msg->u.setup.sft_tuple);
		}
		
		/* In the case the call is in update state
		 * we will need to convert a SETUP to an UPDATE
		 */
		if (call->update) {
			msg->msg_type = ECONN_UPDATE;
		}
	}

	if (err) {
		if (call->hconn) {
			http_ereply(call->hconn, 500, "Internal error");
			call->hconn = mem_deref(call->hconn);
		}
	}
	else {
		if (group && group->federate.tc && !group->federate.isready) {
			struct pending_msg *pm;

			pm = mem_zalloc(sizeof(*pm), pm_destructor);
			if (pm) {
				pm->call = mem_ref(call);
				econn_message_encode(&pm->msg, msg);

				list_append(&group->federate.pendingl,
					    &pm->le, pm);
			}
		}
		else {
			err = send_sft_msg(call, msg, 0);
		}
	}

	return err;
}


static void icall_start_handler(struct icall *icall,
				uint32_t msg_time,
				const char *userid_sender,
				const char *clientid_sender,
				bool video,
				bool should_ring,
				enum icall_conv_type conv_type,
				void *arg)
{
	struct call *call = arg;
	enum icall_call_type call_type;
	struct ecall *ecall = (struct ecall *)call->icall;

	SFTLOG(LOG_LEVEL_INFO, "\n", call);

	call_type = video ? ICALL_CALL_TYPE_VIDEO : ICALL_CALL_TYPE_NORMAL;
	if (call->issft) {
		ecall_set_sessid(ecall, call->sessid);
		ecall_set_propsync_handler(ecall, ecall_propsync_handler);	
		ICALL_CALLE(call->icall, answer, call_type, true);
	}
}

static void icall_answer_handler(struct icall *icall, void *arg)
{
	struct call *call = arg;
	
	SFTLOG(LOG_LEVEL_INFO, "\n", call);
	if (tmr_isrunning(&call->tmr_setup))
		tmr_cancel(&call->tmr_setup);
}

#if 0
static void icall_media_estab_handler(struct icall *icall,
				   const char *userid,
				   const char *clientid,
				   bool update,
				   void *arg)
{
	struct call *call = arg;

	SFTLOG(LOG_LEVEL_INFO, "\n", call);
}
#endif

static void icall_audio_estab_handler(struct icall *icall,
				      const char *userid,
				      const char *clientid,
				      bool update,
				      void *arg)
{
	struct call *call = arg;
	
	SFTLOG(LOG_LEVEL_INFO, "\n", call);
}


static int send_sft_msg(struct call *call, struct econn_message *msg,
			int status)
{
	char *data = NULL;
	int err = 0;

	if (0 == status && call->issft && call->isprov) {
		send_provisional(call, msg);
	}
	else if (call->hconn) {
		if (status) {
			http_ereply(call->hconn, status, "Internal error");
		}
		else {
			err = econn_message_encode(&data, msg);
			if (err)
				goto out;

			info("send_sft_msg(%p): on hconn: %p\n",
			     call, call->hconn);
			http_creply(call->hconn, 200, "OK", "application/json",
				    "%s", data);
			mem_deref(data);
		}

		call->hconn = mem_deref(call->hconn);
	}

 out:
	return err;
}
	

static int send_dce_msg(struct call *call, void *arg)
{
	struct econn_message *msg = arg;
	int err;

	SFTLOG(LOG_LEVEL_INFO, "%H\n", call, econn_message_brief, msg);

	if (call->dc_estab)
		err = ecall_dce_sendmsg((struct ecall *)call->icall, msg);
	else {
		warning("send_dce_msg(%p): no datachannel\n", call);
		err = 0;
	}

	return err;
}

static int send_conf_conn(struct call *call, bool resp,
			  const char *sessid,
			  const char *srcid,
			  const char *dstid)
{
	struct group *group = call->group;
	struct econn_message *msg;
	int err = 0;

	if (!group)
		return EINVAL;

	if (!call->dc_estab && !call->sft_cid)
		return 0;
	
	msg = econn_message_alloc();
	if (!msg) {
		err = ENOMEM;
		goto out;
	}

	econn_message_init(msg, ECONN_CONF_CONN, sessid ? sessid : group->id);

	msg->resp = resp;
	if (0 == call->sft_cid) {
		assign_task(call, send_dce_msg, msg, false);
	}
	else {
		char *rstr = NULL;

		if (srcid)
			str_ncpy(msg->src_userid, srcid, sizeof(msg->src_userid));
		if (dstid)
			str_ncpy(msg->dest_userid, dstid, sizeof(msg->dest_userid));

		err = econn_message_encode(&rstr, msg);
		if (!err) {
			tc_send(group->federate.tc,
				&call->sft_tuple, call->sft_cid,
				(uint8_t *)rstr, str_len(rstr));
		}

		mem_deref(rstr);
	}

 out:
	mem_deref(msg);

	return 0;
}

static bool part_sort_handler(struct le *le1, struct le *le2, void *arg)
{
	struct econn_group_part *p1 = le1->data;
	struct econn_group_part *p2 = le2->data;

	(void)arg;

	return p1->ts <= p2->ts;
}


static int send_conf_part(struct call *call, uint64_t ts,
			  uint8_t *entropy, size_t entropylen,
			  bool include_self, bool resp)
{
	struct group *group = call->group;
	struct econn_message *msg;
	struct le *le;
	size_t n;
	int err = 0;

	if (!group)
		return EINVAL;

	if (!call->dc_estab && !call->sft_cid)
		return 0;
	
	msg = econn_message_alloc();
	if (!msg)
		return ENOMEM;

	econn_message_init(msg, ECONN_CONF_PART, "");

	msg->resp = resp;
	msg->u.confpart.timestamp = ts;
	msg->u.confpart.seqno = g_sft->seqno++;
	//msg->u.confpart.seqno = group->seqno;

	/* Generate entropy */
	if (entropy && entropylen) {
		msg->u.confpart.entropy = mem_ref(entropy);
		msg->u.confpart.entropylen = (uint32_t)entropylen;
	}
	
	n = list_count(&group->calll);

	if (n == 1) {
		if (group->started) {
			msg->u.confpart.should_start = false;
		}
		else {
			if (call->sft_url) {
				msg->u.confpart.should_start = false;
			}
			else {
				msg->u.confpart.should_start = true;
			}
			group->started = true;
		}
	}
	stringlist_append(&msg->u.confpart.sftl, g_sft->url);

	info("send_conf_part: group(%p)->calll has: %u elements ishost: %d\n",
	     group, (uint32_t)list_count(&group->calll), group->sft.ishost);
	
	LIST_FOREACH(&group->calll, le) {
		struct call *pcall = le->data;
		struct econn_group_part *part;

		if (!pcall || (!pcall->mf && !pcall->sft_cid))
			continue;

		if (!pcall->dc_estab && !pcall->sft_cid)
			continue;

		info("send_conf_part: group(%p)->pcall(%p) issft:%d\n", group, pcall, pcall->issft);
		/* only host SFTs collate participants */
		if (pcall->issft && !group->sft.ishost)
			continue;

		if (pcall->issft) {
			struct le *rle;

			info("send_confpart: call=%p pcall=%d include_self=%d\n", call, pcall, include_self);

			if (pcall->federate.url) {
				stringlist_append(&msg->u.confpart.sftl,
						  pcall->federate.url);
			}
			if (!include_self && pcall == call)
				continue;

			info("send_confpart: pcall(%p)->partl=%u\n", pcall, (uint32_t)list_count(&pcall->partl));
			LIST_FOREACH(&pcall->partl, rle) {
				struct participant *rpart = rle->data;

				/* The client populated participants, do NOT
				 * have a call associated with them, 
				 * we only want to add those, and not ourself
				 */
				if (rpart->call)
					continue;

				info("send_confpart: adding SFT(%p) ix=%lu "
				     "rpart:%p/%p %s/%s\n",
				     pcall, rpart->ix, rpart, rpart->call,
				     rpart->userid, rpart->clientid);
				
				part = econn_part_alloc(rpart->userid,
							rpart->clientid);
				if (!part) {
					err = ENOMEM;
					goto out;
				}
				part->ssrca = rpart->ssrca;
				part->ssrcv = rpart->ssrcv;

				part->authorized = false;
				part->muted_state = MUTED_STATE_UNMUTED;
				part->ts = rpart->ix;// - group->start_ts;

				list_append(&msg->u.confpart.partl,
					    &part->le, part);
			}
			continue;
		}

#if 0
		info("send_confpart: adding CLIENT call:%p part_ix=%lu %s/%s video_ssrc=%u\n",
		     pcall, pcall->part_ix, pcall->userid, pcall->clientid, pcall->video.ssrc);
#endif
		part = econn_part_alloc(pcall->userid, pcall->clientid);
		if (!part) {
			err = ENOMEM;
			goto out;
		}
		if (pcall->mf) {
			part->ssrca = mediaflow_get_ssrc(pcall->mf,
							 "audio", false);
			if (pcall->issft || (pcall->ver.major > 0 && pcall->ver.major < 10)) {
				part->ssrcv = mediaflow_get_ssrc(pcall->mf, "video", false);
			}
			else {
				part->ssrcv = pcall->video.ssrc;
			}
		}
		part->authorized = false;
		part->muted_state =
			pcall->muted ? MUTED_STATE_MUTED : MUTED_STATE_UNMUTED;
		part->ts = pcall->part_ix; //pcall->join_ts - group->start_ts;

		list_append(&msg->u.confpart.partl, &part->le, part);
	}

	n = list_count(&msg->u.confpart.partl);
	SFTLOG(LOG_LEVEL_INFO,
	       "icall: %p %s.%s: with %d parts should_start=%d\n",
	       call, call->icall,
	       call->userid, call->clientid,
	       n,
	       msg->u.confpart.should_start);

	if (group->sft.ishost)
		list_sort(&msg->u.confpart.partl, part_sort_handler, NULL);

	if (n > 0) {
		if (call->dc_estab)
			assign_task(call, send_dce_msg, msg, false);
		else if (call->sft_cid) {
			char *mstr = NULL;

			str_ncpy(msg->sessid_sender, call->group->id,
				 ARRAY_SIZE(msg->sessid_sender));
			str_ncpy(msg->src_userid, call->callid,
				 ARRAY_SIZE(msg->src_userid));
			str_ncpy(msg->dest_userid, call->federate.dstid,
				 ARRAY_SIZE(msg->dest_userid));
			
			err = econn_message_encode(&mstr, msg);
			if (err) {
				warning("send_conf_part: failed to "
					"encode message: %m\n", err);
			}
			else {
				tc_send(call->federate.tc,
					&call->sft_tuple, call->sft_cid,
					(uint8_t *)mstr, str_len(mstr));
				mem_deref(mstr);
			}
		}
	}

 out:
	mem_deref(msg);

	return err;
}

static void group_send_conf_part_as_is(struct group *group,
				       const struct econn_message *cmsg)
{
	struct le *le;
	struct econn_message *msg = (struct econn_message *)cmsg;

	msg->resp = false;
	LIST_FOREACH(&group->calll, le) {
		struct call *call = le->data;
		
		if (call && call->active && call->dc_estab && !call->issft) {
			assign_task(call, send_dce_msg, (void *)msg, false);
		}
	}
}

static uint8_t *generate_entropy(size_t *lenp)
{
	uint8_t *entropy;
	size_t len;

	len = ENTROPY_LENGTH;
	entropy = mem_alloc(len, NULL);
	if (!entropy)
		return NULL;
	else {
		randombytes_buf(entropy, len);
		*lenp = len;
		return entropy;
	}
}

static void group_send_conf_part(struct group *group,
				 uint8_t *entropy, size_t entropylen)
{
	uint64_t now;
	struct le *le;
	bool sent = false;

	if (!group)
		return;
	
	now = tmr_jiffies();


	LIST_FOREACH(&group->calll, le) {
		struct call *call = le->data;

		/* CONFPART should only be sent to calls that are not
		 * federated, federated calls need a collated list
		 * from the host SFT
		 */
		if (call && call->active && !call->issft
		    && !call->sft_url
		    && !sa_isset(&call->sft_tuple, SA_ADDR)) {
			sent = true;
			send_conf_part(call, now, entropy, entropylen,
				       true, false);
		}
	}
	if (sent)
		group->seqno++;
}

struct fir_req {
	struct mbuf *mb;
	uint32_t ssrc;
	uint8_t *seq;
};

static int fir_encode_handler(struct mbuf *mb, void *arg)
{
	struct fir_req *fr = arg;

	/* FIR-FCI */
	/* 0                   1                   2                   3
	 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                              SSRC                             |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | Seq nr.       |    Reserved                                   |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	mbuf_write_u32(mb, htonl(fr->ssrc)); /* SSRC of sender */
	mbuf_write_u8(mb, *fr->seq); /* seqno */
	*fr->seq = *fr->seq + 1;
	mbuf_write_u8(mb, 0);
	mbuf_write_u16(mb, 0);

	return 0;
}

static void send_fir(struct call *call)
{
	struct mbuf *mb = NULL;
	uint32_t lssrc;
	int err;

	if (call->video.hi.ssrc == 0 && call->video.lo.ssrc == 0)
		return;

	if (!call->mf)
		return;
	
	mb = mbuf_alloc(256);
	if (!mb) {
		SFTLOG(LOG_LEVEL_WARN, "RTCP buf failed\n", call);
		goto out;
	}

	lssrc = mediaflow_get_ssrc(call->mf, "video", true);
	if (call->video.hi.ssrc) {
		struct fir_req fr = {mb, call->video.hi.ssrc, &call->video.hi.fir_seq};
#if 0
		info("FIR: lssrc=%u rssrc=%u\n", lssrc, call->video.ssrc);
#endif
		mb->pos = 0;
		err = rtcp_encode(mb, RTCP_PSFB, RTCP_PSFB_FIR,
				  lssrc,
				  call->video.hi.ssrc,
				  fir_encode_handler, &fr);
		if (err) {
			SFTLOG(LOG_LEVEL_WARN, "RTCP encode failed: %m\n", call, err);
			goto out;
		}
		mediaflow_send_rtcp(call->mf, mb->buf, mb->end);
	}

	if (call->video.lo.ssrc) {
		struct fir_req fr = {mb, call->video.lo.ssrc, &call->video.lo.fir_seq};
		mb->pos = 0;
		err = rtcp_encode(mb, RTCP_PSFB, RTCP_PSFB_FIR,
				  lssrc,
				  call->video.lo.ssrc,
				  fir_encode_handler, &fr);
		if (err) {
			SFTLOG(LOG_LEVEL_WARN, "RTCP encode failed: %m\n", call, err);
			goto out;
		}
		
		mediaflow_send_rtcp(call->mf, mb->buf, mb->end);
	}

 out:
	mem_deref(mb);
	return;
}


static void fir_handler(void *arg)
{
	struct call *call = arg;

	send_fir(call);

	tmr_start(&call->tmr_fir, avs_service_fir_timeout(),
		  fir_handler, call);
}

static void conn_handler(void *arg)
{
	struct call *call = arg;

	info("conn_handler\n");
	
	if (call->alive) {
		call->alive = false;
		tmr_start(&call->tmr_conn, TIMEOUT_CONN, conn_handler, call);
	}
	else {	
		SFTLOG(LOG_LEVEL_INFO, "connection timeout\n", call);

		ICALL_CALL(call->icall, end);
	}
}

static int generate_provid(char **provid)
{
	crypto_hash_sha256_state ctx;
	const char hexstr[] = "0123456789abcdef";
	const size_t hlen = 16;
	unsigned char hash[crypto_hash_sha256_BYTES];
	const size_t blen = min(hlen, crypto_hash_sha256_BYTES);
	char *uuid = NULL;
	char *dest = NULL;
	size_t i;
	int err = 0;

	err = uuid_v4(&uuid);
	if (err) {
		warning("generate_provid: uuid failed\n");
		goto out;
	}
	
	err = crypto_hash_sha256_init(&ctx);
	if (err) {
		warning("generate_provid: hash init failed\n");
		goto out;
	}

	err = crypto_hash_sha256_update(&ctx,
					(const uint8_t*)uuid,
					strlen(uuid));
	if (err) {
		warning("generate_provid: hash update failed\n");
		goto out;
	}

	err = crypto_hash_sha256_final(&ctx, hash);
	if (err) {
		warning("generate_provid: hash final failed\n");
		goto out;
	}

	dest = mem_zalloc(blen * 2 + 1, NULL);
	if (!dest) {
		err = ENOMEM;
		goto out;
	}

	for (i = 0; i < hlen; i++) {
		dest[i * 2]     = hexstr[hash[i] >> 4];
		dest[i * 2 + 1] = hexstr[hash[i] & 0xf];
	}

	*provid = dest;

out:
	if (err) {
		mem_deref(dest);
	}
	mem_deref(uuid);
	return err;
}


static void start_provisional(struct group *group,
			      const char *url,
			      struct sa *tuple,
			      uint16_t cid,
			      uint8_t *entropy, size_t entropylen)
{
	struct call *call;
	char *provid = NULL;
	int err;

	/* If we already have a federation call for this group, use it */
	if (group->sft.call) {
		send_conf_part(group->sft.call, 0, entropy, entropylen,
			       false, false);
		return;
	}

	group->isfederated = true;

	err = generate_provid(&provid);
	if (err)
		goto out;

	err = alloc_call(&call, g_sft,
			 NULL,
			 NULL, 0,
			 NULL,
			 "sft", "_",
			 provid, provid,
			 false, false,
			 NUM_RTP_STREAMS, NUM_RTP_STREAMS,
			 true);

	if (err) {
		warning("start_provisional: could not allocate call: %m\n",
			err);
		goto out;
	}

	dict_add(g_sft->provisional.calls, provid, call);
	/* Call is now owned by dictionary */
	mem_deref(call);
	
	str_dup(&call->sft_url, url);
	sa_cpy(&call->sft_tuple, tuple);
	call->sft_cid = cid;
	call->issft = true;
	call->isprov = true;
	call->federate.tc = group->federate.tc;
	call->group = mem_ref(group);
	append_group(group, call);
	group->sft.call = mem_ref(call);
	if (0 == call->sft_cid)
		start_icall(call);
	else {
		struct econn_message msg;
		struct econn_props *props;
		char ltup[256];
		uint16_t lcid;

		lcid = turnconn_lcid(group->federate.tc);
		econn_message_init(&msg, ECONN_SETUP, provid);

		if (cid) {
			re_snprintf(ltup, sizeof(ltup), "%s/%u",
				    group->federate.relay_str, lcid);
		}
		else {
			re_snprintf(ltup, sizeof(ltup), "%s",
				    group->federate.relay_str);
		}
		msg.u.setup.sft_tuple = ltup;

		err = econn_props_alloc(&props, NULL);
		if (!err)
			err = econn_props_add(props, "sft_call", "true");
		if (err)
			goto out;
		msg.u.setup.props = props;
		
		send_provisional(call, &msg);

		mem_deref(props);
	}

 out:
	mem_deref(provid);
}


static void icall_datachan_estab_handler(struct icall *icall,
					 const char *userid,
					 const char *clientid,
					 bool update,
					 void *arg)
{
	struct call *call = arg;
	struct group *group;

	if (!call)
		return;

	group = call->group;

	if (call->issft && call->isprov) {
		SFTLOG(LOG_LEVEL_INFO,
		       "provisional call userid: %s clientid: %s update=%d\n",
		       call, userid, clientid, update);
	}
	/* When data channel establishes, don't use HTTP any more */
	call->isprov = false;
	call->dc_estab = true;
	
	SFTLOG(LOG_LEVEL_INFO,
	       "issft: %d group: %p userid: %s clientid: %s update=%d\n",
	       call, call->issft, group, userid, clientid, update);	

	call->video.hi.ssrc = 0;
	call->video.lo.ssrc = 0;
	if (call->mf) {
		call->audio.ssrc = mediaflow_get_ssrc(call->mf, "audio", false);
		SFTLOG(LOG_LEVEL_INFO, "call has version: %d.%d.%d\n",
		       call, call->ver.major, call->ver.minor, call->ver.build);
		if (call->issft || (call->ver.major > 0 && call->ver.major < 10)) {
			SFTLOG(LOG_LEVEL_INFO, "legacy ssrcv handling\n", call);
			call->video.ssrc = mediaflow_get_ssrc(call->mf, "video", false);
			call->video.hi.ssrc = call->video.ssrc;
			call->video.lo.ssrc = call->video.ssrc;
		}
	}

	memset(&call->video.hi.stats, 0, sizeof(call->video.hi.stats));
	memset(&call->video.lo.stats, 0, sizeof(call->video.lo.stats));
	call->audio.stats.freq_ms = 48;
	call->video.hi.stats.freq_ms = 90;
	call->video.lo.stats.freq_ms = 90;

	call->video.hi.dd = mem_deref(call->video.hi.dd);
	call->video.lo.dd = mem_deref(call->video.lo.dd);
	call->video.hi.fir_seq = 0;
	call->video.lo.fir_seq = 0;

	lock_write_get(call->twcc.lock);
	call->twcc.running = false;
	tmr_cancel(&call->twcc.tmr);	
	list_flush(&call->twcc.pktl);
	call->twcc.seqno = -1;
	call->twcc.refts = 0;
	call->twcc.fbcnt = 0;
	lock_rel(call->twcc.lock);

	lock_write_get(g_sft->lock);
	/* If this is an SFT call, we need to move 
	 * the provisional call into a real call, 
	 * by sending a CONFCONN.
	 */
	if (call->issft) {
		ecall_set_confmsg_handler((struct ecall *)call->icall,
					  ecall_confmsg_handler);
		if (group) {
			send_conf_conn(call, false, NULL, call->callid, NULL);
		}
	}
	else {
		tmr_start(&call->tmr_fir, avs_service_fir_timeout(),
			  fir_handler, call);
		tmr_start(&call->tmr_conn, TIMEOUT_CONN, conn_handler, call);

		/* send initial CONPART only to non-federated calls */
		if (group && !call->sft_url
		    && !sa_isset(&call->sft_tuple, SA_ADDR)) {
			uint8_t *entropy;
			size_t entropylen;

			entropy = generate_entropy(&entropylen);
			if (entropy) {
				group_send_conf_part(group,
						     entropy, entropylen);
				sft_send_conf_part(group,
						   entropy, entropylen,
						   true, true);
				mem_deref(entropy);
			}
		}
	}
	lock_rel(g_sft->lock);

	/* If this is not an SFT call,
	 * but the call has an SFT URL or tuple, we should start
	 * a request for a provisional call on the host SFT
	 */
	if (!call->issft) {
		if ((call->sft_url
		     || sa_isset(&call->sft_tuple, SA_ADDR))
		    && !update) {
			uint8_t *entropy;
			size_t entropylen;

			entropy = generate_entropy(&entropylen);

			if (entropy) {
				start_provisional(group,
						  call->sft_url,
						  &call->sft_tuple,
						  call->sft_cid,
						  entropy, entropylen);
				mem_deref(entropy);
			}
		}
	}
}

static void icall_media_stopped_handler(struct icall *icall, void *arg)
{
	struct call *call = arg;
	
	SFTLOG(LOG_LEVEL_INFO, "\n", call);
}

#if 0
static void icall_leave_handler(int reason, uint32_t msg_time, void *arg)
{
	struct call *call = NULL;
	
	SFTLOG(LOG_LEVEL_INFO, "reason=%d\n", call, reason);
}
#endif

#if 0
static void icall_group_changed_handler(void *arg)
{
	struct call *call = arg;
	
	SFTLOG(LOG_LEVEL_INFO, "\n", call);
}
#endif

static bool group_exist_handler(char *key, void *val, void *arg)
{
	struct group *g = arg;

	return g == val;
}

static bool group_exists(struct sft *sft, struct group *group)
{
	struct group *g;

	if (!group)
		return false;
	
	g = dict_apply(sft->groups, group_exist_handler, group);

	return g != NULL;
}

static void close_sfts(struct group *group)
{
	bool has_calls = false;
	struct le *le;

	/* In case we are the host SFT
	 * we rely on other SFTs to take down their connections
	 */
	if (group->sft.ishost) {
		return;
	}
	
	/* First check if we have any non-SFT calls */
	le = group->calll.head;
	if (!le)
		return;
	
	while(le && !has_calls) {
		struct call *call = le->data;

		info("close_sfts(%p): %p(issft=%d/%d)\n",
		     group, call, call->issft, call->sft_url != NULL);
		has_calls = !call->issft;
		le = le->next;
	}

	if (has_calls) {
		info("close_sfts(%p): not closing, still has calls\n", group);
		return;
	}

	/* If we are here, it means all calls that are
	 * left in the group are SFTs, we need to close them
	 */
	le = group->calll.head;
	while(le) {
		struct call *call = le->data;

		le = le->next;

		info("close_sfts(%p): closing SFT call %p(%s)\n",
		     group, call, call->callid);

		if (call->icall) {
			ICALL_CALL(call->icall, end);
		}
		else if (call->sft_cid) {
			struct econn_message msg;
			char *rstr;
			int err;

			econn_message_init(&msg, ECONN_HANGUP, call->callid);
			str_ncpy(msg.dest_userid,
				 call->federate.dstid,
				 sizeof(msg.dest_userid));
			err = econn_message_encode(&rstr, &msg);
			if (!err) {
				tc_send(group->federate.tc,
					&call->sft_tuple, call->sft_cid,
					(uint8_t *)rstr, str_len(rstr));

				mem_deref(rstr);
			}
			call_close_handler(call, false);
		}
	}
}

static void close_call(struct call *call)
{
	struct le *le;

	call->mf = NULL;
	call->active = false;

	list_unlink(&call->group_le);	

	/* Remove all the participants this
	 * call is connected with
	 */
	LIST_FOREACH(&call->partl, le) {
		struct participant *part = le->data;
		struct call *other = NULL;

		if (part)
			other = part->call;
		else
			continue;

		if (call && other)
			assign_task(other, remove_participant, call, false);
	}
	list_flush(&call->partl);
	list_flush(&call->sft_partl);
}

static void sft_send_conf_part(struct group *group,
			       uint8_t *entropy, size_t entropylen,
			       bool ishost, bool resp)
{
	struct le *le;

	info("sft_send_conf_part: group(%p): ishost: %d resp: %d sft-call=%p\n",
	     group, ishost, resp, group->sft.call);

	if (!ishost && group->sft.call) {
		send_conf_part(group->sft.call, 0, entropy, entropylen,
			       false, resp);
		return;
	}

	LIST_FOREACH(&group->calll, le) {
		struct call *call = le->data;

		info("sft_send_conf_part: call:%p issft=%d isprov=%d\n",
		     call, call->issft, call->isprov);
		if (call->issft && !call->isprov) {
			send_conf_part(call, 0, entropy, entropylen,
				       true, resp);
		}
	}
}

static void call_close_handler(struct call *call, bool locked)
{
	char *callid = NULL;
	struct group *group = call->group;
	struct sft *sft = call->sft;
	struct le *le;
	bool issft;
	bool ishost = false;

	info("call_close_handler(%p): group=%p\n", call, group);
	tmr_cancel(&call->tmr_conn);

	issft = call->issft;
	if (group) {
		ishost = group->sft.ishost
		|| (!(call->sft_url || sa_isset(&call->sft_tuple, SA_ADDR)));
	}
	str_dup(&callid, call->callid);

	if (locked)
		lock_write_get(sft->lock);
	close_call(call);
	if (group && group->sft.call == call) {
		group->sft.call = mem_deref(call);
	}
	info("call_close_handler(%p): ishost=%d issft=%d refs=%u\n",
	     call, ishost, issft, mem_nrefs(call));
	dict_remove(sft->calls, callid);
	
	if (group_exists(sft, group)) {
		uint8_t *entropy;
		size_t entropylen;

		entropy = generate_entropy(&entropylen);
		if (entropy) {
			group_send_conf_part(group, entropy, entropylen);
			sft_send_conf_part(group,
					   entropy, entropylen,
					   ishost, ishost);
			mem_deref(entropy);
		}

		/* If call still has any pending requests for
		 * federation, make sure to remove them
		 */
		le = group->federate.pendingl.head;
		while(le) {
			struct pending_msg *pm = le->data;

			le = le->next;
			if (pm->call == call) {
				if (call->hconn) {
					warning("call_close_handler: no response from federation TURN server");
					http_ereply(call->hconn, 501, "No response from federation TURN server");
					call->hconn = mem_deref(call->hconn);
				}
				mem_deref(pm);
			}
		}
	}

	if (locked)
		lock_rel(sft->lock);

	mem_deref(callid);
}

static void icall_close_handler(struct icall *icall,
				int err,
				const char *metrics_json,
				uint32_t msg_time,
				const char *userid,
				const char *clientid,
				void *arg)
{
	struct call *call = arg;

	SFTLOG(LOG_LEVEL_INFO,
	       "[%u] icall=%p callid=%s err=%d userid=%s clientid=%s "
	       "metrics: %s\n",
	       call, mem_nrefs(call), icall, call->callid, err,
	       userid, clientid, metrics_json);
	
	call_close_handler(call, true);
}


#if 0
static void icall_metrics_handler(const char *metrics_json, void *arg)
{
	struct call *call = arg;
	
	SFTLOG(LOG_LEVEL_INFO, "metrics: %s\n", call, metrics_json);
}
#endif

static void icall_vstate_handler(struct icall *icall,
				 const char *userid,
				 const char *clientid,
				 enum icall_vstate state,
				 void *arg)
{
	struct call *call = arg;
	
	SFTLOG(LOG_LEVEL_INFO,
	       "userid=%s clientid=%s state=%s\n",
	       call, userid, clientid,
	       icall_vstate_name(state));
}
	
static void icall_audiocbr_handler(struct icall *icall, const char *userid,
				   const char *clientid, int enabled,
				   void *arg)
{
	struct call *call = arg;
	
	SFTLOG(LOG_LEVEL_INFO,
	       "userid=%s clientid=%s enabled=%d\n",
	       call, userid, clientid, enabled);
}

static void icall_quality_handler(struct icall *icall,
				  const char *userid,
				  const char *clientid,
				  int rtt, int uploss, int downloss,
				  void *arg)
{
	struct call *call = arg;
	
	SFTLOG(LOG_LEVEL_INFO,
	       "userid=%s clientid=%s rtt=%d uploss=%d downloss=%d\n",
	       call, userid, clientid, rtt, uploss, downloss);
}

static int send_propsync(struct call *call, struct econn_props *props,
			 const char *userid, const char *clientid, bool resp)
{
	struct econn_message pmsg;
	char *pstr = NULL;
	size_t plen;
	int err;

	if (!call || !props)
		return EINVAL;

	if (call->mf) {
		if (!call->dc_estab)
			return ENOSYS;
	}

	econn_message_init(&pmsg, ECONN_PROPSYNC, NULL);

	pmsg.resp = resp;
	pmsg.age = 0;
	pmsg.u.propsync.props = props;
	str_ncpy(pmsg.src_userid, userid, sizeof(pmsg.src_userid));
	str_ncpy(pmsg.src_clientid, clientid, sizeof(pmsg.src_clientid));
	/* Add a destination id if we are sending a federation request */
	if (!call->mf && call->federate.dstid) {
		str_ncpy(pmsg.dest_userid, call->federate.dstid,
			 sizeof(pmsg.dest_userid));
	}

	err = econn_message_encode(&pstr, &pmsg);
	if (err) {
		SFTLOG(LOG_LEVEL_WARN, "failed to encode message\n", call);
		goto out;
	}

	plen = str_len(pstr);
	if (call->mf) {
		err = mediaflow_send_dc(call->mf, (uint8_t *)pstr, plen);
		if (err) {
			SFTLOG(LOG_LEVEL_WARN, "failed to send PROPSYNC message\n", call);
			goto out;
		}
		ecall_trace((struct ecall *)call->icall, &pmsg, true,
			    ECONN_TRANSP_DIRECT, "DataChan %H\n",
			    econn_message_brief, &pmsg);
	}
	else {
		if (call->group && call->group->federate.tc && call->sft_cid) {
			tc_send(call->group->federate.tc,
				&call->sft_tuple, call->sft_cid,
				(uint8_t *)pstr, plen);
		}
	}
 out:
	mem_deref(pstr);

	return err;
}

#if 0
static int group_send_propsync(struct group *group)
{
	struct le *le;
	
	LIST_FOREACH(&group->calll, le) {
		struct call *call = le->data;
		
		if (call->issft)
			continue;

		send_propsync(call, call->props,
			      call->userid, call->clientid, false);
	}

	return 0;
}
#endif

static int ecall_ping_handler(struct ecall *ecall,
			      bool response,
			      void *arg)
{
	struct call *call = arg;

#if 0
	SFTLOG(LOG_LEVEL_INFO, "\n", call);
#endif
	
	tmr_start(&call->tmr_conn, TIMEOUT_CONN, conn_handler, call);

	ecall_ping(ecall, true);

	return 0;
}


static int ecall_propsync_handler(struct ecall *ecall,
				  struct econn_message *msg,
				  void *arg)
{
	struct call *call = arg;
	struct le *le;
	const char *muted_str;
	const char *ss_str;

	SFTLOG(LOG_LEVEL_INFO, "\n", call);

	mem_deref(call->props);
	call->props = mem_ref(msg->u.propsync.props);	

	muted_str = econn_props_get(call->props, "muted");
	if (muted_str)
		call->muted = streq(muted_str, "true");
	else
		call->muted = false;
	/* Mark screenshare */
	ss_str = econn_props_get(call->props, "screensend");
	if (ss_str) {
		bool screenshare = streq(ss_str, "true");
		if (screenshare != call->screenshare) {
			info("call(%p): screenshare: %s -> %s\n",
			     call,
			     call->screenshare ? "YES" : "NO",
			     screenshare ? "YES" : "NO");
		}
		call->screenshare = screenshare;
	}
	else {
		call->screenshare = false;
	}

	// Send same packet to all members of this group
	LIST_FOREACH(&call->partl, le) {
		struct participant *part = le->data;
		bool auth = false;
		bool issft = false;
		bool from_sft = call->issft;
			

		issft = part->call ? part->call->issft : false;
		auth = from_sft || (issft || part->auth);

		info("propsync: sending propsync to: part=%p/%p(issft=%d)/%d\n",
		     part, part->call, issft, auth);
		
		if (!part || !part->call)
			continue;

		if (auth) {
			ref_locked(part->call);
			send_propsync(part->call, call->props,
				      msg->src_userid,
				      msg->src_clientid, true);
			deref_locked(part->call);
		}
	}

	return 0;
}

/*
static int deref_tc_handler(void *arg)
{
	mem_deref(arg);

	return 0;
}
*/

static void group_destructor(void *arg)
{
	struct group *group = arg;
	//void *tc;

	info("group_destructor(%p): id=%s\n", group, group->id);

	//tc = group->federate.tc;
	//group->federate.tc = NULL;
	
	//worker_assign_main(deref_tc_handler, tc);
	mem_deref(group->federate.tc);
	mem_deref(group->id);
}

static void farg_destructor(void *arg)
{
	struct start_fed_arg *farg = arg;

	mem_deref(farg->group);
}

static int alloc_group(struct sft *sft,
		       struct group **groupp,
		       const char *groupid,
		       struct zapi_ice_server *turn)
{
	struct group *group;
	bool isfederated = turn != NULL;

	info("alloc_group: new group with id: %s federated=%d\n",
	     groupid, isfederated);
	
	group = mem_zalloc(sizeof(*group), group_destructor);
	if (!group)
		return ENOMEM;

	group->start_ts = tmr_jiffies();
	group->seqno = 1;
	str_dup(&group->id, groupid);
	list_init(&group->calll);

	lock_write_get(sft->lock);
	dict_add(sft->groups, groupid, group);
	lock_rel(sft->lock);
	//mem_deref(group); /* group is now owned by dictionary */
	sft->stats.group_cnt++;

	if (isfederated) {
		struct start_fed_arg *f;

		f = mem_zalloc(sizeof(*f), farg_destructor);
		f->group = mem_ref(group);
		f->turn = *turn;
		worker_assign_task(worker_get(group->id),
				   start_federation_task,
				   f);
	}

	if (groupp)
		*groupp = group;

	return 0;
}

static int remove_participant(struct call *call, void *arg)
{
	struct le *le;
	bool found = false;
	struct call *other = arg;

	info("remove_participant: %p(refs=%u)/%p(refs=%u)\n",
	     call, mem_nrefs(call),
	     other, mem_nrefs(other));
	
	if (call == other)
		return 0;

	lock_write_get(g_sft->lock);
	le = call->partl.head;
	while(le && !found) {
		struct participant *part = le->data;

		le = le->next;

		if (!part)
			continue;

		if (part->call == other) {
			if (call->mf) {
				mediapump_remove_ssrc(call->mf, part->ssrca);
				mediapump_remove_ssrc(call->mf, part->ssrcv);
			}
			info("remove_part: part=%p(refs=%d)\n",
			     part, (int)mem_nrefs(part));
			mem_deref(part);
			found = true;
		}
	}
	lock_rel(g_sft->lock);

	return 0;
}

static void terminate_handler(void *arg)
{
	(void)arg;

	avs_service_terminate();
}

static int service_terminate(void *arg)
{
	(void)arg;

	tmr_start(&g_sft->tmr_terminate, 0, terminate_handler, NULL);

	return 0;
}


static void call_destructor(void *arg)
{
	struct call *call = arg;
	struct group *group = call->group;
	struct sft *sft = call->sft;

	SFTLOG(LOG_LEVEL_INFO, "\n", call);
	
	tmr_cancel(&call->tmr_setup);
	tmr_cancel(&call->tmr_rr);
	tmr_cancel(&call->tmr_fir);
	tmr_cancel(&call->tmr_conn);
	tmr_cancel(&call->tmr_q);
	tmr_cancel(&call->video.tmr_ssrcv);
	lock_write_get(call->twcc.lock);
	call->twcc.running = false;
	tmr_cancel(&call->twcc.tmr);
	list_flush(&call->twcc.pktl);
	lock_rel(call->twcc.lock);
	mem_deref(call->twcc.lock);

	close_call(call);
	list_flush(&call->partl);

	mem_deref(call->turnv);
	mem_deref(call->callid);
	mem_deref(call->clientid);
	mem_deref(call->userid);
	mem_deref(call->sessid);
	mem_deref(call->props);
	mem_deref(call->sft_url);
	mem_deref(call->origin_url);
	mem_deref(call->icall);
	mem_deref(call->http_cli);

	rtp_stream_destroy(call->audio.rtps.v, call->audio.rtps.c);
	rtp_stream_destroy(call->video.rtps.v, call->video.rtps.c);
	
	list_flush(&call->video.select.streaml);

	/* Finally check, if we were the last participant in the group,
	 * if we were, remove group.
	 */
	info("call(%p): belongs to group: %p(%s) in group: %d\n",
	     call, group,
	     group ? group->id : "?",
	     group ? (int)list_count(&group->calll) : (int)0);

	if (group)
		close_sfts(group);

	if (group && group->calll.head == NULL) {
		dict_remove(sft->groups, group->id);
		if (avs_service_is_draining()
		    && dict_count(sft->groups) == 0) {

			worker_assign_main(service_terminate, NULL);
		}
	}
	
	mem_deref(call->group);
	mem_deref(call->federate.url);
	mem_deref(call->federate.dstid);
#if USE_RTX
	mem_deref(call->video.jb);
#endif
	mem_deref(call->video.hi.dd);
	mem_deref(call->video.lo.dd);
	mem_deref(call->lock);
}

static struct participant *find_part_by_userclient(struct list *partl,
						   const char *userid,
						   const char *clientid,
						   uint32_t ssrca,
						   uint32_t ssrcv)
{
	struct participant *part;
	struct le *le;
	bool found = false;

	le = partl->head;
	while(le && !found) {
		part = le->data;
		le = le->next;
#if 0
		info("find_part_by_userclient: partl=%p userid:%s==%s clientid:%s==%s\n",
		     partl, userid, part->userid, clientid, part->clientid);
#endif
		if (part && part->userid && part->clientid) {
			found = streq(part->userid, userid)
				&& streq(part->clientid, clientid);
			if (found) {
				if (ssrca)
					found = found && ssrca == part->ssrca;
				if (ssrcv)
					found = found && ssrcv == part->ssrcv;
			}
		}
	}

	return found ? part : NULL;
}

static struct econn_group_part *find_in_confpart(const struct list *partl,
						 const char *userid,
						 const char *clientid,
						 uint32_t ssrca,
						 uint32_t ssrcv)
{
	struct econn_group_part *part = NULL;
	struct le *le;
	bool found = false;


	if (!userid || !clientid)
		return NULL;
	
	le = partl->head;
	while(le && !found) {
		part = le->data;
		le = le->next;

		found = streq(part->userid, userid)
			&& streq(part->clientid, clientid)
			&& ssrca == part->ssrca
			&& ssrcv == part->ssrcv;
	}

	return found ? part : NULL;
}


static void sft_confpart_handler(const struct econn_message *msg,
				 void *arg)
{
	struct call *call = arg;
	struct participant *rpart;
	struct group *group = call ? call->group : NULL;
	struct le *le;
	const struct list *partl = &msg->u.confpart.partl;
	struct list *call_partl;
	struct list tpl = LIST_INIT;
	bool resp = false;

	SFTLOG(LOG_LEVEL_INFO, "CONFPART-%s participants: %d\n",
	       call, msg->resp ? "Resp" : "Req", list_count(partl));	

	if (msg->resp) {
		resp = true;
		group_send_conf_part_as_is(call->group, msg);
	}

	call_partl = resp ? &call->sft_partl : &call->partl;

	if (resp) {
		tpl = *call_partl;
		list_init(call_partl);
#if 0
		/* First remove all previous participants */
		le = call_partl->head;
		while(le) {
			rpart = le->data;
			le = le->next;
			/* Our own group is regsitered with call,
			 * keep that in
			 */
			if (NULL == rpart->call)
				mem_deref(rpart);
		}
#endif
	}
	else { /* request */
		/* cleanup all removed participants */
		le = call_partl->head;
		while(le) {
			struct econn_group_part *part;
			
			rpart = le->data;
			le = le->next;

			if (rpart->call)
				continue;
			
			part = find_in_confpart(partl,
						rpart->userid,
						rpart->clientid,
						rpart->ssrca,
						rpart->ssrcv);
			if (!part)
				mem_deref(rpart);
		}
	}

	LIST_FOREACH(partl, le) {
		struct econn_group_part *part = le->data;
		struct participant *tpart;
		//struct auth_part *aup;

#if 1
		SFTLOG(LOG_LEVEL_INFO, "resp: %d part_ix: %lu part: %s.%s ssrca=%u ssrcv=%u auth=%d ts=%llu\n",
		       call, resp, call->part_ix, part->userid, part->clientid, part->ssrca, part->ssrcv, part->authorized, part->ts);
#endif
		rpart = find_part_by_userclient(call_partl,
						part->userid,
						part->clientid,
						part->ssrca,
						part->ssrcv);
		if (rpart)
			continue;

		if (tpl.head == NULL) {
			tpart = NULL;
		}
		else {
			tpart = find_part_by_userclient(&tpl,
							part->userid,
							part->clientid,
							0, 0);
			info("sft_confpart_handler: part=%s.%s tpart=%p\n",
			     part->userid, part->clientid, tpart);
		}

		rpart = mem_zalloc(sizeof(*rpart), part_destructor);
		if (!rpart) {
			warning("sft_confpart_handler: failed rpart\n");
			continue;
		}

		//lpart->group = group;
		//lpart->call = mem_ref(other);
		str_dup(&rpart->userid, part->userid);
		str_dup(&rpart->clientid, part->clientid);
		rpart->ssrca = part->ssrca;
		rpart->ssrcv = part->ssrcv;
		if (tpart) {
			rpart->simulcast = tpart->simulcast;
		}
		//rpart->ts = call->join_ts + part->ts;
		rpart->ix = group ? group->part_ix++ : 0;

		list_init(&rpart->authl);
		list_append(call_partl, &rpart->le, rpart);
	}
	list_flush(&tpl);

	if (!resp && group) {
		uint8_t *entropy;
		size_t entropylen;

		entropy = generate_entropy(&entropylen);
		if (entropy) {
			group_send_conf_part(group, entropy, entropylen);
			sft_send_conf_part(group, entropy, entropylen,
					   group->sft.ishost, true);
			//send_conf_part(call, 0, NULL, 0, true, true);

			mem_deref(entropy);
		}
	}
}

static void aup_destructor(void *arg)
{
	struct auth_part *aup = arg;

	mem_deref(aup->userid);
}


static void ecall_confpart_handler(struct ecall *ecall,
				   const struct econn_message *msg,
				   void *arg)
{
	struct call *call = arg;
	struct participant *lpart;
	struct participant *rpart;
	struct le *le;

	const struct list *partl = &msg->u.confpart.partl;

	SFTLOG(LOG_LEVEL_INFO, "participants: %d\n",
	       call, list_count(partl));

	deauth_call(call, false);
	LIST_FOREACH(partl, le) {
		struct econn_group_part *part = le->data;
		struct auth_part *aup;

#if 1
		SFTLOG(LOG_LEVEL_INFO, "part: %s.%s ssrca=%u ssrcv=%u auth=%d\n",
		       call, part->userid, part->clientid, part->ssrca, part->ssrcv, part->authorized);
#endif

		/* Find the call for the participant */
		rpart = call2part(call, part->userid, part->clientid);
		if (!rpart || !rpart->call)
			continue;

		rpart->auth = part->authorized;

		/* lookup ourselves in the remote participant's list */
		lpart = call2part(rpart->call,
				  call->userid, call->clientid);
		if (!lpart)
			continue;

		aup = mem_zalloc(sizeof(*aup), aup_destructor);
		str_dup(&aup->userid, part->userid);
		aup->ssrca = part->ssrca;
		aup->ssrcv = part->ssrcv;
		aup->auth = part->authorized;

		list_append(&lpart->authl, &aup->le, aup);

		send_propsync(rpart->call, call->props,
			      call->userid, call->clientid, true);
	}
}

static void vs_destructor(void *arg)
{
	struct video_stream *vs = arg;

	mem_deref(vs->userid);
}

static void attach_video_stream(struct call *call, const char *userid, uint32_t quality, int ix)
{
	struct video_stream *vs;

	info("attach_video_stream(%p): userid=%s at index=%d q=%d\n",
	     call, userid, ix, quality);

	vs = mem_zalloc(sizeof(*vs), vs_destructor);
	if (!vs)
		goto out;

	str_dup(&vs->userid, userid);
	vs->ix = ix;
	vs->q = quality;
	info("attach_video_stream(%p): appending userid=%s(vs=%p) "
	     "at index=%d\n",
	     call, userid, vs, vs->ix);

	list_append(&call->video.select.streaml, &vs->le, vs);
 out:
	return;
}

#if TEST_QUALITY_SWITCH
static void timeout_q_switch(void *arg)
{
	struct call *call = arg;
	struct le *le;
	enum video_stream_q q;


	LIST_FOREACH(&call->video.select.streaml, le) {
		struct video_stream *vs = le->data;

		switch (vs->q) {
		case VIDEO_STREAM_Q_ANY:
			q = VIDEO_STREAM_Q_HI;
			break;
			
		case VIDEO_STREAM_Q_HI:
			q = VIDEO_STREAM_Q_LO;
			break;
			
		case VIDEO_STREAM_Q_LO:
			q = VIDEO_STREAM_Q_HI;
			break;
		}
		info("timeout_q_switch(%p): %d -> %d\n", call, vs->q, q);

		vs->q = q;
	}
	
	tmr_start(&call->tmr_q, 5000, timeout_q_switch, call);
}
#endif

static void select_video_streams(struct call *call,
				 const char *mode,
				 const struct list *streaml)
{		
	struct le *le;
	int ix = 0;
	
	if (streq(mode, "level")) {
		call->video.select.mode = SELECT_MODE_LEVEL;
		return;
	}
	
	info("select_video_streams(%p): list mode\n", call);
		
	if (!call->group)
		return;

	call->video.select.mode = SELECT_MODE_LIST;

	lock_write_get(call->lock);
	list_flush(&call->video.select.streaml);
	LIST_FOREACH(streaml, le) {
		struct econn_stream_info *si = le->data;

		attach_video_stream(call, si->userid, si->quality, ix);
		++ix;
	}
#if TEST_QUALITY_SWITCH
	tmr_start(&call->tmr_q, 5000, timeout_q_switch, call);
#endif

	/* If we have un-used RTP stream-slots, reset the ssrc */
	if (ix < call->video.rtps.c) {
		int i;
		for(i = ix; i < call->video.rtps.c; ++i) {
			struct rtp_stream *rs = &call->video.rtps.v[i];
			rs->current_ssrc = 0;
		}
	}
	lock_rel(call->lock);
}


static void ecall_confstreams_handler(struct ecall *ecall,
				      const struct econn_message *msg,
				      void *arg)
{
	struct call *call = arg;
	struct le *le;
	bool ishost = call->group ? call->group->sft.ishost : false;

	info("ecall_confstreams_handler(%p): issft=%d(ishost=%d) ecall=%p group=%p n=%d\n",
	     call, call->issft, ishost, ecall, call->group,
	     (int)list_count(&msg->u.confstreams.streaml));

	if (call->issft) {
		struct list *partl = ishost ? &call->partl : &call->sft_partl;

		LIST_FOREACH(&msg->u.confstreams.streaml, le) {
			struct econn_stream_info *si = le->data;
			struct participant *part;

			part = find_part_by_userclient(partl,
						       si->userid,
						       "_",
						       0,
						       0);
			info("ecall_confstreams_handler(%p): part=%p(%s.%s) "
			     "simulcast: hi:%u lo:%u\n",
			     call, part, si->userid, si->ssrcv.clientid,
			     si->ssrcv.hi, si->ssrcv.lo);

			if (part) {
				if (si->ssrcv.hi)
					part->simulcast.ssrcv_hi = si->ssrcv.hi;
				if (si->ssrcv.lo)
					part->simulcast.ssrcv_lo = si->ssrcv.lo;
			}
			else {
				warning("ecall_confstreams_handler(%p): participant not found: %s.%s\n",
					call, si->userid, si->ssrcv.clientid);
			}
		}
		return;
	}
	
	select_video_streams(call,
			     msg->u.confstreams.mode,
			     &msg->u.confstreams.streaml);
}


static void ecall_confmsg_handler(struct ecall *ecall,
				  const struct econn_message *msg,
				  void *arg)
{
	struct call *call = arg;
	struct group *group = NULL;
	const char *groupid;
	int err;
	
	switch (msg->msg_type) {
	case ECONN_CONF_PART:
		if (call->issft) {
			sft_confpart_handler(msg, arg);
		}
		else {
			ecall_confpart_handler(ecall, msg, arg);
		}
		break;

	case ECONN_CONF_STREAMS:
		ecall_confstreams_handler(ecall, msg, arg);
		break;

	case ECONN_CONF_CONN:
		/* CONF_CONN on data channel comes only 
		 * in SFT calls, we distinguish between
		 * requests and responses, requests are only
		 * received on the host SFT, while responses
		 * on individual SFTs
		 */
		group = call->group;
		info("ecall_confmsg_handler: CONF_CONN-%s on sessid=%s "
		     "issft=%d group=%p\n",
		     msg->resp ? "Resp" : "Req", msg->sessid_sender,
		     call->issft, group);
		if (!call->issft) {
			err = EPROTO;
			goto out;
		}
		if (msg->resp) {
			/* When we receive a CONFCONN-response,
			 * we must update the participant list
			 * on the connected SFT
			 */
			if (group) {
				uint8_t *entropy;
				size_t entropylen;

				entropy = generate_entropy(&entropylen);
				if (entropy) {
					send_conf_part(call,
						       0,
						       entropy, entropylen,
						       false, false);
					mem_deref(entropy);
				}
			}
			else {
				warning("ecall_confmsg_handler(%p): "
					"no group\n",
					call);
			}
		}
		else { /* CONFCONN-Req */
			if (!group) {
				groupid = msg->sessid_sender;
				group = find_group(g_sft, groupid);
			}				
			if (!group) {
				warning("ecall_confmsg_handler: no group: "
					"%s found\n",
					groupid);
			}
			else {
				lock_write_get(g_sft->lock);
				if (ecall) {
					char *callid;
				
					info("ecall_confmsg_handler(%p): appending SFT "
					     "call to group: %s(%p)\n",
					     call, groupid, group);
				
					callid = make_callid(groupid,
							     msg->src_userid,
							     call->callid);

					dict_add(g_sft->calls, callid, call);
					dict_remove(g_sft->provisional.calls,
						    call->callid);
					call->callid = mem_deref(call->callid);
					call->callid = callid;				
					if (!call->group) {
						call->group = group;
						append_group(group, call);
					}
				}

				/* Only host SFTs receive CONFCONN-Reqs */
				group->sft.ishost = !msg->resp;
				send_conf_conn(call, true, NULL, call->callid, call->federate.dstid);
				lock_rel(g_sft->lock);
			}
		}
		break;

	default:
		warning("ecall_confmsg_handler: unhandled message: %s\n",
			econn_msg_name(msg->msg_type));
		break;
	}

 out:
	return;
}


static char *make_callid(const char *convid,
			 const char *userid,
			 const char *clientid)
{
	size_t n;
	char *callid;

	n = str_len(convid);
	n += str_len(userid);
	n += str_len(clientid);
	n += 5;

	callid = mem_zalloc(n, NULL);
	if (!callid)
		return NULL;

	re_snprintf(callid, n, "%s.%s.%s", convid, userid, clientid);

	return callid;
}


static int alloc_icall(struct call *call,
		       struct zapi_ice_server *turnv, size_t turnc,
		       const char *cid,
		       bool provisional)
{
	struct ecall *ecall;
	struct icall *icall;
	struct list *ecalls;
	int err = 0;
	size_t i;

	lock_write_get(call->sft->lock);
	ecalls = provisional ? &call->sft->provisional.ecalls
		             : &call->sft->ecalls,
	err = ecall_alloc(&ecall, ecalls,
			  ICALL_CONV_TYPE_ONEONONE,
			  NULL, call->sft->msys,
			  cid, SFT_USERID, call->sft->uuid);
	lock_rel(call->sft->lock);
	if (err) {
		SFTLOG(LOG_LEVEL_WARN, "ecall_alloc failed: %m\n",
		       call, err);
		goto out;
	}
	if (!provisional) {
		ecall_set_confmsg_handler(ecall, ecall_confmsg_handler);
	}
	
	/* Add any turn servers we may have */
	info("sft: call(%p): adding %d TURN servers\n", call, turnc);
	for (i = 0; i < turnc; ++i)
		ecall_add_turnserver(ecall, &turnv[i]);

	icall = ecall_get_icall(ecall);
	mem_deref(call->icall);
	call->icall = icall;

	icall_set_callbacks(icall,
			    icall_send_handler,
			    NULL, // icall_sft_handler,
			    icall_start_handler, 
			    icall_answer_handler,
			    NULL, //icall_media_estab_handler,
			    icall_audio_estab_handler,
			    icall_datachan_estab_handler,
			    icall_media_stopped_handler,
			    NULL, // group_changed_handler
			    NULL, // leave_handler
			    icall_close_handler,
			    NULL, // metrics_handler
			    icall_vstate_handler,
			    icall_audiocbr_handler,
			    NULL, // muted_changed_handler
			    icall_quality_handler,
			    NULL, // norelay_handler
			    NULL, // req_clients_handler
			    NULL, // audio_level_handler
			    NULL, // new_epoch_handler
			    call);
	ICALL_CALL(icall, set_media_laddr, &g_sft->mediasa);

 out:
	return err;
}

static uint32_t regen_lssrc(uint32_t old_ssrc)
{
	uint32_t lssrc;

	/* Generate a new local ssrc that is DIFFERENT,
	 * to what we already have...
	 */
	
	do {
		lssrc = rand_u32();
	}
	while(lssrc == 0 || lssrc == old_ssrc);

	return lssrc;
}

static bool exist_group_ssrc(struct call *call, uint32_t ssrc)
{
	struct group *group = call->group;
	bool found = false;
	struct le *le;

	if (!group)
		return false;
	
	le = group->calll.head;
	while(!found && le) {
		struct call *rcall = le->data;

		found = ssrc == rcall->video.ssrc;
		le = le->next;
	}

	return found;
}

static int ver2vel(const char *ver, struct ver_elem *vel)
{
	char *vactual;
	char *vstr;
	char *v;
	int err;

	err = str_dup(&vactual, ver);
	if (err)
		return err;

	vstr = vactual;
	v = strsep(&vstr, ".");
	vel->major = v ? atoi(v) : -1;
	v = strsep(&vstr, ".");
	vel->minor = v ? atoi(v) : -1;
	if (!vstr)
		vel->build = -1;
	else {
		if (streq(vstr, "local"))
			vel->build = 999;
		else
			vel->build = atoi(vstr);
	}

	//info("ver: %s to vel: %d.%d.%d\n",
	//     ver, vel->major, vel->minor, vel->build);

	mem_deref(vactual);

	return 0;
}


static int alloc_call(struct call **callp, struct sft *sft,
		      const char *toolver,
		      struct zapi_ice_server *turnv, size_t turnc,
		      struct group *group,
		      const char *userid, const char *clientid,
		      const char *callid, const char *sessid,
		      bool selective_audio, bool selective_video,
		      int astreams, int vstreams,
		      bool locked)
{
	struct call *call = NULL;
	size_t i;
	uint32_t ssrc = 0;
	int err = 0;

	if (!callp)
		return EINVAL;

	call = mem_zalloc(sizeof(*call), call_destructor);
	if (!call) {
		err = ENOMEM;
		goto out;
	}
	if (toolver) {
		ver2vel(toolver, &call->ver);
	}

	SFTLOG(LOG_LEVEL_INFO, "toolver: %s callid: %s sessid: %s sel_audio: %d/%d sel_video: %d/%d\n",
	       call, toolver, callid, sessid,
	       selective_audio, astreams, selective_video, vstreams);

	call->active = true;
	str_dup(&call->userid, userid);
	str_dup(&call->clientid, clientid);
	str_dup(&call->callid, callid);
	str_dup(&call->sessid, sessid);
	call->sft = sft;
	if (group)
		call->group = mem_ref(group);
	err = lock_alloc(&call->lock);
	if (err)
		goto out;

#if USE_RTX
	err = jb_alloc(&call->video.jb, VIDEO_JBUF_MIN, VIDEO_JBUF_MAX);
	if (err)
		goto out;
#endif

	call->video.select.mode = SELECT_MODE_LIST;

	if (call->issft || (call->ver.major > 0 && call->ver.major < 10)) {
		SFTLOG(LOG_LEVEL_INFO, "using legacy ssrcv generation\n", call);
	}
	else {
		/* generate a "fake" video ssrc,
		 * since we will have multiple ssrcs
		 * for quality purposes
		 */
		do {
			ssrc = regen_lssrc(ssrc);
		} while(exist_group_ssrc(call, ssrc));
		call->video.ssrc = ssrc;
	}

	if (turnc > 0) {
		call->turnv = mem_zalloc(turnc * sizeof(*turnv), NULL);
		if (!call->turnv) {
			err = ENOMEM;
			goto out;
		}

		for (i = 0; i < turnc; ++i) {
			call->turnv[i] = turnv[i];
		}
		call->turnc = turnc;
	}

	call->audio.is_selective = selective_audio;
	call->audio.ssrcc = selective_audio ? astreams : 0;
	
	call->twcc.seqno = -1;
	call->video.is_selective = selective_video;
	call->video.ssrcc = selective_video ? vstreams : 0;

	lock_alloc(&call->twcc.lock);
	
	tmr_init(&call->tmr_setup);
	tmr_init(&call->tmr_conn);
	tmr_init(&call->tmr_rr);
	tmr_init(&call->tmr_fir);

	if (locked)
		lock_write_get(sft->lock);
	if (group) {
		dict_add(sft->calls, callid, call);
		//mem_deref(call); /* call is now owned by dictionary */
		sft->stats.call_cnt++;
		append_group(group, call);
	}
	if (locked)
		lock_rel(sft->lock);

 out:
	if (err) {
		mem_deref(call);
	}
	else {
		*callp = call;
	}
	return err;

}


static void setup_timeout_handler(void *arg)
{
	struct call *call = arg;

	info("call(%p): setup_timeout_handler\n", call);
	      
	ICALL_CALL(call->icall, end);
}


static int start_icall(struct call *call)
{
	struct ecall *ecall;
	int err;

	if (call->icall)
		call->icall = mem_deref(call->icall);
	
	err = alloc_icall(call,
			  call->turnv, call->turnc,
			  call->group->id,
			  false);
	if (err) {
		goto out;
	}
	
	SFTLOG(LOG_LEVEL_INFO,
	       "starting icall: %p\n",
	       call, call->icall);

	ecall = (struct ecall *)call->icall;
	
	err = ecall_set_sessid(ecall, call->sessid);
	if (err) {
		SFTLOG(LOG_LEVEL_WARN,
		       "set_sessid failed on icall: %p (%m)\n",
		       call, call->icall, err);
		goto out;
	}						

	ecall_set_propsync_handler(ecall, ecall_propsync_handler);
	ecall_set_ping_handler(ecall, ecall_ping_handler);
	
	err = ICALL_CALLE(call->icall,
			  set_video_send_state,
			  ICALL_VIDEO_STATE_STARTED);
	if (err) {
		SFTLOG(LOG_LEVEL_WARN,
		       "send_video_send_state failed on icall: %p (%m)\n",
		       call, call->icall, err);
		goto out;
	}

	err = ICALL_CALLE(call->icall, start,
			  ICALL_CALL_TYPE_VIDEO,
			  true);
	if (err) {
		SFTLOG(LOG_LEVEL_WARN,
		       "start failed on icall: %p (%m)\n",
		       call, call->icall, err);
		goto out;
	}

	tmr_start(&call->tmr_setup, TIMEOUT_SETUP,
		  setup_timeout_handler, call);

 out:
	return err;
}

static int new_call(struct call *call, void *arg)
{
	struct http_conn *hc = arg;
	int err;

	SFTLOG(LOG_LEVEL_INFO, "sft_tuple=%J(cid=%u)\n", call, &call->sft_tuple, call->sft_cid);
		
	call->hconn = mem_ref(hc);
	err = start_icall(call);

	return err;
}


static void deauth_call(struct call *call, bool reset_estab)
{
	struct le *le;

	LIST_FOREACH(&call->partl, le) {
		struct participant *part = le->data;
		struct participant *lpart;
		
		if (!part)
			continue;

		part->auth = false;
		lpart = call2part(part->call, call->userid, call->clientid);
		if (lpart) {
			list_flush(&lpart->authl);
		}
	}
	if (reset_estab)
		call->dc_estab = false;
}

static int restart_call(struct call *call, void *arg)
{
	struct http_conn *hc = arg;
	struct group *group;
	int err = 0;

	SFTLOG(LOG_LEVEL_INFO, "\n", call);
	
	call->hconn = mem_deref(call->hconn);
	call->hconn = mem_ref(hc);
	
	deauth_call(call, true);
	tmr_cancel(&call->tmr_conn);

	call->video.started = false;

	/* We want to move this call to the end of the list,
	 * so it loses its KG privilage on the clients
	 */
	list_unlink(&call->group_le);
	err = ecall_restart((struct ecall *)call->icall,
			    ICALL_CALL_TYPE_VIDEO, false);
	if (err)
		return err;

	/* Re-add the call to the group, at the end of the list */
	group = call->group;
	if (group) {
		call->part_ix = group->part_ix++;
		list_append(&group->calll, &call->group_le, call);
	}

	return 0;
}


static int recreate_call(struct call *call, void *arg)
{
	struct http_conn *hc = arg;

	SFTLOG(LOG_LEVEL_INFO, "\n", call);
	
	call->mf = NULL;

	call->hconn = mem_deref(call->hconn);
	call->hconn = mem_ref(hc);

	deauth_call(call, true);

	//call->video.hi.ssrc = 0;
	//call->video.lo.ssrc = 0;
	
	start_icall(call);

	return 0;
}

static bool print_group_handler(char *key, void *val, void *arg)
{
	struct group *group = val;
	struct le *le;

	info("group(%p): groupid=%s calls:%d\n",
	     group, group->id, list_count(&group->calll));

	LIST_FOREACH(&group->calll, le) {
		struct call *call = le->data;

		info("\tcall(%p): callid=%s\n", call, call->callid);
	}

	return false;
}

static bool print_call_handler(char *key, void *val, void *arg)
{
	struct call *call = val;

	info("call(%p): callid:%s group=%p(%s)\n",
	     call, call->callid,
	     call->group,
	     call->group ? call->group->id : "?");

	return false;
}

static void http_stats_handler(struct http_conn *hc,
			     const struct http_msg *msg,
			     void *arg)
{
	struct sft *sft = arg;
	char *url = NULL;
	struct mbuf *mb = NULL;
	char *stats = NULL;
	uint64_t now;
	int err = 0;;

	pl_strdup(&url, &msg->path);
	info("http_stats_req: URL=%s\n", url);

#if 1
	if (streq(url, "/debug")) {
		lock_write_get(sft->lock);

		info("Calls in list: %d\n", (int)dict_count(sft->groups));
		dict_apply(sft->calls, print_group_handler, NULL);
		info("Parts in list: %d\n", (int)dict_count(sft->calls));
		dict_apply(sft->calls, print_call_handler, NULL);
		http_creply(hc, 200, "OK", "text/plain", "Debug\n");

		lock_rel(sft->lock);

		mem_debug();

		goto out;
	}
#endif
	
	if (!streq(url, "/metrics")) {
		err = ENOENT;
		goto out;
	}

	mb = mbuf_alloc(512);
	now = tmr_jiffies();

	lock_write_get(sft->lock);	

	mbuf_printf(mb, "# HELP sft_uptime "
		    "Uptime in [seconds] of the SFT service\n");
	mbuf_printf(mb, "# TYPE sft_uptime counter\n");
	mbuf_printf(mb, "sft_uptime %llu\n", (now - g_sft->start_ts)/1000);
	mbuf_printf(mb, "\n");

	mbuf_printf(mb, "# HELP sft_build_info "
		    "Build information\n");
	mbuf_printf(mb, "# TYPE sft_build_info gauge\n");
	mbuf_printf(mb, "sft_build_info{version=\"%s\"} 1\n", SFT_VERSION);
	mbuf_printf(mb, "\n");
	
	mbuf_printf(mb, "# HELP sft_participants "
		    "Current number of participants\n");
	mbuf_printf(mb, "# TYPE sft_participants gauge\n");
	mbuf_printf(mb, "sft_participants %zu\n", dict_count(sft->calls));
	mbuf_printf(mb, "\n");

	mbuf_printf(mb, "# HELP sft_calls Current number of calls\n");
	mbuf_printf(mb, "# TYPE sft_calls gauge\n");
	mbuf_printf(mb, "sft_calls %zu\n", dict_count(sft->groups));
	mbuf_printf(mb, "\n");

	mbuf_printf(mb, "# HELP sft_participants_total "
		    "Total number of participants\n");
	mbuf_printf(mb, "# TYPE sft_participants_total counter\n");
	mbuf_printf(mb, "sft_participants_total %llu\n", sft->stats.call_cnt);
	mbuf_printf(mb, "\n");

	mbuf_printf(mb, "# HELP sft_calls_total Total number of calls\n");
	mbuf_printf(mb, "# TYPE sft_calls_total counter\n");
	mbuf_printf(mb, "sft_calls_total %llu\n", sft->stats.group_cnt);
	mbuf_printf(mb, "\n");

	lock_rel(sft->lock);

	mb->pos = 0;
	mbuf_strdup(mb, &stats, mb->end);
	http_creply(hc, 200, "OK", "text/plain", "%s", stats);

 out:
	mem_deref(stats);
	mem_deref(mb);
	mem_deref(url);

	if (err)
		http_ereply(hc, 400, "Bad request");
}

static struct call *find_provisional(struct sft *sft, const char *provid)
{
	struct call *call;
	
	call = dict_lookup(sft->provisional.calls, provid);

	return call;
}

static void split_tuple(struct call *call, const char *tuple)
{
	char *tp;
	char *c;
	int err;

	err = str_dup(&tp, tuple);
	if (err)
		return;
	
	c = strrchr(tp, '/');

	if (c && str_len(c) > 1) {		
		call->sft_cid = (uint16_t)atoi(&c[1]);
	}
	else {
		call->sft_cid = 0;
		info("split_tuple: no cid\n");
	}

	/* Truncate the sft_tuple at the cid */
	if (c) {
		*c = '\0';
		sa_decode(&call->sft_tuple, tp, str_len(tp));
		info("split_tuple: decoding tuple: %s --> %J\n", tp, &call->sft_tuple);
	}

	mem_deref(tp);
}

static struct call *federate_request(struct group *group,
				     struct mbuf *mb,
				     const char *convid)
{
	struct econn_message *cmsg = NULL;
	struct call *call = NULL;
	char *srcid;
	char *dstid;
	int err = 0;

	if (!group)
		return NULL;

	err = econn_message_decode(&cmsg, 0, 0,
				   (const char *)mbuf_buf(mb),
				   mbuf_get_left(mb));
	if (err) {
		warning("federate_request: group(%p): failed to decode econn message: %s\n",
			(char *)mbuf_buf(mb));
		goto out;
	}

	if (!convid) {
		convid = cmsg->sessid_sender;
	}

	switch(cmsg->msg_type) {
	case ECONN_CONF_CONN:
		srcid = cmsg->src_userid;
		dstid = cmsg->dest_userid;

		info("federate_request: CONF_CONN-%s "
		     "convid=%s srcid=%s dstid=%s\n",
		     cmsg->resp ? "resp" : "req", convid, srcid, dstid);

		if (cmsg->resp) {
			lock_write_get(g_sft->lock);
			call = dict_lookup(g_sft->calls, dstid);
			if (call)
				str_dup(&call->federate.dstid, srcid);
			lock_rel(g_sft->lock);
		}
		else {
			lock_write_get(g_sft->lock);
			call = find_provisional(g_sft, convid);

			if (!call) {
				warning("federate_request: provisional call: "
					"%s not found\n",
					convid);
				err = ENOSYS;
				lock_rel(g_sft->lock);				
				goto out;
			}
			call->callid = mem_deref(call->callid);
			call->callid = make_callid("sft", convid, srcid);

			dict_add(g_sft->calls, call->callid, call);
			dict_remove(g_sft->provisional.calls, convid);
			call->isprov = false;

			str_dup(&call->federate.dstid, srcid);

			if (!call->group) {
				call->group = mem_ref(group);
				append_group(group, call);
			}
			lock_rel(g_sft->lock);			
		}
		if (!call) {
			warning("federate_request: no call found\n");
			err = ENOSYS;
			goto out;
		}
		ecall_confmsg_handler(NULL, cmsg, call);
		break;

	case ECONN_CONF_PART:
		dstid = cmsg->dest_userid;

		info("federate_request: CONF_PART-%s convid=%s dstid=%s\n",
		     cmsg->resp ? "resp" : "req", convid, dstid);
		lock_write_get(g_sft->lock);
		call = dict_lookup(g_sft->calls, dstid);		
		lock_rel(g_sft->lock);
		if (!call) {
			warning("federate_request: cannot find call: %s\n",
				dstid);
			err = ENOSYS;
			goto out;
		}
		ecall_confmsg_handler(NULL, cmsg, call);
		break;

	case ECONN_SETUP:
		lock_write_get(g_sft->lock);
		call = find_provisional(g_sft, convid);
		lock_rel(g_sft->lock);
		info("federate_request: SETUP-%s convid=%s call=%p\n",
		     cmsg->resp ? "resp" : "req", convid, call);
		if (call) {
			if (cmsg->resp) {
				dict_add(g_sft->calls, call->callid, call);
				dict_remove(g_sft->provisional.calls, convid);
				if (call->sft_cid) {
					send_conf_conn(call, false, convid,
						       call->callid,
						       call->callid);
				}
			}
			else {
				warning("sft: provisional call: %s "
					"already exists\n");
				call = NULL;
				err = EALREADY;
				goto out;
			}
		}
		else {
			err = alloc_call(&call, g_sft,
					 NULL,
					 NULL, 0,
					 NULL,
					 "prov", "_",
					 convid, cmsg->sessid_sender,
					 false, false,
					 NUM_RTP_STREAMS, NUM_RTP_STREAMS,
					 true);
			if (err) {
				warning("federate_request: failed to "
					"alloc_call: %m\n", err);
				goto out;
			}

			call->issft = true;
			call->isprov = true;
			call->federate.tc = group->federate.tc;
			
			if (cmsg->u.setup.sft_tuple) {
				split_tuple(call, cmsg->u.setup.sft_tuple);
				info("federate_request(%p): setting call: %p "
				     "sft_tuple=%J sft_cid=%u\n",
				     group, call,
				     &call->sft_tuple, call->sft_cid);
				if (call->sft_cid && call->federate.tc) {
					turnconn_add_cid(call->federate.tc,
							 call->sft_cid);
				}
			}
			if (cmsg->u.setup.url) {
				call->federate.url =
					mem_deref(call->federate.url);
				str_dup(&call->federate.url, cmsg->u.setup.url);
			}

			if (0 == call->sft_cid) {
				err = alloc_icall(call, NULL, 0, convid, true);
				if (err) {
					warning("sft: failed to alloc icall: %m\n",
						err);
					goto out;
				}
			}
			lock_write_get(g_sft->lock);
			err = dict_add(g_sft->provisional.calls,
				       convid, call);
			lock_rel(g_sft->lock);
			if (err) {
				warning("sft_req_handler: failed to "
					"add provisional: %m\n", err);
				goto out;
			}

			/* call is now owned by provsional calls dictionary */
			mem_deref(call);
			info("add_provisional(%p): refs=%u\n",
			     call, mem_nrefs(call));

			if (0 == call->sft_cid) {
				info("federate_request: icall SETUP-%s: %s\n",
				     cmsg->resp ? "Resp" : "Req",
				     cmsg->u.setup.sdp_msg);

				ecall_msg_recv((struct ecall *)call->icall,
					       0, 0,
					       "prov",
					       "_",
					       cmsg);
			}
			else {
				struct econn_message rmsg;
				char ltup[256];
				uint16_t lcid;
				char *rstr;

				lcid = turnconn_lcid(group->federate.tc);
				if (lcid) {
					re_snprintf(ltup, sizeof(ltup), "%s/%u",
						    group->federate.relay_str, lcid);
				}
				else {
					re_snprintf(ltup, sizeof(ltup), "%s",
						    group->federate.relay_str);
				}
			
				err = econn_message_init(&rmsg, ECONN_SETUP, convid);
				if (err)
					goto out;

				rmsg.resp = true;
				rmsg.u.setup.props = cmsg->u.setup.props;
				rmsg.u.setup.sft_tuple = ltup;

				err = econn_message_encode(&rstr, &rmsg);
				if (err)
					goto out;

				tc_send(group->federate.tc,
					&call->sft_tuple, call->sft_cid,
					(uint8_t *)rstr, str_len(rstr));

				mem_deref(rstr);
			}
		}
		break;

	case ECONN_HANGUP:
		srcid = cmsg->src_userid;
		dstid = cmsg->dest_userid;

		info("federate_request: HANGUP-%s "
		     "convid=%s srcid=%s dstid=%s\n",
		     cmsg->resp ? "resp" : "req", convid, srcid, dstid);

		lock_write_get(g_sft->lock);
		call = dict_lookup(g_sft->calls, dstid);
		if (call)
			call_close_handler(call, false);
		lock_rel(g_sft->lock);
		break;

	case ECONN_PROPSYNC:
		srcid = cmsg->src_userid;
		dstid = cmsg->dest_userid;

		info("federate_request: PROPSYNC-%s "
		     "convid=%s srcid=%s dstid=%s\n",
		     cmsg->resp ? "resp" : "req", convid, srcid, dstid);

		lock_write_get(g_sft->lock);
		call = dict_lookup(g_sft->calls, dstid);
		lock_rel(g_sft->lock);
		if (call)
			ecall_propsync_handler(NULL, cmsg, call);
		break;

	case ECONN_CONF_STREAMS:
		dstid = cmsg->dest_userid;

		info("federate_request: CONF_STREAMS-%s convid=%s dstid=%s\n",
		     cmsg->resp ? "resp" : "req", convid, dstid);
		lock_write_get(g_sft->lock);
		call = dict_lookup(g_sft->calls, dstid);
		lock_rel(g_sft->lock);
		if (!call) {
			warning("federate_request: cannot find call: %s\n",
				dstid);
			err = ENOSYS;
			goto out;
		}
		
		ecall_confstreams_handler(NULL, cmsg, call);
		break;

	default:
		err = ENOENT;
		break;
	}

 out:
	if (err)
		mem_deref(call);
	mem_deref(cmsg);

	return err ? NULL : call;
}

static void sft_req_handler(struct http_conn *hc,
			    const struct http_msg *msg,
			    void *arg)
{
	char *url = NULL;
	struct call *call = NULL;
	int err = 0;
	char *paths[2];
	int n;
	char *convid = NULL;
	char *body = NULL;
	const struct http_hdr *origin;

	pl_strdup(&url, &msg->path);
	info("sft_req_handler: URL=%s\n", url);

	if (streq(url, "/debug")) {
		info("sft_req_handler: DEBUG\n");
		goto out;
	}

	n = split_paths(url, paths, ARRAY_SIZE(paths));
	if (n != 2) {
		warning("sft: path missmatch expecting 2 got %d\n", n);
		err = EINVAL;
		goto bad_req;
	}

	convid = paths[1];
	if (msg->mb)
		body = (char *)mbuf_buf(msg->mb);

	if (!body) {
		err = ENOSYS;
		goto bad_req;
	}

	call = federate_request(NULL, msg->mb, convid);
	if (!call) {
		err = EPROTO;
		goto out;
	}

	origin = http_msg_xhdr(msg, "Origin");
	if (origin) {
		call->origin_url = mem_deref(call->origin_url);
		pl_strdup(&call->origin_url, &origin->val);
	}

 out:
 bad_req:
	mem_deref(url);
	if (err) {
		mem_deref(call);
		http_ereply(hc, 400, "Bad request");
	}
	else
		http_creply(hc, 200, "OK", "text/plain", "All good\n");
}

static bool is_blacklisted(const char *ver, struct list *cbl)
{
	struct ver_elem bver;
	bool found = false;
	struct le *le;

	//info("is_blacklisted: ver=%s cbl=%p head=%p\n", ver, cbl, cbl->head);

	if (!ver || !cbl || !cbl->head)
		return false;

	ver2vel(ver, &bver);

	/* Never blacklist master builds which have version 0.0.x */
	if (bver.major == 0 && bver.minor == 0)
		return false;
	
	for(le = cbl->head; !found && le; le = le->next) {
		struct ver_elem *vel = le->data;

		//info("is_blacklisted: lt:%d %d.%d.%d\n", vel->lessthan, vel->major, vel->minor, vel->build);
		if (vel->lessthan) {
			found = bver.major < vel->major;
			if (found)
				continue;
			
			if (bver.major == vel->major) {
				found = bver.minor < vel->minor;
				if (found)
					continue;
				
				if (bver.minor == vel->minor)
					found = bver.build < vel->build;
			}
		}
		else {
			found = bver.major == vel->major
			     && bver.minor == vel->minor
			     && bver.build == vel->build;
		}
	}

	//info("is_blacklisted: %d.%d.%d %s\n", bver.major, bver.minor, bver.build, found ? "YES" : "NO");
	
	return found;
}

static int reply_connerror(struct http_conn *hc, struct econn_message *msg,
			   enum econn_confconn_status conn_status)
{
	struct econn_message *rmsg;
	char *rstr;
	int err;

	rmsg = econn_message_alloc();
	if (!rmsg)
		return ENOMEM;

	econn_message_init(rmsg, ECONN_CONF_CONN, msg->sessid_sender);
	rmsg->u.confconn.status = conn_status;

	err = econn_message_encode(&rstr, rmsg);
	if (err) {
		warning("reply_connerror: failed to encode message: %m\n", err);
		return err;
	}

	http_creply(hc, 200, "OK", "application/json", "%s", rstr);

	mem_deref(rstr);
	mem_deref(rmsg);

	return 0;
}

static int reply_msg(struct http_conn *hc, struct econn_message *msg)
{
	struct econn_message *cmsg = NULL;
	char *rstr = NULL;
	int err;

	cmsg = econn_message_alloc();
	if (!cmsg)
		return ENOMEM;

	err = econn_message_init(cmsg, ECONN_CONF_CONN, msg->sessid_sender);
	if (err)
		goto out;

	cmsg->resp = true;
	str_ncpy(cmsg->src_userid, SFT_USERID, sizeof(cmsg->src_userid));
	str_ncpy(cmsg->src_clientid, SFT_USERID, sizeof(cmsg->src_clientid));
	cmsg->u.confconn.status = ECONN_CONFCONN_OK;

	err = econn_message_encode(&rstr, cmsg);
	if (err) {
		warning("reply_msg: failed to encode message: %m\n", err);
		goto out;
	}

	http_creply(hc, 200, "OK", "application/json", "%s", rstr);

 out:
	mem_deref(cmsg);
	mem_deref(rstr);

	return err;
}


static int update_call(struct call *call, void *arg)
{
	struct econn_message *cmsg = arg;

	SFTLOG(LOG_LEVEL_INFO, "\n", call);
	
	tmr_cancel(&call->tmr_setup);

	ICALL_CALLE(call->icall, msg_recv, 0, 0,
		    cmsg->src_userid, cmsg->src_clientid,
		    cmsg);

	return 0;
}

static int turn_chan_hdr_decode(struct turn_chan_hdr *hdr, struct mbuf *mb)
{
	if (!hdr || !mb)
		return EINVAL;

	if (mbuf_get_left(mb) < sizeof(*hdr))
		return ENOENT;

	hdr->nr  = ntohs(mbuf_read_u16(mb));
	hdr->len = ntohs(mbuf_read_u16(mb));

	return 0;
}

static bool tc_recv_handler(struct sa *src, struct mbuf *mb, void *arg)
{
	struct group *group = arg;
	struct stun_unknown_attr ua;
	struct stun_msg *msg = NULL;
	struct turn_chan_hdr hdr;
	int err = 0;

#if DEBUG_PACKET
	info("group(%p): tc_recv_handler: tc=%p src=%J "
	     "data(%zu bytes)=\n%w\n",
	     group, group->federate.tc, src,
	     mbuf_get_left(mb), mbuf_buf(mb), mbuf_get_left(mb));
#endif
	if (stun_msg_decode(&msg, mb, &ua)) {
		uint8_t *b;
		
		err = turn_chan_hdr_decode(&hdr, mb);
		if (err)
			goto out;

		if (mbuf_get_left(mb) < hdr.len)
			goto out;

		/* Is this a RTP packet? */
		b = mbuf_buf(mb);
		if (b[0] > 127) {
			struct rtp_header rtp;
			size_t pos;
			struct call *call;
			bool found = false;
			struct le *le = group->calll.head;

			pos = mb->pos;
			err = rtp_hdr_decode(&rtp, mb);
			if (!err) {
				mb->pos = pos;

				while(!found && le) {
					call = le->data;
					le = le->next;
				
					found = call->issft &&
						exist_ssrc(call, group->sft.ishost,
							   rtp.ssrc,
							   RTP_STREAM_TYPE_ANY);
				}
				if (found) {
					reflow_rtp_recv(mb, call);
					return true;
				}
#if DEBUG_PACKET
				else {
					warning("tc_recv(%p): ssrc: %u not found for call\n", call, rtp.ssrc);
				}
#endif
			}
		}
		else {
			info("tc_recv: signalling on group: %p\n", group);
			federate_request(group, mb, NULL);
		}
		
		return true;
	}

 out:
	mem_deref(msg);

	return false;
}


static void tc_estab_handler(struct turn_conn *tc,
			     const struct sa *relay_addr,
			     const struct sa *mapped_addr,
			     const struct stun_msg *msg, void *arg)
{
	struct group *group = arg;
	struct le *le;

	info("group(%p): tc_estab_handler: tc=%p(%p) established: r=%J m=%J\n",
	     group, group->federate.tc, tc, relay_addr, mapped_addr);

	sa_cpy(&group->federate.relay_addr, relay_addr);

	re_snprintf(group->federate.relay_str,
		    sizeof(group->federate.relay_str),
		    "%J", relay_addr);

	group->federate.isready = true;

	udp_register_helper(&group->federate.uh, tc->us_turn,
			    LAYER_STUN - 1,
			    NULL, tc_recv_handler, group);

	le = group->federate.pendingl.head;
	while(le) {
		struct pending_msg *pm = le->data;
		struct econn_message *cmsg;
		int err = 0;

		le = le->next;
		
		err = econn_message_decode(&cmsg, 0, 0,
					   pm->msg, str_len(pm->msg));
		if (err)
			continue;

		if (cmsg->msg_type == ECONN_SETUP) {
			cmsg->u.setup.sft_tuple =
				mem_deref(cmsg->u.setup.sft_tuple);

			cmsg->u.setup.sft_tuple = sft_tuple(pm->call, group);
			info("call(%p): postponed sft_tuple=%s\n", pm->call, cmsg->u.setup.sft_tuple);
		}
		send_sft_msg(pm->call, cmsg, 0);

		mem_deref(cmsg);
		mem_deref(pm);
	}
}

static void tc_data_handler(struct turn_conn *tc, const struct sa *src,
			     struct mbuf *mb, void *arg)
{
	struct group *group = arg;
	
	info("group(%p): tc_data_handler: tc=%p(%p) src=%J "
	     "data(%zu bytes)=\n%w\n",
	     group, group->federate.tc, tc, src,
	     mbuf_get_left(mb), mbuf_buf(mb), mbuf_get_left(mb));
}

static void tc_err_handler(int err, void *arg)
{
	struct group *group = arg;
	struct le *le;
	
	info("group(%p): tc_error_handler: tc=%p err=%m\n",
	     group, group->federate.tc, err);

	le = group->federate.pendingl.head;
	while(le) {
		struct pending_msg *pm = le->data;

		le = le->next;

		send_sft_msg(pm->call, NULL, 500);
		mem_deref(pm);
	}

	group->federate.tc = mem_deref(group->federate.tc);
}



static void http_req_handler(struct http_conn *hc,
			     const struct http_msg *msg,
			     void *arg)
{
	struct sft *sft = arg;
	struct econn_message *cmsg = NULL;
	char *paths[2];
	char *url;
	char *params;
	char *convid = NULL;
	char *userid = NULL;
	char *clientid = NULL;
	char *callid = NULL;
	struct group *group = NULL;
	bool group_created = false;
	struct call *call = NULL;
	const struct sa *sa;
	char *toolver;
	char *user;
	char *cred;
	enum zrest_state auth_state;
	char *body = NULL;
	struct zapi_ice_server *turnv;
	size_t turnc;
	int n;
	enum econn_confconn_status errcode = ECONN_CONFCONN_OK;
	int err = 0;

	pl_strdup(&url, &msg->path);
	pl_strdup(&params, &msg->prm);

	sa = http_conn_peer(hc);
	info("sft: incoming HTTP from: %J URL=%s\n", sa, url);
	
	n = split_paths(url, paths, ARRAY_SIZE(paths));
	if (n != 2) {
		warning("sft: path missmatch expecting 2 got %d\n", n);
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

	if (msg->mb)
		body = (char *)mbuf_buf(msg->mb);

	if (!body) {
		err = ENOSYS;
		goto bad_req;
	}

	err = econn_message_decode(&cmsg, 0, 0, body, mbuf_get_left(msg->mb));
	if (err)
		goto bad_req;

	userid = cmsg->src_userid;
	clientid = cmsg->src_clientid;
	callid = make_callid(convid, userid, clientid);
	call = find_call(sft, callid);
	group = find_group(sft, convid);

	info("sft: req for %s.%s [%s] for convid=%s %H\n",
	     userid, clientid, callid, convid, econn_message_brief, cmsg);

	if (call) {
		switch(cmsg->msg_type) {
		case ECONN_SETUP:
		case ECONN_UPDATE:			
			if (!cmsg->resp) {
				SFTLOG(LOG_LEVEL_WARN,
				       "only SETUP responses handled\n",
				       call);
				err = EINVAL;
				goto bad_req;
			}

			/* If call is in updating state, it means
			 * we need to convert client's UPDATE to a SETUP
			 */
			if (call->update) {
				cmsg->msg_type = ECONN_SETUP;
				call->update = false;
			}

			err = assign_task(call, update_call, cmsg, true);
			if (err) {
				SFTLOG(LOG_LEVEL_WARN,
				       "assign_task failed\n", call);
				goto bad_req;
			}
				
			err = reply_msg(hc, cmsg);
			if (err) {
				SFTLOG(LOG_LEVEL_WARN,
				       "reply_msg failed\n", call);
				goto bad_req;
			}
			break;

		case ECONN_CONF_CONN:			
			toolver = cmsg->u.confconn.toolver;
			info("sft: incoming request for updating call "
			     "from client with toolver: %s\n", toolver);
			if (is_blacklisted(toolver, &sft->cbl)) {
				warning("sft: client version: %s is blacklisted\n", toolver);
				err = reply_connerror(hc, cmsg,
						      ECONN_CONFCONN_REJECTED_BLACKLIST);
				goto out;
			}

			user = cmsg->u.confconn.sft_username;
			cred = cmsg->u.confconn.sft_credential;
			if (!avs_service_use_auth()) {
				auth_state = ZREST_OK;
			}
			else {
				auth_state = ZREST_UNAUTHORIZED;
				if (user && cred) {
					auth_state = zrest_authenticate(user, cred);
				}				
			}

			switch (auth_state) {
			case ZREST_OK:
			case ZREST_JOIN:
				break;

			case ZREST_EXPIRED:
				errcode = ECONN_CONFCONN_REJECTED_AUTH_EXPIRED;
				break;
				       
			default:
				errcode = ECONN_CONFCONN_REJECTED_AUTH_INVALID;
				break;					
			}

			if (errcode) {			
				err = reply_connerror(hc, cmsg, errcode);
				goto out;
			}

			if (cmsg->u.confconn.update) {
				info("sft: restarting call: %p\n", call);

				assign_task(call, restart_call, hc, true);
			}
			else {
				info("sft: recreating call: %p\n", call);

				/* We want to move this call to the end of the list,
				 * so it loses its KG privilage on the clients
				 */
				list_unlink(&call->group_le);

				if (!call->group) {
					err = ENOENT;
					goto out;
				}
				/* Re-add the call to the group, at the end of the list */
				if (call->group) {
					call->part_ix = call->group->part_ix++;
					list_append(&call->group->calll, &call->group_le, call);
				}
				
				assign_task(call, recreate_call, hc, true);
			}
			break;

		default:
			break;
		}
	}
	else {
		const char *sft_url;
		const char *sft_tuple;

		if (avs_service_is_draining()) {
			err = ESHUTDOWN;
			goto bad_req;
		}
		
		if (pl_strcmp(&msg->met, "POST") != 0) {
			err = EINVAL;
			goto bad_req;
		}

		if (cmsg->msg_type != ECONN_CONF_CONN) {
			err = EINVAL;
			goto bad_req;
		}

		if (!avs_service_use_auth()) {
			auth_state = ZREST_OK;
		}
		else {
			user = cmsg->u.confconn.sft_username;
			cred = cmsg->u.confconn.sft_credential;
			auth_state = ZREST_UNAUTHORIZED;
			if (user && cred) {
				auth_state = zrest_authenticate(user, cred);
			}
		}

		toolver = cmsg->u.confconn.toolver;
		sft_url = cmsg->u.confconn.sft_url ?
			cmsg->u.confconn.sft_url : "LOCAL",
		sft_tuple = cmsg->u.confconn.sft_tuple ?
			cmsg->u.confconn.sft_tuple : "LOCAL";

		info("sft: incoming request for new call from toolver: %s "
		     "sft_url=%s sft_tuple=%s\n",
		     toolver, sft_url, sft_tuple);
		
		if (is_blacklisted(toolver, &sft->cbl)) {
			warning("sft: client version: %s is blacklisted\n",
				toolver);
			err = reply_connerror(hc, cmsg,
					      ECONN_CONFCONN_REJECTED_BLACKLIST);
			goto out;
		}

		if (!group) {
			struct zapi_ice_server turn = {
				.url = "",
				.username = "",
				.credential = ""
			};
			bool isfederated = false;
			const char *turl;
			
			switch(auth_state) {
			case ZREST_OK:
				break;

			case ZREST_JOIN:
				errcode = ECONN_CONFCONN_REJECTED_AUTH_CANTSTART;
				break;

			case ZREST_EXPIRED:
				errcode = ECONN_CONFCONN_REJECTED_AUTH_EXPIRED;
				break;
				       
			default:
				errcode = ECONN_CONFCONN_REJECTED_AUTH_INVALID;
				break;					
			}

			if (errcode) {
				warning("sft: access denied for toolver: %s "
					"sft_url=%s sft_tuple=%s\n",
					toolver, sft_url, sft_tuple);
				err = reply_connerror(hc, cmsg, errcode);

				goto out;
			}
				
			/* If we have a TURN URL it means we are federated */
			turl = avs_service_turn_url();
			if (turl) {
				isfederated = true;
				str_ncpy(turn.url, turl, sizeof(turn.url));
				str_ncpy(turn.username,
					 sft->fed_turn.username,
					 sizeof(turn.username));
				str_ncpy(turn.credential,
					 sft->fed_turn.credential,
					 sizeof(turn.credential));
			}
			err = alloc_group(sft, &group, convid,
					  isfederated ? &turn : NULL);
			if (err)
				goto out;

			group_created = true;
		}

		if (avs_service_use_turn()) {
			turnv = cmsg->u.confconn.turnv;
			turnc = cmsg->u.confconn.turnc;
		}
		else {
			turnv = NULL;
			turnc = 0;
		}

		info("sft: using %d TURN servers for call\n", turnc);
		err = alloc_call(&call,
				 sft,
				 toolver,
				 turnv,
				 turnc,
				 group, userid, clientid,
				 callid, cmsg->sessid_sender,
				 cmsg->u.confconn.selective_audio,
				 cmsg->u.confconn.selective_video,
				 NUM_RTP_STREAMS,
				 cmsg->u.confconn.vstreams,
				 true);
		if (err)
			goto out;

		//call->join_ts = tmr_jiffies();

		if (cmsg->u.confconn.update) {
			call->update = true;
			if (!group->started)
				group->started = true;
		}		

		if (cmsg->u.confconn.sft_url &&
		    str_len(cmsg->u.confconn.sft_url) > 0) {
			str_dup(&call->sft_url,
				cmsg->u.confconn.sft_url);
		}
		if (cmsg->u.confconn.sft_tuple &&
		    str_len(cmsg->u.confconn.sft_tuple) > 0) {
			split_tuple(call, cmsg->u.confconn.sft_tuple);
			info("new_call: tuple: %J(cid=%u)\n", &call->sft_tuple, call->sft_cid);
			group->isfederated = true;
		}
		
		
		assign_task(call, new_call, hc, true);
	}
	
 out:
 bad_req:
	if (err && group_created)
		dict_remove(sft->groups, convid);

	mem_deref(call);
	mem_deref(group);
	mem_deref(cmsg);
	mem_deref(callid);
	mem_deref(url);
	mem_deref(params);

	if (err) {
		switch(err) {
		case ESHUTDOWN:
			http_ereply(hc, 303, "See other");
			break;

		default:
			http_ereply(hc, 400, "Bad request");
			break;
		}
	}
}

static void sft_destructor(void *arg)
{
	struct sft *sft = arg;

	lock_write_get(sft->lock);
	
	dict_flush(sft->calls);
	mem_deref(sft->calls);
	dict_flush(sft->groups);
	mem_deref(sft->groups);
	dict_flush(sft->provisional.calls);
	mem_deref(sft->provisional.calls);
	list_flush(&sft->cbl);
	list_flush(&sft->ecalls);

	mem_deref(sft->httpd);
	mem_deref(sft->httpd_stats);
	mem_deref(sft->httpd_sft_req);
	mem_deref(sft->msys);

	lock_rel(sft->lock);

	mem_deref(sft->lock);
}

static void part_destructor(void *arg)
{
	struct participant *part = arg;

	list_unlink(&part->le);

	info("part_dtor(%p): call: %p[%u]\n", part, part->call, mem_nrefs(part->call));

	mem_deref(part->call);	

	list_flush(&part->authl);

	mem_deref(part->userid);
	mem_deref(part->clientid);
}

static int append_participant(struct group *group,
			      struct call *call, struct call *other)
{
	struct participant *part;

	part = mem_zalloc(sizeof(*part), part_destructor);
	if (!part)
		return ENOMEM;

	part->group = group;

	part->call = mem_ref(other);
	str_dup(&part->userid, other->userid);
	part->ssrca = other->audio.ssrc;
	part->ssrcv = other->video.ssrc;
	part->ix = group->part_ix;

	list_init(&part->authl);
	list_append(&call->partl, &part->le, part);

	return 0;
}

static struct participant *find_call_part(struct call *call,
					  struct call *other)
{
	struct participant *part = NULL;
	struct le *le;
	bool found = false;

	le = call->partl.head;
	while(le && !found) {
		part = le->data;
		found = part->call == other;
		le = le->next;
	}

	return (found) ? part : NULL;
}

static int append_group(struct group *group, struct call *call)
{
	struct le *le;

	info("call(%p): adding to group:%p index=%lu\n", call, group,
	     group->part_ix);

	LIST_FOREACH(&group->calll, le) {
		struct call *cg = le->data;

		if (call->issft) {
			struct participant *part;

			//if (cg->issft)
			//	continue;

			part = find_call_part(cg, call);
			if (!part)
				append_participant(group, cg, call);
			part = find_call_part(call, cg);
			if (!part)
				append_participant(group, call, cg);
		}
		else {
			/* Append the other participants to this call */
			append_participant(group, call, cg);
			/* Append this call to other participants */
			append_participant(group, cg, call);
		}
	}

	call->part_ix = group->part_ix;
	++group->part_ix;
	list_append(&group->calll, &call->group_le, call);

	return 0;
}

static void generate_client_blacklist(struct list *cbl, const char *blstr)
{
	char *blactual;
	char *blsep;
	char *vstr;
	int err;

	info("generate_client_blacklist: %s\n", blstr);
	err = str_dup(&blactual, blstr);
	if (err)
		return;

	blsep = blactual;
	while ((vstr = strsep(&blsep, ",")) != NULL) {
		struct ver_elem *vel;

		vel = mem_zalloc(sizeof(*vel), vel_destructor);
		while(isspace(*vstr)) {
			++vstr;
		}

		if (*vstr == '<') {
			vel->lessthan = true;
			++vstr;
		}
		ver2vel(vstr, vel);
		list_append(cbl, &vel->le, vel);
	}

	mem_deref(blactual);
}

static bool shutdown_handler(void *arg)
{
	struct sft *sft = arg;

	return sft->ecalls.head == NULL && sft->provisional.ecalls.head == NULL;
}

static int module_init(void)
{
	struct sft *sft;
	struct sa *laddr;
	struct mediapump *mp;
	const char *blacklist;
	const struct pl *secret;
	int err;
	
	info("sft: module loading...\n");

	sft = mem_zalloc(sizeof(*sft), sft_destructor);
	if (!sft)
		return ENOMEM;

	sft->seqno = 1;

	avs_service_register_shutdown_handler(shutdown_handler, sft);

	err = lock_alloc(&sft->lock);
	if (err) {
		error("sft: failed to allock lock: %m\n", err);
		goto out;
	}
	err = dict_alloc(&sft->calls);
	if (err) {
		error("sft: failed to alloc calls dict: %m\n", err);
		goto out;
	}
	err = dict_alloc(&sft->groups);
	if (err) {
		error("sft: failed to alloc groups dict: %m\n", err);
		goto out;
	}
	err = dict_alloc(&sft->provisional.calls);
	if (err) {
		error("sft: failed to alloc provisionals dict: %m\n", err);
		goto out;
	}
	list_init(&sft->provisional.ecalls);

	list_init(&sft->ecalls);
	sft->start_ts = tmr_jiffies();

	mp = mediapump_get("reflow");
	if (!mp) {
		err = ENOSYS;
		goto out;
	}
	err = mediapump_set_handlers(mp,
				     reflow_alloc_handler,
				     reflow_close_handler,
				     reflow_version_handler,
				     reflow_rtp_recv,
				     reflow_rtcp_recv,
				     reflow_dc_recv);
	if (err) {
		warning("sft: mediaflow_set_handlers: failed: %m\n", err);
		goto out;
	}

	laddr = avs_service_req_addr();

	err = httpd_alloc(&sft->httpd, laddr, http_req_handler, sft);
	if (err) {
		error("sft: could not alloc httpd: %m\n", err);
		goto out;
	}

	laddr = avs_service_media_addr();
	sa_cpy(&sft->mediasa, laddr);
	info("sft: using %j as media address\n", &sft->mediasa);

	laddr = avs_service_metrics_addr();
	err = httpd_alloc(&sft->httpd_stats, laddr, http_stats_handler, sft);
	if (err) {
		error("sft: could not alloc stats httpd: %m\n", err);
		goto out;
	}

	laddr = avs_service_sft_req_addr();
	if (sa_isset(laddr, SA_ADDR) && sa_isset(laddr, SA_PORT)) {
		info("sft: starting SFT-request server on: %J\n", laddr);
		err = httpd_alloc(&sft->httpd_sft_req, laddr, sft_req_handler, sft);
		if (err) {
			error("sft: could not alloc sft_req httpd: %m\n", err);
			goto out;
		}
	}

	strcpy(sft->uuid, "_");
	sft->url = avs_service_url();
	info("sft: using sft_url=%s\n", sft->url);

	/* Add any blacklisted clients */
	blacklist = avs_service_blacklist();
	if (blacklist)
		generate_client_blacklist(&sft->cbl, blacklist);

	err = msystem_get(&sft->msys, "audummy", NULL, NULL, sft);
	if (err) {
		error("sft: could not get msystem: %m\n", err);
		goto out;
	}
	msystem_set_project(SFT_PROJECT);
	msystem_set_version(SFT_VERSION);

	secret = avs_service_secret();
	if (secret) {
		size_t clen = sizeof(sft->fed_turn.credential) - 1;
		
		zrest_generate_sft_username(sft->fed_turn.username,
					    sizeof(sft->fed_turn.username));
		zrest_get_password(sft->fed_turn.credential,
				   &clen,
				   sft->fed_turn.username,
				   secret->p, secret->l);
		sft->fed_turn.credential[clen] = '\0';
	}

	info("sft: username: %s cred: %s\n", sft->fed_turn.username, sft->fed_turn.credential);
	
	worker_init();

 out:
	if (err)
		mem_deref(sft);
	else {
		g_sft = sft;
	}

	return err;
}


static int module_close(void)
{
	info("sft: module unloading...\n");

	worker_close();
	
	mem_deref(g_sft);

	return 0;
}
	

EXPORT_SYM const struct mod_export DECL_EXPORTS(sft) = {
	"sft",
	"application",
	module_init,
	module_close,
};


	
