/*
* Wire
* Copyright (C) 2019 Wire Swiss GmbH
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _BSD_SOURCE
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
#include <avs_service.h>

/* Use libre internal rtcp function */
#define	RTCP_PSFB_FIR  4   /* FULL INTRA-FRAME */

#define RTCP_RTPFB_TRANS_CC 15

#define EXTMAP_WSEQ  3

#define USE_RR 0

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
	struct dict *calls;
	struct dict *groups;
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

	uint64_t start_ts;
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

struct group {
	char *id;	
	struct list calll; /* list of calls in this group */
	bool started;
	uint32_t seqno;
};

struct blacklist_elem {
	bool lessthan;
	int major;
	int minor;
	int build;

	struct le le;
};

#define TIMEOUT_SETUP 10000
#define TIMEOUT_CONN 10000
#define TIMEOUT_RR 3000
#define TIMEOUT_FIR 3000
#define TIMEOUT_TRANSCC 150

#define RTP_SEQ_MOD (1<<16)

#define SSRC_MIN_SEQUENTIAL 2
#define SSRC_MAX_DROPOUT 3000
#define SSRC_MAX_MISORDER  100

struct ssrc_stats {
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
	uint16_t rseq;
	uint64_t ts;

	struct le le;
};


struct call;
struct transcc {
	struct call *call;
	uint64_t refts;
	uint8_t fbcnt;
	int seqno;
	struct list pktl;

	uint32_t lssrc;
	uint32_t rssrc;

	struct tmr tmr;
};

struct call {
	struct http_conn *hconn;
	
	char *userid;
	char *clientid;
	char *callid;
	char *sessid;
	struct {
		uint32_t ssrc;
		struct ssrc_stats stats;
		struct transcc tcc;
	} audio;
	struct {
		uint32_t ssrc;
		struct ssrc_stats stats;
		uint8_t fir_seq;
		struct transcc tcc;		
	} video;

	struct sft *sft;
	struct group *group;
	struct icall *icall;
	struct mediaflow *mf;
	struct econn_props *props;

	bool muted;
	bool update;
	bool dc_estab;
	bool active;

	struct list partl;

	struct le group_le;

	struct tmr tmr_setup;
	struct tmr tmr_conn;
	struct tmr tmr_rr;
	struct tmr tmr_fir;
};

struct participant {
	struct group *group;
	struct call *call;
	struct call *self;
	uint32_t ssrca;
	uint32_t ssrcv;
	bool auth;
	struct list authl;

	struct le le;
};

struct auth_part {
	uint32_t ssrca;
	uint32_t ssrcv;
	bool auth;

	struct le le;
};

static int append_group(struct group *group, struct call *call);

#if 0
static char *find_query(const char *path)
{
	char *query;
	
	query = strchr(path, '?');
	if (query)
		++query;

	return query;
}
#endif

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



#if 0
static int parse_query(char *query, struct query_param *params, int max_params)
{
	struct query_param *p;
	int i = 0;

	if (!query || !(*query))
		return -1;

	params[0].key = query;
	++i;
	while (i < max_params && (query = strchr(query, '&'))) {
		*query = '\0';
		params[i].key = ++query;
		params[i].val = NULL;

		/* Go back and split previous param */
		p = &params[i - 1];
		p->val = strchr(p->key, '=');
		if (p->val)
			*(p->val)++ = '\0';
		++i;
	}

	p = &params[i - 1];
	/* Go back and split last param */
	p->val = strchr(p->key, '='); 
	if (p->val)
		*(p->val)++ = '\0';

	return i;
}
#endif


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

	group = dict_lookup(sft->groups, groupid);
	if (!group) {
		warning("find_group: no group for groupid: %s\n", groupid);
		return NULL;
	}

	return group;
}
	
static struct call *find_call(struct sft *sft, const char *callid)
{
	struct call *call;

	call = (struct call *)dict_lookup(sft->calls, callid);
	if (!call) {
		warning("find_call: no call for callid: %s found\n", callid);
		return NULL;
	}

	return call;
}

static void reflow_alloc_handler(struct mediaflow *mf, void *arg)
{
	struct call *call = arg;

	info("reflow_alloc_handler: call(%p)->flow(%p)\n", call, mf);
	call->mf = mf;
}

static void reflow_close_handler(struct mediaflow *mf, void *arg)
{
	struct call *call = arg;

	info("reflow_close_handler: call(%p)->mf(%p) mf: %p\n", call, call->mf, mf);
	if (mf == call->mf)
		call->mf = NULL;
}

static void reflow_recv_dc(const uint8_t *buf, size_t len, void *arg)
{
	struct call *call = arg;

	(void)call;
	SFTLOG(LOG_LEVEL_INFO, "dc packet: %zu bytes\n", call, len);
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
	struct le *le;

	LIST_FOREACH(&call->partl, le) {
		struct participant *part = le->data;
		struct call *pcall = part ? part->call : NULL;

		if (!pcall)
			continue;

		if (streq(pcall->userid, userid)
		    && streq(pcall->clientid, clientid)) {
			return part;
		}
	}
	return NULL;
}

#if USE_TRANSCC

/** Is x less than y? */
static inline bool seq_less(uint16_t x, uint16_t y)
{
	return ((int16_t)(x - y)) < 0;
}

static void add_trans_pkt(struct transcc *tcc, struct transpkt *tp)
{
	bool found = false;
	struct le *le;

	for (le = tcc->pktl.head; !found && le; le = le->next) {
		struct transpkt *p = le->data;

		found = seq_less(tp->seqno, p->seqno);
	}
	if (found)
		list_insert_before(&tcc->pktl, le, &tp->le, tp);
	else
		list_append(&tcc->pktl, &tp->le, tp);
}
#endif

static void blel_destructor(void *arg)
{
	struct blacklist_elem *blel = arg;

	(void)blel;
}

#if USE_TRANSCC

static void transpkt_destructor(void *arg)
{
	(void)arg;
}

static int transcc_encode_handler(struct mbuf *mb, void *arg)
{
	struct transcc *tcc = arg;
	struct le *le;
	uint16_t seqno;
	uint32_t refcnt;
	uint64_t ts = tcc->refts;
	uint64_t deltats;

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

	seqno = (uint16_t)tcc->seqno;
	mbuf_write_u16(mb, htons(seqno));

	le = tcc->pktl.head;
	while(le) {
		struct transpkt *tp = le->data;
		struct le *cur_le;

		cur_le = le;
		le = le->next;
		while(seq_less(seqno, tp->seqno)) {
			struct transpkt *p;
			p = mem_zalloc(sizeof(*p), transpkt_destructor);
			p->seqno = seqno;
			list_insert_before(&tcc->pktl, cur_le, &p->le, p);
			++seqno;
		}
		seqno = tp->seqno + 1;
		ts = tp->ts;
	}
	
	mbuf_write_u16(mb, htons((uint16_t)list_count(&tcc->pktl)));

	/* reference time is in multiples of 64ms */
	refcnt = (((uint32_t)(tcc->refts >> 6)) << 8) | tcc->fbcnt;
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
	le = tcc->pktl.head;
	while(le) {
		uint16_t p = 0xC000;
		int i = 0;

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
	deltats = tcc->refts;
	LIST_FOREACH(&tcc->pktl, le) {
		struct transpkt *tp = le->data;

		if (tp->ts) {
			int64_t delta = tp->ts - deltats;

#if 0
			info("transcc(%u): S=%d refts=%llu ts=%llu D=%dms\n",
			     tcc->rssrc, tp->seqno, tcc->refts, tp->ts, delta);
#endif
			delta *= 4; /* small delta in 250us */
			
			mbuf_write_u16(mb, htons((int16_t)delta));
			deltats = tp->ts;
		}
		else {
			//info("transcc(%u): S=%d missing\n", tcc->rssrc, tp->seqno);
		}
	}

	tcc->refts = ts;
	tcc->fbcnt++;
	tcc->seqno = (int)seqno;

	return 0;
}
#endif

#if 0

static int gnack_encode_handler(struct mbuf *mb, void *arg)
{
	struct call *call = arg;

	mbuf_write_u16(mb, htons(seqno));
	mbuf_write_u16(mb, htons(blm));

	return 0;
}

static void send_gnack(struct call *call, struct transcc *tcc)
{
	struct le *le = tcc->pktl.head;
	struct transpkt *tp;
	int rseq = -1;
	int n = 0;

	while(le) {
		tp = le->data;
		if (rseq < 0 && tp->ts) {
			rseq = tp->rseq;
			sseq = rseq;
		}
		if (rseq >= 0) {
			while (seq_less(rseq, tp->rseq) && n < 16) {
				v = 1 << 16 - n;
				rseq++;
				n++;
				if (n == 16 && tcc->call->mf) {
					err = rtcp_encode(mb,
							  RTCP_RTPFB,
							  RTCP_RTPFB_GNACK,
							  tcc->lssrc,
							  tcc->rssrc,
							  gnack_encode_handler,
							  tcc);

					mediaflow_send_rtcp(tcc->call->mf,
							    mb->buf, mb->end);

					n = 0;
				}
			}
		}

		le = le->next;
	}

	if (n > 0 && tcc->call->mf) {
		err = rtcp_encode(mb,
				  RTCP_RTPFB,
				  RTCP_RTPFB_GNACK,
				  tcc->lssrc,
				  tcc->rssrc,
				  gnack_encode_handler,
				  tcc);

		mediaflow_send_rtcp(tcc->call->mf, mb->buf, mb->end);
	}
#endif

#if USE_TRANSCC
static void transcc_handler(void *arg)	
{
	struct transcc *tcc = arg;
	struct mbuf *mb = NULL;
	int err;

	if (list_count(&tcc->pktl) == 0)
		goto out;
	
	mb = mbuf_alloc(256);
	if (!mb) {
		SFTLOG(LOG_LEVEL_WARN, "transport_cc buf failed\n", tcc->call);
		goto out;
	}
	err = rtcp_encode(mb, RTCP_RTPFB, RTCP_RTPFB_TRANS_CC,
			  tcc->lssrc,
			  tcc->rssrc,
			  transcc_encode_handler, tcc);

	if (err) {
		warning("trans_cc: RTCP-encode failed: %m\n", err);
		goto out;
	}

	if (tcc->call->mf)
		mediaflow_send_rtcp(tcc->call->mf, mb->buf, mb->end);

	//send_gnack(call, tcc);

	list_flush(&tcc->pktl);

 out:
	mem_deref(mb);
	tmr_start(&tcc->tmr, TIMEOUT_TRANSCC, transcc_handler, tcc);
}


static void update_transcc(struct call *call,
			   uint64_t ts,
			   struct transcc *tcc,
			   int wseq,
			   int rseq)
{
	struct transpkt *tp;

	if (tcc->refts == 0)
		tcc->refts = ts;

	if (tcc->seqno == -1)
		tcc->seqno = wseq;

	tp = mem_zalloc(sizeof(*tp), transpkt_destructor);
	tp->seqno = wseq;
	tp->rseq = rseq;
	tp->ts = ts;

	add_trans_pkt(tcc, tp);
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


static void reflow_recv_rtp(const uint8_t *data, size_t len, void *arg)
{
	struct call *call = arg;
	struct le *le;
	struct rtp_header rtp;
	struct mbuf mb;
	int rtpxlen;
	size_t hdrlen;
	struct ssrc_stats *s = NULL;
	uint64_t now = tmr_jiffies();
	struct transcc *tcc = NULL;
	int wseq = -1;

	call->active = true;
	
	mb.buf = (uint8_t *) data;
	mb.pos = 0;
	mb.end = len;
	mb.size = len;

	rtp_hdr_decode(&rtp, &mb);

	rtpxlen = rtp.x.len * sizeof(uint32_t);

	hdrlen = mb.pos;
	if ((size_t)rtpxlen > hdrlen) {
		warning("invalid extension hader length\n");
		goto process_rtp;
	}
		
	mb.pos -= rtpxlen;

#if 0
	info("RTP: len=%d hdrlen=%d m=%d ssrc=%u ts:%u seq: %d ext(%s): type=0x%04X len=%d\n",
	     (int)len, (int)hdrlen, rtp.m, rtp.ssrc, rtp.ts, rtp.seq, rtp.ext ? "yes" : "no", rtp.x.type, rtpxlen);
#endif

	//info("RTP>>> %w\n", data, hdrlen + 16);
#if USE_TRANSCC	
	while(rtpxlen > 0 && mb.pos < hdrlen && mb.pos < mb.end) {
		uint8_t idlen = mbuf_read_u8(&mb);
		uint8_t xid = (idlen & 0xf0) >> 4;
		uint8_t xlen = (idlen & 0x0f) + 1;

		//info("RTP mpos=%d idlen=0x%02x xid=%d xlen=%d\n",
		//     (int)mb.pos, idlen, xid, xlen);

		if (xid == EXTMAP_WSEQ) {
			wseq = ntohs(mbuf_read_u16(&mb));
			//info("RTP-WSEQ: %d\n", (int)wseq);
		}
		else
			mb.pos += xlen;

		rtpxlen -= xlen + sizeof(uint8_t);
	}
#else
	(void)wseq;
#endif

 process_rtp:
	if (call->audio.ssrc && rtp.ssrc == call->audio.ssrc) {
		s = &call->audio.stats;
		tcc = &call->audio.tcc;
		if (!tcc->lssrc && call->mf) {
			tcc->lssrc = mediaflow_get_ssrc(call->mf,
							"audio", true);
		}
		if (!tcc->rssrc) {
			tcc->rssrc = rtp.ssrc;
		}
	}
	else if (call->video.ssrc && rtp.ssrc == call->video.ssrc) {
		s = &call->video.stats;
		tcc = &call->video.tcc;
		if (!tcc->lssrc && call->mf) {
			tcc->lssrc = mediaflow_get_ssrc(call->mf,
							"video", true);
		}
		if (!tcc->rssrc) {
			tcc->rssrc = rtp.ssrc;
		}
	}

	if (s) {
		update_ssrc_stats(s, &rtp, now);
	}
#if USE_TRANSCC
	if (wseq >= 0) {
		if (tcc) {
			update_transcc(call, now, tcc, wseq, rtp.seq);
			if (!tmr_isrunning(&tcc->tmr)) {
				tmr_start(&tcc->tmr, TIMEOUT_TRANSCC,
					  transcc_handler, tcc);
			}
		}
	}
#endif
	
	// Send same packet to all members of this group
	LIST_FOREACH(&call->partl, le) {
		struct participant *part = le->data;
		struct participant *rpart;

		if (!part || !part->call)
			continue;

		/* Lookup this participant in remote list,
		 * so we are sure that both sides have
		 * authorized each other
		 */
		rpart = call2part(part->call, call->userid, call->clientid);
		if (!rpart) {
			warning("part: %s.%s not found for part: %s.%s\n",
				call->userid, call->clientid,
				part->call->userid, part->call->clientid);
			
			continue;
		}
		
		if (part->auth && rpart->auth
		    && ssrc_isauth(part, rtp.ssrc)) {
			if (part->call->mf)
				mediaflow_send_rtp(part->call->mf, data, len);
		}
		else {
#if 0
			warning("not authorized: part: %s.%s auth=%d rpart: %s.%s %u auth=%d\n",
				part->call->userid, part->call->clientid, part->auth,
				rpart->call->userid, rpart->call->clientid,
				rtp.ssrc,
				rpart->auth);
#endif
		}
	}
}

static void reflow_recv_rtcp(const uint8_t *data, size_t len, void *arg)
{
	struct call *call = arg;
	
	call->active = true;
	
#if 0
	struct call *call = arg;
	struct rtcp_msg *rtcp;
	struct mbuf mb;
	int err;

	mb.buf = (uint8_t *)data;
	mb.pos = 0;
	mb.end = len;
	mb.size = mb.end;

	err = rtcp_decode(&rtcp, &mb);
	if (err)
		SFTLOG(LOG_LEVEL_WARN, "cannot decode RTCP packet\n", call);
	else {
		SFTLOG(LOG_LEVEL_INFO, "RTCP %H\n", call, rtcp_msg_print, rtcp);
		mem_deref(rtcp);
	}
#endif
}


static int icall_send_handler(struct icall *icall,
			      const char *userid_sender,
			      struct econn_message *msg,
			      struct list *targets,
			      void *arg)
{
	struct call *call = arg;
	const char *convid;
	char *data = NULL;
	int err = 0;

	(void)targets;

	SFTLOG(LOG_LEVEL_INFO,
	       "icall: %p/%p userid: %s msg: %H\n",
	       call, icall, call->icall, userid_sender,
	       econn_message_brief, msg);

	if (!call->hconn) {
		SFTLOG(LOG_LEVEL_WARN, "no HTTP connection\n", call);
		return ENOSYS;
	}

	/* Override the sessid with the convid associated
	 * with this client's group
	 */
	convid = call->group ? call->group->id : NULL;
	if (convid) {
		str_ncpy(msg->sessid_sender, convid,
			 ARRAY_SIZE(msg->sessid_sender));
	}
	if (msg->msg_type == ECONN_SETUP) {
		if (call->sft && call->sft->url) {
			msg->u.setup.url = mem_deref(msg->u.setup.url);
			str_dup(&msg->u.setup.url, call->sft->url);
		}
		/* In the case the call is in update state
		 * we will need to convert a SETUP to an UPDATE
		 */
		if (call->update) {
			msg->msg_type = ECONN_UPDATE;
		}
	}
	err = econn_message_encode(&data, msg);
	if (err)
		goto out;

 out:

	if (err)
		http_ereply(call->hconn, 500, "Internal error");
	else
		http_creply(call->hconn, 200, "OK", "application/json", "%s", data);
		
	mem_deref(data);
	
	call->hconn = mem_deref(call->hconn);

	return err;
}


static void icall_start_handler(struct icall *icall,
				uint32_t msg_time,
				const char *userid_sender,
				const char *clientid_sender,
				bool video,
				bool should_ring,
				enum icall_conv_type call_type,
				void *arg)
{
	struct call *call = arg;

	SFTLOG(LOG_LEVEL_INFO, "\n", call);
}

static void icall_answer_handler(struct icall *icall, void *arg)
{
	struct call *call = arg;
	
	SFTLOG(LOG_LEVEL_INFO, "\n", call);
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

static int send_conf_part(struct call *call, uint64_t ts,
			  uint8_t *entropy, size_t entropylen)
{
	struct group *group = call->group;
	struct econn_message *msg;
	struct mbuf mb;
	struct le *le;
	size_t n;
	int err = 0;

	if (!group)
		return EINVAL;
	
	msg = econn_message_alloc();
	if (!msg)
		return ENOMEM;

	mbuf_init(&mb);
	econn_message_init(msg, ECONN_CONF_PART, "");

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
			msg->u.confpart.should_start = true;
			group->started = true;
		}
	}

	LIST_FOREACH(&group->calll, le) {
		struct call *pcall = le->data;
		struct econn_group_part *part;

		if (!pcall)
			continue;

		if (!pcall->dc_estab)
			continue;

		part = econn_part_alloc(pcall->userid, pcall->clientid);
		if (!part) {
			err = ENOMEM;
			goto out;
		}
		if (pcall->mf) {
			part->ssrca = mediaflow_get_ssrc(pcall->mf, "audio", false);
			part->ssrcv = mediaflow_get_ssrc(pcall->mf, "video", false);
		}
		part->authorized = false;

		list_append(&msg->u.confpart.partl, &part->le, part);
	}

	n = list_count(&msg->u.confpart.partl);
	SFTLOG(LOG_LEVEL_INFO, "icall: %p %s.%s: with %d parts should_start=%d\n",
	       call, call->icall,
	       call->userid, call->clientid,
	       n,
	       msg->u.confpart.should_start);

	if (n > 0)
		err = ecall_dce_sendmsg((struct ecall *)call->icall, msg);

 out:
	mem_deref(msg);

	return err;
}

static void group_send_conf_part(struct group *group)
{
	uint64_t now;
	struct le *le;
	uint8_t *entropy;
	size_t entropylen;
	bool sent = false;

	now = tmr_jiffies();
	
	entropylen = ENTROPY_LENGTH;
	entropy = mem_alloc(entropylen, NULL);
	if (entropy)
		randombytes_buf(entropy, entropylen);

	LIST_FOREACH(&group->calll, le) {
		struct call *call = le->data;

		if (call) {
			sent = true;
			send_conf_part(call, now, entropy, entropylen);
		}
	}
	if (sent)
		group->seqno++;

	mem_deref(entropy);
}

static int rr_encode_handler(struct mbuf *mb, void *arg)
{
	struct call *call = arg;
	struct rtcp_rr rr;

	if (call->audio.ssrc != 0) {
		rr.ssrc = call->audio.ssrc;
		calc_rr(&rr, &call->audio.stats);
#if 0
		info("call(%p): AUDIO-RR(%u): frac:%d lost:%d ext_seq: %u jitter: %u\n",
		     call, call->audio.ssrc, rr.fraction, rr.lost, rr.last_seq, rr.jitter);
#endif

		rtcp_rr_encode(mb, &rr);
	}

	if (call->video.ssrc != 0) {		
		rr.ssrc = call->video.ssrc;
		calc_rr(&rr, &call->video.stats);
#if 0
		info("call(%p): VIDEO-RR(%u): frac:%d lost:%d ext_seq: %u jitter: %u\n",
		     call, call->video.ssrc, rr.fraction, rr.lost, rr.last_seq, rr.jitter);
#endif
		rtcp_rr_encode(mb, &rr);
	}
		
	return 0;
}


static void rr_handler(void *arg)
{
	struct call *call = arg;
	struct mbuf *mb = NULL;
	uint32_t count = 0;
	int err;

	mb = mbuf_alloc(1024);
	if (!mb) {
		SFTLOG(LOG_LEVEL_WARN, "RTCP buf failed\n", call);
		goto out;
	}

	if (call->audio.ssrc != 0)
		++count;
	if (call->video.ssrc != 0)
		++count;

	if (call->mf) {
		err = rtcp_encode(mb, RTCP_RR,
				  count,
				  mediaflow_get_ssrc(call->mf, "audio", true),
				  rr_encode_handler, call);
		if (err) {
			SFTLOG(LOG_LEVEL_WARN, "RTCP encode failed: %m\n", call, err);
			goto out;
		}

		mediaflow_send_rtcp(call->mf, mb->buf, mb->end);
	}
	mem_deref(mb);

 out:
	tmr_start(&call->tmr_rr, TIMEOUT_RR, rr_handler, call);
}

static int fir_encode_handler(struct mbuf *mb, void *arg)
{
	struct call *call = arg;

	/* FIR-FCI */
	/* 0                   1                   2                   3
	 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                              SSRC                             |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * | Seq nr.       |    Reserved                                   |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	mbuf_write_u32(mb, htonl(call->video.ssrc)); /* SSRC of sender */
	mbuf_write_u8(mb, call->video.fir_seq++); /* seqno */
	mbuf_write_u8(mb, 0);
	mbuf_write_u16(mb, 0);

	return 0;
}

static void send_fir(struct call *call)
{
	struct mbuf *mb = NULL;
	uint32_t lssrc;
	int err;

	if (call->video.ssrc == 0)
		goto out;
	
	mb = mbuf_alloc(256);
	if (!mb) {
		SFTLOG(LOG_LEVEL_WARN, "RTCP buf failed\n", call);
		goto out;
	}

	mb->pos = 0;
	if (call->mf) {
		lssrc = mediaflow_get_ssrc(call->mf, "video", true);
		//info("FIR: lssrc=%u rssrc=%u\n", lssrc, call->video.ssrc);
		err = rtcp_encode(mb, RTCP_PSFB, RTCP_PSFB_FIR,
				  lssrc,
				  call->video.ssrc,
				  fir_encode_handler, call);
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


#if 0
static void send_pli(struct call *call)
{
	struct mbuf *mb = NULL;
	int err;

	if (call->video.ssrc == 0)
		goto out;
	
	mb = mbuf_alloc(256);
	if (!mb) {
		SFTLOG(LOG_LEVEL_WARN, "RTCP buf failed\n", call);
		goto out;
	}

	mb->pos = 0;
	if (call->mf) {
		err = rtcp_encode(mb, RTCP_PSFB, RTCP_PSFB_PLI,
				  mediaflow_get_ssrc(call->mf, "video", true),
				  call->video.ssrc, NULL, NULL);
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
#endif

static void fir_handler(void *arg)
{
	struct call *call = arg;

	send_fir(call);
	//send_pli(call);

	tmr_start(&call->tmr_fir, TIMEOUT_FIR, fir_handler, call);
}

static void conn_handler(void *arg)
{
	struct call *call = arg;

	if (call->active) {
		call->active = false;
		tmr_start(&call->tmr_conn, TIMEOUT_CONN, conn_handler, call);
	}
	else {	
		SFTLOG(LOG_LEVEL_INFO, "connection timeout\n", call);
		
		ICALL_CALL(call->icall, end);
	}
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
	call->dc_estab = true;
	
	SFTLOG(LOG_LEVEL_INFO,
	       "group: %p userid: %s clientid: %s update=%d\n",
	       call, group, userid, clientid, update);	

	if (call->mf) {
		call->audio.ssrc = mediaflow_get_ssrc(call->mf, "audio", false);
		call->video.ssrc = mediaflow_get_ssrc(call->mf, "video", false);
	}
	call->audio.stats.freq_ms = 48;
	call->video.stats.freq_ms = 90;
	
	if (USE_RR)
		tmr_start(&call->tmr_rr, TIMEOUT_RR, rr_handler, call);

	tmr_start(&call->tmr_fir, TIMEOUT_FIR, fir_handler, call);
	tmr_start(&call->tmr_conn, TIMEOUT_CONN, conn_handler, call);
	
	group_send_conf_part(group);
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
	
	g = dict_apply(sft->groups, group_exist_handler, group);

	return g != NULL;
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
	struct group *group = call->group;
	struct sft *sft = call->sft;
	
	SFTLOG(LOG_LEVEL_INFO,
	       "icall=%p calid=%s err=%d userid=%s clientid=%s metrics: %s\n",
	       call, icall, call->callid, err, userid, clientid, metrics_json);

	dict_remove(sft->calls, call->callid);

	if (group_exists(sft, group))	
		group_send_conf_part(group);	
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
			 const char *userid, const char *clientid)
{
	struct econn_message pmsg;
	char *pstr = NULL;
	size_t plen;
	int err;

	if (!call || !props)
		return EINVAL;

	if (!call->mf)
		return ENOSYS;
	
	econn_message_init(&pmsg, ECONN_PROPSYNC, NULL);

	pmsg.resp = true;
	pmsg.u.propsync.props = props;
	str_ncpy(pmsg.src_userid, userid, sizeof(pmsg.src_userid));
	str_ncpy(pmsg.src_clientid, clientid, sizeof(pmsg.src_clientid));

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
	}
 out:
	mem_deref(pstr);

	return err;
}

static int ecall_ping_handler(struct ecall *ecall,
			      bool response,
			      void *arg)
{
	struct call *call = arg;
	
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

	//SFTLOG(LOG_LEVEL_INFO, "\n", call);

	mem_deref(call->props);
	call->props = mem_ref(msg->u.propsync.props);	

	muted_str = econn_props_get(call->props, "muted");
	if (muted_str)
		call->muted = streq(muted_str, "true");
	else
		call->muted = false;

	// Send same packet to all members of this group
	LIST_FOREACH(&call->partl, le) {
		struct participant *part = le->data;

		if (!part || !part->call)
			continue;
		
		if (part->auth) {
			send_propsync(part->call, call->props,
				      call->userid, call->clientid);
		}
	}

	return 0;
}


static void group_destructor(void *arg)
{
	struct group *group = arg;

	mem_deref(group->id);
}

static int alloc_group(struct sft *sft,
		       struct group **groupp,
		       const char *groupid)
{
	struct group *group;

	info("alloc_goup: new group with id: %s\n", groupid);
	
	group = mem_zalloc(sizeof(*group), group_destructor);
	if (!group)
		return ENOMEM;

	group->seqno = 1;
	str_dup(&group->id, groupid);
	list_init(&group->calll);

	dict_add(sft->groups, groupid, group);
	mem_deref(group); /* group is now owned by dictionary */
	sft->stats.group_cnt++;
	
	if (groupp)
		*groupp = group;

	return 0;
}

static int remove_participant(struct call *call, struct call *other)
{
	struct le *le;
	bool found = false;

	if (call == other)
		return 0;

	le = call->partl.head;
	while(le && !found) {
		struct participant *part = le->data;

		le = le->next;
		if (part->call == other) {
			if (call->mf) {
				mediapump_remove_ssrc(call->mf, part->ssrca);
				mediapump_remove_ssrc(call->mf, part->ssrcv);
			}
			mem_deref(part);
			found = true;
		}
	}

	return 0;
}

static void call_destructor(void *arg)
{
	struct call *call = arg;
	struct group *group = call->group;
	struct sft *sft = call->sft;
	struct le *le;

	SFTLOG(LOG_LEVEL_INFO, "\n", call);
	
	tmr_cancel(&call->tmr_setup);
	tmr_cancel(&call->tmr_rr);
	tmr_cancel(&call->tmr_fir);
	tmr_cancel(&call->tmr_conn);
	tmr_cancel(&call->audio.tcc.tmr);
	tmr_cancel(&call->video.tcc.tmr);
	
	list_unlink(&call->group_le);

	/* Remove all the participants this
	 * call is connected with
	 */
	LIST_FOREACH(&call->partl, le) {
		struct participant *part = le->data;
		struct call *other = part ? part->call : NULL;

		if (call && other)
			remove_participant(other, call);
	}
	list_flush(&call->partl);

	list_flush(&call->audio.tcc.pktl);
	list_flush(&call->video.tcc.pktl);
	
	mem_deref(call->callid);
	mem_deref(call->clientid);
	mem_deref(call->userid);
	mem_deref(call->sessid);
	mem_deref(call->props);
	mem_deref(call->icall);

	/* Finally check, if we were the last participant in the group,
	 * if we were, remove group.
	 */
	info("call(%p): belongs to group: %p(%s) in group: %d\n",
	     call, group,
	     group ? group->id : "?",
	     group ? (int)list_count(&group->calll) : (int)0);

	if (group && group->calll.head == NULL) {
		dict_remove(sft->groups, group->id);
	}
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

	LIST_FOREACH(partl, le) {
		struct econn_group_part *part = le->data;

#if 0
		SFTLOG(LOG_LEVEL_INFO, "part: %s.%s ssrca=%u ssrcv=%u auth=%d\n",
		       call, part->userid, part->clientid, part->ssrca, part->ssrcv, part->authorized);
#endif

		/* Find the call for the participant */
		rpart = call2part(call, part->userid, part->clientid);
		if (rpart && rpart->call) {
			/* lookup ourselves in the remote participant's list */
			lpart = call2part(rpart->call,
					  call->userid, call->clientid);
			if (lpart) {
				struct auth_part *aup;

				aup = mem_zalloc(sizeof(*aup), NULL);
				aup->ssrca = part->ssrca;
				aup->ssrcv = part->ssrcv;
				aup->auth = part->authorized;

				list_append(&lpart->authl, &aup->le, aup);

				lpart->auth = part->authorized;
				send_propsync(rpart->call, call->props,
					      call->userid, call->clientid);
			}
		}
	}
}


static int alloc_icall(struct call *call,
		       struct zapi_ice_server *turnv, size_t turnc,
		       const char *cid)
{
	struct ecall *ecall;
	int err = 0;
	size_t i;
	
	err = ecall_alloc(&ecall, &call->sft->ecalls,
			  ICALL_CONV_TYPE_ONEONONE,
			  NULL, call->sft->msys,
			  cid, SFT_USERID, call->sft->uuid);
	if (err) {
		SFTLOG(LOG_LEVEL_WARN, "ecall_alloc failed: %m\n",
		       call, err);
		goto out;
	}
	ecall_set_confpart_handler(ecall, ecall_confpart_handler);
	
	/* Add any turn servers we may have */
	for (i = 0; i < turnc; ++i)
		ecall_add_turnserver(ecall, &turnv[i]);

	if (call->icall)
		mem_deref(call->icall);

	call->icall = ecall_get_icall(ecall);

	icall_set_callbacks(call->icall,
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
			    NULL, // req_clients_handler,
			    call);
	ICALL_CALL(call->icall, set_media_laddr, &g_sft->mediasa);

 out:
	return err;
}

static int alloc_call(struct call **callp, struct sft *sft,
		      struct zapi_ice_server *turnv, size_t turnc,
		      struct group *group,
		      const char *userid, const char *clientid,
		      const char *callid, const char *sessid)
{
	struct call *call = NULL;
	int err = 0;

	if (!callp)
		return EINVAL;

	call = mem_zalloc(sizeof(*call), call_destructor);
	if (!call) {
		err = ENOMEM;
		goto out;
	}

	SFTLOG(LOG_LEVEL_INFO, "\n", call);
	
	str_dup(&call->userid, userid);
	str_dup(&call->clientid, clientid);
	str_dup(&call->callid, callid);
	str_dup(&call->sessid, sessid);
	call->sft = sft;
	call->group = group;

	call->audio.tcc.call = call;
	call->audio.tcc.seqno = -1;
	call->audio.tcc.refts = 0;
	call->audio.tcc.fbcnt = 0;

	call->video.tcc.call = call;
	call->audio.tcc.seqno = -1;
	call->video.tcc.refts = 0;
	call->video.tcc.fbcnt = 0;

	tmr_init(&call->tmr_setup);
	tmr_init(&call->tmr_conn);
	tmr_init(&call->tmr_rr);
	tmr_init(&call->tmr_fir);

	err = alloc_icall(call, turnv, turnc, group->id);
	if (err) {
		goto out;
	}

	dict_add(sft->calls, callid, call);
	mem_deref(call); /* call is now owned by dictionary */
	sft->stats.call_cnt++;
	append_group(group, call);
	

 out:
	if (err) {
		mem_deref(call);
	}
	else {
		*callp = call;
	}
	return err;

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

static void setup_timeout_handler(void *arg)
{
	struct call *call = arg;

	info("call(%p): setup_timeout_handler\n", call);
	ICALL_CALL(call->icall, end);
}


static int start_icall(struct call *call)
{
	struct ecall *ecall = (struct ecall *)call->icall;
	int err;
	
	SFTLOG(LOG_LEVEL_INFO,
	       "starting icall: %p\n",
	       call, call->icall);

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
			  false);
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

static bool print_group_handler(char *key, void *val, void *arg)
{
	struct group *group = val;
	struct le *le;

	info("group(%p): groupid=%s calls:%d\n", group, group->id, list_count(&group->calll));

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
	char *url;
	struct mbuf *mb = NULL;
	char *stats = NULL;
	uint64_t now;
	int err = 0;;

	pl_strdup(&url, &msg->path);
	info("http_stats_req: URL=%s\n", url);

#if 1
	if (streq(url, "/debug")) {
		info("Calls in list: %d\n", (int)dict_count(sft->groups));
		dict_apply(sft->calls, print_group_handler, NULL);
		info("Parts in list: %d\n", (int)dict_count(sft->calls));
		dict_apply(sft->calls, print_call_handler, NULL);
		http_creply(hc, 200, "OK", "text/plain", "Debug\n");
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

static int ver2blel(const char *ver, struct blacklist_elem *blel)
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
	blel->major = v ? atoi(v) : -1;
	v = strsep(&vstr, ".");
	blel->minor = v ? atoi(v) : -1;
	if (!vstr) 
		blel->build = -1;
	else {
		if (streq(vstr, "local"))
			blel->build = 999;
		else
			blel->build = atoi(vstr);
	}

	//info("ver: %s to blel: %d.%d.%d\n",
	//     ver, blel->major, blel->minor, blel->build);
	
	mem_deref(vactual);

	return 0;
}

static bool is_blacklisted(const char *ver, struct list *cbl)
{
	struct blacklist_elem bver;
	bool found = false;
	struct le *le;

	//info("is_blacklisted: ver=%s cbl=%p head=%p\n", ver, cbl, cbl->head);

	if (!ver || !cbl || !cbl->head)
		return false;

	ver2blel(ver, &bver);

	/* Never blacklist master builds which have version 0.0.x */
	if (bver.major == 0 && bver.minor == 0)
		return false;
	
	for(le = cbl->head; !found && le; le = le->next) {
		struct blacklist_elem *blel = le->data;

		//info("is_blacklisted: lt:%d %d.%d.%d\n", blel->lessthan, blel->major, blel->minor, blel->build);
		if (blel->lessthan) {
			found = bver.major < blel->major;
			if (found)
				continue;
			
			if (bver.major == blel->major) {
				found = bver.minor < blel->minor;
				if (found)
					continue;
				
				if (bver.minor == blel->minor)
					found = bver.build < blel->build;
			}
		}
		else {
			found = bver.major == blel->major
			     && bver.minor == blel->minor
			     && bver.build == blel->build;
		}
	}

	//info("is_blacklisted: %d.%d.%d %s\n", bver.major, bver.minor, bver.build, found ? "YES" : "NO");
	
	return found;
}

static int reply_blacklist(struct http_conn *hc, struct econn_message *msg)
{
	//struct econn_message *msg;
	char *rstr;
	int err;

	//msg = econn_message_alloc();
	//if (!msg)
	//	return ENOMEM;

	//econn_message_init(msg, ECONN_CONF_CONN, "sft");
	msg->u.confconn.status = ECONN_CONFCONN_REJECTED_BLACKLIST;

	err = econn_message_encode(&rstr, msg);
	if (err) {
		warning("reply_blacklist: failed to encode message: %m\n", err);
		return err;
	}

	http_creply(hc, 200, "OK", "application/json", "%s", rstr);

	mem_deref(rstr);
	//mem_deref(msg);

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

static void deauth_call(struct call *call)
{
	struct le *le;
	
	LIST_FOREACH(&call->partl, le) {
		struct participant *part = le->data;
		struct participant *lpart;
		
		if (!part)
			continue;

		list_flush(&part->authl);
		part->auth = false;
		lpart = call2part(part->call, call->userid, call->clientid);
		if (lpart) {
			list_flush(&lpart->authl);
			lpart->auth = false;
		}
	}
	call->dc_estab = false;
}


static void http_req_handler(struct http_conn *hc,
			     const struct http_msg *msg,
			     void *arg)
{
	struct sft *sft = arg;
#if 0
	struct query_param qp[2];
	char *query;
	int i;
#endif
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
	char *toolver;
	char *body = NULL;
	int n;
	int err = 0;

	pl_strdup(&url, &msg->path);
	pl_strdup(&params, &msg->prm);

#if 0
	query = find_query(params);
	if (!query) {
		warning("sft: missing query\n");
		err = EINVAL;
		goto bad_req;
	}
#endif
       
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
				call->hconn = mem_deref(call->hconn);
				err = EINVAL;
				goto bad_req;
			}
			tmr_cancel(&call->tmr_setup);
			/* If call is in updateing state, it means
			 * we need to convert client's UPDATE to a SETUP
			 */
			if (call->update) {
				cmsg->msg_type = ECONN_SETUP;
				call->update = false;
			}
			err = ICALL_CALLE(call->icall, msg_recv, 0, 0,
					  userid, clientid, cmsg);
			if (err) {
				SFTLOG(LOG_LEVEL_WARN,
				       "msg_recv failed\n", call);
				call->hconn = mem_deref(call->hconn);
				goto bad_req;
			}
			err = reply_msg(hc, cmsg);
			if (err) {
				SFTLOG(LOG_LEVEL_WARN,
				       "reply_msg failed\n", call);
				call->hconn = mem_deref(call->hconn);
				goto bad_req;
			}
			break;

		case ECONN_CONF_CONN:
			toolver = cmsg->u.confconn.toolver;
			info("sft: incoming request for updating call from client with toolver: %s\n", toolver);
			if (is_blacklisted(toolver, &sft->cbl)) {
				warning("sft: client version: %s is blacklisted\n", toolver);
				err = reply_blacklist(hc, cmsg);
				goto out;
			}
			if (cmsg->u.confconn.update) {
				info("sft: restarting call: %p\n", call);
				call->hconn = mem_deref(call->hconn);
				call->hconn = mem_ref(hc);
				
				deauth_call(call);
				/* We want to move this call to the end of the list,
				 * so it loses its KG privilage on the clients
				 */
				list_unlink(&call->group_le);
				err = ecall_restart((struct ecall *)call->icall,
						    ICALL_CALL_TYPE_VIDEO);
				if (err) {
					call->hconn = mem_deref(call->hconn);
					goto out;
				}
				/* Re-add the call to the group, at the end of the list */
				if (call->group)
					list_append(&call->group->calll, &call->group_le, call);
			}
			else {
				info("sft: recreating call: %p\n", call);
				call->mf = NULL;
				deauth_call(call);
				
				call->hconn = mem_deref(call->hconn);
				call->hconn = mem_ref(hc);

				/* We want to move this call to the end of the list,
				 * so it loses its KG privilage on the clients
				 */
				list_unlink(&call->group_le);

				if (!call->group) {
					err = ENOENT;
					goto out;
				}				
				alloc_icall(call,
					    cmsg->u.confconn.turnv,
					    cmsg->u.confconn.turnc,
					    call->group->id);
				err = start_icall(call);
				if (err) {
					call->hconn = mem_deref(call->hconn);
					goto out;
				}
				/* Re-add the call to the group, at the end of the list */
				if (call->group)
					list_append(&call->group->calll, &call->group_le, call);
			}
			break;

		default:
			break;
		}
	}
	else {
		if (pl_strcmp(&msg->met, "POST") != 0) {
			err = EINVAL;
			goto bad_req;
		}
		else {
			if (cmsg->msg_type != ECONN_CONF_CONN) {
				err = EINVAL;
				goto bad_req;
			}

			toolver = cmsg->u.confconn.toolver;
			info("sft: incoming request for new call from toolver: %s\n", toolver);
			if (is_blacklisted(toolver, &sft->cbl)) {
				warning("sft: client version: %s is blacklisted\n", toolver);
				reply_blacklist(hc, cmsg);
				err = 0;
				goto out;
			}

			if (!group) {
				err = alloc_group(sft, &group, convid);
				if (err)
					goto out;

				group_created = true;				
			}
						
			err = alloc_call(&call, sft,
					 cmsg->u.confconn.turnv,
					 cmsg->u.confconn.turnc,
					 group, userid, clientid,
					 callid, cmsg->sessid_sender);
			if (err) {
				goto out;
			}

			if (cmsg->u.confconn.update) {
				call->update = true;
				if (!group->started)
					group->started = true;
			}

			call->hconn = mem_ref(hc);
			err = start_icall(call);
			if (err) {
				call->hconn = mem_deref(call->hconn);
				goto out;
			}
				
		}
	}
	
 out:
 bad_req:
	if (err && group_created)
		dict_remove(sft->groups, convid);

	mem_deref(cmsg);
	mem_deref(callid);
	mem_deref(url);
	mem_deref(params);

	if (err)
		http_ereply(hc, 400, "Bad request");
}

static void sft_destructor(void *arg)
{
	struct sft *sft = arg;

	dict_flush(sft->calls);
	mem_deref(sft->calls);
	dict_flush(sft->groups);
	mem_deref(sft->groups);
	list_flush(&sft->cbl);
	list_flush(&sft->ecalls);

	mem_deref(sft->httpd);
	mem_deref(sft->httpd_stats);
	mem_deref(sft->msys);
}

static void part_destructor(void *arg)
{
	struct participant *part = arg;
	
	list_unlink(&part->le);

	list_flush(&part->authl);
}

static int append_participant(struct group *group,
			      struct call *call, struct call *other)
{
	struct participant *part;
	size_t n = 1;
	size_t i;

	for (i = 0; i < n; ++i) {
		part = mem_zalloc(sizeof(*part), part_destructor);
		if (!part)
			return ENOMEM;

		part->group = group;
		part->call = other;
		part->self = call;
		part->ssrca = other->audio.ssrc;
		part->ssrcv = other->video.ssrc;

		list_init(&part->authl);
		list_append(&call->partl, &part->le, part);
		
	}

	return 0;
}

static int append_group(struct group *group, struct call *call)
{
	struct le *le;

	info("call(%p): adding to group:%p\n", call, group);

	LIST_FOREACH(&group->calll, le) {
		struct call *cg = le->data;

		/* Append the other participants to this call */
		append_participant(group, call, cg);
		/* Append this call to other participants */
		append_participant(group, cg, call);
	}

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
		struct blacklist_elem *blel;

		blel = mem_zalloc(sizeof(*blel), blel_destructor);
		while(isspace(*vstr)) {
			++vstr;
		}

		if (*vstr == '<') {
			blel->lessthan = true;
			++vstr;
		}
		ver2blel(vstr, blel);
		list_append(cbl, &blel->le, blel);
	}

	mem_deref(blactual);
}


static int module_init(void)
{
	struct sft *sft;
	struct sa *laddr;
	struct mediapump *mp;
	const char *blacklist;
	int err;
	
	info("sft: module loading...\n");

	sft = mem_zalloc(sizeof(*sft), sft_destructor);
	if (!sft)
		return ENOMEM;

	sft->seqno = 1;
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
				     reflow_recv_rtp,
				     reflow_recv_rtcp,
				     reflow_recv_dc);
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

	mem_deref(g_sft);

	return 0;
}
	

EXPORT_SYM const struct mod_export DECL_EXPORTS(sft) = {
	"sft",
	"application",
	module_init,
	module_close,
};


	
