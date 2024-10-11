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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <re.h>
#include <rew.h>
#include "avs_log.h"
#include "avs_version.h"
#include "aucodec.h"
#include "avs_uuid.h"
#include "avs_zapi.h"
#include "avs_base.h"
#include "avs_keystore.h"
#include "avs_icall.h"
#include "avs_iflow.h"
#include "avs_extmap.h"
#include "avs_cert.h"
#include "reflow.h"
#include "vidcodec.h"
#include "avs_network.h"
#include "priv_reflow.h"
#include "mediastats.h"
#include "avs_msystem.h"
#include "avs_string.h"

#include "avs_service.h"
#include "avs_service_turn.h"
#include "dce.h"

#ifdef __APPLE__
#       include "TargetConditionals.h"
#endif

#define RFLOG(level, fmt,  ...) loglv(level, "reflow:%s(%p): "fmt, __FUNCTION__, __VA_ARGS__)

#define MAGIC 0xed1af100
#define MAGIC_CHECK(s) \
	if (MAGIC != s->magic) {                                        \
		warning("%s: wrong magic struct=%p (magic=0x%08x)\n",   \
			__REFUNC__, s, s->magic);			\
		BREAKPOINT;                                             \
	}


#define MAX_SRTP_KEY_SIZE (32+14)  /* Master key and salt */

#define NUM_RTP_STREAMS 2

enum {
	RTP_TIMEOUT_MS = 20000,
	RTP_FIRST_PKT_TIMEOUT_MS = 10000,
	RTP_RESTART_TIMEOUT_MS = 2000,
	DCE_TIMEOUT_MS = 5000,
	DTLS_MTU       = 1480,
	SSRC_MAX       = 4,
	ICE_INTERVAL   = 50,    /* milliseconds */
	PORT_DISCARD   = 9,     /* draft-ietf-ice-trickle-05 */
	UDP_SOCKBUF_SIZE = 160*1024,  /* same as Android */
};

enum {
	AUDIO_BANDWIDTH = 32,   /* kilobits/second */
	AUDIO_PTIME     = 40,   /* ms */
	VIDEO_BANDWIDTH = 800,  /* kilobits/second */
};

enum {
	GROUP_PTIME = 60
};


enum sdp_state {
	SDP_IDLE = 0,
	SDP_GOFF,
	SDP_HOFF,
	SDP_DONE
};

struct interface {
	struct le le;

	const struct reflow *rf;     /* pointer to parent */
	const struct ice_lcand *lcand;  /* pointer */
	struct sa addr;
	char ifname[64];
	bool is_default;
};

struct auformat {
	struct sdp_format *fmt;
	const struct aucodec *ac;
	
	struct le le; /* Member of audio format list */
};

struct dtls_peer {
	struct le le;
	size_t headroom;
	struct sa addr;
};

static struct {
	bool initialized;
	struct tls *dtls;
	struct list rfl;
	struct list aucodecl;
	struct list vidcodecl;

	struct {
		struct mediapump *mp;
		mediaflow_alloc_h *alloch;
		mediaflow_close_h *closeh;
		mediaflow_recv_data_h *recv_rtph;
		mediaflow_recv_data_h *recv_rtcph;
		mediaflow_recv_dc_h *recv_dch;
	} mediaflow;
	void *mf_arg;
} g_reflow = {
	.initialized = false,
	.rfl = LIST_INIT,
	.aucodecl = LIST_INIT,
	.vidcodecl = LIST_INIT,
};

struct reflow {
	struct iflow iflow;

	enum icall_conv_type conv_type;
	enum icall_call_type call_type;
	/* common stuff */
	char *clientid_local;
	char *clientid_remote;
	char *userid_remote;
	struct sa laddr_default;
	struct sa media_laddr;	
	char tag[32];
	bool terminated;
	bool closed;
	bool destructed;
	int af;
	int err;

	/* RTP/RTCP */
	struct udp_sock *rtp;
	struct rtp_stats audio_stats_rcv;
	struct rtp_stats audio_stats_snd;
	struct rtp_stats video_stats_rcv;
	struct rtp_stats video_stats_snd;
	struct aucodec_stats codec_stats;

	uint32_t lssrcv[MEDIA_NUM];
	char cname[16];             /* common for audio+video */
	char msid[36];
	char *label;

	/* SDP */
	struct sdp_session *sdp;
	bool sdp_offerer;
	bool got_sdp;
	bool sent_sdp;
	enum sdp_state sdp_state;
	char sdp_rtool[64];
	struct extmap *extmap;

	/* ice: */
	struct trice *trice;
	struct stun *trice_stun;
	struct udp_helper *trice_uh;
	struct ice_candpair *sel_pair;    /* chosen candidate-pair */
	struct udp_sock *us_stun;
	struct list turnconnl;

	struct tmr tmr_rtp;
	struct tmr tmr_error;

	char ice_ufrag[16];
	char ice_pwd[32];
	bool ice_ready;
	char *peer_software;
	uint64_t ts_nat_start;

	/* ice - gathering */
	struct stun_ctrans *ct_gather;
	bool ice_local_eoc;
	bool ice_remote_eoc;
	bool stun_server;
	bool stun_ok;

	/* crypto: */
	enum media_crypto cryptos_local;
	enum media_crypto cryptos_remote;
	enum media_crypto crypto;          /* negotiated crypto */
	enum media_crypto crypto_fallback;
	struct udp_helper *uh_srtp;
	struct srtp *srtp_tx;
	struct srtp *srtp_rx;
	struct tls *dtls;
	struct dtls_sock *dtls_sock;
	struct udp_helper *dtls_uh;   /* for outgoing DTLS-packet */
	struct tls_conn *tls_conn;
	struct list dtls_peers;     /* list of DTLS-peers (struct dtls_peer) */
	enum media_setup setup_local;
	enum media_setup setup_remote;
	bool crypto_ready;
	bool crypto_verified;
	uint64_t ts_dtls;
	enum srtp_suite srtp_suite;

	/* Codec handling */
	struct media_ctx *mctx;
	struct auenc_state *aes;
	struct audec_state *ads;
	pthread_mutex_t mutex_enc;  /* protect the encoder state */
	bool started;
	bool hold;

	/* Video */
	struct {
		struct sdp_media *sdpm;
		struct media_ctx *mctx;
		struct videnc_state *ves;
		struct viddec_state *vds;

		bool has_media;
		bool started;
		char *label;
		bool has_rtp;
		bool disabled;

		char fingerprint[512];
	} video;

	/* Data */
	struct {
		struct sdp_media *sdpm;

		struct dce *dce;
		struct dce_channel *ch;

		bool has_media;
		bool ready;
		uint64_t ts_connect;
	} data;

	/* Audio */
	struct {
		struct sdp_media *sdpm;
		struct list formatl;

		bool disabled;
		bool local_cbr;
		bool remote_cbr;

		char fingerprint[512];
	} audio;
    
	/* User callbacks */
	struct {
		struct {
			uint64_t ts_first;
			uint64_t ts_last;
			size_t bytes;
		} tx, rx;

		size_t n_sdp_recv;
		size_t n_srtp_dropped;
		size_t n_srtp_error;
	} stat;

	bool sent_rtp;
	bool got_rtp;

	struct list interfacel;

	struct reflow_stats rf_stats;
	bool privacy_mode;
	bool group_mode;

	void *extarg;

	struct zapi_ice_server turnv[MAX_TURN_SERVERS];
	size_t turnc;

	
	/* magic number check at the end of the struct */
	uint32_t magic;

	struct le le;

	struct mediaflow *mf;
	struct worker *worker;

	/* RTP streams */
	struct {
		uint32_t *assrcv;
		int assrcc;
		uint32_t *vssrcv;
		int vssrcc;
	} rtps;
};


struct vid_ref {
	struct vidcodec *vc;
	struct reflow *rf;
};


/* Use standard logging */
#if 0
#undef debug
#undef info
#undef warning
#define debug(...)   rf_log(rf, LOG_LEVEL_DEBUG, __VA_ARGS__);
#define info(...)    rf_log(rf, LOG_LEVEL_INFO,  __VA_ARGS__);
#define warning(...) rf_log(rf, LOG_LEVEL_WARN,  __VA_ARGS__);
#endif


#if TARGET_OS_IPHONE
#undef OS
#define OS "ios"
#endif


/* 0.0.0.0 port 0 */
static const struct sa dummy_dtls_peer = {

	.u = {
		.in = {
			 .sin_family = AF_INET,
			 .sin_port = 0,
			 .sin_addr = {0}
		 }
	},

	.len = sizeof(struct sockaddr_in)

};


/* prototypes */
static int print_cand(struct re_printf *pf, const struct ice_cand_attr *cand);
static void add_turn_permission(struct reflow *rf,
				   struct turn_conn *conn,
				   const struct ice_cand_attr *rcand);
static void add_permission_to_remotes(struct reflow *rf);
static void add_permission_to_remotes_ds(struct reflow *rf,
					 struct turn_conn *conn);
static void external_rtp_recv(struct reflow *rf,
			      const struct sa *src, struct mbuf *mb);
static bool headroom_via_turn(size_t headroom);


#if 0
static void rf_log(const struct reflow *rf, enum log_level level,
		   const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	int n;

	va_start(ap, fmt);

	n = re_snprintf(buf, sizeof(buf), "[%p] ", rf);
	str_ncpy(&buf[n], fmt, strlen(fmt)+1);
	fmt = buf;

	vloglv(level, fmt, ap);
	va_end(ap);
}
#endif


static struct dtls_peer *dtls_peer_find(struct reflow *rf,
					size_t headroom, const struct sa *addr)
{
	struct le *le;

	for (le = list_head(&rf->dtls_peers); le; le = le->next) {
		struct dtls_peer *dtls_peer = le->data;
		const bool t1 = headroom_via_turn(headroom);
		const bool t2 = headroom_via_turn(dtls_peer->headroom);

		if (t1 == t2 &&
		    sa_cmp(addr, &dtls_peer->addr, SA_ALL))
			return dtls_peer;
	}

	return NULL;
}


static const char *crypto_name(enum media_crypto crypto)
{
	switch (crypto) {

	case CRYPTO_NONE:      return "None";
	case CRYPTO_DTLS_SRTP: return "DTLS-SRTP";
	default:               return "???";
	}
}


int reflow_cryptos_print(struct re_printf *pf, enum media_crypto cryptos)
{
	int err = 0;

	if (!cryptos)
		return re_hprintf(pf, "%s", crypto_name(CRYPTO_NONE));

	if (cryptos & CRYPTO_DTLS_SRTP) {
		err |= re_hprintf(pf, "%s ", crypto_name(CRYPTO_DTLS_SRTP));
	}
	return err;
}

const char *reflow_setup_name(enum media_setup setup)
{
	switch (setup) {

	case SETUP_ACTPASS: return "actpass";
	case SETUP_ACTIVE:  return "active";
	case SETUP_PASSIVE: return "passive";
	default: return "?";
	}
}


static enum media_setup setup_resolve(const char *name)
{
	if (0 == str_casecmp(name, "actpass")) return SETUP_ACTPASS;
	if (0 == str_casecmp(name, "active")) return SETUP_ACTIVE;
	if (0 == str_casecmp(name, "passive")) return SETUP_PASSIVE;

	return (enum media_setup)-1;
}


static const char *sock_prefix(size_t headroom)
{
	if (headroom >= 36) return "TURN-Ind";
	if (headroom >= 4) return "TURN-Chan";

	return "Socket";
}


static bool headroom_via_turn(size_t headroom)
{
	return headroom >= 4;
}


bool reflow_dtls_peer_isset(const struct reflow *rf)
{
	struct dtls_peer *dtls_peer;

	if (!rf)
		return false;

	dtls_peer = list_ledata(rf->dtls_peers.head);
	if (!dtls_peer)
		return false;

	return sa_isset(&dtls_peer->addr, SA_ALL);
}


static int dtls_peer_print(struct re_printf *pf,
			   const struct dtls_peer *dtls_peer)
{
	if (!dtls_peer)
		return 0;

	return re_hprintf(pf, "%s|%zu|%J",
			  sock_prefix(dtls_peer->headroom),
			  dtls_peer->headroom,
			  &dtls_peer->addr);
}


bool reflow_is_rtpstarted(const struct reflow *rf)
{
	if (!rf)
		return false;

	return rf->got_rtp;
	//return rf->sent_rtp && rf->got_rtp;
}


#if 0
static bool reflow_is_video_started(const struct reflow *rf)
{
	if (!rf)
		return false;

	return rf->video.has_rtp;
}
#endif


static size_t get_headroom(const struct reflow *rf)
{
	size_t headroom = 0;

	if (!rf)
		return 0;

	if (!rf->sel_pair)
		return 0;

	if (rf->sel_pair->lcand->attr.type == ICE_CAND_TYPE_RELAY)
		return 36;
	else
		return 0;


	return headroom;
}


static void ice_error(struct reflow *rf, int err)
{
	warning("reflow(%p): error in ICE-transport (%m)\n", rf, err);

	rf->ice_ready = false;
	rf->err = err;

	list_flush(&rf->interfacel);

	list_flush(&rf->turnconnl);

	rf->trice_uh = mem_deref(rf->trice_uh);  /* note: destroy first */
	rf->sel_pair = mem_deref(rf->sel_pair);

	rf->terminated = true;

	IFLOW_CALL_CB(rf->iflow, closeh,
		err, rf->iflow.arg);
}


static void tmr_error_handler(void *arg)
{
	struct reflow *rf = arg;

	ice_error(rf, rf->err);
}


static void crypto_error(struct reflow *rf, int err)
{
	warning("reflow(%p): error in DTLS (%m)\n", rf, err);

	rf->crypto_ready = false;
	rf->err = err;
	rf->tls_conn = mem_deref(rf->tls_conn);

	rf->terminated = true;

	IFLOW_CALL_CB(rf->iflow, closeh,
		err, rf->iflow.arg);
}


bool reflow_is_ready(const struct reflow *rf)
{
	if (!rf)
		return false;

	if (!rf->ice_ready)
		return false;

	if (rf->cryptos_local == CRYPTO_NONE)
		return true;

	if (rf->crypto == CRYPTO_NONE)
		return false;
	else
		return rf->crypto_ready;

	return true;
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

/* XXX: Move to mediamanager */

static int start_codecs(struct reflow *rf)
{
	return 0;
}

static const uint8_t app_label[4] = "DATA";


static int send_rtcp_app(struct reflow *rf, const uint8_t *pkt, size_t len)
{
	struct mbuf *mb = mbuf_alloc(len);
	int err;

	err = rtcp_encode(mb, RTCP_APP, 0, (uint32_t)0, app_label, pkt, len);
	if (err) {
		warning("reflow(%p): rtcp_encode failed (%m)\n", rf, err);
		goto out;
	}

	err = reflow_send_raw_rtcp(rf, mb->buf, mb->end);
	if (err) {
		warning("reflow(%p): send_raw_rtcp failed (%m)\n", rf, err);
	}

 out:
	mem_deref(mb);
	return err;
}

static int reflow_send_dc_data(struct reflow *rf, const uint8_t *data, size_t len)
{
	int err = ENOSYS;

	if (!rf)
		return EINVAL;

	if (rf->err)
		return rf->err;
	
	if (rf->data.dce && rf->data.ch) {
		err = dce_send(rf->data.dce, rf->data.ch, data, len);
		if (!rf->err && err) {
			rf->err = err;
			IFLOW_CALL_CB(rf->iflow, closeh, err, rf->iflow.arg);
		}
	}

	return err;
	
}

static int reflow_dce_send(struct iflow *flow, const uint8_t *data, size_t len)
{
	struct reflow *rf = (struct reflow *)flow;

	return reflow_send_dc_data(rf, data, len);
}


static int dce_send_data_handler(struct mbuf *mb, void *arg)
{
	struct reflow *rf = arg;
	size_t len = mbuf_get_left(mb);
	int err = 0;

	if (!reflow_is_ready(rf)) {
		warning("reflow(%p): send_data(%zu bytes): not ready"
			" [ice=%d, crypto=%d]\n",
			rf, len, rf->ice_ready, rf->crypto_ready);
		return EINTR;
	}

#if 0
	info("reflow(%p): sending DCE packet: %zu tls_conn=%p\n",
	     rf, len, rf->tls_conn);
#endif

	switch (rf->crypto) {

	case CRYPTO_DTLS_SRTP:
		if (rf->tls_conn) {
			err = dtls_send(rf->tls_conn, mb);
		}
		else {
			warning("reflow(%p): dce_send_data:"
				" no DTLS connection\n", rf);
			return ENOENT;
		}
		break;

	default:
		warning("reflow(%p): dce_send_data: invalid crypto %d\n",
			rf, rf->crypto);
		return EPROTO;
	};

	return err;
}


static void dce_estab_handler(void *arg)
{
	struct reflow *rf = arg;

	rf->rf_stats.dce_estab = (int)(tmr_jiffies() - rf->data.ts_connect);

	info("reflow(%p): dce established (%d ms)\n",
	     rf, rf->rf_stats.dce_estab);

	rf->data.ready = true;
}


static int start_video_codecs(struct reflow *rf)
{
	return 0;
}


static void timeout_rtp(void *arg)
{
	struct reflow *rf = arg;
	bool rtp_started = reflow_is_rtpstarted(rf);
	int diff;

	diff = (int)(tmr_jiffies() - rf->stat.rx.ts_last);

	if (!rtp_started) {
		info("reflow(%p): no RTP received\n", rf);
		rf->terminated = true;
		rf->ice_ready = false;
		
		IFLOW_CALL_CB(rf->iflow, closeh, ETIMEDOUT, rf->iflow.arg);
		return;
	}

	tmr_start(&rf->tmr_rtp, 2000, timeout_rtp, rf);
	
	if (diff > RTP_TIMEOUT_MS) {

		warning("reflow(%p): no RTP packets recvd for"
			" %d ms -- stop\n",
			rf, diff);

		rf->terminated = true;
		rf->ice_ready = false;
		
		IFLOW_CALL_CB(rf->iflow, closeh, ETIMEDOUT, rf->iflow.arg);
	}
}


/* this function is only called once */
static void reflow_established_handler(struct reflow *rf)
{
	enum sdp_dir rdir;

	if (rf->terminated)
		return;
	if (!reflow_is_ready(rf))
		return;

	rdir = sdp_media_rdir(rf->audio.sdpm);

	info("reflow(%p): ICE+DTLS established rdir=%d\n", rf, rdir);

	switch (rdir) {
	case SDP_RECVONLY:
	case SDP_SENDRECV:
		/*
		if (!tmr_isrunning(&rf->tmr_rtp)) {
			tmr_start(&rf->tmr_rtp,
				  RTP_FIRST_PKT_TIMEOUT_MS,
				  timeout_rtp, rf);
		}
		*/
		break;

	default:
		break;
	}

	if (rf->iflow.estabh) {
		const struct sdp_format *fmt;

		fmt = sdp_media_rformat(rf->audio.sdpm, NULL);

		IFLOW_CALL_CB(rf->iflow, estabh,
			      crypto_name(rf->crypto),
			      fmt ? fmt->name : "?",
			      rf->iflow.arg);
	}
}


static bool udp_helper_send_handler_srtp(int *err, struct sa *dst,
					 struct mbuf *mb, void *arg)
{
	struct reflow *rf = arg;
	(void)dst;

	if (packet_is_rtp_or_rtcp(mb) && rf->srtp_tx) {
		if (packet_is_rtcp_packet(mb)) {
			/* drop short RTCP packets */
			if (mbuf_get_left(mb) <= 8)
				return true;

			*err = srtcp_encrypt(rf->srtp_tx, mb);
			if (*err) {
				warning("reflow(%p): srtcp_encrypt() failed"
					"(%m)\n",
					rf, *err);
			}
		}
		else {
			*err = srtp_encrypt(rf->srtp_tx, mb);
			if (*err) {
				warning("reflow(%p): "
					"srtp_encrypt() [%zu bytes] "
					"failed (%m)\n",
					rf, mbuf_get_left(mb), *err);
			}
		}
	}

	return false;
}


static int send_packet(struct reflow *rf, size_t headroom,
		       const struct sa *raddr, struct mbuf *mb_pkt,
		       enum packet pkt)
{
	struct mbuf *mb = NULL;
	size_t len = mbuf_get_left(mb_pkt);
	int err = 0;

	if (!rf)
		return EINVAL;

#if 0
	info("reflow(%p): send_packet `%s' (%zu bytes) via %s to %J\n",
	     rf,
	     packet_classify_name(pkt),
	     mbuf_get_left(mb_pkt),
	     sock_prefix(headroom), raddr);
#endif

	mb = mbuf_alloc(headroom + len);
	if (!mb)
		return ENOMEM;

	mb->pos = headroom;
	mbuf_write_mem(mb, mbuf_buf(mb_pkt), len);
	mb->pos = headroom;

	/* now invalid */
	mb_pkt = NULL;

	if (rf->ice_ready && rf->sel_pair) {

		struct ice_lcand *lcand = NULL;
		void *sock;

		sock = trice_lcand_sock(rf->trice, rf->sel_pair->lcand);
		if (!sock) {
			warning("reflow(%p): send: selected lcand %p"
				" has no sock [%H]\n",
				rf,
				rf->sel_pair->lcand,
				trice_cand_print, rf->sel_pair->lcand);
			err = ENOTCONN;
			goto out;
		}

		if (AF_INET6 == sa_af(raddr)) {
			lcand = trice_lcand_find2(rf->trice,
						  ICE_CAND_TYPE_HOST,
						  AF_INET6);
			if (lcand) {
				info("reflow(%p): send_packet: \n",
				     " using local IPv6 socket\n", rf);
				sock = lcand->us;
			}
		}

#if 0
		debug("reflow(%p): send helper: udp_send: "
		      "sock=%p raddr=%p mb=%p\n", rf, sock, raddr, mb);
#endif
		err = udp_send(sock, raddr, mb);
		if (err) {
			warning("reflow(%p): send helper error"
				" raddr=%J (%m)\n",
				rf, raddr, err);
		}
	}
	else {
		warning("reflow(%p): send_packet: "
			"drop %zu bytes (ICE not ready)\n",
			rf, len);
	}

 out:
	mem_deref(mb);

	return err;
}


/* ONLY for outgoing DTLS packets! */
static bool send_dtls_handler(int *err, struct sa *dst_unused,
			      struct mbuf *mb_pkt, void *arg)
{
	struct reflow *rf = arg;
	const enum packet pkt = packet_classify_packet_type(mb_pkt);
	const size_t start = mb_pkt->pos;
	struct le *le;
	int rc;
	bool success = false;

	if (pkt != PACKET_DTLS) {
		warning("reflow(%p): send_dtls: not a DTLS packet?\n", rf);
		return false;
	}

	++rf->rf_stats.dtls_pkt_sent;

	/*
	 * Send packet to all DTLS peers for better robustness
	 */
	for (le = rf->dtls_peers.head; le; le = le->next) {
		struct dtls_peer *dtls_peer = le->data;

		mb_pkt->pos = start;

#if 0
		info("reflow(%p): dtls_helper: send DTLS packet #%u"
		     " to %H (%zu bytes)"
		     " \n",
		     rf,
		     rf->rf_stats.dtls_pkt_sent,
		     dtls_peer_print, dtls_peer,
		     mbuf_get_left(mb_pkt));
#endif

		rc = send_packet(rf, dtls_peer->headroom,
				 &dtls_peer->addr, mb_pkt, pkt);
		if (!rc)
			success = true;
		else {
			*err = rc;
			warning("reflow(%p): send_dtls_handler:"
				" send_packet failed (%m)\n", rf, rc);
		}
	}

	if (success)
		*err = 0;

	return true;
}


/* For Dual-stack only */
static bool udp_helper_send_handler_trice(int *err, struct sa *dst,
					 struct mbuf *mb, void *arg)
{
	struct reflow *rf = arg;
	enum packet pkt;
	int lerr;
	(void)dst;
	
	pkt = packet_classify_packet_type(mb);
	
	if (pkt == PACKET_DTLS) {
		warning("reflow(%p): dont use this to send DTLS packets\n",
			rf);
	}

	if (pkt == PACKET_STUN)
		return false;    /* continue */

	if (rf->ice_ready && rf->sel_pair) {

		void *sock;

		sock = trice_lcand_sock(rf->trice, rf->sel_pair->lcand);
		if (!sock) {
			warning("reflow(%p): send: selected lcand %p "
				"has no sock [%H]\n",
				rf, rf->sel_pair,
				trice_cand_print, rf->sel_pair->lcand);
		}

		lerr = udp_send(sock, &rf->sel_pair->rcand->attr.addr, mb);
		if (lerr) {
			warning("reflow(%p): helper: udp_send failed"
				" rcand=[%H] (%m)\n",
				rf, trice_cand_print, rf->sel_pair->rcand,
				lerr);
		}
	}
	else {
		warning("reflow(%p): helper: cannot send"
			" %zu bytes to %J, ICE not ready! (packet=%s)\n",
			rf, mbuf_get_left(mb), dst,
			packet_classify_name(pkt));
		*err = ENOTCONN;
	}

	return true;
}


static bool verify_fingerprint(struct reflow *rf,
			       const struct sdp_session *sess,
			       const struct sdp_media *media,
			       struct tls_conn *tc)
{
	struct pl hash;
	uint8_t md_sdp[32], md_dtls[32];
	size_t sz_sdp = sizeof(md_sdp);
	size_t sz_dtls;
	enum tls_fingerprint type;
	const char *attr;
	int err;

	attr = sdp_media_session_rattr(media, sess, "fingerprint");
	if (sdp_fingerprint_decode(attr, &hash, md_sdp, &sz_sdp))
		return false;

	if (0 == pl_strcasecmp(&hash, "sha-256")) {
		type = TLS_FINGERPRINT_SHA256;
		sz_dtls = 32;
	}
	else {
		warning("reflow(%p): dtls_srtp: unknown fingerprint"
			" '%r'\n", rf, &hash);
		return false;
	}

	err = tls_peer_fingerprint(tc, type, md_dtls, sizeof(md_dtls));
	if (err) {
		warning("reflow(%p): dtls_srtp: could not get"
			" DTLS fingerprint (%m)\n", rf, err);
		return false;
	}

	if (sz_sdp != sz_dtls || 0 != memcmp(md_sdp, md_dtls, sz_sdp)) {
		warning("reflow(%p): dtls_srtp: %r fingerprint mismatch\n",
			rf, &hash);
		info("  SDP:  %w\n", md_sdp, sz_sdp);
		info("  DTLS: %w\n", md_dtls, sz_dtls);
		return false;
	}

	info("reflow(%p): dtls_srtp: verified %r fingerprint OK\n",
	     rf, &hash);

	return true;
}


static int check_data_channel(struct reflow *rf)
{
	bool has_data = reflow_has_data(rf);
	int err = 0;

	info("reflow(%p): dtls_estab_handler: has_data=%d active=%d\n",
	     rf, has_data, rf->setup_local == SETUP_ACTIVE);

	if (has_data) {
		info("reflow(%p): dce: connecting.. (%p)\n",
		     rf, rf->data.dce);

		rf->data.ts_connect = tmr_jiffies();

		err = dce_connect(rf->data.dce,
				  rf->setup_local == SETUP_ACTIVE);
		if (err) {
			warning("reflow(%p): dce_connect failed (%m)\n",
				rf, err);
			return err;
		}
	}

	return err;
}


static size_t get_keylen(enum srtp_suite suite)
{
	switch (suite) {

	case SRTP_AES_CM_128_HMAC_SHA1_32: return 16;
	case SRTP_AES_CM_128_HMAC_SHA1_80: return 16;
	case SRTP_AES_256_CM_HMAC_SHA1_32: return 32;
	case SRTP_AES_256_CM_HMAC_SHA1_80: return 32;
	case SRTP_AES_128_GCM:             return 16;
	case SRTP_AES_256_GCM:             return 32;
	default: return 0;
	}
}


static size_t get_saltlen(enum srtp_suite suite)
{
	switch (suite) {

	case SRTP_AES_CM_128_HMAC_SHA1_32: return 14;
	case SRTP_AES_CM_128_HMAC_SHA1_80: return 14;
	case SRTP_AES_256_CM_HMAC_SHA1_32: return 14;
	case SRTP_AES_256_CM_HMAC_SHA1_80: return 14;
	case SRTP_AES_128_GCM:             return 12;
	case SRTP_AES_256_GCM:             return 12;
	default: return 0;
	}
}


static void dtls_estab_handler(void *arg)
{
	struct reflow *rf = arg;
	enum srtp_suite suite;
	uint8_t cli_key[MAX_SRTP_KEY_SIZE], srv_key[MAX_SRTP_KEY_SIZE];
	size_t master_key_len;
	int err;

	if (rf->rf_stats.dtls_estab < 0 && rf->ts_dtls)
		rf->rf_stats.dtls_estab = (int)(tmr_jiffies() - rf->ts_dtls);

	info("reflow(%p): DTLS established (%d ms)\n",
	     rf, rf->rf_stats.dtls_estab);

	info("           cipher %s\n",
	     tls_cipher_name(rf->tls_conn));

	if (rf->got_sdp) {
		if (!verify_fingerprint(rf, rf->sdp, rf->audio.sdpm, rf->tls_conn)) {
			warning("reflow(%p): dtls_srtp: could not verify"
				" remote fingerprint\n", rf);
			err = EAUTH;
			goto error;
		}
		rf->crypto_verified = true;
	}

	err = tls_srtp_keyinfo(rf->tls_conn, &suite,
			       cli_key, sizeof(cli_key),
			       srv_key, sizeof(srv_key));
	if (err) {
		warning("reflow(%p): dtls: no SRTP keyinfo (%m)\n",
			rf, err);
		goto error;
	}

	rf->srtp_suite = suite;

	master_key_len = get_keylen(suite) + get_saltlen(suite);

	info("reflow(%p): DTLS established (suite=%s, master_key=%zu)\n",
	     rf, srtp_suite_name(suite), master_key_len);

	if (master_key_len == 0) {
		warning("reflow(%p): dtls: empty master key\n", rf);
	}

	if (master_key_len == 0) {
		warning("reflow: dtls: empty master key\n");
	}

	rf->srtp_tx = mem_deref(rf->srtp_tx);
	err = srtp_alloc(&rf->srtp_tx, suite,
			 rf->setup_local == SETUP_ACTIVE ? cli_key : srv_key,
			 master_key_len, 0);
	if (err) {
		warning("reflow(%p): dtls: failed to allocate SRTP for TX"
			" (%m)\n",
			rf, err);
		goto error;
	}

	err = srtp_alloc(&rf->srtp_rx, suite,
			 rf->setup_local == SETUP_ACTIVE ? srv_key : cli_key,
			 master_key_len, 0);
	if (err) {
		warning("reflow(%p): dtls: failed to allocate SRTP for RX"
			" (%m)\n",
			rf, err);
		goto error;
	}

	rf->crypto_ready = true;

	reflow_established_handler(rf);

	check_data_channel(rf);

	/* Wipe the keys from memory */
	memset(cli_key, 0, sizeof(cli_key));
	memset(srv_key, 0, sizeof(srv_key));

	return;

 error:
	warning("reflow(%p): DTLS-SRTP error (%m)\n", rf, err);

	/* Wipe the keys from memory */
	memset(cli_key, 0, sizeof(cli_key));
	memset(srv_key, 0, sizeof(srv_key));

	IFLOW_CALL_CB(rf->iflow, closeh,
		err, rf->iflow.arg);
}


static void dtls_recv_handler(struct mbuf *mb, void *arg)
{
	struct reflow *rf = arg;

#if 0
	info("reflow(%p): dtls_recv_handler: %zu bytes\n",
	     rf, mbuf_get_left(mb));
#endif

	if (rf->data.dce)
		dce_recv_pkt(rf->data.dce, mbuf_buf(mb), mbuf_get_left(mb));
}


static void dtls_close_handler(int err, void *arg)
{
	struct reflow *rf = arg;

	MAGIC_CHECK(rf);

	info("reflow(%p): dtls-connection closed (%m)\n", rf, err);

	rf->tls_conn = mem_deref(rf->tls_conn);
	rf->err = err;

	IFLOW_CALL_CB(rf->iflow, closeh, err, rf->iflow.arg);
}


/*
 * called ONCE when we receive DTLS Client Hello from the peer
 *
 * this function is only called when the ICE-layer is established
 */
static void dtls_conn_handler(const struct sa *unused_peer, void *arg)
{
	struct reflow *rf = arg;
	bool okay;
	int err;

	info("reflow(%p): incoming DTLS connect tls=%p(err=%d)\n",
	     rf, rf->tls_conn, rf->err);

	if (rf->err) {
		warning("reflow(%p): DTLS connect when in error state\n", rf);
		return;
	}

	/* NOTE: The DTLS peer should be set in handle_dtls_packet */
	if (!reflow_dtls_peer_isset(rf)) {
		warning("reflow(%p): dtls_conn_handler:"
			" DTLS peer is not set\n", rf);
	}

	/* peer is a dummy address, must not be set/used */
	if (sa_in(unused_peer) || sa_port(unused_peer)) {
		warning("reflow(%p): internal error, unused peer (%J)\n",
			rf, unused_peer);
	}

	if (rf->setup_local == SETUP_ACTPASS) {
		info("reflow(%p): dtls_conn: local setup not decided yet"
		     ", drop packet\n",
		     rf);
		return;
	}

	if (rf->ice_ready) {

		okay = 1;
	}
	else {
		okay = 0;
	}

	if (!okay) {
		warning("reflow(%p): ICE is not ready. "
			"cannot accept DTLS\n", rf);
		return;
	}

	rf->ts_dtls = tmr_jiffies();

	if (rf->tls_conn) {
		warning("reflow(%p): DTLS already accepted\n", rf);
		return;
	}

	err = dtls_accept(&rf->tls_conn, rf->dtls, rf->dtls_sock,
			  dtls_estab_handler, dtls_recv_handler,
			  dtls_close_handler, rf);
	if (err) {
		warning("reflow(%p): dtls_accept failed (%m)\n", rf, err);
		goto error;
	}

	info("reflow(%p): dtls accepted tls_conn=%p\n", rf, rf->tls_conn);

	return;

 error:
	crypto_error(rf, err);
}


static void dtls_peer_destructor(void *data)
{
	struct dtls_peer *dtls_peer = data;

	list_unlink(&dtls_peer->le);
}


static int add_dtls_peer(struct reflow *rf, size_t headroom,
			 const struct sa *peer)
{
	struct dtls_peer *dtls_peer;

	if (!rf || !peer)
		return EINVAL;

	info("reflow(%p): add_dtls_peer:"
	     " headroom=%zu, peer=%J\n", rf, headroom, peer);

	dtls_peer = dtls_peer_find(rf, headroom, peer);
	if (dtls_peer) {
		warning("reflow(%p): find: dtls peer already exist (%H)\n",
			rf, dtls_peer_print, dtls_peer);
		return EALREADY;
	}

	dtls_peer = mem_zalloc(sizeof(*dtls_peer), dtls_peer_destructor);
	if (!dtls_peer)
		return ENOMEM;

	dtls_peer->headroom = headroom;
	dtls_peer->addr = *peer;

	list_append(&rf->dtls_peers, &dtls_peer->le, dtls_peer);

	return 0;
}


static int start_crypto(struct reflow *rf, const struct sa *peer)
{
	int err = 0;

	if (rf->crypto_ready) {
		info("reflow(%p): ice-estab: crypto already ready\n", rf);
		return 0;
	}

	switch (rf->crypto) {

	case CRYPTO_NONE:
		/* Do nothing */
		break;

	case CRYPTO_DTLS_SRTP:

		if (rf->setup_local == SETUP_ACTIVE) {

			size_t headroom = 0;

			if (rf->tls_conn) {
				info("reflow(%p): dtls_connect,"
				     " already connecting ..\n", rf);
				goto out;
			}

			/* NOTE: must be done before dtls_connect() */
			headroom = get_headroom(rf);

			info("reflow(%p): dtls connect via %s to peer %J\n",
			     rf, sock_prefix(headroom), peer);

			rf->ts_dtls = tmr_jiffies();

			if (!dtls_peer_find(rf, headroom, peer)) {

				err = add_dtls_peer(rf, headroom, peer);
				if (err) {
					warning("reflow(%p): start_crypto:"
						" could not add dtls peer"
						" (%m)\n", rf, err);
					return err;
				}
			}

			err = dtls_connect(&rf->tls_conn, rf->dtls,
					   rf->dtls_sock, &dummy_dtls_peer,
					   dtls_estab_handler,
					   dtls_recv_handler,
					   dtls_close_handler, rf);
			if (err) {
				warning("reflow(%p): dtls_connect()"
					" failed (%m)\n", rf, err);
				return err;
			}
		}
		break;

	default:
		warning("reflow(%p): established: "
			"unknown crypto '%s' (%d)\n",
			rf, crypto_name(rf->crypto), rf->crypto);
		break;
	}

 out:
	return err;
}


/* this function is only called once */
static void ice_established_handler(struct reflow *rf,
				    const struct sa *peer)
{
	int err;

	info("reflow(%p): ICE-transport established [got_sdp=%d]"
	     " (peer = %s.%J)\n",
	     rf,
	     rf->got_sdp,
	     rf->sel_pair
	      ? ice_cand_type2name(rf->sel_pair->rcand->attr.type)
	      : "?",
	     peer);

	if (rf->rf_stats.nat_estab < 0 && rf->ts_nat_start) {
		rf->rf_stats.nat_estab =
			(int)(tmr_jiffies() - rf->ts_nat_start);
	}

	if (!dtls_peer_find(rf, get_headroom(rf), peer)) {
		err = add_dtls_peer(rf, get_headroom(rf), peer);
		if (err) {
			warning("reflow(%p): ice_estab:"
				" could not add dtls peer"
				" (%m)\n", rf, err);

			crypto_error(rf, err);
			return;
		}
	}

	if (rf->crypto_ready) {
		info("reflow(%p): ice-estab: crypto already ready\n", rf);
		goto out;
	}

	err = start_crypto(rf, peer);
	if (err) {
		crypto_error(rf, err);
	}

 out:
	reflow_established_handler(rf);
}


static void handle_dtls_packet(struct reflow *rf, const struct sa *src,
			       struct mbuf *mb)
{
	size_t headroom = mb->pos;
	struct dtls_peer *dtls_peer;
	int err;

	++rf->rf_stats.dtls_pkt_recv;

#if 0
	info("reflow(%p): dtls: recv %zu bytes from %s|%J\n",
	     rf, mbuf_get_left(mb), sock_prefix(mb->pos), src);
#endif

	if (!rf->got_sdp) {

		info("reflow(%p): SDP is not ready --"
		     " drop DTLS packet from %J\n",
		     rf, src);
		return;
	}

	if (!reflow_ice_ready(rf)) {

		info("reflow(%p): ICE is not ready (checklist-%s) --"
		     " drop DTLS packet from %J\n",
		     rf,
		     trice_checklist_isrunning(rf->trice) ? "Running"
		                                          : "Not-Running",
		     src);
		return;
	}

	if (!reflow_dtls_peer_isset(rf)) {
		info("reflow(%p): DTLS peer is not set --"
		     " drop DTLS packet from %J\n", rf, src);
		return;
	}

	dtls_peer = dtls_peer_find(rf, headroom, src);
	if (!dtls_peer) {

		info("reflow(%p): packet: dtls_peer not found"
		     " -- adding (%s|%zu|%J)\n",
		     rf, sock_prefix(headroom), headroom, src);

		err = add_dtls_peer(rf, headroom, src);
		if (err) {
			warning("reflow(%p): packet:"
				" could not add dtls peer"
				" (%m)\n", rf, err);
		}
	}

	dtls_recv_packet(rf->dtls_sock, &dummy_dtls_peer, mb);
}


static bool udp_helper_recv_handler_srtp(struct sa *src, struct mbuf *mb,
					 void *arg)
{
	struct reflow *rf = arg;
	size_t len = mbuf_get_left(mb);
	const enum packet pkt = packet_classify_packet_type(mb);
	int err;

	if (pkt == PACKET_DTLS) {
		handle_dtls_packet(rf, src, mb);
		return true;
	}

	if (packet_is_rtp_or_rtcp(mb)) {

		/* the SRTP is not ready yet .. */
		if (!rf->srtp_rx) {
			rf->stat.n_srtp_dropped++;
			goto next;
		}

		if (packet_is_rtcp_packet(mb)) {

			err = srtcp_decrypt(rf->srtp_rx, mb);
			if (err) {
				rf->stat.n_srtp_error++;
				warning("reflow(%p): srtcp_decrypt failed"
					" [%zu bytes] (%m)\n", rf, len, err);
				return true;
			}
		}
		else {
			err = srtp_decrypt(rf->srtp_rx, mb);
			if (err) {
				rf->stat.n_srtp_error++;
				if (err != EALREADY) {
					warning("reflow(%p): srtp_decrypt"
						" failed"
						" [%zu bytes from %J] (%m)\n",
						rf, len, src, err);
				}
				return true;
			}
		}

		if (packet_is_rtcp_packet(mb)) {

			struct rtcp_msg *msg = NULL;
			size_t pos = mb->pos;
			bool is_app = false;
			int r;

			r = rtcp_decode(&msg, mb);
			if (r) {
				warning("reflow(%p): failed to decode"
					" incoming RTCP"
					" packet (%m)\n", rf, r);
				goto done;
			}
			mb->pos = pos;

			if (msg->hdr.pt == RTCP_APP) {

				if (0 != memcmp(msg->r.app.name,
						app_label, 4)) {

					warning("reflow(%p): "
						"invalid app name '%b'\n",
						rf, msg->r.app.name, (size_t)4);
					goto done;
				}

				is_app = true;

				if (rf->data.dce) {
					dce_recv_pkt(rf->data.dce,
						     msg->r.app.data,
						     msg->r.app.data_len);
				}
			}

		done:
			mem_deref(msg);

			/* NOTE: dce handler might deref reflow */
			if (is_app)
				return true;
		}
	}

 next:
	if (packet_is_rtp_or_rtcp(mb)) {

		/* If external RTP is enabled, forward RTP/RTCP packets
		 * to the relevant au/vid-codec.
		 *
		 * otherwise just pass it up to internal RTP-stack
		 */
		external_rtp_recv(rf, src, mb);
		return true; /* handled */
	}

	return false;
}

static void update_rx_stats(struct reflow *rf, size_t len)
{
	uint64_t now = tmr_jiffies();

	if (!rf->stat.rx.ts_first)
		rf->stat.rx.ts_first = now;
	rf->stat.rx.ts_last = now;
	rf->stat.rx.bytes += len;
}

static void update_tx_stats(struct reflow *rf, size_t len)
{
	uint64_t now = tmr_jiffies();

	if (!rf->stat.tx.ts_first)
		rf->stat.tx.ts_first = now;
	rf->stat.tx.ts_last = now;
	rf->stat.tx.bytes += len;
}


/*
 * UDP helper to intercept incoming RTP/RTCP packets:
 *
 * -- send to decoder if supported by it
 */
static void external_rtp_recv(struct reflow *rf,
			      const struct sa *src, struct mbuf *mb)
{
	bool is_rtp = false;
	size_t len = mbuf_get_left(mb);

	is_rtp = !packet_is_rtcp_packet(mb); 
	if (is_rtp) {
		update_rx_stats(rf, len);
	}

	if (!rf->got_rtp && is_rtp) {
		info("reflow(%p): first RTP packet received (%zu bytes)\n",
		     rf, mbuf_get_left(mb));
		rf->got_rtp = true;
	}

#if 0	
	if (g_reflow.mediaflow.recv_rtph) {
		g_reflow.mediaflow.recv_rtph(mb, rf->extarg);
	}
#endif

	if (is_rtp) {
		if (g_reflow.mediaflow.recv_rtph) {
			g_reflow.mediaflow.recv_rtph(mb, rf->extarg);
		}
	}
	/* This is a RTCP packet */	
	else { 
		if (g_reflow.mediaflow.recv_rtcph) {
			g_reflow.mediaflow.recv_rtcph(mb, rf->extarg);
		}
	}
}


static int print_cand(struct re_printf *pf, const struct ice_cand_attr *cand)
{
	if (!cand)
		return 0;

	return re_hprintf(pf, "%s.%J",
			  ice_cand_type2name(cand->type), &cand->addr);
}


static int print_errno(struct re_printf *pf, int err)
{
	if (err == -1)
		return re_hprintf(pf, "Progress..");
	else if (err)
		return re_hprintf(pf, "%m", err);
	else
		return re_hprintf(pf, "Success");
}


int reflow_print_ice(struct re_printf *pf, const struct reflow *rf)
{
	int err = 0;

	if (!rf)
		return 0;

	err = trice_debug(pf, rf->trice);

	return err;
}


int reflow_summary(struct re_printf *pf, const struct reflow *rf)
{
	struct le *le;
	double dur_tx;
	double dur_rx;
	char cid_local_anon[ANON_CLIENT_LEN];
	char cid_remote_anon[ANON_CLIENT_LEN];
	char uid_remote_anon[ANON_ID_LEN];
	int err = 0;

	if (!rf)
		return 0;

	dur_tx = (double)(rf->stat.tx.ts_last - rf->stat.tx.ts_first) / 1000.0;
	dur_rx = (double)(rf->stat.rx.ts_last - rf->stat.rx.ts_first) / 1000.0;

	err |= re_hprintf(pf,
			  "reflow(%p): ------------- reflow summary -------------\n", rf);
	err |= re_hprintf(pf, "clientid_local:  %s\n",
			  anon_client(cid_local_anon, rf->clientid_local));
	err |= re_hprintf(pf, "clientid_remote: %s\n", 
			  anon_client(cid_remote_anon, rf->clientid_remote));
	err |= re_hprintf(pf, "userid_remote: %s\n", 
			  anon_id(uid_remote_anon, rf->userid_remote));
	err |= re_hprintf(pf, "\n");
	err |= re_hprintf(pf, "sdp: state=%d, got_sdp=%d, sent_sdp=%d\n",
			  rf->sdp_state, rf->got_sdp, rf->sent_sdp);
	err |= re_hprintf(pf, "     remote_tool=%s\n", rf->sdp_rtool);

	err |= re_hprintf(pf, "nat: (ready=%d)\n",
			  rf->ice_ready);
	err |= re_hprintf(pf, "remote candidates:\n");

	err |= reflow_print_ice(pf, rf);

	if (rf->sel_pair) {
		err |= re_hprintf(pf, "selected local candidate:   %H\n",
				  trice_cand_print, rf->sel_pair->lcand);
		err |= re_hprintf(pf, "selected remote candidate:  %H\n",
				  trice_cand_print, rf->sel_pair->rcand);
	}
	err |= re_hprintf(pf, "peer_software:       %s\n", rf->peer_software);
	err |= re_hprintf(pf, "eoc:                 local=%d, remote=%d\n",
			  rf->ice_local_eoc, rf->ice_remote_eoc);
	err |= re_hprintf(pf, "\n");

	/* Crypto summary */
	err |= re_hprintf(pf,
			  "crypto: local  = %H\n"
			  "        remote = %H\n"
			  "        common = %s\n",
			  reflow_cryptos_print, rf->cryptos_local,
			  reflow_cryptos_print, rf->cryptos_remote,
			  crypto_name(rf->crypto));
	err |= re_hprintf(pf,
			  "        ready=%d\n", rf->crypto_ready);

	if (rf->crypto == CRYPTO_DTLS_SRTP) {

		err |= re_hprintf(pf, "        peers: (%u)\n",
				  list_count(&rf->dtls_peers));
		for (le = rf->dtls_peers.head; le; le = le->next) {
			struct dtls_peer *dtls_peer = le->data;

			err |= re_hprintf(pf,
					  "        * peer = %H\n",
					  dtls_peer_print, dtls_peer);
		}

		err |= re_hprintf(pf,
				  "        verified=%d\n"
				  "        setup_local=%s\n"
				  "        setup_remote=%s\n"
				  "",
				  rf->crypto_verified,
				  reflow_setup_name(rf->setup_local),
				  reflow_setup_name(rf->setup_remote)
				  );
		err |= re_hprintf(pf, "        setup_time=%d ms\n",
				  rf->rf_stats.dtls_estab);
		err |= re_hprintf(pf, "        packets sent=%u, recv=%u\n",
				  rf->rf_stats.dtls_pkt_sent,
				  rf->rf_stats.dtls_pkt_recv);
	}
	err |= re_hprintf(pf, "        srtp  = %s\n",
			  srtp_suite_name(rf->srtp_suite));
	err |= re_hprintf(pf, "\n");

	err |= re_hprintf(pf, "RTP packets:\n");
	err |= re_hprintf(pf, "bytes sent:  %zu (%.1f bit/s)"
			  " for %.2f sec\n",
		  rf->stat.tx.bytes,
		  dur_tx ? 8.0 * (double)rf->stat.tx.bytes / dur_tx : 0,
		  dur_tx);
	err |= re_hprintf(pf, "bytes recv:  %zu (%.1f bit/s)"
			  " for %.2f sec\n",
		  rf->stat.rx.bytes,
		  dur_rx ? 8.0 * (double)rf->stat.rx.bytes / dur_rx : 0,
		  dur_rx);

	err |= re_hprintf(pf, "\n");
	err |= re_hprintf(pf, "SDP recvd:       %zu\n", rf->stat.n_sdp_recv);
	err |= re_hprintf(pf, "SRTP dropped:    %zu\n",
			  rf->stat.n_srtp_dropped);
	err |= re_hprintf(pf, "SRTP errors:     %zu\n",
			  rf->stat.n_srtp_error);

	err |= re_hprintf(pf, "\naudio_active: %d\n", !rf->audio.disabled);
	err |= re_hprintf(pf, "\nvideo_media:  %d\n", rf->video.has_media);

	if (1) {

		err |= re_hprintf(pf, "TURN Clients: (%u)\n",
				  list_count(&rf->turnconnl));

		for (le = rf->turnconnl.head; le; le = le->next) {
			struct turn_conn *tc = le->data;

			err |= turnconn_debug(pf, tc);
		}
	}

	err |= re_hprintf(pf, "Interfaces: (%u)\n",
			  list_count(&rf->interfacel));
	for (le = rf->interfacel.head; le; le = le->next) {
		struct interface *ifc = le->data;

		err |= re_hprintf(pf, "...%s..%s|%j\n",
				  ifc->is_default ? "*" : ".",
				  ifc->ifname, &ifc->addr);
	}

	err |= re_hprintf(pf,
			  "-----------------------------------------------\n");
	err |= re_hprintf(pf, "\n");

	return err;
}


int reflow_rtp_summary(struct re_printf *pf, const struct reflow *rf)
{
	struct aucodec_stats *voe_stats;
	int err = 0;

	if (!rf)
		return 0;

	err |= re_hprintf(pf,
			  "reflow(%p): ------------- reflow RTP summary -------------\n", rf);

	if (!rf->audio.disabled) {
		voe_stats = reflow_codec_stats((struct reflow*)rf);
		err |= re_hprintf(pf,"Audio TX: \n");
		if (voe_stats) {
			err |= re_hprintf(pf,"Level (dB) %.1f %.1f %.1f \n",
					  voe_stats->in_vol.min,
					  voe_stats->in_vol.avg,
					  voe_stats->in_vol.max);
		}
		err |= re_hprintf(pf,"Bit rate (kbps) %.1f %.1f %.1f \n",
				  rf->audio_stats_snd.bit_rate_stats.min,
				  rf->audio_stats_snd.bit_rate_stats.avg,
				  rf->audio_stats_snd.bit_rate_stats.max);
		err |= re_hprintf(pf,"Packet rate (1/s) %.1f %.1f %.1f \n",
				  rf->audio_stats_snd.pkt_rate_stats.min,
				  rf->audio_stats_snd.pkt_rate_stats.avg,
				  rf->audio_stats_snd.pkt_rate_stats.max);
		err |= re_hprintf(pf,"Loss rate (pct) %.1f %.1f %.1f \n",
				  rf->audio_stats_snd.pkt_loss_stats.min,
				  rf->audio_stats_snd.pkt_loss_stats.avg,
				  rf->audio_stats_snd.pkt_loss_stats.max);

		err |= re_hprintf(pf,"Audio RX: \n");
		if (voe_stats) {
			err |= re_hprintf(pf,"Level (dB) %.1f %.1f %.1f \n",
					  voe_stats->out_vol.min,
					  voe_stats->out_vol.avg,
					  voe_stats->out_vol.max);
		}
		err |= re_hprintf(pf,"Bit rate (kbps) %.1f %.1f %.1f \n",
				  rf->audio_stats_rcv.bit_rate_stats.min,
				  rf->audio_stats_rcv.bit_rate_stats.avg,
				  rf->audio_stats_rcv.bit_rate_stats.max);
		err |= re_hprintf(pf,"Packet rate (1/s) %.1f %.1f %.1f \n",
				  rf->audio_stats_rcv.pkt_rate_stats.min,
				  rf->audio_stats_rcv.pkt_rate_stats.avg,
				  rf->audio_stats_rcv.pkt_rate_stats.max);
		err |= re_hprintf(pf,"Loss rate (pct) %.1f %.1f %.1f \n",
				  rf->audio_stats_rcv.pkt_loss_stats.min,
				  rf->audio_stats_rcv.pkt_loss_stats.avg,
				  rf->audio_stats_rcv.pkt_loss_stats.max);
		err |= re_hprintf(pf,"Mean burst length %.1f %.1f %.1f \n",
				  rf->audio_stats_rcv.pkt_mbl_stats.min,
				  rf->audio_stats_rcv.pkt_mbl_stats.avg,
				  rf->audio_stats_rcv.pkt_mbl_stats.max);
		if (voe_stats){
			err |= re_hprintf(pf,"JB size (ms) %.1f %.1f %.1f \n",
					  voe_stats->jb_size.min,
					  voe_stats->jb_size.avg,
					  voe_stats->jb_size.max);
			err |= re_hprintf(pf,"RTT (ms) %.1f %.1f %.1f \n",
					  voe_stats->rtt.min,
					  voe_stats->rtt.avg,
					  voe_stats->rtt.max);
		}
		err |= re_hprintf(pf,"Packet dropouts (#) %d \n",
				  rf->audio_stats_rcv.dropouts);
	}
	if (rf->video.has_media){
		err |= re_hprintf(pf,"Video TX: \n");
		err |= re_hprintf(pf,"Bit rate (kbps) %.1f %.1f %.1f \n",
				  rf->video_stats_snd.bit_rate_stats.min,
				  rf->video_stats_snd.bit_rate_stats.avg,
				  rf->video_stats_snd.bit_rate_stats.max);
		err |= re_hprintf(pf,"Alloc rate (kbps) %.1f %.1f %.1f \n",
				  rf->video_stats_snd.bw_alloc_stats.min,
				  rf->video_stats_snd.bw_alloc_stats.avg,
				  rf->video_stats_snd.bw_alloc_stats.max);
		err |= re_hprintf(pf,"Frame rate (1/s) %.1f %.1f %.1f \n",
				  rf->video_stats_snd.frame_rate_stats.min,
				  rf->video_stats_snd.frame_rate_stats.avg,
				  rf->video_stats_snd.frame_rate_stats.max);
		err |= re_hprintf(pf,"Loss rate (pct) %.1f %.1f %.1f \n",
				  rf->video_stats_snd.pkt_loss_stats.min,
				  rf->video_stats_snd.pkt_loss_stats.avg,
				  rf->video_stats_snd.pkt_loss_stats.max);

		err |= re_hprintf(pf,"Video RX: \n");
		err |= re_hprintf(pf,"Bit rate (kbps) %.1f %.1f %.1f \n",
				  rf->video_stats_rcv.bit_rate_stats.min,
				  rf->video_stats_rcv.bit_rate_stats.avg,
				  rf->video_stats_rcv.bit_rate_stats.max);
		err |= re_hprintf(pf,"Alloc rate (kbps) %.1f %.1f %.1f \n",
				  rf->video_stats_rcv.bw_alloc_stats.min,
				  rf->video_stats_rcv.bw_alloc_stats.avg,
				  rf->video_stats_rcv.bw_alloc_stats.max);
		err |= re_hprintf(pf,"Frame rate (1/s) %.1f %.1f %.1f \n",
				  rf->video_stats_rcv.frame_rate_stats.min,
				  rf->video_stats_rcv.frame_rate_stats.avg,
				  rf->video_stats_rcv.frame_rate_stats.max);
		err |= re_hprintf(pf,"Loss rate (pct) %.1f %.1f %.1f \n",
				  rf->video_stats_rcv.pkt_loss_stats.min,
				  rf->video_stats_rcv.pkt_loss_stats.avg,
				  rf->video_stats_rcv.pkt_loss_stats.max);
		err |= re_hprintf(pf,"Packet dropouts (#) %d \n",
				  rf->video_stats_rcv.dropouts);
	}

	err |= re_hprintf(pf,
			  "-----------------------------------------------\n");

	return err;
}


/* NOTE: all udp-helpers must be free'd before RTP-socket */
static void destructor(void *arg)
{
	struct reflow *rf = arg;
	void *p;

	if (MAGIC != rf->magic) {
		warning("reflow(%p): destructor: bad magic (0x%08x)\n",
			rf, rf->magic);
		return;
	}

	/* dce may ref this object while we are destructing, 
	 * which means this destrucot may be called multiple times, 
	 * ensure that it returns gracefully in that case.
	 */
	if (rf->destructed)
		return;	

	dce_detach(rf->data.dce);

	list_unlink(&rf->le);
	
	rf->terminated = true;	

	if (rf->started)
		reflow_stop_media(&rf->iflow);

	info("reflow(%p): destroyed (%H) got_sdp=%d\n",
	     rf, print_errno, rf->err, rf->got_sdp);

	if (!rf->closed && g_reflow.mediaflow.closeh) {
		g_reflow.mediaflow.closeh(rf->mf, rf->extarg);
	}
	
	/* print a nice summary */
	if (rf->got_sdp) {
		info("%H\n", reflow_summary, rf);
		info("%H\n", reflow_rtp_summary, rf);
	}

	tmr_cancel(&rf->tmr_rtp);
	tmr_cancel(&rf->tmr_error);

	/* XXX: voe is calling to reflow_xxx here */
	/* deref the encoders/decodrs first, as they may be multithreaded,
	 * and callback in here...
	 * Remove decoder first as webrtc might still send RTCP packets
	 */
	p = rf->ads;
	rf->ads = NULL;	
	mem_deref(p);

	p = rf->aes;
	rf->aes = NULL;
	mem_deref(p);

	p = rf->video.ves;
	rf->video.ves = NULL;
	mem_deref(p);

	p = rf->video.vds;
	rf->video.vds = NULL;
	mem_deref(p);

	rf->data.dce = mem_deref(rf->data.dce);

	rf->tls_conn = mem_deref(rf->tls_conn);

	list_flush(&rf->interfacel);
	list_flush(&rf->dtls_peers);

	rf->trice_uh = mem_deref(rf->trice_uh);  /* note: destroy first */
	rf->sel_pair = mem_deref(rf->sel_pair);
	rf->trice = mem_deref(rf->trice);
	rf->trice_stun = mem_deref(rf->trice_stun);
	rf->us_stun = mem_deref(rf->us_stun);
	list_flush(&rf->turnconnl);

	rf->dtls_sock = mem_deref(rf->dtls_sock);

	rf->uh_srtp = mem_deref(rf->uh_srtp);

	rf->rtp = mem_deref(rf->rtp); /* must be free'd after ICE and DTLS */
	list_flush(&rf->audio.formatl);	
	rf->sdp = mem_deref(rf->sdp);

	rf->srtp_tx = mem_deref(rf->srtp_tx);
	rf->srtp_rx = mem_deref(rf->srtp_rx);
	rf->dtls = mem_deref(rf->dtls);
	rf->ct_gather = mem_deref(rf->ct_gather);

	rf->label = mem_deref(rf->label);
	rf->video.label = mem_deref(rf->video.label);

	rf->peer_software = mem_deref(rf->peer_software);

	rf->userid_remote = mem_deref(rf->userid_remote);
	rf->clientid_remote = mem_deref(rf->clientid_remote);
	rf->clientid_local = mem_deref(rf->clientid_local);
	
	rf->extmap = mem_deref(rf->extmap);

	if (!rf->closed && g_reflow.mediaflow.closeh) {
		g_reflow.mediaflow.closeh(rf->mf, rf->extarg);
	}
	
	rf->mf = mem_deref(rf->mf);

	rf->rtps.assrcv = mem_deref(rf->rtps.assrcv);
	rf->rtps.vssrcv = mem_deref(rf->rtps.vssrcv);
	rf->destructed = true;
}


/* XXX: check if we need this, or it can be moved ? */
static void stun_udp_recv_handler(const struct sa *src,
				  struct mbuf *mb, void *arg)
{
	struct reflow *rf = arg;
	struct stun_unknown_attr ua;
	struct stun_msg *msg = NULL;

	debug("reflow(%p): stun: receive %zu bytes from %J\n",
	      rf, mbuf_get_left(mb), src);

	if (0 == stun_msg_decode(&msg, mb, &ua) &&
	    stun_msg_method(msg) == STUN_METHOD_BINDING) {

		switch (stun_msg_class(msg)) {

		case STUN_CLASS_SUCCESS_RESP:
		case STUN_CLASS_ERROR_RESP:
			(void)stun_ctrans_recv(rf->trice_stun, msg, &ua);
			break;

		default:
			re_printf("STUN message from %J dropped\n", src);
			break;
		}
	}

	mem_deref(msg);
}


/*
 * See https://tools.ietf.org/html/draft-ietf-rtcweb-jsep-14#section-5.1.1
 */
static const char *sdp_profile(enum media_crypto cryptos)
{
	if (cryptos & CRYPTO_DTLS_SRTP)
		return "UDP/TLS/RTP/SAVPF";

	return "RTP/SAVPF";
}


/* should not reach here */
static void rtp_recv_handler(const struct sa *src,
			     struct mbuf *mb, void *arg)
{
	struct reflow *rf = arg;
	(void)src;
	(void)mb;

	info("reflow(%p): nobody cared about incoming packet (%zu bytes)\n",
	     rf, mbuf_get_left(mb));
}


static int init_ice(struct reflow *rf)
{
	struct trice_conf conf = {
		.nom = ICE_NOMINATION_AGGRESSIVE,
		.debug = false,
		.trace = false,
#if TARGET_OS_IPHONE
		.ansi = false,
#elif defined (__ANDROID__)
		.ansi = false,
#else
		.ansi = true,
#endif
		.enable_prflx = !rf->privacy_mode
	};
	enum ice_role role = ICE_ROLE_UNKNOWN;  /* NOTE: this is set later */
	int err;

	err = trice_alloc(&rf->trice, &conf, role,
			  rf->ice_ufrag, rf->ice_pwd);
	if (err) {
		warning("reflow(%p): DUALSTACK trice error (%m)\n",
			rf, err);
		goto out;
	}

	err = trice_set_software(rf->trice, avs_version_str());
	if (err)
		goto out;

	err = stun_alloc(&rf->trice_stun, NULL, NULL, NULL);
	if (err)
		goto out;

	/*
	 * tuning the STUN transaction values
	 *
	 * RTO=150 and RC=7 gives around 12 seconds timeout
	 */
	stun_conf(rf->trice_stun)->rto = 150;  /* milliseconds */
	stun_conf(rf->trice_stun)->rc =    8;  /* retransmits */

	/* Virtual socket for directing outgoing Packets */
	err = udp_register_helper(&rf->trice_uh, rf->rtp,
				  LAYER_ICE,
				  udp_helper_send_handler_trice,
				  NULL, rf);
	if (err)
		goto out;

 out:
	return err;
}

static void af_destructor(void *arg)
{
	struct auformat *af = arg;

	list_unlink(&af->le);
	mem_deref(af->fmt);
}


static bool valid_rf(struct reflow *rf)
{
	bool found = false;
	struct le *le;

	for(le = g_reflow.rfl.head; !found && le; le = le->next) {
		found = rf == le->data;
	}

	return found;
}

static void dc_estab_handler(void *arg)
{
	struct reflow *rf = arg;
	int err = 0;

	RFLOG(LOG_LEVEL_INFO, "datachan carrier established\n", rf);

	if (reflow_is_sdp_offerer(rf)) {
		err = dce_open_chan(rf->data.dce, rf->data.ch);
		if (err) {
			warning("ecall: dce_open_chan failed (%m)\n", err);
			goto out;
		}
	}

 out:
	return;
}

static void dc_open_handler(int chid, const char *label,
			    const char *protocol, void *arg)
{
	struct reflow *rf = arg;

	RFLOG(LOG_LEVEL_INFO, "data channel opened with label %s\n", rf, label);

	
	if (!rf->closed)
		IFLOW_CALL_CB(rf->iflow, dce_estabh, rf->iflow.arg);
}


static void dc_data_handler(int chid, uint8_t *data, size_t len, void *arg)
{
	struct reflow *rf = arg;

	if (!rf->closed)
		IFLOW_CALL_CB(rf->iflow, dce_recvh, data, len, rf->iflow.arg);
}

static void dc_closed_handler(int chid, const char *label,
			      const char *protocol, void *arg)
{
	struct reflow *rf = arg;

	RFLOG(LOG_LEVEL_INFO, "dc-closed: closed=%d closeh=%p\n", rf, rf->closed, rf->iflow.dce_closeh);

	if (!rf->closed)
		IFLOW_CALL_CB(rf->iflow, dce_closeh, rf->iflow.arg);
}

static bool exist_ssrc(struct reflow *rf, uint32_t ssrc)
{
	bool found = false;
	int i;

	for (i = 0; !found && i < rf->rtps.assrcc; ++i) {
		found = rf->rtps.assrcv[i] == ssrc;
	}
	for (i = 0; !found && i < rf->rtps.vssrcc; ++i) {
		found = rf->rtps.vssrcv[i] == ssrc;
	}

	return found;
}


/**
 * Create a new reflow.
 *
 * No ICE candidates are added here, you need to do that explicitly.
 *
 * @param aucodecl     Optional list of audio-codecs (struct aucodec)
 * @param audio_srate  Force a specific sample-rate (optional)
 * @param audio_ch     Force a specific number of channels (optional)
 */
int reflow_alloc(struct iflow		**flowp,
		 const char		*convid,
		 const char		*userid_self,
		 const char		*clientid_self,
		 enum icall_conv_type	conv_type,
		 enum icall_call_type	call_type,
		 enum icall_vstate	vstate,
		 void			*extarg)
{
	enum media_crypto cryptos;
	struct sa laddr_sdp;
	struct reflow *rf = NULL;
	struct le *le;
	struct sa laddr_rtp;
	struct sa *maddr;
	uint16_t lport = PORT_DISCARD;
	int err;

	if (!flowp)
		return EINVAL;

	/*
	 * NOTE: v4 has presedence over v6 for now
	 */
	if (0 == net_default_source_addr_get(AF_INET, &laddr_sdp)) {
		info("reflow_alloc:: local IPv4 addr %j\n", &laddr_sdp);
	}
	else if (0 == net_default_source_addr_get(AF_INET6, &laddr_sdp)) {
		info("reflow_alloc: local IPv6 addr %j\n", &laddr_sdp);
	}
	else if (msystem_get_loopback(msystem_instance())) {
		sa_set_str(&laddr_sdp, "127.0.0.1", 0);
		info("reflow_alloc:: local IPv4 addr %j\n", &laddr_sdp);
	}
	else {
		warning("reflow_alloc: no local addresses\n");
		return EAFNOSUPPORT;
	}

	if (!sa_isset(&laddr_sdp, SA_ADDR))
		return EINVAL;

	rf = mem_zalloc(sizeof(*rf), destructor);
	if (!rf)
		return ENOMEM;

	info("reflow_alloc(%p): allocated\n", rf);
	
	iflow_set_functions(&rf->iflow,
			    reflow_set_video_state,
			    reflow_generate_offer,
			    reflow_generate_answer,
			    reflow_handle_offer,
			    reflow_handle_answer,
			    reflow_has_video,
			    reflow_is_gathered,
			    NULL, // reflow_enable_privacy
			    reflow_set_call_type,
			    reflow_get_audio_cbr,
			    reflow_set_audio_cbr,
			    reflow_set_remote_userclientid,
			    reflow_add_turnserver,
			    reflow_gather_all_turn,
			    NULL, //reflow_add_decoders_for_user,
			    NULL, //reflow_remove_decoders_for_user,
			    NULL, //reflow_sync_decoders,
			    NULL, //reflow_set_e2ee_key,
			    reflow_dce_send,
			    reflow_stop_media,
			    reflow_close,
			    NULL, //reflow_get_stats,
			    NULL, //reflow_get_audio_level
			    reflow_debug);
	list_append(&g_reflow.rfl, &rf->le, rf);

	cryptos = CRYPTO_DTLS_SRTP;

	rf->magic = MAGIC;
	rf->privacy_mode = false;
	rf->group_mode = false;
	rf->af = sa_af(&laddr_sdp);

	rf->rf_stats.turn_alloc = -1;
	rf->rf_stats.nat_estab  = -1;
	rf->rf_stats.dtls_estab = -1;
	rf->rf_stats.dce_estab  = -1;

	tmr_init(&rf->tmr_rtp);
	tmr_init(&rf->tmr_error);

	err = str_dup(&rf->clientid_local,
		      clientid_self ? clientid_self
		                    : "0102030405060708");
	if (err)
		goto out;

	rf->dtls   = mem_ref(g_reflow.dtls);
	rf->setup_local    = SETUP_ACTPASS;
	rf->setup_remote   = SETUP_ACTPASS;
	rf->cryptos_local = cryptos;
	rf->crypto_fallback = CRYPTO_DTLS_SRTP;

	err = pthread_mutex_init(&rf->mutex_enc, NULL);
	if (err)
		goto out;

	rand_str(rf->ice_ufrag, sizeof(rf->ice_ufrag));
	rand_str(rf->ice_pwd, sizeof(rf->ice_pwd));

	/* Get any media address override */
	maddr = avs_service_media_addr();
	if (maddr) {
		sa_cpy(&rf->media_laddr, maddr);
	}
	
	/* RTP must listen on 0.0.0.0 so that we can send/recv
	   packets on all interfaces */
	sa_init(&laddr_rtp, AF_INET);

	if (sa_isset(&rf->media_laddr, SA_ADDR))
		info("reflow_alloc udp_listen: maddr=%j\n", &rf->media_laddr);
	else
		info("reflow_alloc udp_listen: default media address\n");
		
	err = udp_listen(&rf->rtp, &laddr_rtp, rtp_recv_handler, rf);
	if (err) {
		warning("reflow(%p): rtp_listen failed (%m)\n", rf, err);
		goto out;
	}

	info("reflow_alloc sdp_session_alloc\n");
	err = sdp_session_alloc(&rf->sdp, &laddr_sdp);
	if (err)
		goto out;

	(void)sdp_session_set_lattr(rf->sdp, true, "tool", avs_version_str());

	info("reflow_alloc sdp_session_alloc\n");
	err = sdp_media_add(&rf->audio.sdpm, rf->sdp, "audio",
			    PORT_DISCARD,
			    sdp_profile(cryptos));
	if (err)
		goto out;

	sdp_media_set_lbandwidth(rf->audio.sdpm,
				 SDP_BANDWIDTH_AS, AUDIO_BANDWIDTH);
	sdp_media_set_lattr(rf->audio.sdpm, true, "ptime", "%u", AUDIO_PTIME);

	/* needed for new versions of WebRTC */
	err = sdp_media_set_alt_protos(rf->audio.sdpm, 2,
				       "UDP/TLS/RTP/SAVPF", "RTP/SAVPF");
	if (err)
		goto out;

	sdp_media_set_lattr(rf->audio.sdpm, false, "mid", "audio");
	sdp_media_set_lattr(rf->audio.sdpm, false,
		"extmap", "1 urn:ietf:params:rtp-hdrext:ssrc-audio-level vad=on");
	sdp_media_set_lattr(rf->audio.sdpm, false,
			    "extmap", "2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time");
#if USE_TRANSCC
	sdp_media_set_lattr(rf->audio.sdpm, false,
			    "extmap", "3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01");
#endif
	
	rand_str(rf->cname, sizeof(rf->cname));
	rand_str(rf->msid, sizeof(rf->msid));
	err = uuid_v4(&rf->label);
	err |= uuid_v4(&rf->video.label);
	if (err)
		goto out;
	

	rf->lssrcv[MEDIA_AUDIO] = regen_lssrc(rf->lssrcv[MEDIA_AUDIO]);
	info("reflow(%p): local SSRC is %u\n",
	      rf, rf->lssrcv[MEDIA_AUDIO]);

#if 0
	err = sdp_media_set_lattr(rf->audio.sdpm, false, "ssrc-group",
				  "SIM %u", rf->lssrcv[MEDIA_AUDIO]);
	
	err = sdp_media_set_lattr(rf->audio.sdpm, false, "ssrc", "%u cname:%s",
				  rf->lssrcv[MEDIA_AUDIO], rf->cname);
	if (err)
		goto out;
#endif

	info("reflow_alloc init_ice\n");
	/* ICE */
	err = init_ice(rf);
	if (err)
		goto out;
	
	/* populate SDP with all known audio-codecs */
	LIST_FOREACH(&g_reflow.aucodecl, le) {
		struct aucodec *ac = list_ledata(le);
		struct auformat *af;

		af = mem_zalloc(sizeof(*af), af_destructor);
		if (!af) {
			err = ENOMEM;
			goto out;
		}
		err = sdp_format_add(&af->fmt, rf->audio.sdpm, false,
				     ac->pt, ac->name, ac->srate, ac->ch,
				     NULL, NULL, ac, false,
				     "");
		if (err)
			goto out;

		af->ac = ac;
		list_append(&rf->audio.formatl, &af->le, af);

#if USE_TRANSCC
		sdp_media_set_lattr(rf->audio.sdpm, false,
				    "rtcp-fb", "%s transport-cc",
				    ac->pt);
#endif
	}

	reflow_add_video(rf, &g_reflow.vidcodecl);
	reflow_add_data(rf);
	/* Set ICE-options */
	sdp_session_set_lattr(rf->sdp, false, "ice-options",
			      "trickle");

	/* Mandatory */
	sdp_media_set_lattr(rf->audio.sdpm, false, "rtcp-mux", NULL);

	sdp_media_set_lport_rtcp(rf->audio.sdpm, lport);


	sdp_media_set_lattr(rf->audio.sdpm, false, "ice-ufrag",
			    "%s", rf->ice_ufrag);
	sdp_media_set_lattr(rf->audio.sdpm, false, "ice-pwd",
			    "%s", rf->ice_pwd);


	rf->srtp_suite = (enum srtp_suite)-1;

	/* we enable support for DTLS-SRTP by default, so that the
	   SDP attributes are sent in the offer. the attributes
	   might change later though, depending on the SDP answer */

	info("reflow_alloc using cryptos %u\n", cryptos);
	if (cryptos & CRYPTO_DTLS_SRTP) {

		info("reflow_alloc using DTLS\n");
		struct sa laddr_dtls;

		sa_set_str(&laddr_dtls, "0.0.0.0", 0);

		if (!rf->dtls) {
			warning("reflow(%p): dtls context is missing\n", rf);
		}

		err = dtls_listen(&rf->dtls_sock, &laddr_dtls,
				  NULL, 2, LAYER_DTLS,
				  dtls_conn_handler, rf);
		if (err) {
			warning("reflow(%p): dtls_listen failed (%m)\n",
				rf, err);
			goto out;
		}

		/* Virtual socket for re-directing outgoing DTLS-packet */
		err = udp_register_helper(&rf->dtls_uh,
					  dtls_udp_sock(rf->dtls_sock),
					  LAYER_DTLS_TRANSPORT,
					  send_dtls_handler,
					  NULL, rf);
		if (err)
			goto out;

		dtls_set_mtu(rf->dtls_sock, DTLS_MTU);

		re_snprintf(rf->audio.fingerprint,
			    sizeof(rf->audio.fingerprint),
			    "sha-256 %H",
			    dtls_print_sha256_fingerprint, rf->dtls);

		err = sdp_media_set_lattr(rf->audio.sdpm, true,
					  "fingerprint", "sha-256 %H",
					  dtls_print_sha256_fingerprint,
					  rf->dtls);
		if (err)
			goto out;

		err = sdp_media_set_lattr(rf->audio.sdpm, true, "setup",
					reflow_setup_name(rf->setup_local));
		if (err)
			goto out;
	}

	/* install UDP socket helpers */
	err |= udp_register_helper(&rf->uh_srtp, rf->rtp, LAYER_SRTP,
				   udp_helper_send_handler_srtp,
				   udp_helper_recv_handler_srtp,
				   rf);
	if (err)
		goto out;

	{
		int dce_err;

		dce_err = dce_alloc(&rf->data.dce,
				    dce_send_data_handler,
				    dce_estab_handler,
				    rf);
		if (dce_err) {
			info("reflow(%p): dce_alloc failed (%m)\n",
			     rf, dce_err);
		}

		err = dce_channel_alloc(&rf->data.ch,
					rf->data.dce,
					"calling-3.0",
					"",
					dc_estab_handler,
					dc_open_handler,
					dc_closed_handler,
					dc_data_handler,
					rf);

		if (err) {
			RFLOG(LOG_LEVEL_WARN,
			      "dce_channel_alloc failed (%m)\n", rf, err);
			goto out;
		}
		
	}

	rf->laddr_default = laddr_sdp;
	sa_set_port(&rf->laddr_default, lport);

	err = extmap_alloc(&rf->extmap);

	rf->extarg = extarg;
	if (g_reflow.mediaflow.alloch) {
		struct mediaflow *mf;

		mf = mem_zalloc(sizeof(*mf), NULL);
		if (!mf) {
			err = ENOMEM;
			goto out;
		}
		rf->mf = mf;
		mf->mp = g_reflow.mediaflow.mp;
		mf->flow = rf;
		g_reflow.mediaflow.alloch(mf, extarg);
	}
	
	info("reflow(%p): created new reflow with"
	     " local port %u and %u audio-codecs"
	     " \n",
	     rf, lport, list_count(&g_reflow.aucodecl));

 out:
	if (err)
		mem_deref(rf);
	else if (flowp)
		*flowp = (struct iflow*)rf;

	return err;
}


int reflow_set_setup(struct reflow *rf, enum media_setup setup)
{
	int err;

	if (!rf)
		return EINVAL;

	info("reflow(%p): local_setup: `%s' --> `%s'\n",
	     rf,
	     reflow_setup_name(rf->setup_local),
	     reflow_setup_name(setup));

	if (setup != rf->setup_local) {

		if (rf->setup_local == SETUP_ACTPASS) {

			rf->setup_local = setup;
		}
		else {
			warning("reflow(%p): set_setup: Illegal transition"
				" from `%s' to `%s'\n",
				rf, reflow_setup_name(rf->setup_local),
				reflow_setup_name(setup));
			return EPROTO;
		}
	}

	err = sdp_media_set_lattr(rf->audio.sdpm, true, "setup",
				  reflow_setup_name(rf->setup_local));
	if (err)
		return err;

	if (rf->video.sdpm) {
		err = sdp_media_set_lattr(rf->video.sdpm, true,
					"setup",
					reflow_setup_name(rf->setup_local));
		if (err)
			return err;
	}

	return 0;
}


bool reflow_is_sdp_offerer(const struct reflow *rf)
{
	if (!rf)
		return false;

	return rf->sdp_offerer;
}


enum media_setup reflow_local_setup(const struct reflow *rf)
{
	if (!rf)
		return (enum media_setup)-1;

	return rf->setup_local;
}

int reflow_disable_audio(struct reflow *rf)
{
	int err = 0;

	err = sdp_media_set_lattr(rf->audio.sdpm, false, "inactive", NULL);
	if (err)
		goto out;

	rf->audio.disabled = true;

out:
	return err;
}

int reflow_add_video(struct reflow *rf, struct list *vidcodecl)
{
	struct le *le;
	int err;

	if (!rf || !vidcodecl)
		return EINVAL;

	/* already added */
	if (rf->video.sdpm)
		return 0;

	info("reflow(%p): adding video-codecs (%u)\n",
	     rf, list_count(vidcodecl));

	err = sdp_media_add(&rf->video.sdpm, rf->sdp, "video",
			    PORT_DISCARD,
			    sdp_profile(rf->cryptos_local));
	if (err)
		goto out;

	sdp_media_set_lbandwidth(rf->video.sdpm,
				 SDP_BANDWIDTH_AS, VIDEO_BANDWIDTH);

	/* needed for new versions of WebRTC */
	err = sdp_media_set_alt_protos(rf->video.sdpm, 2,
				       "UDP/TLS/RTP/SAVPF", "RTP/SAVPF");
	if (err)
		goto out;


	/* SDP media attributes */

	sdp_media_set_lattr(rf->video.sdpm, false, "mid", "video");
	sdp_media_set_lattr(rf->video.sdpm, false,
			    "extmap",
			    "2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time");
	sdp_media_set_lattr(rf->video.sdpm, false,
			    "extmap",
			    "3 http://www.webrtc.org/experiments/rtp-hdrext/generic-frame-descriptor-00");

	/*
	  sdp_media_set_lattr(rf->video.sdpm, false,
	  "extmap",
	  "2 http://www.webrtc.org/experiments/rtp-hdrext/generic-frame-descriptor-01");
	*/

#if USE_TRANSCC
	sdp_media_set_lattr(rf->video.sdpm, false,
			    "extmap",
			    "4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01");
#endif
	
	sdp_media_set_lattr(rf->video.sdpm, false, "rtcp-mux", NULL);

	sdp_media_set_lport_rtcp(rf->video.sdpm, PORT_DISCARD);

	sdp_media_set_lattr(rf->video.sdpm, false,
			    "ice-ufrag", "%s", rf->ice_ufrag);
	sdp_media_set_lattr(rf->video.sdpm, false,
			    "ice-pwd", "%s", rf->ice_pwd);

	if (rf->dtls) {
		re_snprintf(rf->video.fingerprint,
			    sizeof(rf->video.fingerprint),
			    "sha-256 %H",
			    dtls_print_sha256_fingerprint, rf->dtls);
		
		err = sdp_media_set_lattr(rf->video.sdpm, true,
					  "fingerprint", "sha-256 %H",
					  dtls_print_sha256_fingerprint,
					  rf->dtls);
		if (err)
			goto out;

		err = sdp_media_set_lattr(rf->video.sdpm, true,
					"setup",
					reflow_setup_name(rf->setup_local));
		if (err)
			goto out;
	}

	{
		size_t ssrcc = list_count(vidcodecl);
		uint32_t ssrcv[SSRC_MAX];
		char ssrc_group[16];
		char ssrc_fid[sizeof(ssrc_group)*SSRC_MAX + 5];
		int i = 0;
		int k = 0;
		int c;
		
		if (ssrcc > SSRC_MAX) {
			warning("reflow(%p): max %d SSRC's\n", rf, SSRC_MAX);
			err = EOVERFLOW;
			goto out;
		}

		for(c = 0; c < SSRC_MAX; ++c) {
			ssrcv[c] = 0;
		}

		*ssrc_fid = '\0';

		LIST_FOREACH(vidcodecl, le) {
			struct vidcodec *vc = list_ledata(le);
			struct vid_ref *vr;
		   
			vr = mem_zalloc(sizeof(*vr), NULL);
			if (!vr)
				goto out;

			vr->rf = rf;
			vr->vc = vc;

			err = sdp_format_add(NULL, rf->video.sdpm, false,
					     vc->pt, vc->name, 90000, 1,
					     NULL,
					     NULL,
					     vr, true,
					     "%s", vc->fmtp);
			mem_deref(vr);
			if (err) {
				
				goto out;
			}

#if USE_TRANSCC
			sdp_media_set_lattr(rf->video.sdpm, false,
					    "rtcp-fb", "%s transport-cc",
					    vc->pt);
#endif
#if USE_REMB
			sdp_media_set_lattr(rf->video.sdpm, false,
					    "rtcp-fb", "%s goog-remb",
					    vc->pt);
#endif

			
			ssrcv[i] = rand_u32();
			re_snprintf(ssrc_group, sizeof(ssrc_group),
				    "%u ", ssrcv[i]);
			strcat(ssrc_fid, ssrc_group);
			++i;
		}
		if (strlen(ssrc_fid))
			ssrc_fid[strlen(ssrc_fid) - 1] = '\0';

		if (i > 1) {
			err = sdp_media_set_lattr(rf->video.sdpm, false, "ssrc-group",
						  "FID %s", ssrc_fid);
			if (err)
				goto out;
		}

		if (ssrcc > 0)
			rf->lssrcv[MEDIA_VIDEO] = ssrcv[0];
		if (ssrcc > 1)
			rf->lssrcv[MEDIA_VIDEO_RTX] = ssrcv[1];

		for (k = 0; k < i; ++k) {
			err = sdp_media_set_lattr(rf->video.sdpm, false,
						  "ssrc", "%u cname:%s",
						  ssrcv[k], rf->cname);
			err |= sdp_media_set_lattr(rf->video.sdpm, false,
						  "ssrc", "%u msid:%s %s",
						   ssrcv[k],
						   rf->msid, rf->video.label);
			err |= sdp_media_set_lattr(rf->video.sdpm, false,
						  "ssrc", "%u mslabel:%s",
						   ssrcv[k], rf->msid);
			err |= sdp_media_set_lattr(rf->video.sdpm, false,
						  "ssrc", "%u label:%s",
						   ssrcv[k], rf->video.label);
			if (err)
				goto out;
		}
	}

 out:
	return err;
}


int reflow_add_data(struct reflow *rf)
{
	int err;

	if (!rf)
		return EINVAL;

	info("reflow(%p): add_data: adding data channel\n", rf);

	err = sdp_media_add(&rf->data.sdpm, rf->sdp, "application",
			    PORT_DISCARD,
			    "DTLS/SCTP");
	if (err)
		goto out;

	sdp_media_set_lattr(rf->data.sdpm, false, "mid", "data");

	sdp_media_set_lattr(rf->data.sdpm, false,
			    "ice-ufrag", "%s", rf->ice_ufrag);
	sdp_media_set_lattr(rf->data.sdpm, false,
			    "ice-pwd", "%s", rf->ice_pwd);

	if (rf->dtls) {
		err = sdp_media_set_lattr(rf->data.sdpm, true,
					  "fingerprint", "sha-256 %H",
					  dtls_print_sha256_fingerprint,
					  rf->dtls);
		if (err) {
			warning("reflow(%p): add_data: failed to lattr "
				"'fingerprint': %m\n", rf, err);
			goto out;
		}

		err = sdp_media_set_lattr(rf->data.sdpm, true,
					"setup",
					reflow_setup_name(rf->setup_local));
		if (err) {
			warning("reflow(%p): add_data: failed to lattr "
				"'setup': %m\n", rf, err);
			goto out;
		}
	}

	err = sdp_format_add(NULL, rf->data.sdpm, false,
			     "5000", NULL, 0, 0,
			     NULL, NULL, NULL, false, NULL);
	if (err)
		goto out;

	err = sdp_media_set_lattr(rf->data.sdpm, true,
			      "sctpmap", "5000 webrtc-datachannel 16");
	if (err) {
		warning("reflow(%p): add_data: failed to add lattr: %m\n",
			rf, err);
		goto out;
	}

 out:
	return err;
}


void reflow_set_tag(struct reflow *rf, const char *tag)
{
	if (!rf)
		return;

	str_ncpy(rf->tag, tag, sizeof(rf->tag));
}


static int handle_setup(struct reflow *rf)
{
	const char *rsetup;
	enum media_setup setup_local;
	int err;

	rsetup = sdp_media_session_rattr(rf->audio.sdpm, rf->sdp, "setup");

	info("reflow(%p): remote_setup=%s\n", rf, rsetup);

	rf->setup_remote = setup_resolve(rsetup);

	switch (rf->setup_remote) {

	case SETUP_ACTPASS:
		/* RFC 5763 setup:active is RECOMMENDED */
		if (rf->setup_local == SETUP_ACTPASS)
			setup_local = SETUP_ACTIVE;
		else
			setup_local = rf->setup_local;
		break;

	case SETUP_ACTIVE:
		setup_local = SETUP_PASSIVE;
		break;

	case SETUP_PASSIVE:
		setup_local = SETUP_ACTIVE;
		break;

	default:
		warning("reflow(%p): illegal setup '%s' from remote\n",
			rf, rsetup);
		return EPROTO;
	}

	info("reflow(%p): local_setup=%s\n",
	     rf, reflow_setup_name(rf->setup_local));

	reflow_set_setup(rf, setup_local);

	err = sdp_media_set_lattr(rf->audio.sdpm, true, "setup",
				  reflow_setup_name(rf->setup_local));
	if (err)
		return err;

	if (rf->video.sdpm) {
		err = sdp_media_set_lattr(rf->video.sdpm, true,
					"setup",
					reflow_setup_name(rf->setup_local));
		if (err)
			return err;
	}

	if (rf->data.sdpm) {
		err = sdp_media_set_lattr(rf->data.sdpm, true,
					"setup",
					reflow_setup_name(rf->setup_local));
		if (err)
			return err;
	}

	return 0;
}


static int handle_dtls_srtp(struct reflow *rf)
{
	const char *fingerprint;
	struct pl fp_name;
	re_printf_h *fp_printh;
	int err;

	fingerprint = sdp_media_session_rattr(rf->audio.sdpm, rf->sdp,
					      "fingerprint");

	err = re_regex(fingerprint, str_len(fingerprint),
		       "[^ ]+ [0-9A-F:]*", &fp_name, NULL);
	if (err) {
		warning("reflow(%p): could not parse fingerprint attr\n",
			rf);
		return err;
	}

	debug("reflow(%p): DTLS-SRTP fingerprint selected (%r)\n",
	      rf, &fp_name);

	if (0 == pl_strcasecmp(&fp_name, "sha-256")) {
		fp_printh = (re_printf_h *)dtls_print_sha256_fingerprint;
	}
	else {
		warning("reflow(%p): unsupported fingerprint (%r)\n",
			rf, &fp_name);
		return EPROTO;
	}

	err = sdp_media_set_lattr(rf->audio.sdpm, true, "fingerprint", "%r %H",
				  &fp_name, fp_printh, rf->dtls);
	if (err)
		return err;


	err = handle_setup(rf);
	if (err) {
		warning("reflow(%p): handle_setup failed (%m)\n", rf, err);
		return err;
	}

	debug("reflow(%p): incoming SDP offer has DTLS fingerprint = '%s'\n",
	      rf, fingerprint);

	/* DTLS has already been established, before SDP o/a */
	if (rf->crypto_ready && rf->tls_conn && !rf->crypto_verified) {

		info("reflow(%p): sdp: verifying DTLS fp\n", rf);

		if (!verify_fingerprint(rf, rf->sdp, rf->audio.sdpm, rf->tls_conn)) {
			warning("reflow(%p): dtls_srtp: could not verify"
				" remote fingerprint\n", rf);
			return EAUTH;
		}

		rf->crypto_verified = true;
	}

	return 0;
}


static void demux_packet(struct reflow *rf, const struct sa *src,
			 struct mbuf *mb)
{
	enum packet pkt;
	bool hdld;

	pkt = packet_classify_packet_type(mb);

	if (rf->trice) {

		/* if the incoming UDP packet is not in the list of
		 * remote ICE candidates, we should not trust it.
		 * note that new remote candidates are added dynamically
		 * as PRFLX in the ICE-layer.
		 */
		if (!trice_rcand_find(rf->trice, ICE_COMPID_RTP,
				      IPPROTO_UDP, src)) {

			debug("reflow(%p): demux: unauthorized"
			      " %s packet from %J"
			      " (rcand-list=%u)\n",
			      rf, packet_classify_name(pkt), src,
			      list_count(trice_rcandl(rf->trice)));
		}
	}

	switch (pkt) {

	case PACKET_RTP:
	case PACKET_RTCP:
		hdld = udp_helper_recv_handler_srtp((struct sa *)src, mb, rf);
		if (!hdld) {
			warning("reflow(%p): rtp packet not handled\n", rf);
		}
		break;

	case PACKET_DTLS:
		handle_dtls_packet(rf, src, mb);
		break;

	case PACKET_STUN:
		stun_udp_recv_handler(src, mb, rf);
		break;

	default:
		warning("reflow(%p): @@@ udp: dropping %zu bytes from %J\n",
			rf, mbuf_get_left(mb), src);
		break;
	}
}


static void trice_udp_recv_handler(const struct sa *src, struct mbuf *mb,
				   void *arg)
{
	struct reflow *rf = arg;

	demux_packet(rf, src, mb);
}


static void interface_destructor(void *data)
{
	struct interface *ifc = data;

	list_unlink(&ifc->le);
	/*mem_deref(ifc->lcand);*/
}


static int interface_add(struct reflow *rf, struct ice_lcand *lcand,
			 const char *ifname, const struct sa *addr)
{
	struct interface *ifc;

	ifc = mem_zalloc(sizeof(*ifc), interface_destructor);
	if (!ifc)
		return ENOMEM;


	ifc->lcand = lcand;
	ifc->addr = *addr;
	if (ifname)
		str_ncpy(ifc->ifname, ifname, sizeof(ifc->ifname));
	ifc->is_default = sa_cmp(addr, &rf->laddr_default, SA_ADDR);
	ifc->rf = rf;

	list_append(&rf->interfacel, &ifc->le, ifc);

	return 0;
}


static struct interface *interface_find(const struct list *interfacel,
					const struct sa *addr)
{
	struct le *le;

	for (le = list_head(interfacel); le; le = le->next) {
		struct interface *ifc = le->data;

		if (sa_cmp(addr, &ifc->addr, SA_ADDR))
			return ifc;
	}

	return NULL;
}


/*
 * Calculate the local preference for ICE
 *
 * - The interface type takes precedence over address family
 * - IPv4 takes precedence over IPv6, due to stability
 *
 */
static uint16_t calc_local_preference(const char *ifname, int af)
{
	uint16_t lpref_af, lpref_ifc;

	/* VPN */
	if (0 == re_regex(ifname, str_len(ifname), "ipsec") ||
	    0 == re_regex(ifname, str_len(ifname), "utun")) {

		lpref_ifc = 1;
	}
	/* GPRS */
	else if (0 == re_regex(ifname, str_len(ifname), "pdp_ip")) {

		lpref_ifc = 2;
	}
	/* Normal interface */
	else {
		lpref_ifc = 3;
	}

	switch (af) {

	default:
	case AF_INET:
		lpref_af = 2;
		break;

	case AF_INET6:
		lpref_af = 1;
		break;
	}

	return lpref_ifc<<8 | lpref_af;
}


/* NOTE: only ADDRESS portion of 'addr' is used */
int reflow_add_local_host_candidate(struct reflow *rf,
				       const char *ifname,
				       const struct sa *addr)
{
	struct ice_lcand *lcand = NULL;
	struct interface *ifc;
	const uint16_t lpref = calc_local_preference(ifname, sa_af(addr));
	const uint32_t prio = ice_cand_calc_prio(ICE_CAND_TYPE_HOST, lpref, 1);
	int err = 0;

	if (!rf || !addr)
		return EINVAL;

	if (!sa_isset(addr, SA_ADDR)) {
		warning("reflow(%p): add_cand: address not set\n", rf);
		return EINVAL;
	}
	if (sa_port(addr)) {
		warning("reflow(%p): add_local_host: "
			"Port should not be set\n", rf);
		return EINVAL;
	}

	info("reflow(%p): add_local_host_cand: "
	     " %s:%j  (lpref=0x%04x prio=0x%08x)\n",
	     rf, ifname, addr, lpref, prio);

	ifc = interface_find(&rf->interfacel, addr);
	if (ifc) {
		info("reflow(%p): interface already added\n", rf);
		return 0;
	}

	if (!rf->privacy_mode) {
		err = trice_lcand_add(&lcand, rf->trice,
				      ICE_COMPID_RTP,
				      IPPROTO_UDP, prio, addr, NULL,
				      ICE_CAND_TYPE_HOST, NULL,
				      0,     /* tcptype */
				      NULL,  /* sock */
				      0);
		if (err) {
			warning("reflow(%p): add_local_host[%j]"
				" failed (%m)\n",
				rf, addr, err);
			return err;
		}

		/* hijack the UDP-socket of the local candidate
		 *
		 * NOTE: this must be done for all local candidates
		 */
		udp_handler_set(lcand->us, trice_udp_recv_handler, rf);
		if (sa_isset(&rf->media_laddr, SA_ADDR) && AF_INET6 != sa_af(addr)) {
			struct ice_cand_attr mcand =
				*(struct ice_cand_attr *)lcand;
			uint16_t port;

			port = sa_port(&mcand.addr);
			sa_cpy(&mcand.addr, &rf->media_laddr);
			sa_set_port(&mcand.addr, port);
			err = sdp_media_set_lattr(rf->audio.sdpm, false,
						  "candidate",
						  "%H",
						  ice_cand_attr_encode,
						  &mcand);
		}
		else {
			err = sdp_media_set_lattr(rf->audio.sdpm, false,
						  "candidate",
						  "%H",
						  ice_cand_attr_encode, lcand);
		}
		if (err)
			return err;

		if (ifname) {
			str_ncpy(lcand->ifname, ifname,
				 sizeof(lcand->ifname));
		}

		udp_sockbuf_set(lcand->us, UDP_SOCKBUF_SIZE);
	}

	err = interface_add(rf, lcand, ifname, addr);
	if (err)
		return err;

	return err;
}


void reflow_set_ice_role(struct reflow *rf, enum ice_role role)
{
	int err;

	if (!rf)
		return;

	if (sdp_media_session_rattr(rf->audio.sdpm, rf->sdp, "ice-lite")) {
		info("reflow(%p): remote side is ice-lite"
		     " -- force controlling\n", rf);

		role = ICE_ROLE_CONTROLLING;
	}

	err = trice_set_role(rf->trice, role);
	if (err) {
		warning("reflow(%p): trice_set_role failed (%m)\n",
			rf, err);
		return;
	}
}

static bool fmt_add(struct sdp_media *sdpm, struct sdp_format *fmt)
{

	return true;
}


static void bundle_ssrc(struct reflow *rf,
			struct sdp_session *sess, struct sdp_media *sdpm,
			uint32_t ssrc, uint32_t mid, const char *fingerprint,
			bool is_video)
{
	struct sdp_media *newm;
	const char *mtype;
	char *label;
	bool disabled = false;
	int32_t bw;
	int lport;
	int err;
	struct sa sa;
	struct le *le;

	mtype = is_video ? sdp_media_video : sdp_media_audio;
	bw = is_video ? VIDEO_BANDWIDTH : AUDIO_BANDWIDTH;
	(void)bw;
	disabled = ssrc == 0;
	lport = 9; //disabled ? 0 : 9;
	err = sdp_media_add(&newm, sess, mtype, lport, sdp_media_proto(sdpm));
	if (err) {
		warning("bundle_ssrc: video add failed: %m\n", err);
		return;
	}

	sa_init(&sa, AF_INET);
	sa_set_str(&sa, "127.0.0.1", lport);
	sdp_media_set_disabled(newm, false);
	sdp_media_set_laddr(newm, &sa);
	sdp_media_set_lport(newm, lport);
	sdp_media_set_lattr(newm, false, "mid", "%u", mid);
	sdp_media_set_lattr(newm, false, "rtcp-mux", NULL);
	sdp_media_set_lattr(newm, false, "ice-ufrag", "%s", rf->ice_ufrag);
	sdp_media_set_lattr(newm, false, "ice-pwd", "%s", rf->ice_pwd);
	
	sdp_media_set_lattr(newm, true, "fingerprint", "%s", fingerprint);
	sdp_media_set_lattr(newm, true, "setup", reflow_setup_name(rf->setup_local));
	
	if (is_video) {
		sdp_media_set_lattr(newm, false, "extmap",
			"2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time");
		sdp_media_set_lattr(newm, false, "extmap",
			"3 http://www.webrtc.org/experiments/rtp-hdrext/generic-frame-descriptor-00");
		
	}
	else {
		sdp_media_set_lattr(newm, false, "extmap",
		       "1 urn:ietf:params:rtp-hdrext:ssrc-audio-level vad=on");
		sdp_media_set_lattr(newm, false, "extmap",
		       "2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time");
	}
	
	uuid_v4(&label);
	
	if (!disabled) {
		sdp_media_set_lattr(newm, false, "ssrc", "%u cname:%s",
				    ssrc, label);
		sdp_media_set_lattr(newm, false, "ssrc", "%u msid:%s %s",
				    ssrc, label, label);
		sdp_media_set_lattr(newm, false, "ssrc", "%u mslabel:%s",
				    ssrc, label);
		sdp_media_set_lattr(newm, false, "ssrc", "%u label:%s",
				    ssrc, label);
	}
	mem_deref(label);


	//sdp_media_format_apply(sdpm, false, NULL, -1, NULL,
	//		       -1, -1, fmt_handler, newm);

	//sdp_media_rattr_apply(sdpm, NULL,
	//		      media_rattr_handler, newm);

	LIST_FOREACH(sdp_media_format_lst(sdpm, true), le) {
		struct sdp_format *fmt = le->data;

		sdp_format_add(NULL, newm, false,
		       fmt->id, fmt->name, fmt->srate, fmt->ch,
		       NULL, NULL, NULL, false, "%s", fmt->params);
	}
	
	sdp_media_set_ldir(newm, disabled ? SDP_INACTIVE : SDP_SENDONLY);
	sdp_media_set_lbandwidth(newm, SDP_BANDWIDTH_AS, bw);
}


static struct sdp_media *find_media(struct sdp_session *sess, bool video)
				    
{
	struct sdp_media *sdpm;
	const struct list *medial;
	struct le *le;
	bool found = false;
	const char *type = video ? sdp_media_video : sdp_media_audio;

	if (!sess) {
		return NULL;
	}

	medial = sdp_session_medial(sess, true);

	for (le = medial->head; le && !found; le = le->next) {
		sdpm = (struct sdp_media *)le->data;
		
		found = streq(type, sdp_media_name(sdpm));
	}

	return found ? sdpm : NULL;
}


int reflow_generate_offer(struct iflow *iflow,
			  char *sdp, size_t sz)
{
	struct reflow *rf = (struct reflow*)iflow;
	struct mbuf *mb = NULL;
	bool offer = true;
	bool has_video;
	bool has_data;
	int err = 0;

	if (!rf || !sdp)
		return EINVAL;

	if (rf->sdp_state != SDP_IDLE) {
		warning("reflow(%p): invalid sdp state %d (%s)\n",
			rf, rf->sdp_state, __func__);
	}
	rf->sdp_state = SDP_GOFF;

	rf->sdp_offerer = true;

	reflow_set_ice_role(rf, ICE_ROLE_CONTROLLING);

	/* for debugging */
	sdp_session_set_lattr(rf->sdp, true,
			      offer ? "x-OFFER" : "x-ANSWER", NULL);

	has_video = rf->video.sdpm && !rf->video.disabled;
	has_data = rf->data.sdpm != NULL;

	/* Setup the bundle, depending on usage of video or data */
	{
		struct mbuf *bmb;
		char *bstr;
		int i;
		uint32_t mid = 1;
		struct sdp_media *sdpa;
		struct sdp_media *sdpv;
		char *protoa;
		char *protov;

		sdpa = find_media(rf->sdp, false);
		sdpv = find_media(rf->sdp, true);
		str_dup(&protoa, sdp_media_proto(sdpa));
		str_dup(&protov, sdp_media_proto(sdpv));
		//sdpa = rf->audio.sdpm;
		//sdpv = rf->video.sdpm;

		//list_flush((struct list *)sdp_session_medial(rf->sdp, true));
	
		
		bmb = mbuf_alloc(256);
		if (!bmb) {
			err = ENOMEM;
			goto out;
		}
		
		if (has_video && has_data)
			mbuf_printf(bmb, "BUNDLE audio video data");
		else if (has_video)
			mbuf_printf(bmb, "BUNDLE audio video");
		else if (has_data) 
			mbuf_printf(bmb, "BUNDLE audio data");

		for (i = 0; i < rf->rtps.assrcc; ++i) {
			mbuf_printf(bmb, " %u", mid);
			bundle_ssrc(rf, rf->sdp, sdpa,
				    rf->rtps.assrcv[i], mid,
				    rf->audio.fingerprint, false);
			++mid;
		}
		if (has_video) {
			for (i = 0; i < rf->rtps.vssrcc; ++i) {
				mbuf_printf(bmb, " %u", mid);
				bundle_ssrc(rf, rf->sdp, sdpv,
					    rf->rtps.vssrcv[i], mid,
					    rf->video.fingerprint, true);
				++mid;
			}
		}
		
		bmb->pos = 0;
		mbuf_strdup(bmb, &bstr, mbuf_get_left(bmb));
		
		sdp_session_set_lattr(rf->sdp, true, "group", bstr);

		mem_deref(bstr);
		mem_deref(bmb);
		mem_deref(protoa);
		mem_deref(protov);
	}
			
	err = sdp_encode(&mb, rf->sdp, offer);
	if (err) {
		warning("reflow(%p): sdp encode(offer) failed (%m)\n",
			rf, err);
		goto out;
	}

	if (re_snprintf(sdp, sz, "%b", mb->buf, mb->end) < 0) {
		err = ENOMEM;
		goto out;
	}

	debug("reflow(%p) --- generate SDP offer ---------\n", rf);
	debug("%s", sdp);
	debug("----------------------------------------------\n");

	rf->sent_sdp = true;

 out:
	mem_deref(mb);

	return err;
}


int reflow_generate_answer(struct iflow *iflow,
			   char *sdp, size_t sz)
{
	struct reflow *rf = (struct reflow*)iflow;
	bool offer = false;
	struct mbuf *mb = NULL;
	int err = 0;

	if (!rf || !sdp)
		return EINVAL;

	if (rf->sdp_state != SDP_HOFF) {
		warning("reflow(%p): invalid sdp state (%s)\n",
			rf, __func__);
	}
	rf->sdp_state = SDP_DONE;

	rf->sdp_offerer = false;

	reflow_set_ice_role(rf, ICE_ROLE_CONTROLLED);

	/* for debugging */
	sdp_session_set_lattr(rf->sdp, true,
			      offer ? "x-OFFER" : "x-ANSWER", NULL);

	err = sdp_encode(&mb, rf->sdp, offer);
	if (err)
		goto out;

	if (re_snprintf(sdp, sz, "%b", mb->buf, mb->end) < 0) {
		err = ENOMEM;
		goto out;
	}

	debug("reflow(%p) -- generate SDP answer ---------\n", rf);
	debug("%s", sdp);
	debug("----------------------------------------------\n");

	rf->sent_sdp = true;

	reflow_start_ice(rf);
 out:
	mem_deref(mb);

	return err;
}

static bool add_extmap(const char *name, const char *value, void *arg)
{
	struct reflow *rf = (struct reflow *)arg;

	extmap_set(rf->extmap, value);
	return false;
}

/* after the SDP has been parsed,
   we can start to analyze it
   (this must be done _after_ sdp_decode() )
*/
static int post_sdp_decode(struct reflow *rf)
{
	const char *mid, *tool;
	int err = 0;

	if (0 == sdp_media_rport(rf->audio.sdpm)) {
		warning("reflow(%p): sdp medialine port is 0 - disabled\n",
			rf);
		return EPROTO;
	}

	tool = sdp_session_rattr(rf->sdp, "tool");
	if (tool) {
		str_ncpy(rf->sdp_rtool, tool, sizeof(rf->sdp_rtool));
	}

	if (rf->trice) {

		const char *rufrag, *rpwd;

		rufrag = sdp_media_session_rattr(rf->audio.sdpm, rf->sdp,
						 "ice-ufrag");
		rpwd   = sdp_media_session_rattr(rf->audio.sdpm, rf->sdp,
						 "ice-pwd");
		if (!rufrag || !rpwd) {
			warning("reflow(%p): post_sdp_decode: no remote"
				" ice-ufrag/ice-pwd\n", rf);
			warning("%H\n", sdp_session_debug, rf->sdp);
		}

		err |= trice_set_remote_ufrag(rf->trice, rufrag);
		err |= trice_set_remote_pwd(rf->trice, rpwd);
		if (err)
			goto out;

		if (sdp_media_rattr(rf->audio.sdpm, "end-of-candidates"))
			rf->ice_remote_eoc = true;
	}

	mid = sdp_media_rattr(rf->audio.sdpm, "mid");
	if (mid) {
		debug("reflow(%p): updating mid-value to '%s'\n", rf, mid);
		sdp_media_set_lattr(rf->audio.sdpm, true, "mid", mid);
	}

	if (!sdp_media_rattr(rf->audio.sdpm, "rtcp-mux")) {
		warning("reflow(%p): no 'rtcp-mux' attribute in SDP"
			" -- rejecting\n", rf);
		err = EPROTO;
		goto out;
	}

	sdp_media_rattr_apply(rf->audio.sdpm, "extmap", add_extmap, rf);

	if (rf->video.sdpm) {
		const char *group;

		mid = sdp_media_rattr(rf->video.sdpm, "mid");
		if (mid) {
			debug("reflow(%p): updating video mid-value "
			      "to '%s'\n", rf, mid);
			sdp_media_set_lattr(rf->video.sdpm,
					    true, "mid", mid);
		}

		group = sdp_session_rattr(rf->sdp, "group");
		if (group) {
			sdp_session_set_lattr(rf->sdp, true, "group", group);
		}
		sdp_media_rattr_apply(rf->video.sdpm, "extmap", add_extmap, rf);
	}

	if (rf->data.sdpm) {
		mid = sdp_media_rattr(rf->data.sdpm, "mid");
		if (mid) {
			debug("reflow(%p): updating data mid-value "
			      "to '%s'\n", rf, mid);
			sdp_media_set_lattr(rf->data.sdpm,
					    true, "mid", mid);
		}
		sdp_media_rattr_apply(rf->data.sdpm, "extmap", add_extmap, rf);
	}
    
	if (sdp_media_session_rattr(rf->audio.sdpm, rf->sdp, "ice-lite")) {
		info("reflow(%p): remote side is ice-lite"
		     " -- force controlling\n", rf);
		reflow_set_ice_role(rf, ICE_ROLE_CONTROLLING);
	}

	/*
	 * Handle negotiation about a common crypto-type
	 */

	rf->cryptos_remote = 0;
	if (sdp_media_session_rattr(rf->audio.sdpm, rf->sdp, "fingerprint")) {

		rf->cryptos_remote |= CRYPTO_DTLS_SRTP;
	}

	if (sdp_media_rattr(rf->audio.sdpm, "crypto")) {

		warning("reflow(%p): remote peer supports SDESC\n", rf);
	}

	rf->crypto = rf->cryptos_local & rf->cryptos_remote;

	info("reflow(%p): negotiated crypto = %s\n",
	     rf, crypto_name(rf->crypto));

	if (rf->cryptos_local && !rf->cryptos_remote) {
		warning("reflow(%p): we offered crypto, but got none\n", rf);
		return EPROTO;
	}

	/* check for a common crypto here, reject if nothing in common
	 */
	if (rf->cryptos_local && rf->cryptos_remote) {

		if (!rf->crypto) {

			warning("reflow(%p): no common crypto in SDP offer"
				" -- rejecting\n", rf);
			err = EPROTO;
			goto out;
		}
	}

	if (rf->crypto & CRYPTO_DTLS_SRTP) {

		err = handle_dtls_srtp(rf);
		if (err) {
			warning("reflow(%p): handle_dtls_srtp failed (%m)\n",
				rf, err);
			goto out;
		}
	}

	err = handle_setup(rf);
	if (err) {
		warning("reflow(%p): handle_setup failed (%m)\n", rf, err);
		return err;
	}

 out:
	return err;
}


int reflow_handle_offer(struct iflow *iflow, const char *sdp)
{
	struct reflow *rf = (struct reflow*)iflow;
	struct mbuf *mbo = NULL;
	int err = 0;

	if (!rf || !sdp)
		return EINVAL;

	if (rf->sdp_state != SDP_IDLE) {
		warning("reflow(%p): invalid sdp state %d (%s)\n",
			rf, rf->sdp_state, __func__);
		return EPROTO;
	}
	rf->sdp_state = SDP_HOFF;

	++rf->stat.n_sdp_recv;

	rf->sdp_offerer = false;

	reflow_set_ice_role(rf, ICE_ROLE_CONTROLLED);

	mbo = mbuf_alloc(1024);
	if (!mbo)
		return ENOMEM;

	err = mbuf_write_str(mbo, sdp);
	if (err)
		goto out;

	mbo->pos = 0;

	debug("reflow(%p) -- recv SDP offer ----------\n", rf);
	debug("%s", sdp);
	debug("------------------------------------------\n");

	err = sdp_decode(rf->sdp, mbo, true);
	if (err) {
		warning("reflow(%p): could not parse SDP offer"
			" [%zu bytes] (%m)\n",
			rf, mbo->end, err);
		goto out;
	}

	rf->got_sdp = true;

	/* after the SDP offer has been parsed,
	   we can start to analyze it */

	err = post_sdp_decode(rf);
	if (err)
		goto out;


	if (!rf->audio.disabled) {
		start_codecs(rf);
	}

	if (sdp_media_rformat(rf->video.sdpm, NULL)) {

		info("reflow(%p): SDP has video enabled\n", rf);

		rf->video.has_media = true;
		start_video_codecs(rf);
	}
	else {
		info("reflow(%p): video is disabled\n", rf);
	}

	if (sdp_media_rformat(rf->data.sdpm, NULL)) {
		info("reflow(%p): SDP has data channel\n", rf);
		rf->data.has_media = true;
	}

 out:
	mem_deref(mbo);

	return err;
}


int reflow_handle_answer(struct iflow *iflow, const char *sdp)
{
	struct reflow *rf = (struct reflow*)iflow;
	struct mbuf *mb;
	bool offer = false;
	int err = 0;

	if (!rf || !sdp)
		return EINVAL;

	if (rf->sdp_state != SDP_GOFF) {
		warning("reflow(%p): invalid sdp state (%s)\n",
			rf, __func__);
	}
	rf->sdp_state = SDP_DONE;

	++rf->stat.n_sdp_recv;

	mb = mbuf_alloc(1024);
	if (!mb)
		return ENOMEM;

	err = mbuf_write_str(mb, sdp);
	if (err)
		goto out;

	mb->pos = 0;

	debug("reflow(%p) -- recv SDP answer ----------\n", rf);
	debug("%s", sdp);
	debug("------------------------------------\n");

	err = sdp_decode(rf->sdp, mb, offer);
	if (err) {
		warning("reflow(%p): could not parse SDP answer"
			" [%zu bytes] (%m)\n", rf, mb->end, err);
		goto out;
	}

	rf->got_sdp = true;

	/* after the SDP has been parsed,
	   we can start to analyze it
	   (this must be done _after_ sdp_decode() )
	*/

	err = post_sdp_decode(rf);
	if (err)
		goto out;

	if (!rf->audio.disabled) {
		start_codecs(rf);
	}

	if (sdp_media_rformat(rf->video.sdpm, NULL)) {

		info("reflow(%p): SDP has video enabled\n", rf);

		rf->video.has_media = true;
		start_video_codecs(rf);
	}
	else {
		info("reflow(%p): video is disabled\n", rf);
	}


	if (sdp_media_rformat(rf->data.sdpm, NULL)) {

		info("reflow(%p): SDP has data channel\n", rf);

		rf->data.has_media = true;
	}
	else {
		info("reflow(%p): no data channel\n", rf);
	}

	reflow_start_ice(rf);
 out:
	mem_deref(mb);

	return err;
}


/*
 * This function does 2 things:
 *
 * - handle offer
 * - generate answer
 */
int reflow_offeranswer(struct reflow *rf,
			  char *answer, size_t answer_sz,
			  const char *offer)
{
	int err = 0;

	if (!rf || !answer || !offer)
		return EINVAL;

	err = reflow_handle_offer(&rf->iflow, offer);
	if (err)
		return err;

	err = reflow_generate_answer(&rf->iflow, answer, answer_sz);
	if (err)
		return err;

	return 0;
}


void reflow_sdpstate_reset(struct reflow *rf)
{
	if (!rf)
		return;

	rf->sdp_state = SDP_IDLE;

	sdp_session_del_lattr(rf->sdp, "x-OFFER");
	sdp_session_del_lattr(rf->sdp, "x-ANSWER");

	rf->got_sdp = false;
	rf->sent_sdp = false;
}


int reflow_send_rtp(struct reflow *rf, const struct rtp_header *hdr,
		       const uint8_t *pld, size_t pldlen)
{
	struct mbuf *mb;
	size_t headroom = 0;
	int err = 0;

	if (!rf || !pld || !pldlen || !hdr)
		return EINVAL;

	MAGIC_CHECK(rf);

	/* check if media-stream is ready for sending */
	if (!reflow_is_ready(rf)) {
		warning("reflow(%p): send_rtp: not ready\n", rf);
		return EINTR;
	}

	if (rf->err)
		return rf->err;

	headroom = get_headroom(rf);

	mb = mbuf_alloc(headroom + pldlen);
	if (!mb)
		return ENOMEM;

	mb->pos = headroom;
	err  = rtp_hdr_encode(mb, hdr);
	err |= mbuf_write_mem(mb, pld, pldlen);
	if (err)
		goto out;

	mb->pos = headroom;

	update_tx_stats(rf, pldlen); /* This INCLUDES the rtp header! */

	err = udp_send(rf->rtp, &rf->sel_pair->rcand->attr.addr, mb);
	if (err)
		goto out;

 out:
	mem_deref(mb);

	return err;
}


/* NOTE: might be called from different threads */
int reflow_send_raw_rtp(struct reflow *rf, const uint8_t *buf,
			   size_t len)
{
	struct mbuf *mb;
	size_t headroom;
	int err;

	if (!rf || !buf)
		return EINVAL;

	MAGIC_CHECK(rf);

	/* check if media-stream is ready for sending */
	if (!reflow_is_ready(rf)) {
		/*
		warning("reflow(%p): send_raw_rtp(%zu bytes): not ready"
			" [ice=%d, crypto=%d]\n",
			rf, len, rf->ice_ready, rf->crypto_ready);
		*/
		return EINTR;
	}

	if (rf->err)
		return rf->err;

	pthread_mutex_lock(&rf->mutex_enc);

	headroom = get_headroom(rf);

	mb = mbuf_alloc(headroom + len);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	mb->pos = headroom;
	err = mbuf_write_mem(mb, buf, len);
	if (err)
		goto out;
	mb->pos = headroom;

	if (len >= RTP_HEADER_SIZE)
		update_tx_stats(rf, len - RTP_HEADER_SIZE);

	err = udp_send(rf->rtp, &rf->sel_pair->rcand->attr.addr, mb);
	if (err)
		goto out;

 out:
	mem_deref(mb);

	pthread_mutex_unlock(&rf->mutex_enc);

	return err;
}

static void mf_assign_worker(struct mediaflow *mf, struct worker *w)
{
	struct reflow *rf;

	if (!mf)
		return;

	rf = mf->flow;
	rf->worker = w;

	info("reflow(%p): dce=%p worker=%p\n", rf, rf->data.dce, w);

	dce_assign_worker(rf->data.dce, w);
}

static int mf_assign_streams(struct mediaflow *mf,
			     uint32_t **assrcv, int assrcc,
			     uint32_t **vssrcv, int vssrcc)
{
	struct reflow *rf;
	uint32_t *ssrcv;
	int err = 0;
	int i;
	
	if (!mf)
		return EINVAL;

	rf = mf->flow;

	/* Audio streams */
	ssrcv = mem_zalloc(assrcc * sizeof(*ssrcv), NULL);
	if (!ssrcv) {
		err = ENOMEM;
		goto out;
	}
	rf->rtps.assrcv = ssrcv;
	for(i = 0; i < assrcc; ++i) {
		uint32_t ssrc = 0;
		do {
			ssrc = regen_lssrc(ssrc);
		} while(exist_ssrc(rf, ssrc));
		ssrcv[i] = ssrc;
		rf->rtps.assrcc = i + 1;
	}
	if (assrcv)
		*assrcv = ssrcv;

	/* Video streams */
	ssrcv = mem_zalloc(vssrcc * sizeof(*ssrcv), NULL);
	if (!ssrcv) {
		err = ENOMEM;
		goto out;
	}
	rf->rtps.vssrcv = ssrcv;
	for(i = 0; i < vssrcc; ++i) {
		uint32_t ssrc = 0;
		do {
			ssrc = regen_lssrc(ssrc);
		} while(exist_ssrc(rf, ssrc));
		ssrcv[i] = ssrc;
		rf->rtps.vssrcc = i + 1;
	}
	if (vssrcv)
		*vssrcv = ssrcv;

 out:
	if (err)
		mem_deref(ssrcv);

	return err;
}


static int mf_send_rtp(struct mediaflow *mf, const uint8_t *data, size_t len)
{
	struct reflow *rf;
	
	if (!mf)
		return EINVAL;

	rf = mf->flow;

	return reflow_send_raw_rtp(rf, data, len);
}

static int mf_send_rtcp(struct mediaflow *mf, const uint8_t *data, size_t len)
{
	struct reflow *rf;
	
	if (!mf)
		return EINVAL;

	rf = mf->flow;

	return reflow_send_raw_rtcp(rf, data, len);
}


static int mf_send_dc(struct mediaflow *mf, const uint8_t *data, size_t len)
{
	struct reflow *rf;

	if (!mf)
		return EINVAL;

	rf = mf->flow;

	return reflow_send_dc_data(rf, data, len);
}


static uint32_t mf_get_ssrc(struct mediaflow *mf, const char *type, bool local)
{
	enum media_type mt;
	struct reflow *rf;
	uint32_t ssrc = 0;
	int err;
	
	if (streq(type, "video")) {
		mt = MEDIA_VIDEO;
	}
	else {
		mt = MEDIA_AUDIO;
	}

	if (!mf)
		return 0;

	rf = mf->flow;

	if (local) {
		ssrc = reflow_get_local_ssrc(rf, mt);
	}
	else {
		err = reflow_get_remote_ssrc(rf, mt, &ssrc);
		if (err)
			ssrc = 0;
	}

	return ssrc;
}

static void reflow_remove_ssrc(struct reflow *rf, uint32_t ssrc)
{
	if (!rf)
		return;
	
	srtp_remove_stream(rf->srtp_tx, ssrc);
}

static void mf_remove_ssrc(struct mediaflow *mf, uint32_t ssrc)
{
	struct reflow *rf;

	if (!mf)
		return;

	rf = mf->flow;
	reflow_remove_ssrc(rf, ssrc);
}

int reflow_send_raw_rtcp(struct reflow *rf,
			    const uint8_t *buf, size_t len)
{
	struct mbuf *mb;
	size_t headroom;
	int err;

	if (!rf || !buf || !len)
		return EINVAL;

	MAGIC_CHECK(rf);

	/* check if media-stream is ready for sending */
	if (!reflow_is_ready(rf)) {
#if 0
		warning("reflow(%p): send_raw_rtcp(%zu bytes): not ready"
			" [ice=%d, crypto=%d]\n",
			rf, len, rf->ice_ready, rf->crypto_ready);
#endif
		return EINTR;
	}

	if (rf->err)
		return rf->err;
	
	pthread_mutex_lock(&rf->mutex_enc);

	headroom = get_headroom(rf);

	mb = mbuf_alloc(headroom + len);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	mb->pos = headroom;
	err = mbuf_write_mem(mb, buf, len);
	if (err)
		goto out;
	mb->pos = headroom;

	err = udp_send(rf->rtp, &rf->sel_pair->rcand->attr.addr, mb);
	if (err)
		goto out;

 out:
	mem_deref(mb);

	pthread_mutex_unlock(&rf->mutex_enc);

	return err;
}


static bool rcandidate_handler(const char *name, const char *val, void *arg)
{
	struct reflow *rf = arg;
	struct ice_cand_attr rcand;
	int err;

	err = ice_cand_attr_decode(&rcand, val);
	if (err || rcand.compid != ICE_COMPID_RTP ||
	    rcand.proto != IPPROTO_UDP)
		goto out;

	err = trice_rcand_add(NULL, rf->trice, rcand.compid,
			      rcand.foundation, rcand.proto, rcand.prio,
			      &rcand.addr, rcand.type, rcand.tcptype);
	if (err) {
		warning("reflow(%p): rcand: trice_rcand_add failed"
			" [%J] (%m)\n",
			rf, &rcand.addr, err);
	}

 out:
	return false;
}


static void trice_estab_handler(struct ice_candpair *pair,
				const struct stun_msg *msg, void *arg)
{
	struct reflow *rf = arg;
	void *sock;
	bool use_pair = false;
	int err;

	info("reflow(%p): ice pair established  %H\n",
	     rf, trice_candpair_debug, pair);

	/* verify local candidate */
	sock = trice_lcand_sock(rf->trice, pair->lcand);
	if (!sock) {
		warning("reflow(%p): estab: lcand has no sock [%H]\n",
			rf, trice_cand_print, pair->lcand);
		return;
	}

#if 0
	if (!pair->nominated) {
		warning("reflow(%p): ICE pair is not nominated!\n", rf);
	}
#endif

	if (rf->sel_pair) {
		use_pair = pair->rcand->attr.type < rf->sel_pair->rcand->attr.type;
	}
	
	/* We use the first pair that is working */
	if (use_pair || !rf->ice_ready) {
		struct stun_attr *attr;
		struct turn_conn *conn;
		struct ice_candpair *p = rf->sel_pair;

		rf->sel_pair = NULL;
		mem_deref(p);
		rf->sel_pair = mem_ref(pair);

		rf->ice_ready = true;

		attr = stun_msg_attr(msg, STUN_ATTR_SOFTWARE);
		if (attr && !rf->peer_software) {
			(void)str_dup(&rf->peer_software, attr->v.software);
		}

		info("reflow(%p): trice: setting peer to %H [%s]\n",
		     rf, print_cand, pair->rcand,
		     rf->peer_software);

#if 1
		// TODO: extra for PRFLX
		udp_handler_set(pair->lcand->us, trice_udp_recv_handler, rf);
#endif


		/* add TURN channel */
		conn = turnconn_find_allocated(&rf->turnconnl,
					       IPPROTO_UDP);
		if (conn && AF_INET == sa_af(&pair->rcand->attr.addr)) {

			info("reflow(%p): adding TURN channel to %J\n",
			     rf, &pair->rcand->attr.addr);

			err = turnconn_add_channel(conn,
						   &pair->rcand->attr.addr);
			if (err) {
				warning("reflow(%p): could not add TURN"
					" channel (%m)\n", rf, err);
			}
		}

		ice_established_handler(rf, &pair->rcand->attr.addr);
	}
}


static bool all_failed(const struct list *lst)
{
	struct le *le;

	if (list_isempty(lst))
		return false;

	for (le = list_head(lst); le; le = le->next) {

		struct ice_candpair *pair = le->data;

		if (pair->state != ICE_CANDPAIR_FAILED)
			return false;
	}

	return true;
}


static void trice_failed_handler(int err, uint16_t scode,
				 struct ice_candpair *pair, void *arg)
{
	struct reflow *rf = arg;

#if 0
	info("reflow(%p): candpair not working [%H]\n",
	     rf, trice_candpair_debug, pair);

#endif

	if (!list_isempty(trice_validl(rf->trice)))
		return;

	if (all_failed(trice_checkl(rf->trice))) {

		int to = (int)(tmr_jiffies() - rf->ts_nat_start);

		warning("reflow(%p): all pairs failed"
			" after %d milliseconds"
			" (checklist=%u, validlist=%u)\n",
			rf, to,
			list_count(trice_checkl(rf->trice)),
			list_count(trice_validl(rf->trice))
			);

		rf->ice_ready = false;
		rf->err = EPROTO;

		tmr_start(&rf->tmr_error, 0, tmr_error_handler, rf);
	}
}


/*
 * Start the reflow state-machine.
 *
 * this should be called after SDP exchange is complete. we will now
 * start sending ICE connectivity checks to all known remote candidates
 */
int reflow_start_ice(struct reflow *rf)
{
	struct le *le;
	int err;

	if (!rf)
		return EINVAL;

	MAGIC_CHECK(rf);

	rf->ts_nat_start = tmr_jiffies();

	sdp_media_rattr_apply(rf->audio.sdpm, "candidate",
			      rcandidate_handler, rf);

	/* add permission for ALL TURN-Clients */
	for (le = rf->turnconnl.head; le; le = le->next) {
		struct turn_conn *conn = le->data;

		if (conn->turnc && conn->turn_allocated) {
			add_permission_to_remotes_ds(rf, conn);
		}
	}

	info("reflow(%p): start_ice: starting ICE checklist with"
	     " %u remote candidates\n",
	     rf, list_count(trice_rcandl(rf->trice)));

	err = trice_checklist_start(rf->trice, rf->trice_stun,
				    ICE_INTERVAL,
				    trice_estab_handler,
				    trice_failed_handler,
				    rf);
	if (err) {
		warning("reflow(%p): could not start ICE checklist (%m)\n",
			rf, err);
		return err;
	}

	return 0;
}


int reflow_set_video_state(struct iflow *iflow,
			   enum icall_vstate vstate)
{
	struct reflow *rf = (struct reflow*)iflow;
	int err = 0;

	if (!rf->video.has_media) {
		return ENODEV;
	}

	return err;
}


bool reflow_is_sending_video(struct reflow *rf)
{
	if (!rf)
		return false;

	return rf->video.started;
}


void reflow_stop_media(struct iflow *iflow)
{
	struct reflow *rf = (struct reflow*)iflow;

	if (!rf)
		return;

	if (!rf->started)
		return;

	info("reflow(%p): stop_media\n", rf);

	rf->started = false;

	tmr_cancel(&rf->tmr_rtp);
	rf->sent_rtp = false;
	rf->got_rtp = false;

	IFLOW_CALL_CB(rf->iflow, stoppedh,
		rf->iflow.arg);
}

void reflow_reset_media(struct reflow *rf)
{
	void *p;
	
	if (!rf)
		return;

	rf->mctx = NULL;
	
	p = rf->ads;
	rf->ads = NULL;
	mem_deref(p);

	p = rf->aes;
	rf->aes = NULL;
	mem_deref(p);


	p = rf->video.ves;
	rf->video.ves = NULL;
	mem_deref(p);

	p = rf->video.vds;
	rf->video.vds = NULL;
	mem_deref(p);

	rf->video.mctx = NULL;
}


static uint32_t calc_prio(enum ice_cand_type type, int af,
			  int turn_proto, bool turn_secure)
{
	uint16_t lpref = 0;

	switch (turn_proto) {

	case IPPROTO_UDP:
		lpref = 3;
		break;

	case IPPROTO_TCP:
		if (turn_secure)
			lpref = 1;
		else
			lpref = 2;
		break;
	}

	return ice_cand_calc_prio(type, lpref, ICE_COMPID_RTP);
}


static void submit_local_candidate(struct reflow *rf,
				   enum ice_cand_type type,
				   const struct sa *addr,
				   const struct sa *rel_addr, bool eoc,
				   int turn_proto, bool turn_secure,
				   void **sockp, struct udp_sock *sock)
{
	struct ice_cand_attr attr = {
		.foundation = "1",  /* NOTE: same foundation for all */
		.compid     = ICE_COMPID_RTP,
		.proto      = IPPROTO_UDP,
		.prio       = 0,
		.addr       = *addr,
		.type       = type,
		.tcptype    = 0,
	};
	char cand[512];
	struct ice_lcand *lcand;
	int err;
	bool add;

	switch (type) {

	case ICE_CAND_TYPE_RELAY:
		add = true;
		break;

	default:
		add = !rf->privacy_mode;
		break;
	}

	if (!add) {
		debug("reflow(%p): NOT adding cand %s (privacy mode)\n",
		      rf, ice_cand_type2name(type));
		return;
	}

	attr.prio = calc_prio(type, sa_af(addr),
			      turn_proto, turn_secure);

	if (turn_proto == IPPROTO_UDP) {

	}
	else
		sock = NULL;


	err = trice_lcand_add(&lcand, rf->trice, attr.compid,
			      attr.proto, attr.prio, addr, NULL,
			      attr.type, rel_addr,
			      0 /* tcptype */,
			      sock, LAYER_ICE);
	if (err) {
		warning("reflow(%p): add local cand failed (%m)\n",
			rf, err);
		return;
	}

	if (sockp)
		*sockp = lcand->us;

	/* hijack the UDP-socket of the local candidate
	 *
	 * NOTE: this must be done for all local candidates
	 */
	udp_handler_set(lcand->us, trice_udp_recv_handler, rf);

	re_snprintf(cand, sizeof(cand), "a=candidate:%H",
		    ice_cand_attr_encode, lcand);

	/* also add the candidate to SDP */

	if (add) {
		err = sdp_media_set_lattr(rf->audio.sdpm, false,
					  "candidate",
					  "%H",
					  ice_cand_attr_encode, lcand);
		if (err)
			return;
	}
}


static void gather_stun_resp_handler(int err, uint16_t scode,
				     const char *reason,
				     const struct stun_msg *msg, void *arg)
{
	struct reflow *rf = arg;
	struct stun_attr *map = NULL, *attr;

	if (err) {
		warning("reflow(%p): stun_resp %m\n", rf, err);
		goto error;
	}

	if (scode) {
		warning("reflow(%p): stun_resp %u %s\n", rf, scode, reason);
		goto error;
	}

	map = stun_msg_attr(msg, STUN_ATTR_XOR_MAPPED_ADDR);
	if (!map) {
		warning("reflow(%p): xor_mapped_addr attr missing\n", rf);
		goto error;
	}

	rf->stun_ok = true;

	attr = stun_msg_attr(msg, STUN_ATTR_SOFTWARE);
	info("reflow(%p): STUN allocation OK"
	     " (mapped=%J) [%s]\n",
	     rf,
	     &map->v.xor_mapped_addr,
	     attr ? attr->v.software : "");

	submit_local_candidate(rf, ICE_CAND_TYPE_SRFLX,
			       &map->v.xor_mapped_addr, &rf->laddr_default,
			       true, IPPROTO_UDP, false, NULL, rf->us_stun);

	rf->ice_local_eoc = true;
	sdp_media_set_lattr(rf->audio.sdpm, true, "end-of-candidates", NULL);

	IFLOW_CALL_CB(rf->iflow, gatherh,
		rf->iflow.arg);

	return;

 error:
	/* NOTE: only flag an error if ICE is not established yet */
	if (!rf->ice_ready)
		ice_error(rf, err ? err : EPROTO);
}


// TODO: should be done PER interface
int reflow_gather_stun(struct reflow *rf, const struct sa *stun_srv)
{
	struct stun *stun = NULL;
	struct sa laddr;
	void *sock = NULL;
	int err;

	if (!rf || !stun_srv)
		return EINVAL;

	if (rf->ct_gather)
		return EALREADY;

	sa_init(&laddr, sa_af(stun_srv));

	if (!rf->trice)
		return EINVAL;

	err = udp_listen(&rf->us_stun, &laddr,
			 stun_udp_recv_handler, rf);
	if (err)
		return err;

	stun = rf->trice_stun;
	sock = rf->us_stun;

	if (!stun || !sock) {
		warning("reflow(%p): gather_stun: no STUN/SOCK instance\n",
			rf);
		return EINVAL;
	}

	err = stun_request(&rf->ct_gather, stun, IPPROTO_UDP,
			   sock, stun_srv, 0,
			   STUN_METHOD_BINDING, NULL, 0, false,
			   gather_stun_resp_handler, rf, 0);
	if (err) {
		warning("reflow(%p): stun_request failed (%m)\n", rf, err);
		return err;
	}

	rf->stun_server = true;

	return 0;
}


static void add_turn_permission(struct reflow *rf,
				struct turn_conn *conn,
				const struct ice_cand_attr *rcand)
{
	bool add;
	int err;

	if (!rf || !rcand)
		return;

	if (AF_INET != sa_af(&rcand->addr))
		return;

	if (rcand->type == ICE_CAND_TYPE_HOST)
		add = !sa_ipv4_is_private(&rcand->addr);
	else
		add = true;

	if (add) {
		info("reflow(%p): adding TURN permission"
		     " to remote address %s.%j <turnconn=%p>\n",
		     rf,
		     ice_cand_type2name(rcand->type),
		     &rcand->addr, conn);

		err = turnconn_add_permission(conn, &rcand->addr);
		if (err) {
			warning("reflow(%p): failed to"
				" add permission (%m)\n",
				rf, err);
		}
	}
}


static void add_permissions(struct reflow *rf, struct turn_conn *conn)
{
	struct le *le;

	for (le = list_head(trice_rcandl(rf->trice)); le; le = le->next) {

		struct ice_rcand *rcand = le->data;

		add_turn_permission(rf, conn, &rcand->attr);
	}
}


static void add_permission_to_remotes(struct reflow *rf)
{
	struct turn_conn *conn;
	struct le *le;

	if (!rf)
		return;

	if (!rf->trice)
		return;

	for (le = rf->turnconnl.head; le; le = le->next) {

		conn = le->data;

		if (conn->turn_allocated)
			add_permissions(rf, conn);
	}
}


static void add_permission_to_remotes_ds(struct reflow *rf,
					 struct turn_conn *conn)
{
	struct le *le;

	if (!rf->trice)
		return;

	for (le = list_head(trice_rcandl(rf->trice)); le; le = le->next) {

		struct ice_rcand *rcand = le->data;

		add_turn_permission(rf, conn, &rcand->attr);
	}
}


/* all outgoing UDP-packets must be sent via
 * the TCP-connection to the TURN server
 */
static bool turntcp_send_handler(int *err, struct sa *dst,
				 struct mbuf *mb, void *arg)
{
	struct turn_conn *tc = arg;

	*err = turnc_send(tc->turnc, dst, mb);
	if (*err) {
		warning("reflow: turnc_send failed (%zu bytes to %J)\n",
			mbuf_get_left(mb), dst);
	}

	return true;
}


static void turnconn_estab_handler(struct turn_conn *conn,
				   const struct sa *relay_addr,
				   const struct sa *mapped_addr,
				   const struct stun_msg *msg, void *arg)
{
	struct reflow *rf = arg;
	void *sock = NULL;
	int err;
	(void)msg;

	info("reflow(%p): TURN-%s established (%J)\n",
	     rf, turnconn_proto_name(conn), relay_addr);

	if (!valid_rf(rf)) {
		warning("reflow(%p): turnconn_estab_handler: not valid\n",
			rf);
		return;
	}
	
	if (rf->rf_stats.turn_alloc < 0 &&
	    conn->ts_turn_resp &&
	    conn->ts_turn_req) {

		rf->rf_stats.turn_alloc =
			(int)(conn->ts_turn_resp - conn->ts_turn_req);
	}

#if 0
	if (0) {

		sdp_media_set_laddr(rf->audio.sdpm, relay_addr);
		sdp_media_set_laddr(rf->video.sdpm, relay_addr);

		add_permission_to_relays(rf, conn);
	}
#endif

	/* NOTE: important to ship the SRFLX before RELAY cand. */

	if (conn->proto == IPPROTO_UDP) {
		submit_local_candidate(rf, ICE_CAND_TYPE_SRFLX,
				       mapped_addr, &rf->laddr_default, false,
				       conn->proto, conn->secure, NULL,
				       conn->us_turn);
	}

	submit_local_candidate(rf, ICE_CAND_TYPE_RELAY,
			       relay_addr, mapped_addr, true,
			       conn->proto, conn->secure, &sock,
			       conn->us_turn);

	if (conn->proto == IPPROTO_TCP) {
		/* NOTE: this is needed to snap up outgoing UDP-packets */
		conn->us_app = mem_ref(sock);
		err = udp_register_helper(&conn->uh_app, sock, LAYER_TURN,
					  turntcp_send_handler, NULL, conn);
		if (err) {
			warning("reflow(%p): TURN failed to register "
				"UDP-helper (%m)\n", rf, err);
			goto error;
		}
	}

	rf->ice_local_eoc = true;
	sdp_media_set_lattr(rf->audio.sdpm, true, "end-of-candidates", NULL);

	add_permission_to_remotes_ds(rf, conn);
	add_permission_to_remotes(rf);

	/* NOTE: must be called last, since app might deref reflow */
	IFLOW_CALL_CB(rf->iflow, gatherh,
		rf->iflow.arg);

	return;

 error:
	/* NOTE: only flag an error if ICE is not established yet */
	if (!rf->ice_ready)
		ice_error(rf, err ? err : EPROTO);
}


/* incoming packets over TURN - demultiplex to the right module */
static void turnconn_data_handler(struct turn_conn *conn, const struct sa *src,
				  struct mbuf *mb, void *arg)
{
	struct reflow *rf = arg;
	struct ice_lcand *lcand;
	enum packet pkt;

	pkt = packet_classify_packet_type(mb);

	if (pkt == PACKET_STUN) {

		debug("reflow(%p): incoming STUN-packet via TURN\n", rf);

		// TODO: this supports only one TURN-client for now
		//       add support for multiple clients
		lcand = trice_lcand_find2(rf->trice,
					  ICE_CAND_TYPE_RELAY, sa_af(src));
		if (lcand) {

			/* forward packet to ICE */
			trice_lcand_recv_packet(lcand, src, mb);
		}
		else {
			debug("reflow(%p): turnconn: no local candidate\n",
			      rf);
			demux_packet(rf, src, mb);
		}
	}
	else {
		demux_packet(rf, src, mb);
	}
}


static void turnconn_error_handler(int err, void *arg)
{
	struct reflow *rf = arg;
	bool one_allocated;
	bool all_failed;

	one_allocated = turnconn_is_one_allocated(&rf->turnconnl);
	all_failed = turnconn_are_all_failed(&rf->turnconnl);

	warning("reflow(%p): turnconn_error:  turnconnl=%u"
		"  [one_allocated=%d, all_failed=%d]  (%m)\n",
		rf, list_count(&rf->turnconnl), one_allocated, all_failed, err);

	if (all_failed)
		goto fail;

	if (list_count(&rf->turnconnl) > 1 ||
	    one_allocated) {

		info("reflow(%p): ignoring turn error, already have 1\n",
		     rf);
		return;
	}

 fail:
	/* NOTE: only flag an error if ICE is not established yet */
	if (!rf->ice_ready)
		ice_error(rf, err ? err : EPROTO);
}


#if 0
static struct interface *default_interface(const struct reflow *rf)
{
	struct le *le;

	for (le = rf->interfacel.head; le; le = le->next) {
		struct interface *ifc = le->data;

		if (ifc->is_default)
			return ifc;
	}

	/* default not found, just return first one */
	return list_ledata(list_head(&rf->interfacel));
}
#endif

/*
 * Gather RELAY and SRFLX candidates (UDP only)
 */
int reflow_gather_turn(struct reflow *rf,
		       struct turn_conn *tc,
		       const struct sa *turn_srv,
		       const char *username, const char *password)
{
	struct interface *ifc;
	struct sa turn_srv6;
	void *sock = NULL;
	int err;

	(void)ifc;
	
	if (!rf || !turn_srv)
		return EINVAL;

	info("reflow(%p): gather_turn: %J(UDP)\n", rf, turn_srv);
	
	if (!sa_isset(turn_srv, SA_ALL)) {
		warning("reflow(%p): gather_turn: no TURN server\n", rf);
		return EINVAL;
	}


	if (!rf->trice)
		return EINVAL;

	/* NOTE: this should only be done if we detect that
	 *       we are behind a NAT64
	 */
	if (rf->af != sa_af(turn_srv)) {

		err = sa_translate_nat64(&turn_srv6, turn_srv);
		if (err) {
			warning("reflow(%p): gather_turn: "
				"sa_translate_nat64(%j) failed (%m)\n",
				rf, turn_srv, err);
			return err;
		}

		info("reflow(%p): Dualstack: TRANSLATE NAT64"
		     " (%J ----> %J)\n",
		     rf, turn_srv, &turn_srv6);

		turn_srv = &turn_srv6;
	}

#if 0
	/* Reuse UDP-sockets from HOST interface */
	ifc = default_interface(rf);
	if (ifc) {
		info("reflow(%p): gather_turn: default interface"
		     " is %s|%j (lcand=%p)\n",
		     rf, ifc->ifname, &ifc->addr, ifc->lcand);

		if (ifc->lcand)
			sock = ifc->lcand->us;
	}
#endif

	info("reflow(%p): gather_turn: %J\n", rf, turn_srv);

	err = turnconn_start(tc, &rf->turnconnl,
			     turn_srv, IPPROTO_UDP, false,
			     username, password,
			     rf->af, sock,
			     LAYER_STUN, LAYER_TURN,
			     turnconn_estab_handler,
			     turnconn_data_handler,
			     turnconn_error_handler, rf);
	if (err)
		warning("reflow(%p): turnc_alloc failed (%m)\n", rf, err);

	return err;
}


/*
 * Add a new TURN-server and gather RELAY candidates (TCP or TLS)
 */
int reflow_gather_turn_tcp(struct reflow *rf,
			   struct turn_conn *tc,
			   const struct sa *turn_srv,
			   const char *username, const char *password,
			   bool secure)
{
	int err = 0;

	if (!rf || !turn_srv)
		return EINVAL;

	info("reflow(%p): gather_turn_tcp: %J(secure=%d)\n",
	     rf, turn_srv, secure);

	err = turnconn_start(tc, &rf->turnconnl,
			     turn_srv, IPPROTO_TCP, secure,
			     username, password,
			     rf->af, NULL,
			     LAYER_STUN, LAYER_TURN,
			     turnconn_estab_handler,
			     turnconn_data_handler,
			     turnconn_error_handler, rf);
	if (err)
		return err;

	return err;
}


size_t reflow_remote_cand_count(const struct reflow *rf)
{
	if (!rf)
		return 0;

	return list_count(trice_rcandl(rf->trice));
}


void reflow_set_fallback_crypto(struct reflow *rf, enum media_crypto cry)
{
	if (!rf)
		return;

	rf->crypto_fallback = cry;
}


enum media_crypto reflow_crypto(const struct reflow *rf)
{
	return rf ? rf->crypto : CRYPTO_NONE;
}


struct auenc_state *reflow_encoder(const struct reflow *rf)
{
	return rf ? rf->aes : NULL;
}


struct audec_state *reflow_decoder(const struct reflow *rf)
{
	if (!rf)
		return NULL;

	MAGIC_CHECK(rf);

	return rf->ads;
}


struct videnc_state *reflow_video_encoder(const struct reflow *rf)
{
	return rf ? rf->video.ves : NULL;
}


struct viddec_state *reflow_video_decoder(const struct reflow *rf)
{
	return rf ? rf->video.vds : NULL;
}


int reflow_debug(struct re_printf *pf, const struct iflow *iflow)
{
	struct reflow *rf = (struct reflow*)iflow;
	struct ice_rcand *rcand = NULL;
	int err = 0;
	char nat_letter = ' ';

	if (!rf)
		return 0;

	nat_letter = rf->ice_ready ? 'I' : ' ';

	if (rf->sel_pair)
		rcand = rf->sel_pair->rcand;

	err = re_hprintf(pf, "%c%c%c%c%c ice=%s-%s.%J [%s] tx=%zu rx=%zu",
			 rf->got_sdp ? 'S' : ' ',
			 nat_letter,
			 rf->crypto_ready ? 'D' : ' ',
			 reflow_is_rtpstarted(rf) ? 'R' : ' ',
			 rf->data.ready ? 'C' : ' ',
			 reflow_lcand_name(rf),
			 rcand ? ice_cand_type2name(rcand->attr.type) : "?",
			 rcand ? &rcand->attr.addr : NULL,
			 rf->peer_software,
			 rf->stat.tx.bytes,
			 rf->stat.rx.bytes);

	return err;
}


const char *reflow_peer_software(const struct reflow *rf)
{
	return rf ? rf->peer_software : NULL;
}


bool reflow_has_video(const struct iflow *iflow)
{
	struct reflow *rf = (struct reflow*)iflow;
	return rf ? rf->video.has_media : false;
}


bool reflow_has_data(const struct reflow *rf)
{
	return rf ? rf->data.sdpm != NULL : false;
}

int reflow_video_debug(struct re_printf *pf, const struct reflow *rf)
{
	if (!rf)
		return 0;

	return 0;
}


const struct tls_conn *reflow_dtls_connection(const struct reflow *rf)
{
	return rf ? rf->tls_conn : NULL;
}


bool reflow_is_started(const struct reflow *rf)
{
	return rf ? rf->started : false;
}


bool reflow_got_sdp(const struct reflow *rf)
{
	return rf ? rf->got_sdp : false;
}


/*
 * return TRUE if one SDP sent AND one SDP received
 */
bool reflow_sdp_is_complete(const struct reflow *rf)
{
	if (!rf)
		return false;

	return rf->got_sdp && rf->sent_sdp;
}


bool reflow_is_gathered(const struct iflow *iflow)
{
	struct reflow *rf = (struct reflow*)iflow;
	if (!rf)
		return false;

	debug("reflow(%p): is_gathered:  turnconnl=%u/%u  stun=%d/%d\n",
	      rf,
	      rf->turnc, list_count(&rf->turnconnl),
	      rf->stun_server, rf->stun_ok);

	if (!list_isempty(&rf->turnconnl))
		return turnconn_is_one_allocated(&rf->turnconnl);

	if (rf->stun_server)
		return rf->stun_ok;

	if (rf->turnc)
		return false;

	return list_count(&rf->interfacel) > 0;
}


uint32_t reflow_get_local_ssrc(struct reflow *rf, enum media_type type)
{
	if (!rf || type >= MEDIA_NUM)
		return 0;

	return rf->lssrcv[type];
}


int reflow_get_remote_ssrc(const struct reflow *rf, enum media_type type,
			      uint32_t *ssrcp)
{
	struct sdp_media *sdpm;
	const char *rssrc;
	struct pl pl_ssrc;
	int err;

	sdpm = type == MEDIA_AUDIO ? rf->audio.sdpm : rf->video.sdpm;

	rssrc = sdp_media_rattr(sdpm, "ssrc");
	if (!rssrc)
		return ENOENT;

	err = re_regex(rssrc, str_len(rssrc), "[0-9]+", &pl_ssrc);
	if (err)
		return err;

	*ssrcp = pl_u32(&pl_ssrc);

	return 0;
}


bool reflow_dtls_ready(const struct reflow *rf)
{
	if (!rf)
		return false;

	return rf->crypto_ready;
}


bool reflow_ice_ready(const struct reflow *rf)
{
	if (!rf)
		return false;

	return rf->ice_ready;
}


const struct rtp_stats* reflow_rcv_audio_rtp_stats(const struct reflow *rf)
{
	if (!rf)
		return NULL;

	return &rf->audio_stats_rcv;
}


const struct rtp_stats* reflow_snd_audio_rtp_stats(const struct reflow *rf)
{
	if (!rf)
		return NULL;

	return &rf->audio_stats_snd;
}


const struct rtp_stats* reflow_rcv_video_rtp_stats(const struct reflow *rf)
{
	if (!rf)
		return NULL;

	return &rf->video_stats_rcv;
}


const struct rtp_stats* reflow_snd_video_rtp_stats(const struct reflow *rf)
{
	if (!rf)
		return NULL;

	return &rf->video_stats_snd;
}


struct aucodec_stats *reflow_codec_stats(struct reflow *rf)
{
#if 0
	const struct aucodec *ac;

	if (!rf)
		return NULL;

	ac = audec_get(rf->ads);
	if (ac && ac->get_stats)
		ac->get_stats(rf->ads, &rf->codec_stats);

	return &rf->codec_stats;
#else
	return NULL;
#endif
}


const struct reflow_stats *reflow_stats_get(const struct reflow *rf)
{
	return rf ? &rf->rf_stats : NULL;
}

int32_t reflow_get_media_time(const struct reflow *rf)
{
	if (!rf)
		return -1;
    
	int dur_rx = (int)(rf->stat.rx.ts_last - rf->stat.rx.ts_first);
    
	return dur_rx;
}

void reflow_set_local_eoc(struct reflow *rf)
{
	if (!rf)
		return;

	rf->ice_local_eoc = true;
	sdp_media_set_lattr(rf->audio.sdpm, true, "end-of-candidates", NULL);
}


bool reflow_have_eoc(const struct reflow *rf)
{
	if (!rf)
		return false;

	return rf->ice_local_eoc && rf->ice_remote_eoc;
}


void reflow_enable_privacy(struct reflow *rf, bool enabled)
{
	if (!rf)
		return;

	rf->privacy_mode = enabled;

	trice_conf(rf->trice)->enable_prflx = !enabled;
}


void reflow_enable_group_mode(struct reflow *rf, bool enabled)
{
	if (!rf)
		return;

	rf->group_mode = enabled;

	if (rf->group_mode) {
		sdp_media_set_lattr(rf->audio.sdpm, true, "ptime", "%u", GROUP_PTIME);
	}
	else {
		sdp_media_del_lattr(rf->audio.sdpm, "ptime");
	}
}


const char *reflow_lcand_name(const struct reflow *rf)
{
	struct ice_lcand *lcand;

	if (!rf)
		return NULL;

	if (!rf->sel_pair)
		return "???";

	lcand = rf->sel_pair->lcand;

	if (lcand)
		return ice_cand_type2name(lcand->attr.type);
	else
		return "???";
}


const char *reflow_rcand_name(const struct reflow *rf)
{
	if (!rf)
		return NULL;

	if (!rf->sel_pair)
		return "???";

	return ice_cand_type2name(rf->sel_pair->rcand->attr.type);
}


struct dce *reflow_get_dce(const struct reflow *rf)
{
	if (!rf || !rf->data.dce)
		return NULL;
    
	return rf->data.dce;
}


uint32_t reflow_candc(const struct reflow *rf, bool local,
			 enum ice_cand_type typ)
{
	struct list *lst;
	struct le *le;
	uint32_t n = 0;

	lst = local ? trice_lcandl(rf->trice) : trice_rcandl(rf->trice);

	for (le = list_head(lst);le;le=le->next) {
		struct ice_cand_attr *cand = le->data;

		if (typ == cand->type)
			++n;
	}

	return n;
}

void reflow_set_audio_cbr(struct iflow *iflow, bool enabled)
{
	struct reflow *rf = (struct reflow*)iflow;
	struct le *le;
	
	if (!rf)
		return;

	info("reflow(%p): set_audio_cbr: enabled=%d\n", rf, enabled);
	
	/* If CBR is already set, do not reset mid-call */
	if (!rf->audio.local_cbr)
		rf->audio.local_cbr = enabled;

	LIST_FOREACH(&rf->audio.formatl, le) {
		struct auformat *af = le->data;
		const char *fmtp = rf->audio.local_cbr ? af->ac->fmtp_cbr
			                               : af->ac->fmtp;

		info("reflow(%p): set_audio_cbr: %s\n", rf, fmtp);

		sdp_format_set_params(af->fmt, "%s", fmtp);
	}
}

bool reflow_get_audio_cbr(const struct iflow *iflow, bool local)
{
	struct reflow *rf = (struct reflow*)iflow;
	if (!rf)
		return false;
    
	return local ? rf->audio.local_cbr : rf->audio.remote_cbr;
}


/* NOTE: Remote clientid can only be set once. */
int reflow_set_remote_userclientid(struct iflow *iflow,
				   const char *userid,
				   const char *clientid) 
{
	struct reflow *rf = (struct reflow*)iflow;
	int err = 0;

	if (!rf || !str_isset(clientid) || !str_isset(userid))
		return EINVAL;

	if (str_isset(rf->userid_remote)) {
		warning("reflow(%p):: remote userid is already set\n", rf);
		return EALREADY;
	}

	if (str_isset(rf->clientid_remote)) {
		warning("reflow(%p): remote clientid is already set\n", rf);
		return EALREADY;
	}

	err = str_dup(&rf->userid_remote, userid);
	if (err) {
		goto out;
	}

	err =  str_dup(&rf->clientid_remote, clientid);
	if (err) {
		goto out;
	}

out:
	if (err) {
		rf->userid_remote = mem_deref(rf->userid_remote);
		rf->clientid_remote = mem_deref(rf->clientid_remote);
	}

	return err;
}


struct ice_candpair *reflow_selected_pair(const struct reflow *rf)
{
	return rf ? rf->sel_pair : NULL;
}


enum ice_role reflow_local_role(const struct reflow *rf)
{
	if (!rf)
		return ICE_ROLE_UNKNOWN;

	return trice_local_role(rf->trice);
}


void reflow_video_set_disabled(struct reflow *rf, bool dis)
{
	if (!rf)
		return;

	rf->video.disabled = dis;
	sdp_media_set_disabled(rf->video.sdpm, dis);
}


static void gather_turn(struct reflow *rf,
			struct turn_conn *tc,
			const struct sa *srv,
			const char *username,
			const char *password,
			int proto,
			bool secure)
{
	int err = 0;
	
	switch (proto) {
	case IPPROTO_UDP:
		if (secure) {
			warning("reflow(%p): secure UDP not supported\n",
				rf);
		}
		err = reflow_gather_turn(rf, tc, srv, username, password);
		if (err) {
			warning("reflow(%p): gather_turn: failed (%m)\n",
				rf, err);
			goto out;
		}
		break;

	case IPPROTO_TCP:
		err = reflow_gather_turn_tcp(rf, tc, srv,
					     username, password,
					     secure);
		if (err) {
			warning("reflow(%p): gather_turn_tcp: failed (%m)\n",
				rf, err);
			goto out;
		}
		break;

	default:
		warning("reflow(%p): unknown protocol (%d)\n",
			rf, proto);
		break;
	}

 out:
	return;
}

static void turnconn_ready_handler(struct turn_conn *tc,
				   const struct sa *srv,
				   const char *username,
				   const char *password,
				   int proto,
				   bool secure,
				   void *arg)
{
	struct reflow *rf = arg;

	gather_turn(rf, tc, srv, username, password, proto, secure);
}

int reflow_add_turnserver(struct iflow *iflow,
			  const char *url,
			  const char *username,
			  const char *password)
{
	struct reflow *rf = (struct reflow*)iflow;
	struct zapi_ice_server *turn;

	if (!rf || !url)
		return EINVAL;

	if (rf->turnc >= ARRAY_SIZE(rf->turnv))
		return EOVERFLOW;

	info("reflow(%p): adding turn: %s\n", rf, url);
	
	turn = &rf->turnv[rf->turnc];
	str_ncpy(turn->url, url, sizeof(turn->url));
	str_ncpy(turn->username, username, sizeof(turn->username));
	str_ncpy(turn->credential, password, sizeof(turn->credential));
	++rf->turnc;

	return 0;
}


static bool exist_ifl(struct list *ifl, const char *name)
{
	bool found = false;
	struct le *le;

	for(le = ifl->head; le && !found; le = le->next) {
		struct avs_service_ifentry *ife = le->data;
		
		found = streq(ife->name, name);
	}

	return found;
}

static bool interface_handler(const char *ifname, const struct sa *sa,
			      void *arg)
{
	struct reflow *rf = arg;
	struct ice_lcand *lcand = NULL;
	struct interface *ifc;
	const uint16_t lpref = calc_local_preference(ifname, sa_af(sa));
	const uint32_t prio = ice_cand_calc_prio(ICE_CAND_TYPE_HOST, lpref, 1);
	struct list *ifl;
	int err = 0;

	/* Skip loopback and link-local addresses */
	if (sa_is_loopback(sa) || sa_is_linklocal(sa))
		return false;

	ifl = avs_service_iflist();
	if (ifl) {
		if (!exist_ifl(ifl, ifname))
			return false;
	}
	
	RFLOG(LOG_LEVEL_INFO,
	      "adding local candidate interface: %s:%j\n",
	      rf, ifname, sa);


	if (!sa_isset(sa, SA_ADDR)) {
		RFLOG(LOG_LEVEL_WARN, "address not set\n", rf);
		err =  EINVAL;
		goto out;
	}
	if (sa_port(sa)) {
		RFLOG(LOG_LEVEL_WARN, "port should not be set\n", rf);
		err =  EINVAL;
		goto out;
	}
	

	RFLOG(LOG_LEVEL_INFO, 
	      "%s:%j  (lpref=0x%04x prio=0x%08x)\n",
	      rf, ifname, sa, lpref, prio);
	
	ifc = interface_find(&rf->interfacel, sa);
	if (ifc) {
		RFLOG(LOG_LEVEL_INFO,
		      "interface: %s already added\n", rf, ifc->ifname);
		return 0;
	}

	//if (!rf->privacy_mode) {
	{
		err = trice_lcand_add(&lcand, rf->trice,
				      ICE_COMPID_RTP,
				      IPPROTO_UDP, prio, sa, NULL,
				      ICE_CAND_TYPE_HOST, NULL,
				      0,     /* tcptype */
				      NULL,  /* sock */
				      0);
		if (err) {
			RFLOG(LOG_LEVEL_WARN,
			      "local_host[%j] failed (%m)\n",
			      rf, sa, err);
			return err;
		}

		/* hijack the UDP-socket of the local candidate
		 *
		 * NOTE: this must be done for all local candidates
		 */
		udp_handler_set(lcand->us, trice_udp_recv_handler, rf);

		if (sa_isset(&rf->media_laddr, SA_ADDR)) {
			struct ice_cand_attr mcand =
				*(struct ice_cand_attr *)lcand;
			uint16_t port;

			port = sa_port(&mcand.addr);
			sa_cpy(&mcand.addr, &rf->media_laddr);
			sa_set_port(&mcand.addr, port);
			err = sdp_media_set_lattr(rf->audio.sdpm, false,
						  "candidate",
						  "%H",
						  ice_cand_attr_encode,
						  &mcand);
		}
		else {
			err = sdp_media_set_lattr(rf->audio.sdpm, false,
						  "candidate",
						  "%H",
						  ice_cand_attr_encode, lcand);
		}
		if (err)
			goto out;

		if (ifname) {
			str_ncpy(lcand->ifname, ifname,
				 sizeof(lcand->ifname));
		}

		udp_sockbuf_set(lcand->us, UDP_SOCKBUF_SIZE);
	}

	err = interface_add(rf, lcand, ifname, sa);
	if (err)
		return err;

out:
	if (err) {
		RFLOG(LOG_LEVEL_WARN,
		      "failed to add candidate %s:%j (%m)\n",
		      rf, ifname, sa, err);
		return false;
	}

	return false;
}

int reflow_gather_all_turn(struct iflow *iflow, bool offer)
{
	struct reflow *rf = (struct reflow*)iflow;
	size_t i;
	(void)offer;
	
	if (!rf)
		return EINVAL;
	
	for (i = 0; i < rf->turnc; ++i) {
		struct zapi_ice_server *turn;
		struct turn_conn *tc;
		int err;

		turn = &rf->turnv[i];

		err = turnconn_alloc(&tc, &rf->turnconnl,
				     turn,
				     turnconn_ready_handler,
				     turnconn_estab_handler,
				     turnconn_data_handler,
				     turnconn_error_handler,
				     rf);
		if (err != EAGAIN) {
			warning("reflow(%p): turnconn alloc failed: %m\n",
				rf, err);
		}
	}

	net_if_apply(interface_handler, rf);
	if (rf->turnc == 0 && list_count(&rf->interfacel) > 0) {
		IFLOW_CALL_CB(rf->iflow, gatherh, rf->iflow.arg);
	}

	return 0;
}


void reflow_set_call_type(struct iflow *iflow,
			  enum icall_call_type call_type)
{
	struct reflow *rf = (struct reflow*)iflow;

	rf->call_type = call_type;
}

void reflow_close(struct iflow *iflow)
{
	struct reflow *rf = (struct reflow *)iflow;

	info("reflow(%p): close\n", rf);

	rf->closed = true;
	if (g_reflow.mediaflow.closeh) {
		g_reflow.mediaflow.closeh(rf->mf, rf->extarg);
	}

	mem_deref(iflow);
}

static const char *cipherv[] = {

	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES256-GCM-SHA384",

};


static int init_dtls(struct tls **dtlsp)
{
	int err;
	struct tls *dtls;

	err = tls_alloc(&dtls, TLS_METHOD_DTLS, NULL, NULL);
	if (err) {
		warning("reflow: failed to create DTLS context (%m)\n",
			err);
		goto out;
	}

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
			   "SRTP_AEAD_AES_128_GCM:"
			   "SRTP_AES128_CM_SHA1_80");
	if (err) {
		warning("flowmgr: failed to enable SRTP profile (%m)\n",
			err);
		goto out;
	}

	*dtlsp = dtls;

out:
	if (err) {
		mem_deref(dtls);
	}
	return err;
}

static char fmtp_no_cbr[] = "stereo=0;sprop-stereo=0;useinbandfec=1";
static char fmtp_cbr[] = "stereo=0;sprop-stereo=0;useinbandfec=1;cbr=1";

const char *audio_exts[] = {"urn:ietf:params:rtp-hdrext:ssrc-audio-level",
			    NULL};

static struct aucodec opus = {
	.pt         = "111",
	.name       = "opus",
	.srate      = 48000,
	.ch         = 2,
	.fmtp       = fmtp_no_cbr,
	.fmtp_cbr   = fmtp_cbr,
	.extensions = audio_exts,
};

const char *video_exts[] = {"http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
			    NULL};

static struct vidcodec vp8 = {
	.pt         = "100",
	.name       = "VP8",
	.variant    = NULL,
	.fmtp       = NULL,
	.extensions = video_exts,
};

static void mf_set_handlers(mediaflow_alloc_h *alloch,
			    mediaflow_close_h *closeh,
			    mediaflow_recv_data_h *rtph,
			    mediaflow_recv_data_h *rtcph,
			    mediaflow_recv_dc_h *dch)
{
	g_reflow.mediaflow.alloch = alloch;
	g_reflow.mediaflow.closeh = closeh;
	g_reflow.mediaflow.recv_rtph = rtph;
	g_reflow.mediaflow.recv_rtcph = rtcph;
	g_reflow.mediaflow.recv_dch = dch;
}

static int module_init(void)
{
	int err = 0;

	list_append(&g_reflow.aucodecl, &opus.le, &opus);
	list_append(&g_reflow.vidcodecl, &vp8.le, &vp8);
	
	info("reflow_init: setting flow to reflow\n");
	if (g_reflow.initialized)
		return EALREADY;
/*
	iflow_register_statics(reflow_destroy,
			       reflow_set_mute,
			       reflow_get_mute);
*/

	err = init_dtls(&g_reflow.dtls);
	if (err) {
		goto out;
	}

	iflow_set_alloc(reflow_alloc);
	mediapump_register(&g_reflow.mediaflow.mp, "reflow",
			   mf_set_handlers,
			   mf_assign_worker,			   
			   mf_assign_streams,
			   mf_send_rtp,
			   mf_send_rtcp,
			   mf_send_dc,
			   mf_get_ssrc,
			   mf_remove_ssrc);
			   
	dns_init(NULL);
	dce_init();
	g_reflow.initialized = true;

out:
	return err;
}

static int module_close(void)
{
	struct le *le;
	
	info("reflow: module closing...\n");

	g_reflow.dtls = mem_deref(g_reflow.dtls);

	le = g_reflow.rfl.head;
	while(le) {
		struct reflow *rf = le->data;
		le = le->next;
		IFLOW_CALL_CB(rf->iflow, closeh,
			      EINTR, rf->iflow.arg);
	}

	g_reflow.mediaflow.mp = mem_deref(g_reflow.mediaflow.mp);
	dce_close();
	dns_close();
	g_reflow.initialized = false;
	
	return 0;
}

EXPORT_SYM const struct mod_export DECL_EXPORTS(reflow) = {
	"reflow",
	"mediaflow",
	module_init,
	module_close,
};
