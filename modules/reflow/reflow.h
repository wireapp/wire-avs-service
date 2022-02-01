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


/*
 * Mediaflow
 */

struct reflow;
struct zapi_candidate;
struct aucodec_stats;
struct rtp_stats;

enum media_pt {
	MEDIA_PT_DYNAMIC_START =  96,
	MEDIA_PT_DYNAMIC_END   = 127,

	/* custom range of Payload-types for audio/video,
	   to properly support Bundle multiplexing */
	MEDIA_PT_AUDIO_START =  96,
	MEDIA_PT_AUDIO_END   =  99,
	MEDIA_PT_VIDEO_START = 100,
	MEDIA_PT_VIDEO_END   = 110,
};

enum media_crypto {
	CRYPTO_NONE      = 0,
	CRYPTO_DTLS_SRTP = 1<<0,
};

/* only valid for DTLS-SRTP */
enum media_setup {
	SETUP_ACTPASS,
	SETUP_ACTIVE,
	SETUP_PASSIVE
};

enum media_type {
	MEDIA_AUDIO = 0,
	MEDIA_VIDEO = 1,
	MEDIA_VIDEO_RTX = 2,
	/* sep */
	MEDIA_NUM = 3,
};

/*
 * Mediaflow statistics in [ms]
 *
 * -2  error
 * -1  init
 */
struct reflow_stats {
	int32_t turn_alloc;
	int32_t nat_estab;
	int32_t dtls_estab;
	int32_t dce_estab;

	unsigned dtls_pkt_sent;
	unsigned dtls_pkt_recv;
};


int reflow_alloc(struct iflow		**flowp,
		 const char		*convid,
		 const char		*userid_self,
		 const char		*clientid_self,
		 enum icall_conv_type	conv_type,
		 enum icall_call_type	call_type,
		 enum icall_vstate	vstate,
		 void			*extarg);

int reflow_add_turn_server(struct iflow *iflow,
			      struct zapi_ice_server *turn);
int reflow_set_setup(struct reflow *rf, enum media_setup setup);
bool reflow_is_sdp_offerer(const struct reflow *rf);
enum media_setup reflow_local_setup(const struct reflow *rf);

int reflow_disable_audio(struct reflow *rf);
int reflow_add_video(struct reflow *rf, struct list *vidcodecl);
int reflow_add_data(struct reflow *rf);

int reflow_start_ice(struct reflow *rf);

int reflow_start_media(struct reflow *rf);
void reflow_stop_media(struct iflow *iflow);
void reflow_reset_media(struct reflow *rf);


int reflow_set_video_state(struct iflow *iflow,
			   enum icall_vstate vstate);

void reflow_set_tag(struct reflow *rf, const char *tag);
int reflow_add_local_host_candidate(struct reflow *rf,
				       const char *ifname,
				       const struct sa *addr);
int reflow_generate_offer(struct iflow *iflow, char *sdp, size_t sz);
int reflow_generate_answer(struct iflow *iflow, char *sdp, size_t sz);
int reflow_handle_offer(struct iflow *iflow, const char *sdp);
int reflow_handle_answer(struct iflow *iflow, const char *sdp);
int reflow_offeranswer(struct reflow *rf,
			  char *answer, size_t answer_sz,
			  const char *offer);
void reflow_sdpstate_reset(struct reflow *rf);
int reflow_send_rtp(struct reflow *rf, const struct rtp_header *hdr,
		       const uint8_t *pld, size_t pldlen);
int reflow_send_raw_rtp(struct reflow *rf,
			   const uint8_t *buf, size_t len);
int reflow_send_raw_rtcp(struct reflow *rf,
			    const uint8_t *buf, size_t len);
bool reflow_is_ready(const struct reflow *rf);
int reflow_gather_stun(struct reflow *rf, const struct sa *stun_srv);
struct turn_conn;
int reflow_gather_turn(struct reflow *rf,
		       struct turn_conn *tc,
		       const struct sa *turn_srv,
		       const char *username, const char *password);
int reflow_gather_turn_tcp(struct reflow *rf,
			   struct turn_conn *tc,
			   const struct sa *turn_srv,
			   const char *username, const char *password,
			   bool secure);
size_t reflow_remote_cand_count(const struct reflow *rf);
int reflow_summary(struct re_printf *pf, const struct reflow *rf);
int reflow_rtp_summary(struct re_printf *pf, const struct reflow *rf);
void reflow_set_fallback_crypto(struct reflow *rf, enum media_crypto cry);
enum media_crypto reflow_crypto(const struct reflow *rf);

struct auenc_state *reflow_encoder(const struct reflow *rf);
struct audec_state *reflow_decoder(const struct reflow *rf);
int reflow_debug(struct re_printf *pf, const struct iflow *iflow);

const char *reflow_peer_software(const struct reflow *rf);

bool reflow_has_video(const struct iflow *iflow);
bool reflow_is_sending_video(struct reflow *rf);
int  reflow_video_debug(struct re_printf *pf, const struct reflow *rf);

struct videnc_state *reflow_video_encoder(const struct reflow *rf);
struct viddec_state *reflow_video_decoder(const struct reflow *rf);

bool reflow_has_data(const struct reflow *rf);

const struct tls_conn *reflow_dtls_connection(const struct reflow *rf);

bool reflow_is_started(const struct reflow *rf);

bool reflow_got_sdp(const struct reflow *rf);
bool reflow_sdp_is_complete(const struct reflow *rf);
bool reflow_is_gathered(const struct iflow *iflow);

uint32_t reflow_get_local_ssrc(struct reflow *rf, enum media_type type);
int reflow_get_remote_ssrc(const struct reflow *rf,
			      enum media_type type, uint32_t *ssrcp);

bool reflow_dtls_ready(const struct reflow *rf);
bool reflow_ice_ready(const struct reflow *rf);
bool reflow_is_rtpstarted(const struct reflow *rf);
int  reflow_cryptos_print(struct re_printf *pf, enum media_crypto cryptos);
const char *reflow_setup_name(enum media_setup setup);


const struct rtp_stats* reflow_rcv_audio_rtp_stats(const struct reflow *rf);
const struct rtp_stats* reflow_snd_audio_rtp_stats(const struct reflow *rf);
const struct rtp_stats* reflow_rcv_video_rtp_stats(const struct reflow *rf);
const struct rtp_stats* reflow_snd_video_rtp_stats(const struct reflow *rf);
struct aucodec_stats* reflow_codec_stats(struct reflow *rf);
int32_t reflow_get_media_time(const struct reflow *rf);

int reflow_hold_media(struct reflow *rf, bool hold);

const struct reflow_stats *reflow_stats_get(const struct reflow *rf);

void reflow_set_local_eoc(struct reflow *rf);
bool reflow_have_eoc(const struct reflow *rf);
void reflow_enable_privacy(struct reflow *rf, bool enabled);
void reflow_enable_group_mode(struct reflow *rf, bool enabled);

const char *reflow_lcand_name(const struct reflow *rf);
const char *reflow_rcand_name(const struct reflow *rf);
bool reflow_dtls_peer_isset(const struct reflow *rf);

struct dce *reflow_get_dce(const struct reflow *rf);

uint32_t reflow_candc(const struct reflow *rf, bool local,
			 enum ice_cand_type typ);
bool reflow_get_audio_cbr(const struct iflow *iflow, bool local);
void reflow_set_audio_cbr(struct iflow *iflow, bool enabled);
int reflow_set_remote_userclientid(struct iflow *iflow,
				      const char *userid, const char *clientid);
void reflow_set_ice_role(struct reflow *rf, enum ice_role role);
struct ice_candpair *reflow_selected_pair(const struct reflow *rf);
enum ice_role reflow_local_role(const struct reflow *rf);
int reflow_print_ice(struct re_printf *pf, const struct reflow *rf);

int reflow_set_extcodec(struct reflow *rf, void *arg);
void reflow_video_set_disabled(struct reflow *rf, bool dis);

int reflow_add_turnserver(struct iflow *iflow,
			  const char *url,
			  const char *username,
			  const char *password);
int reflow_gather_all_turn(struct iflow *iflow, bool offer);

void reflow_set_call_type(struct iflow *iflow,
			  enum icall_call_type call_type);

void reflow_close(struct iflow *iflow);

int reflow_init(void);

int reflow_init_with_codecs(struct list *aucodecl,
			    struct list *vidcodecl);


