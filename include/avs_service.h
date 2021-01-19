/*
 * Wire
 * Copyright (C) 2020 Wire Swiss GmbH
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
/*
 * HTTP Server
 */
struct http_conn;
typedef void (httpd_req_h)(struct http_conn *conn,
			   const struct http_msg *msg,
			   void *arg);
	
struct httpd;
	
struct httpd_url {
	const char *path;
	bool auth;
	
	httpd_req_h *reqh;
	void *arg;

	struct le le;
};

void httpd_url_register(struct httpd *httpd, struct httpd_url *url);
void httpd_url_unregister(struct httpd *httpd, struct httpd_url *url);
int  httpd_alloc(struct httpd **httpdp, struct sa *laddr,
		 httpd_req_h *reqh, void *arg);


/*
 * Modules
 */

#ifdef STATIC
#define DECL_EXPORTS(name) exports_ ##name
#else
#define DECL_EXPORTS(name) exports
#endif

int module_load(const char *name);

/* Mediaflow */

struct mediapump;
/* Each mediapump should implement this */
struct mediaflow {
	struct mediapump *mp;
	void *flow;
};

/* Functions implementig mediaflows should use these functions */
typedef void (mediaflow_alloc_h) (struct mediaflow *mf, void *arg);
typedef void (mediaflow_close_h) (struct mediaflow *mf, void *arg);
typedef int  (mediaflow_send_data_h)(struct mediaflow *mf,
				     const uint8_t *buf, size_t len);
typedef int  (mediaflow_send_dc_h)(struct mediaflow *mf,
				   const uint8_t *buf, size_t len);
typedef uint32_t (mediaflow_get_ssrc_h) (struct mediaflow *mf,
					 const char *type, bool local);
typedef void (mediaflow_remove_ssrc_h)(struct mediaflow *mf, uint32_t ssrc);

typedef void (mediaflow_recv_data_h)(const uint8_t *data, size_t len,
				     void *arg);
typedef void (mediaflow_recv_dc_h)(const uint8_t *data, size_t len,
				   void *arg);
typedef void (mediapump_set_handlers_h)(mediaflow_alloc_h *alloch,
					mediaflow_close_h *closeh,
					mediaflow_recv_data_h *rtph,
					mediaflow_recv_data_h *rtcph,
					mediaflow_recv_dc_h *dch);


int mediapump_register(struct mediapump **mpp,
		       const char *name,
		       mediapump_set_handlers_h *set_handlers,
		       mediaflow_send_data_h *rtph,
		       mediaflow_send_data_h *rtcph,
		       mediaflow_send_dc_h *dch,
		       mediaflow_get_ssrc_h *get_ssrch,
		       mediaflow_remove_ssrc_h *remove_ssrch);

/* Users of mediaflows should use these functions */
					
struct mediapump *mediapump_get(const char *name);
int mediapump_set_handlers(struct mediapump *mp,
			   mediaflow_alloc_h *alloch,
			   mediaflow_close_h *closeh,
			   mediaflow_recv_data_h *rtph,
			   mediaflow_recv_data_h *rtcph,
			   mediaflow_recv_dc_h *dch);
int mediaflow_send_rtp(struct mediaflow *mf,
		       const uint8_t *data, size_t len);
int mediaflow_send_rtcp(struct mediaflow *mf,
		       const uint8_t *data, size_t len);
int mediaflow_send_dc(struct mediaflow *mf,
		      const uint8_t *data, size_t len);
uint32_t mediaflow_get_ssrc(struct mediaflow *mf, const char *type, bool local);
void mediapump_remove_ssrc(struct mediaflow *mf, uint32_t ssrc);


struct sa  *avs_service_req_addr(void);
struct sa  *avs_service_media_addr(void);
struct sa  *avs_service_metrics_addr(void);
const char *avs_service_url(void);
const char *avs_service_blacklist(void);

/*
 * Config
 */

void config_set_file(const char *path);
void config_set_buf(const char *str);
int  config_init(void);
void config_close(void);
struct conf *avs_service_conf(void);
