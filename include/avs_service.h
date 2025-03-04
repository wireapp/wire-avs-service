#define MAX_OPEN_FILES 1048576


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



struct sa  *avs_service_req_addr(void);
struct sa  *avs_service_media_addr(void);
struct sa  *avs_service_alt_media_addr(void);

/* Member of iflist */
struct avs_service_ifentry {
	struct sa sa;
	char *name;

	struct le le;
};
struct list  *avs_service_iflist(void);

struct sa  *avs_service_metrics_addr(void);
struct sa  *avs_service_sft_req_addr(void);
const char *avs_service_url(void);

const char *avs_service_blacklist(void);
bool avs_service_use_turn(void);
bool avs_service_use_sft_turn(void);
bool avs_service_use_auth(void);

struct dnsc *avs_service_dnsc(void);
const char *avs_service_federation_url(void);

const char *avs_service_turn_url(void);
const char *avs_service_secret_path(void);

const struct pl *avs_service_secret(void);

bool avs_service_is_draining(void);
void avs_service_terminate(void);

typedef bool (avs_service_shutdown_h) (void *arg);
void avs_service_register_shutdown_handler(avs_service_shutdown_h *shuth, void *arg);


/*
 * Config
 */

void config_set_file(const char *path);
void config_set_buf(const char *str);
int  config_init(void);
void config_close(void);
struct conf *avs_service_conf(void);
int avs_service_worker_count(void);
uint64_t avs_service_fir_timeout(void);

/*
 * Workers
 */

struct worker;
struct worker_task;

enum worker_task_id {
        WORKER_TASK_RUN = 1,
	WORKER_TASK_QUIT = 2,

	/* Tasks for main queue */
	WORKER_TASK_DEREF = 100,

	/* Dispatch function */
	WORKER_TASK_DISPATCH = 200,
};


typedef int (worker_task_h)(void *arg);

int worker_init(void);
void worker_close(void);

struct worker *worker_get(const char *id);
struct worker *worker_main(void);
int worker_assign_task(struct worker *worker,
		       worker_task_h *taskh,
		       void *arg);
int worker_assign_main(worker_task_h *taskh, void *arg);
void *worker_tid(struct worker *w);

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
typedef void (mediaflow_assign_worker_h) (struct mediaflow *mf, struct worker *w);
typedef int  (mediaflow_send_data_h)(struct mediaflow *mf,
				     const uint8_t *buf, size_t len);
typedef int  (mediaflow_send_dc_h)(struct mediaflow *mf,
				   const uint8_t *buf, size_t len);
typedef uint32_t (mediaflow_get_ssrc_h) (struct mediaflow *mf,
					 const char *type, bool local);
typedef void (mediaflow_remove_ssrc_h)(struct mediaflow *mf, uint32_t ssrc);

typedef void (mediaflow_recv_data_h)(struct mbuf *mb, void *arg);
typedef void (mediaflow_recv_dc_h)(struct mbuf *mb, void *arg);
typedef int  (mediaflow_assign_streams_h)(struct mediaflow *mf,
					  uint32_t **assrcv,
					  int assrcc,
					  uint32_t **vssrcv,
					  uint32_t **rtx_ssrcv,
					  int vssrcc);
typedef void (mediapump_set_handlers_h)(mediaflow_alloc_h *alloch,
					mediaflow_close_h *closeh,
					mediaflow_recv_data_h *rtph,
					mediaflow_recv_data_h *rtcph,
					mediaflow_recv_dc_h *dch);


int mediapump_register(struct mediapump **mpp,
		       const char *name,
		       mediapump_set_handlers_h *set_handlersh,
		       mediaflow_assign_worker_h *assign_workerh,
		       mediaflow_assign_streams_h *assign_streamsh,
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
void mediaflow_assign_worker(struct mediaflow *mf, struct worker *w);
int mediaflow_assign_streams(struct mediaflow *mf,
			     uint32_t **assrcv,
			     int assrcc,
			     uint32_t **vssrcv,
			     uint32_t **rtx_ssrcv,
			     int vssrcc);
int mediaflow_send_rtp(struct mediaflow *mf,
		       const uint8_t *data, size_t len);
int mediaflow_send_rtcp(struct mediaflow *mf,
		       const uint8_t *data, size_t len);
int mediaflow_send_dc(struct mediaflow *mf,
		      const uint8_t *data, size_t len);
uint32_t mediaflow_get_ssrc(struct mediaflow *mf, const char *type, bool local);
void mediapump_remove_ssrc(struct mediaflow *mf, uint32_t ssrc);


/* Protocol stack layers (order is important) */
enum {
	/*LAYER_RTP  =  40,*/
	LAYER_DTLS =  20,       /* must be above zero */
	LAYER_DTLS_TRANSPORT = 15,  /* below DTLS */
	LAYER_SRTP =  10,       /* must be below RTP */
	LAYER_ICE  = -10,
	LAYER_TURN = -20,       /* must be below ICE */
	LAYER_STUN = -30,       /* must be below TURN */
};

/* ZREST */
enum zrest_state {
	ZREST_OK,
	ZREST_JOIN,
	ZREST_EXPIRED,
	ZREST_UNAUTHORIZED,
	ZREST_ERROR,
};

int zrest_get_password(char *pass, size_t *passlen, const char *user,
		       const char *secret, size_t sec_len);
void zrest_generate_sft_username(char *user, size_t sz);
enum zrest_state zrest_authenticate(const char *user, const char *credential);

