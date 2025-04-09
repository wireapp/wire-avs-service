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

#define NUM_WORKERS 16
#define TIMEOUT_FIR 1000


/* Global Context */
struct avs_service {
	time_t start_time;

	struct sa req_addr;
	struct sa media_addr;
	struct sa sft_req_addr;
	struct sa alt_media_addr;
	struct sa mediaif_addr;
	struct sa metrics_addr;

	char url[256];
	char federation_url[256];
	char sft_req_url[256];
	char blacklist[256];
	bool direct_federation;

	struct list ifl;

	struct {
		char url[256];
		char secret_path[256];
	} turn;

	struct {
		char *prefix;
		char path[256];
		FILE *fp;
	} log;

	int worker_count;
	uint64_t fir_timeout;	
	bool use_turn;
	bool use_auth;
	bool is_draining;
	struct pl secret;

	struct dnsc *dnsc;
	struct {
		bool enabled;
		int nprocs;
		bool main;
		struct sa *req_addr;
		struct sa *metrics_addr;
		struct sa *sft_addr;
	} lb;

	struct list shuthl;
};

static struct avs_service avsd = {
       .worker_count = NUM_WORKERS,
       .use_turn = false,
       .use_auth = false,
       .secret = PL_INIT,
       .dnsc = NULL,
       .direct_federation = false,

       /* lb */
       .lb.enabled = false,
       .lb.nprocs = 0,
       .lb.main = false,
       .lb.req_addr = NULL,
       .lb.metrics_addr = NULL,
       .lb.sft_addr = NULL,
};


struct shutdown_entry {
	avs_service_shutdown_h *shuth;
	void *arg;

	struct le le;
};

#define LOCALHOST_IPV4 "127.0.0.1"

#define DEFAULT_REQ_ADDR "127.0.0.1"
#define DEFAULT_REQ_PORT 8585

#define DEFAULT_METRICS_ADDR "127.0.0.1"
#define DEFAULT_METRICS_PORT 49090

#define DEFAULT_SFT_REQ_ADDR "127.0.0.1"
#define DEFAULT_SFT_REQ_PORT 9999

#define DEFAULT_MEDIA_ADDR "127.0.0.1"


static void usage(void)
{
	(void)re_fprintf(stderr,
			 "usage: sftd [-a] [-I <addr>] [-p <port>] [-A <addr>] [-M <addr>] [-r <port>] "
			 "[-u <URL>] [-b <blacklist> [-d] [-n <nprocs>] [-l <prefix>] [-q] [-w <count>] "
			 "[-B <addr>] -T -t <URL> -s <path> -x <addr:port>\n");
	(void)re_fprintf(stderr, "\t-a              Force authorization\n"),
	(void)re_fprintf(stderr, "\t-I <addr>       Address for HTTP requests (default: %s)\n",
			 DEFAULT_REQ_ADDR);
	(void)re_fprintf(stderr, "\t-p <port>       Port for HTTP requests (default: %d)\n",
			 DEFAULT_REQ_PORT);
	(void)re_fprintf(stderr, "\t-A <addr>       Address for media (default: same as request address)\n");
	(void)re_fprintf(stderr, "\t-M <addr>       Address for metrics requests (default: %s)\n",
			 DEFAULT_METRICS_ADDR);
	(void)re_fprintf(stderr, "\t-r <port>       Port for metrics requests (default: %d)\n",
			 DEFAULT_METRICS_PORT);
	(void)re_fprintf(stderr, "\t-u <URL>        URL to use in responses\n");
	(void)re_fprintf(stderr, "\t-O <iflist>     Comma seperated list of interface names for media\n"
			         "\t\t\t Example: eth0,eth1\n");
	(void)re_fprintf(stderr, "\t-b <blacklist>  Comma seperated client version blacklist\n"
			         "\t\t\t Example: <6.2.9,6.2.11\n");
	(void)re_fprintf(stderr, "\t-l <prefix>     Log to file with prefix\n");
	(void)re_fprintf(stderr, "\t-q              Quiet (less-verbose logging)\n");
	(void)re_fprintf(stderr, "\t-T              Use TURN servers when gathering\n");
	(void)re_fprintf(stderr, "\t-t <url>        Multi SFT TURN URL\n");
	(void)re_fprintf(stderr, "\t-s <path>       Path to shared secrets file\n");
	(void)re_fprintf(stderr, "\t-w <count>      Worker count (default: %d)\n", NUM_WORKERS);
	(void)re_fprintf(stderr, "\t-d              Spawn SFT processes\n");
	(void)re_fprintf(stderr, "\t-n <nprocs>     Used together with -d and indicates # of processes to spawn "
			 "(default: # of cores)\n");
	(void)re_fprintf(stderr, "\t-x <addr:port>  Address tuple for listening to federation SFT requests\n");
	(void)re_fprintf(stderr, "\t-B <addr>       Alternate media address\n");
}

static void signal_handler(int sig)
{
	static bool term = false;
	(void)sig;

	switch(sig) {
	case SIGUSR1:
		mem_debug();
		return;

	case SIGTERM: {
		bool can_shutdown = true;
		struct le *le;
		
		avsd.is_draining = true;

		for(le = avsd.shuthl.head; le && can_shutdown; le = le->next) {
			struct shutdown_entry *se = le->data;

			if (se->shuth) {
				can_shutdown = se->shuth(se->arg);
			}
		}
		if (!can_shutdown)
			return;
		
	}
		break;

	default:
		break;
	}
	
	if (term) {
		warning("Aborted.\n");
		exit(0);
	}

	term = true;

	warning("Terminating ...\n");

	avs_service_terminate();

}

static void error_handler(int err, void *arg)
{
	(void) arg;

	error("The Engine just broken: %m.\n", err);
	re_cancel();
}


static void shutdown_handler(void *arg)
{
	(void) arg;

	error("Shutting down now.\n");
	re_cancel();
}

static const char *level_prefix(enum log_level level)
{
	switch (level) {
	case LOG_LEVEL_DEBUG: return "DEBUG: ";
	case LOG_LEVEL_INFO:  return "INFO:  ";
	case LOG_LEVEL_WARN:  return "WARN:  ";
	case LOG_LEVEL_ERROR: return "ERROR: ";
	default:              return "UNKN:  ";
	}
}

static void log_handler(uint32_t level, const char *msg, void *arg)
{
	struct timeval tv;
	struct mbuf *mb;

	mb = mbuf_alloc(1024);
	if (!mb)
		return;

	if (gettimeofday(&tv, NULL) == 0) {
		struct tm  tstruct;
		uint32_t tms;
		char timebuf[64];
		const pthread_t tid = pthread_self();
		const int pid = getpid();

		memset(timebuf, 0, 64);
		tstruct = *localtime(&tv.tv_sec);
		tms = tv.tv_usec / 1000;
		strftime(timebuf, sizeof(timebuf), "%m-%d %X", &tstruct);
		mbuf_printf(mb, "%s.%03u P(%d(%s)) T(%p) %s%s",
			    timebuf, tms,
			    pid, avsd.lb.main ? "main" : "child",
			    tid,
			    level_prefix(level), msg);
	}
	else {
		mbuf_printf(mb, "%s%s", level_prefix(level), msg);
	}

	if (avsd.log.fp) {
		fwrite(mb->buf, 1, mb->end, avsd.log.fp);
		fflush(avsd.log.fp);
	}

	mem_deref(mb);
}

static struct log logh = {
	.h = log_handler
};

static int load_secret(const char *path)
 {
	 char secret[256];
	 FILE *fp;
	 int err = 0;

	 if (!path)
		 return EINVAL;
	 
	 fp = fopen(path, "ra");
	 info("sft: opening: %s fp=%p\n", path, fp);
	 if (!fp) {
		 warning("sft: failed to open secret file: %s\n", path);
		 return EBADF;
	 }
	 if (fscanf(fp, "%255s", secret) > 0) {
		 char *psec;
		 info("sft: secret %s read\n", secret);

		 err = str_dup(&psec, secret);		 
		 if (!err) {
			 avsd.secret.p = psec;
			 avsd.secret.l = str_len(secret);
		 }
	 }
	 fclose(fp);

	 return err;
 }

static void ife_destructor(void *arg)
{
	struct avs_service_ifentry *ife = arg;

	mem_deref(ife->name);
}

static void generate_iflist(struct list *ifl, const char *ifstr)
{
	char *ifactual;
	char *ifsep;
	char *vstr;
	int err;

	info("avsd: generate_iflist: %s\n", ifstr);
	err = str_dup(&ifactual, ifstr);
	if (err)
		return;

	ifsep = ifactual;
	while ((vstr = strsep(&ifsep, ",")) != NULL) {
		struct avs_service_ifentry *ife;

		ife = mem_zalloc(sizeof(*ife), ife_destructor);
		while(isspace(*vstr)) {
			++vstr;
		}
		//sa_set_str(&ife->sa, vstr, 0);
		str_dup(&ife->name, vstr);
		
		list_append(ifl, &ife->le, ife);
	}

	mem_deref(ifactual);
}


int main(int argc, char *argv[])
{
	enum log_level log_level = LOG_LEVEL_DEBUG;
	struct sa goog;
	struct sa sftsa;
	int err;
	
	(void)sys_coredump_set(true);

	memset(&avsd, 0, sizeof(avsd));

	avsd.worker_count = NUM_WORKERS;
	avsd.fir_timeout = TIMEOUT_FIR;
	avsd.log.prefix = NULL;
	avsd.log.fp = stdout;
	avsd.lb.nprocs = get_nprocs();
	avsd.log.fp = stdout;

	for (;;) {

		const int c = getopt(argc, argv, "aA:B:b:c:df:I:k:l:M:n:O:p:qr:s:Tt:u:vw:x:");
		if (0 > c)
			break;

		switch (c) {
		case 'a':
			avsd.use_auth = true;
			break;
			
		case 'A':
			sa_set_str(&avsd.media_addr, optarg, 0);
			break;

		case 'B':
			sa_set_str(&avsd.alt_media_addr, optarg, 0);
			break;

		case 'b':
			str_ncpy(avsd.blacklist, optarg,
				 sizeof(avsd.blacklist));
			break;

		case 'd':
			avsd.lb.enabled = true;
			break;

		case 'f':
			str_ncpy(avsd.federation_url, optarg,
				 sizeof(avsd.federation_url));
			break;

		case 'I':
			err = sa_set_str(&avsd.req_addr, optarg,
					 DEFAULT_REQ_PORT);
			if (err)
				goto out;
			break;

		case 'k':
			avsd.fir_timeout = (uint64_t)atoi(optarg);
			break;

		case 'l':
			str_dup(&avsd.log.prefix, optarg);
			break;

		case 'M':
			err = sa_set_str(&avsd.metrics_addr, optarg,
					 DEFAULT_METRICS_PORT);
			if (err)
				goto out;
			break;

		case 'n':
			avsd.lb.nprocs = atoi(optarg);
			break;

		case 'O':
			generate_iflist(&avsd.ifl, optarg);
			break;
			
		case 'p':
			sa_set_port(&avsd.req_addr, atoi(optarg));
			break;

		case 'q':
			log_level = LOG_LEVEL_WARN;
			break;

		case 'r':
			sa_set_port(&avsd.metrics_addr, atoi(optarg));
			break;

		case 's':
			load_secret(optarg);
			break;
			
		case 'T':
			info("avsd: using TURN\n");
			avsd.use_turn = true;
			break;

		case 't':
			str_ncpy(avsd.turn.url, optarg,
				 sizeof(avsd.turn.url));
			break;

		case 'u':
			str_ncpy(avsd.url, optarg, sizeof(avsd.url));
			break;

		case 'v':
			re_fprintf(stderr, "version: %s\n", SFT_VERSION);
			goto out;

		case 'w':
			avsd.worker_count = atoi(optarg);
			break;

		case 'x':
			str_ncpy(avsd.sft_req_url, optarg, sizeof(avsd.sft_req_url));
			break;

		default:
			err = EINVAL;
			usage();
			goto out;
		}
	}

	if (avsd.use_auth && NULL == avsd.secret.p) {
		error("sft: using auth, but no secret present. Exiting...\n");
		err = EBADF;
		goto out;
	}

	/* Request address */
	if (sa_af(&avsd.req_addr) == 0)
		sa_init(&avsd.req_addr, AF_INET);
	if (!sa_isset(&avsd.req_addr, SA_PORT)) {
		sa_set_port(&avsd.req_addr, DEFAULT_REQ_PORT);
	}	
	if (!sa_isset(&avsd.req_addr, SA_ADDR)) {
		sa_set_str(&avsd.req_addr, DEFAULT_REQ_ADDR,
			   sa_port(&avsd.req_addr));
	}
	if (str_isset(avsd.sft_req_url)) {
		struct uri uri;
		struct pl tpl = PL(avsd.sft_req_url);
		
		err = uri_decode(&uri, &tpl);
		if (err) {
			error("sft: cannot parse SFT-request URI: %s error=%m\n", avsd.sft_req_url, err);
			goto out;
		}
		sa_init(&avsd.sft_req_addr, uri.af);
		sa_set(&avsd.sft_req_addr, &uri.host, uri.port);
	}

	/* Media address */
	if (sa_af(&avsd.media_addr) == 0)
		sa_init(&avsd.media_addr, AF_INET);
	if (!sa_isset(&avsd.media_addr, SA_ADDR)) {
		sa_set_str(&avsd.media_addr, DEFAULT_MEDIA_ADDR, 0);
	}

	/* Metrics address */
	if (sa_af(&avsd.metrics_addr) == 0)
		sa_init(&avsd.metrics_addr, AF_INET);
	if (!sa_isset(&avsd.metrics_addr, SA_PORT)) {
		sa_set_port(&avsd.metrics_addr, DEFAULT_METRICS_PORT);
	}	
	if (!sa_isset(&avsd.metrics_addr, SA_ADDR)) {
		sa_set_str(&avsd.metrics_addr, DEFAULT_METRICS_ADDR,
			   sa_port(&avsd.metrics_addr));
	}

	if (!str_isset(avsd.url)) {
		re_snprintf(avsd.url, sizeof(avsd.url),
			 "http://%J", &avsd.req_addr);
	}

	err = libre_init();
	fd_setsize(0);
	fd_setsize(MAX_OPEN_FILES);	
	if (err)
		goto out;

	err = avs_init(0);
	if (err)
		goto out;

	log_set_min_level(log_level);
	log_enable_stderr(false);

	if (avsd.log.prefix) {
		char  buf[256];
		time_t     now = time(0);
		struct tm  tstruct;

		tstruct = *localtime(&now);
		strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);
		buf[13] = '-';
		buf[16] = '-';

		re_snprintf(avsd.log.path, sizeof(avsd.log.path),
			    "%s_%s.log", avsd.log.prefix, buf);

		avsd.log.fp = fopen(avsd.log.path, "a");
	}

	if (avsd.lb.enabled) {
		int nprocs = 0;
		pid_t pid;

		avsd.worker_count = 0;
		avsd.lb.req_addr = mem_zalloc(avsd.lb.nprocs * sizeof(*avsd.lb.req_addr), NULL);
		if (!avsd.lb.req_addr)
			return ENOMEM;
		avsd.lb.metrics_addr = mem_zalloc(avsd.lb.nprocs * sizeof(*avsd.lb.metrics_addr),
						  NULL);
		if (!avsd.lb.metrics_addr)
			return ENOMEM;

		avsd.lb.sft_addr = mem_zalloc(avsd.lb.nprocs * sizeof(*avsd.lb.sft_addr), NULL);
		if (!avsd.lb.sft_addr)
			return ENOMEM;
		
		sa_cpy(&sftsa, &avsd.sft_req_addr);
		
		do {
			int req_port;
			int metrics_port;
			int sft_port;
			struct sa rsa;
			struct sa msa;
			struct sa ssa;
			
			pid = fork();

			req_port = sa_port(&avsd.req_addr) + nprocs;
			metrics_port = sa_port(&avsd.metrics_addr) + nprocs + 1;
			sft_port = sa_port(&sftsa) + nprocs;

			sa_set_str(&rsa, LOCALHOST_IPV4, req_port);

			/* Metrics */
			sa_set_str(&msa, LOCALHOST_IPV4, metrics_port);

			/* SFT-request */
			sa_cpy(&ssa, &avsd.sft_req_addr);
			sa_set_port(&ssa, sft_port);
			
			if (pid == 0) {
				avsd.lb.main = false;
				avsd.worker_count = 0;
				avsd.direct_federation = true;
				sa_cpy(&avsd.req_addr, &rsa);
				sa_cpy(&avsd.metrics_addr, &msa);
				sa_cpy(&avsd.sft_req_addr, &ssa);
			}
			else if (pid > 0) {
				avsd.lb.main = true;
				sa_cpy(&avsd.lb.req_addr[nprocs], &rsa);
				sa_cpy(&avsd.lb.metrics_addr[nprocs], &msa);
				sa_cpy(&avsd.lb.sft_addr[nprocs], &ssa);
			}
			++nprocs;
		}
		while(nprocs < avsd.lb.nprocs && pid > 0);
	}

	log_register_handler(&logh);

	sa_init(&goog, AF_INET);
	sa_set_str(&goog, "8.8.8.8", DNS_PORT);
	err = dnsc_alloc(&avsd.dnsc, NULL, &goog, 1);
	if (err) {
		warning("dns: dnsc_alloc failed: %m\n", err);
		goto out;
	}
	
	if (avsd.lb.main) {
		lb_init(avsd.lb.nprocs);
	}
	else {
		err = module_init();
		if (err) {
			warning("%s: module_init failed: %m\n", argv[0], err);
			goto out;
		}
	}

	avsd.start_time = time(NULL);

	info("welcome to AVS-service -- using '%s'\n", avs_version_str());

	re_main(signal_handler);

 out:
	info("avsd quit -- cleaning up..\n");

	avs_close();
	libre_close();

	avsd.dnsc = mem_deref(avsd.dnsc);
	avsd.secret.p = mem_deref((void *)avsd.secret.p);
	log_unregister_handler(&logh);
	
	/* check for memory leaks */
	tmr_debug();
	mem_debug();

	(void)shutdown_handler;
	(void)error_handler;

	log_unregister_handler(&logh);

		
	return err;
}


struct sa  *avs_service_req_addr(void)
{
	return &avsd.req_addr;
}

struct sa *avs_service_get_req_addr(int ix)
{
	if (ix < 0 || ix >= avsd.lb.nprocs)
		return NULL;

	return &avsd.lb.req_addr[ix];
}

struct sa *avs_service_get_sft_addr(int ix)
{
	if (ix < 0 || ix >= avsd.lb.nprocs)
		return NULL;

	return &avsd.lb.sft_addr[ix];
}


struct sa *avs_service_get_metrics_addr(int ix)
{
	if (ix < 0 || ix >= avsd.lb.nprocs)
		return NULL;

	return &avsd.lb.metrics_addr[ix];
}

struct sa  *avs_service_media_addr(void)
{
	return sa_isset(&avsd.media_addr, SA_ADDR) ? &avsd.media_addr
		                                   : NULL;
}

struct sa  *avs_service_alt_media_addr(void)
{
	return sa_isset(&avsd.alt_media_addr, SA_ADDR) ? &avsd.alt_media_addr
		                                       : NULL;
}

struct list  *avs_service_iflist(void)
{
	return (avsd.ifl.head != NULL) ? &avsd.ifl : NULL;
}


struct sa  *avs_service_metrics_addr(void)
{
	return &avsd.metrics_addr;
}


const char *avs_service_sft_req_url(void)
{
	return str_isset(avsd.sft_req_url) ? avsd.sft_req_url : NULL;
}

struct sa *avs_service_sft_req_addr(void)
{
	return sa_isset(&avsd.sft_req_addr, SA_ALL) ? &avsd.sft_req_addr : NULL;
}


const char *avs_service_url(void)
{
	return avsd.url[0] != '\0' ? avsd.url : NULL;
}

const char *avs_service_blacklist(void)
{
	return avsd.blacklist[0] != '\0' ? avsd.blacklist : NULL;
	
}

int avs_service_worker_count(void)
{
	return avsd.worker_count;
}

bool avs_service_use_turn(void)
{
	return avsd.use_turn;
}


struct dnsc *avs_service_dnsc(void)
{
	return avsd.dnsc;
}

const char *avs_service_federation_url(void)
{
	return avsd.federation_url[0] != '\0' ? avsd.federation_url : NULL;
}

bool avs_service_direct_federation(void)
{
	return avsd.direct_federation;
}

const char *avs_service_turn_url(void)
{
	return avsd.turn.url[0] != '\0' ? avsd.turn.url : NULL;
}

bool avs_service_use_auth(void)
{
	return avsd.use_auth;
}

const char *avs_service_secret_path(void)
{
	return avsd.turn.secret_path[0] != '\0' ? avsd.turn.secret_path : NULL;
}

const struct pl *avs_service_secret(void)	
{
	return pl_isset(&avsd.secret) ? &avsd.secret : NULL;
}

uint64_t avs_service_fir_timeout(void)
{
	return avsd.fir_timeout;
}

bool avs_service_is_draining(void)
{
	return avsd.is_draining;
}


void avs_service_register_shutdown_handler(avs_service_shutdown_h *shuth, void *arg)
{
	struct shutdown_entry *se;

	se = mem_zalloc(sizeof(*se), NULL);
	if (!se)
		return;

	se->shuth = shuth;
	se->arg = arg;

	list_append(&avsd.shuthl, &se->le, se);	
}


void avs_service_terminate(void)
{
	list_flush(&avsd.ifl);
	list_flush(&avsd.shuthl);
	
	module_close();
	
	re_cancel();

	mem_deref(avsd.lb.req_addr);
	mem_deref(avsd.lb.metrics_addr);
	mem_deref(avsd.lb.sft_addr);
	if (avsd.lb.main)
		lb_close();

	mem_deref(avsd.log.prefix);
	if (avsd.log.fp && avsd.log.fp != stdout) {
		fclose(avsd.log.fp);
	}
}
