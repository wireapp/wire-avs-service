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
#include <sys/time.h>
#include <sys/types.h>
#include <wordexp.h>
#include <re.h>
#include <avs_log.h>
#include <avs_base.h>
#include <avs_semaphore.h>
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
	struct sa mediaif_addr;
	struct sa metrics_addr;
	struct sa sft_req_addr;

	char url[256];
	char federation_url[256];
	char blacklist[256];

	struct list ifl;

	struct {
		char url[256];
		char secret_path[256];
	} turn;

	struct {
		char prefix[256];	
		FILE *fp;
		bool file;
		struct lock *lock;
		struct list linel;
		struct avs_sem *sem;
		bool running;
		pthread_t th;
	} log;

	int worker_count;
	uint64_t fir_timeout;	
	bool use_turn;
	bool use_auth;
	bool is_draining;
	struct pl secret;

	struct dnsc *dnsc;
<<<<<<< release-4.1

	struct list shuthl;
=======
	
>>>>>>> local
};

struct log_line {
	struct mbuf *mb;

	struct le le;
};

static struct avs_service avsd = {
       .worker_count = NUM_WORKERS,
       .use_turn = false,
       .use_auth = false,
       .secret = PL_INIT,
       .dnsc = NULL,
};


struct shutdown_entry {
	avs_service_shutdown_h *shuth;
	void *arg;

	struct le le;
};

#define DEFAULT_REQ_ADDR "127.0.0.1"
#define DEFAULT_REQ_PORT 8585

#define DEFAULT_METRICS_ADDR "127.0.0.1"
#define DEFAULT_METRICS_PORT 49090

#define DEFAULT_SFT_REQ_ADDR "127.0.0.1"
#define DEFAULT_SFT_REQ_PORT 9999


static void usage(void)
{
	(void)re_fprintf(stderr,
			 "usage: sftd [-a] [-I <addr>] [-p <port>] [-A <addr>] [-M <addr>] [-r <port>] "
			 "[-u <URL>] [-b <blacklist> [-l <prefix>] [-O <iflist>] "
			 "[-q] [-w <count>] -T -t <URL> -s <path> -w <count>\n");
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

static void logl_destructor(void *arg)
{
	struct log_line *logl = arg;

	mem_deref(logl->mb);
}

static void log_handler(uint32_t level, const char *msg, void *arg)
{
	struct timeval tv;
	struct log_line *logl;

	logl = mem_alloc(sizeof(*logl), logl_destructor);
	if (!logl)
		return;
	logl->mb = mbuf_alloc(1024);
	if (!logl->mb)
		return;
			 
	if (gettimeofday(&tv, NULL) == 0) {
		struct tm  tstruct;
		uint32_t tms;
		char timebuf[64];
		const pthread_t tid = pthread_self();

		memset(timebuf, 0, 64);
		tstruct = *localtime(&tv.tv_sec);
		tms = tv.tv_usec / 1000;
		strftime(timebuf, sizeof(timebuf), "%m-%d %X", &tstruct);
		mbuf_printf(logl->mb, "%s.%03u T(%p) %s%s",
			   timebuf, tms,
			   tid,
			   level_prefix(level), msg);
	}
	else {
		mbuf_printf(logl->mb, "%s%s", level_prefix(level), msg);
	}


	lock_write_get(avsd.log.lock);
	list_append(&avsd.log.linel, &logl->le, logl);
	lock_rel(avsd.log.lock);	
	avs_sem_post(avsd.log.sem);
}

static void *log_thread(void *arg)
{
	struct le *le;
	FILE *fp;
	
	if (avsd.log.file)
		fp = avsd.log.fp;
	else
		fp = stdout;

	if (!fp)
		return NULL;
	
	while (avsd.log.running) {
		struct log_line *logl;
		
		avs_sem_wait(avsd.log.sem);
		
		lock_write_get(avsd.log.lock);
		le = avsd.log.linel.head;
		if (le)
			list_unlink(le);
		lock_rel(avsd.log.lock);
		if (!le) {
			continue;
		}

		logl = le->data;
		
		fwrite(logl->mb->buf, 1, logl->mb->end, fp);
		fflush(fp);

		mem_deref(logl);
	}

	return NULL;
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
		 warning("sft: failed to openj secret file: %s\n", path);
		 return EBADF;
	 }
	 if (fscanf(fp, "%256s", secret) > 0) {
		 char *psec;
		 info("sft: secret %s read\n", secret);

		 err = str_dup(&psec, secret);		 
		 if (!err) {
			 avsd.secret.p = psec;
			 avsd.secret.l = str_len(secret);
		 }
	 }

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
	char log_file_name[255];
	struct sa goog;
	int err;
	
	(void)sys_coredump_set(true);

	memset(&avsd, 0, sizeof(avsd));

	avsd.worker_count = NUM_WORKERS;
	avsd.fir_timeout = TIMEOUT_FIR;
	lock_alloc(&avsd.log.lock);
	list_init(&avsd.log.linel);
	
	for (;;) {

		const int c = getopt(argc, argv, "aA:b:c:f:I:k:l:M:O:p:qr:s:Tt:u:vw:x:");
		if (0 > c)
			break;

		switch (c) {
		case 'a':
			avsd.use_auth = true;
			break;
			
		case 'A':
			sa_set_str(&avsd.media_addr, optarg, 0);
			break;

		case 'b':
			str_ncpy(avsd.blacklist, optarg,
				 sizeof(avsd.blacklist));
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
			avsd.log.file = true;
			str_ncpy(avsd.log.prefix, optarg, sizeof(avsd.log.prefix));
			break;

		case 'M':
			err = sa_set_str(&avsd.metrics_addr, optarg,
					 DEFAULT_METRICS_PORT);
			if (err)
				goto out;
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

		default:
			err = EINVAL;
			usage();
			goto out;
		}
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
	re_printf("AVS-service setting fd_setsize: %d\n", MAX_OPEN_FILES);
	fd_setsize(0);
	fd_setsize(MAX_OPEN_FILES);	
	if (err)
		goto out;

	err = avs_init(0);
	if (err)
		goto out;

	log_set_min_level(log_level);
	log_enable_stderr(false);
	if (avsd.log.file) {
		char  buf[256];
		time_t     now = time(0);
		struct tm  tstruct;

		tstruct = *localtime(&now);
		strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);
		buf[13] = '-';
		buf[16] = '-';

		re_snprintf(log_file_name, sizeof(log_file_name),
			    "%s_%s.log", avsd.log.prefix, buf);

		avsd.log.fp = fopen(log_file_name, "a");
	}

	/* Create logging thread */
	avs_sem_alloc(&avsd.log.sem, 0);
	avsd.log.running = true;
	pthread_create(&avsd.log.th, NULL, log_thread, NULL);
	
	log_register_handler(&logh);

	err = module_init();
	if (err) {
		warning("%s: module_init failed: %m\n", argv[0], err);
		goto out;
	}
	
	avsd.start_time = time(NULL);

	re_printf("welcome to AVS-service -- using '%s'\n", avs_version_str());
	info("welcome to AVS-service -- using '%s'\n", avs_version_str());

	sa_init(&goog, AF_INET);
	sa_set_str(&goog, "8.8.8.8", DNS_PORT);
	err = dnsc_alloc(&avsd.dnsc, NULL, &goog, 1);
	if (err) {
		warning("dns: dnsc_alloc failed: %m\n", err);
		goto out;
	}
<<<<<<< release-4.1

=======
	
>>>>>>> local
	re_main(signal_handler);

 out:
	info("avsd quit -- cleaning up..\n");

	avs_close();
	libre_close();

	avsd.dnsc = mem_deref(avsd.dnsc);
	avsd.secret.p = mem_deref((void *)avsd.secret.p);

	avsd.log.running = false;
	pthread_join(avsd.log.th, NULL);
	avsd.log.lock = mem_deref(avsd.log.lock);
	
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

struct sa  *avs_service_media_addr(void)
{
	return sa_isset(&avsd.media_addr, SA_ADDR) ? &avsd.media_addr
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


struct sa *avs_service_sft_req_addr(void)
{
	return &avsd.sft_req_addr;
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
	
	module_close();
	
	re_cancel();
}
