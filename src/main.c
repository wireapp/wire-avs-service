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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
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
#define TIMEOUT_FIR 3000

/* Global Context */
struct avs_service {
	time_t start_time;

	struct sa req_addr;
	struct sa media_addr;
	struct sa metrics_addr;

	char url[256];
	char blacklist[256];

	struct {
		char prefix[256];	
		FILE *fp;
		bool file;
		struct lock *lock;
	} log;

	int worker_count;
	uint64_t fir_timeout;
	bool use_turn;
};
struct avs_service avsd = {
       .worker_count = NUM_WORKERS,
       .use_turn = false,
};

#define DEFAULT_REQ_ADDR "127.0.0.1"
#define DEFAULT_REQ_PORT 8585

#define DEFAULT_METRICS_ADDR "127.0.0.1"
#define DEFAULT_METRICS_PORT 49090


static void usage(void)
{
	(void)re_fprintf(stderr,
			 "usage: sftd [-I <addr>] [-p <port>] [-A <addr>] [-M <addr>] [-r <port>]"
			 "[-u <URL>] [-b <blacklist>] [-k <timeout_ms> [-l <prefix>] [-q] [-w <count>] -T\n");
	(void)re_fprintf(stderr, "\t-I <addr>       Address for HTTP requests (default: %s)\n",
			 DEFAULT_REQ_ADDR);
	(void)re_fprintf(stderr, "\t-p <port>       Port for HTTP requests (default: %d)\n",
			 DEFAULT_REQ_PORT);
	(void)re_fprintf(stderr, "\t-A <addr>       Address for media (default: same as request address)\n");
	(void)re_fprintf(stderr, "\t-M <addr>       Address for metrics requests (default: %s)\n",
			 DEFAULT_METRICS_ADDR);
	(void)re_fprintf(stderr, "\t-r <port>       Port for metrics requests (default: %d)\n",
			 DEFAULT_METRICS_PORT);
	(void)re_fprintf(stderr, "\t-u <URL>        Url to use in responses\n");
	(void)re_fprintf(stderr, "\t-b <blacklist>  Comma seperated client version blacklist\n"
			         "\t\t\t Example: <6.2.9,6.2.11\n");
	(void)re_fprintf(stderr, "\t-l <prefix>     Log to file with prefix\n");
	(void)re_fprintf(stderr, "\t-q              Quiet (less-verbose logging)\n");
	(void)re_fprintf(stderr, "\t-T              Use TURN servers when gathering\n");
	(void)re_fprintf(stderr, "\t-w <count>      Worker count (default: %d)\n", NUM_WORKERS);
	(void)re_fprintf(stderr, "\t-k <timeout_ms> Key frame timeout (default: %u)\n", TIMEOUT_FIR);
}

static void signal_handler(int sig)
{
	static bool term = false;
	(void)sig;

	if (sig == SIGUSR1) {
		mem_debug();
		return;
	}
	
	
	if (term) {
		warning("Aborted.\n");
		exit(0);
	}

	term = true;

	warning("Terminating ...\n");	

	module_close();
	
	re_cancel();
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
	FILE *fp = NULL;

	mb = mbuf_alloc(1024);
	if (!mb)
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
		mbuf_printf(mb, "%s.%03u T(%p) %s%s",
			   timebuf, tms,
			   tid,
			   level_prefix(level), msg);
	}
	else {
		mbuf_printf(mb, "%s%s", level_prefix(level), msg);
	}


	lock_write_get(avsd.log.lock);
	
	if (avsd.log.file)
		fp = avsd.log.fp;
	else
		fp = stdout;

	if (fp) {
		fwrite(mb->buf, 1, mb->end, fp);
		fflush(fp);
	}
	lock_rel(avsd.log.lock);

	mem_deref(mb);
}

static struct log logh = {
	.h = log_handler
};


int main(int argc, char *argv[])
{
	enum log_level log_level = LOG_LEVEL_INFO;
	char log_file_name[255];
	int err;
	
	(void)sys_coredump_set(true);

	memset(&avsd, 0, sizeof(avsd));

	avsd.worker_count = NUM_WORKERS;
	avsd.fir_timeout = TIMEOUT_FIR;
	lock_alloc(&avsd.log.lock);
	
	for (;;) {

		const int c = getopt(argc, argv, "A:b:I:k:l:M:p:qr:Tu:w:");
		if (0 > c)
			break;

		switch (c) {
		case 'A':
			sa_set_str(&avsd.media_addr, optarg, 0);
			break;

		case 'b':
			str_ncpy(avsd.blacklist, optarg, sizeof(avsd.blacklist));
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

		case 'p':
			sa_set_port(&avsd.req_addr, atoi(optarg));
			break;

		case 'r':
			sa_set_port(&avsd.metrics_addr, atoi(optarg));
			break;

		case 'T':
			info("avsd: using TURN\n");
			avsd.use_turn = true;
			break;
			
		case 'u':
			str_ncpy(avsd.url, optarg, sizeof(avsd.url));
			break;

		case 'q':
			log_level = LOG_LEVEL_WARN;
			break;

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

	log_register_handler(&logh);

	err = module_init();
	if (err) {
		warning("%s: module_init failed: %m\n", argv[0], err);
		goto out;
	}
	
	avsd.start_time = time(NULL);

	re_printf("welcome to AVS-service -- using '%s'\n", avs_version_str());
	info("welcome to AVS-service -- using '%s'\n", avs_version_str());

	re_main(signal_handler);

 out:
	info("avsd quit -- cleaning up..\n");

	avs_close();
	libre_close();

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

struct sa  *avs_service_metrics_addr(void)
{
	return &avsd.metrics_addr;
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

uint64_t avs_service_fir_timeout(void)
{
	return avsd.fir_timeout;
}
