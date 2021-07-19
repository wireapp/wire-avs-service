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

#include <string.h>
#include <time.h>
#include <re.h>
#include <avs_log.h>
#include <avs_wcall.h>
#include <avs_service.h>

static struct list httpdl = LIST_INIT;

struct httpd {
	struct http_sock *srv_sock;
	struct list urll;
	time_t start;
	struct sa laddr;

	httpd_req_h *reqh;
	void *arg;

	struct le le;
};


static inline const struct httpd_url *url_find(struct httpd *httpd,
					       const struct pl *path)
{
	struct le *le;

	if (!path)
		return NULL;

	for (le = httpd->urll.head; le; le = le->next) {
		const struct httpd_url *url = le->data;

		if (!pl_strcmp(path, url->path))
			return url;
	}

	return NULL;
}


static void http_handler(struct http_conn *hc, const struct http_msg *msg,
			 void *arg)
{
	struct httpd *httpd = arg;
	const struct httpd_url *url;	

	/* XXX: add authentication here? */
	
	url = url_find(httpd, &msg->path);
	if (!url) {
		if (httpd->reqh) {
			httpd->reqh(hc, msg, httpd->arg);
			return;
		}
		else {
			debug("httpd: http path not found: %r\n", &msg->path);
			(void)http_ereply(hc, 404, "Not Found");
			return;
		}
	}

	if (url->reqh)
		url->reqh(hc, msg, url->arg);
}


void httpd_url_register(struct httpd *httpd, struct httpd_url *url)
{
	if (!httpd || !url)
		return;

	list_append(&httpd->urll, &url->le, url);

	debug("httpd(%p): url_register: %s\n", httpd, url->path);
}


void httpd_url_unregister(struct httpd *httpd, struct httpd_url *url)
	
{
	if (!httpd || !url)
		return;
	
	list_unlink(&url->le);

	debug("httpd[%p]: url_unregister: %s\n", httpd, url->path);
}


static int print_urls(struct re_printf *pf, void *arg)
{
	struct httpd *httpd = arg;
	struct le *le;
	int err;

	err = re_hprintf(pf, "<h3>Available URLs:</h3>\n");

	for (le = httpd->urll.head; le; le = le->next) {

		const struct httpd_url *url = le->data;

		err |= re_hprintf(pf, "<a href=\"%s\">%s</a><br>\n",
				  url->path, url->path);
	}

	return err;
}


static void status_handler(struct http_conn *hc, const struct http_msg *msg,
			   void *arg)
{
	struct httpd *httpd = arg;
	uint32_t uptime = (uint32_t)(time(NULL) - httpd->start);

	(void)msg;
	(void)http_creply(hc, 200, "OK", "text/html",
			  "<!DOCTYPE html>\n"
			  "<html>\n"
			  "<head><title>Server Info</title></head>\n"
			  "<body>\n<h2>Server Info</h2>\n<pre>\n"
			  "Version: " VERSION "\n"
			  "Built:   " __DATE__ " " __TIME__ "\n"
			  "Uptime:  %H\n"
			  "</pre>\n"

			  "%H\n"
			  "</body>\n"
			  "</html>\n",
			  fmt_human_time, &uptime, print_urls, httpd);
}


static struct httpd_url url_root = {
	.path = "/",
	.auth  = true,
	.reqh = status_handler,
	.arg = NULL,
};


static void httpd_destructor(void *arg)
{
	struct httpd *httpd = arg;

	httpd_url_unregister(httpd, &url_root);

	list_unlink(&httpd->le);

	mem_deref(httpd->srv_sock);
}

int httpd_alloc(struct httpd **httpdp, struct sa *laddr,
		httpd_req_h *reqh, void *arg)
{
	struct httpd *httpd;
	int err = 0;

	httpd = mem_zalloc(sizeof(*httpd), httpd_destructor);
	if (!httpd)
		return ENOMEM;

	httpd->reqh = reqh;
	httpd->arg = arg;
	sa_cpy(&httpd->laddr, laddr);
	
	err = http_listen(&httpd->srv_sock, laddr, http_handler, httpd);
	if (err) {
		error("httpd_init: listen %J failed: %m\n",
		      &laddr, err);
		goto out;
	}

	info("httpd_alloc: listen: %J\n", laddr);

	//url_root.arg = httpd;
	//httpd_url_register(httpd, url);
	httpd->start = time(NULL);

	list_append(&httpdl, &httpd->le, httpd);

out:
	if (!err && httpdp)
		*httpdp = httpd;
	else
		mem_deref(httpd);

	return err;
}


