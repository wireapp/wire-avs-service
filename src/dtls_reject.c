/*
 * Wire
 * Copyright (C) 2026 Wire Swiss GmbH
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

/* Counts the DTLS handshakes that sftd rejects, for /metrics */

#include <re.h>
#include <avs_service.h>

static uint64_t rejectedv[AVS_SERVICE_DTLS_REJECT_MAX];


/* Called on the worker threads */
void avs_service_dtls_rejected(enum avs_service_dtls_reject reason)
{
	if (reason < AVS_SERVICE_DTLS_REJECT_MAX)
		__atomic_add_fetch(&rejectedv[reason], 1, __ATOMIC_RELAXED);
}


uint64_t avs_service_dtls_rejected_count(enum avs_service_dtls_reject reason)
{
	if (reason >= AVS_SERVICE_DTLS_REJECT_MAX)
		return 0;

	return __atomic_load_n(&rejectedv[reason], __ATOMIC_RELAXED);
}


/* Prints the counters in the Prometheus text format */
int avs_service_dtls_rejected_metrics(struct re_printf *pf, void *arg)
{
	int err;
	(void)arg;

	err = re_hprintf(pf, "# HELP sft_dtls_rejected_total "
			 "DTLS handshakes rejected because the peer has no "
			 "key exchange group or no DTLS version in common "
			 "with sftd\n");
	err |= re_hprintf(pf, "# TYPE sft_dtls_rejected_total counter\n");
	err |= re_hprintf(pf, "sft_dtls_rejected_total{reason=\"group\"} "
			  "%llu\n",
			  avs_service_dtls_rejected_count(
				  AVS_SERVICE_DTLS_REJECT_GROUP));
	err |= re_hprintf(pf, "sft_dtls_rejected_total{reason=\"version\"} "
			  "%llu\n",
			  avs_service_dtls_rejected_count(
				  AVS_SERVICE_DTLS_REJECT_VERSION));

	return err;
}
