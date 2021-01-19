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

struct dtls_peer {
	struct le le;
	size_t headroom;
	struct sa addr;
};

int dtls_print_sha256_fingerprint(struct re_printf *pf, const struct tls *tls);

void dtls_conn_handler(const struct sa *unused_peer, void *arg);

bool send_dtls_handler(int *err, struct sa *dst_unused,
		       struct mbuf *mb_pkt, void *arg);

int reflow_init_dtls(struct tls **dtlsp);

struct dtls_peer *dtls_peer_find(struct list *dtls_peers,
				 size_t headroom,
				 const struct sa *addr);

int dtls_peer_add(struct list *dtls_peers,
		  size_t headroom,
		  const struct sa *peer);

