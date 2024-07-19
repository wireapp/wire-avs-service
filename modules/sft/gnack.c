
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <re.h>
#include <avs_log.h>

#include "gnack.h"


#define MAX_GNACK_SIZE 100

#define RTX_PT 101

struct gnack_entry {
	struct call *call;

	uint32_t ssrc;
	uint16_t seq;
	uint8_t *plb;
	size_t pllen;
	size_t plpos;

	struct le le;
};

static inline bool seq_less(uint16_t x, uint16_t y)
{
	return ((int16_t)(x - y)) < 0;
}

static void rtx_destructor(void *arg)
{
	struct gnack_rtx *rtx = arg;

	mem_deref(rtx->plb);
	list_unlink(&rtx->le);
}

static int add_packets(struct gnack_rtx_stream *rs,
		       struct list *rtxl,
		       uint32_t ssrc,
		       uint16_t pid, uint16_t blp)
{	
	struct gnack_rtx *rtx;
	struct le *le;
	bool adding = true;
	int n = 0;
	int err = 0;

	for (le = rs->l.head; adding && le; le = le->next) {
		struct gnack_entry *ge = le->data;
		struct rtp_header rtp;
		struct mbuf mb;

		if (ge->ssrc != ssrc)
			continue;

		if (ge->seq != pid) {
			if (!seq_less(ge->seq, pid)) {
				adding = false;
			}
			continue;
		}

		rtx = mem_zalloc(sizeof(*rtx), rtx_destructor);
		if (!rtx)
			continue;

		/* The RTX packet contains the OSN as its first 16 bits */
		rtx->plb = mem_alloc(ge->pllen + sizeof(uint16_t), NULL);
		if (!rtx->plb)
			continue;


		/* RTX packet format is described in RFC-4588
		 *
		 * 0                   1                   2                   3
		 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |                         RTP Header                            |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |            OSN                |                               |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
		 * |                  Original RTP Packet Payload                  |
		 * |                                                               |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *
		 * RTX-header:
		 * - ssrc -- must belong to the RTX payload.
		 * - seq  -- monotonously increasing sequence number on RTX stream
		 */

		memcpy(rtx->plb, ge->plb, ge->plpos);
		*(uint16_t *)((void *)&rtx->plb[ge->plpos]) = htons(ge->seq);
		memcpy(&rtx->plb[ge->plpos + sizeof(uint16_t)],
		       &ge->plb[ge->plpos],
		       ge->pllen - ge->plpos);
		rtx->pllen = ge->pllen + sizeof(uint16_t);
		rtx->plpos = ge->plpos;

		mb.pos = 0;
		mb.buf = rtx->plb;
		mb.end = mb.size = rtx->pllen;
		err = rtp_hdr_decode(&rtp, &mb);
		
		/* Update the RTP header to reflect RTX packet */
		rtp.pt = RTX_PT;
		rtp.ssrc = rs->ssrc;
		rtp.seq = rs->seq;
		++rs->seq;
		
		mb.pos = 0;
		rtp_hdr_encode(&mb, &rtp);

		list_append(rtxl, &rtx->le, rtx);
		++n;

		adding = blp != 0;

		if (adding) {
			bool counting = true;

			while(counting) {
				++pid;
				counting = (blp & 0x1) == 0x0;
				blp = blp >> 1;
			}
		}
	}

	return n;
}

void gnack_handler(struct call *call, struct gnack_rtx_stream *rs,
		   gnack_send_h *gsendh, struct rtcp_msg *rtcp)
{
	uint32_t i;

	for (i = 0; i < rtcp->r.fb.n; ++i) {
		struct list rtxl = LIST_INIT;

		if (gsendh) {
			int n;
			
			n = add_packets(rs,
					&rtxl,
					rtcp->r.fb.ssrc_media,
					rtcp->r.fb.fci.gnackv[i].pid,
					rtcp->r.fb.fci.gnackv[i].blp);
			if (n > 0)
				gsendh(call, rs, &rtxl);
			else {
				warning("gnack_handler: no packet found for ssrc=%u seq=%d[%04x)\n",
					rtcp->r.fb.ssrc_media,
					rtcp->r.fb.fci.gnackv[i].pid,
					rtcp->r.fb.fci.gnackv[i].blp);
			}
		}

		list_flush(&rtxl);
	}
}

static void ge_destructor(void *arg)
{
	struct gnack_entry *ge = arg;

	list_unlink(&ge->le);

	mem_deref(ge->plb);
}

static bool sort_handler(struct le *le1, struct le *le2, void *arg)
{
	struct gnack_entry *ge1 = le1->data;
	struct gnack_entry *ge2 = le2->data;
		
	return seq_less(ge1->seq, ge2->seq);
}

int gnack_add_payload(struct call *call, struct gnack_rtx_stream *rs,
		      struct rtp_header *rtp,
		      uint8_t *plb, size_t pllen, size_t plpos)
{
	struct gnack_entry *ge = NULL;
	int err = 0;

	if (list_count(&rs->l) >= MAX_GNACK_SIZE) {
		struct le *le = list_head(&rs->l);

		ge = le->data;
		if (ge) {
			list_unlink(&ge->le);
			mem_deref(ge);
		}
	}
	ge = mem_zalloc(sizeof(*ge), ge_destructor);
	if (!ge)
		return ENOMEM;

	ge->plb = mem_alloc(pllen, NULL);
	if (!ge->plb) {
		err = ENOMEM;
		goto out;
	}

	memcpy(ge->plb, plb, pllen);
	ge->pllen = pllen;
	ge->plpos = plpos;
	ge->ssrc = rtp->ssrc;
	ge->seq = rtp->seq;

	list_append(&rs->l, &ge->le, ge);
	list_sort(&rs->l, sort_handler, NULL);
	
 out:
	if (err)
		mem_deref(ge);

	return err;
}
