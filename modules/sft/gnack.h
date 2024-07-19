struct call;

struct gnack_rtx {
	uint8_t *plb;
	size_t  pllen;
	size_t plpos;

	struct le le;
};

struct gnack_rtx_stream {
	struct list l;
	uint16_t seq;
	uint32_t ssrc;
};

typedef void (gnack_send_h)(struct call *call,
			    struct gnack_rtx_stream *rs,
			    struct list *rtxl);

void gnack_handler(struct call *call, struct gnack_rtx_stream *rs,
		   gnack_send_h *gsendh, struct rtcp_msg *rtcp);
int  gnack_add_payload(struct call *call, struct gnack_rtx_stream *rs,
		       struct rtp_header *rtp,
		       uint8_t *plb, size_t pllen, size_t plpos);

