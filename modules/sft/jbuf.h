/**
 * @file re_jbuf.h  Interface to Jitter Buffer
 *
 * Copyright (C) 2010 Creytiv.com
 */
struct jb;
struct rtp_header;

/** Jitter buffer statistics */
struct jb_stat {
	uint32_t n_put;        /**< Number of frames put into jitter buffer */
	uint32_t n_get;        /**< Number of frames got from jitter buffer */
	uint32_t n_oos;        /**< Number of out-of-sequence frames        */
	uint32_t n_dups;       /**< Number of duplicate frames detected     */
	uint32_t n_late;       /**< Number of frames arriving too late      */
	uint32_t n_lost;       /**< Number of lost frames                   */
	uint32_t n_overflow;   /**< Number of overflows                     */
	uint32_t n_underflow;  /**< Number of underflows                    */
	uint32_t n_flush;      /**< Number of times jitter buffer flushed   */
};

typedef void (jb_lost_h)(uint32_t ssrc, uint16_t seq, int nlost, void *arg);

int  jb_alloc(struct jb **jbp, uint32_t min, uint32_t max);
int  jb_put(struct jb *jb, const struct rtp_header *hdr, void *mem);
int  jb_get(struct jb *jb, struct rtp_header *hdr,
	    jb_lost_h *losth,
	    void **mem, void *arg);
void jb_flush(struct jb *jb);
int  jb_stats(const struct jb *jb, struct jb_stat *jstat);
int  jb_debug(struct re_printf *pf, const struct jb *jb);
