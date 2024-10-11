#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <re.h>
#include "avs.h"
#include "bitstream.h"
#include "dep_desc.h"


static int read_mandatory(struct bitstream *bs, struct dep_desc *dd)
{
	dd->sof = bitstream_read_bits(bs, 1) == 1;
	dd->eof = bitstream_read_bits(bs, 1) == 1;
	dd->tid = bitstream_read_bits(bs, 6);
	dd->fid = bitstream_read_bits(bs, 16);

	return 0;
}

static void template_destructor(void *arg)
{
	struct dep_desc_template *template = arg;

	mem_deref(template->fdiff.v);
	mem_deref(template->chains);
	mem_deref(template->dtis);
}

static int template_layers(struct bitstream *bs, struct dep_desc *dd)
{
	struct list templatel = LIST_INIT;
	struct le *le;
	size_t i;
	int s = 0;
	int t = 0;
	bool done = false;
	int err = 0;
	
	while (!done) {
		struct dep_desc_template *template;
		uint8_t idc;

		template = mem_zalloc(sizeof(*template), template_destructor);
		if (!template) {
			err = ENOMEM;
			goto out;
		}
		template->s = s;
		template->t = t;

		list_append(&templatel, &template->le, template);
	    
		idc = bitstream_read_bits(bs, 2);
		switch (idc) {
		case 1:
			t++;
			if (t > dd->t_max) {
				dd->t_max = t;
			}
			break;
			
		case 2:
			t = 0;
			s++;
			break;

		case 3:
			done = true;
			break;
		}
	} 
	dd->s_max = s;
	for (i = 0; i < dd->template.c; ++i) {
		mem_deref(dd->template.v[i]);
	}
	dd->template.v = mem_deref(dd->template.v);
	dd->template.c = list_count(&templatel);
	if (dd->template.c > 0) {
		dd->template.v = mem_zalloc(dd->template.c * sizeof(*dd->template.v), NULL);
		if (!dd->template.v) {
			err = ENOMEM;
			goto out;
		}
	}

	le = templatel.head;
	for(i = 0; i < dd->template.c; ++i) {
		struct dep_desc_template *template = le->data;

		dd->template.v[i] = mem_ref(template);
		le = le->next;
	}

 out:
	list_flush(&templatel);

	return err;
}

static int template_dtis(struct bitstream *bs, struct dep_desc *dd)
{
	size_t i;

	for(i = 0; i < dd->template.c; ++i) {
		struct dep_desc_template *template = dd->template.v[i];
		size_t d;

		template->dtis = mem_deref(template->dtis);
		if (dd->dt.cnt > 0) {
			template->dtis = mem_zalloc(dd->dt.cnt, NULL);
			if (!template->dtis)
				continue;
		}

		for (d = 0; d < dd->dt.cnt; ++d) {
			// See table A.1 below for meaning of DTI values.
			template->dtis[d] = bitstream_read_bits(bs, 2);
		}
	}

	return 0;
}

struct fdiff {
	uint8_t val;

	struct le le;
};

static int template_fdiffs(struct bitstream *bs, struct dep_desc *dd)
{
	size_t i;
	int err = 0;

	for (i = 0; i < dd->template.c; ++i) {
		struct dep_desc_template *template = dd->template.v[i];
		struct list fl = LIST_INIT;
		struct le *le;
		size_t f;
		bool fdiff_follows;

		fdiff_follows = bitstream_read_bits(bs, 1) == 1;
		while (fdiff_follows) {
			struct fdiff *fdiff;

			fdiff = mem_zalloc(sizeof(*fdiff), NULL);
			if (!fdiff) {
				err = ENOMEM;
				goto out;
			}

			fdiff->val = bitstream_read_bits(bs, 4) + 1;
			list_append(&fl, &fdiff->le, fdiff);

			fdiff_follows = bitstream_read_bits(bs, 1) == 1;
		}
		template->fdiff.c = list_count(&fl);
		template->fdiff.v = mem_deref(template->fdiff.v);
		if (template->fdiff.c > 0) {
			template->fdiff.v = mem_zalloc(template->fdiff.c * sizeof(*template->fdiff.v),
						       NULL);
			if (!template->fdiff.v) {
				continue;
			}
		}
		le = fl.head;
		for(f = 0; f < template->fdiff.c; ++f) {
			struct fdiff *fdiff = le->data;

			template->fdiff.v[f] = fdiff->val;
			le = le->next;
		}
		list_flush(&fl);
	}

 out:
	return err;
}

static int read_resolutions(struct bitstream *bs, struct dep_desc *dd)
{
	size_t i;

	dd->resolution.v = mem_deref(dd->resolution.v);
	dd->resolution.c = dd->s_max + 1;
	if (dd->resolution.c > 0) {
		dd->resolution.v = mem_zalloc(dd->resolution.c * sizeof(*dd->resolution.v),
					      NULL);
		if (!dd->resolution.v)
			return ENOMEM;
	}

	for (i = 0; i < dd->resolution.c; ++i) {
		struct dep_desc_resolution *res = &dd->resolution.v[i];
		
		res->w = bitstream_read_bits(bs, 16) + 1;
		res->h = bitstream_read_bits(bs, 16) + 1;
	}

	return 0;
}

static int decode_target_layers(struct bitstream *bs, struct dep_desc *dd)
{
	size_t i;

	dd->dt.layers = mem_deref(dd->dt.layers);
	
	if (dd->dt.cnt == 0)
		return 0;

	dd->dt.layers = mem_zalloc(sizeof(*dd->dt.layers) * dd->dt.cnt, NULL);
	if (!dd->dt.layers)
		return ENOMEM;
	
	for (i = 0; i < dd->dt.cnt; ++i) {
		int s = 0;
		int t = 0;
		size_t j;
		
		for (j = 0; j < dd->template.c; ++j) {
			struct dep_desc_template *template = dd->template.v[j];
			if (template->dtis[i] != 0) {
				if (template->s > s) {
					s = template->s;
				}
				if (template->t > t) {
					t = template->t;
				}
			}
		}

		dd->dt.layers[i].s = s;
		dd->dt.layers[i].t = t;
	}

	return 0;
}

static int template_chains(struct bitstream *bs, struct dep_desc *dd)
{
	size_t i;
	size_t d;
	int err = 0;

	dd->chain_cnt = bitstream_read_ns(bs, dd->dt.cnt + 1);
	if (dd->chain_cnt == 0)
		return 0;

	for (d = 0; d < dd->dt.cnt; ++d) {
		(void)bitstream_read_ns(bs, dd->chain_cnt);
	}

	for (i = 0; i < dd->template.c; ++i) {
		struct dep_desc_template *template = dd->template.v[i];
		size_t c;

		template->chains = mem_deref(template->chains);
		if (dd->chain_cnt > 0) {
			template->chains = mem_zalloc(dd->chain_cnt, NULL);
			if (!template->chains) {
				err = ENOMEM;
				goto out;
			}
		}
		for (c = 0; c < dd->chain_cnt; ++c) {
			template->chains[c] = bitstream_read_bits(bs, 4);
		}
	}
 out:
	return err;
}

static int read_template(struct bitstream *bs, struct dep_desc *dd)
{
	dd->dt.tid_offset = bitstream_read_bits(bs, 6);
	dd->dt.cnt = bitstream_read_bits(bs, 5) + 1;

	template_layers(bs, dd);
	template_dtis(bs, dd);
	template_fdiffs(bs, dd);
	template_chains(bs, dd);
	decode_target_layers(bs, dd);

	dd->has_resolution = bitstream_read_bits(bs, 1) == 1;
	if (dd->has_resolution) {
		read_resolutions(bs, dd);
	}

	return 0;
}

			

static int read_extended(struct bitstream *bs, struct dep_desc *dd)
{
	bool has_template = bitstream_read_bits(bs, 1) == 1;
	bool has_active_dt = bitstream_read_bits(bs, 1) == 1;

	dd->has_dtis   = bitstream_read_bits(bs, 1) == 1;
	dd->has_fdiffs = bitstream_read_bits(bs, 1) == 1;
	dd->has_chains = bitstream_read_bits(bs, 1) == 1;

	if (has_template) {
		read_template(bs, dd);
		dd->dt.mask = (1 << dd->dt.cnt) - 1;
	}

	if (has_active_dt) {
		dd->dt.mask = bitstream_read_bits(bs, dd->dt.cnt);
	}

	return 0;
}

static int frame_fdiffs(struct bitstream *bs, struct dep_desc *dd,
			struct dep_desc_frame *frame)
{
	uint8_t fdiff_size = bitstream_read_bits(bs, 2);
	struct list fl = LIST_INIT;
	struct le *le;
	size_t i;
	int err = 0;
	
	while (fdiff_size) {
		struct fdiff *fdiff = mem_zalloc(sizeof(*fdiff), NULL);
		if (!fdiff) {
			err = ENOMEM;
			goto out;
		}
		fdiff->val = bitstream_read_bits(bs, 4 * fdiff_size) + 1;
		list_append(&fl, &fdiff->le, fdiff);
		
		fdiff_size = bitstream_read_bits(bs, 2);
	}
	frame->fdiff.c = list_count(&fl);
	if (frame->fdiff.c > 0) {
		frame->fdiff.v = mem_zalloc(frame->fdiff.c * sizeof(*frame->fdiff.v),
					    NULL);
		if (!frame->fdiff.v) {
			err = ENOMEM;
			goto out;
		}
		frame->fdiff.allocated = true;
	}

	le = fl.head;
	for(i = 0; i < frame->fdiff.c; ++i) {
		struct fdiff *fdiff = le->data;

		frame->fdiff.v[i] = fdiff->val;
	}

 out:
	list_flush(&fl);

	return err;
}

static int frame_dtis(struct bitstream *bs, struct dep_desc *dd,
		      struct dep_desc_frame *frame)
{
	size_t i;

	frame->dti.c = dd->dt.cnt;
	frame->dti.v = mem_zalloc(frame->dti.c * sizeof(*frame->dti.v), NULL);
	if (!frame->dti.v)
		return ENOMEM;
	frame->dti.allocated = true;

	for (i = 0; i < frame->dti.c; ++i) {
		// See table A.1 below for meaning of DTI values.
		frame->dti.v[i] = bitstream_read_bits(bs, 2);
	}

	return 0;
}

static int frame_chains(struct bitstream *bs, struct dep_desc *dd,
			struct dep_desc_frame *frame)
{
	size_t i;

	frame->chain.c = dd->chain_cnt;
	if (frame->chain.c > 0) {
		frame->chain.v = mem_zalloc(frame->chain.c * sizeof(*frame->chain.v), NULL);
		if (!frame->chain.v)
			return ENOMEM;
		frame->chain.allocated = true;
	}
	
	for (i = 0; i < frame->chain.c; ++i) {
		frame->chain.v[i] = bitstream_read_bits(bs, 8);
	}

	return 0;
}


static int read_frame_dep(struct bitstream *bs,
			  struct dep_desc *dd,
			  struct dep_desc_frame *frame)
{
	struct dep_desc_template *template;
	size_t tid = (dd->tid + 64 - dd->dt.tid_offset) % 64;

	if (tid >= dd->template.c)
		return ERANGE;

	template = dd->template.v[tid];

	frame->s = template->s;
	frame->t = template->t;

	if (dd->has_dtis) {
		frame_dtis(bs, dd, frame);
	}
	else {
		frame->dti.allocated = false;
		frame->dti.c = dd->dt.cnt;
		frame->dti.v = template->dtis;
	}

	if (dd->has_fdiffs) {
		frame_fdiffs(bs, dd, frame);
	}
	else {
		frame->fdiff.allocated = false;
		frame->fdiff.c = template->fdiff.c;
		frame->fdiff.v = template->fdiff.v; 
	}

	if (dd->has_chains) {
		frame_chains(bs, dd, frame);
	} else {
		frame->chain.allocated = false;
		frame->chain.c = dd->chain_cnt;
		frame->chain.v = template->chains;
	}

	if (dd->has_resolution) {
		if ((size_t)frame->s < dd->resolution.c) {
			frame->resolution = dd->resolution.v[frame->s];
		}
	}

	return 0;
}

static void frame_destructor(void *arg)
{	
	struct dep_desc_frame *frame = arg;

	if (frame->fdiff.allocated)
		mem_deref(frame->fdiff.v);
	if (frame->chain.allocated)
		mem_deref(frame->chain.v);
	if (frame->dti.allocated)
		mem_deref(frame->dti.v);
}

static void destructor(void *arg)
{
	struct dep_desc *dd = arg;
	size_t i;

	mem_deref(dd->dt.layers);
	for(i = 0; i < dd->template.c; ++i) {
		mem_deref(dd->template.v[i]);
	}
	mem_deref(dd->template.v);
	mem_deref(dd->resolution.v);
}

int dep_desc_read(struct dep_desc **ddp,
		  struct dep_desc_frame **framep,
		  uint8_t *buf, size_t sz)
{
	struct bitstream *bs = NULL;
	struct dep_desc *dd;
	struct dep_desc_frame *frame;
	bool allocated = false;
	int err = 0;

	if (!ddp || !framep || !buf || !sz)
		return EINVAL;

	if (*ddp)
		dd = *ddp;
	else {
		dd = mem_zalloc(sizeof(*dd), destructor);
		if (!dd)
			return ENOMEM;
		allocated = true;
	}

	frame = mem_zalloc(sizeof(*frame), frame_destructor);
	if (!frame) {
		err = ENOMEM;
		goto out;
	}
	
	err = bitstream_alloc(&bs, buf, sz, false);
	if (err)
		goto out;

	err = read_mandatory(bs, dd);
	if (err) {
		warning("dep_desc: failed to read mandatory\n");
		goto out;
	}
	if (sz > 3) {
		err = read_extended(bs, dd);
		if (err) {
			warning("dep_desc: failed to read extended\n");
			goto out;
		}
	}
	else {
		dd->has_dtis = false;
		dd->has_fdiffs = false;
		dd->has_chains = false;
	}
	err = read_frame_dep(bs, dd, frame);
	if (err) {
		warning("dep_desc: failed to read frame\n");
		goto out;
	}
	

 out:
	mem_deref(bs);
	if (err) {
		mem_deref(frame);
		if (allocated)
			mem_deref(dd);
	}
	else {
		if (allocated)
			*ddp = dd;
		*framep = frame;
	}

	return err;
}

int dep_desc_dd_debug(struct re_printf *pf, const struct dep_desc *dd)
{
	int err;
	size_t i;
	
	err = re_hprintf(pf, "\tsof: %d\n", dd->sof);
	err = re_hprintf(pf, "\teof: %d\n", dd->eof);
	err = re_hprintf(pf, "\ttid: %d\n", dd->tid);
	err = re_hprintf(pf, "\tfid: %d\n", dd->fid);
	err = re_hprintf(pf, "\ttid: %d\n", dd->tid);
	err = re_hprintf(pf, "\thas_dtis: %d\n", dd->has_dtis);
	err = re_hprintf(pf, "\thas_fdiffs: %d\n", dd->has_fdiffs);
	err = re_hprintf(pf, "\thas_chains: %d\n", dd->has_chains);
	err = re_hprintf(pf, "\thas_resolution: %d\n", dd->has_resolution);
	err = re_hprintf(pf, "\ts_max: %d\n", dd->s_max);
	err = re_hprintf(pf, "\tt_max: %d\n", dd->t_max);
	err = re_hprintf(pf, "\ttemplates: %d\n", dd->template.c);
	err = re_hprintf(pf, "\tresolutions: %d\n", dd->resolution.c);
	if (dd->resolution.v) {
		for(i = 0; i < dd->resolution.c; ++i) {
			struct dep_desc_resolution *res = &dd->resolution.v[i];
			err = re_hprintf(pf, "\t\t%dx%d\n", res->w, res->h);
		}
	}
	
	return err;
}


int dep_desc_frame_debug(struct re_printf *pf, const struct dep_desc_frame *frame)
{
	int err;
	
	err = re_hprintf(pf, "\ts: %d\n", frame->s);
	err = re_hprintf(pf, "\tt: %d\n", frame->t);
	err = re_hprintf(pf, "\tresolution: %dx%d", frame->resolution.w, frame->resolution.h);

	return err;
}


