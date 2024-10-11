#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <re.h>

#include "bitstream.h"

struct bitstream {
	bool allocated;
	uint8_t *buf;
	size_t sz;
	size_t at;
};

static void destructor(void *arg)
{
	struct bitstream *bs = arg;

	if (bs->allocated)
		mem_deref(bs->buf);
}

int bitstream_alloc(struct bitstream **bsp, uint8_t *buf, size_t sz, bool cpy)
{
	struct bitstream *bs;
	int err = 0;

	if (!bsp || !buf || !sz)
		return EINVAL;
	
	bs = mem_zalloc(sizeof(*bs), destructor);
	if (!bs)
		return ENOMEM;

	if (!cpy) {
		bs->buf = buf;
	}
	else {
		bs->allocated = true;
		bs->buf = mem_alloc(sz, NULL);
		if (!bs->buf) {
			err = ENOMEM;
			goto out;
		}
		memcpy(bs->buf, buf, sz);
	}
	bs->sz = sz;
	
 out:
	if (err) {
		mem_deref(bs);
	}
	else {
		*bsp = bs;		
	}

	return err;
}

static uint32_t read_bit(struct bitstream *bs)
{
	int pos = bs->at / 8;
	uint32_t mask = 1 << (7 - (bs->at % 8));

	//printf("read_bit: at=%zu pos=%d[%02x] mask=%02x\n", bs->at, pos, bs->buf[pos], mask);
	
	++bs->at;
	
	return (bs->buf[pos] & mask) == mask;
}

uint32_t bitstream_read_bits(struct bitstream *bs, int n)
{
	uint32_t x = 0;
	int i;

	if (bs->at + n >= bs->sz * 8) {
		return 0;
	}
	
	for(i = 0; i < n; i++) {
		x = 2 * x + read_bit(bs);
	}

	return x;
}


uint32_t bitstream_read_ns(struct bitstream *bs, int n)
{
	uint32_t w = 0;
	uint32_t x = n;
	uint32_t m;
	uint32_t v;

	while (x != 0) {
		x = x >> 1;
		w++;
	}
	m = (1 << w) - n;
	v = bitstream_read_bits(bs, w - 1);

	return (v < m) ? v : ((v << 1) - m + read_bit(bs));
}
