
struct dep_desc_resolution {
	int w;
	int h;
};

struct dep_desc_template {
	int s;
	int t;

	struct {
		size_t c;
		uint8_t *v;
	} fdiff;

	uint8_t *chains;
	uint8_t *dtis;

	struct le le;
};

struct dep_desc {
	uint32_t tid;
	bool has_dtis;
	bool has_fdiffs;
	bool has_chains;
	bool has_resolution;

	int s_max;
	int t_max;

	size_t chain_cnt;
	
	struct {
		size_t cnt;
		uint16_t mask;
		int tid_offset;
		struct {
			int s;
			int t;
		} *layers;
	} dt;

	struct {
		size_t c;
		struct dep_desc_template **v;
	} template;
	

	struct {
		size_t c;
		struct dep_desc_resolution *v;
	} resolution;
};


struct dep_desc_frame {
	bool sof;
	bool eof;
	uint32_t fid;
	bool has_template;

	int s;
	int t;
	
	struct {
		bool allocated;
		size_t c;
		uint8_t *v;
	} fdiff;

	struct {
		bool allocated;
		size_t c;
		uint8_t *v;
	} chain;

	struct {
		bool allocated;
		size_t c;
		uint8_t *v;
	} dti;

	struct dep_desc_resolution resolution;
};

int  dep_desc_read(struct dep_desc **ddp,
		   struct dep_desc_frame **frame,
		   uint8_t *buf, size_t sz);
int  dep_desc_dd_debug(struct re_printf *pf, const struct dep_desc *dd);
int  dep_desc_frame_debug(struct re_printf *pf, const struct dep_desc_frame *frame);

