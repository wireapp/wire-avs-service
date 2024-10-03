#
# module.mk
#

MOD		:= sft
$(MOD)_SRCS	+= bitstream.c
$(MOD)_SRCS	+= dep_desc.c
$(MOD)_SRCS	+= gnack.c
$(MOD)_SRCS	+= jbuf.c
$(MOD)_SRCS	+= sft.c

include mk/mod.mk
