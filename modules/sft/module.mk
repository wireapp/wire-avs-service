#
# module.mk
#

MOD		:= sft
$(MOD)_SRCS	+= gnack.c
$(MOD)_SRCS	+= sft.c

include mk/mod.mk
