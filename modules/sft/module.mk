#
# module.mk
#

MOD		:= sft
$(MOD)_SRCS	+= sft.c zauth.c

include mk/mod.mk
