#
# module.mk
#

MOD		:= reflow
$(MOD)_SRCS	+= dce.c
$(MOD)_SRCS	+= dtls.c
$(MOD)_SRCS	+= mediastats.c
$(MOD)_SRCS	+= packet.c
$(MOD)_SRCS	+= reflow.c
$(MOD)_SRCS	+= sdp.c
$(MOD)_SRCS	+= turnconn.c

include mk/mod.mk
