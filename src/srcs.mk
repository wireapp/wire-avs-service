#
# srcs.mk All application source files.
#

SRCS    += config.c
SRCS 	+= helper.c
SRCS	+= httpd.c
SRCS	+= lb.c
SRCS	+= main.c
SRCS    += mediapump.c
SRCS	+= module.c
SRCS    += turnconn.c
SRCS    += worker.c
SRCS	+= zrest.c

ifneq ($(STATIC),)
SRCS    += static.c
endif
