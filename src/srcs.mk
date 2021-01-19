#
# srcs.mk All application source files.
#

SRCS    += config.c
SRCS	+= httpd.c
SRCS	+= main.c
SRCS    += mediapump.c
SRCS	+= module.c

ifneq ($(STATIC),)
SRCS    += static.c
endif
