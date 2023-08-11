#
# Makefile
#

PROJECT	  := sftd

SFT_VER_MAJOR := 2
SFT_VER_MINOR := 1
ifeq ($(BUILD_NUMBER),)
SFT_VER_BUILD := local
else
SFT_VER_BUILD := $(BUILD_NUMBER)
endif

SFT_VERSION := $(SFT_VER_MAJOR).$(SFT_VER_MINOR).$(SFT_VER_BUILD)


TARGET_MK := mk/target.mk
include $(TARGET_MK)

# Path to avs
#
ifeq ($(AVS_DIR),)
AVS_DIR := contrib/avs
endif

AVS_PATH := $(AVS_DIR)/build/dist/$(HOST_TARGET)/avscore

RE_PATH := $(AVS_DIR)/contrib/re
LIBRE_MK := $(RE_PATH)/mk/re.mk

include $(LIBRE_MK)
include mk/modules.mk
include mk/contrib.mk

INSTALL := install
ifeq ($(DESTDIR),)
PREFIX  := /usr/local
else
PREFIX  := /usr
endif
BINDIR	:= $(PREFIX)/bin

ifeq ($(WEBRTC_VER),)
WEBRTC_VER := m79.7
endif

BUILD_SRC := $(BUILD)/src

# preprocessor flags
CPPFLAGS += \
	-DHAVE_INET6=1 \
	-DHAVE_INTTYPES_H \
	-DHAVE_STDBOOL_H \
	-DHAVE_CRYPTOBOX \
	-DHAVE_PROTOBUF \
	-DSFT_PROJECT='"$(PROJECT)"' \
	-DSFT_VERSION='"$(SFT_VERSION)"' \
	-DUSE_REMB=1 \
	-Iinclude \
	-I$(BUILD)/include \
	-I$(AVS_DIR)/include \
	-I$(AVS_PATH)/include \
	-I$(RE_PATH)/include \
	-I$(AVS_DIR)/contrib/rew/include \
	-Icontrib/usrsctp

# System-specific configuration
#
ifeq ($(HOST_UNAME),Linux)
CCACHE :=
CC := clang
CXX := clang++
LD := clang++
STATIC := 1
CXXFLAGS +=
#-stdlib=libc++
LFLAGS +=
#-stdlib=libc++
TARGET_ARCH = linux
endif
ifeq ($(HOST_UNAME),Darwin)
STATIC := 1
TARGET_ARCH = osx
endif

# Always use STATIC ifneq ($(STATIC),)
CPPFLAGS += -DSTATIC=1
#endif

CFLAGS	+= -g -Wall -std=c99 \
	-Wno-c11-extensions \
	-Wno-gnu-zero-variadic-macro-arguments \
	-fPIE
CXXFLAGS+= -g -Wall -std=c++11 -fPIE
CXXFLAGS+= $(EXTRA_CXXFLAGS)

LFLAGS  += \
	-L$(BUILD)/lib \
	-L$(AVS_PATH)/lib

ifneq ($(SYSROOT_ALT),)
LFLAGS += -L$(SYSROOT_ALT)/lib
endif


JAVAC	:= javac


JAVA_CLASSES_DIR := classes
JAVA_SRCS 	:= \
	java/com/wire/blender/BlenderListener.java \
	java/com/wire/blender/Blender.java

# JNI specifics
JNI_FLAGS	:= -I${JAVA_HOME}/include \
			$(CPPFLAGS) $(CFLAGS) 	
	#		-z noexecstack \

ifeq ($(HOST_UNAME),Darwin)
JNI_FLAGS	+= -I${JAVA_HOME}/include/darwin
JNI_SUFFIX := jnilib
else
ifeq ($(HOST_UNAME),Linux)
JNI_FLAGS	+= -I${JAVA_HOME}/include/linux -fPIC
JNI_SUFFIX := so
else
JNI_SUFFIX := so
endif
endif

JNI_SRCS	:= \
	java/jni/blender_jni.c


# Static build: include module linker-flags in binary
#ifneq ($(STATIC),)
#LFLAGS	+= $(MOD_LFLAGS)
#endif


CONTRIB_PROTOBUF_LIBS := $(shell pkg-config --libs 'libprotobuf-c >= 1.0.0')

LIBS	+=  -lavscore -lrew -lre -lssl -lcrypto -lsodium -lusrsctp -lm -lpthread -ldl

ifeq ($(HOST_UNAME),Linux)
#LIBS   += -lX11 -lXcomposite -lXdamage -lXext -lXfixes -lXrender -levent
endif


BIN	:= $(PROJECT)$(BIN_SUFFIX)

ifeq ($(STATIC),)
MOD_BINS:= $(patsubst %,%.so,$(MODULES))
endif

APP_MK	:= src/srcs.mk

MOD_MK	:= $(patsubst %,modules/%/module.mk,$(MODULES))
MOD_BLD	:= $(patsubst %,$(BUILD)/modules/%,$(MODULES))

include $(APP_MK)
include $(MOD_MK)

OBJS    += \
	$(patsubst %.c,$(BUILD_SRC)/%.o,$(filter %.c,$(SRCS))) \
	$(patsubst %.cpp,$(BUILD_SRC)/%.o,$(filter %.cpp,$(SRCS)))

JNI_OBJS += \
	$(patsubst %.c,$(BUILD)/java/jni/%.o,$(filter %.c,$(JNI_SRCS))) \
	$(patsubst %.cpp,$(BUILD)/java/jni/%.o,$(filter %.cpp,$(JNI_SRCS)))



#
# makefile targets
#


all: contrib $(MOD_BINS) $(BIN)

-include $(OBJS:.o=.d)

$(BIN): $(CONTRIB_USRSCTP_TARGET) $(CONTRIB_AVS_TARGET) $(OBJS)
	@echo "  LD      $@"
	$(CC) $^ $(LFLAGS) -L$(BUILD)/lib -L$(AVS_PATH)/lib $(LIBS) -o $@
#-static -pie

$(BUILD)/%.o: %.c $(BUILD_SRC) Makefile $(APP_MK)
	@echo "  CC      $@"
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $< $(DFLAGS)

$(BUILD)/%.o: %.cpp $(BUILD_SRC) Makefile $(APP_MK)
	@echo "  CXX     $@"
	@$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ -c $< $(DFLAGS)

$(BUILD_SRC): Makefile
	@mkdir -p $(BUILD_SRC) $(MOD_BLD)
	@touch $@

clean:
	@rm -rf $(BIN) $(MOD_BINS) $(BUILD)

distclean: clean contrib_clean

install: $(BIN)
	@mkdir -p $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(BIN) $(DESTDIR)$(BINDIR)

.PHONY: java
java:   
	@mkdir -p $(BUILD)/$(JAVA_CLASSES_DIR)
	$(JAVAC) -d $(BUILD)/$(JAVA_CLASSES_DIR) $(JAVA_SRCS)

.PHONY: jni
jni: 	$(OBJS)
	@mkdir -p $(BUILD)/java/jni
	@echo "  JNI      $@"
	$(CC) $(JNI_FLAGS) -c $(JNI_SRCS) -o $(BUILD)/java/jni/blender_jni.o
	$(CXX) $(JNI_FLAGS) $(CXXFLAGS) $(OBJS) \
		$(BUILD)/java/jni/blender_jni.o \
		-shared \
		-o libblender.$(JNI_SUFFIX) \
		$(LFLAGS) $(APP_LFLAGS)	$(JNI_LIBS) $(LIBS)



src/static.c: $(BUILD) Makefile $(APP_MK) $(MOD_MK)
	@echo "  SH      $@"
	@echo "/* static.c - autogenerated by makefile */"  > $@
	@echo "#include <re_types.h>"  >> $@
	@echo "#include <re_mod.h>"  >> $@
	@echo ""  >> $@
	@for n in $(MODULES); do \
		echo "extern const struct mod_export exports_$${n};" >> $@ ; \
	done
	@echo ""  >> $@
	@echo "const struct mod_export *mod_table[] = {"  >> $@
	@for n in $(MODULES); do \
		echo "  &exports_$${n},"  >> $@  ; \
	done
	@echo "  NULL"  >> $@
	@echo "};"  >> $@

dump:
	@echo "AVS_PATH           = $(AVS_PATH)"
	@echo "DESTDIR            = $(DESTDIR)"
	@echo ""
	@echo "BUILD              = $(BUILD)"
	@echo "TARGET_ARCH        = $(TARGET_ARCH)"
	@echo "CC                 = $(CC)"
	@echo "CXX                = $(CXX)"
	@echo "LD                 = $(LD)"
	@echo "CPPFLAGS (preproc) = $(CPPFLAGS)"
	@echo "CFLAGS =             $(CFLAGS)"
	@echo "CXXFLAGS =           $(CXXFLAGS)"
	@echo ""
	@echo "SRCS = $(SRCS)"
	@echo "OBJS = $(OBJS)"
	@echo "LIBS = $(LIBS)"

version:
	@echo "$(SFT_VERSION)"
