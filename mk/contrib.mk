#
# Makefile Snippet for Third-party Libraries
#
#
# This snippet allows building all the third-party libraries that are
# contained in this here repository.
#
# The snippet has a main target "contrib" that builds all the libraries
# for the current configuration. However, there is normally no need to
# use this target. All the other bits and bops have dependencies on the
# libraries they need, so by building them you'll also build those
# contrib libraries necessary.
#
# The rules for all the contrib libraries follow a similar pattern: For
# each library there is a CONTRIB_<library>_TARGET that either points to
# the static library or, in case of OpenSSL where there is two, a stamp
# file. This target depends on CONTRIB_<library>_FILES. This one is
# collected by running "git ls-files" over the sources to ensure that
# the library is rebuilt if the sources change.
#
# Because of this it is very important that when upgrading a contrib
# library to make sure that none of the files that change upon each
# rebuild are checked into git. The source distribution may contain such
# files, so carefully weed them all out. Also make sure that
# contrib/.gitignore contains all files produced by the build process.
#
# When using the contrib libraries, add $(CONTRIB_<library>_TARGET) to
# your object dependencies. The linker flags for linking with the
# libraries are in $(CONTRIB_<library>_LIBS) and a list of the static
# libraries complete with correct path in $(CONTRIB_<library>_LIB_FILES).
#
# Currently, no other argument variables are being defined. That may
# change later.
#
# The include files are all installed into build/$(AVS_PAIR)/include as
# if that were /usr/include. The $(CPPFLAGS) already contain an -I flag
# for this path, so you should be all set.
#


JOBS	:= -j8

CONTRIB_PARTS := USRSCTP AVS

CONTRIB_BASE := $(shell pwd)/contrib
FULL_BUILD := $(shell pwd)/$(BUILD)

CONTRIB_INCLUDE_PATH := $(CONTRIB_BASE)/include

#--- usrsctp ---

CONTRIB_USRSCTP_PATH := $(CONTRIB_BASE)/usrsctp
CONTRIB_USRSCTP_BUILD_PATH := $(BUILD)/usrsctp
CONTRIB_USRSCTP_CONFIG_TARGET := $(CONTRIB_USRSCTP_PATH)/configure
CONTRIB_USRSCTP_TARGET := $(BUILD)/lib/libusrsctp.a
CONTRIB_USRSCTP_FILES := $(shell git ls-files $(CONTRIB_USRSCTP_PATH))

CONTRIB_USRSCTP_LIBS := -Lcontrib/usrsctp -lusrsctp
CONTRIB_USRSCTP_LIB_FILES := $(CONTRIB_USRSCTP_TARGET)

CONTRIB_USRSCTP_CFLAGS := -I$(CONTRIB_USRSCTP_PATH)
ifeq ($(AVS_OS),ios)
CONTRIB_USRSCTP_CFLAGS += -I$(CONTRIB_INCLUDE_PATH)/ios
endif


$(CONTRIB_USRSCTP_CONFIG_TARGET):
	cd $(CONTRIB_USRSCTP_PATH) && \
	./bootstrap


CONTRIB_USRSCTP_OPTIONS := \
	--disable-inet --disable-inet6 \
	--enable-static \
	--enable-shared=no \
	--enable-warnings-as-errors=no


$(CONTRIB_USRSCTP_TARGET): $(TOOLCHAIN_MASTER) $(CONTRIB_USRSCTP_CONFIG_TARGET) $(CONTRIB_USRSCTP_DEPS) $(CONTRIB_USRSCTP_FILES)
	@rm -rf $(CONTRIB_USRSCTP_BUILD_PATH)
	@mkdir -p $(CONTRIB_USRSCTP_BUILD_PATH)
	@mkdir -p $(BUILD)/include/usrsctplib
	cd $(CONTRIB_USRSCTP_BUILD_PATH) && \
		CC="$(CC)" \
		CXX="$(CXX)" \
		RANLIB="$(RANLIB)" \
		AR="$(AR)" \
		CFLAGS="$(CPPFLAGS) $(CFLAGS) $(CONTRIB_USRSCTP_CFLAGS)" \
		CXXFLAGS="$(CPPFLAGS) $(CXXFLAGS)" \
		LDFLAGS="$(CONTRIB_USRSCTP_LDFLAGS)" \
		$(CONTRIB_USRSCTP_PATH)/configure \
			$(CONTRIB_USRSCTP_OPTIONS) \
			--prefix="$(FULL_BUILD)" \
			$(HOST_OPTIONS)
		$(MAKE) -C $(CONTRIB_USRSCTP_BUILD_PATH) clean
	$(MAKE) $(JOBS) -C $(CONTRIB_USRSCTP_BUILD_PATH)/usrsctplib
	$(MAKE) -C $(CONTRIB_USRSCTP_BUILD_PATH)/usrsctplib install
	@mv $(FULL_BUILD)/include/usrsctp.h \
			$(FULL_BUILD)/include/usrsctplib
#--- avs ---

CONTRIB_AVS_PATH := $(CONTRIB_BASE)/avs
CONTRIB_AVS_BUILD_PATH := $(AVS_PATH)
CONTRIB_AVS_TARGET := $(AVS_PATH)/lib/libavscore.a

$(CONTRIB_AVS_TARGET): $(TOOLCHAIN_MASTER)
	@make -C $(AVS_DIR) HAVE_WEBRTC= NO_OPENSSL=1 dist_host

.PHONY: contrib_avs
contrib_avs: $(CONTRIB_AVS_TARGET)

#--- Phony Targets ---

.PHONY: contrib contrib_clean
contrib: $(foreach part,$(CONTRIB_PARTS),$(CONTRIB_$(part)_TARGET))
contrib_clean:
	@rm -rf $(BUILD)
	@make -C contrib/avs distclean


