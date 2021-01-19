#
# libavs -- Build System
#
# Set up build system for $(TARGET)
#
# Valid targets are:
#
#    android        - android ARMv7
#    iosarmv7       - iOS ARMv7
#    iosarmv7s      - iOS ARMv7s
#    iosarm64       - iOS ARM64
#    iossim32       - iOS Simulator 32 bit
#    iossim64       - iOS Simulator 64 bit
#    linux          - GNU/Linux amd64
#    osx            - OSX amd64
#
# Use the fatios.sh script to create the multitarget iOS output.
#
# The linux target serves as a fallback for any other Unix sytem. That
# may or may not work.
#


XCRUN	:= xcrun


# Determine the host system target. We may or may not need it.
#
HOST_UNAME := $(shell uname)
ifeq ($(HOST_UNAME),Darwin)
HOST_TARGET := osx
else
HOST_TARGET := linux
endif

# $(OUTPUT) is set only if you give $(TARGET) explicitely. Otherwise we
# just dump everything into the root directory.
#
ifneq ($(TARGET),)
OUTPUT := build/output/$(TARGET)
DESTDIR := build/dest/$(TARGET)
PREFIX :=
else
OUTPUT := .
endif

# If no $(TARGET) is given, we fall back to the host target.
#
ifeq ($(TARGET),)
TARGET := $(HOST_TARGET)
endif

COMPONENT_TARGET := $(TARGET)

# Android
#
# Needs $(ANDROID_TOOLCHAIN) and $(ANDROID_NDK_ROOT)
#
# XXX Warn if $(ANDROID_TOOLCHAIN) and $(ANDROID_NDK_ROOT) aren't set.
#
ifeq ($(TARGET),android)

BASE_TARGET  := android
CROSS_PREFIX := $(ANDROID_TOOLCHAIN)/bin/arm-linux-androideabi-
CC           := $(ANDROID_TOOLCHAIN)/bin/clang
CPP          := $(CROSS_PREFIX)cpp
CXX          := $(ANDROID_TOOLCHAIN)/bin/clang++
CXXCPP       := $(ANDROID_TOOLCHAIN)/bin/clang++
LD           := $(ANDROID_TOOLCHAIN)/bin/clang++
AR           := $(CROSS_PREFIX)ar
RANLIB       := $(CROSS_PREFIX)ranlib
SYSROOT      := $(ANDROID_NDK_ROOT)/platforms/android-14/arch-arm/usr
NDK_SOURCES  := $(ANDROID_NDK_ROOT)/sources


CFLAGS	+= \
	-fvisibility=default -Os \
	-march=armv7-a -mfpu=neon -mfloat-abi=softfp -mcpu=cortex-a8 \
	-D__ARM_ARCH_7__ -D__ARM_ARCH_7A__ -D__ARM_NEON__ \
	-fPIC \
	-ffunction-sections -funwind-tables \
	-fstack-protector -fno-short-enums \
	-fomit-frame-pointer -fno-strict-aliasing \
	-DANDROID -D__ANDROID__ -U__STRICT_ANSI__ \
	-Wno-strict-prototypes -Wno-nested-externs \
	-Wno-shadow -Wno-cast-align \
	-I$(NDK_SOURCES)/cxx-stl/llvm-libc++abi/libcxxabi/include \
	-I$(NDK_SOURCES)/cpufeatures
LFLAGS	+= \
	-nostdlib -Wl,-soname,libtwolib-second.so \
	-Wl,--whole-archive \
	-Wl,--no-undefined \
	-L$(SYSROOT)/lib
LIBS 	+= \
	-lcpufeatures -lc -lm -lgcc

endif


# iosarmv7
#
ifeq ($(TARGET),iosarmv7)

BASE_TARGET  := ios
SDK	:= $(shell $(XCRUN) --show-sdk-path --sdk iphoneos)
CC	:= $(shell $(XCRUN) --sdk iphoneos -f clang)
CXX	:= $(shell $(XCRUN) --sdk iphoneos -f clang++)
CXXCPP	:= $(shell $(XCRUN) --sdk iphoneos -f clang++)
LD	:= $(shell $(XCRUN) --sdk iphoneos -f clang++)
AR	:= $(shell $(XCRUN) --sdk iphoneos -f ar)
RANLIB	:= $(shell $(XCRUN) --sdk iphoneos -f ranlib)
SYSROOT	:= $(SDK)/usr

CFLAGS	+= \
	-fvisibility=default -Os \
	-arch armv7 \
	-DIPHONE \
	-pipe -no-cpp-precomp \
	-isysroot $(SDK)
OCFLAGS	+= \
	-fobjc-arc
LFLAGS	+= \
	-arch armv7 \
	-no-cpp-precomp -isysroot $(SDK)
LIBS	+= \
	-lz
COMPONENT_TARGET := ios

endif


# iosarmv7s
#
ifeq ($(TARGET),iosarmv7s)

BASE_TARGET  := ios
SDK	:= $(shell $(XCRUN) --show-sdk-path --sdk iphoneos)
CC	:= $(shell $(XCRUN) --sdk iphoneos -f clang)
CXX	:= $(shell $(XCRUN) --sdk iphoneos -f clang++)
CXXCPP	:= $(shell $(XCRUN) --sdk iphoneos -f clang++)
LD	:= $(shell $(XCRUN) --sdk iphoneos -f clang++)
AR	:= $(shell $(XCRUN) --sdk iphoneos -f ar)
RANLIB	:= $(shell $(XCRUN) --sdk iphoneos -f ranlib)
SYSROOT	:= $(SDK)/usr

CFLAGS	+= \
	-fvisibility=default -Os \
	-arch armv7s \
	-DIPHONE \
	-pipe -no-cpp-precomp \
	-isysroot $(SDK)
OCFLAGS	+= \
	-fobjc-arc
LFLAGS	+= \
	-arch armv7 \
	-no-cpp-precomp -isysroot $(SDK)
LIBS	+= \
	-lz

COMPONENT_TARGET := ios

endif


# iosarm64
#
ifeq ($(TARGET),iosarm64)

BASE_TARGET  := ios
SDK	:= $(shell $(XCRUN) --show-sdk-path --sdk iphoneos)
CC	:= $(shell $(XCRUN) --sdk iphoneos -f clang)
CXX	:= $(shell $(XCRUN) --sdk iphoneos -f clang++)
CXXCPP	:= $(shell $(XCRUN) --sdk iphoneos -f clang++)
LD	:= $(shell $(XCRUN) --sdk iphoneos -f clang++)
AR	:= $(shell $(XCRUN) --sdk iphoneos -f ar)
RANLIB	:= $(shell $(XCRUN) --sdk iphoneos -f ranlib)
SYSROOT	:= $(SDK)/usr

CFLAGS	+= \
	-fvisibility=default -Os \
	-arch arm64 \
	-DIPHONE \
	-pipe -no-cpp-precomp \
	-isysroot $(SDK)
OCFLAGS	+= \
	-fobjc-arc
LFLAGS	+= \
	-arch armv7 \
	-no-cpp-precomp -isysroot $(SDK)
LIBS	+= \
	-lz

COMPONENT_TARGET := ios

endif


# iossim32
#
ifeq ($(TARGET),iossim32)

BASE_TARGET  := ios
SDK	:= $(shell $(XCRUN) --show-sdk-path --sdk iphonesimulator)
CC	:= $(shell $(XCRUN) --sdk iphonesimulator -f clang)
CXX	:= $(shell $(XCRUN) --sdk iphonesimulator -f clang++)
CXXCPP	:= $(shell $(XCRUN) --sdk iphonesimulator -f clang++)
LD	:= $(shell $(XCRUN) --sdk iphonesimulator -f clang++)
AR	:= $(shell $(XCRUN) --sdk iphonesimulator -f ar)
RANLIB	:= $(shell $(XCRUN) --sdk iphonesimulator -f ranlib)
SYSROOT	:= $(SDK)/usr

CFLAGS	+= \
	-fvisibility=default -Os \
	-arch i386 \
	-DIPHONE \
	-pipe -no-cpp-precomp \
	-miphoneos-version-min=7.0 \
	-isysroot $(SDK)
OCFLAGS	+= \
	-fobjc-arc
LFLAGS	+= \
	-arch i386 \
	-miphoneos-version-min=7.0 \
	-isysroot $(SDK)
LIBS	+= \
	-lz

COMPONENT_TARGET := ios

endif


# iossim64
#
ifeq ($(TARGET),iossim64)

BASE_TARGET  := ios
SDK	:= $(shell $(XCRUN) --show-sdk-path --sdk iphonesimulator)
CC	:= $(shell $(XCRUN) --sdk iphonesimulator -f clang)
CXX	:= $(shell $(XCRUN) --sdk iphonesimulator -f clang++)
CXXCPP	:= $(shell $(XCRUN) --sdk iphonesimulator -f clang++)
LD	:= $(shell $(XCRUN) --sdk iphonesimulator -f clang++)
AR	:= $(shell $(XCRUN) --sdk iphonesimulator -f ar)
RANLIB	:= $(shell $(XCRUN) --sdk iphonesimulator -f ranlib)
SYSROOT	:= $(SDK)/usr

CFLAGS	+= \
	-fvisibility=default -Os \
	-arch x86_64 \
	-DIPHONE \
	-pipe -no-cpp-precomp \
	-miphoneos-version-min=7.0 \
	-isysroot $(SDK)
OCFLAGS	+= \
	-fobjc-arc
LFLAGS	+= \
	-arch x86_64 \
	-miphoneos-version-min=7.0 \
	-isysroot $(SDK)
LIBS	+= \
	-lz

COMPONENT_TARGET := ios

endif


# Linux
#
ifeq ($(TARGET),linux)

BASE_TARGET  := linux
SUFFIX	:= linux
CC	:= /usr/bin/clang
CPP	:= /usr/bon/cpp
CXX	:= /usr/bin/clang++
CXXCPP	:= /usr/bin/clang++
LD	:= /usr/bin/clang++
AR	:= /usr/bin/ar
RANLIB	:= /usr/bin/ranlib
SYSROOT	:= /usr

CFLAGS		+= -fvisibility=default -Os
CXXFLAGS	+= -stdlib=libc++
LFLAGS		+= -stdlib=libc++

#LIBS += -lc++abi

endif


# osx
#
ifeq ($(TARGET),osx)

BASE_TARGET  := osx
SDK	:= $(shell $(XCRUN) --show-sdk-path --sdk macosx)
CC	:= $(shell $(XCRUN) --sdk macosx -f clang)
CXX	:= $(shell $(XCRUN) --sdk macosx -f clang++)
CXXCPP	:= $(shell $(XCRUN) --sdk macosx -f clang++)
LD	:= $(shell $(XCRUN) --sdk macosx -f clang++)
AR	:= $(shell $(XCRUN) --sdk macosx -f ar)
RANLIB	:= $(shell $(XCRUN) --sdk macosx -f ranlib)
SYSROOT	:= $(SDK)/usr

CFLAGS	+= \
	-fvisibility=default -Os \
	-pipe -no-cpp-precomp \
	-isysroot $(SDK)
OCFLAGS	+= \
	-fobjc-arc
LFLAGS	+= \
	-no-cpp-precomp -isysroot $(SDK) \
	-framework SystemConfiguration -framework CoreFoundation
LIBS	+= \
	-lz

TEST_LIBS += \
	     -framework Foundation \
             -framework CoreFoundation \
             -framework CoreAudio \
	     -framework AudioUnit \
             -framework CoreVideo \
             -framework AudioToolbox \
             -framework AudioUnit \
             -framework CoreGraphics \
             -framework Cocoa \
             -framework OpenGL \
             -framework QTKit \
             -framework IOKit

endif

# Something for all platforms
#
CXXFLAGS := $(CXXFLAGS) $(CFLAGS)
