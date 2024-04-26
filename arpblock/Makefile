TARGET=arpblock
ANDROID_NDK_ROOT=/home/kali/SDK/ndk/21.3.6528147
ANDROID_API_VERSION=21

LDLIBS=-lpcap

ifeq ($(findstring arm, $(ARCH)), arm)
CC=$(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
CFLAGS=-target aarch64-linux-android$(ANDROID_API_VERSION) -I./sysroot/include/
LDFLAGS=-target aarch64-linux-android$(ANDROID_API_VERSION) -L./sysroot/lib/
endif

all: $(TARGET)

$(TARGET): $(TARGET).o

clean:
	rm -f $(TARGET) *.o
