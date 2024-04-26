TARGET=Hello-World
ANDROID_NDK_ROOT=/home/kali/SDK/ndk/21.3.6528147
ANDROID_API_VERSION=21

ifeq ($(findstring arm, $(ARCH)), arm)
CC=$(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
CFLAGS=-target aarch64-linux-android$(ANDROID_API_VERSION)
LDFLAGS=$(CFLAGS)
endif

ifeq ($(ARCH), arm32)
CFLAGS+= -m32
endif

all: $(TARGET)

$(TARGET): $(TARGET).o

clean:
	rm -f $(TARGET) *.o
