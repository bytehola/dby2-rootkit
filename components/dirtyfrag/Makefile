NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
DIRTYFRAG_SRC ?= native

CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang
CFLAGS := -O2 -g0 -Wall -Wextra -I$(DIRTYFRAG_SRC)

.PHONY: all clean

all: build/df_probe build/uevent_spam

build/df_probe: src/df_probe.c $(DIRTYFRAG_SRC)/aes256.h
	mkdir -p build
	$(CC) $(CFLAGS) $< -o $@

build/uevent_spam: src/uevent_spam.c
	mkdir -p build
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf build
