NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
NDK_TOOLCHAIN := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64
CC := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android30-clang
STRIP := $(NDK_TOOLCHAIN)/bin/llvm-strip

CFLAGS := -O2 -g0 -Wall -Wextra -Wno-unused-parameter

.PHONY: all clean

all: build/libdfroot.so build/dfroot-stage2

build/dfroot-stage2: stage2.c
	mkdir -p build
	$(CC) --target=aarch64-linux-android30 \
		--sysroot=$(NDK_TOOLCHAIN)/sysroot \
		-O2 -Wall -Wextra -nostdlib -static -ffreestanding $< -o $@
	$(STRIP) $@

build/loader: loader.c loader.ld
	mkdir -p build
	$(CC) --target=aarch64-linux-android30 \
		--sysroot=$(NDK_TOOLCHAIN)/sysroot \
		-O2 -Wall -Wextra -nostdlib -static -ffreestanding \
		-Wl,-T,loader.ld -Wl,-z,max-page-size=4096 \
		-Wl,--build-id=none $< -o $@.elf
	$(NDK_TOOLCHAIN)/bin/llvm-objcopy --strip-sections $@.elf $@

build/splicehelper: splicehelper.c
	mkdir -p build
	$(CC) --target=aarch64-linux-android30 \
		--sysroot=$(NDK_TOOLCHAIN)/sysroot \
		-O2 -Wall -Wextra -nodefaultlibs -nostartfiles \
		-ffreestanding -static $< -o $@
	$(STRIP) $@

build/libdfroot.so: exp.c libcxx.S elf_parser.c aes256.h include.inc ko_select.h \
		build/splicehelper build/loader ko/dfroot-android11-5.4.ko
	mkdir -p build
	cp build/splicehelper splicehelper
	cp build/loader loader
	$(CC) $(CFLAGS) -I. -fPIE -pie exp.c libcxx.S elf_parser.c \
		-o $@ -Wl,-z,max-page-size=16384

clean:
	rm -rf build
