obj-m := dfroot_boot.o

HELPER_PATH ?= /data/local/tmp/dfroot-stage2

CFLAGS_dfroot_boot.o := -Os -fno-addrsig \
	-fno-asynchronous-unwind-tables -fno-unwind-tables
ccflags-y += -DDFROOT_HELPER_PATH=\"$(HELPER_PATH)\"
