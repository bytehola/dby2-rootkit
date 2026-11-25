/* QEMU-only overrides for the bootable non-LTO DBY2 kernel image. */
#ifndef QEMU_TARGET_H
#define QEMU_TARGET_H

#include "target.h"

#undef SLIDE_INIT_TASK_IMAGE
#define SLIDE_INIT_TASK_IMAGE 0xffffffc01292a340ULL

#undef SLIDE_EMPTY_ZERO_PAGE_IMAGE
#define SLIDE_EMPTY_ZERO_PAGE_IMAGE 0xffffffc012c2a000ULL

#endif
