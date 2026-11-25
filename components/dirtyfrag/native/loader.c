/*
 * Minimal DirtyFrag module loader. It runs from a vendor_file while
 * executing in vendor_modprobe and exposes finit_module's errno in comm.
 */
typedef unsigned long size_t;
typedef long ssize_t;

#define AT_FDCWD (-100L)
#define O_RDONLY 0L
#define PR_SET_NAME 15L
#define SYS_openat 56L
#define SYS_close 57L
#define SYS_nanosleep 101L
#define SYS_finit_module 273L
#define SYS_prctl 167L
#define SYS_exit_group 94L

static const char module_path[] =
    "/vendor/lib64/camera/com.qti.sensor.imx318.so";
static const char name_prefix[] = "dfroot-";

static long sys_call4(long number, long arg0, long arg1, long arg2, long arg3) {
  register long x8 __asm__("x8") = number;
  register long x0 __asm__("x0") = arg0;
  register long x1 __asm__("x1") = arg1;
  register long x2 __asm__("x2") = arg2;
  register long x3 __asm__("x3") = arg3;
  __asm__ volatile("svc #0"
                   : "=r"(x0)
                   : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3)
                   : "memory", "cc");
  return x0;
}

static long sys_call2(long number, long arg0, long arg1) {
  return sys_call4(number, arg0, arg1, 0, 0);
}

static void format_errno(char name[16], int value) {
  for (int index = 0; index < 15; index++) {
    name[index] = 0;
  }
  for (int index = 0; index < 7; index++) {
    name[index] = name_prefix[index];
  }

  name[7] = (char)('0' + (value / 100) % 10);
  name[8] = (char)('0' + (value / 10) % 10);
  name[9] = (char)('0' + value % 10);
  name[10] = 0;
}

void loader_main(void) {
  char name[16];
  long module_fd =
      sys_call4(SYS_openat, AT_FDCWD, (long)module_path, O_RDONLY, 0);
  int result_errno = 0;

  if (module_fd >= 0) {
    long load_result =
        sys_call4(SYS_finit_module, module_fd, (long)"", 0, 0);
    if (load_result < 0) {
      result_errno = (int)-load_result;
    }
    sys_call2(SYS_close, module_fd, 0);
  } else {
    result_errno = (int)-module_fd;
  }

  format_errno(name, result_errno);
  sys_call4(SYS_prctl, PR_SET_NAME, (long)name, 0, 0);

  for (;;) {
    struct {
      long seconds;
      long nanoseconds;
    } interval = {30, 0};
    sys_call2(SYS_nanosleep, (long)&interval, 0);
  }
}

__attribute__((naked)) void _start(void) {
  __asm__ volatile(
      "bl loader_main\n"
      "mov x0, #0\n"
      "mov x8, #94\n"
      "svc #0\n");
}
