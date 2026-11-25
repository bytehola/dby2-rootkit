#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int write_map(const char *path, const char *text) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "open %s: %s\n", path, strerror(errno));
    return 0;
  }
  ssize_t written = write(fd, text, strlen(text));
  int close_rc = close(fd);
  if (written != (ssize_t)strlen(text) || close_rc != 0) {
    fprintf(stderr, "write %s: %s\n", path, strerror(errno));
    return 0;
  }
  return 1;
}

int main(void) {
  if (unshare(CLONE_NEWUSER) != 0) {
    fprintf(stderr, "unshare(CLONE_NEWUSER): %s\n", strerror(errno));
    return 1;
  }
  if (!write_map("/proc/self/uid_map", "0 2000 1\n")) {
    return 2;
  }
  if (setresuid(0, 0, 0) != 0) {
    fprintf(stderr, "setresuid: %s\n", strerror(errno));
    return 3;
  }
  struct sched_param param;
  memset(&param, 0, sizeof(param));
  param.sched_priority = 50;
  int rc = sched_setscheduler(0, SCHED_FIFO, &param);
  int saved_errno = errno;
  printf("uid=%d euid=%d sched_setscheduler=%d errno=%d (%s)\n", getuid(),
         geteuid(), rc, rc == 0 ? 0 : saved_errno,
         rc == 0 ? "ok" : strerror(saved_errno));
  return rc == 0 ? 0 : 4;
}
