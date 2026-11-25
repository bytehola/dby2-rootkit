#define _GNU_SOURCE

#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static void write_text_file(const char *path, const char *text) {
  int fd = open(path, O_WRONLY);
  if (fd < 0) {
    return;
  }
  (void)!write(fd, text, strlen(text));
  close(fd);
}

static void mount_guest_filesystems(void) {
  mkdir("/proc", 0755);
  mkdir("/dev", 0755);
  mkdir("/data", 0755);
  mkdir("/data/local", 0755);
  mkdir("/data/local/tmp", 0777);
  (void)mount("proc", "/proc", "proc", 0, NULL);
  (void)mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
  (void)mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
  (void)mknod("/dev/kmsg", S_IFCHR | 0666, makedev(1, 11));
  (void)mknod("/dev/random", S_IFCHR | 0666, makedev(1, 8));
  (void)mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9));
  (void)chmod("/dev/kmsg", 0666);
}

static void configure_kernel_logging(void) {
  if (access("/glskip_sysctl", F_OK) == 0) {
    return;
  }
  write_text_file("/proc/sys/kernel/perf_event_paranoid", "-1\n");
  write_text_file("/proc/sys/kernel/printk_devkmsg", "on\n");
}

static void redirect_standard_fds(void) {
  int null_fd = open("/dev/null", O_RDWR);
  if (null_fd < 0) {
    return;
  }
  (void)dup2(null_fd, STDIN_FILENO);
  (void)dup2(null_fd, STDOUT_FILENO);
  (void)dup2(null_fd, STDERR_FILENO);
  if (null_fd > STDERR_FILENO) {
    close(null_fd);
  }
}

static int read_kernel_base(char *buffer, size_t buffer_size) {
  int fd = open("/glbase", O_RDONLY);
  if (fd < 0) {
    return 0;
  }
  ssize_t length = read(fd, buffer, buffer_size - 1);
  close(fd);
  if (length <= 0) {
    return 0;
  }
  buffer[length] = '\0';
  buffer[strcspn(buffer, "\r\n")] = '\0';
  return buffer[0] != '\0';
}

static void read_guest_mode(char *buffer, size_t buffer_size) {
  snprintf(buffer, buffer_size, "--verify-safe");
  int fd = open("/glmode", O_RDONLY);
  if (fd < 0) {
    return;
  }
  ssize_t length = read(fd, buffer, buffer_size - 1);
  close(fd);
  if (length <= 0) {
    snprintf(buffer, buffer_size, "--verify-safe");
    return;
  }
  buffer[length] = '\0';
  buffer[strcspn(buffer, "\r\n")] = '\0';
}

static void log_completion(const char *mode, int status) {
  int fd = open("/dev/kmsg", O_WRONLY);
  if (fd < 0) {
    return;
  }
  char message[160];
  int length = snprintf(message, sizeof(message),
                        "qemu-init: %s exited status=%#x%s\n",
                        mode, status,
                        WIFEXITED(status) && WEXITSTATUS(status) == 0
                            ? " (SUCCESS)"
                            : "");
  if (length > 0) {
    (void)!write(fd, message, (size_t)length);
  }
  close(fd);
}

int main(int argc, char **argv) {
  mount_guest_filesystems();
  configure_kernel_logging();

  char kernel_base[64];
  int have_kernel_base = read_kernel_base(kernel_base, sizeof(kernel_base));
  char mode[256];
  read_guest_mode(mode, sizeof(mode));

  pid_t child = fork();
  if (child == 0) {
    gid_t shell_groups[1] = {3003};
    (void)setgroups(1, shell_groups);
    (void)setgid(2000);
    (void)setuid(2000);
    cpu_set_t parent_cpu;
    CPU_ZERO(&parent_cpu);
    CPU_SET(0, &parent_cpu);
    (void)sched_setaffinity(0, sizeof(parent_cpu), &parent_cpu);

    char *exploit_argv[32];
    int argument_count = 0;
    exploit_argv[argument_count++] = "/ghostlock_exe";
    char *mode_cursor = mode;
    char *mode_token = NULL;
    while ((mode_token = strsep(&mode_cursor, " \t")) != NULL &&
           argument_count < 20) {
      if (mode_token[0] != '\0') {
        exploit_argv[argument_count++] = mode_token;
      }
    }
    exploit_argv[argument_count++] = "--probe-cycle";
    exploit_argv[argument_count++] = "--attempts";
    exploit_argv[argument_count++] = "1";
    if (have_kernel_base) {
      exploit_argv[argument_count++] = "--kaslr-base";
      exploit_argv[argument_count++] = kernel_base;
    }
    exploit_argv[argument_count++] = "--log-file";
    exploit_argv[argument_count++] = "/dev/kmsg";
    exploit_argv[argument_count] = NULL;
    char *environment[] = {NULL};
    execve(exploit_argv[0], exploit_argv, environment);
    _exit(127);
  }

  int status = 0;
  if (child > 0) {
    (void)waitpid(child, &status, 0);
    log_completion(mode, status);
  }
  for (;;) {
    pause();
  }
}
