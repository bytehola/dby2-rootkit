#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$PROJECT_DIR/../../.." && pwd)"

NDK_ROOT="${NDK_ROOT:-$REPO_DIR/tmp/huawe-root/build/android-ndk-r29}"
NDK_CC="${NDK_CC:-$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang}"
QEMU_ROOT="${QEMU_ROOT:-/tmp/dby2-qemu-root}"
QEMU="${QEMU:-$QEMU_ROOT/usr/bin/qemu-system-aarch64}"
KERNEL_IMAGE="${KERNEL_IMAGE:-$REPO_DIR/tmp/huawe-root/build/target-lto-src/arch/arm64/boot/Image}"
KERNEL_BASE="${KERNEL_BASE:-}"
OUT_DIR="${OUT_DIR:-/tmp/dby2-qemu-run}"
MODE="${MODE:---verify-safe --detach --mcast-waiter-off 0xc0}"
SMP="${SMP:-4}"
MEMORY="${MEMORY:-2048}"
CPU_MODEL="${CPU_MODEL:-cortex-a72}"
GDB_PORT="${GDB_PORT:-}"
GDB_WAIT="${GDB_WAIT:-0}"

if [[ ! -x "$NDK_CC" ]]; then
  echo "missing Android NDK compiler: $NDK_CC" >&2
  exit 1
fi
if [[ ! -f "$KERNEL_IMAGE" ]]; then
  echo "missing kernel Image: $KERNEL_IMAGE" >&2
  exit 1
fi
if [[ ! -x "$QEMU" ]]; then
  echo "missing QEMU binary: $QEMU" >&2
  exit 1
fi

mkdir -p "$OUT_DIR/root"

"$NDK_CC" -static -O2 -g0 -Wall -Wextra \
  -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -I"$PROJECT_DIR/src" -DTARGET_CONFIG_H='"target.h"' \
  "$PROJECT_DIR/src/main.c" \
  "$PROJECT_DIR/src/util.c" \
  "$PROJECT_DIR/src/slide.c" \
  "$PROJECT_DIR/src/su.c" \
  "$PROJECT_DIR/src/perf.c" \
  "$PROJECT_DIR/src/main_exe.c" \
  -o "$OUT_DIR/root/ghostlock_exe" -pthread

"$NDK_CC" -static -O2 -g0 -Wall -Wextra \
  "$SCRIPT_DIR/qemu_init.c" \
  -o "$OUT_DIR/root/init"

printf '%s\n' "$MODE" >"$OUT_DIR/root/glmode"
if [[ "${SKIP_SYSCTL:-0}" == "1" ]]; then
  touch "$OUT_DIR/root/glskip_sysctl"
else
  rm -f "$OUT_DIR/root/glskip_sysctl"
fi
if [[ -n "$KERNEL_BASE" ]]; then
  printf '%s\n' "$KERNEL_BASE" >"$OUT_DIR/root/glbase"
else
  rm -f "$OUT_DIR/root/glbase"
fi

chmod 0755 "$OUT_DIR/root/init" "$OUT_DIR/root/ghostlock_exe"
(
  cd "$OUT_DIR/root"
  find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9
) >"$OUT_DIR/initramfs.cpio.gz"

export LD_LIBRARY_PATH="$QEMU_ROOT/usr/lib/x86_64-linux-gnu:$QEMU_ROOT/lib/x86_64-linux-gnu"
export QEMU_DATADIR="$QEMU_ROOT/usr/share/qemu"

gdb_arguments=()
if [[ -n "$GDB_PORT" ]]; then
  gdb_arguments=(-gdb "tcp:127.0.0.1:${GDB_PORT}")
fi
if [[ "$GDB_WAIT" == "1" ]]; then
  gdb_arguments+=(-S)
fi

exec "$QEMU" \
  -machine virt \
  -nodefaults \
  -cpu "$CPU_MODEL" \
  -smp "$SMP" \
  -m "$MEMORY" \
  -kernel "$KERNEL_IMAGE" \
  -initrd "$OUT_DIR/initramfs.cpio.gz" \
  -append "nokaslr rdinit=/init earlycon=pl011,0x09000000 keep_bootcon console=ttyAMA0 loglevel=7 panic=0 printk.devkmsg=on initcall_blacklist=proc_app_info_init,msm_restart_init,scm_mem_protection_init,trace_event_init,event_trace_init,perf_event_init,perf_event_sysfs_init,tracer_init_tracefs,event_trace_self_tests_init,ftrace_test_event_filter,init_kprobe_trace,init_uprobe_trace,trace_events_hist_init,init_trace_printk_function_export,init_graph_tracefs,kernel_stp_module_init,checkroot_init,storage_rochk_misc_init,init_f2fs_fs" \
  -display none \
  -serial stdio \
  "${gdb_arguments[@]}" \
  -no-reboot
