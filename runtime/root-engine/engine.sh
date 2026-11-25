#!/usr/bin/env bash
set -euo pipefail

adb_path="${ADB:-}"
target_serial="${SERIAL:-}"
profile_id="${DBY2_PROFILE_ID:-unknown}"
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runtime_engine="${DBY2_RUNTIME_ENGINE:-${project_root}/components/root-engine/dby2-root.sh}"

if [ -z "${adb_path}" ]; then
  echo "RUNTIME_ADB_MISSING" >&2
  exit 2
fi

if [ -z "${target_serial}" ]; then
  echo "RUNTIME_SERIAL_MISSING" >&2
  exit 2
fi

adb_shell() {
  "${adb_path}" -s "${target_serial}" shell "$@"
}

mark_boot_session() {
  adb_shell \
    "/system/bin/su -c 'mkdir -p /data/adb/dby2 && chmod 700 /data/adb/dby2 && cat /proc/sys/kernel/random/boot_id > /data/adb/dby2/boot_id && chmod 600 /data/adb/dby2/boot_id'" \
    >/dev/null
}

device_model="$(adb_shell getprop ro.product.model | tr -d '\r' | tr -d '\n')"
if [ "${device_model}" != "DBY2-W00" ]; then
  echo "RUNTIME_DEVICE_MISMATCH model=${device_model}" >&2
  exit 5
fi

root_identity="$(
  adb_shell '/system/bin/su -c id' 2>/dev/null |
    tr -d '\r' |
    head -n 1
)" || true
if printf '%s\n' "${root_identity}" | grep -q 'uid=0(root)'; then
  mark_boot_session
  echo "ROOT_ALREADY_ACTIVE profile=${profile_id}"
  echo "BOOT_SESSION_MARKED"
  exit 0
fi

if [ ! -f "${runtime_engine}" ]; then
  echo "RUNTIME_PAYLOAD_MISSING path=${runtime_engine}" >&2
  exit 2
fi

export ADB="${adb_path}"
export SERIAL="${target_serial}"
export DBY2_PROFILE_ID="${profile_id}"
set +e
bash "${runtime_engine}"
engine_status=$?
set -e

if [ "${engine_status}" -eq 0 ]; then
  mark_boot_session
  echo "BOOT_SESSION_MARKED"
fi

exit "${engine_status}"
