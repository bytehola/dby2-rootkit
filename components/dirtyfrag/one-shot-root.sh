#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADB="${ADB:-adb}"
SERIAL="${SERIAL:-}"
DEVICE_DIR="/data/local/tmp"
DEVICE_STAGE2="${DEVICE_DIR}/dfroot-stage2"
DEVICE_SU="${DEVICE_DIR}/dfroot-su"
DEVICE_GHOSTLOCK="${DEVICE_DIR}/glksu-avc/ghostlock_ksu"
MODULE_SLOT="${DEVICE_DIR}/df-module-oneshot.slot"
MODULE_LOG="${DEVICE_DIR}/df-module-oneshot.log"

adb_device() {
  "${ADB}" -s "${SERIAL}" shell "$@"
}

adb_source_path() {
  local source_path
  source_path="$(realpath "$1")"
  if [[ "${ADB,,}" == *.exe ]] && command -v wslpath >/dev/null 2>&1; then
    wslpath -w "${source_path}"
  else
    printf '%s\n' "${source_path}"
  fi
}

wait_for_device() {
  local candidate
  for _ in $(seq 1 90); do
    if [ -z "${SERIAL}" ]; then
      SERIAL="$("${ADB}" devices | tr -d '\r' |
        awk 'NR > 1 && $2 == "device" { print $1; exit }')"
    fi
    for candidate in "${SERIAL}"; do
      [ -n "${candidate}" ] || continue
      state="$("${ADB}" -s "${candidate}" get-state 2>/dev/null | tr -d '\r' || true)"
      if [ "${state}" = "device" ]; then
        SERIAL="${candidate}"
        return 0
      fi
    done
    sleep 2
  done
  echo "等待 ADB 设备超时" >&2
  return 1
}

push_with_retry() {
  local source_path="$1"
  local destination_path="$2"
  local adb_source
  adb_source="$(adb_source_path "${source_path}")"
  for _ in $(seq 1 30); do
    wait_for_device
    if "${ADB}" -s "${SERIAL}" push "${adb_source}" "${destination_path}" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_module_prep() {
  for _ in $(seq 1 60); do
    wait_for_device
    if adb_device "grep -q 'module-prep: signature and load-data policy checks cleared' \
      '${MODULE_LOG}'" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_bootstrap() {
  for _ in $(seq 1 60); do
    wait_for_device
    if adb_device "test -f /dev/dfroot-ok" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_device

if [ ! -f "${ROOT_DIR}/build/harness-apk/DBY2DirtyFrag.apk" ] ||
   [ ! -f "${ROOT_DIR}/native/build/dfroot-stage2" ] ||
   [ ! -f "${ROOT_DIR}/native/dfroot-su.sh" ]; then
  echo "缺少构建产物" >&2
  exit 1
fi

if ! adb_device "test -x '${DEVICE_GHOSTLOCK}'"; then
  echo "设备上缺少 GhostLock：${DEVICE_GHOSTLOCK}" >&2
  exit 1
fi

if [ "${ALLOW_TRIGGERED:-0}" != "1" ] && adb_device "test -e /dev/df"; then
  echo "当前 boot 已触发过 DirtyFrag，请先重启平板" >&2
  exit 1
fi

echo "[1/5] 部署 DirtyFrag 与 root broker"
dirtyfrag_apk="$(adb_source_path "${ROOT_DIR}/build/harness-apk/DBY2DirtyFrag.apk")"
"${ADB}" -s "${SERIAL}" install --no-incremental -r \
  "${dirtyfrag_apk}" >/dev/null
push_with_retry "${ROOT_DIR}/native/build/dfroot-stage2" "${DEVICE_STAGE2}"
push_with_retry "${ROOT_DIR}/native/dfroot-su.sh" "${DEVICE_SU}"
adb_device "chmod 755 '${DEVICE_STAGE2}' '${DEVICE_SU}'"

echo "[2/5] 关闭模块签名检查"
adb_device "rm -f '${MODULE_SLOT}' '${MODULE_LOG}'"
adb_device "touch '${MODULE_SLOT}'; chmod 666 '${MODULE_SLOT}'"
if ! adb_device "${DEVICE_GHOSTLOCK} --module-prep --detach --probe-cycle \
  --spin-park --no-rt --runtime-cpu 6 --attempts 1 \
  --slot-file '${MODULE_SLOT}' --log-file '${MODULE_LOG}' --fsync"; then
  echo "module-prep 期间 ADB 短暂中断，等待设备恢复"
fi
wait_for_module_prep

echo "[3/5] 触发 DirtyFrag"
wait_for_device
adb_device "am force-stop dev.dby2.dirtyfrag"
if ! adb_device "am start -W -n dev.dby2.dirtyfrag/.MainActivity >/dev/null"; then
  echo "触发期间 ADB 短暂中断，等待设备恢复"
fi
if ! wait_for_bootstrap; then
  echo "DirtyFrag bootstrap 未创建 /dev/dfroot-ok" >&2
  exit 1
fi

echo "[4/5] 验证 UID 0 broker"
root_output="$(adb_device "'${DEVICE_SU}' 'id; cat /proc/uptime'")" || {
  echo "root broker 命令执行失败" >&2
  exit 1
}
printf '%s\n' "${root_output}"
if ! printf '%s\n' "${root_output}" | grep -q 'uid=0(root)'; then
  echo "root broker 未返回 UID 0" >&2
  exit 1
fi

echo "[5/5] 验证系统可用性"
adb_device 'pidof system_server surfaceflinger; cat /proc/uptime'
echo "ROOT_READY"
