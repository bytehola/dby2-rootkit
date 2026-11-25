#!/system/bin/sh

set -u

log_file=/data/local/tmp/dby2-xposed-activate.log
nya_dir=/data/adb/modules/zygisksu
vector_dir=/data/adb/modules/zygisk_vector
nya_marker="$vector_dir/nyazygisk-injected"
manager_marker="$vector_dir/.dby2-manager.sha256"
usap_policy_source=/data/local/tmp/one-tap-usap-policy.sh
usap_policy_target=/data/adb/post-fs-data.d/dby2-vector-usap.sh

exec >>"$log_file" 2>&1
echo "=== activation start $(date '+%Y-%m-%d %H:%M:%S') ==="
rm -f "$nya_marker"

if [ "$(id -u)" != "0" ]; then
  echo "XPosed_ACTIVATION_NOT_ROOT"
  exit 10
fi

setprop persist.device_config.runtime_native.usap_pool_enabled false
mkdir -p /data/adb/post-fs-data.d
if [ -f "$usap_policy_source" ]; then
  cp "$usap_policy_source" "$usap_policy_target"
  chown 0:0 "$usap_policy_target"
  chmod 0755 "$usap_policy_target"
  chcon u:object_r:system_file:s0 "$usap_policy_target" || true
fi

if [ ! -x "$nya_dir/bin/zygisk-ptrace64" ] ||
   [ ! -x "$vector_dir/daemon" ]; then
  echo "XPosed_MODULES_MISSING"
  exit 11
fi

export PATH=/debug_ramdisk:/system/bin:/vendor/bin
export MAGISKTMP=/debug_ramdisk

chcon -R u:object_r:xposed_file:s0 "$vector_dir/bin" || true

if [ -f /data/local/tmp/one-tap-vector-service.sh ]; then
  cp /data/local/tmp/one-tap-vector-service.sh "$vector_dir/service.sh"
  chown 0:0 "$vector_dir/service.sh"
  chmod 755 "$vector_dir/service.sh"
  chcon u:object_r:system_file:s0 "$vector_dir/service.sh" || true
fi

if ! /debug_ramdisk/magiskpolicy --live \
    --apply "$nya_dir/sepolicy.rule"; then
  echo "NYAZYGISK_SEPOLICY_FAILED"
fi

if ! /debug_ramdisk/magiskpolicy --live \
    --apply "$vector_dir/sepolicy.rule"; then
  echo "VECTOR_SEPOLICY_FAILED"
fi

unset KSU APATCH
cd "$nya_dir" || exit 12
if ! /system/bin/sh ./late-load.sh; then
  echo "NYAZYGISK_LATE_LOAD_FAILED"
  exit 13
fi

attempt=0
while [ "$attempt" -lt 20 ]; do
  if pidof zygiskd64 >/dev/null 2>&1 &&
     grep -q '^zygote_64_status=injected$' \
       /data/system_de/nyazygisk/module.prop 2>/dev/null; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done

if ! grep -q '^zygote_64_status=injected$' \
    /data/system_de/nyazygisk/module.prop 2>/dev/null; then
  echo "NYAZYGISK_INJECTION_FAILED"
  exit 14
fi

printf '%s\n' "$(cat /proc/sys/kernel/random/boot_id)" >"$nya_marker"
chmod 0644 "$nya_marker"
chcon u:object_r:system_file:s0 "$nya_marker" || true
echo "DBY2_ZYGISK_READY"

manager_hash="$(sha256sum "$vector_dir/manager.apk" | awk '{ print $1 }')"
if ! pm path org.matrix.vector.manager >/dev/null 2>&1 ||
   [ "$(cat "$manager_marker" 2>/dev/null || true)" != "$manager_hash" ]; then
  if ! pm install -r "$vector_dir/manager.apk"; then
    echo "VECTOR_MANAGER_INSTALL_FAILED"
    exit 17
  fi
  printf '%s\n' "$manager_hash" >"$manager_marker"
  chmod 0644 "$manager_marker"
  chcon u:object_r:system_file:s0 "$manager_marker" || true
fi

if ! pm path org.matrix.vector.manager >/dev/null 2>&1; then
  echo "VECTOR_MANAGER_INSTALL_FAILED"
  exit 17
fi
echo "DBY2_VECTOR_MANAGER_READY"

if pidof vectord >/dev/null 2>&1; then
  echo "DBY2_VECTOR_SERVICE_ALREADY_RUNNING"
else
  chmod 755 "$vector_dir/service.sh"
  /debug_ramdisk/busybox setsid "$vector_dir/service.sh" \
    </dev/null >/dev/null 2>&1 &
  echo "DBY2_VECTOR_SERVICE_STARTED"
fi

zygote_pid="$(pidof zygote64 | awk '{ print $1 }')"
if [ -z "$zygote_pid" ]; then
  echo "ZYGOTE64_MISSING"
  exit 15
fi

for android_env_name in \
  ANDROID_ROOT \
  ANDROID_DATA \
  ANDROID_ART_ROOT \
  ANDROID_I18N_ROOT \
  ANDROID_TZDATA_ROOT \
  BOOTCLASSPATH \
  DEX2OATBOOTCLASSPATH; do
  android_env_value="$(
    tr '\0' '\n' <"/proc/$zygote_pid/environ" |
      sed -n "s/^$android_env_name=//p" |
      head -n 1
  )"
  if [ -n "$android_env_value" ]; then
    export "$android_env_name=$android_env_value"
  fi
done

attempt=0
while [ "$attempt" -lt 45 ]; do
  status_json="$(
    /debug_ramdisk/busybox nsenter -t 1 -m -w"$vector_dir" \
      /system/bin/app_process \
      -Djava.class.path="$vector_dir/daemon.apk" \
      -Duser.dir="$vector_dir" \
      -Djava.io.tmpdir=/data/local/tmp \
      /system/bin org.matrix.vector.daemon.Cli \
      --json status 2>/dev/null || true
  )"
  if printf '%s\n' "$status_json" | grep -q '"success": true'; then
    echo "DBY2_VECTOR_READY"
    echo "DBY2_XPOSED_READY"
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 1
done

echo "VECTOR_DAEMON_NOT_READY"
exit 16
