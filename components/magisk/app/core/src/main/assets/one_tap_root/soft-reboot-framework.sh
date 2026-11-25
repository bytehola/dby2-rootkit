#!/system/bin/sh
set -u

vector_directory=/data/adb/modules/zygisk_vector
delay_seconds="${1:-10}"

if ! pidof vectord >/dev/null 2>&1; then
  echo "VECTOR_DAEMON_NOT_RUNNING"
  exit 1
fi

zygote_pid="$(pidof zygote64 | awk 'NR == 1 { print $1 }')"
if [ -z "$zygote_pid" ]; then
  echo "ZYGOTE64_NOT_RUNNING"
  exit 1
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

cli_output="$(
  /debug_ramdisk/busybox nsenter -t 1 -m -w"$vector_directory" \
    /system/bin/app_process \
    -Djava.class.path="$vector_directory/daemon.apk" \
    -Duser.dir="$vector_directory" \
    -Djava.io.tmpdir=/data/local/tmp \
    /system/bin org.matrix.vector.daemon.Cli \
    --json soft-reboot --delay-seconds "$delay_seconds" 2>&1
)"
cli_status=$?
printf '%s\n' "$cli_output"

if [ "$cli_status" -eq 0 ] &&
   printf '%s\n' "$cli_output" | grep -q '"success": true'; then
  echo "DBY2_SOFT_REBOOT_SCHEDULED"
  exit 0
fi

echo "DBY2_SOFT_REBOOT_SCHEDULE_FAILED"
exit 1
