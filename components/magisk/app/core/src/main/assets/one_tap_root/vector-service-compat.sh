#!/system/bin/sh

MODDIR="${0%/*}"
cd "$MODDIR" || exit 1

exec >>/data/local/tmp/vector-service-launch.log 2>&1
echo "=== vector service start $(date '+%Y-%m-%d %H:%M:%S') ==="

zygote_pid="$(pidof zygote64 | awk '{ print $1 }')"
if [ -z "$zygote_pid" ]; then
  echo "zygote64 is not running"
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

exec /debug_ramdisk/busybox nsenter -t 1 -m -w"$MODDIR" \
  /system/bin/app_process \
  -Djava.class.path="$MODDIR/daemon.apk" \
  -Duser.dir="$MODDIR" \
  -Djava.io.tmpdir=/data/local/tmp \
  /system/bin --nice-name=vectord \
  org.matrix.vector.daemon.VectorDaemon \
  --system-server-max-retry=3 "$@"
