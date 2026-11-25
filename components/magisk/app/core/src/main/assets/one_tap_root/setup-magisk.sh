#!/system/bin/sh

set -eu

manager_uid="${1:-}"
native_directory="${2:-}"
expected_version="${3:-}"

case "$manager_uid" in
  ""|*[!0-9]*)
    echo "INVALID_MANAGER_UID"
    exit 10
    ;;
esac

if [ -z "$native_directory" ] || [ ! -d "$native_directory" ]; then
  echo "INVALID_NATIVE_DIRECTORY"
  exit 11
fi

magisk_temporary=/debug_ramdisk
overlay_root=/metadata/dfroot-overlay-manager
overlay_upper="$overlay_root/upper"
overlay_work="$overlay_root/work"
overlay_lower=/data/local/tmp/dfroot-overlay-lower
magisk_data=/data/adb/magisk

install_file_atomically() {
  source_file="$1"
  target_file="$2"
  target_mode="$3"
  target_temporary="${target_file}.new"

  cp "$source_file" "$target_temporary"
  chown 0:0 "$target_temporary"
  chmod "$target_mode" "$target_temporary"
  mv -f "$target_temporary" "$target_file"
}

overlay_is_active=false
if grep -q "overlay /system/bin overlay .*upperdir=$overlay_upper" /proc/mounts; then
  overlay_is_active=true
else
  rm -rf "$overlay_root"
fi

if ! grep -q " $magisk_temporary " /proc/mounts; then
  mount -t tmpfs -o mode=0755 tmpfs "$magisk_temporary"
fi

mkdir -p \
  "$magisk_temporary/.magisk/device" \
  "$magisk_data" \
  "$overlay_upper" \
  "$overlay_work" \
  "$overlay_lower"

install_magisk_binary=true
daemon_pids="$(pidof magiskd 2>/dev/null || true)"
if [ -n "$daemon_pids" ]; then
  daemon_uses_current_inode=true
  for daemon_pid in $daemon_pids; do
    daemon_executable="$(readlink "/proc/$daemon_pid/exe" 2>/dev/null || true)"
    if [ "$daemon_executable" != "$magisk_temporary/magisk" ]; then
      daemon_uses_current_inode=false
      break
    fi
  done

  if [ "$daemon_uses_current_inode" = true ]; then
    install_magisk_binary=false
    echo "MAGISK_BINARY_PRESERVED_FOR_PID=$daemon_pids"
  else
    for daemon_pid in $daemon_pids; do
      kill -9 "$daemon_pid" 2>/dev/null || true
    done
    sleep 1
    echo "STALE_MAGISK_DAEMON_STOPPED"
  fi
fi

if [ "$install_magisk_binary" = true ]; then
  install_file_atomically \
    "$native_directory/libmagisk.so" \
    "$magisk_temporary/magisk" \
    755
fi
install_file_atomically "$native_directory/libmagiskpolicy.so" \
  "$magisk_temporary/magiskpolicy" 755
install_file_atomically "$native_directory/libmagiskboot.so" \
  "$magisk_temporary/magiskboot" 755
install_file_atomically "$native_directory/libmagiskinit.so" \
  "$magisk_temporary/magiskinit" 755
install_file_atomically "$native_directory/libbusybox.so" \
  "$magisk_temporary/busybox" 755
install_file_atomically "$native_directory/libinit-ld.so" \
  "$magisk_temporary/init-ld" 755

install_file_atomically "$magisk_temporary/magiskboot" \
  "$magisk_data/magiskboot" 755
install_file_atomically "$magisk_temporary/magiskinit" \
  "$magisk_data/magiskinit" 755
install_file_atomically "$magisk_temporary/magiskpolicy" \
  "$magisk_data/magiskpolicy" 755
install_file_atomically "$magisk_temporary/busybox" \
  "$magisk_data/busybox" 755
install_file_atomically "$magisk_temporary/magisk" \
  "$magisk_data/magisk" 755
install_file_atomically /data/local/tmp/one-tap-util_functions.sh \
  "$magisk_data/util_functions.sh" 644
install_file_atomically /data/local/tmp/one-tap-boot_patch.sh \
  "$magisk_data/boot_patch.sh" 755

if [ ! -b "$magisk_temporary/.magisk/device/preinit" ]; then
  rm -f "$magisk_temporary/.magisk/device/preinit"
  mknod "$magisk_temporary/.magisk/device/preinit" b 8 0
  chmod 600 "$magisk_temporary/.magisk/device/preinit"
fi

cp /data/local/tmp/one-tap-su-wrapper.sh "$overlay_upper/su"
cp /data/local/tmp/one-tap-magisk-wrapper.sh "$overlay_upper/magisk"
chown 0:0 "$overlay_upper/su" "$overlay_upper/magisk"
chmod 755 "$overlay_upper/su" "$overlay_upper/magisk"
chcon u:object_r:system_file:s0 "$overlay_upper/su" "$overlay_upper/magisk"

"$magisk_temporary/magiskpolicy" --live \
  "permissive kernel" \
  "allow kernel untrusted_app lnk_file { getattr read }" \
  "allow kernel adb_data_file dir { open read write search getattr add_name remove_name }" \
  "allow kernel adb_data_file file { open read write append getattr ioctl map }" \
  "allow kernel untrusted_app fifo_file { read write getattr ioctl }" \
  "allow untrusted_app kernel fifo_file { read write getattr ioctl }" \
  "allow kernel untrusted_app binder { call transfer }" \
  "allow untrusted_app kernel binder { call transfer }"

if [ "$overlay_is_active" = false ]; then
  if ! grep -q " $overlay_lower " /proc/mounts; then
    mount --bind /system/bin "$overlay_lower"
  fi
  mount -t overlay overlay \
    -o "lowerdir=$overlay_lower,upperdir=$overlay_upper,workdir=$overlay_work" \
    /system/bin
fi

"$magisk_temporary/magisk" --daemon
"$magisk_temporary/magisk" --sqlite \
  "REPLACE INTO policies (uid,policy,until,logging,notification) VALUES($manager_uid,2,0,1,1)"

daemon_version="$("$magisk_temporary/magisk" -v)"
case "$daemon_version" in
  "$expected_version":*)
    ;;
  *)
    echo "MAGISK_DAEMON_VERSION_MISMATCH=$daemon_version"
    exit 20
    ;;
esac

if [ ! -x /system/bin/magisk ] || [ ! -x /system/bin/su ]; then
  echo "SYSTEM_WRAPPERS_MISSING"
  exit 21
fi

echo "MAGISK_DAEMON_READY=$daemon_version"
echo "MAGISK_READY"
