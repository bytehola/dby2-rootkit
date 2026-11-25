#!/system/bin/sh

set -eu

apk_path="${1:-}"
busybox=/debug_ramdisk/busybox
magisk=/debug_ramdisk/magisk
modules_directory=/data/adb/modules
updates_directory=/data/adb/modules_update
staging_directory=/data/local/tmp/dby2-one-tap-modules
backup_directory=/data/local/tmp/dby2-module-backup

if [ -z "$apk_path" ] || [ ! -r "$apk_path" ]; then
  echo "APK_NOT_READABLE"
  exit 10
fi

if [ ! -x "$busybox" ] || [ ! -x "$magisk" ]; then
  echo "MAGISK_RUNTIME_INCOMPLETE"
  exit 11
fi

mkdir -p "$staging_directory" "$backup_directory"

install_module() {
  module_id="$1"
  module_archive="$2"
  module_check="$3"
  module_fingerprint="${4:-}"
  archive_path="$staging_directory/$module_id.zip"
  timestamp="$(date +%s)-$$"
  fingerprint_path="$modules_directory/$module_id/.dby2-package.sha256"

  if [ -d "$modules_directory/$module_id" ] &&
     [ ! -e "$modules_directory/$module_id/disable" ] &&
     [ ! -e "$modules_directory/$module_id/remove" ] &&
     [ -e "$modules_directory/$module_id/$module_check" ] &&
     { [ -z "$module_fingerprint" ] ||
       [ "$(cat "$fingerprint_path" 2>/dev/null || true)" = "$module_fingerprint" ]; }; then
    echo "${module_id}_READY"
    return
  fi

  if [ -d "$modules_directory/$module_id" ]; then
    mv "$modules_directory/$module_id" \
      "$backup_directory/${module_id}-active-$timestamp"
  fi
  if [ -d "$updates_directory/$module_id" ]; then
    mv "$updates_directory/$module_id" \
      "$backup_directory/${module_id}-update-$timestamp"
  fi

  "$busybox" unzip -p "$apk_path" "assets/one_tap_root/$module_archive" \
    > "$archive_path"
  if [ ! -s "$archive_path" ]; then
    echo "${module_id}_ARCHIVE_MISSING"
    exit 12
  fi

  "$magisk" --install-module "$archive_path"

  if [ -d "$updates_directory/$module_id" ]; then
    if [ -d "$modules_directory/$module_id" ]; then
      mv "$modules_directory/$module_id" \
        "$backup_directory/${module_id}-install-stub-$timestamp"
    fi
    mv "$updates_directory/$module_id" "$modules_directory/$module_id"
  fi

  rm -f "$modules_directory/$module_id/update"

  if [ ! -e "$modules_directory/$module_id/$module_check" ]; then
    echo "${module_id}_INSTALL_FAILED"
    exit 13
  fi

  if [ -n "$module_fingerprint" ]; then
    printf '%s\n' "$module_fingerprint" > "$fingerprint_path"
    chmod 0644 "$fingerprint_path"
  fi

  rm -f "$archive_path"
  echo "${module_id}_INSTALLED"
}

install_module \
  "zygisksu" \
  "NyaZygisk-v2.6-1-ce72ac8-debug.zip" \
  "bin/zygisk-ptrace64"
install_module \
  "zygisk_vector" \
  "Vector-vcanary-3119-1-Debug.zip" \
  "daemon" \
  "e5844365ffd1c48594c39fecca493b4f72babcd69d382ab1c05749ef122ed829"

echo "DBY2_EXTENSIONS_READY"
