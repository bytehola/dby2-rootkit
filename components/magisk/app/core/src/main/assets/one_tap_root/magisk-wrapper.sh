#!/system/bin/sh

real_magisk=/debug_ramdisk/magisk

if [ "$(id -u)" = "0" ]; then
  exec "$real_magisk" "$@"
fi

case "${1:-}" in
  -v|--version)
    /system/bin/su -c "$real_magisk -v"
    exit $?
    ;;
  -V|--version-code)
    /system/bin/su -c "$real_magisk -V"
    exit $?
    ;;
esac

command_line="$real_magisk"
for argument in "$@"; do
  escaped_argument="$(printf '%s' "$argument" | sed "s/'/'\\\\''/g")"
  command_line="$command_line '$escaped_argument'"
done

exec /system/bin/su -c "$command_line"
