#!/system/bin/sh

broker_dir=/data/local/tmp/dfroot-root
slot_count=8
slot=

if [ "$#" -eq 0 ]; then
  echo "usage: dfroot-su COMMAND..." >&2
  exit 2
fi

command=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -v|--version)
      echo "31.1:MAGISK:R"
      exit 0
      ;;
    -V|--version-code)
      echo "31100"
      exit 0
      ;;
    -c|--command)
      shift
      command="${1:-}"
      break
      ;;
    -0|--root|-M|--mount-master|--preserve-environment)
      shift
      ;;
    -s|--shell)
      shift
      [ "$#" -gt 0 ] && shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      shift
      ;;
    *)
      break
      ;;
  esac
done

if [ -z "$command" ]; then
  command="$*"
fi
if [ -z "$command" ]; then
  command="id"
fi

while [ -z "$slot" ]; do
  candidate=0
  while [ "$candidate" -lt "$slot_count" ]; do
    lock_dir="$broker_dir/lock$candidate"
    if [ ! -e "$broker_dir/busy$candidate" ] &&
       mkdir "$lock_dir" 2>/dev/null; then
      slot="$candidate"
      break
    fi
    candidate=$((candidate + 1))
  done
  if [ -z "$slot" ]; then
    sleep 0.05
  fi
done

request_file="$broker_dir/request$slot"
request_tmp="$broker_dir/request$slot.tmp"
output_file="$broker_dir/output$slot"
status_file="$broker_dir/status$slot"
done_file="$broker_dir/done$slot"

trap 'rmdir "$lock_dir" 2>/dev/null' EXIT HUP INT TERM

rm -f "$done_file" "$status_file" "$output_file" "$request_file" "$request_tmp"
printf '%s' "$command" > "$request_tmp" || exit 3
mv "$request_tmp" "$request_file" || exit 3

while [ ! -f "$done_file" ]; do
  sleep 0.05
done

cat "$output_file" 2>/dev/null
status=1
if [ -f "$status_file" ]; then
  read -r status < "$status_file"
fi
rm -f "$done_file" "$status_file" "$output_file" "$request_file"
exit "${status:-1}"
