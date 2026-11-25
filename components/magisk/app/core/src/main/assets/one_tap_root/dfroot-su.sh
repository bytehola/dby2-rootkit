#!/system/bin/sh

broker_directory=/data/local/tmp/dfroot-root
slot_count=8
selected_slot=
slot_attempts=0

if [ "$#" -eq 0 ]; then
  echo "usage: dfroot-su COMMAND..." >&2
  exit 2
fi

command=
while [ "$#" -gt 0 ]; do
  case "$1" in
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

while [ -z "$selected_slot" ]; do
  candidate_slot=0
  while [ "$candidate_slot" -lt "$slot_count" ]; do
    slot_lock="$broker_directory/lock$candidate_slot"
    if [ ! -e "$broker_directory/busy$candidate_slot" ] &&
       mkdir "$slot_lock" 2>/dev/null; then
      selected_slot="$candidate_slot"
      break
    fi
    candidate_slot=$((candidate_slot + 1))
  done
  if [ -z "$selected_slot" ]; then
    slot_attempts=$((slot_attempts + 1))
    if [ "$slot_attempts" -ge 200 ]; then
      echo "BROKER_SLOTS_BUSY" >&2
      exit 125
    fi
    sleep 0.05
  fi
done

request_file="$broker_directory/request$selected_slot"
request_temporary="$broker_directory/request$selected_slot.tmp"
output_file="$broker_directory/output$selected_slot"
status_file="$broker_directory/status$selected_slot"
done_file="$broker_directory/done$selected_slot"
slot_lock="$broker_directory/lock$selected_slot"

trap 'rmdir "$slot_lock" 2>/dev/null' EXIT HUP INT TERM

rm -f "$done_file" "$status_file" "$output_file" \
  "$request_file" "$request_temporary"
printf '%s' "$command" > "$request_temporary" || exit 3
mv "$request_temporary" "$request_file" || exit 3

wait_attempts=0
while [ ! -f "$done_file" ]; do
  wait_attempts=$((wait_attempts + 1))
  if [ "$wait_attempts" -ge 2200 ]; then
    echo "BROKER_TIMEOUT" >&2
    exit 124
  fi
  sleep 0.05
done

cat "$output_file" 2>/dev/null

exit_status=1
if [ -f "$status_file" ]; then
  read -r exit_status < "$status_file"
fi

rm -f "$done_file" "$status_file" "$output_file" "$request_file"
exit "${exit_status:-1}"
