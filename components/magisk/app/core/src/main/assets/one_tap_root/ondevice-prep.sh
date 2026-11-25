#!/system/bin/sh

set -eu

package_name="${1:-}"
if [ -z "$package_name" ]; then
  echo "PACKAGE_NAME_MISSING"
  exit 10
fi

code_path="$(
  dumpsys package "$package_name" |
    sed -n 's/^[[:space:]]*codePath=//p' |
    head -n 1
)"
if [ -z "$code_path" ]; then
  echo "APP_CODE_PATH_MISSING"
  exit 11
fi

ghostlock_binary="/data/local/tmp/onetap-ghostlock-$$"
stage2_binary="/data/local/tmp/dfroot-stage2"
module_log="/data/local/tmp/onetap-module-$$.log"
module_slot="/data/local/tmp/onetap-module-$$.slot"

cp "$code_path/lib/arm64/libghostlockexec.so" "$ghostlock_binary"
chmod 755 "$ghostlock_binary"

if [ ! -x "$stage2_binary" ]; then
  cp "$code_path/lib/arm64/libdfrootstage2.so" "$stage2_binary"
  chmod 755 "$stage2_binary"
fi

touch "$module_slot"
chmod 666 "$module_slot"

"$ghostlock_binary" \
  --module-prep \
  --detach \
  --probe-cycle \
  --spin-park \
  --no-rt \
  --runtime-cpu 6 \
  --attempts 1 \
  --slot-file "$module_slot" \
  --log-file "$module_log" \
  --fsync

if ! grep -q "module-prep: signature and load-data policy checks cleared" \
    "$module_log"; then
  tail -n 160 "$module_log" 2>/dev/null
  echo "MODULE_PREP_FAILED"
  exit 20
fi

echo "MODULE_PREP_READY"
