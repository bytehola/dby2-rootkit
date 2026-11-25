#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAVA_HOME="${JAVA_HOME:-}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
CARGO_HOME="${CARGO_HOME:-}"
RUSTUP_HOME="${RUSTUP_HOME:-}"

for required_variable in \
  JAVA_HOME \
  ANDROID_SDK_ROOT \
  ANDROID_NDK_HOME \
  CARGO_HOME \
  RUSTUP_HOME; do
  required_path="${!required_variable}"
  if [ -z "${required_path}" ] || [ ! -d "${required_path}" ]; then
    echo "${required_variable} must point to an existing directory" >&2
    exit 2
  fi
done

export JAVA_HOME
export ANDROID_HOME="${ANDROID_SDK_ROOT}"
export ANDROID_NDK_HOME
export CARGO_HOME
export RUSTUP_HOME
export PATH="${JAVA_HOME}/bin:${CARGO_HOME}/bin:${PATH}"

echo "[1/5] Building DBY2 root engine"
make -C "${PROJECT_ROOT}/components/root-engine" \
  -j4 LOGCAT=0 NDK_ROOT="${ANDROID_NDK_HOME}"

echo "[2/5] Building DirtyFrag native payload"
make -C "${PROJECT_ROOT}/components/dirtyfrag/native" \
  clean
make -C "${PROJECT_ROOT}/components/dirtyfrag/native" \
  NDK_ROOT="${ANDROID_NDK_HOME}"

echo "[3/5] Building NyaZygisk and Vector module archives"
"${PROJECT_ROOT}/runtime/modules/build.sh"

echo "[4/5] Refreshing Magisk bundled payloads"
magisk_jni_directory="${PROJECT_ROOT}/components/magisk/app/apk/src/main/jniLibs/arm64-v8a"
magisk_asset_directory="${PROJECT_ROOT}/components/magisk/app/core/src/main/assets/one_tap_root"
runtime_module_directory="${PROJECT_ROOT}/runtime/modules/build"

install -m 0755 \
  "${PROJECT_ROOT}/components/root-engine/build/bin/ghostlock_exe" \
  "${magisk_jni_directory}/libghostlockexec.so"
install -m 0755 \
  "${PROJECT_ROOT}/components/dirtyfrag/native/build/dfroot-stage2" \
  "${magisk_jni_directory}/libdfrootstage2.so"
install -m 0755 \
  "${PROJECT_ROOT}/components/dirtyfrag/native/build/libdfroot.so" \
  "${magisk_jni_directory}/libdirtyfrag.so"

nyazygisk_archive="$(
  find "${runtime_module_directory}" -maxdepth 1 -type f \
    -name 'NyaZygisk-*.zip' -printf '%T@ %p\n' |
    sort -n |
    tail -n 1 |
    cut -d ' ' -f 2-
)"
vector_archive="$(
  find "${runtime_module_directory}" -maxdepth 1 -type f \
    -name 'Vector-*.zip' -printf '%T@ %p\n' |
    sort -n |
    tail -n 1 |
    cut -d ' ' -f 2-
)"
if [ -z "${nyazygisk_archive}" ] || [ -z "${vector_archive}" ]; then
  echo "module build did not produce NyaZygisk and Vector archives" >&2
  exit 3
fi

nyazygisk_asset="NyaZygisk-v2.6-1-ce72ac8-debug.zip"
vector_asset="Vector-vcanary-3119-1-Debug.zip"

install_archive() {
  local source_archive="$1"
  local destination_archive="$2"
  if [ "$(realpath "${source_archive}")" != \
       "$(realpath -m "${destination_archive}")" ]; then
    install -m 0644 "${source_archive}" "${destination_archive}"
  fi
}

install_archive "${nyazygisk_archive}" \
  "${runtime_module_directory}/${nyazygisk_asset}"
install_archive "${vector_archive}" \
  "${runtime_module_directory}/${vector_asset}"
install_archive "${nyazygisk_archive}" \
  "${magisk_asset_directory}/${nyazygisk_asset}"
install_archive "${vector_archive}" \
  "${magisk_asset_directory}/${vector_asset}"

echo "[5/5] Building Magisk and DBY2 RootKit APKs"
(
  cd "${PROJECT_ROOT}/components/magisk/app"
  ../build.py native
  ./gradlew :apk:assembleDebug --no-daemon
)
mkdir -p "${PROJECT_ROOT}/runtime/magisk"
install -m 0644 \
  "${PROJECT_ROOT}/components/magisk/app/apk/build/outputs/apk/debug/apk-debug.apk" \
  "${PROJECT_ROOT}/runtime/magisk/DBY2-Magisk-OneTap.apk"

ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT}" \
JAVA_HOME="${JAVA_HOME}" \
"${PROJECT_ROOT}/app/rootkit-manager/build.sh"

printf 'ROOT_ENGINE=%s\n' \
  "${PROJECT_ROOT}/components/root-engine/build/bin/ghostlock_exe"
printf 'MAGISK_APK=%s\n' \
  "${PROJECT_ROOT}/runtime/magisk/DBY2-Magisk-OneTap.apk"
printf 'ROOTKIT_APK=%s\n' \
  "${PROJECT_ROOT}/app/rootkit-manager/build/DBY2-RootKit-debug.apk"
printf 'NYAZYGISK_ZIP=%s\n' \
  "${runtime_module_directory}/${nyazygisk_asset}"
printf 'VECTOR_ZIP=%s\n' \
  "${runtime_module_directory}/${vector_asset}"
