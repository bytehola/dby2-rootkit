#!/usr/bin/env bash
set -euo pipefail

MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${MODULE_ROOT}/../.." && pwd)"
OUTPUT_DIR="${MODULE_ROOT}/build"

NYAZYGISK_SOURCE="${NYAZYGISK_SOURCE:-${PROJECT_ROOT}/components/nyazygisk}"
VECTOR_SOURCE="${VECTOR_SOURCE:-${PROJECT_ROOT}/components/vector}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
JAVA_HOME="${JAVA_HOME:-}"
CARGO_HOME="${CARGO_HOME:-}"
RUSTUP_HOME="${RUSTUP_HOME:-}"

required_paths=(
  "${NYAZYGISK_SOURCE}"
  "${VECTOR_SOURCE}"
  "${ANDROID_SDK_ROOT}"
  "${JAVA_HOME}"
  "${CARGO_HOME}"
  "${RUSTUP_HOME}"
)

for required_path in "${required_paths[@]}"; do
  if [ -z "${required_path}" ] || [ ! -d "${required_path}" ]; then
    echo "missing required module build path: ${required_path}" >&2
    exit 1
  fi
done

if [ ! -x "${NYAZYGISK_SOURCE}/gradlew" ] ||
   [ ! -x "${VECTOR_SOURCE}/gradlew" ]; then
  echo "Gradle wrapper missing from NyaZygisk or Vector source" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

export ANDROID_HOME="${ANDROID_SDK_ROOT}"
export PATH="${CARGO_HOME}/bin:${JAVA_HOME}/bin:${PATH}"

echo "[1/2] Building NyaZygisk arm64 debug module"
(
  cd "${NYAZYGISK_SOURCE}"
  ./gradlew :module:zipDebug --no-daemon
)
nyazygisk_zip="$(
  find "${NYAZYGISK_SOURCE}/module/build/outputs/release" \
    -type f -name 'NyaZygisk-*.zip' |
    sort |
    tail -n 1
)"
cp "${nyazygisk_zip}" "${OUTPUT_DIR}/"

echo "[2/2] Building Vector debug module"
(
  cd "${VECTOR_SOURCE}"
  ./gradlew :zygisk:zipDebug --no-daemon
)
vector_zip="$(
  find "${VECTOR_SOURCE}/zygisk/release" \
    -type f -name 'Vector-*.zip' |
    sort |
    tail -n 1
)"
cp "${vector_zip}" "${OUTPUT_DIR}/"

cd "${OUTPUT_DIR}"
sha256sum ./*.zip > SHA256SUMS

echo "NyaZygisk: ${OUTPUT_DIR}/$(basename "${nyazygisk_zip}")"
echo "Vector:    ${OUTPUT_DIR}/$(basename "${vector_zip}")"
echo "Checksums: ${OUTPUT_DIR}/SHA256SUMS"
