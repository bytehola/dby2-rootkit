#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_APK="${SOURCE_APK:-${ROOT_DIR}/vendor/DirtyFrag-v1.18.apk}"
OUTPUT_DIR="${ROOT_DIR}/build/apk"
OUTPUT_APK="${OUTPUT_DIR}/DirtyFrag-DBY2.apk"
JDK_ROOT="${JDK_ROOT:-${JAVA_HOME:-}}"
SDK_ROOT="${SDK_ROOT:-${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}}"
BUILD_TOOLS="${SDK_ROOT}/build-tools/35.0.0"
KEYSTORE="${KEYSTORE:-${DBY2_KEYSTORE:-}}"

for required_file in \
  "${SOURCE_APK}" \
  "${ROOT_DIR}/native/build/libdfroot.so" \
  "${JDK_ROOT}/bin/java" \
  "${BUILD_TOOLS}/zipalign" \
  "${BUILD_TOOLS}/apksigner" \
  "${KEYSTORE}"; do
  if [ ! -f "${required_file}" ]; then
    echo "missing required file: ${required_file}" >&2
    exit 1
  fi
done

export JAVA_HOME="${JDK_ROOT}"
export PATH="${JDK_ROOT}/bin:${PATH}"

rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"
unzip -q "${SOURCE_APK}" -d "${OUTPUT_DIR}/unpacked"
cp "${ROOT_DIR}/native/build/libdfroot.so" \
  "${OUTPUT_DIR}/unpacked/lib/arm64-v8a/libdfroot.so"
chmod 0755 "${OUTPUT_DIR}/unpacked/lib/arm64-v8a/libdfroot.so"

(
  cd "${OUTPUT_DIR}/unpacked"
  # Android requires resources.arsc to remain uncompressed and 4-byte aligned.
  zip -q -r -0 "${OUTPUT_DIR}/unsigned.apk" .
)

"${BUILD_TOOLS}/zipalign" -f 4 \
  "${OUTPUT_DIR}/unsigned.apk" "${OUTPUT_DIR}/aligned.apk"
"${BUILD_TOOLS}/apksigner" sign \
  --ks "${KEYSTORE}" \
  --ks-pass pass:android \
  --key-pass pass:android \
  --out "${OUTPUT_APK}" \
  "${OUTPUT_DIR}/aligned.apk"
"${BUILD_TOOLS}/apksigner" verify --verbose "${OUTPUT_APK}"

sha256sum "${OUTPUT_APK}"
