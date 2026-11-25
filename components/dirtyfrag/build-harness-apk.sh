#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_DIR="${ROOT_DIR}/apk-harness"
OUTPUT_DIR="${ROOT_DIR}/build/harness-apk"
OUTPUT_APK="${OUTPUT_DIR}/DBY2DirtyFrag.apk"
JDK_ROOT="${JDK_ROOT:-${JAVA_HOME:-}}"
SDK_ROOT="${SDK_ROOT:-${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}}"
BUILD_TOOLS="${SDK_ROOT}/build-tools/35.0.0"
ANDROID_JAR="${SDK_ROOT}/platforms/android-35/android.jar"
KEYSTORE="${KEYSTORE:-${DBY2_KEYSTORE:-}}"

for required_file in \
  "${ROOT_DIR}/native/build/libdfroot.so" \
  "${JDK_ROOT}/bin/javac" \
  "${BUILD_TOOLS}/aapt2" \
  "${BUILD_TOOLS}/d8" \
  "${BUILD_TOOLS}/zipalign" \
  "${BUILD_TOOLS}/apksigner" \
  "${ANDROID_JAR}" \
  "${KEYSTORE}"; do
  if [ ! -f "${required_file}" ]; then
    echo "missing required file: ${required_file}" >&2
    exit 1
  fi
done

export JAVA_HOME="${JDK_ROOT}"
export PATH="${JDK_ROOT}/bin:${PATH}"

rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}/classes" "${OUTPUT_DIR}/dex" \
  "${OUTPUT_DIR}/lib/arm64-v8a"

"${BUILD_TOOLS}/aapt2" link \
  --manifest "${HARNESS_DIR}/AndroidManifest.xml" \
  -I "${ANDROID_JAR}" \
  --min-sdk-version 31 \
  --target-sdk-version 31 \
  --version-code 1 \
  --version-name 1.0 \
  -o "${OUTPUT_DIR}/base.apk"

"${JDK_ROOT}/bin/javac" \
  -source 8 \
  -target 8 \
  -classpath "${ANDROID_JAR}" \
  -d "${OUTPUT_DIR}/classes" \
  "${HARNESS_DIR}/src/dev/dby2/dirtyfrag/MainActivity.java"

find "${OUTPUT_DIR}/classes" -name '*.class' -print0 |
  xargs -0 "${BUILD_TOOLS}/d8" \
    --min-api 31 \
    --lib "${ANDROID_JAR}" \
    --output "${OUTPUT_DIR}/dex"

cp "${ROOT_DIR}/native/build/libdfroot.so" \
  "${OUTPUT_DIR}/lib/arm64-v8a/libdirtyfrag.so"
chmod 0755 "${OUTPUT_DIR}/lib/arm64-v8a/libdirtyfrag.so"
cp "${OUTPUT_DIR}/dex/classes.dex" "${OUTPUT_DIR}/classes.dex"
cp "${OUTPUT_DIR}/base.apk" "${OUTPUT_DIR}/unsigned.apk"

(
  cd "${OUTPUT_DIR}"
  zip -q -r -0 unsigned.apk classes.dex lib
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
