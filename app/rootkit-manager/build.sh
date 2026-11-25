#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${APP_ROOT}/build"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
JDK_ROOT="${JAVA_HOME:-}"

if [ -z "${SDK_ROOT}" ] || [ ! -d "${SDK_ROOT}" ]; then
  echo "ANDROID_SDK_ROOT or ANDROID_HOME is required" >&2
  exit 1
fi

if [ -z "${JDK_ROOT}" ] || [ ! -x "${JDK_ROOT}/bin/javac" ]; then
  echo "JAVA_HOME pointing to a JDK is required" >&2
  exit 1
fi

BUILD_TOOLS="$(
  find "${SDK_ROOT}/build-tools" -mindepth 1 -maxdepth 1 -type d |
    sort -V |
    tail -n 1
)"
ANDROID_JAR="$(
  find "${SDK_ROOT}/platforms" -name android.jar -type f |
    sort -V |
    tail -n 1
)"

if [ -z "${BUILD_TOOLS}" ] || [ -z "${ANDROID_JAR}" ]; then
  echo "Android build-tools or platform android.jar is missing" >&2
  exit 1
fi

KEYSTORE="${BUILD_DIR}/debug.keystore"
OUTPUT_APK="${BUILD_DIR}/DBY2-RootKit-debug.apk"

mkdir -p "${BUILD_DIR}/classes" "${BUILD_DIR}/dex"
find "${BUILD_DIR}/classes" -type f -delete
find "${BUILD_DIR}/dex" -type f -delete
rm -f \
  "${BUILD_DIR}/base.apk" \
  "${BUILD_DIR}/classes.dex" \
  "${BUILD_DIR}/unsigned.apk" \
  "${BUILD_DIR}/aligned.apk" \
  "${OUTPUT_APK}"

export JAVA_HOME="${JDK_ROOT}"
export PATH="${JDK_ROOT}/bin:${PATH}"

if [ ! -f "${KEYSTORE}" ]; then
  "${JDK_ROOT}/bin/keytool" \
    -genkeypair \
    -keystore "${KEYSTORE}" \
    -storepass android \
    -keypass android \
    -alias debug \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000 \
    -dname "CN=DBY2 RootKit Debug,O=DBY2,C=CN" \
    >/dev/null 2>&1
fi

"${BUILD_TOOLS}/aapt2" link \
  --manifest "${APP_ROOT}/AndroidManifest.xml" \
  -I "${ANDROID_JAR}" \
  --min-sdk-version 31 \
  --target-sdk-version 31 \
  --version-code 20 \
  --version-name 2.0 \
  -o "${BUILD_DIR}/base.apk"

mapfile -t JAVA_SOURCES < <(
  find "${APP_ROOT}/src" -name '*.java' -type f | sort
)

"${JDK_ROOT}/bin/javac" \
  -source 8 \
  -target 8 \
  -Xlint:-options \
  -classpath "${ANDROID_JAR}" \
  -d "${BUILD_DIR}/classes" \
  "${JAVA_SOURCES[@]}"

find "${BUILD_DIR}/classes" -name '*.class' -print0 |
  xargs -0 "${BUILD_TOOLS}/d8" \
    --min-api 31 \
    --lib "${ANDROID_JAR}" \
    --output "${BUILD_DIR}/dex"

cp "${BUILD_DIR}/dex/classes.dex" "${BUILD_DIR}/classes.dex"
cp "${BUILD_DIR}/base.apk" "${BUILD_DIR}/unsigned.apk"
(
  cd "${BUILD_DIR}"
  zip -q -r -0 unsigned.apk classes.dex
)

"${BUILD_TOOLS}/zipalign" -f 4 \
  "${BUILD_DIR}/unsigned.apk" \
  "${BUILD_DIR}/aligned.apk"
"${BUILD_TOOLS}/apksigner" sign \
  --ks "${KEYSTORE}" \
  --ks-pass pass:android \
  --key-pass pass:android \
  --out "${OUTPUT_APK}" \
  "${BUILD_DIR}/aligned.apk"
"${BUILD_TOOLS}/apksigner" verify --verbose "${OUTPUT_APK}"
sha256sum "${OUTPUT_APK}"
