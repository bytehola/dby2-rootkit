#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_VERSION="${RELEASE_VERSION:-2.1}"
OUTPUT_DIRECTORY="${OUTPUT_DIRECTORY:-${PROJECT_ROOT}/dist/user-release}"
BUILD_COMPONENTS="${BUILD_COMPONENTS:-1}"
WINDOWS_PYTHON="${WINDOWS_PYTHON:-}"
PLATFORM_TOOLS_DIRECTORY="${PLATFORM_TOOLS_DIRECTORY:-}"
MAGISK_APK="${MAGISK_APK:-${PROJECT_ROOT}/runtime/magisk/DBY2-Magisk-OneTap.apk}"
ROOTKIT_APK="${ROOTKIT_APK:-${PROJECT_ROOT}/app/rootkit-manager/build/DBY2-RootKit-debug.apk}"
NYAZYGISK_ZIP="${NYAZYGISK_ZIP:-${PROJECT_ROOT}/runtime/modules/build/NyaZygisk-v2.6-1-ce72ac8-debug.zip}"
VECTOR_ZIP="${VECTOR_ZIP:-${PROJECT_ROOT}/runtime/modules/build/Vector-vcanary-3119-1-Debug.zip}"
GHOSTLOCK_BINARY="${GHOSTLOCK_BINARY:-${PROJECT_ROOT}/components/root-engine/build/bin/ghostlock_exe}"

release_name="DBY2-RootKit-User-${RELEASE_VERSION}-win64"
build_root="$(mktemp -d /tmp/dby2-user-release.XXXXXX)"
release_directory="${build_root}/${release_name}"
archive_path="${OUTPUT_DIRECTORY}/${release_name}.zip"
checksum_path="${archive_path}.sha256"

if [ -z "${WINDOWS_PYTHON}" ]; then
  echo "WINDOWS_PYTHON must point to python.exe" >&2
  exit 2
fi
if [ -z "${PLATFORM_TOOLS_DIRECTORY}" ]; then
  echo "PLATFORM_TOOLS_DIRECTORY must point to Android platform-tools" >&2
  exit 2
fi

required_files=(
  "${WINDOWS_PYTHON}"
  "${PLATFORM_TOOLS_DIRECTORY}/adb.exe"
  "${PLATFORM_TOOLS_DIRECTORY}/AdbWinApi.dll"
  "${PLATFORM_TOOLS_DIRECTORY}/AdbWinUsbApi.dll"
  "${MAGISK_APK}"
  "${ROOTKIT_APK}"
  "${NYAZYGISK_ZIP}"
  "${VECTOR_ZIP}"
  "${GHOSTLOCK_BINARY}"
)
for required_file in "${required_files[@]}"; do
  if [[ "${required_file}" == C:* ]]; then
    continue
  fi
  if [ ! -f "${required_file}" ]; then
    echo "missing required file: ${required_file}" >&2
    exit 1
  fi
done

if [ -e "${archive_path}" ] || [ -e "${checksum_path}" ]; then
  echo "release already exists: ${archive_path}" >&2
  exit 3
fi

mkdir -p \
  "${release_directory}/adb" \
  "${release_directory}/profiles/dby2-w00" \
  "${release_directory}/runtime/magisk" \
  "${release_directory}/runtime/modules" \
  "${release_directory}/runtime/rootkit" \
  "${release_directory}/runtime/root-engine" \
  "${release_directory}/ui"

if ! command -v wslpath >/dev/null 2>&1; then
  echo "wslpath is required to build the Windows GUI from WSL." >&2
  exit 1
fi

if [ "${BUILD_COMPONENTS}" = "1" ]; then
  "${PROJECT_ROOT}/scripts/build-components.sh"
fi

win_package_root="$(wslpath -w "${PROJECT_ROOT}/pc/dby2-rootctl")"
win_gui_script="$(wslpath -w "${PROJECT_ROOT}/pc/dby2-rootctl/dby2_rootctl/web_gui.py")"
win_build_dist="$(wslpath -w "${build_root}/pyinstaller-dist")"
win_build_work="$(wslpath -w "${build_root}/pyinstaller-work")"
win_build_spec="$(wslpath -w "${build_root}/pyinstaller-spec")"

"${PROJECT_ROOT}/scripts/test.sh"

'/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe' \
  -NoProfile \
  -Command "& '${WINDOWS_PYTHON}' -m PyInstaller \
    --noconfirm \
    --clean \
    --onedir \
    --console \
    --collect-all webview \
    --name DBY2-RootKit \
    --distpath '${win_build_dist}' \
    --workpath '${win_build_work}' \
    --specpath '${win_build_spec}' \
    --paths '${win_package_root}' \
    '${win_gui_script}'"

cp -a "${build_root}/pyinstaller-dist/DBY2-RootKit/." \
  "${release_directory}/"

cp \
  "${PLATFORM_TOOLS_DIRECTORY}/adb.exe" \
  "${PLATFORM_TOOLS_DIRECTORY}/AdbWinApi.dll" \
  "${PLATFORM_TOOLS_DIRECTORY}/AdbWinUsbApi.dll" \
  "${release_directory}/adb/"
cp "${PLATFORM_TOOLS_DIRECTORY}/NOTICE.txt" \
  "${release_directory}/adb/ADB-NOTICE.txt"

cp "${MAGISK_APK}" \
  "${release_directory}/runtime/magisk/DBY2-Magisk-OneTap.apk"
cp "${ROOTKIT_APK}" \
  "${release_directory}/runtime/rootkit/DBY2-RootKit-debug.apk"
cp "${NYAZYGISK_ZIP}" \
  "${release_directory}/runtime/modules/NyaZygisk-v2.6-1-ce72ac8-debug.zip"
cp "${VECTOR_ZIP}" \
  "${release_directory}/runtime/modules/Vector-vcanary-3119-1-Debug.zip"
cp "${GHOSTLOCK_BINARY}" \
  "${release_directory}/runtime/root-engine/DBY2-GhostLock-arm64"

cp "${PROJECT_ROOT}/profiles/dby2-w00/"*.json \
  "${release_directory}/profiles/dby2-w00/"
cp -a "${PROJECT_ROOT}/pc/user-release/web/." \
  "${release_directory}/ui/"
cp "${PROJECT_ROOT}/pc/user-release/README.txt" \
  "${release_directory}/README.txt"
cp "${PROJECT_ROOT}/NOTICE" \
  "${release_directory}/THIRD_PARTY_NOTICES.txt"
cp "${PROJECT_ROOT}/LICENSE" \
  "${release_directory}/LICENSE"
printf '%s\n' \
  "DBY2 RootKit ${RELEASE_VERSION}" \
  "Source tag: v${RELEASE_VERSION}" \
  "Source archive: DBY2-RootKit-${RELEASE_VERSION}-source.tar.gz" \
  "License: GNU GPL version 3 or later" \
  > "${release_directory}/SOURCE-INFO.txt"

RELEASE_VERSION="${RELEASE_VERSION}" \
RELEASE_DIRECTORY="${release_directory}" \
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

release_directory = Path(os.environ["RELEASE_DIRECTORY"])
asset_entries = {
    "magisk_apk": "runtime/magisk/DBY2-Magisk-OneTap.apk",
    "rootkit_apk": "runtime/rootkit/DBY2-RootKit-debug.apk",
    "nyazygisk_zip": "runtime/modules/NyaZygisk-v2.6-1-ce72ac8-debug.zip",
    "vector_zip": "runtime/modules/Vector-vcanary-3119-1-Debug.zip",
    "root_engine_binary": "runtime/root-engine/DBY2-GhostLock-arm64",
}

def sha256(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as file_handle:
        while True:
            file_chunk = file_handle.read(1024 * 1024)
            if not file_chunk:
                break
            digest.update(file_chunk)
    return digest.hexdigest()

manifest = {
    "schema_version": 1,
    "product": "DBY2 RootKit",
    "version": os.environ.get("RELEASE_VERSION", "1.0.0"),
    "adb_path": "adb/adb.exe",
    "profile_directory": "profiles/dby2-w00",
    "assets": {
        asset_name: {
            "path": relative_path,
            "sha256": sha256(release_directory / relative_path),
        }
        for asset_name, relative_path in asset_entries.items()
    },
}
(release_directory / "release-manifest.json").write_text(
    json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY

(
  cd "${build_root}"
  mkdir -p "${OUTPUT_DIRECTORY}"
  zip -q -r "${archive_path}" "${release_name}"
)
(
  cd "${OUTPUT_DIRECTORY}"
  sha256sum "${release_name}.zip" > "${release_name}.zip.sha256"
)

unzip -t "${archive_path}" >/dev/null
printf 'RELEASE_ARCHIVE=%s\n' "${archive_path}"
printf 'RELEASE_CHECKSUM=%s\n' "${checksum_path}"
stat -c 'RELEASE_SIZE_BYTES=%s' "${archive_path}"
cat "${checksum_path}"
printf 'BUILD_DIRECTORY=%s\n' "${build_root}"
