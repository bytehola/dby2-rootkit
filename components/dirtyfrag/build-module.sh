#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_SOURCE="${KERNEL_SOURCE:-}"
MODULE_SOURCE="${ROOT_DIR}/module"
OUTPUT="${OUTPUT:-${ROOT_DIR}/build/dfroot_boot.ko}"
PATCHED_OUTPUT="${PATCHED_OUTPUT:-${ROOT_DIR}/build/dfroot_boot.device-crc.ko}"
MODULE_STAGE_OUTPUT="${MODULE_STAGE_OUTPUT:-${ROOT_DIR}/native/ko/dfroot-android11-5.4.ko}"
HELPER_PATH="${HELPER_PATH:-/data/local/tmp/dfroot-stage2}"
LOCALVERSION="${DBY2_LOCALVERSION:-}"
CLANG_BIN="${CLANG_BIN:-}"
LLVM_STRIP="${LLVM_STRIP:-}"

if [ -z "${KERNEL_SOURCE}" ] || [ ! -d "${KERNEL_SOURCE}" ]; then
  echo "KERNEL_SOURCE must point to a prepared DBY2 kernel tree" >&2
  exit 2
fi
if [ -n "${CLANG_BIN}" ]; then
  PATH="${CLANG_BIN}:${PATH}"
fi
if [ -z "${LLVM_STRIP}" ]; then
  LLVM_STRIP="$(command -v llvm-strip || true)"
fi
if [ -z "${LLVM_STRIP}" ] || [ ! -x "${LLVM_STRIP}" ]; then
  echo "LLVM_STRIP must point to llvm-strip" >&2
  exit 2
fi

make_arguments=(
  ARCH=arm64
  LLVM=1
  CC=clang
  HOSTCC=clang
  CROSS_COMPILE=aarch64-linux-gnu-
)
if [ -n "${LOCALVERSION}" ]; then
  make_arguments+=(LOCALVERSION="${LOCALVERSION}")
fi

make -C "${KERNEL_SOURCE}" \
  "${make_arguments[@]}" \
  include/config/kernel.release include/generated/utsrelease.h

make -C "${KERNEL_SOURCE}" M="${MODULE_SOURCE}" \
  "${make_arguments[@]}" clean

make -C "${KERNEL_SOURCE}" M="${MODULE_SOURCE}" \
  "${make_arguments[@]}" KBUILD_MODPOST_WARN=1 \
  HELPER_PATH="${HELPER_PATH}" modules

mkdir -p "$(dirname "${OUTPUT}")" "$(dirname "${PATCHED_OUTPUT}")" \
  "$(dirname "${MODULE_STAGE_OUTPUT}")"
cp "${MODULE_SOURCE}/dfroot_boot.ko" "${OUTPUT}"
"${LLVM_STRIP}" --strip-debug "${OUTPUT}"
python3 "${ROOT_DIR}/fix-modversions.py" \
  "${OUTPUT}" "${PATCHED_OUTPUT}"
install -m 0644 "${PATCHED_OUTPUT}" \
  "${MODULE_STAGE_OUTPUT}"

modinfo "${PATCHED_OUTPUT}" | sed -n '1,20p'
sha256sum "${OUTPUT}" "${PATCHED_OUTPUT}"
