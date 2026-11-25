#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"

cd "${PROJECT_ROOT}"

if [ -n "$(git status --porcelain)" ]; then
  echo "working tree is not clean; commit or stash changes before release" >&2
  exit 1
fi

revision="$(git rev-parse --short=12 HEAD)"
version="${RELEASE_VERSION:-2.0}"
archive_name="DBY2-RootKit-${version}-source.tar.gz"
archive_path="${DIST_DIR}/${archive_name}"
checksum_path="${archive_path}.sha256"

./scripts/test.sh

mkdir -p "${DIST_DIR}"
git archive \
  --format=tar.gz \
  --prefix="DBY2-RootKit-${version}/" \
  --output="${archive_path}" \
  HEAD

(
  cd "${DIST_DIR}"
  sha256sum "${archive_name}" > "${archive_name}.sha256"
)

echo "source archive: ${archive_path}"
echo "checksum: ${checksum_path}"
