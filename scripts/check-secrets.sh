#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

failed=0

report_failure() {
  echo "secret check failed: $1" >&2
  failed=1
}

if find . \
  \( -path './.git' -o -path '*/build' -o -path './dist' \) -prune -o \
  -type f \( -name '*.keystore' -o -name '*.jks' -o -name 'adb-private.pem' \) \
  -print |
  grep -q .; then
  report_failure "private signing or ADB key material is present"
fi

if rg -n --hidden \
  -g '!.git/**' \
  -g '!**/__pycache__/**' \
  -g '!**/build/**' \
  -g '!dist/**' \
  -g '!*.pyc' \
  -g '!scripts/check-secrets.sh' \
  'BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY' .; then
  report_failure "private key block is present"
fi

if rg -n --hidden \
  -g '!.git/**' \
  -g '!**/__pycache__/**' \
  -g '!**/build/**' \
  -g '!dist/**' \
  -g '!*.pyc' \
  -g '!scripts/check-secrets.sh' \
  '/mnt/c/Users/|/mnt/d/Users/|/home/k452b/' .; then
  report_failure "personal home path is present"
fi

if rg -n --hidden \
  -g '!.git/**' \
  -g '!**/__pycache__/**' \
  -g '!**/build/**' \
  -g '!dist/**' \
  -g '!*.pyc' \
  -g '!components/**' \
  -g '!scripts/check-secrets.sh' \
  '\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b' .; then
  report_failure "private LAN address is present"
fi

if rg -n --hidden \
  -g '!.git/**' \
  -g '!**/__pycache__/**' \
  -g '!**/build/**' \
  -g '!dist/**' \
  -g '!*.pyc' \
  -g '!components/**' \
  -g '!scripts/check-secrets.sh' \
  '\bWXSYD[0-9A-Z]+\b' .; then
  report_failure "real-looking Huawei device serial is present"
fi

if [ "${failed}" -ne 0 ]; then
  exit 1
fi

echo "secret check passed"
