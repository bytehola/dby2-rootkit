#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${PROJECT_ROOT}/pc/dby2-rootctl"
PYTHONPATH=. python3 -m unittest discover -s tests -v
python3 -m py_compile dby2_rootctl/*.py

cd "${PROJECT_ROOT}"
bash -n bin/dby2-rootctl
bash -n scripts/build-components.sh
bash -n scripts/build-user-release.sh
bash -n scripts/build-source-release.sh
bash -n scripts/check-secrets.sh
bash -n app/rootkit-manager/build.sh
bash -n components/root-engine/dby2-root.sh
bash -n components/dirtyfrag/build-apk.sh
bash -n components/dirtyfrag/build-harness-apk.sh
bash -n components/dirtyfrag/build-module.sh
bash -n components/dirtyfrag/one-shot-root.sh
bash -n runtime/modules/build.sh
bash -n runtime/root-engine/engine.sh
./scripts/check-secrets.sh
