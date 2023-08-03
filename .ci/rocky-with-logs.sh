#!/usr/bin/env bash
# pipefail is super important to make sure that failures in the rocky command get propagated to the
# exit code of this bash script
set -euo pipefail
IFS=$'\n\t'
ROOT="$(dirname $0)/.."
"$ROOT/rocky" "$@" 2>&1 | xz -9 > "$ROOT/rocky.logs.txt.xz"
