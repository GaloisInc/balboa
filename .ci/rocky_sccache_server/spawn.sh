#!/usr/bin/env nix-shell
#!nix-shell --pure default.nix -i bash
set -euxo pipefail
IFS=$'\n\t'

source $(dirname "$0")/../sccache-env.sh

tmp=$(mktemp -d)
function run_daemon() {
    rocky_sccache_server --bind "$SCCACHE_ENDPOINT" --data "$ROCKY_SCCACHE_DATA_DIR" --ready "$tmp/ready" &
}

mkfifo "$tmp/ready"
run_daemon &
# Wait for the server to start
head -c 1 "$tmp/ready" > /dev/null
rm "$tmp/ready"
rmdir "$tmp"
sccache --start-server
