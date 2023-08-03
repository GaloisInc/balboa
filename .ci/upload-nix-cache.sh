#!/usr/bin/env bash
set -e
# We explicitly don't set -x to avoid leaking $NIX_BINARY_CACHE_SECRET_KEY
source $(dirname "$0")/nix-cache-env.sh
SECRET_KEY_PATH="/tmp/nix-cache-secret-key"
echo -n "rocky-ci-nix-cache:" > $SECRET_KEY_PATH
echo -n "$NIX_BINARY_CACHE_SECRET_KEY" >> $SECRET_KEY_PATH
echo "Uploading nix packages to cache"
nix copy --all --to "$ROCKY_NIX_BINARY_CACHE_S3_URL&secret-key=$SECRET_KEY_PATH"
