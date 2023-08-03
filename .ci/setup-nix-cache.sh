#!/bin/bash
set -e -x
source $(dirname "$0")/nix-cache-env.sh
sudo mkdir -p /etc/nix
sudo bash -c 'cat > /etc/nix/nix.conf' << EOF
substituters = https://cache.nixos.org/ $ROCKY_NIX_BINARY_CACHE_S3_URL
trusted-public-keys = $ROCKY_NIX_BINARY_CACHE_PUBKEY cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
EOF
