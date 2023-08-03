#!/usr/bin/env bash
set -e -x
cd $(dirname "$0")/..
nix-shell --pure -I nixpkgs=./etc/nix/pkgs.nix --arg enableSccache true etc/nix/pkgsets/rust.nix --run 'sccache --show-stats || true'
