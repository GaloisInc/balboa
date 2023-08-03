# Rely on sccache in CI
export CARGO_INCREMENTAL=0
export ROCKY_SCCACHE_DATA_DIR="/var/lib/rocky-sccache"
export SCCACHE_ENDPOINT="127.64.64.1:9000"
export SCCACHE_BUCKET=rocky-sccache
export SCCACHE_S3_USE_SSL=off
export AWS_ACCESS_KEY_ID=galois
export AWS_SECRET_ACCESS_KEY=galoissecret
export SCCACHE_RUSTC_WRAPPER=sccache-ensuring-key-prefix
export RUSTC_WRAPPER=$SCCACHE_RUSTC_WRAPPER
