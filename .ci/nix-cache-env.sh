source $(dirname "$BASH_SOURCE")/sccache-env.sh
mkdir -p ~/.aws
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id=$AWS_ACCESS_KEY_ID
aws_secret_access_key=$AWS_SECRET_ACCESS_KEY
EOF
ROCKY_NIX_BINARY_CACHE_S3_URL="s3://$SCCACHE_BUCKET/rocky-nix?profile=default&endpoint=$SCCACHE_ENDPOINT"
ROCKY_NIX_BINARY_CACHE_PUBKEY="rocky-ci-nix-cache:n3+YvxqPU0xIeazJLqWwLG9Mln/Ig67wu3RTI+GrcCQ="
