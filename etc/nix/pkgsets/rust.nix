# rustfmt will be available if useMinimalProfile is false or if addRustFmt is true
{ pkgs ? (import ../pkgs.nix { }), enableSccache ? false, useMinimalProfile ? true, addRustFmt ? false, addLLVMTools ? false }:

with pkgs;
let
  # We strip the whitespace from the rust-toolchain file.
  rust-toolchain-version = builtins.head (builtins.match "([^\r\n]+)[\r\n]*" (builtins.readFile ../../../rust-toolchain));
  rust-toolchain = rust-bin.fromRustupToolchain {
    channel = rust-toolchain-version;
    profile = if useMinimalProfile then "minimal" else null;
    components = (lib.optionals addRustFmt [ "rustfmt" ]) ++ (lib.optionals addLLVMTools [ "llvm-tools-preview" ]);
  };
in
mkShell {
  shellHook = ''
    if [[ `uname` != "Darwin" ]]; then
      export NIX_x86_64_unknown_linux_gnu_SET_BUILD_ID=1
      export NIX_SET_BUILD_ID=1
    fi
    export RUST_BACKTRACE=1
  '' + (if !enableSccache then "" else "source " + ../../../.ci/sccache-env.sh + "\n");
  buildInputs = [
    rust-toolchain
    # This is a RUSTC_WRAPPER that we can use to generate a fully llvm-linked bitcode of some
    # target. We need to use a RUSTC_WRAPPER, since we can't set our LTO/bitcode flags for
    # proc-macro crates. This wrapper checks to see whether we're compiling a proc-macro crate,
    # and will only add our LTO/llvm-bitcore flags for non-proc-macro crates.
    (writeShellScriptBin "rustc-llvm-bitcode-wrapper"
      ''
        if echo "$@" | grep 'crate-type proc-macro' >/dev/null 2>/dev/null; then
          EXTRA_ARGS=""
        else
          EXTRA_ARGS="-Clto -Cembed-bitcode=yes --emit=llvm-bc"
        fi
        if [[ -z "$SCCACHE_RUSTC_WRAPPER" ]]; then
          exec "$@" $EXTRA_ARGS
        else
          exec "$SCCACHE_RUSTC_WRAPPER" "$@" $EXTRA_ARGS
        fi
      '')
  ] ++ (lib.optionals enableSccache [
    sccache
    (writeShellScriptBin "sccache-ensuring-key-prefix"
      ''
        if [[ -z "$SCCACHE_S3_KEY_PREFIX" ]]; then
            echo "MISSING SCCACHE_S3_KEY_PREFIX environment variable"
            exit 1
        fi
        exec ${sccache}/bin/sccache "$@"
      '')
  ]) ++
  (lib.optionals stdenv.isDarwin [
    libiconv
    darwin.apple_sdk.frameworks.Security
    (writeShellScriptBin "xcrun" ''
      # Because cc-rs wants to find an Apple SDK:
      # https://github.com/alexcrichton/cc-rs/blob/bd9c671a48f13884802e9c76f2f38119ee4f64cc/src/lib.rs#L2608-L2614
      if [[ "$1" == "--show-sdk-path" ]] && [[ "$2" == "--sdk" ]]; then
        exit 0
      else
        echo "This fake xcrun was invoked with unexpected options: " "$@" >&2
        exit 1
      fi
    '')
  ]);
  inputsFrom = [ (import ./cacert.nix { }) ];
}
