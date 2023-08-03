# `rocky`: A rust library suite for channel obfuscation

`rocky` provides a suite of libraries for channel obfuscation.

* `balboa`: A framework for building obfuscated channels based on embedding
  messages in TLS traffic.
* `mickey`: A library for making a reliable and in-order transport out of `balboa` channels.
* `stallone`: A low-latency (sub-10-nanosecond) logging library, inspired but
somewhat different from the [nanolog](https://github.com/PlatformLab/NanoLog) logging library.
Such a high-performant logging library is needed to avoid introducing possible timing attacks.

## A Note on Security

`rocky` should be considered **PROTOTYPE** software. Do not deploy it in
production, or trust it with sensitive data.

We've made some choices in our deployment which are downright INSECURE, but are
okay for prototype purposes. Please DO NOT USE IN PRODUCTION.

# How to use the Rocky repo
## Setting up your machine
You'll need to install [Nix](https://nixos.org/download.html) on your machine. Nix is a package
manager that we use to ensure that everyone can execute the Rocky codebase in a reproducible
environment.

As of this writing (May 2021), installing Nix on macOS can be a bit tricky due to recent changes to
security policies on the Mac. It's definitely do-able, but it's slightly trickier than installing
Nix on Linux.

Also, note that if you have Cargo's `git-fetch-with-cli` configuration option enabled globally, it
might cause build failures with Cargo inside of Nix (since the Nix environment does not have the
git CLI installed).

### Optional Setup
#### Rustup
To build the Rust code and run the Rust unit tests, you can either run Rust from inside of the Nix
environment (which is the most hermetic/stable option), or you can run Rust outside of the Nix
environment. This can be convienent for checking that the Rust code compiles, or to run the Rust
unit tests (since they only depend on Rust itself, and so can be safely run outside of the Nix
environment).

If you want to be able to run Rust from outside of the Nix environment, you should install
[Rustup](https://rustup.rs).

# Working with the Rocky codebase
## Working with Rust Code
If you've installed rustup (see above), then you can run all of these commands in your normal shell.
If you haven't installed rustup, you can run these Rust commands inside of a Nix shell, which can
be entered by running `nix-shell --pure` in the root of the rocky repo.

The standard `cargo` commands for working with rust code will work with the rocky codebase:

* `cargo check --workspace --all-targets` will check the codebase for errors. This command is faster
  than a full build.
* `cargo doc --workspace --no-deps` will generate rust documentation for the entire codebase, and
  put the documentation in `target/doc`
* `cargo test --workspace` will run the Rust-language unit tests in the codebase.

## Working with Integration Tests
Much of the rocky codebase would be hard or impossible to test with just unit testing in the Rust
test framework. As a result, in addition to the Rust tests, we also have Python tests which will
execute the rust code in various situations.

The command to execute the Python tests is `./rocky test`. This command will automatically compile
any Rust code that's needed for the tests. See `./rocky test --help` for more info on available
options. If a test fails, logs for the test will be written to `/tmp/rocky`.

While some logs are available in textual format, the majority of the logs are stored in Stallone's
compressed log format. See the "Stallone" section below for how to view them.

The command `./rocky pdoc` will write documentation on the Python code to `target/pdoc`.

## Utilities for working with the codebase
* `./rocky format` will ensure that all of the code in the codebase has a consistent style.
* `./rocky mypy` will run the [Mypy type checker](http://www.mypy-lang.org/) to type-check the
  Python code in the codebase.

Both of these scripts will be run as part of Rocky's CI (Continuous Integration), and the CI will
reject changes which do not pass both these checks.

## Stallone Logs
For efficiency reasons, Stallone does not directly write logs in plain-text format. Instead,
applications talk to the Stallone collector process in order to submit log data. The collector will
then write those logs into a binary format, which can be decompressed as either plain text or JSON
afterwards.

Operations with stallone can be executed by running the `stallone-tools` command. You can access
this command at `target/release/stallone-tools` after building it with
`cargo build --release --bin stallone-tools`. (If you'd prefer a shorter build time, at the expense
of a slower binary, you can omit the `--release` flag.)

All of the `stallone-tools` subcommands are documented with the `--help` flag, but here's a summary.

`stallone-tools collect-logs` will launch a Stallone log collector, which will write compressed logs
to the designated output.

`stallone-tools decompress-logs` will decompress the compressed logs. In order to decompress the
compressed logs, `decompress-logs` must be provided either the executables that contributed to the
logs, or (at least) the metadata of the schema of the log events. This metadata is equivalent (for
Stallone's purposes) to providing the raw binary. The `stallone-tools parse-binary-metadata` command
will extract the metadata from binaries.

When running the Python tests in the Rocky repository, the testing framework will have already run
the `parse-binary-metadata` command for you, so you won't need to worry about finding which binaries
produced logging output.

### Example of Decompressing Logs from a Test
```
target/debug/stallone-tools decompress-logs /tmp/rocky/test_conti_Aes128GCM_BuildMode0/logs/stallone_stallone/raw.bin log.txt /tmp/rocky/stallone-metadata.yml
````

Note that the warning "failed to fill whole buffer" is currently emitted on every invocation. This
is a bug in the code (see the comment in `stallone/tools/src/main.rs` if you're curious).

## Profiling

### Using Perf

1. Install perf via your local Linux package manager.
2. Install a flamegraph toolsuite (https://github.com/brendangregg/FlameGraph or via your package manager)
3. Build a standalone binary (e.g. `cargo build --release --example chunk_wire_protocol_incoming`)
4. Install `flamegraph-rs`: `cargo install flamegraph`
5. Generate a flamegraph: `flamegraph target/release/example/chunk_wire_protocol_incoming`
   - Behind the scenes, this invokes `perf record`, `stackcollapse` and `flamegraph`.
8. View the flamegraph in your browser.

# License

MIT License

The `internal_ring_buffer.rs` file contains code from https://github.com/utaal/spsc-bip-buffer/blob/32342b38984d28abb2f61125900ca2b3e94e777f/src/lib.rs
That code is MIT/Apache dual-licensed.

The `crc/src/baseline.rs` file contains code from https://github.com/RustAudio/ogg/blob/0d14027131ec16bd7959fd5246ac5b0a2977370d/src/crc.rs
That code is licensed under what looks like a 3-clause BSD license.

The `crc/cbits` files are from https://github.com/intel/soft-crc/tree/34a84bfd8278ff48e6aa67f0746618242266c8a2
That code is licensed under a 3-clause BSD license.

The `third_party/ring` directory contains (modified) code from the ring crate.
That code is liberally licensed, but apparently the licencing situation is complicated, so look at its license file.
We have made custom changes to that directory. We're only changing things to mark some internals of `ring` as public.

The `third_party/serdebug` library is MIT licensed from https://github.com/RReverser/serdebug/tree/37569734af3987ce38e43fe28682f5e8c2d184b2.
Its files have been copied in, and we have made some changes.

`balboa/rewriter/src/tls/gen_prf_tests.go` contains code from Go's TLS library. That code is
licensed under a "BSD-style" license.

`etc/nix/docker-image.nix` contains some MIT-licensed code from https://github.com/NixOS/nixpkgs/blob/fc63be7ac8c33e4ef0e45b868e89a9181a1525e5/pkgs/build-support/docker/examples.nix

`etc/nix/sources.nix` comes from the `niv` project, and is MIT-licensed.

# Authors

- Alex J. Malozemoff <amaloz@galois.com>
- Brent Carmer <bcarmer@galois.com>
- James Parker <james@galois.com>
- Marc Rosen <marc@galois.com>
- Panchapakesan Shyamshankar <shyam@galois.com>

# Acknowledgements
This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract Number FA8750-19-C-0085. Any opinions, findings and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the DARPA.

Copyright © 2019-2022 Galois, Inc.
