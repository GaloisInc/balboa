#![allow(unused_imports, dead_code)]

extern crate balboa_rewriter;

use rustls::BulkAlgorithm;

// UGH. This sucks. There's no way for us to expose this module for a benchmark.
// So we just include it with some hackery. The right solution is probably to:
// TODO: move this benchmark and the testsuite into a separate crate where they can live together,
// so that users of balboa-rewriter can avoid depending on the testsuite.
include!("../src/tls_rewriter/testsuite.rs");

fn main() {
    println!("Running tests");
    const SIZE: usize = 1000 * 1000;
    let enable_tls13 = false;
    run_test(
        3000,
        ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage,
        &rustls::version::TLS12,
        |_| NullCompressor,
        |_| NullDecompressor,
        |_| NullCompressor,
        |_| NullDecompressor,
        |stream| {
            stream.write_all(&vec![0; SIZE]).unwrap();
        },
        |stream| {
            let mut buf = vec![0; SIZE];
            stream.read_exact(&mut buf).unwrap();
        },
        0,
        enable_tls13,
    );
    println!("Finished running tests");
}
