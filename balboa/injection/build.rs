fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/thread_local.c");
    cc::Build::new()
        .file("src/thread_local.c")
        // We pick the "initial-exec" TLS model, since it works with LD_PRELOAD, generates faster
        // code than other TLS models and, most importantly, is definitely async-signal-safe.
        // See https://web.archive.org/web/20210216062208/https://maskray.me/blog/2021-02-14-all-about-thread-local-storage
        // The only _stable_ mechanisms in Rust to do thread-locals allocate memory. That's why we
        // use this C wrapper instead.
        .flag("-ftls-model=initial-exec")
        .flag("--std=c11")
        .opt_level(3) // This code is pretty simple, anyway.
        // TODO: enable cross-language LTO.
        .compile("balba-injection-thread-local");
}
