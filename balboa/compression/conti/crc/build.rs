use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").ok();
    if arch.as_ref().map(|x| x.as_str()) != Some("x86_64") {
        return;
    }
    let target = env::var("TARGET").unwrap();
    let sources = vec![
        "cbits/crc.c",
        "cbits/crc.h",
        "cbits/crc_wimax.h",
        "cbits/crcext.h",
        "cbits/types.h",
    ];
    for src in &sources {
        println!("cargo:rerun-if-changed={}", src);
    }
    let mut build = cc::Build::new();
    for src in &sources {
        if src.ends_with(".c") {
            build.file(src);
        }
    }
    build.opt_level(3);
    build.pic(true);
    let mut flags = vec!["-msse4.2", "-mpclmul", "-Wall", "-Wextra", "-pedantic"];
    if !build.get_compiler().is_like_clang() {
        flags.push("-falign-loops=32");
    }
    for flag in flags {
        build.flag(flag);
    }
    if !target.contains("darwin") && !target.contains("windows") {
        build.flag("-fvisibility=hidden");
    }
    build.debug(true);
    // build.flag("-v");
    build.compile("balboaconticrc");
    println!("cargo:root={}", env::var("OUT_DIR").unwrap());
}
