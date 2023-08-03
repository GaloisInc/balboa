use std::path::PathBuf;

use stallone_common::positioned_errno;

fn main() {
    let base = PathBuf::from(std::env::var("STALLONE_MASTER").unwrap());
    stallone_common::stallone_emergency_log(&base, "context", &positioned_errno!(-1, "my context"))
        .unwrap();
}
