#![deny(unused_must_use)]

// NOTE: we use log instead of stallone for logging intentionally, to prevent a feedback loop.

mod emergency_log;
mod master;
mod processinfo;
mod sock_thread;
mod timestamp_generator;

pub use master::Master;
pub use processinfo::gather_machine_info;
