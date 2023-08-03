//! Stallone is a low-latency (~10ns "ish" per log event) logging library.
//!
//! # Motivation
//! * The more latency that we add to Balboa, the more likely it is to be detected.
//! * Standard rust logging libraries clock in at tens to hundreds of microseconds
//! per logging line. Since it takes Balboa under 100 microseconds (typically) to
//! operate on a single system call, it seems unreasonable to more than double the
//! latency, for a single log line.
//!
//! # How to use it (as a client to log)
//! 1.  Add an entry to your `Cargo.toml` file, like:
//!     `stallone = { path = "../../stallone/log" }`
//!     Because the `path` directive specifies relative paths, you may need to
//!     specify a different path for your project.
//! 2.  Initialize Stallone using `stallone::initialize_for_process(path)`, where
//!     path is the path to a Stallone master socket.
//! 3.  Log things!
//!
//! ## How does one "Log things!" with Stallone?
//! Here's some example code:
//! ```rust
//! fn say_hello(name: &str, age: i32) {
//!     stallone::info!(
//!         "I am greeting you!",
//!         name: &str = name,
//!         age: i32 = age,
//!     );
//! }
//! ```
//!
//! It produces a log line which looks like (when rendered):
//! ```text
//! [~12.6s (0) Info (stallone/tools/src/test_log.rs:26:5)] I am greeting you!
//!     Stallone-Specific PID: 1
//!     Thread ID: 0675218811354526AABBBEEE7797E326
//!     age: 77
//!     name: "Joe"
//! ```
//!
//! Note that, unlike a standard logging framework, Stallone supports structured
//! logging. Rather than formatting fields into a log line, each log record
//! consists of structured data. As a result, in addition to the rendered log line
//! above, we can also see the log in JSON form:
//! ```json
//! {
//!     "LogRecord": {
//!         "pid": 1,
//!         "thread_id": 114998777700517668551535043556865021446,
//!         "epoch": 100,
//!         "per_epoch_index": 0,
//!         "log_record_type": 1137838467130642299,
//!         "payload": {
//!             "schema": {
//!                 "hash_value": 1137838467130642299,
//!                 "level": 2,
//!                 "message": "I am greeting you!",
//!                 "file": "stallone/tools/src/test_log.rs",
//!                 "module_path": "stallone_tools::test_log",
//!                 "line": 26,
//!                 "column": 5,
//!                 "key_value_pairs": [
//!                     {
//!                         "name": "name",
//!                         "ty": "Str",
//!                         "is_context": false
//!                     },
//!                     {
//!                         "name": "age",
//!                         "ty": "I32",
//!                         "is_context": false
//!                     }
//!                 ]
//!             },
//!             "values": {
//!                 "age": 77,
//!                 "name": "Joe"
//!             },
//!             "context": {}
//!         }
//!     }
//! }
//! ```
//! This enables us to easily perform queries over log records without having to
//! resort to string parsing.
//!
//! ### Logging Custom Types
//! You can only log types which implement the `stallone::LoggableMetadata trait`. Rather than implementing this trait yourself, it is preferable to instead `derive` it, as in the example below:
//!
//! ```rust
//! use stallone::LoggableMetadata;
//!
//! #[derive(Debug, LoggableMetadata)]
//! pub enum RecordType {
//!     Handshake,
//!     ApplicationData,
//!     ChangeCipherSpec,
//!     Alert,
//!     Other(u8),
//! }
//!
//! #[derive(Debug, LoggableMetadata)]
//! pub struct RecordHeader {
//!     pub record_type: RecordType,
//!     pub version: u16,
//!     pub size: usize,
//! }
//! ```
//!
//! ### Picking a log level
//! Unlike many traditional logging frameworks, it is possible for Stallone to drop
//! log events. If log events are dropped, you'll see a message (see below) telling
//! you how many messages were dropped, and when.
//! ```text
//! [5.478387888s (~5.47s);  2019-10-29 00:12:50.725773 UTC] Dropped 902805 Info Log Events for Process 1 thread 3F9DD55E41ED3620AB3DF09D345EDC11
//! ```
//!
//! Stallone's buffers are able to hold about 100,000 log events before events
//! start getting dropped. Because the master process is constantly draining log
//! events, in practice, it seems unlikely that events will be dropped (I've only
//! been able to cause messages to be dropped by logging hundreds of thousands of
//! times in under 10 milliseconds).
//!
//! All that being said, because it is possible (most like if the TA3 logging API
//! gets backed up) that events will be dropped, it is a smart idea to choose an
//! appropriate log level. Stallone supports four logging levels: Error, Warn, Info,
//! and Debug. You can log to each log level via an appropriate macro (e.g.
//! `stallone::info!`). Each log level has its own separate buffer. As a result,
//! log events from each buffer are dropped independently. For example, even if we
//! are spamming many debug events, and debug events are being dropped, that is
//! entirely independent of all the other buffers, and so other buffers can still
//! accept events even if the debug-level buffer is full.
//!
//! When picking a log level, it is a smart idea to choose a log level based on
//! how important it is that the log message be seen. Ideally, the debug log level
//! will have the most messages, followed by info, and so forth. This helps ensure
//! that, even if messages do get dropped, they are mostly less important debug
//! messages.
//!
//! ### Logging with Context
//! Stallone can optionally associate logging information with the currently running
//! thread, tagging the thread with contextual information. Here's an example
//! excerpt from logs of Icecast and VLC running with Balboa:
//! ```text
//! [~14.95s (0) Debug (balboa/injection/src/lib.rs:262:17)] For Server IP and Port, should we intercept that connection?
//!     Stallone-Specific PID: 2
//!     Thread ID: 4C3CEBEA548FC82D83629D97B517AA59
//!     decision: true
//!     ip: V4("127.0.0.1")
//!     port: 8443
//!
//!
//! [~14.95s (1) Info (balboa/rewriter/src/tls_rewriter.rs:353:9)] Begin OUTGOING rewrite
//!     Stallone-Specific PID: 2
//!     Thread ID: 4C3CEBEA548FC82D83629D97B517AA59
//!     buffer_length: 242
//!     mode: Client
//!     client_random: None
//!     (Context set at (14.95s, 1)) mode: Client
//!     (Context set at (14.95s, 1)) client_random: None
//!
//!
//! [~14.95s (2) Debug (balboa/rewriter/src/tls_rewriter.rs:121:17)] Got client random
//!     Stallone-Specific PID: 2
//!     Thread ID: 4C3CEBEA548FC82D83629D97B517AA59
//!     client_random: "XbeJJwGp9x6YXB/LgZLVMa3ltKRgwpJkOL5GklJYnEI="
//!     (Context set at (14.95s, 1)) mode: Client
//!     (Context set at (14.95s, 2)) client_random: "XbeJJwGp9x6YXB/LgZLVMa3ltKRgwpJkOL5GklJYnEI="
//!
//!
//! [~14.95s (3) Debug (balboa/rewriter/src/tls_rewriter/states.rs:124:9)] Or-ing bits into TLS state
//!     Stallone-Specific PID: 2
//!     Thread ID: 4C3CEBEA548FC82D83629D97B517AA59
//!     has_server_random_and_ciphersuite: false
//!     invalid: false
//!     has_client_random: true
//!     (Context set at (14.95s, 1)) mode: Client
//!     (Context set at (14.95s, 2)) client_random: "XbeJJwGp9x6YXB/LgZLVMa3ltKRgwpJkOL5GklJYnEI="
//!
//!
//! [~14.95s (4) Info (balboa/rewriter/src/tls_rewriter.rs:379:9)] END OUTGOING rewrite
//!     Stallone-Specific PID: 2
//!     Thread ID: 4C3CEBEA548FC82D83629D97B517AA59
//!     mode: stallone::EraseFromContext
//!     client_random: stallone::EraseFromContext
//! ```
//!
//! In the above, we see the logs corresponding to VLC initiating a connection with
//! Icecast. In the "Begin OUTGOING rewrite" log event, we set context saying what
//! mode (client or server) the TLS connection is. This information is replicated
//! (efficiently: setting context fields is free for the log event producer) across
//! each subsequent log event until it gets overwritten or cleared. When Balboa
//! sees the client random tag, it updates the context with the client random
//! (which makes it easy to identify which log messages are associated with which
//! TLS connection). Once the rewrite finishes, Balboa clears the `mode` and
//! `client_random` context fields.
//!
//! Here's an example of how to set context:
//! ```text
//! stallone::info!(
//!     "Begin OUTGOING rewrite",
//!     #[context(true)]
//!     mode: TLSRewriterMode = self.common.mode,
//!     #[context(true)]
//!     client_random: Option<tls::ClientRandom> =
//!         if self.common.shared_state.state().has_client_random() {
//!             Some(tls::ClientRandom(
//!                 self.common.shared_state.client_random.load(),
//!             ))
//!         } else {
//!             None
//!         },
//!     buffer_length: usize = buf.len(),
//! );
//! ```
//! and how to clear context:
//! ```rust
//! stallone::info!(
//!     "END OUTGOING rewrite",
//!     #[context(true)]
//!     mode: stallone::EraseFromContext = stallone::EraseFromContext,
//!     #[context(true)]
//!     client_random: stallone::EraseFromContext = stallone::EraseFromContext,
//! );
//! ```
//!
//! ## Time
//! The timestamp information `~12.6s (0)` is interpreted as, this message was
//! logged approximately 12.6 seconds since the master process started up.
//!
//! TODO: talk about inter-thread timing vs intra-thread timing.
//!
//! ## A note about Stallone and futures
//! While Stallone will operate properly in the presence of futures, its behavior
//! of associating data with the current thread's ID may be undesirable, because a
//! task won't be pegged to a single thread.
//!
//! # Stallone in Tests
//! In tests, if you want to see Stallone output, you can do one (or both) of the following:
//!
//! 1. Set the environment variable `STALLONE_TEST_MASTER` to the path of a running stallone master.
//!    This will cause messages logged by stallone to be sent to the given master.
//! 2. Set the environment variable `STALLONE_TEST_LOG` to `1`. This will cause messages logged by
//!    Stallone to be printed to standard error.
//!
//! # Design
//! TODO: explain the design

#![deny(unused_must_use)]

#[doc(hidden)]
pub use stallone_common::{const_siphash, internal_metadata_structures, LoggableMetadata};
pub use stallone_common::{Level, NUM_LEVELS};
pub use stallone_derive::LoggableMetadata;
use std::path::Path;

mod build_id;

mod global_state;
mod macros;
#[doc(hidden)]
pub mod stallone_in_tests;
mod thread_local;
pub use macros::*;
pub use thread_local::stallone_thread_local;

/// Initialize the stallone for this process.
///
/// This function will attempt to connect to the stallone master pointed to by the `STALLONE_MASTER`
/// environment variable. If the `STALLONE_MASTER` environment variable doesn't exist, or if logging
/// fails to be established, this function will silently fail. (If the `STALLONE_MASTER` environment
/// variable is set, failures in initializing stallone will be reported as "emergency log" messages)
///
/// If you attempt to log messages before initialization, the log messages will be silently dropped.
///
/// # Example Usage
/// ```
/// stallone::initialize(Default::default());
/// ```
#[cold]
pub fn initialize(config: StalloneConfig) {
    if let Some(path) = std::env::var_os("STALLONE_MASTER") {
        let _ = crate::global_state::initialize(Path::new(&path), &config);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StalloneConfig {
    /// The size, in bytes, of the buffer of log payloads.
    pub buffer_size: usize,
    /// A limit, for each log level, of the maximum number of bytes for that log level which can
    /// live in the log payload buffer.
    ///
    /// `log_level_capacities[0]` is the capacity for the _Error_ log level, index `1` corresponds
    /// to _Warning_, etc.
    ///
    /// These capacities do not need to add up to the `buffer_size`. A log record will be dropped
    /// if there's not enough room in the buffer or if the log level capacity would be exceeded.
    pub log_level_capacities: [u64; NUM_LEVELS],
    /// If set to true, stallone will re-initialize itself on fork to set itself up for logging in
    /// the forked process. If false, stallone will clean up after itself on fork, but will not
    /// re-initialize itself for logging in the subprocess.
    ///
    /// The default value for this option is `false`. Setting this to `true` can result in
    /// verbose output from stallone. In particular, spawning a subprocess on UNIX systems consists
    /// of a `fork()` followed by an `exec()`. If stallone is told to follow forked processes, then
    /// it may report a `fork()` followed by the death of the forked process when the exec happens.
    /// (In some cases, Rust may use posix_spawn which bypasses Stallone's fork handler.)
    pub follow_forks: bool,
}
impl Default for StalloneConfig {
    fn default() -> Self {
        // TODO: what are the right defaults?
        StalloneConfig {
            buffer_size: 1024 * 1024 * 3,
            log_level_capacities: [1024 * 1024 * 10, 1024 * 1024 * 2, 1024 * 1024, 1024 * 1024],
            follow_forks: false,
        }
    }
}

/// If this value is set for a context field, then that field won't be added to future log events.
///
/// There is nothing "special" about this type, except that Stallone log parsers know to look for
/// a type of this specific name.
#[derive(Debug, Clone, Copy)]
pub struct EraseFromContext;

impl LoggableMetadata for EraseFromContext {
    const TYPE_ID: stallone_common::internal_metadata_structures::ValueType<'static> =
        stallone_common::internal_metadata_structures::ValueType::Record {
            contents: stallone_common::internal_metadata_structures::RecordType {
                name: "stallone::EraseFromContext",
                fields: &[],
            },
        };

    #[inline(always)]
    fn log_size(&self) -> usize {
        0
    }

    #[inline(always)]
    fn log_serialize(&self, _buf: &mut [u8]) {}
}
