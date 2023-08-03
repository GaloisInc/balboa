use crate::schema::*;
use serde::{Deserialize, Serialize};
use stallone_common::{Level, StallonePID};
use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    time::{Duration, SystemTime},
};

mod value;
pub use value::*;

/// A timestamp assigned to (some) log events
#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
pub struct Timestamp {
    /// The epoch is the current time window of the world (the master and all processes connected
    /// to it). It corresponds to the number of milliseconds since the stallone master started. It
    /// doesn't have very fine resolution, though.
    pub epoch_ms: u64,
    pub monotonic: Duration,
    pub walltime: SystemTime,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct ThreadId(pub u64);

/// Information that the stallone master will sample when the log producer first connects to the
/// master.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProcessInfo {
    pub parent_pid: Option<StallonePID>,
    pub os_pid: u32,
    /// This is the build ID of whatever binary stallone is running from. e.g. if stallone is
    /// being used from an LD_PRELOAD'd library, then we will get the build ID of that library.
    #[serde(with = "serde_bytes")]
    pub build_id: Vec<u8>,
    pub exe_path: String,
    pub cmdline: Vec<String>,
    // This might change, but it's at least the initial cwd
    pub cwd: String,
    pub environ: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct MachineUname {
    pub sys: String,
    pub node: String,
    pub release: String,
    pub version: String,
    pub machine: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MachineMetadata {
    pub started_at: SystemTime,
    pub environment_vars: HashMap<String, String>,
    pub socket_path: PathBuf,
    pub stallone_master_pid: u32,
    pub hostname: String,
    pub cpu_info: String,
    pub mem_info: String,
    pub machine_id: String,
    pub ip_addresses: HashMap<String, Vec<IpAddr>>,
    pub uname: MachineUname,
}

/// A Log Record was logged by `stallone::info!` and other similar functions. The payload is the
/// body of the log record.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogRecord<Payload> {
    pub pid: StallonePID,
    pub thread_id: ThreadId,
    pub epoch_ms: u64,
    pub log_record_type: LogRecordMetadataHash,
    pub payload: Payload,
}

/// A log event parameterized by the contents of the Log record payload.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum GenericLogEvent<Payload> {
    /// A log event that one would generate with `stallone::info!` and friends.
    LogRecord(LogRecord<Payload>),
    StartedProcess {
        pid: StallonePID,
        timestamp: Timestamp,
        // This might be None if we fail to fetch process info for some reason.
        process_info: Option<ProcessInfo>,
    },
    StartedThread {
        pid: StallonePID,
        thread_id: ThreadId,
        timestamp: Timestamp,
    },
    EndedThread {
        pid: StallonePID,
        thread_id: ThreadId,
        timestamp: Timestamp,
    },
    EndedProcess {
        pid: StallonePID,
        timestamp: Timestamp,
    },
    DroppedEvents {
        pid: StallonePID,
        timestamp: Timestamp,
        thread_id: ThreadId,
        #[serde(with = "crate::level_serde")]
        level: Level,
        count: u64,
    },
    Timestamp(Timestamp),
    /// The emergency log contains error information about a process that was unable to connect to
    /// stallone, for some reason.
    EmergencyLog {
        timestamp: Timestamp,
        error_reported_at: SystemTime,
        body: String,
    },
}

impl<T> GenericLogEvent<T> {
    pub fn map<U, F: FnOnce(LogRecord<T>) -> U>(self, mapper: F) -> GenericLogEvent<U> {
        #[derive(Debug)]
        enum Never {}
        self.map_with_error::<U, Never, _>(|r| Ok(mapper(r)))
            .expect("The never type cannot be instantiated")
    }

    pub fn map_with_error<'a, U, E, F: FnOnce(LogRecord<T>) -> Result<U, E> + 'a>(
        self,
        mapper: F,
    ) -> Result<GenericLogEvent<U>, E> {
        Ok(match self {
            GenericLogEvent::EmergencyLog {
                timestamp,
                error_reported_at,
                body,
            } => GenericLogEvent::EmergencyLog {
                timestamp,
                error_reported_at,
                body,
            },
            GenericLogEvent::StartedThread {
                pid,
                thread_id,
                timestamp,
            } => GenericLogEvent::StartedThread {
                pid,
                thread_id,
                timestamp,
            },
            GenericLogEvent::EndedThread {
                pid,
                thread_id,
                timestamp,
            } => GenericLogEvent::EndedThread {
                pid,
                thread_id,
                timestamp,
            },
            GenericLogEvent::DroppedEvents {
                pid,
                thread_id,
                timestamp,
                level,
                count,
            } => GenericLogEvent::DroppedEvents {
                pid,
                thread_id,
                timestamp,
                level,
                count,
            },
            GenericLogEvent::EndedProcess { pid, timestamp } => {
                GenericLogEvent::EndedProcess { pid, timestamp }
            }
            GenericLogEvent::Timestamp(ts) => GenericLogEvent::Timestamp(ts),
            GenericLogEvent::LogRecord(record) => {
                let pid = record.pid;
                let thread_id = record.thread_id;
                let epoch_ms = record.epoch_ms;
                let log_record_type = record.log_record_type;
                GenericLogEvent::LogRecord(LogRecord {
                    pid,
                    thread_id,
                    epoch_ms,
                    log_record_type,
                    payload: mapper(record)?,
                })
            }
            GenericLogEvent::StartedProcess {
                pid,
                timestamp,
                process_info,
            } => GenericLogEvent::StartedProcess {
                pid,
                timestamp,
                process_info,
            },
        })
    }
}

/// This is a compressed log record.
pub type CompactLogEvent = GenericLogEvent<serde_bytes::ByteBuf>;
