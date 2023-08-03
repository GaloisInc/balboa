use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use stallone_parsing::{
    ContextualizedLogEventPayload, GenericLogEvent, LogRecordMetadataInfo, MachineMetadata,
    OwnedValue, SerializeValueWithType, Timestamp, Value, ValueType,
};
use std::collections::HashMap;
use std::time::Duration;

pub(super) struct SerializedContextualizedLogEventPayload<'a, 'b, 'c>(
    pub(super) ContextualizedLogEventPayload<'a, 'b, 'c>,
);
impl<'a, 'b, 'c> Serialize for SerializedContextualizedLogEventPayload<'a, 'b, 'c> {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_map(Some(3))?;
        s.serialize_entry("metadata", &self.0.metadata)?;
        struct SerializeContext<'a>(&'a HashMap<&'a str, (OwnedValue, &'a ValueType)>);
        impl<'a> Serialize for SerializeContext<'a> {
            fn serialize<S>(
                &self,
                serializer: S,
            ) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
            where
                S: Serializer,
            {
                let mut s = serializer.serialize_map(Some(self.0.len()))?;
                for (k, (v, t)) in self.0.iter() {
                    s.serialize_entry(k, &SerializeValueWithType(v, t))?;
                }
                s.end()
            }
        }
        s.serialize_entry("context", &SerializeContext(self.0.context))?;
        struct SerializeValues<'a, 'b>(&'a LogRecordMetadataInfo, &'b [Value<'b>]);
        impl<'a, 'b> Serialize for SerializeValues<'a, 'b> {
            fn serialize<S>(
                &self,
                serializer: S,
            ) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
            where
                S: Serializer,
            {
                let mut s = serializer.serialize_map(Some(self.0.fields.len()))?;
                for (v, f) in self.1.iter().zip(self.0.fields.iter()) {
                    s.serialize_entry(&f.name, &SerializeValueWithType(v, &f.type_id))?;
                }
                s.end()
            }
        }
        s.serialize_entry("values", &SerializeValues(self.0.metadata, self.0.values))?;
        s.end()
    }
}

struct DisplayTimestamp<'a>(&'a Timestamp);
impl<'a> std::fmt::Display for DisplayTimestamp<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let ts = self.0;
        let wall_time: chrono::DateTime<chrono::Utc> = ts.walltime.into();
        write!(
            f,
            "[{:?} (~{:?});  {}]",
            ts.monotonic,
            Duration::from_millis(ts.epoch_ms),
            wall_time,
        )
    }
}

pub(super) struct DisplayMachineMetadata<'a>(pub(super) &'a MachineMetadata);
impl<'a> std::fmt::Display for DisplayMachineMetadata<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Started master at {:?}\n",
            chrono::DateTime::<chrono::Utc>::from(self.0.started_at)
        )?;
        write!(f, "    ENV: {:?}\n", self.0.environment_vars)?;
        write!(
            f,
            "    Stallone master pid {:?}\n",
            self.0.stallone_master_pid
        )?;
        write!(f, "    Stallone master path {:?}\n", self.0.socket_path)?;
        write!(f, "    Hostname: {:?}\n", self.0.hostname)?;
        write!(f, "    /proc/cpuinfo: {:?}\n", self.0.cpu_info)?;
        write!(f, "    /proc/meminfo: {:?}\n", self.0.mem_info)?;
        write!(f, "    /etc/machine-id: {:?}\n", self.0.machine_id)?;
        write!(f, "    IP addresses: {:?}\n", self.0.ip_addresses)?;
        write!(f, "    Uname: {:?}\n", self.0.uname)?;
        Ok(())
    }
}

pub(super) struct DisplayLogEvent<'a, 'b, 'c, 'd>(
    pub(super) &'a GenericLogEvent<ContextualizedLogEventPayload<'b, 'c, 'd>>,
);

impl<'a, 'b, 'c, 'd> std::fmt::Display for DisplayLogEvent<'a, 'b, 'c, 'd> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use GenericLogEvent::*;
        match self.0 {
            LogRecord(r) => {
                let payload = &r.payload;
                writeln!(
                    f,
                    "[~{:?} {:?} ({}:{}:{})] {}",
                    Duration::from_millis(r.epoch_ms),
                    payload.metadata.level,
                    payload.metadata.file,
                    payload.metadata.line,
                    payload.metadata.column,
                    payload.metadata.message,
                )?;
                write!(
                    f,
                    "    Stallone-Specific PID: {:?}\n    Thread ID: {:?}",
                    r.pid, r.thread_id
                )?;
                assert_eq!(payload.values.len(), payload.metadata.fields.len());
                for (v, field) in payload.values.iter().zip(payload.metadata.fields.iter()) {
                    write!(
                        f,
                        "\n{}",
                        textwrap::indent(
                            &format!(
                                "{}: {:#?}",
                                field.name,
                                serdebug::debug(&SerializeValueWithType(v, &field.type_id))
                            ),
                            "    "
                        )
                    )?;
                }
                for (k, (v, t)) in payload.context.iter() {
                    write!(
                        f,
                        "\n{}",
                        textwrap::indent(
                            &format!(
                                "(ctx) {}: {:#?}",
                                k,
                                serdebug::debug(&SerializeValueWithType(v, t))
                            ),
                            "    "
                        )
                    )?;
                }
            }
            StartedProcess {
                pid,
                timestamp,
                process_info,
            } => {
                write!(
                    f,
                    "{} Started Process {:?}",
                    DisplayTimestamp(timestamp),
                    *pid,
                )?;
                if let Some(pi) = process_info.as_ref() {
                    write!(
                        f,
                        "\n{}",
                        textwrap::indent(&serdebug::to_string_pretty(pi), "    ")
                    )?;
                }
            }
            StartedThread {
                pid,
                thread_id,
                timestamp,
            } => {
                write!(
                    f,
                    "{} Started Thread {:?} for Process {:?}",
                    DisplayTimestamp(timestamp),
                    *thread_id,
                    *pid,
                )?;
            }
            EndedThread {
                pid,
                thread_id,
                timestamp,
            } => {
                write!(
                    f,
                    "{} Ended Thread {:?} for Process {:?}",
                    DisplayTimestamp(timestamp),
                    *thread_id,
                    *pid,
                )?;
            }
            EndedProcess { pid, timestamp } => {
                write!(
                    f,
                    "{} Ended Process {:?}",
                    DisplayTimestamp(timestamp),
                    *pid,
                )?;
            }
            DroppedEvents {
                pid,
                timestamp,
                thread_id,
                level,
                count,
            } => {
                write!(
                    f,
                    "{} Dropped {} {:?} Log Events for Process {:?} thread {:?}",
                    DisplayTimestamp(timestamp),
                    *count,
                    *level,
                    *pid,
                    *thread_id
                )?;
            }
            Timestamp(t) => {
                write!(f, "{}", DisplayTimestamp(t))?;
            }
            EmergencyLog {
                timestamp,
                body,
                error_reported_at,
            } => {
                write!(
                    f,
                    "{} (reported at {}) Emergency Log: {}",
                    DisplayTimestamp(timestamp),
                    chrono::DateTime::<chrono::Utc>::from(*error_reported_at),
                    body
                )?;
            }
        }
        Ok(())
    }
}
