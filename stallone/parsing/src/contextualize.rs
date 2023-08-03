//! Helpers which consume a stream of log records, and track the per-thread context values that
//! are set in the stream.

use crate::{
    GenericLogEvent, LogRecordMetadataHash, LogRecordMetadataInfo, OwnedValue, ThreadId, Value,
    ValueType,
};
use stallone_common::StallonePID;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub struct UnableToFindValueType {
    hash: LogRecordMetadataHash,
}
impl std::fmt::Display for UnableToFindValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Unable to find log record type for hash: {:?}",
            self.hash
        )
    }
}
impl std::error::Error for UnableToFindValueType {}

/// A log event with its metadata and associated values and associated context values.
#[derive(Debug, Copy, Clone)]
pub struct ContextualizedLogEventPayload<'a, 'b, 'c> {
    pub values: &'c [Value<'c>],
    pub metadata: &'a LogRecordMetadataInfo,
    // TODO: track which log event set this context.
    pub context: &'b HashMap<&'a str, (OwnedValue, &'a ValueType)>,
}

/// The state used to add context to log events.
pub struct LogEventContextualizer<'a> {
    schema: &'a HashMap<LogRecordMetadataHash, LogRecordMetadataInfo>,
    context: HashMap<(StallonePID, ThreadId), HashMap<&'a str, (OwnedValue, &'a ValueType)>>,
    empty_hash_map: HashMap<&'a str, (OwnedValue, &'a ValueType)>,
}
impl<'a> LogEventContextualizer<'a> {
    pub fn new(schema: &'a HashMap<LogRecordMetadataHash, LogRecordMetadataInfo>) -> Self {
        LogEventContextualizer {
            schema,
            context: HashMap::new(),
            empty_hash_map: HashMap::new(),
        }
    }

    /// Process a parsed log event, returning it with context.
    ///
    /// Log events should be `process`ed in order. All log events, not just `LogRecord`s, should be
    /// processed.
    pub fn process<'b, 'c>(
        &'b mut self,
        record: GenericLogEvent<&'c [Value<'c>]>,
    ) -> Result<GenericLogEvent<ContextualizedLogEventPayload<'a, 'b, 'c>>, UnableToFindValueType>
    {
        if let GenericLogEvent::EndedThread {
            pid,
            thread_id,
            timestamp: _,
        } = &record
        {
            self.context.remove(&(*pid, *thread_id));
        }
        record.map_with_error(move |record| {
            let schema = if let Some(schema) = self.schema.get(&record.log_record_type) {
                schema
            } else {
                // TODO: provide more context
                return Err(UnableToFindValueType {
                    hash: record.log_record_type,
                });
            };
            for (field, value) in schema.fields.iter().zip(record.payload.iter()) {
                if !field.is_context {
                    continue;
                }
                let context = self
                    .context
                    .entry((record.pid, record.thread_id))
                    .or_insert(HashMap::new());
                if field.type_id.is_erase_from_context() {
                    context.remove(field.name.as_str());
                } else {
                    context.insert(&field.name, (value.to_owned(), &field.type_id));
                }
            }
            Ok(ContextualizedLogEventPayload {
                values: record.payload,
                metadata: schema,
                context: self
                    .context
                    .get(&(record.pid, record.thread_id))
                    .as_ref()
                    .copied()
                    .unwrap_or(&self.empty_hash_map),
            })
        })
    }
}
