use crate::timestamp_generator::TimestampGenerator;
use crossbeam_channel::SendError;
use snafu::{ResultExt, Snafu};
use stallone_common::protocol;
use stallone_parsing::CompactLogEvent;
use std::{
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Debug, Snafu)]
enum EmergencyLogStepError {
    #[snafu(display("Error reading directory for emergency log {:?}: {}", path, source))]
    ErrorReadingDirectory {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Error reading file {:?}: {}", path, source))]
    ErrorReadingFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Error getting file creation time {:?}: {}", path, source))]
    ErrorGettingFileCreationTime {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Error deleting file {:?}: {}", path, source))]
    ErrorDeletingFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    ELSESendError {
        source: SendError<CompactLogEvent>,
    },
}

fn collect_emergency_log_events_step(
    timestamp_generator: &TimestampGenerator,
    path: &Path,
    drain: &mut crossbeam_channel::Sender<CompactLogEvent>,
) -> Result<(), EmergencyLogStepError> {
    // TODO: we don't want to keep re-reading a file and failing each time.
    // We want to check whether a filename ends with "." followed by this extension.
    let mut suffix = [0; protocol::STALLONE_EMERGENCY_LOG_EXT.as_bytes().len() + 1];
    suffix[0] = b'.';
    suffix[1..].copy_from_slice(protocol::STALLONE_EMERGENCY_LOG_EXT.as_bytes());
    for entry in std::fs::read_dir(path).with_context(|_| ErrorReadingDirectorySnafu {
        path: path.to_path_buf(),
    })? {
        let entry = entry.with_context(|_| ErrorReadingDirectorySnafu {
            path: path.to_path_buf(),
        })?;
        if !entry.file_name().as_os_str().as_bytes().ends_with(&suffix) {
            continue;
        }
        let path = entry.path();
        let error_reported_at = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .with_context(|_| ErrorGettingFileCreationTimeSnafu {
                path: path.to_path_buf(),
            })?;
        let contents_results =
            std::fs::read_to_string(&path).with_context(|_| ErrorReadingFileSnafu {
                path: path.to_path_buf(),
            });
        // If reading the contents fails, because, for example, the contents aren't UTF-8, we don't
        // want to keep retrying the same file over and over again. But we need to read the file
        // before we can remove it. As a result, we collect the result from reading the file into
        // a string, but we only check to see whether it caused an error AFTER we've deleted the file.
        std::fs::remove_file(&path).with_context(|_| ErrorDeletingFileSnafu {
            path: path.to_path_buf(),
        })?;
        let body = contents_results?;
        drain
            .send(CompactLogEvent::EmergencyLog {
                error_reported_at,
                timestamp: timestamp_generator.generate(),
                body,
            })
            .context(ELSESendSnafu)?;
    }
    Ok(())
}

pub(crate) fn collect_emergency_log_events(
    timestamp_generator: &TimestampGenerator,
    base_path: PathBuf,
    keep_master_running: Arc<AtomicBool>,
    mut drain: crossbeam_channel::Sender<CompactLogEvent>,
) {
    // TODO: use inotify?
    let emergency_path = base_path.join(protocol::EMERGENCY_LOG_DIRECTORY_NAME);
    loop {
        match collect_emergency_log_events_step(&timestamp_generator, &emergency_path, &mut drain) {
            Ok(_) => {}
            Err(EmergencyLogStepError::ELSESendError { .. }) => {
                break;
            }
            Err(e) => {
                log::warn!("Unable to probe for emergency log events: {}", e);
            }
        }
        if !keep_master_running.load(Ordering::SeqCst) {
            // Do one more step before exiting, to ensure that we capture any emergency logs that
            // were created before keep_master_running went low. There might've been a pause in
            // between when we finished the step above and when keep_master_running went low.
            match collect_emergency_log_events_step(
                &timestamp_generator,
                &emergency_path,
                &mut drain,
            ) {
                Ok(_) | Err(EmergencyLogStepError::ELSESendError { .. }) => {}
                Err(e) => {
                    log::warn!("Unable to probe for emergency log events: {}", e);
                }
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
