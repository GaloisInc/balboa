#![deny(unused_must_use)]

use crate::printing::{
    DisplayLogEvent, DisplayMachineMetadata, SerializedContextualizedLogEventPayload,
};
use anyhow::Context;
use bumpalo::Bump;
use stallone_parsing::{
    CompactLogEvent, GenericLogEvent, LogEventContextualizer, LogRecordMetadataHash,
    LogRecordMetadataInfo, MachineMetadata,
};
use std::collections::hash_map::Entry;
use std::io::BufReader;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use std::{
    collections::HashMap,
    convert::Infallible,
    io::{BufWriter, Read, Write},
    path::PathBuf,
    str::FromStr,
};
use structopt::StructOpt;

mod printing;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

const STALLONE_METADATA_YAML_VERSION_COMMENT: &'static [u8] =
    b"# Stallone YAML binary metadata version 2\n";
const STALLONE_BINARY_VERSION: &'static str = "Stallone version 2.1";

enum Input {
    Stdin,
    Path(PathBuf),
}
impl FromStr for Input {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "-" {
            Self::Stdin
        } else {
            Self::Path(PathBuf::from_str(s)?)
        })
    }
}
impl Input {
    fn with_read<F, T>(&self, cb: F) -> anyhow::Result<T>
    where
        for<'a> F: FnOnce(&'a mut dyn Read) -> anyhow::Result<T>,
    {
        match self {
            Input::Stdin => {
                let stdin = std::io::stdin();
                let mut locked = stdin.lock();
                cb(&mut locked)
            }
            Input::Path(p) => {
                let mut f = std::fs::File::open(&p)
                    .with_context(|| format!("Failed to open file (for reading) at {:?}", &p))?;
                cb(&mut f)
            }
        }
    }
}

enum Output {
    Stdout,
    Path(PathBuf),
}
impl std::fmt::Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Output::Stdout => write!(f, "stdout"),
            Output::Path(p) => write!(f, "{:?}", p),
        }
    }
}
impl FromStr for Output {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "-" {
            Self::Stdout
        } else {
            Self::Path(PathBuf::from_str(s)?)
        })
    }
}
impl Output {
    fn with_write<F, T>(&self, cb: F) -> anyhow::Result<T>
    where
        for<'a> F: FnOnce(&'a mut dyn Write) -> anyhow::Result<T>,
    {
        match self {
            Self::Stdout => {
                let stdout = std::io::stdout();
                let mut locked = stdout.lock();
                cb(&mut locked)
            }
            Self::Path(p) => {
                let mut f = std::fs::File::create(&p)
                    .with_context(|| format!("Failed to open file (for writing) at {:?}", &p))?;
                cb(&mut f)
            }
        }
    }
}

#[derive(StructOpt)]
struct Opt {
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Clone, Copy, Debug)]
enum OutputFormat {
    Json,
    Text,
}
impl FromStr for OutputFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("json") {
            Ok(Self::Json)
        } else if s.eq_ignore_ascii_case("text") {
            Ok(Self::Text)
        } else {
            Err(anyhow::format_err!(
                "Unknown output format {:?} expected \"json\" or \"text\"",
                s
            ))
        }
    }
}

#[derive(StructOpt)]
enum Command {
    /// Extract the Stallone metadata from the given binaries, and write the metadata to the
    /// output path in YAML form.
    ParseBinaryMetadata {
        /// The paths to binaries to extract metadata from. These binaries do NOT have to run on the
        /// host system.
        #[structopt(required = true)]
        binaries: Vec<PathBuf>,
        /// The path to write the metadata. This can be a `-` to write to STDOUT.
        #[structopt(short, long, default_value = "-")]
        output: Output,
    },
    /// Run a stallone master server to collect logs.
    ///
    /// This command follows the systemd-readyness protocol, and will signal its readyness after
    /// it's begun listening on the master path.
    CollectLogs {
        /// After receiving a Ctrl-C or interrupt, Stallone will try to finish processing the log
        /// events in its queue before exiting. If there are many log events in this buffer, this
        /// may take awhile. To avoid this, Stallone will exit at most --timeout-after-exit-request
        /// seconds after receiving a Ctrl-C, even if it never finished writing all the logs.
        ///
        /// Passing 0 as an option to this flag will make Stallone wait until its queue is empty
        /// before exiting.
        #[structopt(long, default_value = "30")]
        timeout_after_exit_request: u32,
        /// If specified, how many events the buffer should contain.
        #[structopt(long, default_value = "10000")]
        buffer_size: usize,
        /// The path where the stallone master should be created.
        /// (This path shouldn't already exist.) Set the `STALLONE_MASTER` environment variable of
        /// a process to this path to send log messages to this master.
        master_path: PathBuf,
        /// The path where the logs should be written.
        ///
        /// Put `-` to write to stdout. The output is binary. Thus, if `-` is specified, the output
        /// should be redirected to somewhere that's not a terminal.
        #[structopt(short, long, default_value = "-")]
        output: Output,
    },
    /// Decompress stallone log files
    DecompressLogs {
        /// What format should the decompressed log entries be outputted in.
        /// Valid options are: `text` or `json`
        #[structopt(long, default_value = "text")]
        output_format: OutputFormat,
        /// Where is the compressed log file? You can specify `-` to read from stdin.
        compressed_logs: Input,
        /// Where should output be written? You can specify `-` to write to stdout.
        #[structopt(short, long, default_value = "-")]
        output: Output,
        /// Where is the binary metadata coming from? Specify at least one source. You can specify
        /// binaries that have been compiled with stallone or YAML files produced by
        /// `parse-binary-metadata`. If you specify binaries, they can come from any platform (e.g.
        /// you can specify a Linux binary, even if you're running this command on macOS).
        #[structopt(required = true)]
        binary_metadata: Vec<PathBuf>,
    },
}

/// Read schema from files. Auto-detect whether it's a YAML file or a binary to parse.
fn read_schema_from_binaries(
    binaries: &[PathBuf],
) -> anyhow::Result<HashMap<LogRecordMetadataHash, LogRecordMetadataInfo>> {
    let mut out = HashMap::new();
    for binary in binaries.into_iter() {
        let binary_bytes = std::fs::read(&binary)
            .with_context(|| format!("Unable to read binary {:?}", &binary))?;
        let mut new_entries = if binary_bytes.starts_with(STALLONE_METADATA_YAML_VERSION_COMMENT) {
            serde_yaml::from_slice(&binary_bytes)
                .with_context(|| format!("Unable to read yaml from {:?}", &binary))?
        } else {
            stallone_parsing::load_binary_metadata(&binary_bytes)
                .with_context(|| format!("Unable to extract binary metadata from {:?}", &binary))
                .with_context(|| {
                    format!(
                    "{:?} did not appear to be YAML, since it did not start with the magic string",
                    &binary
                )
                })?
                .log_record_schemas
        };
        for (k, v) in new_entries.drain() {
            match out.entry(k) {
                Entry::Occupied(e) => {
                    anyhow::ensure!(
                        e.get() == &v,
                        "Conflicted definitions for log record metadata hash {:?}",
                        k
                    );
                }
                Entry::Vacant(e) => {
                    e.insert(v);
                }
            }
        }
    }
    Ok(out)
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();
    pretty_env_logger::formatted_timed_builder()
        .filter_level(log::LevelFilter::Trace)
        .try_init()
        .expect("failed to set logger.");
    match opt.cmd {
        Command::ParseBinaryMetadata { binaries, output } => {
            let schema = read_schema_from_binaries(&binaries)?;
            output
                .with_write(|w| {
                    w.write_all(STALLONE_METADATA_YAML_VERSION_COMMENT)?;
                    writeln!(w, "# DO NOT MODIFY!")?;
                    serde_yaml::to_writer(w, &schema)?;
                    Ok(())
                })
                .with_context(|| format!("Unable to write executable schemas to {}", output))?;
        }
        Command::CollectLogs {
            master_path,
            output,
            buffer_size,
            timeout_after_exit_request,
        } => {
            let master = stallone_master::Master::new(master_path.clone(), buffer_size)
                .with_context(|| format!("Failed to create master at {:?}", master_path))?;
            // Setup the signal handlers.
            fn setup_signal_handler(
                signal: libc::c_int,
                flag: &Arc<AtomicBool>,
                timeout_after_exit_request: u32,
            ) -> anyhow::Result<()> {
                let flag = flag.clone();
                unsafe {
                    // SAFETY: `flag.fetch_and` is signal-safe. `alarm` is signal-safe.
                    signal_hook::low_level::register(signal, move || {
                        if flag.fetch_and(false, Ordering::Relaxed) {
                            // We are the successful party, we should set the alarm.
                            libc::alarm(timeout_after_exit_request);
                        }
                    })
                }
                .with_context(|| format!("Unable to set signal handler for {}", signal))?;
                Ok(())
            }
            setup_signal_handler(
                signal_hook::consts::SIGHUP,
                &master.keep_master_running,
                timeout_after_exit_request,
            )?;
            setup_signal_handler(
                signal_hook::consts::SIGTERM,
                &master.keep_master_running,
                timeout_after_exit_request,
            )?;
            setup_signal_handler(
                signal_hook::consts::SIGINT,
                &master.keep_master_running,
                timeout_after_exit_request,
            )?;
            let mut reported_signal_received = false;
            // Then we get to the heart of the matter.
            output.with_write(|out| {
                let mut out = lz4::EncoderBuilder::new()
                    .block_size(lz4::BlockSize::Max4MB)
                    .build(out)
                    .expect("lz4");
                bincode::serialize_into(&mut out, STALLONE_BINARY_VERSION).with_context(|| {
                    format!("Writing the stallone binary version into {}", output)
                })?;
                bincode::serialize_into(
                    &mut out,
                    &stallone_master::gather_machine_info(master_path.clone()),
                )
                .with_context(|| format!("Writing the stallone machine metadata {}", output))?;
                systemd_ready::systemd_notify_ready()
                    .with_context(|| "Notifying systemd readyness")?;
                loop {
                    if !reported_signal_received
                        && !master.keep_master_running.load(Ordering::Relaxed)
                    {
                        reported_signal_received = true;
                        log::info!("Got termination signal");
                    }
                    while let Ok(evt) = master.recv.recv_timeout(Duration::from_millis(100)) {
                        bincode::serialize_into(&mut out, &Some(evt))
                            .with_context(|| format!("Writing log events into {}", output))?;
                    }
                    // After there's a lull, we flush the buffer, and block until there's another event.
                    out.flush()
                        .with_context(|| format!("Flushing log events to {}", output))?;
                    match master.recv.recv() {
                        Ok(evt) => {
                            bincode::serialize_into(&mut out, &Some(evt))
                                .with_context(|| format!("Writing log events into {}", output))?;
                        }
                        Err(_) => {
                            // The master has hung-up. Hopefully because we told it to.
                            break;
                        }
                    }
                }
                bincode::serialize_into::<_, Option<CompactLogEvent>>(&mut out, &None)
                    .with_context(|| format!("Writing none to denote EOF into {}", output))?;
                log::info!("Stallone master is gracefully exiting.");
                let (out, r) = out.finish();
                r.with_context(|| format!("Finalizing the LZ4 stream for {}", output))?;
                out.flush()
                    .with_context(|| format!("Performing the final flush for {}", output))?;
                Ok(())
            })?;
        }
        Command::DecompressLogs {
            output_format,
            binary_metadata,
            compressed_logs,
            output,
        } => {
            let schema = read_schema_from_binaries(&binary_metadata)?;
            anyhow::ensure!(
                !schema.is_empty(),
                "None of the provided metadata sources contained stallone metadata."
            );
            compressed_logs.with_read(|input| {
                let input = BufReader::new(input);
                let mut input = lz4::Decoder::new(input).with_context(|| "Opening Lz4 stream")?;
                let stallone_version: String = bincode::deserialize_from(&mut input)
                    .with_context(|| "Reading stallone version string")?;
                anyhow::ensure!(
                    stallone_version.as_str() == STALLONE_BINARY_VERSION,
                    "Expected stallone version {:?}. Got {:?}",
                    STALLONE_BINARY_VERSION,
                    stallone_version
                );
                let machine_metadata: MachineMetadata = bincode::deserialize_from(&mut input)?;
                let mut evts: Vec<CompactLogEvent> = Vec::new();
                loop {
                    match bincode::deserialize_from(&mut input) {
                        Ok(Some(evt)) => {
                            evts.push(evt);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            log::warn!("Stopping after deserialize error: {}", e);
                            break;
                        }
                    }
                }
                // It's very important that this is a stable sort.
                evts.sort_by_key(|evt| match evt {
                    GenericLogEvent::LogRecord(record) => record.epoch_ms,
                    GenericLogEvent::StartedProcess { timestamp, .. } => timestamp.epoch_ms,
                    GenericLogEvent::StartedThread { timestamp, .. } => timestamp.epoch_ms,
                    GenericLogEvent::EndedThread { timestamp, .. } => timestamp.epoch_ms,
                    GenericLogEvent::EndedProcess { timestamp, .. } => timestamp.epoch_ms,
                    GenericLogEvent::DroppedEvents { timestamp, .. } => timestamp.epoch_ms,
                    GenericLogEvent::Timestamp(timestamp) => timestamp.epoch_ms,
                    GenericLogEvent::EmergencyLog { timestamp, .. } => timestamp.epoch_ms,
                });
                output
                    .with_write(|output| {
                        let mut output = BufWriter::new(output);
                        match output_format {
                            OutputFormat::Json => {
                                serde_json::to_writer(&mut output, &machine_metadata)?;
                                output.write_all(b"\n")?;
                            }
                            OutputFormat::Text => {
                                writeln!(output, "{}", DisplayMachineMetadata(&machine_metadata))?;
                            }
                        }
                        let mut arena = Bump::new();
                        let mut ctx = LogEventContextualizer::new(&schema);
                        for evt in evts {
                            arena.reset();
                            let evt = evt.map_with_error(|body| {
                                stallone_parsing::parse_log_record_body(
                                    schema.get(&body.log_record_type).ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "Unable to get schema for log record type {:?}",
                                            body.log_record_type
                                        )
                                    })?,
                                    &body.payload,
                                    &arena,
                                )
                                .map_err(|e| anyhow::Error::from(e))
                            })?;
                            let evt = ctx.process(evt)?;
                            match output_format {
                                OutputFormat::Json => {
                                    serde_json::to_writer(
                                        &mut output,
                                        &evt.map(|x| {
                                            SerializedContextualizedLogEventPayload(x.payload)
                                        }),
                                    )?;
                                    output.write_all(b"\n")?;
                                }
                                OutputFormat::Text => {
                                    writeln!(output, "{}", DisplayLogEvent(&evt))?;
                                }
                            }
                        }
                        output.flush().with_context(|| "Flushing output")?;
                        Ok(())
                    })
                    .with_context(|| "Writing output")?;
                Ok(())
            })?;
        }
    }
    Ok(())
}
