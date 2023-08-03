use crate::{
    emergency_log::collect_emergency_log_events,
    processinfo::gather_process_info,
    sock_thread::{start_socket_thread, SocketEvent},
    timestamp_generator::TimestampGenerator,
};
use crossbeam_channel::{SendError, Sender};
use stallone_common::{
    internal_ring_buffer as rb, positioned_io_result, protocol, PositionedIOResult, StallonePID,
    ALL_LEVELS, NUM_LEVELS,
};
use stallone_parsing::{CompactLogEvent, LogRecord, LogRecordMetadataHash, ThreadId};
use std::{
    collections::{hash_map::Entry, HashMap},
    os::unix::net::UnixDatagram,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

// TODO: rate limit warnings of identical strings

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PollResult {
    GoToSleep,
    PollAgain,
}
impl PollResult {
    fn merge(a: PollResult, b: PollResult) -> PollResult {
        use PollResult::*;
        match (a, b) {
            (PollAgain, _) | (_, PollAgain) => PollAgain,
            (GoToSleep, GoToSleep) => GoToSleep,
        }
    }
}

const TIMESTAMP_EVENT_EVERY: Duration = Duration::from_secs(30);
const CHECK_DROPPED_EVENTS_EVERY: Duration = Duration::from_millis(1000);
const DELAY_DURATION: Duration = Duration::from_millis(10);
const LOG_EVENTS_PER_RUN: usize = 64;

struct Thread {
    reader: rb::Reader,
    last_drop_check: Option<Instant>,
    dropped_event_counts: [u64; NUM_LEVELS],
    // If the thread has died, then this log event is populated with info about when.
    has_died: Option<CompactLogEvent>,
}

impl Thread {
    /// # Safety
    /// `f` should have no other `rb::Reader`s
    unsafe fn open(f: &std::fs::File) -> PositionedIOResult<Self> {
        let reader = rb::Reader::new(f)?;
        Ok(Thread {
            reader,
            last_drop_check: None,
            dropped_event_counts: [0; NUM_LEVELS],
            has_died: None,
        })
    }

    fn update_dropped_event_counts(
        &mut self,
        timestamp_generator: &TimestampGenerator,
        drain: &mut Sender<CompactLogEvent>,
        pid: StallonePID,
        tid: ThreadId,
    ) -> Result<(), SendError<CompactLogEvent>> {
        let new_dropped_events = self.reader.sample_dropped_events();
        for ((level, dst), src) in ALL_LEVELS
            .iter()
            .cloned()
            .zip(self.dropped_event_counts.iter_mut())
            .zip(new_dropped_events.iter().cloned())
        {
            if *dst > src {
                log::warn!(
                    "{:?} {:?} Level {:?} had old drop count under new drop count: {} {}",
                    pid,
                    tid,
                    level,
                    src,
                    *dst
                );
            } else if *dst < src {
                drain.send(CompactLogEvent::DroppedEvents {
                    pid,
                    timestamp: timestamp_generator.generate(),
                    thread_id: tid,
                    level: level,
                    count: src - *dst,
                })?;
            }
            *dst = src;
        }
        Ok(())
    }
    fn poll_updates(
        &mut self,
        now: std::time::Instant,
        timestamp_generator: &TimestampGenerator,
        drain: &mut Sender<CompactLogEvent>,
        pid: StallonePID,
        tid: ThreadId,
    ) -> Result<PollResult, SendError<CompactLogEvent>> {
        // First, check up on the dropped log events.
        if self
            .last_drop_check
            .map(|time| now - time)
            .map(|duration| duration >= CHECK_DROPPED_EVENTS_EVERY)
            .unwrap_or(true)
        {
            self.last_drop_check = Some(now);
            self.update_dropped_event_counts(timestamp_generator, drain, pid, tid)?;
        }
        // Then, check to see if the thread is dead.
        if self.has_died.is_none() && self.reader.is_dead() {
            self.has_died = Some(CompactLogEvent::EndedThread {
                pid,
                thread_id: tid,
                timestamp: timestamp_generator.generate(),
            });
        }
        // And, finally, the moment you've all been waiting for...log events!
        let mut out = Ok(PollResult::GoToSleep);
        if let Err(e) = self
            .reader
            .read_log_records(LOG_EVENTS_PER_RUN, |header, payload| {
                let evt = CompactLogEvent::LogRecord(LogRecord {
                    pid,
                    thread_id: tid,
                    epoch_ms: header.epoch_ms,
                    log_record_type: LogRecordMetadataHash {
                        schema_hash: header.log_record_type.schema_hash,
                    },
                    payload: serde_bytes::ByteBuf::from(payload.to_vec()),
                });
                if let Ok(_) = out {
                    out = drain.send(evt).map(|_| PollResult::PollAgain);
                }
            })
        {
            // TODO: should we start reading from this thread entirely?
            log::warn!(
                "Unable to read log record from {:?} thread {:?} : {}",
                pid,
                tid,
                e,
            );
        }
        out
    }
}

struct Process {
    // If the process has died, then this is populated with the log event of its death.
    has_died: Option<CompactLogEvent>,
    next_thread_id: u64,
    threads: HashMap<ThreadId, Thread>,
}

struct State {
    processes: HashMap<StallonePID, Process>,
}

impl State {
    fn poll(
        &mut self,
        now: std::time::Instant,
        timestamp_generator: &TimestampGenerator,
        drain: &mut Sender<CompactLogEvent>,
    ) -> Result<PollResult, SendError<CompactLogEvent>> {
        let mut out = PollResult::GoToSleep;
        let mut err: Option<SendError<CompactLogEvent>> = None;
        self.processes.retain(|pid, proc| {
            proc.threads.retain(|tid, thread| {
                // Return true if the thread should be RETAINED/KEPT
                match thread.poll_updates(now, timestamp_generator, drain, *pid, *tid) {
                    Ok(pr) => {
                        out = PollResult::merge(out, pr);
                        let keep_alive = thread.has_died.is_none() || pr == PollResult::PollAgain;
                        if !keep_alive {
                            if let Err(e) = thread.update_dropped_event_counts(
                                timestamp_generator,
                                drain,
                                *pid,
                                *tid,
                            ) {
                                err = Some(e);
                            }
                            if let Err(e) = drain.send(
                                thread
                                    .has_died
                                    .take()
                                    .expect("!keep_alive => !has_died.is_none()"),
                            ) {
                                err = Some(e);
                            }
                        }
                        keep_alive
                    }
                    Err(e) => {
                        err = Some(e);
                        true
                    }
                }
            });
            // Return true if the process should be RETAINED/KEPT
            // We keep tracking the process if it's still alive, or if it has threads.
            let keep_alive = proc.has_died.is_none() || !proc.threads.is_empty();
            if !keep_alive {
                if let Err(e) = drain.send(
                    proc.has_died
                        .take()
                        .expect("!keep_alive => !has_died.is_none()"),
                ) {
                    err = Some(e);
                }
            }
            keep_alive
        });
        if let Some(e) = err {
            Err(e)
        } else {
            Ok(out)
        }
    }
    fn handle_socket_event(
        &mut self,
        timestamp_generator: &TimestampGenerator,
        drain: &mut Sender<CompactLogEvent>,
        evt: SocketEvent,
    ) -> Result<(), SendError<CompactLogEvent>> {
        match evt {
            SocketEvent::NewProcess(pinfo) => match self.processes.entry(pinfo.stallone_pid) {
                Entry::Occupied(_) => {
                    log::warn!("Process {:?} had already been created", pinfo.stallone_pid);
                }
                Entry::Vacant(v) => {
                    v.insert(Process {
                        has_died: None,
                        next_thread_id: 1,
                        threads: HashMap::new(),
                    });
                    drain.send(CompactLogEvent::StartedProcess {
                        pid: pinfo.stallone_pid,
                        timestamp: timestamp_generator.generate(),
                        process_info: Some(gather_process_info(
                            pinfo.pid,
                            &pinfo.build_id[..],
                            pinfo.parent_pid,
                        )),
                    })?;
                }
            },
            SocketEvent::DeadProcess(spid) => match self.processes.get_mut(&spid) {
                None => {
                    log::warn!("No such dead process {:?}", spid);
                }
                Some(proc) => {
                    if proc.has_died.is_some() {
                        log::warn!("We've already recorded that {:?} has died", spid);
                    } else {
                        proc.has_died = Some(CompactLogEvent::EndedProcess {
                            pid: spid,
                            timestamp: timestamp_generator.generate(),
                        });
                        for (tid, thread) in proc.threads.iter_mut() {
                            if thread.has_died.is_none() {
                                thread.has_died = Some(CompactLogEvent::EndedThread {
                                    pid: spid,
                                    thread_id: *tid,
                                    timestamp: timestamp_generator.generate(),
                                });
                            }
                        }
                    }
                }
            },
            SocketEvent::NewThread(spid, file) => {
                match self.processes.get_mut(&spid) {
                    None => {
                        log::warn!("No such process to add thread to {:?}", spid);
                    }
                    Some(proc) => {
                        let tid = ThreadId(proc.next_thread_id);
                        proc.next_thread_id += 1;
                        if proc.has_died.is_some() {
                            log::warn!(
                                "Adding thread {:?} to process {:?} AFTER we saw it die",
                                tid,
                                spid
                            );
                        }
                        drain.send(CompactLogEvent::StartedThread {
                            pid: spid,
                            thread_id: tid,
                            timestamp: timestamp_generator.generate(),
                        })?;
                        match unsafe {
                            // SAFETY: We hope, given the stallone protocol, that there are no other
                            // readers. (This should be the case if the IPC protocol has been
                            // followed.)
                            Thread::open(&file)
                        } {
                            Ok(mut thread) => {
                                if proc.has_died.is_some() {
                                    thread.has_died = Some(CompactLogEvent::EndedThread {
                                        pid: spid,
                                        thread_id: tid,
                                        timestamp: timestamp_generator.generate(),
                                    });
                                }
                                proc.threads.insert(tid, thread);
                            }
                            Err(e) => {
                                log::warn!(
                                    "Unable to open thread {:?} for process {:?} due to {}",
                                    tid,
                                    spid,
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn run(
    keep_master_running: Arc<AtomicBool>,
    timestamp_generator: Arc<TimestampGenerator>,
    _base_path: PathBuf,
    socket_events: crossbeam_channel::Receiver<SocketEvent>,
    mut drain: crossbeam_channel::Sender<CompactLogEvent>,
) -> Result<(), crossbeam_channel::SendError<CompactLogEvent>> {
    let mut state = State {
        processes: HashMap::new(),
    };
    let mut last_timestamp_event: Option<std::time::Instant> = None;
    while keep_master_running.load(Ordering::Relaxed) || !state.processes.is_empty() {
        let now = std::time::Instant::now();
        let start_next_iteration_at = now + DELAY_DURATION;
        if last_timestamp_event
            .map(|time| now - time)
            .map(|duration| duration >= TIMESTAMP_EVENT_EVERY)
            .unwrap_or(true)
        {
            last_timestamp_event = Some(now);
            drain.send(CompactLogEvent::Timestamp(timestamp_generator.generate()))?;
        }
        // We don't want socket events to starve out other tasks that we have.
        for _ in 0..128 {
            match socket_events.try_recv() {
                Ok(evt) => state.handle_socket_event(&timestamp_generator, &mut drain, evt)?,
                Err(_) => {
                    break;
                }
            }
        }
        // Now we need to do our regularly scheduled polling.
        match state.poll(now, &timestamp_generator, &mut drain)? {
            PollResult::GoToSleep => {
                let now = std::time::Instant::now();
                match socket_events.recv_timeout(if now >= start_next_iteration_at {
                    Duration::default()
                } else {
                    start_next_iteration_at - now
                }) {
                    Ok(evt) => state.handle_socket_event(&timestamp_generator, &mut drain, evt)?,
                    Err(_) => {
                        // Do nothing.
                    }
                }
            }
            PollResult::PollAgain => {}
        }
    }
    Ok(())
}

pub struct Master {
    pub recv: crossbeam_channel::Receiver<CompactLogEvent>,
    pub keep_master_running: Arc<AtomicBool>,
}
impl Master {
    /// This will stop the master as soon as it all its processes have died.
    /// It is signal-safe.
    pub fn gracefully_stop_master(&self) {
        self.keep_master_running.store(false, Ordering::Relaxed);
    }

    /// Construct a new master from the given base path.
    pub fn new(base_path: PathBuf, buffer_size: usize) -> PositionedIOResult<Master> {
        positioned_io_result!(std::fs::create_dir(&base_path))?;
        positioned_io_result!(std::fs::create_dir(
            &base_path.join(protocol::EMERGENCY_LOG_DIRECTORY_NAME)
        ))?;
        log::debug!("Made stallone log directory at {:?}", base_path);
        let socket = positioned_io_result!(UnixDatagram::bind(
            base_path.join(protocol::SOCKET_FILE_NAME)
        ))?;
        positioned_io_result!(socket.set_nonblocking(true))?;
        log::debug!("Bound datagram socket");
        let timestamp_generator = Arc::new(TimestampGenerator::new(
            base_path.join(protocol::EPOCH_FILE_NAME),
        )?);
        log::debug!("Started timestamp generator");
        let (sender, r) = crossbeam_channel::bounded::<CompactLogEvent>(buffer_size);
        let (s_socket_events, r_socket_events) = crossbeam_channel::bounded(buffer_size);
        start_socket_thread(socket, s_socket_events)?;
        let emergency_log_event_sender = sender.clone();
        let base_path2 = base_path.clone();
        let timestamp_generator2 = timestamp_generator.clone();
        let keep_master_running = Arc::new(AtomicBool::new(true));
        let keep_master_running2 = keep_master_running.clone();
        let keep_master_running3 = keep_master_running.clone();
        std::thread::spawn(move || {
            collect_emergency_log_events(
                timestamp_generator2.as_ref(),
                base_path2,
                keep_master_running3,
                emergency_log_event_sender,
            )
        });
        std::thread::spawn(move || {
            // The only possible error is a SendError, and it's okay to ignore that, and just exit.
            let _ = run(
                keep_master_running2,
                timestamp_generator,
                base_path,
                r_socket_events,
                sender,
            );
        });
        Ok(Master {
            recv: r,
            keep_master_running,
        })
    }
}
