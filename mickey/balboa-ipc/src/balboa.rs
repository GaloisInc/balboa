use crate::{
    chunk_allocator::{ChunkAllocatorReader, ChunkId, HasChunk},
    incoming::{FailedToGetIncomingChunk, IncomingWindowConsumer},
    outgoing::OutgoingQueueConsumer,
    types::{
        BalboaMickeyIPCMessage, ChunkControlWord, ChunkSeqnum, ChunkState, HostId,
        MAX_BALBOA_MICKEY_IPC_MESSAGE_LENGTH,
    },
    wire_protocol, CHUNK_SIZE,
};
use balboa_compression::{CompressContext, DecompressContext};
use balboa_coroutine::{CoroutineBasedStreamRewriter, GenState, StreamCoroutineShouldNeverExit};
use parking_lot::RwLock;
use scm_rights::ScmRightsExt;
use stallone::LoggableMetadata;
use stallone_common::{
    positioned_io_error, positioned_io_result, PositionedIOError, PositionedIOResult,
};
use std::{
    collections::HashMap,
    fs::File,
    net::Ipv4Addr,
    os::unix::{io::FromRawFd, net::UnixDatagram},
    path::PathBuf,
    sync::{atomic::Ordering, Arc, Weak},
    time::{Duration, Instant},
};

struct BalboaMickeyIPCState {
    main_sock: UnixDatagram,
    chunks: Arc<ChunkAllocatorReader>,
    outgoing: RwLock<HashMap<Ipv4Addr, (HostId, Weak<OutgoingQueueConsumer>)>>,
    incoming: RwLock<HashMap<Ipv4Addr, (HostId, Weak<IncomingWindowConsumer>)>>,
}
impl BalboaMickeyIPCState {
    fn get_host_id_and_ctx<T>(
        &self,
        msg: BalboaMickeyIPCMessage,
        map: &RwLock<HashMap<Ipv4Addr, (HostId, Weak<T>)>>,
        ip: Ipv4Addr,
        cons: fn(File) -> PositionedIOResult<T>,
    ) -> PositionedIOResult<(HostId, Arc<T>)> {
        if let Some((host_id, outgoing)) = map
            .read()
            .get(&ip)
            .and_then(|(host_id, outgoing)| outgoing.upgrade().map(|outgoing| (*host_id, outgoing)))
        {
            stallone::debug!(
                "Got context info from cache",
                host_id: HostId = host_id,
                msg: BalboaMickeyIPCMessage = msg,
            );
            return Ok((host_id, outgoing));
        }
        stallone::debug!(
            "Fetching context info from mickey",
            msg: BalboaMickeyIPCMessage = msg,
        );
        let (sock1, sock2) = positioned_io_result!(UnixDatagram::pair())?;
        // TODO: set read or write timeouts?
        let message = &bincode::serialize(&msg).map_err(|e| {
            positioned_io_error!(std::io::Error::new(std::io::ErrorKind::InvalidData, *e))
        })?;
        assert!(message.len() <= MAX_BALBOA_MICKEY_IPC_MESSAGE_LENGTH);
        positioned_io_result!(self.main_sock.sendmsg_file(&sock2, message,))?;
        let mut buf = [0; 4];
        match positioned_io_result!(sock1.recvmsg_file(&mut buf[..]))? {
            (Some(fd), 4) => {
                let host_id = HostId(u32::from_le_bytes(buf));
                let outgoing = Arc::new(cons(unsafe { File::from_raw_fd(fd) })?);
                let mut outgoing_guard = map.write();
                let (_, outgoing_weak) = outgoing_guard
                    .entry(ip)
                    .or_insert_with(|| (host_id, Arc::downgrade(&outgoing)));
                if let Some(outgoing) = outgoing_weak.upgrade() {
                    Ok((host_id, outgoing))
                } else {
                    *outgoing_weak = Arc::downgrade(&outgoing);
                    Ok((host_id, outgoing))
                }
            }
            (None, _) => {
                #[derive(Debug)]
                struct MissingFileWhenReadingFile;
                impl std::fmt::Display for MissingFileWhenReadingFile {
                    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(f, "missing file when reading file")
                    }
                }
                impl std::error::Error for MissingFileWhenReadingFile {}
                Err(positioned_io_error!(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    MissingFileWhenReadingFile
                )))
            }
            (_, _) => {
                #[derive(Debug)]
                struct WrongHostIdSizeWhenReadingFile;
                impl std::fmt::Display for WrongHostIdSizeWhenReadingFile {
                    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(f, "wrong hostid size when reading file")
                    }
                }
                impl std::error::Error for WrongHostIdSizeWhenReadingFile {}
                Err(positioned_io_error!(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    WrongHostIdSizeWhenReadingFile
                )))
            }
        }
    }
}

pub struct BalboaMickeyIPC {
    state: Arc<BalboaMickeyIPCState>,
}
impl BalboaMickeyIPC {
    // TODO: this doesn't need to be a PathBuf
    pub fn open(path: PathBuf) -> PositionedIOResult<Self> {
        let main_sock = positioned_io_result!(UnixDatagram::unbound())?;
        positioned_io_result!(main_sock.connect(&path))?;
        let (sock1, sock2) = positioned_io_result!(UnixDatagram::pair())?;
        let message = &bincode::serialize(&BalboaMickeyIPCMessage::GetChunksFile).map_err(|e| {
            positioned_io_error!(std::io::Error::new(std::io::ErrorKind::InvalidData, *e))
        })?;
        assert!(message.len() <= MAX_BALBOA_MICKEY_IPC_MESSAGE_LENGTH);
        positioned_io_result!(main_sock.sendmsg_file(&sock2, message,))?;
        let mut buf = [0];
        let chunks = if let (Some(fd), _) = positioned_io_result!(sock1.recvmsg_file(&mut buf[..]))?
        {
            Arc::new(ChunkAllocatorReader::new(unsafe { File::from_raw_fd(fd) })?)
        } else {
            #[derive(Debug)]
            struct MissingFileWhenReadingChunksFile;
            impl std::fmt::Display for MissingFileWhenReadingChunksFile {
                fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(f, "missing file when reading chunks file")
                }
            }
            impl std::error::Error for MissingFileWhenReadingChunksFile {}
            return Err(positioned_io_error!(std::io::Error::new(
                std::io::ErrorKind::Other,
                MissingFileWhenReadingChunksFile
            )));
        };
        Ok(BalboaMickeyIPC {
            state: Arc::new(BalboaMickeyIPCState {
                main_sock,
                chunks,
                outgoing: RwLock::new(HashMap::new()),
                incoming: RwLock::new(HashMap::new()),
            }),
        })
    }

    pub fn compress_context(&self, ip: Ipv4Addr) -> PositionedIOResult<impl CompressContext> {
        let state = self.state.clone();
        struct CC(CoroutineBasedStreamRewriter);
        impl CompressContext for CC {
            fn recv_covert_bytes(&mut self, dst: &mut [u8]) {
                let start = Instant::now();
                self.0.rewrite(dst);
                stallone::debug!(
                    "Mickey compress_context rewrite time",
                    duration: Duration = start.elapsed()
                );
            }
        }
        Ok(CC(CoroutineBasedStreamRewriter::new(
            move |mut gs| async move {
                // TODO: make sure this doesn't execute until after covert signaling (add as smoketest)
                match state
                    .get_host_id_and_ctx(
                        BalboaMickeyIPCMessage::GetOutgoingFile(ip),
                        &state.outgoing,
                        ip,
                        OutgoingQueueConsumer::new,
                    )
                    .and_then(|(host_id1, outgoing)| {
                        state
                            .get_host_id_and_ctx(
                                BalboaMickeyIPCMessage::GetIncomingFile(ip),
                                &state.incoming,
                                ip,
                                IncomingWindowConsumer::new,
                            )
                            .map(|(host_id2, incoming)| (host_id1, outgoing, host_id2, incoming))
                    }) {
                    Ok((host_id, outgoing, host_id2, incoming)) => {
                        debug_assert_eq!(host_id, host_id2);
                        outgoing_covert_data(host_id, &state.chunks, outgoing, incoming, &mut gs)
                            .await
                    }
                    Err(e) => {
                        stallone::error!(
                            "Unable to setup compress context",
                            ip: Ipv4Addr = ip,
                            error: String = format!("{}", e),
                        );
                        loop {
                            // TODO: this ZEROS should come from the wire protocol.
                            static ZEROES: &'static [u8] = &[0; 1024];
                            gs.write_exact_ignoring_contents(ZEROES).await;
                        }
                    }
                }
            },
        )))
    }

    pub fn decompress_context(&self, ip: Ipv4Addr) -> PositionedIOResult<impl DecompressContext> {
        let state = self.state.clone();
        struct DC(CoroutineBasedStreamRewriter, Vec<u8>);
        impl DecompressContext for DC {
            fn send_covert_bytes(&mut self, src: &[u8]) {
                // TODO: switch to previewing once that's working.
                self.1.clear();
                self.1.extend_from_slice(src);
                let start = Instant::now();
                self.0.rewrite(&mut self.1[..]);
                stallone::debug!(
                    "Mickey decompress_context rewrite time",
                    duration: Duration = start.elapsed(),
                );
            }
        }
        Ok(DC(
            CoroutineBasedStreamRewriter::new(move |mut gs| async move {
                // TODO: make sure this doesn't execute until after covert signaling (add as smoketest)
                match state.get_host_id_and_ctx(
                    BalboaMickeyIPCMessage::GetIncomingFile(ip),
                    &state.incoming,
                    ip,
                    IncomingWindowConsumer::new,
                ) {
                    Ok((host_id, incoming)) => {
                        incoming_covert_data(host_id, state.chunks.clone(), incoming, &mut gs).await
                    }
                    Err(e) => {
                        stallone::error!(
                            "Unable to setup decompress context",
                            ip: Ipv4Addr = ip,
                            error: String = format!("{}", e),
                        );
                        loop {
                            gs.advance_without_modifying(1024).await;
                        }
                    }
                }
            }),
            Vec::new(),
        ))
    }
}

#[derive(Debug, LoggableMetadata)]
enum FailureToRecvChunkToSendNonIoError {
    NothingToDequeue,
    IllgalInitialStateOrHostId(ChunkControlWord),
    ChunkControlWordChangedAfterReading {
        original: ChunkControlWord,
        latest: ChunkControlWord,
    },
}

async fn maybe_write_an_ack(
    last_written_ack: &mut Option<u64>,
    incoming: &IncomingWindowConsumer,
    gs: &mut GenState,
) {
    let current_ack = incoming.get_our_cumulative_ack();
    if last_written_ack
        .map(|last| last < current_ack)
        .unwrap_or(true)
    {
        *last_written_ack = Some(current_ack);
        wire_protocol::write_frame(
            gs,
            &wire_protocol::Frame::Ack {
                cumulative: ChunkSeqnum(current_ack),
            },
        )
        .await;
    }
}

async fn try_to_send_next_chunk(
    gs: &mut GenState,
    host_id: HostId,
    chunks: &ChunkAllocatorReader,
    outgoing: &OutgoingQueueConsumer,
    chunk_buf: &mut [u8; CHUNK_SIZE],
) -> Result<(), FailureToRecvChunkToSend> {
    let seqnum = chunk_to_send(host_id, &chunks, &outgoing, chunk_buf)?;
    wire_protocol::write_frame(gs, &wire_protocol::Frame::Chunk(seqnum, &chunk_buf)).await;
    Ok(())
}

async fn outgoing_covert_data(
    host_id: HostId,
    chunks: &ChunkAllocatorReader,
    outgoing: Arc<OutgoingQueueConsumer>,
    incoming: Arc<IncomingWindowConsumer>,
    gs: &mut GenState,
) -> StreamCoroutineShouldNeverExit {
    stallone::debug!("Starting outgoing coroutine", host_id: HostId = host_id,);
    let mut chunk_buf = Box::new([0; CHUNK_SIZE]);
    let mut last_written_ack: Option<u64> = None;
    const SEND_AN_ACK_EVERY: usize = include!("config-params/send-an-ack-every.txt");
    assert!(SEND_AN_ACK_EVERY >= 1);
    loop {
        maybe_write_an_ack(&mut last_written_ack, &incoming, gs).await;
        for _ in 0..SEND_AN_ACK_EVERY {
            if let Err(e) =
                try_to_send_next_chunk(gs, host_id, chunks, &outgoing, &mut chunk_buf).await
            {
                // If we fail to send a chunk for any reason, let's log why.
                match e {
                    FailureToRecvChunkToSend::IoError(e) => {
                        stallone::warn!(
                            "Unable to dequeue chunk due to IO error",
                            err: String = format!("{}", e)
                        );
                    }
                    FailureToRecvChunkToSend::NonIoError(e) => {
                        // This isn't necessarily bad.
                        stallone::debug!(
                            "Unable to dequeue chunk",
                            e: FailureToRecvChunkToSendNonIoError = e
                        );
                    }
                }
                // Then we'll send an ack.
                maybe_write_an_ack(&mut last_written_ack, &incoming, gs).await;
                // TODO: if sending an ack flipped the coroutine buffer, we might want to try to
                // find more data to send, before resorting to filling the buffer with padding bytes.
                // Then we'll "cool off" for a sec, fill the outgoing buffer with padding bytes (zeroes)
                // and we'll try again on the next buffer. This is helpful as our "most frequent"
                // "failure" will likely be just having nothing more to dequeue. We also need to
                // eventually fill the space for covert data with _something_, and we don't want to
                // block until we have things to send.
                // TODO: add a test to make sure that padding works, and we don't block if there's
                // nothing to send.
                // If we try to write 0 padding bytes, then we won't yield at all.
                let nbytes = gs.buffer_size_remaining().max(1);
                wire_protocol::write_padding(gs, nbytes).await;
                break;
            }
        }
    }
}

fn process_chunk_frame(
    seqnum: ChunkSeqnum,
    body: &[u8; CHUNK_SIZE],
    incoming: &IncomingWindowConsumer,
    chunks: &ChunkAllocatorReader,
    host_id: HostId,
) {
    stallone::debug!("Saw chunk frame", seqnum: ChunkSeqnum = seqnum);
    match incoming.get(seqnum) {
        Ok(Ok(chunk_id)) => {
            match chunks.chunk(chunk_id) {
                Ok(chunk) => {
                    // TODO: ordering
                    let initial = chunk.control_word(Ordering::SeqCst);
                    if initial.host_id != host_id || initial.seqnum != seqnum {
                        // Because a chunk destined for incoming content will never
                        // be freed until it has been filled, we can safely discard
                        // any chunks in this situation
                        stallone::debug!(
                            "DISCARDING Stale chunk from incoming window",
                            initial: ChunkControlWord = initial,
                            host_id: HostId = host_id,
                            seqnum: ChunkSeqnum = seqnum,
                        );
                        return;
                    }
                    if initial.state != ChunkState::EmptyIncoming || initial.reserved {
                        // Either somebody else has claimed the chunk, or we
                        // the chunk has already been removed from play.
                        stallone::debug!(
                            "DISCARDING Chunk state not EmptyIncoming (or reservable)",
                            initial: ChunkControlWord = initial,
                            host_id: HostId = host_id,
                            seqnum: ChunkSeqnum = seqnum,
                        );
                        return;
                    }
                    // NOTE: we cannot use the weak version here, since we
                    // use success to indicate which party won the race.
                    // TODO: are this orderings right?
                    if let Err(cw) = chunk.raw_control_word().compare_exchange(
                        u64::from(initial),
                        u64::try_from(ChunkControlWord {
                            reserved: true,
                            ..initial
                        })
                        .unwrap(),
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                    ) {
                        let cw = ChunkControlWord::from(cw);
                        stallone::debug!(
                            "DISCARDING Chunk. Failed to reserve chunk for writing",
                            initial: ChunkControlWord = initial,
                            new_control_word: ChunkControlWord = cw,
                            host_id: HostId = host_id,
                            seqnum: ChunkSeqnum = seqnum,
                        );
                        return;
                    }
                    // Now we have reserved the chunk. Time to write!
                    // We have exclusive access now, and if we die, then the
                    // exclusive access dies with us.
                    // TODO: we shouldn't do that. Maybe put the PID and
                    // start timestamp in a separate atomic used to lock the
                    // write?
                    chunk.store_contents(&body[..]);
                    chunk.raw_control_word().store(
                        u64::try_from(ChunkControlWord {
                            state: ChunkState::FilledIncoming,
                            reserved: true,
                            ..initial
                        })
                        .unwrap(),
                        Ordering::Release,
                    );
                    stallone::debug!(
                        "SUCCESSFULLY stored chunk",
                        initial: ChunkControlWord = initial,
                        host_id: HostId = host_id,
                        seqnum: ChunkSeqnum = seqnum,
                    );
                    return;
                }
                Err(e) => {
                    stallone::warn!(
                        "DISCARDING incoming chunk due to failure to resolve chunk id",
                        chunk_id: ChunkId = chunk_id,
                        seqnum: ChunkSeqnum = seqnum,
                        e: String = format!("{}", e),
                    );
                    return;
                }
            }
        }
        Ok(Err(e)) => {
            stallone::debug!(
                "DISCARDING CHUNK: failed to get incoming chunk",
                e: FailedToGetIncomingChunk = e,
                seqnum: ChunkSeqnum = seqnum,
            );
            return;
        }
        Err(io_error) => {
            stallone::warn!(
                "DISCARDING CHUNK due to io error",
                io_error: String = format!("{}", io_error),
                seqnum: ChunkSeqnum = seqnum,
            );
            return;
        }
    }
}

async fn incoming_covert_data(
    host_id: HostId,
    chunks: Arc<ChunkAllocatorReader>,
    incoming: Arc<IncomingWindowConsumer>,
    gs: &mut GenState,
) -> StreamCoroutineShouldNeverExit {
    // TODO: report statistics.
    let mut reader = Box::new(wire_protocol::Reader::new());
    loop {
        match reader.read(gs).await {
            Ok(wire_protocol::ReaderOutput {
                frame,
                bytes_consumed: _,
            }) => match frame {
                wire_protocol::Frame::Chunk(seqnum, body) => {
                    process_chunk_frame(seqnum, body, &incoming, &chunks, host_id);
                }
                wire_protocol::Frame::Ack { cumulative } => {
                    stallone::debug!("Saw ack", cumulative: ChunkSeqnum = cumulative);
                    incoming.store_their_cumulative_ack(cumulative.0);
                }
            },
            Err(e) => {
                stallone::warn!(
                    "Unable to parse frame",
                    e: wire_protocol::FrameParseError = e
                );
            }
        }
    }
}

enum FailureToRecvChunkToSend {
    IoError(PositionedIOError),
    NonIoError(FailureToRecvChunkToSendNonIoError),
}
impl From<PositionedIOError> for FailureToRecvChunkToSend {
    fn from(x: PositionedIOError) -> Self {
        FailureToRecvChunkToSend::IoError(x)
    }
}
impl From<FailureToRecvChunkToSendNonIoError> for FailureToRecvChunkToSend {
    fn from(x: FailureToRecvChunkToSendNonIoError) -> Self {
        FailureToRecvChunkToSend::NonIoError(x)
    }
}

fn chunk_to_send(
    host_id: HostId,
    chunks: &ChunkAllocatorReader,
    outgoing: &OutgoingQueueConsumer,
    buf: &mut [u8; CHUNK_SIZE],
) -> Result<ChunkSeqnum, FailureToRecvChunkToSend> {
    use FailureToRecvChunkToSendNonIoError::*;
    // NOTE: if you want to debug this, considering replacing the low-key lock release
    // with an IPC spinlock (probably in the chunk control word).
    if let Some(chunk_id) = outgoing.dequeue()? {
        let chunk = chunks.chunk(chunk_id)?;
        let cw = chunk.control_word(Ordering::Acquire);
        if cw.state != ChunkState::FilledOutgoing || cw.host_id != host_id {
            return Err(IllgalInitialStateOrHostId(cw).into());
        }
        chunk.load_contents(&mut buf[..]);
        // We want to order this load AFTER all loads that precede it. Acquire doesn't do that.
        // TODO: is this Ordering correct? Can we do better by using the fence() function?
        let cw2 = chunk.control_word(Ordering::SeqCst);
        if cw2 != cw {
            Err(ChunkControlWordChangedAfterReading {
                original: cw,
                latest: cw2,
            }
            .into())
        } else {
            Ok(cw.seqnum)
        }
    } else {
        Err(NothingToDequeue.into())
    }
}
