//! This contains the logic to manage the IPC data structures for incoming data.

use crate::chunk_wire_protocol::HeapChunk;
use bytes::BytesMut;
use crossbeam::channel;
use mickey_balboa_ipc::{
    chunk_allocator::{Chunk, ChunkAllocatorWriter, ChunkId},
    incoming::IncomingWindowController,
    types::{ChunkControlWord, ChunkSeqnum, ChunkState, HostId},
    CHUNK_SIZE,
};
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

// TODO: because some of this logic is similar to the outgoing logic, can we combine this somehow?

pub fn incoming_thread(
    host_id: HostId,
    chunks: Arc<Mutex<ChunkAllocatorWriter>>,
    mut incoming_window_controller: IncomingWindowController,
    incoming_chunks: channel::Sender<HeapChunk>,
) -> Result<(), channel::SendError<HeapChunk>> {
    // TODO: how should we be handling the I/O errors in this thread?
    // TODO: we should grow and shrink the queue as the number of active VLC connections changes.
    const DESIRED_QUEUE_SIZE: usize = include!("config-params/incoming-queue-size.txt");
    // Just like we'll need to monitor stats for VLCs.
    let mut in_flight_chunks: VecDeque<(ChunkSeqnum, Chunk)> = VecDeque::new();
    let mut next_chunk_seqnum = ChunkSeqnum(0);
    let mut offset = 0;
    loop {
        // TODO: at what rate should we be polling?
        let start = Instant::now();
        let mut queue_changed = false;
        // It's important that we first dequeue before adding more in-flight chunks.
        while let Some((seqnum, chunk)) = in_flight_chunks.front() {
            debug_assert!(offset <= (seqnum.0 as u64));
            let cw = chunk.control_word(Ordering::Acquire);
            debug_assert_eq!(cw.host_id, host_id);
            debug_assert_eq!(cw.seqnum, *seqnum);
            if cw.state == ChunkState::FilledIncoming {
                let mut body = BytesMut::with_capacity(CHUNK_SIZE);
                static ZERO_CHUNK: [u8; CHUNK_SIZE] = [0; CHUNK_SIZE];
                body.extend_from_slice(&ZERO_CHUNK[..]);
                chunk.load_contents(&mut body[..]);
                stallone::debug!(
                    "about to send contents of chunk",
                    chunk_id: ChunkId = chunk.id(),
                    seqnum: ChunkSeqnum = seqnum,
                );
                incoming_chunks.send(HeapChunk::try_from(body.freeze()).unwrap())?;
                stallone::debug!(
                    "sent contents of chunk",
                    chunk_id: ChunkId = chunk.id(),
                    seqnum: ChunkSeqnum = seqnum,
                );
                chunk.raw_control_word().store(0, Ordering::Release);
                {
                    chunks.lock().free(chunk.id());
                }
                in_flight_chunks.pop_front();
                offset += 1;
                queue_changed = true;
            } else {
                break;
            }
        }
        while in_flight_chunks.len() < DESIRED_QUEUE_SIZE {
            let seqnum = next_chunk_seqnum;
            next_chunk_seqnum.0 += 1;
            let chunk = { chunks.lock().allocate().expect("Can allocate chunk") };
            chunk.raw_control_word().store(
                u64::try_from(ChunkControlWord {
                    host_id,
                    seqnum,
                    reserved: false,
                    state: ChunkState::EmptyIncoming,
                })
                .unwrap(),
                Ordering::Release,
            );
            stallone::debug!(
                "Added chunk to incoming queue",
                seqnum: ChunkSeqnum = seqnum,
                chunk_id: ChunkId = chunk.id(),
            );
            in_flight_chunks.push_back((seqnum, chunk));
            queue_changed = true;
        }
        if queue_changed {
            if cfg!(debug) {
                for (i, (seqnum, _)) in in_flight_chunks.iter().enumerate() {
                    debug_assert_eq!(i as u64 + offset, seqnum.0 as u64);
                    debug_assert!(seqnum.0 as u64 >= offset);
                }
            }
            let start = Instant::now();
            incoming_window_controller
                .set_queue_contents(offset, in_flight_chunks.iter().map(|(_, chunk)| chunk.id()))
                .unwrap();
            stallone::debug!(
                "Incoming window changed. Updating IPC incoming window.",
                len: usize = in_flight_chunks.len(),
                offset: u64 = offset,
                duration: Duration = start.elapsed(),
            );
        }
        stallone::debug!(
            "Incoming queue update duration",
            duration: Duration = start.elapsed()
        );
        const INCOMING_THREAD_SLEEP_MS: u64 =
            include!("config-params/incoming-thread-sleep-duration-ms.txt");
        std::thread::sleep(Duration::from_millis(INCOMING_THREAD_SLEEP_MS));
    }
}
