//! This contains the logic to manage the IPC data structures for outgoing data.

use crate::chunk_wire_protocol::HeapChunk;
use bytes::Bytes;
use crossbeam::channel;
use mickey_balboa_ipc::{
    chunk_allocator::{Chunk, ChunkAllocatorWriter, ChunkId},
    incoming::IncomingWindowConsumer,
    outgoing::OutgoingQueueProducer,
    types::{ChunkControlWord, ChunkSeqnum, ChunkState, HostId},
};
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

pub fn outgoing_thread(
    host_id: HostId,
    chunks: Arc<Mutex<ChunkAllocatorWriter>>,
    incoming_window_consumer: IncomingWindowConsumer,
    mut queue: OutgoingQueueProducer,
    outgoing_chunks: channel::Receiver<HeapChunk>,
) {
    // TODO: how should we be handling the I/O errors in this thread?
    // TODO: we should grow and shrink the queue as the number of active Icecast connections changes.
    // NOTE: the desired queue size is the number of kilobytes per 10ms that we can shift.
    const DESIRED_QUEUE_SIZE: usize = include!("config-params/outgoing-queue-size.txt");
    // Just like we'll need to monitor stats for VLCs.
    let mut in_flight_chunks = VecDeque::<(ChunkSeqnum, Chunk)>::new();
    let mut next_chunk_seqnum = ChunkSeqnum(0);
    loop {
        // TODO: at what rate should we be polling?
        let start = Instant::now();
        let mut queue_changed = false;
        let mut num_dequeued = 0;
        let cumulative_ack = incoming_window_consumer.get_their_cumulative_ack();
        // Free stuff before we bring the queue back to the desired size.
        while let Some((seqnum, chunk)) = in_flight_chunks.front() {
            // RECALL: cumulative_ack is EXCLUSIVE
            if (seqnum.0 as u64) < cumulative_ack {
                queue_changed = true;
                stallone::debug!(
                    "Freeing chunk because it has been acked",
                    seqnum: ChunkSeqnum = seqnum,
                    chunk_id: ChunkId = chunk.id(),
                );
                chunk.raw_control_word().store(0, Ordering::Release);
                {
                    chunks.lock().free(chunk.id());
                }
                in_flight_chunks.pop_front();
                num_dequeued += 1;
            } else {
                break;
            }
        }
        while in_flight_chunks.len() < DESIRED_QUEUE_SIZE {
            match outgoing_chunks.try_recv() {
                Ok(body) => {
                    let body = Bytes::from(body);
                    let seqnum = next_chunk_seqnum;
                    next_chunk_seqnum.0 += 1;
                    let chunk = { chunks.lock().allocate().expect("Can allocate chunk") };
                    chunk.store_contents(&body[..]);
                    chunk.raw_control_word().store(
                        u64::try_from(ChunkControlWord {
                            host_id,
                            seqnum,
                            reserved: false,
                            state: ChunkState::FilledOutgoing,
                        })
                        .unwrap(),
                        Ordering::Release,
                    );
                    stallone::debug!(
                        "Added chunk to queue",
                        seqnum: ChunkSeqnum = seqnum,
                        chunk_id: ChunkId = chunk.id(),
                    );
                    in_flight_chunks.push_back((seqnum, chunk));
                    queue_changed = true;
                }
                Err(channel::TryRecvError::Empty) => break,
                Err(channel::TryRecvError::Disconnected) => return,
            }
        }
        if queue_changed {
            let start = Instant::now();
            // TODO: set_queue_contents should be made more explicitly aware of the outgoing sliding
            // window.
            queue
                .set_queue_contents(
                    in_flight_chunks.iter().map(|(_, chunk)| chunk.id()),
                    // TOGGLING THIS TO `None` will change the benchmarks!
                    Some(num_dequeued),
                )
                .unwrap();
            stallone::debug!(
                "Outgoing queue changed. Updating IPC queue.",
                len: usize = in_flight_chunks.len(),
                duration: Duration = start.elapsed(),
            );
        }
        stallone::debug!(
            "Outgoing queue update duration",
            duration: Duration = start.elapsed()
        );
        const OUTGOING_THREAD_SLEEP_MS: u64 =
            include!("config-params/outgoing-thread-sleep-duration-ms.txt");
        std::thread::sleep(Duration::from_millis(OUTGOING_THREAD_SLEEP_MS));
    }
}
