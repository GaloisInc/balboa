//! This module contains the structures and protocols to send outgoing chunks.

use crate::{chunk_allocator::ChunkId, utils::MmapableFileArray};
use stallone_common::{positioned_io_result, PositionedIOResult};
use std::{
    fs::File,
    sync::atomic::{AtomicU64, Ordering},
};

bit_struct_u64! {
    #[quickcheck_test(test_control_word_roundtrip)]
    struct QueueControlWord {
        index: 39,
        length: 24,
        which_buffer: 1,
    }
}

#[test]
fn test_index_is_least_significant() {
    assert_eq!(
        QueueControlWord::from(
            u64::try_from(QueueControlWord {
                which_buffer: 1,
                length: 12,
                index: 34,
            })
            .unwrap()
                + 1
        ),
        QueueControlWord {
            which_buffer: 1,
            length: 12,
            index: 35,
        }
    );
}

pub struct OutgoingQueueProducer {
    contents: MmapableFileArray<AtomicU64>,
    which_buffer: u64,
}
impl OutgoingQueueProducer {
    pub fn new() -> PositionedIOResult<Self> {
        let file = positioned_io_result!(scm_rights::make_tmpfile())?;
        positioned_io_result!(file.set_len((std::mem::size_of::<AtomicU64>() as u64) * 1024))?;
        Ok(OutgoingQueueProducer {
            contents: MmapableFileArray::new(file)?,
            which_buffer: 0,
        })
    }
    pub fn file(&self) -> &File {
        self.contents.file()
    }
    pub fn set_queue_contents(
        &mut self,
        chunk_ids: impl IntoIterator<Item = ChunkId>,
        shift_hint: Option<u64>,
    ) -> PositionedIOResult<()> {
        let mut length = 0;
        self.which_buffer = 1 - self.which_buffer;
        let mut store_idx = 1 + (self.which_buffer as usize);
        let mut contents = self.contents.get();
        for id in chunk_ids {
            if store_idx >= contents.len() {
                positioned_io_result!(self.file().set_len(
                    ((contents.len() + 1024) as u64) * (std::mem::size_of::<AtomicU64>() as u64)
                ))?;
                contents = self.contents.remap()?;
            }
            // TODO: error out if the remapped file is too small.
            assert!(store_idx < contents.len());
            // We can order this relaxed, since everything is committed when we store the control
            // word below.
            contents[store_idx].store(usize::from(id) as u64, Ordering::Relaxed);
            length += 1;
            store_idx += 2;
        }
        // There's probably going to be some overlap between the existing queue contents and the new
        // queue contents. As a result, when we set-up the new queue, we want to have consumers
        // start off right where they left-off.
        let old_control_word = QueueControlWord::from(contents[0].load(Ordering::Acquire));
        let old_index = old_control_word
            .index
            .checked_rem(old_control_word.length)
            .unwrap_or(0);
        let index = shift_hint
            .and_then(|shift_hint| old_index.checked_sub(shift_hint))
            .filter(|index| *index < length);
        // The old index is the index that we were at, but contents have probably advanced since the
        // last old_index. We fix this by subtracting off the shift_hint.
        contents[0].store(
            u64::try_from(QueueControlWord {
                which_buffer: self.which_buffer,
                length,
                // This makes a difference on discard reason. It makes us go from 100% already
                // passed seqnum to 40% already reserved. (Sometimes) at the cost of ~3% efficiency.
                index: index.unwrap_or(0),
            })
            .unwrap(),
            Ordering::Release,
        );
        Ok(())
    }
}

/// The queue's capacity can never shrink.
pub struct OutgoingQueueConsumer {
    contents: MmapableFileArray<AtomicU64>,
}
impl OutgoingQueueConsumer {
    pub fn new(file: File) -> PositionedIOResult<Self> {
        Ok(OutgoingQueueConsumer {
            contents: MmapableFileArray::new(file)?,
        })
    }

    // NOTE: "dequeue" is a bit of a misnomer. This won't remove it from the queue, and we might
    // loop back around. NOTE: this operation might return stale or outdated information.
    pub fn dequeue(&self) -> PositionedIOResult<Option<ChunkId>> {
        let mut mapping = self.contents.get();
        // Per test_index_is_least_significant above, this increment will increase the index in the
        // control word.
        // TODO: we should more explicitly reason about how frequently a queue's control word needs
        // to be reset to 0 index in order to prevent issues. I think, in theory, _any control word_
        // should be fine (and just possibly return stale results) as long as the data on the page,
        // itself doesn't get corrupted. Worst-case, we'll return an error about the mapping not
        // being big enough, and then this function will error out. But with 35 bits for the index,
        // it seems unlikely that this will happen.
        // TODO: warn/error-out if the index looks like it's gonna overflow.
        let control_word = QueueControlWord::from(mapping[0].fetch_add(1, Ordering::AcqRel));
        if control_word.length == 0 {
            // Avoid DIV/MOD by zero.
            return Ok(None);
        }
        debug_assert!(control_word.which_buffer == 0 || control_word.which_buffer == 1);
        // TODO: what should we do if the u64->usize conversion fails? It won't on 64-bit...
        let queue_entry_idx = usize::try_from(control_word.index % control_word.length).unwrap();
        let mapping_idx = 1 /* control word */ + 2 * queue_entry_idx + usize::try_from(control_word.which_buffer).unwrap();
        if mapping_idx >= mapping.len() {
            mapping = self.contents.remap()?;
        }
        if mapping_idx >= mapping.len() {
            // TODO: return an error here instead of panicking!
            panic!(
                "mapping smaller than control word length {} >= {}",
                mapping_idx,
                mapping.len()
            );
        }
        // NOTE: we are still using the control word. Because the queue capacity (though not its
        // length) is monotonically increasing, using an old control word will never SEGFAULT or
        // otherwise cause an index out-of-bounds issue. However, it may result in stale data.
        Ok(Some(ChunkId::from(
            usize::try_from(mapping[mapping_idx].load(Ordering::Acquire)).unwrap(),
        )))
    }
}

#[test]
fn test_outgoing_queue() {
    let mut producer = OutgoingQueueProducer::new().unwrap();
    let consumer = OutgoingQueueConsumer::new(producer.file().try_clone().unwrap()).unwrap();
    assert_eq!(consumer.dequeue().unwrap(), None);
    producer
        .set_queue_contents(
            vec![ChunkId::from(2), ChunkId::from(1), ChunkId::from(84)],
            None,
        )
        .unwrap();
    assert_eq!(consumer.dequeue().unwrap(), Some(ChunkId::from(2)));
    assert_eq!(consumer.dequeue().unwrap(), Some(ChunkId::from(1)));
    assert_eq!(consumer.dequeue().unwrap(), Some(ChunkId::from(84)));
    assert_eq!(consumer.dequeue().unwrap(), Some(ChunkId::from(2)));
    assert_eq!(consumer.dequeue().unwrap(), Some(ChunkId::from(1)));
    assert_eq!(consumer.dequeue().unwrap(), Some(ChunkId::from(84)));
    producer.set_queue_contents(vec![], None).unwrap();
    assert_eq!(consumer.dequeue().unwrap(), None);
    // We pick something bigger than the increase capacity size to force a remap.
    let next_ids: Vec<_> = (2..7464).map(ChunkId::from).collect();
    producer.set_queue_contents(next_ids.clone(), None).unwrap();
    for x in next_ids {
        assert_eq!(consumer.dequeue().unwrap(), Some(x));
    }
}
