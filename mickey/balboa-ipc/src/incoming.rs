use crate::{
    chunk_allocator::ChunkId,
    types::{ChunkSeqnum, CHUNK_SEQNUM_BITS},
    utils::MmapableFileArray,
};
use stallone::LoggableMetadata;
use stallone_common::{positioned_io_result, PositionedIOResult};
use std::{
    fs::File,
    sync::atomic::{AtomicU64, Ordering},
};

bit_struct_u64! {
    #[quickcheck_test(test_incoming_control_word)]
    struct IncomingControlWord {
        which_buffer: 1,
        // The offset doubles as the cumulative ACK
        offset: CHUNK_SEQNUM_BITS,
        length: 23,
    }
}

const CONTROL_WORD_INDEX: usize = 0;
const ACK_WORD_INDEX: usize = 1;
const NUMBER_OF_PREFIX_WORDS: usize = 2;

pub struct IncomingWindowController {
    contents: MmapableFileArray<AtomicU64>,
    which_buffer: u64,
}

impl IncomingWindowController {
    pub fn new() -> PositionedIOResult<Self> {
        let file = positioned_io_result!(scm_rights::make_tmpfile())?;
        positioned_io_result!(file.set_len((std::mem::size_of::<AtomicU64>() as u64) * 1024))?;
        Ok(IncomingWindowController {
            contents: MmapableFileArray::new(file)?,
            which_buffer: 0,
        })
    }
    pub fn file(&self) -> &File {
        self.contents.file()
    }
    // TODO: this code is rather similar to the outgoing queue (except that it's accessed differently)
    // Can we reuse some of this code?
    pub fn set_queue_contents(
        &mut self,
        offset: u64,
        chunk_ids: impl IntoIterator<Item = ChunkId>,
    ) -> PositionedIOResult<()> {
        let mut length = 0;
        self.which_buffer = 1 - self.which_buffer;
        let mut store_idx = NUMBER_OF_PREFIX_WORDS + (self.which_buffer as usize);
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
        let cw = u64::try_from(IncomingControlWord {
            which_buffer: self.which_buffer,
            length,
            offset,
        })
        .unwrap();
        contents[CONTROL_WORD_INDEX].store(cw, Ordering::Release);
        Ok(())
    }
}

#[derive(Debug, LoggableMetadata)]
pub enum FailedToGetIncomingChunk {
    AlreadyPassedSeqnum {
        control_word: IncomingControlWord,
        seqnum: ChunkSeqnum,
    },
    NotUpToSeqnum {
        control_word: IncomingControlWord,
        seqnum: ChunkSeqnum,
    },
}

pub struct IncomingWindowConsumer {
    contents: MmapableFileArray<AtomicU64>,
}
impl IncomingWindowConsumer {
    pub fn new(file: File) -> PositionedIOResult<Self> {
        Ok(IncomingWindowConsumer {
            contents: MmapableFileArray::new(file)?,
        })
    }

    pub fn get_our_cumulative_ack(&self) -> u64 {
        let mapping = self.contents.get();
        IncomingControlWord::from(mapping[CONTROL_WORD_INDEX].load(Ordering::Relaxed)).offset
    }

    // "their" = "remote"
    pub fn get_their_cumulative_ack(&self) -> u64 {
        let mapping = self.contents.get();
        let word = &mapping[ACK_WORD_INDEX];
        word.load(Ordering::Relaxed)
    }

    // "their" = "remote"
    pub fn store_their_cumulative_ack(&self, ack: u64) {
        let mapping = self.contents.get();
        let word = &mapping[ACK_WORD_INDEX];
        let mut old = word.load(Ordering::Relaxed);
        stallone::debug!("Old vs new ack", old: u64 = old, ack: u64 = ack);
        // This CAS loop is lock-free, but not wait-free.
        while old < ack {
            // TODO: memory ordering
            match word.compare_exchange_weak(old, ack, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => break,
                Err(new_value) => {
                    old = new_value;
                }
            }
        }
    }

    // NOTE: this operation might return stale or outdated information.
    // TODO: result of result might be funky.
    pub fn get(
        &self,
        seqnum: ChunkSeqnum,
    ) -> PositionedIOResult<Result<ChunkId, FailedToGetIncomingChunk>> {
        let mut mapping = self.contents.get();
        let control_word =
            IncomingControlWord::from(mapping[CONTROL_WORD_INDEX].load(Ordering::Acquire));
        if u64::from(seqnum) < control_word.offset {
            // We've already passed this seqnum.
            return Ok(Err(FailedToGetIncomingChunk::AlreadyPassedSeqnum {
                control_word,
                seqnum,
            }));
        }
        debug_assert!(control_word.which_buffer == 0 || control_word.which_buffer == 1);
        let entry_idx = u64::from(seqnum).checked_sub(control_word.offset).unwrap();
        if entry_idx >= control_word.length {
            return Ok(Err(FailedToGetIncomingChunk::NotUpToSeqnum {
                control_word,
                seqnum,
            }));
        }
        // TODO: what should we do if the u64->usize conversion fails? It won't on 64-bit...
        let entry_idx = usize::try_from(entry_idx).unwrap();
        let mapping_idx = NUMBER_OF_PREFIX_WORDS
            + 2 * entry_idx
            + usize::try_from(control_word.which_buffer).unwrap();
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
        Ok(Ok(ChunkId::from(
            usize::try_from(mapping[mapping_idx].load(Ordering::Acquire)).unwrap(),
        )))
    }
}
