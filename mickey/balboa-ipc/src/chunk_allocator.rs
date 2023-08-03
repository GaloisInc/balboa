//! This module implements a "slab"-ish allocator for 1KB chunks which can be shared between
//! multiple processes. The `ChunkAllocatorWriter` is the exclusive "writer" which can allcoate
//! and free chunks, while any process that has a `ChunkAllocatorReader` can read/write chunk data.

use crate::{
    types::{ChunkControlWord, ChunkState},
    utils::{MmapableFileArray, MmapedArray, SafelyMmapable},
};
use stallone::LoggableMetadata;
use stallone_common::{positioned_io_result, PositionedIOResult};
use std::{
    cell::UnsafeCell,
    fs::File,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

// Chunks are indexed continuously. Each page is stored subsequently.

pub const CHUNK_SIZE: usize = include!("config-params/chunk-size.txt");
const CHUNKS_PER_PAGE: usize = include!("config-params/chunks-per-page.txt");

/// This is an index into a chunk slot in the table.
#[derive(LoggableMetadata, Debug, PartialEq, Eq, Clone, Copy)]
pub struct ChunkId(usize);
impl ChunkId {
    fn page_idx(&self) -> usize {
        self.0 / CHUNKS_PER_PAGE
    }
    fn chunk_idx(&self) -> usize {
        self.0 % CHUNKS_PER_PAGE
    }
}
impl From<ChunkId> for usize {
    fn from(x: ChunkId) -> Self {
        x.0
    }
}
impl From<usize> for ChunkId {
    fn from(x: usize) -> Self {
        ChunkId(x)
    }
}

/// The writer has the ability to allocate new chunks, and has the decision about freeing them.
pub struct ChunkAllocatorWriter {
    free_list: Vec<ChunkId>,
    pages: MmapableFileArray<ChunkPage>,
}

impl ChunkAllocatorWriter {
    pub fn new() -> PositionedIOResult<Self> {
        let file = positioned_io_result!(scm_rights::make_tmpfile())?;
        let pages = MmapableFileArray::new(file)?;
        Ok(ChunkAllocatorWriter {
            free_list: Vec::new(),
            pages,
        })
    }

    /// Get the backing file for the allocated chunks.
    pub fn file(&self) -> &File {
        &self.pages.file()
    }

    pub fn allocate(&mut self) -> PositionedIOResult<Chunk> {
        let id = self.allocate_raw()?;
        debug_assert_ne!(id.0, 0);
        let chunk = Chunk {
            pages: self.pages.get(),
            id,
        };
        // We want to ensure that this load isn't re-ordered before previous loads.
        // Hence SeqCst.
        debug_assert_eq!(
            chunk.control_word(Ordering::SeqCst).state,
            ChunkState::Unused
        );
        Ok(chunk)
    }

    fn allocate_raw(&mut self) -> PositionedIOResult<ChunkId> {
        // TODO: we probably want subsequent allocations to be next to each other? For cache reasons?
        if let Some(id) = self.free_list.pop() {
            return Ok(id);
        }
        let mut num_pages = self.pages.get().len();
        let start_chunk_ids = num_pages * CHUNKS_PER_PAGE;
        num_pages += 1;
        stallone::debug!("Out of free chunks. Allocating another page.");
        positioned_io_result!(self
            .file()
            .set_len((num_pages as u64) * (std::mem::size_of::<ChunkPage>() as u64)))?;
        self.free_list.reserve(CHUNKS_PER_PAGE);
        self.free_list.extend(
            (start_chunk_ids..start_chunk_ids + CHUNKS_PER_PAGE)
                .filter(|x| {
                    // We don't want chunk ID 0 to ever be allocated.
                    *x != 0
                })
                .map(ChunkId),
        );
        self.pages.remap()?;
        Ok(self
            .free_list
            .pop()
            .expect("We just pushed to the freelist"))
    }

    /// Any chunk that is being freed should have first marked as "Unused". This prevents some race
    /// conditions by forcing all chunks to cycle through the "Unused" state before being used for
    /// another purpose.
    pub fn free(&mut self, id: ChunkId) {
        debug_assert_eq!(
            ChunkControlWord::from(
                self.pages.get()[id.page_idx()].states[id.chunk_idx()].load(Ordering::Acquire)
            )
            .state,
            ChunkState::Unused
        );
        self.free_list.push(id);
    }
}
impl HasChunk for ChunkAllocatorWriter {
    fn pages(&self) -> &MmapableFileArray<ChunkPage> {
        &self.pages
    }
}

/// This trait consolidates functionaliy common to both the reader and writer.
pub trait HasChunk {
    fn pages(&self) -> &MmapableFileArray<ChunkPage>;

    fn chunk(&self, id: ChunkId) -> PositionedIOResult<Chunk> {
        if id.0 == 0 {
            stallone::warn!("Tried to access chunk ID 0. That ID should never be allocated.");
        }
        let mut chunk_pages = self.pages().get();
        let page = id.page_idx();
        if page >= chunk_pages.len() {
            // If there aren't enough pages loaded, then we'll create a new mapping, in the hopes
            // that it will make the chunk ID valid.
            chunk_pages = self.pages().remap()?;
        }
        // Assert that the chunk actually exists. The "Chunk" struct will otherwise lazily load and
        // lazily check that the page is valid.
        assert!(page < chunk_pages.len());
        debug_assert_ne!(id.0, 0);
        Ok(Chunk {
            pages: chunk_pages,
            id,
        })
    }
}

//// The "read" side of the chunk allocator which can read/write chunk data.
pub struct ChunkAllocatorReader {
    pages: MmapableFileArray<ChunkPage>,
}
impl HasChunk for ChunkAllocatorReader {
    fn pages(&self) -> &MmapableFileArray<ChunkPage> {
        &self.pages
    }
}

impl ChunkAllocatorReader {
    pub fn new(file: File) -> PositionedIOResult<Self> {
        Ok(ChunkAllocatorReader {
            pages: MmapableFileArray::new(file)?,
        })
    }
}

/// This is a chunk in the allocator.
pub struct Chunk {
    pages: Arc<MmapedArray<ChunkPage>>,
    id: ChunkId,
}
impl Chunk {
    pub fn id(&self) -> ChunkId {
        self.id
    }

    pub fn raw_control_word(&self) -> &AtomicU64 {
        &self.pages[self.id.page_idx()].states[self.id.chunk_idx()]
    }

    pub fn control_word(&self, ordering: Ordering) -> ChunkControlWord {
        ChunkControlWord::from(self.raw_control_word().load(ordering))
    }

    /// # Panics
    /// Panics if `dst.len() != CHUNK_SIZE`
    pub fn load_contents(&self, dst: &mut [u8]) {
        assert_eq!(dst.len(), CHUNK_SIZE);
        let contents = &self.pages[self.id.page_idx()].bodies[self.id.chunk_idx()];
        // We use libc's memcpy. In theory, there should be no concurrent access to the bytes, but
        // it'd be best to not produce UB if that's not true (and rust's copy_from_slice) seems more
        // complicated than memcpy. (This is probably not scientific.)
        unsafe {
            libc::memcpy(
                dst.as_mut_ptr() as *mut std::ffi::c_void,
                (*contents.get()).as_ptr() as *const std::ffi::c_void,
                CHUNK_SIZE,
            );
        }
    }
    /// # Panics
    /// Panics if `dst.len() != CHUNK_SIZE`
    pub fn store_contents(&self, src: &[u8]) {
        stallone::debug!("Store contents into chunk", chunk_id: ChunkId = self.id,);
        assert_eq!(src.len(), CHUNK_SIZE);
        let contents = &self.pages[self.id.page_idx()].bodies[self.id.chunk_idx()];
        // We use libc's memcpy. In theory, there should be no concurrent access to the bytes, but
        // it'd be best to not produce UB if that's not true (and rust's copy_from_slice) seems more
        // complicated than memcpy. (This is probably not scientific.)
        unsafe {
            libc::memcpy(
                (*contents.get()).as_mut_ptr() as *mut std::ffi::c_void,
                src.as_ptr() as *const std::ffi::c_void,
                CHUNK_SIZE,
            );
        }
    }
}

#[doc(hidden)]
#[repr(C)]
pub struct ChunkPage {
    states: [AtomicU64; CHUNKS_PER_PAGE],
    bodies: [UnsafeCell<[u8; CHUNK_SIZE]>; CHUNKS_PER_PAGE],
}
// This is true since we take pains when using the bodies to make sure that it's not racy.
unsafe impl Sync for ChunkPage {}
unsafe impl SafelyMmapable for ChunkPage {}

#[test]
fn test_chunk_allocator() {
    let mut writer = ChunkAllocatorWriter::new().unwrap();
    let chunks: Vec<_> = (0..CHUNKS_PER_PAGE)
        .map(|_| writer.allocate().unwrap())
        .collect();
    chunks[2].store_contents(&[13; CHUNK_SIZE][..]);
    let reader = ChunkAllocatorReader::new(writer.file().try_clone().unwrap()).unwrap();
    let mut buf = [0; CHUNK_SIZE];
    reader
        .chunk(chunks[2].id())
        .unwrap()
        .load_contents(&mut buf);
    assert_eq!(&buf[..], &[13; CHUNK_SIZE][..]);
    let extra_chunk = writer.allocate().unwrap();
    extra_chunk.store_contents(&[74; CHUNK_SIZE][..]);
    reader
        .chunk(extra_chunk.id())
        .unwrap()
        .load_contents(&mut buf);
    assert_eq!(&buf[..], &[74; CHUNK_SIZE][..]);
}
