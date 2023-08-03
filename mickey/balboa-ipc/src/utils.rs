use parking_lot::RwLock;
use stallone_common::{positioned_io_result, PositionedIOResult};
use std::{fs::File, os::unix::io::AsRawFd, sync::Arc};

pub unsafe trait SafelyMmapable: Sync + Send {}
unsafe impl SafelyMmapable for std::sync::atomic::AtomicU64 {}

pub(crate) struct MmapedArray<T: SafelyMmapable> {
    body: *const T,
    size: usize,
    len_bytes: usize,
}
// TODO: should these be impl'd here?
unsafe impl<T: SafelyMmapable> Send for MmapedArray<T> {}
unsafe impl<T: SafelyMmapable> Sync for MmapedArray<T> {}
impl<T: SafelyMmapable> MmapedArray<T> {
    /// The size of `f` should only ever _montonically increase_ during its lifetime.
    fn map(f: &File) -> PositionedIOResult<Self> {
        let len_bytes = usize::try_from(positioned_io_result!(f.metadata())?.len()).unwrap();
        // NOTE: there's a possible data race between when we check the file size and when we map
        // the file into memory. This is okay, since the file size will be monotonically increasing,
        // So we'll never try to map more of the file than exists in reality.
        let size = len_bytes / std::mem::size_of::<T>();
        let ptr = if len_bytes == 0 {
            std::ptr::null_mut()
        } else {
            unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len_bytes,
                    libc::PROT_READ | libc::PROT_WRITE,
                    // TODO: should we MAP_POPULATE?
                    libc::MAP_SHARED,
                    f.as_raw_fd(),
                    0,
                )
            }
        };
        if ptr == libc::MAP_FAILED {
            Err(stallone_common::positioned_io_error!(
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(MmapedArray {
                body: ptr as *const T,
                size,
                len_bytes,
            })
        }
    }
}
impl<T: SafelyMmapable> std::ops::Drop for MmapedArray<T> {
    fn drop(&mut self) {
        if !self.body.is_null() {
            unsafe {
                libc::munmap(self.body as *const _ as *mut _, self.len_bytes);
            }
        }
    }
}
impl<T: SafelyMmapable> std::ops::Deref for MmapedArray<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.body, self.size) }
    }
}

pub struct MmapableFileArray<T: SafelyMmapable> {
    file: File,
    array: RwLock<Arc<MmapedArray<T>>>,
}

impl<T: SafelyMmapable> MmapableFileArray<T> {
    pub(crate) fn new(file: File) -> PositionedIOResult<Self> {
        let array = RwLock::new(Arc::new(MmapedArray::map(&file)?));
        Ok(MmapableFileArray { file, array })
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn get(&self) -> Arc<MmapedArray<T>> {
        self.array.read().clone()
    }
    pub(crate) fn remap(&self) -> PositionedIOResult<Arc<MmapedArray<T>>> {
        let new_map = Arc::new(MmapedArray::map(&self.file)?);
        let mut guard = self.array.write();
        if guard.size < new_map.size {
            *guard = new_map;
        }
        Ok(guard.clone())
    }
}
