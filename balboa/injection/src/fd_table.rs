use crate::fd_state::FdState;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::{
    collections::HashMap,
    sync::{atomic::AtomicU64, Arc},
};

pub type FD = i32;

// TODO: generally, does the fd table race with interceptors?

/// This is a standard limit on the number of file descriptors in Linux.
///
/// `FdSet` currently allocates one bit for each FD. As a result, if this number grows much higher,
/// then it may be preferable to switch to a sparser representation (or a hierarchy of bitsets).
const MAX_FDS: usize = 524288;
const FD_SET_NUM_CELLS: usize = MAX_FDS / 64;
/// This is a bitset that supports signal-safe queries.
struct FdSet {
    contents: [AtomicU64; FD_SET_NUM_CELLS],
}

// We want to statically zero initialize an FdSet. Because AtomicU64 isn't copy, we can't initialize
// a [AtomicU64; _] array with [value; count] syntax. It'd be great to use std::mem::zeroed(), but
// that's not a const fn. So, we turn to std::mem::transmute to turn an array of zero integers into
// an array of zero atomic integers. Unfortunately, while transmute _is_ a const fn, it's unstable
// to call it from a const fn, as of this writing. As a result, we have this new_fd_set macro,
// instead, so that we can end up invoking transmute only from a static initializer.
macro_rules! new_fd_set {
    () => {
        FdSet {
            contents: unsafe {
                // SAFETY: AtomicU64 has a defined representation, and arrays also have a defined
                // representation. An array of AtomicU64s is plain-old-data.
                std::mem::transmute::<[u64; FD_SET_NUM_CELLS], [AtomicU64; FD_SET_NUM_CELLS]>(
                    [0; FD_SET_NUM_CELLS],
                )
            },
        }
    };
}

impl FdSet {
    fn cell(&self, fd: FD) -> Option<(&AtomicU64, u64)> {
        let fd = usize::try_from(fd).ok()?;
        let cell = self.contents.get(fd / 64)?;
        let mask = 1 << (fd % 64);
        Some((cell, mask))
    }
    fn contains(&self, fd: FD) -> bool {
        // TODO: can we relax the memory ordering? I think so? In practice, when FdSet is used,
        // it'll be in conjunction with the RwLock on the FdState table.
        self.cell(fd)
            .map(|(cell, mask)| (cell.load(Ordering::SeqCst) & mask) != 0)
            .unwrap_or(false)
    }
    fn insert(&self, fd: FD) {
        let (cell, mask) = self.cell(fd).expect("Trying to insert an out of bounds fd");
        // TODO: See note on ordering above.
        cell.fetch_or(mask, Ordering::SeqCst);
    }
    fn remove(&self, fd: FD) {
        if let Some((cell, mask)) = self.cell(fd) {
            // TODO: See note on ordering above.
            cell.fetch_and(!mask, Ordering::SeqCst);
        }
    }
}

static ACCEPT_FD_SET: FdSet = new_fd_set!();

static FD_TABLE_SET: FdSet = new_fd_set!();
static FD_TABLE: AtomicPtr<RwLock<HashMap<FD, Arc<FdState>>>> =
    AtomicPtr::new(std::ptr::null_mut());

#[cold]
pub fn initialize() {
    FD_TABLE.store(
        Box::into_raw(Box::new(RwLock::new(HashMap::with_capacity(256)))),
        Ordering::Relaxed,
    );
}

pub fn is_in_accept_fd_set(fd: FD) -> bool {
    ACCEPT_FD_SET.contains(fd)
}

pub fn add_to_accept_fd_set(fd: FD) {
    ACCEPT_FD_SET.insert(fd);
}

pub fn remove_from_accept_fd_set(fd: FD) {
    ACCEPT_FD_SET.remove(fd);
}

fn get_fd_table() -> &'static RwLock<HashMap<FD, Arc<FdState>>> {
    let ptr = FD_TABLE.load(Ordering::Relaxed);
    assert!(!ptr.is_null(), "called before balboa was initialized");
    let out = unsafe {
        // SAFETY: this pointer is not null (by the assert). This pointer was created by allocating
        // memory. This memory will never be freed. The type is Sync.
        &*ptr
    };
    #[inline(always)]
    fn assert_type_is_sync<T: Sync>(_x: &T) {}
    assert_type_is_sync(out);
    out
}

/// # Async-Signal Safety
/// It is signal-safe to lookup a file descriptor which is not in the table.
pub fn get(fd: FD) -> Option<Arc<FdState>> {
    if !FD_TABLE_SET.contains(fd) {
        return None;
    }
    get_fd_table().read().get(&fd).cloned()
}

pub fn insert(fd: FD, value: Arc<FdState>) {
    debug_assert!(fd >= 0);
    // The ordering of these two doesn't matter so much. A problem would only occur if a process is
    // accessing a file descriptor before it's been fully established (e.g. guessing the return
    // value of open, and writing to the FD before open has reutrned). And that should hopefully not
    // happen in real programs.
    get_fd_table().write().insert(fd, value);
    FD_TABLE_SET.insert(fd);
}

pub fn remove(fd: FD) {
    // The same note from insert about ordering applies here.
    FD_TABLE_SET.remove(fd);
    get_fd_table().write().remove(&fd);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{
        collection::{hash_set, vec, SizeRange},
        prelude::*,
    };

    proptest! {
        #[test]
        fn test_fd_set(
            starter in hash_set(0..MAX_FDS, SizeRange::default()),
            ops in vec((any::<bool>(), 0..MAX_FDS), 128..=128)
        ) {
            let mut canonical = starter;
            let actual = new_fd_set!();
            for x in canonical.iter() {
                actual.insert(*x as i32);
            }
            assert!(!actual.contains(-1));
            assert!(!actual.contains(MAX_FDS as i32));
            for (should_insert, fd) in ops.into_iter() {
                assert_eq!(actual.contains(fd as i32), canonical.contains(&fd));
                if should_insert {
                    actual.insert(fd as i32);
                    canonical.insert(fd);
                } else {
                    actual.remove(fd as i32);
                    canonical.remove(&fd);
                }
                assert_eq!(actual.contains(fd as i32), canonical.contains(&fd));
            }
        }
    }

    #[test]
    fn test_max_fds_is_a_multiple_of_64() {
        assert_eq!(MAX_FDS % 64, 0);
    }
}
