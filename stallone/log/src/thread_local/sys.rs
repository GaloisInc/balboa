use memoffset::offset_of;

// Keep this module in sync with thread_local.c
// TODO: let's see if we could pack the entire thread local into a single 64-byte cache line.
pub(super) const PAYLOAD_SIZE: usize = 120;
pub(super) type StateWord = u64;

#[repr(C)]
pub(super) struct StalloneThreadLocal {
    pub(super) state: u64,
    pub(super) payload: [u8; PAYLOAD_SIZE],
}

impl StalloneThreadLocal {
    /// # Safety
    /// `this` must point to a valid `StalloneThreadLocal` allocation.
    pub(super) unsafe fn state_ptr(this: *mut StalloneThreadLocal) -> *mut StateWord {
        // SAFETY: so long as `this` is a valid pointer, then the state will be in the allocation.
        (this as *mut u8).offset(offset_of!(StalloneThreadLocal, state) as isize) as *mut u64
    }
    /// # Safety
    /// `this` must point to a valid `StalloneThreadLocal` allocation.
    pub(super) unsafe fn payload_ptr(this: *mut StalloneThreadLocal) -> *mut u8 {
        // SAFETY: so long as `this` is a valid pointer, then the payload will be in the allocation.
        (this as *mut u8).offset(offset_of!(StalloneThreadLocal, payload) as isize)
    }
}

#[test]
fn test_size() {
    use super::*;
    assert!(
        std::mem::size_of::<ThreadLocalLog>() <= PAYLOAD_SIZE,
        "{}",
        std::mem::size_of::<ThreadLocalLog>()
    );
    assert_eq!(
        std::mem::align_of::<StalloneThreadLocal>() % std::mem::align_of::<ThreadLocalLog>(),
        0
    );
}

extern "C" {
    // This is initialized to 0 by default.
    pub(super) fn stallone_thread_local_access() -> *mut StalloneThreadLocal;
}
