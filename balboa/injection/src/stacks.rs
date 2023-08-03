//! Some programs that we inject into don't have enough space left on their stacks for our code to
//! operate when they call syscall wrappers. To get around that, we allocate a custom stack for
//! ourselves, and switch to it.
//!
//! # Stack pooling
//! To avoid mmaping a new stack every time we need one, we have a pool of stacks that we draw from,
//! when possible.
//!
//! In order for this pool to be signal-safe, it needs to be lock-free (as a safety property).
//! Many existing implementations are designed to give good concurrent performance, but they might
//! not be _truly_ lock-free in all cases (since lock-freedom isn't needed for safety in most use
//! cases).
//!
//! To keep things simple, we go with an array-based design. We also aren't super concerned with
//! cache coherency issues, since poor cache coherency might balloon our operations to a few hundred
//! nanoseconds, which shouldn't be too bad for our use-case.
//!
//! We have an atomic 64-bit bitmask denoting which stacks are available, and an array of 64 pointer
//! slots to store the stack pointer in. If a bit in `AVAILABLE_STACKS_BITMASK` is 1, then that
//! means that the corresponding slot in the `AVAILABLE_STACK_STORAGE` array is populated with an
//! allocated stack.
//!
//! ## How to fetch a stack from the pool?
//! In a loop:
//! 1. Load `AVAILABLE_STACKS_BITMASK`. If it's 0, then there's no available stacks, and we'll need
//!    to allocate a stack from the kernel (the slow path).
//! 2. Pick a 1 bit in `AVAILABLE_STACKS_BITMASK`, and atomically mask it out (setting it to 0). If
//!    we successfully set the bit to 0 (that is, the previous value of the bitmask before the RMW
//!    bitwise-AND operation had the 1 bit set), then we have successfully claimed the value of the
//!    slot. We atomically load the value at the slot, and store a null pointer there.
//! 3. If we failed to set the bit to 0 (that is, another thread reserved it before us), then we
//!    try again in a loop.
//! ### Lock-Freedom
//! This algorithm is lock-free (though it's not wait-free). The only time the loop would iterate
//! would be if a bit in `AVAILABLE_STACKS_BITMASK` transitions from 1 to 0 in between our initial
//! load and our RMW atomic-and operation. The only way this transition could occur would be if
//! another thread updated it. Thus, if all other threads were paused at any point, then this
//! algorithm would complete in constant-time.
//!
//! ## How to add a stack to the pool?
//! Our general plan is that we'll iterate _once_ through the `AVAILABLE_STACK_STORAGE` array and
//! attempt to CAS a null pointer in that storage with the pointer we want to insert. If we succeed,
//! then we'll set the corresponding 0 bit in `AVAILABLE_STACKS_BITMASK` to 1. We're guaranteed that
//! the corresponding bit in `AVAILABLE_STACKS_BITMASK` is 0, since we have an invariant that says
//! that a `NULL` value in the stack storage implies a 0 bit in the bitmask.
//!
//! If we fail to add the stack to the pool, we'll `munmap()` it, and release the memory back to the
//! kernel.
//!
//! To avoid loading 64 64-bit pointers (which is a number of memory accesses), we first load the
//! `AVAILABLE_STACKS_BITMASK`, and then limit our search for null pointers in
//! `AVAILABLE_STACK_STORAGE` to only those slots with 0 bits in the bitmask. While this might mean
//! that we "miss" some possible free slots compared to the above approach, this approach should
//! lead to a performance increase.
//!
//! ### Lock-Freedom
//! This algorithm is lock-free since it contains no loops, and will therefore complete in constant-
//! time.

use std::convert::TryFrom;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

const STACK_SIZE: usize = 4 * 1024 * 1024; // 4 MB
                                           // TODO: make the page size bigger
const PAGE_SIZE: usize = 4096;

// NOTE: this algorithm isn't _great_ for cache coherency.
static AVAILABLE_STACKS_BITMASK: AtomicU64 = AtomicU64::new(0);
// This constant is needed since AtomicPtr isn't Copy.
const NULL: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static AVAILABLE_STACK_STORAGE: [AtomicPtr<u8>; 64] = [NULL; 64];

struct Stack {
    stack_body: *mut u8,
}
impl Stack {
    /// Allocate a stack with leading and trailing guard pages. Returning a pointer to `STACK_SIZE`
    /// valid bytes, aligned to a page boundary.
    ///
    /// This function will first draw from a pool of pre-allocated stacks, before trying to ask the
    /// kernel for more memory.
    ///
    /// # Async Signal-Safety
    /// This function is async signal-safe.
    fn new() -> Self {
        // TODO: it might be possible to relax this memory ordering
        let mut available_stacks = AVAILABLE_STACKS_BITMASK.load(Ordering::SeqCst);
        let stack_body = loop {
            if available_stacks == 0 {
                break Self::alloc_stack_slow();
            }
            let available_idx = available_stacks.trailing_zeros();
            let mask_on = 1 << available_idx;
            debug_assert_ne!(available_stacks & mask_on, 0);
            available_stacks = AVAILABLE_STACKS_BITMASK.fetch_and(!mask_on, Ordering::SeqCst);
            if available_stacks & mask_on != 0 {
                // Nobody swooped in and stole the index that we chose before we could take it.
                let idx = usize::try_from(available_idx).expect("usize can at least hold 64");
                let ptr = &AVAILABLE_STACK_STORAGE[idx];
                // Strictly speaking, it'd be okay for this to be a load followed by a store.
                let out = ptr.swap(std::ptr::null_mut(), Ordering::SeqCst);
                assert!(!out.is_null());
                break out;
            }
        };
        Stack { stack_body }
    }

    /// Allocate a stack with leading and trailing guard pages. Returning a pointer to `STACK_SIZE`
    /// valid bytes, aligned to a page boundary.
    ///
    /// This function will directly ask the kernel for the memory for the new stack.
    ///
    /// # Async Signal-Safety
    /// This function is async signal-safe.
    fn alloc_stack_slow() -> *mut u8 {
        unsafe {
            #[cfg(target_os = "linux")]
            const MAP_STACK: libc::c_int = libc::MAP_STACK;
            #[cfg(target_os = "macos")]
            const MAP_STACK: libc::c_int = 0;
            let full_out = libc::mmap(
                std::ptr::null_mut(),
                STACK_SIZE + PAGE_SIZE * 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_STACK,
                -1,
                0,
            );
            assert_ne!(full_out, libc::MAP_FAILED);
            let full_out = full_out as *mut u8;
            let rc = libc::mprotect(full_out as *mut libc::c_void, PAGE_SIZE, libc::PROT_NONE);
            assert_eq!(rc, 0);
            let body_out = full_out.offset(PAGE_SIZE as isize);
            let rc = libc::mprotect(
                body_out.offset(STACK_SIZE as isize) as *mut libc::c_void,
                PAGE_SIZE,
                libc::PROT_NONE,
            );
            assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
            body_out
        }
    }
}
impl std::ops::Drop for Stack {
    fn drop(&mut self) {
        // TODO: it might be possible to relax this memory ordering
        let available_stacks = AVAILABLE_STACKS_BITMASK.load(Ordering::SeqCst);
        // We do one iteration through the bits of the bitmask. If that fails, then we abort trying
        // to store into the free list. We have to be careful about re-trying, since we need to be
        // writing a lock-free algorithm.
        for i in 0..64 {
            let mask = 1 << i;
            let idx = usize::try_from(i).expect("usize can store 63");
            if available_stacks & mask != 0 {
                if AVAILABLE_STACK_STORAGE[idx]
                    .compare_exchange(
                        std::ptr::null_mut(),
                        self.stack_body,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok()
                {
                    let old = AVAILABLE_STACKS_BITMASK.fetch_or(mask, Ordering::SeqCst);
                    assert_eq!(old & mask, 0);
                    return;
                }
            }
        }
        // We failed to insert the stack into the free list. We'll munmap it, instead.
        unsafe {
            let _ = libc::munmap(
                self.stack_body.sub(PAGE_SIZE) as *mut libc::c_void,
                STACK_SIZE + PAGE_SIZE * 2,
            );
        }
    }
}

/// Run the specified function on a freshly allocated stack.
///
/// # Async Signal-Safety
/// This function is as async signal-safe as the callback, `f`.
#[inline]
pub fn run_on_fresh_stack<F: FnOnce() -> R, R>(f: F) -> R {
    let stack = Stack::new();
    unsafe {
        // SAFETY REQUIRMENTS (per the psm docs):
        // 1. The stack base address must be aligned as appropriate for the target.
        // 2. The stack size must be a multiple of stack alignment required by target.
        // 3. The size must not overflow isize.
        // 4. callback must not unwind or return control flow by any other means than directly returning.
        // SAFETY:
        // 1 is guaranteed by mmap.
        // 2,3 are guaranteed by our constants
        // 4 is true since we abort on panic
        psm::on_stack(stack.stack_body, STACK_SIZE, f)
    }
}

#[test]
fn test_run_on_fresh_stack() {
    let mut hash = None;
    run_on_fresh_stack(|| {
        let buf = [0xab; 1024 * 1024];
        hash = Some(blake3::hash(&buf));
    });
    dbg!(hash);
}

#[test]
fn test_stack_allocator() {
    fn check_stack(stack: &Stack) {
        assert_eq!(stack.stack_body as u64 % (PAGE_SIZE as u64), 0);
        // If this doesn't crash, then the stack is okay!
        unsafe {
            libc::memset(stack.stack_body as *mut libc::c_void, 0xff, STACK_SIZE);
        }
    }
    use std::collections::HashSet;
    assert_eq!(AVAILABLE_STACKS_BITMASK.load(Ordering::SeqCst), 0);
    for ptr in AVAILABLE_STACK_STORAGE.iter() {
        assert!(ptr.load(Ordering::SeqCst).is_null());
    }
    let mut pool = HashSet::new();
    let mut stacks = Vec::new();
    for _ in 0..64 {
        let stack = Stack::new();
        check_stack(&stack);
        assert!(pool.insert(stack.stack_body));
        stacks.push(stack);
    }
    {
        let stack = Stack::new();
        check_stack(&stack);
        assert!(!pool.contains(&stack.stack_body));
        stacks.push(stack);
    }
    stacks.clear();
    for _ in 0..4 {
        let stack = Stack::new();
        check_stack(&stack);
        assert!(pool.contains(&stack.stack_body));
        stacks.push(stack);
    }
}
