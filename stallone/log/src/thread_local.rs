use crate::global_state::{GlobalState, PerProcessGlobalState};
use stallone_common::{
    internal_metadata_structures::LogRecordMetadataHash,
    internal_ring_buffer as rb, positioned_errno, protocol,
    scm_rights::{make_tempfile_fd, ScmRightsExt},
    stallone_emergency_log, EpochNumber, Level, LogRecordHeader, PositionedErrnoResult,
};
use std::{fs::File, os::unix::prelude::FromRawFd, sync::atomic::Ordering};

mod sys;

#[doc(hidden)]
pub struct ThreadLocalLog {
    writer: rb::Writer,
    current_epoch_page: &'static EpochNumber,
}
impl std::ops::Drop for ThreadLocalLog {
    fn drop(&mut self) {
        self.writer.mark_thread_dead();
    }
}

impl ThreadLocalLog {
    // This function needs to be signal-safe.
    fn new(global_state: &'static GlobalState) -> PositionedErrnoResult<Self> {
        let file = make_tempfile_fd().map_err(|errno| positioned_errno!(errno))?;
        let mut file = unsafe {
            // SAFETY: file is the sole owner of the FD
            File::from_raw_fd(file)
        };
        rb::initialize_file(
            &mut file,
            global_state.config.buffer_size,
            &global_state.config.log_level_capacities,
        )?;
        let writer = unsafe {
            // SAFETY: we've just created the file, so there can't be any other writers.
            rb::Writer::new(&file)?
        };
        let msg = protocol::Message::ThreadRingBuffer {
            stallone_pid: unsafe {
                // SAFETY: per the documentation in global_state, the only time that the per-process
                // global state will be mutated is in the pthread_atfork child handler.
                (*(global_state.per_process.get() as *const PerProcessGlobalState)).stallone_pid
            },
        };
        global_state
            .socket
            .sendmsg_file_errno(&file, &msg.serialize()[..])
            .map_err(|errno| positioned_errno!(errno))?;
        Ok(ThreadLocalLog {
            writer,
            current_epoch_page: unsafe {
                // SAFETY: current_epoch_page is a valid pointer. Global state will never be dropped
                &*global_state.current_epoch_page
            },
        })
    }
    #[inline(always)]
    fn current_epoch(&self) -> u64 {
        // TODO: do we need a memory fence instead of just using a load?
        // (On x86-64, this is just a mov, so it doesn't matter there.)
        // This needs to be SeqCst, since we want all memory operations to be ordered with respect
        // to the current epoch.
        self.current_epoch_page.load(Ordering::SeqCst)
    }

    #[inline(always)]
    #[doc(hidden)]
    pub fn write_record<F>(
        &mut self,
        level: Level,
        log_record_type: LogRecordMetadataHash,
        length: usize,
        write_data: F,
    ) where
        for<'a> F: FnOnce(&'a mut [u8]),
    {
        if length >= LogRecordHeader::LENGTH_MAX as usize {
            // TODO: log this
            return;
        }
        let epoch_ms = self.current_epoch();
        self.writer.write(
            LogRecordHeader {
                level,
                length,
                epoch_ms,
                log_record_type,
            },
            write_data,
        );
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ThreadLocalState {
    Uninit = 0, // This is the default state.
    Initializing,
    StalloneReady,
    StalloneMutablyBorrowed,
    StalloneThreadLocalInitializationFailed,
}

/// Initialize the thread-local state
///
/// If this function returns true, the state must be set to StalloneReady.
/// If this function returns false, that means that the thread-local state should not be examined.
///
/// # Async-Signal Safety
/// This function is async-signal safe.
#[inline(never)]
fn thread_local_init(
    ptr: *mut sys::StalloneThreadLocal,
    state_ptr: *mut sys::StateWord,
    state: sys::StateWord,
) -> bool {
    if let Some(gs) = crate::global_state::get() {
        if state == ThreadLocalState::Uninit as sys::StateWord {
            unsafe {
                // SAFETY: state_ptr is a valid pointer. Other threads won't write to this pointer,
                // since we're only ever accessing the state from the current thread.
                std::ptr::write(state_ptr, ThreadLocalState::Initializing as sys::StateWord);
            }
            unsafe {
                // SAFETY: gs.thread_local_destructor_key has been initialized.
                // ASYNC-SIGNAL-SAFETY: this won't allocate so long as gs.thread_local_destructor_key is
                // under 32 (with glibc).
                libc::pthread_setspecific(
                    gs.thread_local_destructor_key,
                    ptr as *const libc::c_void,
                );
            }
            match ThreadLocalLog::new(gs) {
                Ok(tll) => {
                    unsafe {
                        // SAFETY: we've verified that ptr is big enough to store state, and is
                        // adequately aligned (via tests). In addition, ptr is a valid pointer,
                        // and cannot be concurrently modified by another thread.
                        std::ptr::write(
                            sys::StalloneThreadLocal::payload_ptr(ptr) as *mut ThreadLocalLog,
                            tll,
                        );
                    }
                    unsafe {
                        // SAFETY: state_ptr is a valid pointer. Other threads won't write to this pointer,
                        // since we're only ever accessing the state from the current thread.
                        std::ptr::write(
                            state_ptr,
                            ThreadLocalState::StalloneReady as sys::StateWord,
                        );
                    }
                    true
                }
                Err(e) => {
                    let _ =
                        stallone_emergency_log(&gs.base_path, "thread-local initialization", &e);
                    unsafe {
                        // SAFETY: state_ptr is a valid pointer. Other threads won't write to this pointer,
                        // since we're only ever accessing the state from the current thread.
                        std::ptr::write(
                            state_ptr,
                            ThreadLocalState::StalloneThreadLocalInitializationFailed
                                as sys::StateWord,
                        );
                    }
                    false
                }
            }
        } else if state
            == ThreadLocalState::StalloneThreadLocalInitializationFailed as sys::StateWord
        {
            false
        } else {
            // TODO: should we log an error, but not panic here? It's a failed assertion, but it doesn't
            // need to be fatal, neccessarily.
            panic!("Unexpected stallone thread local state {}", state);
        }
    } else {
        false
    }
}

/// Forget/leak the the contents of the thread local, by marking it as uninit.
/// This function is only called on fork, so it's not a big leak, and it means we don't need to
/// assert that the drop operation of the thread-local is async-signal safe.
/// # Async-signal Safety
/// This function is async-signal safe.
pub(crate) fn reset_thread_local() {
    let ptr = unsafe {
        // SAFETY: this operation should be completely safe.
        sys::stallone_thread_local_access()
    };
    let state_ptr = unsafe {
        // SAFETY: this pointer is in-bounds, since `ptr` ought to point to an allocation large
        // enough to contain StalloneThreadLocal
        sys::StalloneThreadLocal::state_ptr(ptr)
    };
    unsafe {
        // SAFETY: state_ptr is a valid pointer not being accessed from other threads.
        std::ptr::write(state_ptr, ThreadLocalState::Uninit as sys::StateWord);
    }
}

/// `use_state` might not neccessarily get called.
///
/// # Async-signal Safety
/// This function is async-signal safe.
#[doc(hidden)]
#[inline(always)]
pub fn stallone_thread_local<F>(use_state: F)
where
    for<'a> F: FnOnce(&'a mut ThreadLocalLog),
{
    let ptr = unsafe {
        // SAFETY: this operation should be completely safe.
        sys::stallone_thread_local_access()
    };
    // One scenario we need to guard against is an implementation of LoggableMetadata calling into
    // stallone logging functions. While this shouldn't happen, if calling stallone::info! from
    // log_serialize or log_size could trigger UB, then we'd need to mark _something_ as unsafe.
    // Rather than marking things as unsafe, we'll just check the state byte of the thread-local to
    // make sure that we're not recursively calling stallone logging functions. (This is the same
    // check that RefCell would be doing.)
    let state_ptr = unsafe {
        // SAFETY: this pointer is in-bounds, since `ptr` ought to point to an allocation large
        // enough to contain StalloneThreadLocal
        sys::StalloneThreadLocal::state_ptr(ptr)
    };
    // It is NOT safe to obtain a reference to state that is held while use_state is called, since
    // that could lead to the same "RefCell" problems that are mentioned above.
    let state = unsafe {
        // SAFETY: state_ptr is a valid pointer not being accessed from other threads.
        std::ptr::read(state_ptr)
    };
    // TODO: do we need to mark this as unlikely?
    if state != ThreadLocalState::StalloneReady as sys::StateWord {
        if !thread_local_init(ptr, state_ptr, state) {
            return;
        }
    }
    #[cfg(debug_assertions)]
    unsafe {
        // SAFETY: state_ptr is a valid pointer not being accessed from other threads.
        assert_eq!(
            std::ptr::read(state_ptr),
            ThreadLocalState::StalloneReady as sys::StateWord,
        );
    }
    unsafe {
        // SAFETY: state_ptr is a valid pointer not being accessed from other threads.
        std::ptr::write(
            state_ptr,
            ThreadLocalState::StalloneMutablyBorrowed as sys::StateWord,
        );
    }
    {
        let tll_ref = unsafe {
            // SAFETY: we've verified in tests that ptr is properly aligned and large enough to store
            // the ThreadLocalLogState. We know that we are the exclusive owner of the initialized
            // thread local contents, since the current state is `StalloneReady`.
            &mut *(sys::StalloneThreadLocal::payload_ptr(ptr) as *mut ThreadLocalLog)
        };
        use_state(tll_ref);
    }
    // Restore the thread-local state to enabled.
    unsafe {
        // SAFETY: state_ptr is a valid pointer not being accessed from other threads.
        std::ptr::write(state_ptr, ThreadLocalState::StalloneReady as sys::StateWord);
    }
}

#[warn(unsafe_op_in_unsafe_fn)]
pub(crate) unsafe extern "C" fn thread_local_destructor(ptr: *mut libc::c_void) {
    let ptr = ptr as *mut sys::StalloneThreadLocal;
    let state_ptr = unsafe {
        // SAFETY: this pointer is in-bounds, since `ptr` ought to point to an allocation large
        // enough to contain StalloneThreadLocal
        sys::StalloneThreadLocal::state_ptr(ptr)
    };
    let state = unsafe {
        // SAFETY: state_ptr is a valid pointer not being accessed from other threads.
        std::ptr::read(state_ptr)
    };
    if state == ThreadLocalState::StalloneReady as sys::StateWord {
        unsafe {
            // SAFETY: state_ptr is a valid pointer not being accessed from other threads.
            std::ptr::write(state_ptr, ThreadLocalState::Uninit as sys::StateWord);
        }
        unsafe {
            // SAFETY: we've verified in tests that ptr is properly aligned and large enough to store
            // the ThreadLocalLogState. We know that we are the exclusive owner of the initialized
            // thread local contents, since the old state is `StalloneReady`. We've set the state to
            // `Uninit` (and also this thread is exiting), so nothing will try to re-use this data
            // again.
            std::ptr::drop_in_place(
                sys::StalloneThreadLocal::payload_ptr(ptr) as *mut ThreadLocalLog
            );
        }
    }
}
