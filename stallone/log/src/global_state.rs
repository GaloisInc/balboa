use arrayvec::ArrayVec;
use std::{
    cell::UnsafeCell,
    os::unix::{
        net::{UnixDatagram, UnixStream},
        prelude::{AsRawFd, FromRawFd, IntoRawFd},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicPtr, Ordering},
        Once,
    },
    time::Duration,
};
use uuid::Uuid;

use stallone_common::{
    positioned_errno, positioned_io_error, positioned_io_result,
    protocol::{self, BUILD_ID_MAX_SIZE},
    scm_rights::ScmRightsExt,
    stallone_emergency_log, EpochNumber, PositionedErrnoResult, PositionedIOResult, StallonePID,
};

use crate::StalloneConfig;

pub(crate) struct GlobalState {
    pub(crate) socket: UnixDatagram,
    pub(crate) current_epoch_page: *const EpochNumber,
    pub(crate) base_path: PathBuf,
    pub(crate) config: StalloneConfig,
    pub(crate) thread_local_destructor_key: libc::pthread_key_t,
    // Once this cell is initialized, it should only ever be mutated inside of the pthread_atfork
    // child handler. Inside the child handler, the only thread that will be running is the child
    // thread, so it will be safe to mutate the contents of this UnsafeCell (which only contains POD).
    pub(crate) per_process: UnsafeCell<PerProcessGlobalState>,
}

/// This will get re-initialized on fork.
pub(crate) struct PerProcessGlobalState {
    pub(crate) stallone_pid: StallonePID,
    build_id: ArrayVec<u8, BUILD_ID_MAX_SIZE>,
    keepalive_stream: libc::c_int,
}

impl PerProcessGlobalState {
    #[cold]
    fn new(socket: &UnixDatagram) -> PositionedIOResult<Self> {
        let stallone_pid = Uuid::new_v4();
        let build_id = ArrayVec::try_from(crate::build_id::build_id()).unwrap_or(ArrayVec::new());
        let msg = protocol::Message::ProcessInfo(protocol::ProcessInfo {
            pid: std::process::id(),
            stallone_pid,
            parent_pid: None,
            build_id: build_id.clone(),
        });
        // We'll send the process start message now.
        // First, we create a STREAM socket pair that the master can use to see when this process dies.
        let (ours, masters) = positioned_io_result!(UnixStream::pair())?;
        positioned_io_result!(socket.sendmsg_file(&masters, &msg.serialize()[..]))?;
        Ok(PerProcessGlobalState {
            stallone_pid,
            build_id,
            keepalive_stream: ours.into_raw_fd(),
        })
    }

    #[cold]
    fn cleanup_in_fork(&mut self) {
        // Start by cleaning up the old state.
        unsafe {
            libc::close(self.keepalive_stream);
        }
        self.keepalive_stream = -1;
    }

    /// Update the per-process global state for a forked process.
    ///
    /// # Async-Signal Safety
    /// This function is async-signal safe.
    #[cold]
    fn fork(&mut self, socket: &UnixDatagram) -> PositionedErrnoResult<()> {
        self.cleanup_in_fork();
        // Now let's try populating the new state.
        let stallone_pid = {
            use uuid::{Builder, Variant, Version};
            let mut bytes = [0; 16];
            stallone_common::signal_safe_getrandom(&mut bytes)?;
            let mut b = Builder::from_bytes(bytes);
            b.set_variant(Variant::RFC4122).set_version(Version::Random);
            b.into_uuid()
        };
        let msg = protocol::Message::ProcessInfo(protocol::ProcessInfo {
            pid: std::process::id(),
            stallone_pid,
            parent_pid: Some(self.stallone_pid),
            build_id: self.build_id.clone(),
        });
        self.stallone_pid = stallone_pid;
        let mut sockets = [0 as libc::c_int; 2];
        if unsafe {
            // SAFETY: sockets is an array of two C integers.
            #[cfg(target_os = "macos")]
            const CLOSE_ON_EXEC: i32 = 0;
            #[cfg(target_os = "linux")]
            const CLOSE_ON_EXEC: i32 = libc::SOCK_CLOEXEC;
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | CLOSE_ON_EXEC,
                0,
                sockets.as_mut_ptr(),
            )
        } < 0
        {
            return Err(positioned_errno!(errno::errno().0));
        }
        self.keepalive_stream = sockets[0];
        socket
            .sendmsg_file_errno(
                &unsafe {
                    // SAFETY: The UnixStream will be the sole owner of the socket.
                    UnixStream::from_raw_fd(sockets[1])
                },
                &msg.serialize()[..],
            )
            .map_err(|e| positioned_errno!(e))?;
        #[cfg(target_os = "macos")]
        {
            let _ = scm_rights::set_close_on_exec(sockets[0]);
        }
        Ok(())
    }
}

static GLOBAL_STATE: AtomicPtr<GlobalState> = AtomicPtr::new(std::ptr::null_mut());
static GLOBAL_STATE_INIT_ONCE: Once = Once::new();

#[cold]
fn initialize_inner(base: &Path, config: &StalloneConfig) -> PositionedIOResult<()> {
    let socket = positioned_io_result!(UnixDatagram::unbound())?;
    positioned_io_result!(socket.connect(base.join(protocol::SOCKET_FILE_NAME)))?;
    // We can only set at microsecond resolution. If we try to set anything under a microsecond,
    // Rust will set it to a microsecond.
    positioned_io_result!(socket.set_write_timeout(Some(Duration::from_micros(2))))?;
    let epoch_file =
        positioned_io_result!(std::fs::File::open(base.join(protocol::EPOCH_FILE_NAME)))?;
    let current_epoch_page = unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            std::mem::size_of::<EpochNumber>(),
            libc::PROT_READ,
            libc::MAP_SHARED,
            epoch_file.as_raw_fd(),
            0,
        );
        if ptr == libc::MAP_FAILED {
            return Err(positioned_io_error!(std::io::Error::last_os_error()));
        }
        if ptr as usize % std::mem::align_of::<EpochNumber>() != 0 {
            return Err(positioned_io_error!(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Misaligned epoch: ptr={:X}", ptr as usize)
            )));
        }
        ptr as *const EpochNumber
    };
    let mut thread_local_destructor_key = 0;
    if unsafe {
        // SAFETY: the key pointer is only used for the duration of `pthread_key_create`, and it's
        // valid for that duration.
        // TODO: set the dtor
        libc::pthread_key_create(
            &mut thread_local_destructor_key,
            Some(crate::thread_local::thread_local_destructor),
        )
    } != 0
    {
        return Err(positioned_io_error!(std::io::Error::new(
            std::io::ErrorKind::Other,
            "unable to make pthread key"
        )));
    }
    let per_process = PerProcessGlobalState::new(&socket)?;
    let gs = GlobalState {
        socket,
        current_epoch_page,
        base_path: base.to_path_buf(),
        config: config.clone(),
        thread_local_destructor_key,
        per_process: UnsafeCell::new(per_process),
    };
    GLOBAL_STATE.store(Box::leak(Box::new(gs)), Ordering::Release);
    unsafe {
        libc::pthread_atfork(None, None, Some(fork_child_handler) /*child*/);
    }
    Ok(())
}

/// # Safety
/// This function should only be called from the `pthread_atfork` child handler.
/// # Async-Signal Safety
/// This function _MUST_ be async-signal safe, since it's the `pthread_atfork` `child` handler.
// NOTE: the name of this function is used by test_stallone.py
#[warn(unsafe_op_in_unsafe_fn)]
#[cold]
unsafe extern "C" fn fork_child_handler() {
    crate::thread_local::reset_thread_local();
    if let Some(gs) = get() {
        let per_process_state: &mut PerProcessGlobalState = unsafe {
            // SAFETY: since we're in the atfork handler, there can be no concurrent mutator, since
            // we're the only living thread. In addition, we never mutate the per_process values
            // outside of this function, so we know there wasn't a concurrent mutation in the parent
            // process that we need to contend with. (In addition, since per_process is just POD,
            // anyway, concurrent mutations wouldn't be a problem for us in a separate address space).
            &mut *gs.per_process.get()
        };
        if gs.config.follow_forks {
            if let Err(e) = per_process_state.fork(&gs.socket) {
                let _ = stallone_emergency_log(
                    &gs.base_path,
                    "making new per-process global state",
                    &e,
                );
                // This will disable stallone.
                GLOBAL_STATE.store(std::ptr::null_mut(), Ordering::Relaxed);
            }
        } else {
            per_process_state.cleanup_in_fork();
            // This will disable stallone.
            GLOBAL_STATE.store(std::ptr::null_mut(), Ordering::Relaxed);
        }
    }
}

/// Calling this function more than once will result in an "already initialized" error.
#[cold]
pub(crate) fn initialize(base: &Path, config: &StalloneConfig) -> PositionedIOResult<()> {
    let mut out = Err(positioned_io_error!(std::io::Error::new(
        std::io::ErrorKind::Other,
        "stallone already initialized"
    )));
    GLOBAL_STATE_INIT_ONCE.call_once(|| match initialize_inner(base, config) {
        Ok(()) => {
            out = Ok(());
        }
        Err(e) => {
            let msg = e.to_string();
            // TODO: we're using this API a little bit hackily (we're hard-coding an error number
            // of -1, and we're putting the message into the context).
            let _ = stallone_emergency_log(base, &msg, &positioned_errno!(-1));
            out = Err(e);
        }
    });
    out
}

/// # Async-Signal Safety
/// This function is async-signal safe.
#[inline(always)]
pub(crate) fn get() -> Option<&'static GlobalState> {
    let ptr = GLOBAL_STATE.load(Ordering::Acquire);
    if ptr == std::ptr::null_mut() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}
