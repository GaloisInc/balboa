use stallone_common::{
    positioned_io_result, EpochNumber, PositionedIOResult, EPOCH_NUMBER_NUM_BITS,
};
use stallone_parsing::Timestamp;
use std::{
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub(crate) struct TimestampGenerator {
    timestamp_thread_should_exit: Arc<AtomicBool>,
    monotonic_start: Instant,
    epoch_ptr: Arc<EpochPointer>,
}

struct EpochPointer(*const EpochNumber);
unsafe impl Send for EpochPointer {}
unsafe impl Sync for EpochPointer {}
impl EpochPointer {
    fn new(epoch_file: &std::fs::File) -> PositionedIOResult<Self> {
        let ptr = unsafe {
            use std::os::unix::io::AsRawFd;
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<EpochNumber>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                epoch_file.as_raw_fd(),
                0,
            );
            if ptr == libc::MAP_FAILED {
                return positioned_io_result!(Err(std::io::Error::last_os_error()));
            }
            assert_eq!(ptr as usize % std::mem::align_of::<EpochNumber>(), 0);
            ptr as *const EpochNumber
        };
        Ok(EpochPointer(ptr))
    }
}
impl std::ops::Deref for EpochPointer {
    type Target = EpochNumber;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.0 }
    }
}
impl std::ops::Drop for EpochPointer {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.0 as *mut libc::c_void,
                std::mem::size_of::<EpochNumber>(),
            );
        }
    }
}

const SLEEP_DURATION: Duration = Duration::from_millis(10);

impl TimestampGenerator {
    fn timestamp_thread(
        start: Instant,
        should_exit: Arc<AtomicBool>,
        epoch_ptr: Arc<EpochPointer>,
    ) {
        while !should_exit.load(Ordering::Relaxed) {
            // This is an INEXACT sleep.
            std::thread::sleep(SLEEP_DURATION);
            let epoch = unsafe { &*epoch_ptr.0 };
            // We don't need to use an RMW instruction, since we're the only thread modifying the
            // epoch.
            let duration = start.elapsed();
            let millis = duration.as_millis();
            if millis < u128::from(1_u64 << EPOCH_NUMBER_NUM_BITS) {
                // TODO: see the epoch ordering question in `logimpl.rs`
                // We know this conversion doesn't truncate since EPOCH_NUMBER_NUM_BITS is a u64.
                epoch.store(millis as u64, Ordering::SeqCst);
            } else {
                log::warn!("Exhausted epoch bits at {:?}", duration);
                epoch.store((1 << EPOCH_NUMBER_NUM_BITS) - 1, Ordering::SeqCst);
                break;
            }
        }
        log::debug!("Exiting timestamp generator thread");
    }

    pub(crate) fn new(epoch_file: impl AsRef<Path>) -> PositionedIOResult<TimestampGenerator> {
        let mut epoch_file = positioned_io_result!(std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(epoch_file))?;
        positioned_io_result!(epoch_file.write_all(&[0; std::mem::size_of::<EpochNumber>()]))?;
        let timestamp_thread_should_exit = Arc::new(AtomicBool::new(false));
        let monotonic_start = Instant::now();
        let epoch_ptr = Arc::new(EpochPointer::new(&epoch_file)?);
        {
            let timestamp_thread_should_exit = timestamp_thread_should_exit.clone();
            let epoch_ptr = epoch_ptr.clone();
            std::thread::spawn(move || {
                Self::timestamp_thread(monotonic_start, timestamp_thread_should_exit, epoch_ptr)
            });
        }
        Ok(TimestampGenerator {
            timestamp_thread_should_exit,
            monotonic_start,
            epoch_ptr,
        })
    }

    pub(crate) fn current_epoch(&self) -> u64 {
        // This needs to be SeqCst, since we don't want any memory operations to be re-ordered with
        // respect to this load.
        self.epoch_ptr.load(Ordering::SeqCst)
    }

    pub(crate) fn generate(&self) -> Timestamp {
        Timestamp {
            epoch_ms: self.current_epoch(),
            monotonic: Instant::now() - self.monotonic_start,
            walltime: std::time::SystemTime::now(),
        }
    }
}

impl std::ops::Drop for TimestampGenerator {
    fn drop(&mut self) {
        self.timestamp_thread_should_exit
            .store(true, Ordering::Relaxed);
    }
}
