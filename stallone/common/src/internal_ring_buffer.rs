//! This is a multi-process implementation of a [Bip Buffer](https://web.archive.org/web/20200211194501/https://www.codeproject.com/articles/3479/the-bip-buffer-the-circular-buffer-with-a-twist)
//!
//! This module implements a SPSC (Single Producer Single Consumer) inter-process bip buffer. A bip
//! buffer is a "ring buffer with a twist." The "twist" is that we can reserve continuous chunks of
//! bytes. If, for example, we want to reserve 5 bytes, but there are only 2 bytes left in the ring
//! buffer before we'd wrap around, we'd discard the remaining 2 bytes, and wrap-around early to
//! make sure that we get a continous reservation (which doesn't need to wrap around internally).
//!
//! This is based on https://github.com/utaal/spsc-bip-buffer/blob/32342b38984d28abb2f61125900ca2b3e94e777f/src/lib.rs
//! That code is MIT/Apache dual-licensed.

use super::NUM_LEVELS;
use crate::{
    positioned_errno, positioned_io_result, Level, LogRecordHeader, PositionedErrnoResult,
    PositionedIOResult, ALL_LEVELS,
};
use errno::errno;
use std::fs::File;
use std::os::unix::prelude::AsRawFd;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

pub const MIN_PAYLOAD_SIZE: usize = 1024;

/// The fields that the writer will store into.
///
/// This is 64-byte aligned so that it's cache-aligned to prevent False Sharing
/// (with `ReaderStored`).
/// This is `repr(C)` so that it's POD, since we mmap it.
#[repr(C, align(64))]
struct WriterStored {
    write: AtomicUsize,
    last: AtomicUsize,
    dropped_log_events: [AtomicU64; NUM_LEVELS],
}

/// The fields that the reader will store.
///
/// This is 64-byte aligned so that it's cache-aligned to prevent False Sharing
/// (with `WriterStored`).
/// This is `repr(C)` so that it's POD, since we mmap it.
#[repr(C, align(64))]
struct ReaderStored {
    read: AtomicUsize,
    // This is the lengths of reservations made at each log level.
    acknowledged_sizes_per_level: [AtomicU64; NUM_LEVELS],
}

#[repr(C)]
struct SharedLogPageHeader {
    // NOTE: this should just be POD.
    // All members of this struct MUST BE VALID when filled with zeros.
    // log_level_capacities should be first, since we want to initialize it with the file API.
    log_level_capacities: [u64; NUM_LEVELS],
    // 0 is alive. 1 is dead.
    thread_is_dead: AtomicU8,
    writer_stored: WriterStored,
    reader_stored: ReaderStored,
}

/// A handle which points to shared log page which we can fill with log records.
pub struct SharedLogPageHandle {
    header: *const SharedLogPageHeader,
    payload_size: usize,
}

impl SharedLogPageHandle {
    // TODO: is this function actually unsafe? I can't think of any safety requirements it actually
    // has.
    /// This function is async-signal safe.
    unsafe fn new_from_initialized_file(file: &std::fs::File) -> PositionedErrnoResult<Self> {
        let file_len = {
            let rc = libc::lseek(file.as_raw_fd(), 0, libc::SEEK_END);
            if rc < 0 {
                return Err(positioned_errno!(errno().0));
            }
            rc as u64
        };
        if file_len < (std::mem::size_of::<SharedLogPageHeader>() + MIN_PAYLOAD_SIZE) as u64 {
            return Err(positioned_errno!(-1, "stallone file too small"));
        }
        let file_len = usize::try_from(file_len)
            .map_err(|_| positioned_errno!(-1, "stallone file too big"))?;
        // It's okay if f is close()d when this function returns. mmap() will increment the refcount
        #[cfg(not(target_os = "linux"))]
        const MAP_POPULATE: libc::c_int = 0;
        // Let's talk about MAP_POPULATE.
        // MAP_POPULATE will cause the kernel to "Populate (prefault) page tables for a mapping."
        // This makes stallone perform better on benchmarks, since it means that no page faulting is
        // required during the run of the benchmark. However, this makes initialization much slower.
        // As a result, for now, we'll take the hit on the per-log cost (which should be minimal
        // once the buffer wraps around anyway), to reduce the initialization time (which is on the
        // order of 0.5 seconds or more, depending on the buffer size).
        // TODO: investigate large/huge pages as a way to increase performance without having the
        // long initialization cost.
        #[cfg(target_os = "linux")]
        const MAP_POPULATE: libc::c_int = 0; //libc::MAP_POPULATE;
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            file_len,
            libc::PROT_WRITE | libc::PROT_READ,
            libc::MAP_SHARED | MAP_POPULATE,
            file.as_raw_fd(),
            0,
        );
        if ptr == libc::MAP_FAILED {
            return Err(positioned_errno!(errno().0));
        }
        Ok(SharedLogPageHandle {
            header: ptr as *const SharedLogPageHeader,
            payload_size: file_len - std::mem::size_of::<SharedLogPageHeader>(),
        })
    }

    // We can't return a mutable slice, since that'd imply we have exclusive ownership over the
    // entire slice, and that's not always true.
    #[inline(always)]
    fn payload(&self) -> *mut u8 {
        unsafe {
            // SAFETY: this won't reach outside the mmap allocation, and it won't wrap, since the
            // mmap'd buffer is large enough to contain the header and payload.
            (self.header as *mut SharedLogPageHeader).offset(1) as *mut u8
        }
    }

    #[inline(always)]
    fn header<'a>(&'a self) -> &'a SharedLogPageHeader {
        unsafe { &*self.header }
    }
}

impl Drop for SharedLogPageHandle {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.header as *mut libc::c_void,
                std::mem::size_of::<SharedLogPageHeader>() + self.payload_size,
            );
        }
    }
}

/// Given an empty file, initialize it so that it's primed for a buffer of a given size, and
/// configured so that the given log level capacities will be respected.
/// # Signal-Safety
/// This function should be signal-safe.
pub fn initialize_file(
    file: &mut std::fs::File,
    buffer_size: usize,
    log_level_capacities: &[u64; NUM_LEVELS],
) -> PositionedErrnoResult<()> {
    assert!(buffer_size >= MIN_PAYLOAD_SIZE);
    let mut buf = [0; NUM_LEVELS * 8];
    // Write the log_level_capacities.
    for (dst, src) in buf.chunks_exact_mut(8).zip(log_level_capacities.iter()) {
        dst.copy_from_slice(&src.to_ne_bytes());
    }
    let mut buf: &[u8] = &buf;
    while !buf.is_empty() {
        let rc = unsafe {
            // SAFETY: buf is valid
            libc::write(file.as_raw_fd(), buf.as_ptr() as *const _, buf.len())
        };
        if rc < 0 {
            return Err(positioned_errno!(errno::errno().0));
        }
        buf = &buf[rc as usize..];
    }
    // This zeroes the rest of the bytes of the file.
    let rc = unsafe {
        // SAFETY: this should be safe
        libc::ftruncate(
            file.as_raw_fd(),
            (std::mem::size_of::<SharedLogPageHeader>() + buffer_size) as i64,
        )
    };
    if rc < 0 {
        return Err(positioned_errno!(errno::errno().0));
    }
    let rc = unsafe {
        // SAFETY: this should be safe
        libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET)
    };
    if rc < 0 {
        return Err(positioned_errno!(errno::errno().0));
    }
    Ok(())
}

pub struct Reader {
    handle: SharedLogPageHandle,
    read: usize,
    priv_write: usize,
    priv_last: usize,
    priv_acknowledged_sizes_per_level: [u64; NUM_LEVELS],
}

unsafe impl std::marker::Send for Reader {}

#[derive(Debug, Clone, Copy)]
pub enum LogRecordReadError {
    NotEnoughBytesForLogRecordHeader { actual: usize },
    NotEnoughBytesForLogRecordBody { actual: usize, needed: usize },
}
impl std::fmt::Display for LogRecordReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for LogRecordReadError {}

impl Reader {
    /// Initialize a reader from a file.
    ///
    /// # Safety
    /// There must be no other `Reader`s for this file.
    pub unsafe fn new(f: &File) -> PositionedIOResult<Reader> {
        let handle = positioned_io_result!(SharedLogPageHandle::new_from_initialized_file(f)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        let priv_last = handle.payload_size;
        Ok(Reader {
            handle,
            read: 0,
            priv_write: 0,
            priv_last,
            priv_acknowledged_sizes_per_level: [0; NUM_LEVELS],
        })
    }

    /// Is this thread dead.
    pub fn is_dead(&self) -> bool {
        self.handle.header().thread_is_dead.load(Ordering::Acquire) != 0
    }

    pub fn sample_dropped_events(&self) -> [u64; NUM_LEVELS] {
        let mut out = [0; NUM_LEVELS];
        for (dst, src) in out
            .iter_mut()
            .zip(self.handle.header().writer_stored.dropped_log_events.iter())
        {
            *dst = src.load(Ordering::Relaxed);
        }
        out
    }

    pub fn read_log_records<F>(
        &mut self,
        mut max_to_read: usize,
        mut log_record: F,
    ) -> Result<(), LogRecordReadError>
    where
        for<'a> F: FnMut(LogRecordHeader, &'a [u8]),
    {
        let mut buf = self.valid();
        let mut consumed = 0;
        let mut read_for_level = [0; NUM_LEVELS];
        while !buf.is_empty() && max_to_read > 0 {
            if buf.len() < 16 {
                return Err(LogRecordReadError::NotEnoughBytesForLogRecordHeader {
                    actual: buf.len(),
                });
            }
            let mut hdr_bytes = [0; 16];
            hdr_bytes.copy_from_slice(&buf[0..16]);
            buf = &buf[16..];
            let hdr = LogRecordHeader::from(u128::from_ne_bytes(hdr_bytes));
            read_for_level[usize::from(hdr.level)] += 16 + hdr.length as u64;
            if buf.len() < hdr.length {
                return Err(LogRecordReadError::NotEnoughBytesForLogRecordBody {
                    actual: buf.len(),
                    needed: hdr.length,
                });
            }
            log_record(hdr, &buf[0..hdr.length]);
            buf = &buf[hdr.length..];
            consumed += 16 + hdr.length;
            max_to_read -= 1;
        }
        self.consume(consumed);
        debug_assert_eq!(consumed as u64, read_for_level.iter().cloned().sum());
        for (level, read) in ALL_LEVELS
            .iter()
            .cloned()
            .zip(read_for_level.iter().cloned())
        {
            if read > 0 {
                self.advance_read_for_level(level, read);
            }
        }
        Ok(())
    }

    // amount should include the header size.
    fn advance_read_for_level(&mut self, level: Level, amount: u64) {
        self.priv_acknowledged_sizes_per_level[usize::from(level)] += amount;
        self.handle
            .header()
            .reader_stored
            .acknowledged_sizes_per_level[usize::from(level)]
        .store(
            self.priv_acknowledged_sizes_per_level[usize::from(level)],
            Ordering::Relaxed,
        );
    }

    fn valid<'a>(&'a mut self) -> &'a [u8] {
        loop {
            self.priv_write = self
                .handle
                .header()
                .writer_stored
                .write
                .load(Ordering::Acquire);

            break if self.priv_write >= self.read {
                unsafe {
                    std::slice::from_raw_parts(
                        self.handle.payload().add(self.read),
                        self.priv_write - self.read,
                    )
                }
            } else {
                self.priv_last = self
                    .handle
                    .header()
                    .writer_stored
                    .last
                    .load(Ordering::Relaxed);
                if self.read == self.priv_last {
                    self.read = 0;
                    continue;
                }
                unsafe {
                    std::slice::from_raw_parts(
                        self.handle.payload().add(self.read),
                        self.priv_last - self.read,
                    )
                }
            };
        }
    }

    /// Consumes the first `len` bytes in `valid`. This marks them as read and they won't be
    /// included in the slice returned by the next invocation of `valid`. This is used to
    /// communicate the reader's progress and free buffer space for future writes.
    fn consume(&mut self, len: usize) -> bool {
        if self.priv_write >= self.read {
            if len <= self.priv_write - self.read {
                self.read += len;
            } else {
                return false;
            }
        } else {
            let remaining = self.priv_last - self.read;
            if len == remaining {
                self.read = 0;
            } else if len <= remaining {
                self.read += len;
            } else {
                return false;
            }
        }
        self.handle
            .header()
            .reader_stored
            .read
            .store(self.read, Ordering::Release);
        true
    }
}

#[derive(Clone, Copy)]
struct LevelSizes {
    sent: u64,
    acknowledged: u64,
}
impl LevelSizes {
    /// How many bytes have been sent that haven't been acknowledged?
    fn pending(&self) -> u64 {
        self.sent - self.acknowledged
    }
}

pub struct Writer {
    handle: SharedLogPageHandle,
    write: usize,
    last: usize,
    sizes_per_level: [LevelSizes; NUM_LEVELS],
}

unsafe impl std::marker::Send for Writer {}

struct PendingReservation {
    start: usize,
    len: usize,
    wraparound: bool,
}

impl Writer {
    /// Create a new writer from an initialized file.
    ///
    /// # Signal-Safety
    /// This function should be signal-safe.
    /// # Safety
    /// There should be no other writers.
    pub unsafe fn new(f: &File) -> PositionedErrnoResult<Self> {
        let handle = SharedLogPageHandle::new_from_initialized_file(f)?;
        let last = handle.payload_size;
        Ok(Writer {
            handle,
            write: 0,
            last,
            sizes_per_level: [LevelSizes {
                sent: 0,
                acknowledged: 0,
            }; NUM_LEVELS],
        })
    }

    pub fn mark_thread_dead(&mut self) {
        self.handle
            .header()
            .thread_is_dead
            .store(1, Ordering::Release);
    }

    fn log_event_dropped(&mut self, level: Level) {
        // We use an RMW instruction here since, if the log event is dropped, the atomic add is
        // still faster than actually writing the log event (so a slight extra delay over performing
        // a local addition and then a store is minimal). Reducing the size of the writer state
        // means it takes up fewer cache lines, which should speed things up.
        self.handle.header().writer_stored.dropped_log_events[usize::from(level)]
            .fetch_add(1, Ordering::Release);
        // TODO: I think we need a fence here to synchronize the addition with the epoch word.
    }

    // TODO: should this be #[inline(never)]? Or should the fast case be inlined?
    fn get_pending_reservation(&mut self, header: LogRecordHeader) -> Option<PendingReservation> {
        debug_assert!(header.length <= LogRecordHeader::LENGTH_MAX);
        let sizes = &mut self.sizes_per_level[usize::from(header.level)];
        let capacity = self.handle.header().log_level_capacities[usize::from(header.level)];
        let len = header.length + 16;
        if sizes.pending() + (len as u64) > capacity {
            sizes.acknowledged = self
                .handle
                .header()
                .reader_stored
                .acknowledged_sizes_per_level[usize::from(header.level)]
            .load(Ordering::Relaxed);
        }
        if sizes.pending() + (len as u64) > capacity {
            None
        } else {
            let read = self
                .handle
                .header()
                .reader_stored
                .read
                .load(Ordering::Acquire);
            if self.write >= read {
                if self.handle.payload_size.saturating_sub(self.write) >= len {
                    Some(PendingReservation {
                        start: self.write,
                        len,
                        wraparound: false,
                    })
                } else {
                    if read.saturating_sub(1) >= len {
                        Some(PendingReservation {
                            start: 0,
                            len,
                            wraparound: true,
                        })
                    } else {
                        None
                    }
                }
            } else {
                if (read - self.write).saturating_sub(1) >= len {
                    Some(PendingReservation {
                        start: self.write,
                        len,
                        wraparound: false,
                    })
                } else {
                    None
                }
            }
        }
    }

    #[inline(always)]
    pub fn write<F>(&mut self, header: LogRecordHeader, write_body: F)
    where
        for<'a> F: FnOnce(&'a mut [u8]),
    {
        if let Some(r) = self.get_pending_reservation(header) {
            debug_assert!(r.start + r.len < self.handle.payload_size);
            {
                let full_body = unsafe {
                    std::slice::from_raw_parts_mut(self.handle.payload().add(r.start), r.len)
                };
                full_body[0..16].copy_from_slice(&u128::from(header).to_ne_bytes());
                write_body(&mut full_body[16..]);
            }
            if r.wraparound {
                self.handle
                    .header()
                    .writer_stored
                    .last
                    .store(self.write, Ordering::Relaxed);
                self.write = 0;
            }
            self.write += r.len;
            if self.write > self.last {
                self.last = self.write;
                self.handle
                    .header()
                    .writer_stored
                    .last
                    .store(self.last, Ordering::Relaxed);
            }
            self.handle
                .header()
                .writer_stored
                .write
                .store(self.write, Ordering::Release);
            let sizes = &mut self.sizes_per_level[usize::from(header.level)];
            sizes.sent += 16 + header.length as u64;
        } else {
            self.log_event_dropped(header.level);
        }
    }
}
