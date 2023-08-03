//! You probably want to be looking at the `stallone` crate. This crate is used internally.

#![deny(unused_must_use)]

use crate::internal_metadata_structures::{LogRecordMetadataHash, ValueType};

pub mod const_siphash;
pub mod internal_ring_buffer;
mod loggable_metadata_impls;
pub mod protocol;
pub use scm_rights;

use crate::const_siphash::SipHash24;
pub use scm_rights::make_tmpfile;
use std::fmt::Debug;

/// A random number used to identify a particular process.
pub type StallonePID = uuid::Uuid;

/// An epoch is used for inter-thread and inter-process timing of log events.
///
/// The epoch's value is in milliseconds. It should never exceed `EPOCH_NUMBER_NUM_BITS` bits.
pub type EpochNumber = std::sync::atomic::AtomicU64;
/// The epoch would take about 8920 years to overflow with this many bits.
pub const EPOCH_NUMBER_NUM_BITS: u64 = 48;

/// An Error corresponding to an errno.
///
/// # Async-Signal Safety
/// This function does not have a destructor, and so can be created and destroyed within a signal
/// handler without invoking the memory allocator.
#[derive(Debug, Clone, Copy)]
pub struct PositionedErrno {
    pub file: &'static str,
    pub line: u32,
    pub column: u32,
    pub context: &'static str,
    pub errno: i32,
}
impl std::fmt::Display for PositionedErrno {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "At {}:{}:{}, {}: errno {}",
            self.file, self.line, self.column, self.context, self.errno
        )
    }
}
impl std::error::Error for PositionedErrno {}

#[macro_export]
macro_rules! positioned_errno {
    ($errno:expr$(, $context:expr)? $(,)?) => {{
        let context = "";
        let _ = context; // silence warning
        $(let context = $context;)?
        $crate::PositionedErrno {
            context,
            errno: $errno,
            file: file!(),
            line: line!(),
            column: column!(),
        }
    }};
}
pub type PositionedErrnoResult<T> = Result<T, PositionedErrno>;

/// This is a lighter-weight alternative to computing a backtrace for each error, and it's easier
/// than naming each possible IO error that we can see.
#[derive(Debug)]
pub struct PositionedIOError {
    pub error: std::io::Error,
    pub file: &'static str,
    pub line: u32,
    pub column: u32,
}
impl std::fmt::Display for PositionedIOError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "At {}:{}:{}, {}",
            self.file, self.line, self.column, self.error
        )
    }
}
impl std::error::Error for PositionedIOError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
pub type PositionedIOResult<T> = Result<T, PositionedIOError>;

#[macro_export]
macro_rules! positioned_io_error {
    ($error:expr) => {
        $crate::PositionedIOError {
            error: $error,
            file: file!(),
            line: line!(),
            column: column!(),
        }
    };
}

#[macro_export]
macro_rules! positioned_io_result {
    ($result:expr) => {
        $result.map_err(|e| $crate::positioned_io_error!(e))
    };
}

#[doc(hidden)]
pub mod internal_metadata_structures;

mod emergency_log;
pub use emergency_log::stallone_emergency_log;

/// This is an async-signal-safe getrandom function.
/// Prefer using the `getrandom` crate when async-signal safety is not needed.
// We can't use getrandom, since it sometimes takes a lock.
pub fn signal_safe_getrandom(mut dst: &mut [u8]) -> PositionedErrnoResult<()> {
    let fd = unsafe {
        // SAFETY: path is null-terminated.
        libc::open(
            b"/dev/urandom\0".as_ptr() as *const _,
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(positioned_errno!(errno::errno().0));
    }
    let mut out = Ok(());
    while !dst.is_empty() {
        let delta = unsafe {
            // SAFETY: dst.as_ptr() points to dst.len() bytes of a slice
            libc::read(fd, dst.as_ptr() as *mut _, dst.len())
        };
        if delta <= 0 {
            out = Err(positioned_errno!(errno::errno().0));
            break;
        }
        dst = &mut dst[delta as usize..];
    }
    unsafe {
        // SAFETY: there's nothing unsafe here.
        libc::close(fd);
    }
    out
}

/// An instance of this struct witnesses that `T` is Plain-Old Data, and it can be freely `memcpy`'d
/// into a buffer of bytes.
pub struct IsPod<T: ?Sized>(std::marker::PhantomData<T>);
impl<T> IsPod<T> {
    /// You probably don't want to call this function.
    ///
    /// Calling this function makes the following claims about `T`:
    /// # Safety
    /// 1. `T` is plain old data, and it can be `memcpy`'d into a bytebuffer
    /// 2. `T`'s byte representation is well-defined. This means that `T` (and all of its
    ///     fields/children) are either primitive (e.g. `u8`, but not `bool`), an array, or defined
    ///     with `#[repr(C)]` or `#[repr(transparent)]`.
    /// See [`bytemuck::Pod`](https://docs.rs/bytemuck/1.5.1/bytemuck/trait.Pod.html#Safety) for a
    /// more comprehensive list.
    // TODO: technically, is this actually unsafe? We only ever view a struct as bytes, not the
    // other way around. As a result, we the worst thing that could happen is that we get
    // meaningless bytes out, I think.
    pub const unsafe fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

/// A type that can be logged by stallone.
///
/// PLEASE DO NOT IMPLEMENT THIS TRAIT YOURSELF! Instead, use `#[derive(LoggableMetadata])`.
///
/// Recursive types cannot be logged (since they'll cause an infinite loop).
pub trait LoggableMetadata: Debug {
    /// A descriptor of the type `Self`.
    const TYPE_ID: ValueType<'static>;
    /// If this is `Some`, then `Self` satisfies all of the safety requirements of `IsPod`,
    /// `self.log_size() == std::mem::size_of::<Self>)`, and (on a little endian machine),
    /// `log_serialize` is equivalent to `memcpy`-ing `self`.
    const IS_POD: Option<IsPod<Self>> = None;

    // WARNING: if this structure can be atomically updated, then realize that the log_size might be
    // different than the size of the buffer passed to serialize.
    /// How many bytes do we need to serialize this value?
    fn log_size(&self) -> usize;
    /// Serialize this value into the given buffer. The buffer should be `self.log_self()` in length
    /// This needs to match the parsing algorithm in `stallone/parsing/parsing.rs`.
    fn log_serialize(&self, buf: &mut [u8]);
}

/// The level at which to log an event
#[repr(u8)]
#[derive(Copy, Eq, Debug, PartialOrd, Ord, PartialEq, Clone)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}
impl Level {
    const fn hash(&self, state: SipHash24) -> SipHash24 {
        state.update_u64(*self as u64)
    }
}

/// How many log levels are there?
pub const NUM_LEVELS: usize = 4;
/// An array consisting of all log levels.
pub const ALL_LEVELS: [Level; NUM_LEVELS] = [Level::Error, Level::Warn, Level::Info, Level::Debug];

#[test]
fn test_all_levels() {
    for (i, l) in ALL_LEVELS.iter().copied().enumerate() {
        assert_eq!(i, usize::from(l));
    }
}

impl From<Level> for usize {
    #[inline(always)]
    fn from(level: Level) -> usize {
        level as usize
    }
}
impl From<Level> for u8 {
    fn from(level: Level) -> Self {
        level as u8
    }
}

#[derive(Debug, Copy, Clone)]
pub struct IllegalLevelByte(pub u8);
impl std::fmt::Display for IllegalLevelByte {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:02X} is not a legal level byte", self.0)
    }
}
impl std::error::Error for IllegalLevelByte {}

impl TryFrom<u8> for Level {
    type Error = IllegalLevelByte;

    fn try_from(value: u8) -> Result<Self, IllegalLevelByte> {
        match value {
            0 => Ok(Self::Error),
            1 => Ok(Self::Warn),
            2 => Ok(Self::Info),
            3 => Ok(Self::Debug),
            _ => Err(IllegalLevelByte(value)),
        }
    }
}

/// (Internal only) The header of a log record as its stored in the ring buffer before the master
/// process drains it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRecordHeader {
    /// The log level of the record (2 bits)
    pub level: Level,
    /// The number of bytes in the record body (ignoring this header's size) (14 bits)
    pub length: usize,
    /// The current epoch (48/`EPOCH_NUMBER_NUM_BITS` bits). This is an approximate measure of the
    /// number of milliseconds since the Stallone master first launched.
    pub epoch_ms: u64,
    /// The hash value used to identify the log record schema. (64 bits)
    pub log_record_type: LogRecordMetadataHash,
}

impl LogRecordHeader {
    /// The maximum possible length of a log record
    pub const LENGTH_MAX: usize = (1 << 14) - 1;
}

impl From<LogRecordHeader> for u128 {
    #[inline(always)]
    fn from(hdr: LogRecordHeader) -> Self {
        // Keep the epoch and length in the lower 64-bits of the output, so that no dynamic values
        // need to straddle the upper or lower words of the log record header.
        debug_assert!(hdr.length <= LogRecordHeader::LENGTH_MAX);
        debug_assert!(hdr.epoch_ms < 1 << EPOCH_NUMBER_NUM_BITS);
        (hdr.length as u128)
            | ((hdr.epoch_ms as u128) << 14)
            | ((hdr.level as u128) << 62)
            | ((hdr.log_record_type.schema_hash as u128) << 64)
    }
}

impl From<u128> for LogRecordHeader {
    fn from(bits: u128) -> Self {
        LogRecordHeader {
            level: Level::try_from(((bits >> 62) as u8) & 0b11)
                .expect("the & means there are no invalid values"),
            length: (bits & (LogRecordHeader::LENGTH_MAX as u128)) as usize,
            epoch_ms: ((bits >> 14) as u64) & ((1 << EPOCH_NUMBER_NUM_BITS) - 1),
            log_record_type: LogRecordMetadataHash {
                schema_hash: (bits >> 64) as u64,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn encode_decode_log_record_header(
            length in any::<usize>(),
            epoch_ms in 0_u64..((1 << EPOCH_NUMBER_NUM_BITS) - 1),
            level in any::<u8>(),
            schema_hash in any::<u64>(),
        ) {
            let hdr = LogRecordHeader {
                length: LogRecordHeader::LENGTH_MAX & length,
                epoch_ms,
                level: Level::try_from(level & 0b11).unwrap(),
                log_record_type: LogRecordMetadataHash {
                    schema_hash,
                },
            };
            let encoded = u128::from(hdr);
            prop_assert_eq!(LogRecordHeader::from(encoded), hdr);
        }
    }
}
