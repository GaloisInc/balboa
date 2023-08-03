// This entire module needs to be signal-safe.
// TODO: this module is generally not treating EINTR specially. That's probably okay for now...

use std::path::Path;

use crate::{protocol, signal_safe_getrandom, PositionedErrno, PositionedErrnoResult};
use arrayvec::ArrayVec;
use std::fmt::Write;
use std::os::unix::ffi::OsStrExt;

// This name is used, exactly, in test_stallone.py
struct MiniFile(i32);
impl std::ops::Drop for MiniFile {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: nothing about this is unsafe.
            libc::close(self.0);
        }
    }
}
impl Write for MiniFile {
    fn write_str(&mut self, mut s: &str) -> std::fmt::Result {
        while !s.is_empty() {
            let delta = unsafe {
                // SAFETY: the buffer we provide is valid for the duration of the write call,
                // for the given length of bytes.
                libc::write(self.0, s.as_ptr() as *const _, s.len())
            };
            if delta < 0 {
                return Err(std::fmt::Error);
            }
            s = &s[delta as usize..];
        }
        Ok(())
    }
}

// This name is used, exactly, in test_stallone.py
struct ArrayVecWriter<'a, const N: usize>(&'a mut ArrayVec<u8, N>);
impl<'a, const N: usize> Write for ArrayVecWriter<'a, N> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0
            .try_extend_from_slice(s.as_bytes())
            .map_err(|_| std::fmt::Error)
    }
}

/// In the event that we're unable to start Stallone logging, we want to log that fact, but we don't
/// want to print to stderr. Instead, we'll write the message to a temporary file.
#[cold]
pub fn stallone_emergency_log(
    base_path: &Path,
    context: &str,
    error: &PositionedErrno,
) -> PositionedErrnoResult<()> {
    // NOTE: this function cannot use most of the Rust standard library's File I/O functions, since
    // they use std::io::Error which allocates.
    // TODO: PATH_MAX is aparently somewhat ill-defined.
    let mut path: ArrayVec<u8, { libc::PATH_MAX as usize + 1 }> = ArrayVec::new();
    path.try_extend_from_slice(base_path.as_os_str().as_bytes())
        .map_err(|_| positioned_errno!(libc::ENOMEM))?;
    if path.last().filter(|ch| **ch != b'/').is_some() {
        path.try_push(b'/')
            .map_err(|_| positioned_errno!(libc::ENOMEM))?;
    }
    let id = {
        let mut buf = [0; 16];
        signal_safe_getrandom(&mut buf)?;
        u128::from_ne_bytes(buf)
    };
    write!(
        ArrayVecWriter(&mut path),
        "{}/ELOG.{:X}.",
        protocol::EMERGENCY_LOG_DIRECTORY_NAME,
        id
    )
    .map_err(|_| positioned_errno!(libc::ENOMEM))?;
    path.try_push(b'\0')
        .map_err(|_| positioned_errno!(libc::ENOMEM))?; // Add the null terminator.
    let fd = unsafe {
        // SAFETY: path is null-terminated.
        libc::open(
            path.as_slice().as_ptr() as *const i8,
            libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
            0o666,
        )
    };
    if fd < 0 {
        return Err(positioned_errno!(errno::errno().0));
    }

    let mut fd = MiniFile(fd);
    if let Err(_) = write!(
        &mut fd,
        "PID: {}\n{}\n{}",
        std::process::id(),
        context,
        error
    ) {
        return Err(positioned_errno!(-1));
    }
    std::mem::drop(fd);
    let mut new_path = path.clone();
    new_path.pop(); // Remove the null terminator.
    new_path
        .try_extend_from_slice(&protocol::STALLONE_EMERGENCY_LOG_EXT.as_bytes())
        .map_err(|_| positioned_errno!(libc::ENOMEM))?;
    new_path
        .try_push(b'\0')
        .map_err(|_| positioned_errno!(libc::ENOMEM))?; // Add the null terminator.
    if unsafe {
        // SAFETY: both path and new_path are null terminated.
        libc::rename(path.as_ptr() as *const _, new_path.as_ptr() as *const _)
    } < 0
    {
        return Err(positioned_errno!(errno::errno().0));
    }
    Ok(())
}
