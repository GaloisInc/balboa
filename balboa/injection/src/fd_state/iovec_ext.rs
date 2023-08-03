//! Utility functions on `[libc::iovec]` slices.

use std::ops::Range;

pub(super) trait IoVecExt
where
    Self: AsRef<[libc::iovec]>,
{
    fn total_bytes(&self) -> usize {
        self.as_ref().iter().map(|x| x.iov_len).sum()
    }
    // TODO: the safety of these functions currently requires that the iovecs meet the requirements
    // for std::slice::from_raw_parts. Is this something that we want to assume in practice? In
    // particular, you could imagine that there's some sort of concurrent modification going on,
    // from another thread that might violate our safety requirements. I think, the "right" way to
    // do this is probably to use std::ptr::read (and friends) when interacting with the iovecs,
    // since they have weaker safety requirements.

    unsafe fn iterate_byte_slice(&self, mut f: impl FnMut(&[u8]) -> ()) {
        for x in self.as_ref().iter() {
            f(std::slice::from_raw_parts(
                x.iov_base as *const u8,
                x.iov_len,
            ));
        }
    }
    unsafe fn copy_from_iovec(&self, dst: &mut Vec<u8>, range: Range<usize>) {
        let start_idx = range.start;
        let end_idx = range.end;
        assert!(end_idx <= self.total_bytes());
        stallone::warn_assert!(start_idx <= end_idx);
        if end_idx < start_idx {
            return;
        }
        let mut pos = 0;
        self.iterate_byte_slice(|mut bytes| {
            if pos < start_idx {
                let to_skip = (start_idx - pos).min(bytes.len());
                bytes = &bytes[to_skip..];
                pos += to_skip;
            }
            if range.contains(&pos) {
                let to_take = (end_idx - pos).min(bytes.len());
                dst.extend_from_slice(&bytes[0..to_take]);
                pos += to_take;
            }
        });
    }

    /// Copy from `buffer` into `self`.
    ///
    /// # Panics
    /// This function will panic if there isn't enough room in `self` to store `buffer`'s contents.
    unsafe fn copy_from_contigous_buffer(&self, mut buffer: &[u8]) {
        for iovec in self.as_ref().iter() {
            let from_this_iovec = buffer.len().min(iovec.iov_len);
            std::slice::from_raw_parts_mut(iovec.iov_base as *mut u8, from_this_iovec)
                .copy_from_slice(&buffer[0..from_this_iovec]);
            buffer = &buffer[from_this_iovec..];
        }
        // This asserts that there aren't more bytes in the buffer than in the iovec.
        assert!(buffer.is_empty());
    }
}
impl IoVecExt for [libc::iovec] {}

#[test]
fn test_iterate_byte_slice() {
    let lens: Vec<usize> = vec![0, 10, 4, 8, 3, 8, 32, 8];
    assert!(lens.iter().cloned().sum::<usize>() < 255);
    let mut parts: Vec<Vec<u8>> = lens.iter().map(|l| vec![0; *l]).collect();
    for (dst, src) in parts.iter_mut().flatten().zip((0..255).into_iter()) {
        *dst = src;
    }
    let combined: Vec<u8> = parts.iter().flatten().cloned().collect();
    let iovec_vec: Vec<libc::iovec> = parts
        .iter()
        .map(|part| libc::iovec {
            iov_base: part.as_ptr() as *mut libc::c_void,
            iov_len: part.len(),
        })
        .collect();
    let iovec: &[libc::iovec] = &iovec_vec[..];
    for start in 0..combined.len() {
        for end in start..=combined.len() {
            let range = start..end;
            let mut dst = Vec::new();
            unsafe {
                iovec.copy_from_iovec(&mut dst, range.clone());
            }
            assert_eq!(&dst[..], &combined[range]);
        }
    }
}
