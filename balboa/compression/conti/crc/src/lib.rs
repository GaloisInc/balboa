#[cfg(all(
    target_arch = "x86_64",
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1"
))]
mod hwaccel {
    use parking_lot::Once;
    #[allow(dead_code)]
    extern "C" {
        fn balboa_conti_crc_CRCInit();
        fn balboa_conti_crc_compute_the_crc(start: u32, data: *const u8, len: u32) -> u32;
        fn balboa_conti_crc_compute_the_crc_lut(start: u32, data: *const u8, len: u32) -> u32;
    }
    // TODO: if we can specify an old CRC to extend, then we'll be able to save memory.
    // Unfortunately, while that works with the LUT function, it doesn't work with the
    // hardware accelerated version. We'll just suck it up and memcpy for now.
    pub fn compute(buf: &[u8]) -> u32 {
        let start = 0;
        static INIT: Once = Once::new();
        INIT.call_once(|| unsafe {
            balboa_conti_crc_CRCInit();
        });
        let size = u32::try_from(buf.len()).expect("buffer too big for crc32");
        unsafe { balboa_conti_crc_compute_the_crc(start, buf.as_ptr(), size) }
    }
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1"
))]
pub use hwaccel::compute;

#[cfg(not(all(
    target_arch = "x86_64",
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "sse4.1"
)))]
pub fn compute(buf: &[u8]) -> u32 {
    baseline::vorbis_crc32_update(0, buf)
}

#[cfg(test)]
use proptest::prelude::*;

#[cfg(any(test, not(target_arch = "x86_64")))]
mod baseline;

#[cfg(test)]
proptest! {
    #[test]
    fn test_matches_baseline(buf in any::<Vec<u8>>()) {
        let bl = baseline::vorbis_crc32_update(0, &buf[..]);
        let actual = compute(&buf[..]);
        prop_assert_eq!(bl, actual);
    }
}
