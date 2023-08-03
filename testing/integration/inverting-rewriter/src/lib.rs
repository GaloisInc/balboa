//! For testing purposes, we have a compressor/decompressor that invert every byte that they see.
//! This should help make sure that we safely mangle plaintexts

use balboa_compression::{CanPreviewPlaintextData, Compressor, Decompressor};

pub struct InvertingCompressor;
impl CanPreviewPlaintextData for InvertingCompressor {
    fn preview(&mut self, _buf: &[u8]) {}
}
impl Compressor for InvertingCompressor {
    fn compress(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = !*byte;
        }
    }
}

pub struct InvertingDecompressor;
impl CanPreviewPlaintextData for InvertingDecompressor {
    fn preview(&mut self, _buf: &[u8]) {}
}
impl Decompressor for InvertingDecompressor {
    fn decompress(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = !*byte;
        }
    }
}
