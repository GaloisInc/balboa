use balboa_compression::{Compressor, Decompressor};

/// An interface to unify the compressor and decompressor sides of the HTTP code.
pub(super) enum CompressorOrDecompressor {
    Compressor(Box<dyn Compressor + Send>),
    Decompressor(Box<dyn Decompressor + Send>),
}
impl From<Box<dyn Compressor + Send>> for CompressorOrDecompressor {
    fn from(x: Box<dyn Compressor + Send>) -> Self {
        CompressorOrDecompressor::Compressor(x)
    }
}
impl From<Box<dyn Decompressor + Send>> for CompressorOrDecompressor {
    fn from(x: Box<dyn Decompressor + Send>) -> Self {
        CompressorOrDecompressor::Decompressor(x)
    }
}
impl CompressorOrDecompressor {
    pub(super) fn preview(&mut self, buf: &[u8]) {
        match self {
            CompressorOrDecompressor::Compressor(x) => x.preview(buf),
            CompressorOrDecompressor::Decompressor(x) => x.preview(buf),
        }
    }
    pub(super) fn mutate(&mut self, buf: &mut [u8]) {
        match self {
            CompressorOrDecompressor::Compressor(x) => x.compress(buf),
            CompressorOrDecompressor::Decompressor(x) => x.decompress(buf),
        }
    }
}
