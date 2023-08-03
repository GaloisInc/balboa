//! Traits for embedding covert data inside of plaintext streams.
//!
//! The Balboa rewriter will be provided [`Compressor`] and [`Decompressor`] values to process TLS
//! plaintext. On the outgoing side, the `compressor` will be provided with outgoing buffers to
//! insert covert data into. On the incoming side, the `decompressor` will be provided with
//! incoming buffers to extract covert data from, and replace with the original plaintext.
//!
//! When a compressor or decompressor is created, it will be given a [`CompressContext`] or a
//! [`DecompressContext`] which will allow the compressor or decompressor to interact with the
//! stream of covert data.
//!
//! # Coroutines
//!
//! Because compressors and decompressors are _stateful_ (they often need to track things like the
//! current position), it's often easier to write them using the [`balboa_coroutine`] library,
//! which can automate much of the state tracking. See the documentation on [`balboa_coroutine`]
//! for details.
//!
//! To help construct compressors and decompressors from coroutines, the
//! `new_coroutine_compressor` and `new_coroutine_decompressor` functions exist.

use balboa_coroutine;
use balboa_coroutine::{
    CoroutineBasedStreamRewriter, GenStateImmutable, PreviewingCoroutineBasedStreamRewriter,
    StreamCoroutineShouldNeverExit,
};
use std::future::Future;

// TODO: do we want to pass info about the TLS record size to these traits?
// TODO: use the type system to ensure that the preview method won't get called after compress()/decompress()
// ^ related to the same to-do in the balboa-coroutine library.
/// A type which which can `preview()` plaintext data going over the wire, before it can rewrite it
pub trait CanPreviewPlaintextData {
    /// Before covert signaling has occurred, the compressor can still observe the plaintext that's
    /// going over the wire (`buf`), so that it can keep track of state.
    /// WARNING: `preview()` MAY RECEIVE UNTRUSTED (incoming) DATA. In the presence of
    /// UNTRUSTED DATA, the only requirement is that it not crash
    /// (panic or DoS).
    ///
    /// # Panics
    /// This function can panic if it gets called after a call to `compress` or `decompress`.
    /// (Such a situation represents a logic fault in the program, rather than an issue which can
    /// be triggered by untrusted data.)
    fn preview(&mut self, buf: &[u8]);
}

/// The compressor rewrites _outgoing_ plaintext
pub trait Compressor: CanPreviewPlaintextData {
    /// Rewrite `buf` (a plaintext buffer) to insert outgoing covert data.
    fn compress(&mut self, buf: &mut [u8]);
}

/// The decompressor rewrites _incoming_ plaintext.
pub trait Decompressor: CanPreviewPlaintextData {
    /// Rewrite `buf` (a plaintext buffer) to replace incoming covert data with the original bytes.
    ///
    /// WARNING: `decompress()` MAY RECEIVE UNTRUSTED DATA. In the presence of
    /// UNTRUSTED DATA, the only requirement is that the decompressor not crash
    /// (panic or DoS). It's okay if it emits "wrong" bytes, or if its internal
    /// state gets messed up, since the Balboa framework will stop invoking the
    /// `decompress` function once an authentication check fails.
    fn decompress(&mut self, buf: &mut [u8]);
}

/// A compressor which does no rewriting.
pub struct NullCompressor;
impl Compressor for NullCompressor {
    fn compress(&mut self, _: &mut [u8]) {}
}
impl CanPreviewPlaintextData for NullCompressor {
    fn preview(&mut self, _buf: &[u8]) {}
}

/// A decompressor which does no rewriting.
pub struct NullDecompressor;
impl CanPreviewPlaintextData for NullDecompressor {
    fn preview(&mut self, _buf: &[u8]) {}
}
impl Decompressor for NullDecompressor {
    fn decompress(&mut self, _: &mut [u8]) {}
}

/// A handle to an outgoing covert data stream.
pub trait CompressContext {
    /// Fill `dst` with outgoing covert bytes to send to the peer
    fn recv_covert_bytes(&mut self, dst: &mut [u8]);
}
/// A handle to an incoming covert data stream
pub trait DecompressContext {
    /// Publish (to the local receiver) the `src` covert bytes received from the peer.
    fn send_covert_bytes(&mut self, src: &[u8]);
}

/// A [`CompressContext`] that does nothing.
pub struct NullCompressContext;
impl CompressContext for NullCompressContext {
    fn recv_covert_bytes(&mut self, _dst: &mut [u8]) {}
}

/// A [`DecompressContext`] that does nothing.
pub struct NullDecompressContext;
impl DecompressContext for NullDecompressContext {
    fn send_covert_bytes(&mut self, _src: &[u8]) {}
}

enum CoroutineInner {
    // This is an option so that we can move the Previewing out of it.
    Preview(Option<PreviewingCoroutineBasedStreamRewriter>),
    Mutating(CoroutineBasedStreamRewriter),
}
impl CanPreviewPlaintextData for CoroutineInner {
    fn preview(&mut self, buf: &[u8]) {
        match self {
            CoroutineInner::Preview(p) => p.as_mut().unwrap().preview(buf),
            CoroutineInner::Mutating(_) => panic!("Preview called after decompress"),
        }
    }
}
impl Decompressor for CoroutineInner {
    fn decompress(&mut self, buf: &mut [u8]) {
        if let CoroutineInner::Preview(p) = self {
            *self = CoroutineInner::Mutating(p.take().unwrap().into_mutable());
        }
        match self {
            CoroutineInner::Preview(_) => panic!("We just made this mutable!"),
            CoroutineInner::Mutating(m) => m.rewrite(buf),
        }
    }
}

impl Compressor for CoroutineInner {
    fn compress(&mut self, buf: &mut [u8]) {
        self.decompress(buf);
    }
}

/// Create a [`Decompressor`] (to rewrite _incoming_ data) which processes data using a
/// [`balboa_coroutine`].
///
/// `body` contains the [`balboa_coroutine`] which will be used to rewrite the plaintext stream.
///
/// # Security Warning
/// The decompression coroutine will operate on _unauthenticated data_. See the note on
/// [`Decompressor`] for more details.
pub fn new_coroutine_decompressor<
    F: Future<Output = StreamCoroutineShouldNeverExit> + Send + 'static,
>(
    body: impl (FnOnce(GenStateImmutable) -> F) + Send + 'static,
) -> Box<dyn Decompressor + Send + 'static> {
    Box::new(CoroutineInner::Preview(Some(
        PreviewingCoroutineBasedStreamRewriter::new(body),
    )))
}

/// Create a [`Compressor`] (to rewrite _outgoing_ data) which processes data using a
/// [`balboa_coroutine`].
///
/// `body` contains the [`balboa_coroutine`] which will be used to rewrite the plaintext stream.
pub fn new_coroutine_compressor<
    F: Future<Output = StreamCoroutineShouldNeverExit> + Send + 'static,
>(
    body: impl (FnOnce(GenStateImmutable) -> F) + Send + 'static,
) -> Box<dyn Compressor + Send + 'static> {
    Box::new(CoroutineInner::Preview(Some(
        PreviewingCoroutineBasedStreamRewriter::new(body),
    )))
}
