//! Crate for rewriting TLS records.

#![deny(unused_must_use)]
#[allow(unused_imports)]
use crate as balboa_rewriter;

use stallone::LoggableMetadata;

pub mod read_state;
pub mod sslkeylogfile;
pub mod tls;
pub mod tls_rewriter;

pub trait OutgoingRewriter {
    fn outgoing_rewrite(&mut self, buf: &mut [u8]);
}

pub trait IncomingRewriter {
    fn incoming_rewrite(&mut self, buf: &mut [u8]) -> StreamChangeData;
}

pub struct NullRewriter;
impl OutgoingRewriter for NullRewriter {
    fn outgoing_rewrite(&mut self, _buf: &mut [u8]) {}
}
impl IncomingRewriter for NullRewriter {
    fn incoming_rewrite(&mut self, _buf: &mut [u8]) -> StreamChangeData {
        StreamChangeData::default()
    }
}

/// All indices are in terms of original positions.
///
/// It should always be the case that the index of `add_byte` is less than the index of
/// `remove_byte`.
#[derive(Clone, Copy, Debug, Default, PartialEq, LoggableMetadata)]
pub struct StreamChangeData {
    pub add_byte: Option<(usize, u8)>,
    pub remove_byte: Option<usize>,
}

/// Retrieve a mutable reference to a `StreamChangeData` object. We need this trait since the
/// `mangle_application_data` function is generic over values yielded by a coroutine, and we need
/// access to the concrete `StreamChangeData` type in certain cases when calling that function.
/// This trait should be implemented for all types which can be yielded by the `GenStateImmutable`
/// coroutine.
pub trait GetStreamChangeData {
    fn get_stream_change_data(&mut self) -> Option<&mut StreamChangeData>;
}

impl GetStreamChangeData for StreamChangeData {
    fn get_stream_change_data(&mut self) -> Option<&mut StreamChangeData> {
        Some(self)
    }
}

impl GetStreamChangeData for () {
    fn get_stream_change_data(&mut self) -> Option<&mut StreamChangeData> {
        None
    }
}
