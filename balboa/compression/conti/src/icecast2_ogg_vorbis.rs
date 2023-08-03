//! Module for compressing and decompressing ogg-vorbis streams emitted by
//! `icecast` version 2.

mod compressor;
mod decompressor;
mod ogg_body_reader;
mod utils;
pub use compressor::new_compressor;
pub use decompressor::new_decompressor;
