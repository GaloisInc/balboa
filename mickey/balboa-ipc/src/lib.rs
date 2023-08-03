//! This crate contains the datastructures and protocols for (mostly) lock-free communication
//! between mickey and balboa-injected processes.

#![deny(unused_must_use)]

#[macro_use]
mod u64_bitstruct;

pub mod chunk_allocator;
pub mod incoming;
pub mod outgoing;
pub mod types;
mod utils;
mod wire_protocol;

pub use chunk_allocator::CHUNK_SIZE;

pub mod balboa;
pub mod crypto;
