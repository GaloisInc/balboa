//! Functionality for shared library injection to intercept incoming / outgoing
//! traffic of a pre-existing application.

use balboa_rewriter::{IncomingRewriter, OutgoingRewriter};
use std::net::SocketAddr;

mod fd_state;
mod fd_table;
mod globals;
mod make_rewriters;
pub use make_rewriters::make_rewriters;

// These members should only be accessed by macros.
#[doc(hidden)]
pub mod inject;
#[doc(hidden)]
pub use globals::initialize_balboa_injection;
#[doc(hidden)]
pub mod libc_overrides;

// TODO: it'd be nice if there was a more elegant way of testing this.
// This is only public so that it can be used by an example for a test.
#[doc(hidden)]
pub mod stacks;

/// Customization entry point for a Balboa injection.
///
/// Core trait for intercepting incoming / outgoing data from a pre-existing
/// application.
pub trait BalboaInterceptors: 'static + Sync {
    /// If true, then set the `follow_forks` option in the stallone config.
    ///
    /// See [`stallone::StalloneConfig::follow_forks`]
    const STALLONE_FOLLOW_FORKS: bool = false;
    /// If true, allocate and run interceptors on a separate stack.
    ///
    /// You'll know this is neccessary if, after injection, the target process is crashing inside
    /// the injection, on a memory address which is right at the edge of the stack.
    const RUN_ON_CUSTOM_STACK: bool = false;

    /// Initialize any state needed for the interceptor.
    fn initialize() -> Self;

    /// Should Balboa rewrite connections `accept()`ed on `addr`?
    fn listen_on_addr(&self, addr: SocketAddr) -> bool {
        let _ = addr;
        false
    }

    /// Returns either the reading / writing rewriter that we will be using for
    /// a client connection, or `None` if no rewriter should be used.
    ///
    /// `remote` is the address of the peer wanting to connect.
    fn rewriters_for_tcp_client(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        let _ = remote;
        None
    }

    /// Returns either the reading / writing rewriter that we will be using for
    /// a server connection, or `None` if no rewriter should be used.
    fn rewriters_for_tcp_server(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        let _ = remote;
        None
    }
}
