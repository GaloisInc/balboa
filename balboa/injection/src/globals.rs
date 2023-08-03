//! Global variables used in the Baloba injection.
//!
//! Ordinarily, it's a faux-pas to use global variables. In this case, though, it's justified!
//! Balboa needs to store state about which file descriptors to inject over, as well as
//! what state is needed to manipulate these file descriptors. This state is global to the process,
//! because the kernel's file descriptor table is global to the process. Thus, we need to use
//! global variables here, too.

use balboa_rewriter::{IncomingRewriter, OutgoingRewriter};

use crate::{fd_table, BalboaInterceptors};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub(crate) static BALBOA_IS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static BALBOA_IS_INITIALIZING: AtomicBool = AtomicBool::new(false);

/// We can't turn [`BalboaInterceptors`] into `dyn`, so we have an object-safe variant which can be
/// `dyn`.
pub(crate) trait ObjectSafeBalboaInterceptors: 'static + Sync {
    fn listen_on_addr(&self, addr: SocketAddr) -> bool;
    fn rewriters_for_tcp_client(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )>;
    fn rewriters_for_tcp_server(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )>;
}

/// The concrete object-safe wrapper for [`BalboaInterceptors`]
pub(crate) struct ObjectSafeBalboaInterceptorsAdapter<BI: BalboaInterceptors>(pub(crate) BI);

impl<BI: BalboaInterceptors> ObjectSafeBalboaInterceptors
    for ObjectSafeBalboaInterceptorsAdapter<BI>
{
    fn listen_on_addr(&self, addr: SocketAddr) -> bool {
        self.0.listen_on_addr(addr)
    }

    fn rewriters_for_tcp_client(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        self.0.rewriters_for_tcp_client(remote)
    }

    fn rewriters_for_tcp_server(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        self.0.rewriters_for_tcp_server(remote)
    }
}

/// The [`BalboaInterceptors`] that's been set up for this process.
///
/// Since this is a `static mut` any access to it is inherently unsafe. If `BALBOA_IS_INITIALIZED` is
/// true, then this means that BALBOA_INTERCEPTORS has been set (to `Some`), and its value should
/// never change during the run of the program.
static mut BALBOA_INTERCEPTORS: Option<Box<dyn ObjectSafeBalboaInterceptors + Sync>> = None;

/// # Safety
/// `BALBOA_IS_INITIALIZED` might not be `true` yet. When `BALBOA_IS_INITIALIZED` is set to `true`,
/// that must occur with a `Release` (or stronger) ordering.
///
/// This function can be called from only one thread at once.
#[cold]
#[warn(unsafe_op_in_unsafe_fn)]
unsafe fn set_balboa_interceptors<BI: BalboaInterceptors>(bi: BI) {
    let bi = Box::new(ObjectSafeBalboaInterceptorsAdapter(bi));
    unsafe {
        // SAFETY: `BALBOA_IS_INITIALIZED` is not yet true. Therefore there are no concurrent
        // accesses.
        BALBOA_INTERCEPTORS = Some(bi);
    }
}

/// Load a reference to the Balboa interceptors.
///
/// # Panics
/// This function will panic if [`BALBOA_IS_INITIALIZED`] isn't `true`.
#[inline]
pub(crate) fn balboa_interceptors() -> &'static dyn ObjectSafeBalboaInterceptors {
    assert!(BALBOA_IS_INITIALIZED.load(Ordering::Acquire));
    unsafe {
        // SAFETY: BALBOA_IS_INITIALIZED is true. Once BALBOA_IS_INITIALIZED becomes true, we
        // guarantee that the BALBOA_INTERCEPTORS will not be mutated.
        BALBOA_INTERCEPTORS.as_ref()
    }
    .expect("balboa has been initialized")
    .as_ref()
}

/// When the env var `BALBOA_BIND_CLIENT_IP_BEFORE_CONNECT` is set to an IPv4 address, then this
/// variable will be populated with the IPv4 address of the environment variable.
/// The `BALBOA_BIND_CLIENT_IP_BEFORE_CONNECT` env var is used to simulate multiple machines during
/// tests. When it's set, and when the process attempts to connect to `127.0.0.0/8`, the injection
/// will bind the outgoing socket to `BALBOA_BIND_CLIENT_IP_BEFORE_CONNECT` before connecting. The
/// injection will also disable TCP fast open in this case. This will make it appear to the
/// the recipient as if the IP address that initiated the connection was `BALBOA_BIND_CLIENT_IP_BEFORE_CONNECT`
pub(crate) static BIND_IP_PRE_CONNECT: AtomicU32 = AtomicU32::new(BIND_IP_PRE_CONNECT_EMPTY);

/// The value which signifies that no `bind()` should occur before a `connect()`.
pub(crate) const BIND_IP_PRE_CONNECT_EMPTY: u32 = 0;

#[cold]
fn setup_panic_handler() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::abort();
    }));
}

/// # Panics
/// This function will panic if it's called more than once.
#[cold]
pub fn initialize_balboa_injection<BI: BalboaInterceptors>() {
    if BALBOA_IS_INITIALIZED.load(Ordering::Acquire) {
        panic!("Balboa was already initialized!");
    }
    if BALBOA_IS_INITIALIZING.swap(true, Ordering::Relaxed) {
        panic!("Balboa has already begun initializing!");
    }
    setup_panic_handler(); // Do this FIRST!
    fd_table::initialize();
    stallone::initialize(stallone::StalloneConfig {
        follow_forks: BI::STALLONE_FOLLOW_FORKS,
        ..Default::default()
    });
    // This is synchronized by the Once surrounding the initialization, so this can be Relaxed.
    BIND_IP_PRE_CONNECT.store(
        if let Some(ip) = std::env::var("BALBOA_BIND_CLIENT_IP_BEFORE_CONNECT")
            .ok()
            .and_then(|x| Ipv4Addr::from_str(&x).ok())
        {
            let bits = u32::from(ip);
            if bits == BIND_IP_PRE_CONNECT_EMPTY {
                eprintln!("BALBOA_BIND_CLIENT_IP_BEFORE_CONNECT ignored since it's '0.0.0.0'");
            }
            bits
        } else {
            BIND_IP_PRE_CONNECT_EMPTY
        },
        Ordering::Relaxed,
    );
    // The very last step.
    let bi = BI::initialize();
    unsafe {
        // SAFETY: immediately after this call, we set BALBOA_IS_INITIALIZED high with a Release
        // ordering. There are no concurrent calls to set_balboa_interceptors, since we've checked
        // the BALBOA_IS_INITIALIZING global.
        set_balboa_interceptors(bi);
    }
    BALBOA_IS_INITIALIZED.store(true, Ordering::Release);
}
