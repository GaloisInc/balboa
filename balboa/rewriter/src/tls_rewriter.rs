/*
CONCERNS:
 * TLS downgrade attack
 * tls compression?
 * session resumption (esp. with TLS 1.3)
 * renegotiation (also p. 38 of the tls 1.2 spec: you can send a clienthello at any time. it's insecure, tho?)
 * rekeying
 * TLS 1.3 0-RTT
 * kernel TLS
 * we're only using the cipher suite to detect TLS 1.3. Could an attacker exploit the fact that we support both tls 1.2 and 1.3 to detect ROCKY
*/

use crate::{
    tls::{self, ClientRandom, TlsSecret, TlsSecretLabel},
    tls_rewriter::{
        errors::TLSRewriterError,
        shared_state::{TLSConnectionSharedState, TLSConnectionSharedStateSnapshot},
    },
    IncomingRewriter, OutgoingRewriter, StreamChangeData,
};
use balboa_compression::{CompressContext, Compressor, DecompressContext, Decompressor};
use balboa_coroutine::GenState;
use balboa_covert_signaling_types::{
    CovertSignalingToken, PinnedServerPubKey, RockySecret, ServerCovertSignalingSecret,
};
use parking_lot::{Mutex, RwLock};
use stallone::LoggableMetadata;
use std::{future::Future, marker::PhantomData, net::SocketAddr, ops::Deref, sync::Arc};

mod errors;
mod handshake;
mod mangling;
mod rocky_crypto;
mod shared_state;
mod tls_record_parser;
mod utils;

#[cfg(test)]
pub mod testsuite;

type Result<T> = std::result::Result<T, errors::TLSRewriterError>;

#[derive(Debug, Eq, PartialEq, Copy, Clone, LoggableMetadata)]
pub enum TLSRewriterMode {
    Server,
    Client,
}

impl std::ops::Not for TLSRewriterMode {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            TLSRewriterMode::Server => TLSRewriterMode::Client,
            TLSRewriterMode::Client => TLSRewriterMode::Server,
        }
    }
}

struct CoroutineHelper {
    sock_addr: SocketAddr,
    shared_state: Arc<TLSConnectionSharedState>,
    mode: TLSRewriterMode,
    ioo: IncomingOrOutgoing,
}
impl CoroutineHelper {
    fn set_stallone_context(&self) {
        let client_random = self.shared_state.try_client_random();
        stallone::info!(
            "Setting stallone context for TLS rewriter coroutine",
            #[context(true)]
            mode: TLSRewriterMode = self.mode,
            #[context(true)]
            ioo: IncomingOrOutgoing = self.ioo,
            #[context(true)]
            client_random: Option<tls::ClientRandom> = client_random,
            #[context(true)]
            connection_state: TLSConnectionSharedStateSnapshot = self.shared_state.snapshot(),
            #[context(true)]
            sock_addr: SocketAddr = self.sock_addr,
        );
    }

    fn clear_stallone_context(&self) {
        stallone::info!(
            "Clearing stallone context for TLS rewriter coroutine",
            #[context(true)]
            mode: stallone::EraseFromContext = stallone::EraseFromContext,
            #[context(true)]
            ioo: stallone::EraseFromContext = stallone::EraseFromContext,
            #[context(true)]
            client_random: stallone::EraseFromContext = stallone::EraseFromContext,
            #[context(true)]
            connection_state: stallone::EraseFromContext = stallone::EraseFromContext,
            #[context(true)]
            sock_addr: stallone::EraseFromContext = stallone::EraseFromContext,
        );
    }
}

pub struct TlsOutgoingRewriter {
    helper: CoroutineHelper,
    coro: balboa_coroutine::CoroutineBasedStreamRewriter,
}

impl OutgoingRewriter for TlsOutgoingRewriter {
    fn outgoing_rewrite(&mut self, buf: &mut [u8]) {
        self.helper.set_stallone_context();
        if self.helper.shared_state.is_invalid() {
            stallone::debug!("Transparently passing-thru outgoing rewrite due to invalid state.");
        } else {
            self.coro.rewrite(buf);
        }
        self.helper.clear_stallone_context();
    }
}

pub struct TlsIncomingRewriter {
    helper: CoroutineHelper,
    coro: balboa_coroutine::CoroutineBasedStreamRewriter<StreamChangeData>,
}

impl IncomingRewriter for TlsIncomingRewriter {
    fn incoming_rewrite(&mut self, buf: &mut [u8]) -> StreamChangeData {
        self.helper.set_stallone_context();
        let out = if self.helper.shared_state.is_invalid() {
            stallone::debug!("Transparently passing-thru incoming rewrite due to invalid state.");
            StreamChangeData::default()
        } else {
            self.coro.rewrite(buf)
        };
        self.helper.clear_stallone_context();
        out
    }
}

#[derive(Clone, Copy, LoggableMetadata, Debug)]
pub enum IncomingOrOutgoing {
    Incoming,
    Outgoing,
}

async fn outer_loop<
    R: Default,
    F: Future<Output = std::result::Result<(), (TLSRewriterError, GenState<R>)>> + Send,
>(
    gs: GenState<R>,
    ss: Arc<TLSConnectionSharedState>,
    inner: impl FnOnce(GenState<R>) -> F,
) {
    let mut gs = match inner(gs).await {
        Ok(_) => panic!("inner generator/coroutine finished"),
        Err((e, gs)) => {
            stallone::warn!("entered Invalid state", e: TLSRewriterError = e);
            ss.transition_invalid();
            gs
        }
    };
    loop {
        // Ignore the error.
        gs.advance_without_modifying(1024 * 1024).await;
    }
}

async fn incoming_rewrite(
    ctx_info: ContextualInfo,
    ss: Arc<TLSConnectionSharedState>,
    decompress_buffer: Arc<Mutex<Vec<u8>>>,
    decompress_context: &mut (dyn DecompressContext + Send + 'static),
    decompressor: &mut (dyn Decompressor + Send + 'static),
    gs: &mut GenState<StreamChangeData>,
    enable_tls13: bool,
) -> Result<()> {
    let rp = tls_record_parser::AboutToParseHeader::new(gs);
    let (crypto_params, hdr, body) = match !ctx_info.mode() {
        TLSRewriterMode::Server => {
            handshake::server(
                &ctx_info,
                IncomingOrOutgoing::Incoming,
                decompressor,
                &ss,
                rp,
                enable_tls13,
            )
            .await?
        }
        TLSRewriterMode::Client => {
            handshake::client(
                &ctx_info,
                IncomingOrOutgoing::Incoming,
                decompressor,
                &ss,
                rp,
            )
            .await?
        }
    };
    stallone::debug!("Finished handshake. Starting mangling.");
    mangling::incoming(
        ctx_info.mode(),
        decompress_buffer,
        decompress_context,
        decompressor,
        &ss,
        crypto_params,
        hdr,
        body,
    )
    .await
}

async fn outgoing_rewrite(
    ctx_info: ContextualInfo,
    ss: Arc<TLSConnectionSharedState>,
    compressor: &mut (dyn Compressor + Send + 'static),
    gs: &mut GenState,
    enable_tls13: bool,
) -> Result<()> {
    let rp = tls_record_parser::AboutToParseHeader::new(gs);
    let (crypto_params, hdr, body) = match ctx_info.mode() {
        TLSRewriterMode::Server => {
            handshake::server(
                &ctx_info,
                IncomingOrOutgoing::Outgoing,
                compressor,
                &ss,
                rp,
                enable_tls13,
            )
            .await?
        }
        TLSRewriterMode::Client => {
            handshake::client(&ctx_info, IncomingOrOutgoing::Outgoing, compressor, &ss, rp).await?
        }
    };
    stallone::debug!("Finished handshake. Starting mangling.");
    mangling::outgoing(ctx_info.mode(), compressor, &ss, crypto_params, hdr, body).await
}

/// Is there a guaranteed ordering between client and server messages?
///
/// In protocols like HTTP, the client will _always_ send the first message. The server won't (in
/// usual situations) send any data until it hears from the client. For protocols like this, where
/// the `FirstClientMessagePrecedesFirstServerMessage`, Balboa can enable some optimizations. Balboa
/// can still operate on protocols with `NoSuchOrdering`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LoggableMetadata)]
pub enum ClientServerMessageOrdering {
    FirstClientMessagePrecedesFirstServerMessage,
    NoSuchOrdering,
}
impl Default for ClientServerMessageOrdering {
    fn default() -> Self {
        ClientServerMessageOrdering::NoSuchOrdering
    }
}

/// How should TLS secrets be captured?
///
/// If the target application supports `SSLKEYLOGFILE`, then the usual implementation of this trait
/// to use is [`super::sslkeylogfile::SSLKeyLogFile`]. If the target application uses openssl, then
/// look at the `balboa-openssl-injection` crate.
pub trait TlsSecretProvider {
    /// Fetch the TLS secret corresponding to the given `client_random` and `label`.
    fn tls_secret(&self, label: TlsSecretLabel, client_random: &ClientRandom) -> TlsSecret;
}

impl<'a, T: TlsSecretProvider> TlsSecretProvider for &'a T {
    fn tls_secret(&self, label: TlsSecretLabel, client_random: &ClientRandom) -> TlsSecret {
        self.deref().tls_secret(label, client_random)
    }
}

impl<T: TlsSecretProvider> TlsSecretProvider for Arc<T> {
    fn tls_secret(&self, label: TlsSecretLabel, client_random: &ClientRandom) -> TlsSecret {
        let t: &T = &*self;
        t.tls_secret(label, client_random)
    }
}

#[derive(Clone)]
pub enum ModeSpecificContext {
    Client {
        // TODO: maybe, in the future, parse the TLS signing key out of the certificate message,
        // that way we can key off of it and use it to help determine the server identity, rather
        // than being so reliant on the IP address.
        server_pub_key: Arc<PinnedServerPubKey>,
        covert_signaling_token: CovertSignalingToken,
    },
    Server {
        server_secret: Arc<ServerCovertSignalingSecret>,
    },
}

#[derive(Clone)]
pub struct ContextualInfo {
    pub rocky_secret: RockySecret,
    pub mode_specific: ModeSpecificContext,
    pub client_server_message_ordering: ClientServerMessageOrdering,
    pub tls_secret_provider: Arc<dyn TlsSecretProvider + Sync + Send>,
}
impl ContextualInfo {
    pub fn mode(&self) -> TLSRewriterMode {
        match &self.mode_specific {
            ModeSpecificContext::Client { .. } => TLSRewriterMode::Client,
            ModeSpecificContext::Server { .. } => TLSRewriterMode::Server,
        }
    }
}

pub(crate) enum CovertSignalingContextInner {
    NotYetCovertlySignaled(
        Mutex<
            Box<
                dyn FnMut(
                        CovertSignalingToken,
                    ) -> (
                        Box<dyn CompressContext + Send + 'static>,
                        Box<dyn DecompressContext + Send + 'static>,
                    ) + Send
                    + 'static,
            >,
        >,
    ),
    HasBeenCovertlySignaled {
        compress_context: Mutex<Box<dyn CompressContext + Send + 'static>>,
        decompress_context: Mutex<Box<dyn DecompressContext + Send + 'static>>,
    },
}
impl CovertSignalingContextInner {
    /// # Panics
    /// This function will panic if `covertly_signaled` has already been called.
    fn covertly_signaled(&mut self, token: CovertSignalingToken) {
        match self {
            CovertSignalingContextInner::NotYetCovertlySignaled(init) => {
                let (compress_context, decompress_context) = (init.lock())(token);
                *self = CovertSignalingContextInner::HasBeenCovertlySignaled {
                    compress_context: Mutex::new(compress_context),
                    decompress_context: Mutex::new(decompress_context),
                };
            }
            CovertSignalingContextInner::HasBeenCovertlySignaled { .. } => {
                panic!("Already been covertly signaled!")
            }
        }
    }
}

// TODO: this adds a ton of indirection and dyn. It'd be nice to avoid this. The easiest way to do
// so would be to go in and add additional parameters to coroutines. This would solve a lot of our
// problems, but would be a major API change.
pub(crate) struct CovertSignalingContext<T: Send + 'static> {
    inner: Arc<RwLock<CovertSignalingContextInner>>,
    phantom: PhantomData<T>,
}
impl CompressContext for CovertSignalingContext<Box<dyn CompressContext + Send + 'static>> {
    fn recv_covert_bytes(&mut self, dst: &mut [u8]) {
        match self.inner.read().deref() {
            CovertSignalingContextInner::NotYetCovertlySignaled(_) => {
                panic!("Trying to get covert bytes before covert signaling!")
            }
            CovertSignalingContextInner::HasBeenCovertlySignaled {
                compress_context,
                decompress_context: _,
            } => compress_context.lock().recv_covert_bytes(dst),
        }
    }
}
impl DecompressContext for CovertSignalingContext<Box<dyn DecompressContext + Send + 'static>> {
    fn send_covert_bytes(&mut self, src: &[u8]) {
        match self.inner.read().deref() {
            CovertSignalingContextInner::NotYetCovertlySignaled(_) => {
                panic!("Trying to get covert bytes before covert signaling!")
            }
            CovertSignalingContextInner::HasBeenCovertlySignaled {
                compress_context: _,
                decompress_context,
            } => decompress_context.lock().send_covert_bytes(src),
        }
    }
}

pub fn new_pair(
    sock_addr: SocketAddr,
    ctx_info: ContextualInfo,
    covert_data_interface: impl (FnOnce(
            CovertSignalingToken,
        ) -> (
            Box<dyn CompressContext + Send + 'static>,
            Box<dyn DecompressContext + Send + 'static>,
        )) + Send
        + 'static,
    compressor_factory: impl FnOnce(
        Box<dyn CompressContext + Send + 'static>,
    ) -> Box<dyn Compressor + Send + 'static>,
    decompressor_factory: impl FnOnce(
        Box<dyn DecompressContext + Send + 'static>,
    ) -> Box<dyn Decompressor + Send + 'static>,
    enable_tls13: bool,
) -> (TlsOutgoingRewriter, TlsIncomingRewriter) {
    let mode = ctx_info.mode();
    let ctx_info2 = ctx_info.clone();
    let mut covert_data_interface = Some(covert_data_interface);
    let covert_ctx_inner = Arc::new(RwLock::new(
        CovertSignalingContextInner::NotYetCovertlySignaled(Mutex::new(Box::new(move |token| {
            (covert_data_interface
                .take()
                .expect("covert_data_interface should be called at most once"))(token)
        }))),
    ));
    let ss = Arc::new(shared_state::TLSConnectionSharedState::new(
        covert_ctx_inner.clone(),
    ));
    let ss1 = ss.clone();
    let ss2 = ss.clone();
    let mut compressor = compressor_factory(Box::new(CovertSignalingContext {
        inner: covert_ctx_inner.clone(),
        phantom: PhantomData,
    }));
    let mut decompress_context: CovertSignalingContext<
        Box<dyn DecompressContext + Send + 'static>,
    > = CovertSignalingContext {
        inner: covert_ctx_inner.clone(),
        phantom: PhantomData,
    };
    let (buffering_decompress_context, decompress_buffer) =
        mangling::BufferingIncomingDecompressContext::new();
    let mut decompressor = decompressor_factory(buffering_decompress_context);
    (
        TlsOutgoingRewriter {
            helper: CoroutineHelper {
                sock_addr,
                shared_state: ss.clone(),
                mode,
                ioo: IncomingOrOutgoing::Outgoing,
            },
            coro: balboa_coroutine::CoroutineBasedStreamRewriter::new(move |gs| async move {
                let ss3 = ss1.clone();
                outer_loop(gs, ss1, |mut gs| async move {
                    match outgoing_rewrite(
                        ctx_info,
                        ss3,
                        compressor.as_mut(),
                        &mut gs,
                        enable_tls13,
                    )
                    .await
                    {
                        Ok(()) => Ok(()),
                        Err(e) => Err((e, gs)),
                    }
                })
                .await;
                panic!("outgoing rewriter completed.");
            }),
        },
        TlsIncomingRewriter {
            helper: CoroutineHelper {
                sock_addr,
                shared_state: ss,
                mode,
                ioo: IncomingOrOutgoing::Incoming,
            },
            coro: balboa_coroutine::CoroutineBasedStreamRewriter::new(move |gs| async move {
                let ss3 = ss2.clone();
                outer_loop(gs, ss2, |mut gs| async move {
                    match incoming_rewrite(
                        ctx_info2,
                        ss3,
                        decompress_buffer,
                        &mut decompress_context,
                        decompressor.as_mut(),
                        &mut gs,
                        enable_tls13,
                    )
                    .await
                    {
                        Ok(()) => Ok(()),
                        Err(e) => Err((e, gs)),
                    }
                })
                .await;
                panic!("incoming rewriter completed.");
            }),
        },
    )
}
