//! Injection support for `icecast`.

use balboa_compression::NullDecompressor;
use balboa_injection::{balboa_inject, BalboaInterceptors};
use balboa_rewriter::{
    tls_rewriter::{ClientServerMessageOrdering, TLSRewriterMode},
    IncomingRewriter, OutgoingRewriter,
};
use std::{net::SocketAddr, sync::Arc};

struct IcecastInjection;
impl BalboaInterceptors for IcecastInjection {
    const RUN_ON_CUSTOM_STACK: bool = true;
    fn initialize() -> Self {
        IcecastInjection
    }
    fn listen_on_addr(&self, remote: SocketAddr) -> bool {
        remote.port() == 8443
    }

    fn rewriters_for_tcp_server(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        Some(balboa_injection::make_rewriters(
            remote,
            TLSRewriterMode::Server,
            // Because Icecast responds to HTTP
            ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage,
            |ctx| {
                conti::icecast2_ogg_vorbis::new_compressor(
                    ctx,
                    std::env::var("OGG_FILE").expect("missing OGG_FILE env var"),
                )
                .unwrap()
            },
            |_| Box::new(NullDecompressor),
            Arc::new(&*SSL_KEY_LOG_FILE),
        ))
    }
}

balboa_inject!(IcecastInjection);
balboa_openssl_injection::balboa_inject_openssl_sslkeylogfile!(
    SSL_KEY_LOG_FILE: balboa_rewriter::sslkeylogfile::SSLKeyLogFile
);
