//! Injection support for `socat` streaming RTSP h264 video.

use balboa_compression_rtsp::new_server_rewriters;
use balboa_injection::{balboa_inject, BalboaInterceptors};
use balboa_rewriter::{
    tls_rewriter::{ClientServerMessageOrdering, TLSRewriterMode},
    IncomingRewriter, OutgoingRewriter,
};
use std::{net::SocketAddr, sync::Arc};

struct SocatInjection;
impl BalboaInterceptors for SocatInjection {
    const STALLONE_FOLLOW_FORKS: bool = true;
    fn initialize() -> Self {
        SocatInjection
    }
    fn listen_on_addr(&self, remote: SocketAddr) -> bool {
        remote.port() == 9554
    }

    fn rewriters_for_tcp_server(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        let (c, d) = new_server_rewriters();
        Some(balboa_injection::make_rewriters(
            remote,
            TLSRewriterMode::Server,
            // Because Icecast responds to HTTP
            ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage,
            c,
            d,
            Arc::new(&*SSL_KEY_LOG_FILE),
        ))
    }
}

balboa_inject!(SocatInjection);

balboa_openssl_injection::balboa_inject_openssl_sslkeylogfile!(
    SSL_KEY_LOG_FILE: balboa_rewriter::sslkeylogfile::SSLKeyLogFile
);
