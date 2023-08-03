use balboa_injection::{balboa_inject, BalboaInterceptors};
use balboa_rewriter::{
    tls_rewriter::{ClientServerMessageOrdering, TLSRewriterMode},
    IncomingRewriter, OutgoingRewriter,
};
use balboa_testing_inverting_rewriter::{InvertingCompressor, InvertingDecompressor};
use std::{net::SocketAddr, sync::Arc};

struct OpensslEcho;
impl BalboaInterceptors for OpensslEcho {
    fn initialize() -> Self {
        OpensslEcho
    }

    fn listen_on_addr(&self, _remote: SocketAddr) -> bool {
        true
    }

    fn rewriters_for_tcp_client(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        Some(balboa_injection::make_rewriters(
            remote,
            TLSRewriterMode::Client,
            ClientServerMessageOrdering::NoSuchOrdering,
            |_| Box::new(InvertingCompressor),
            |_| Box::new(InvertingDecompressor),
            Arc::new(&*SSL_KEY_LOG_FILE),
        ))
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
            ClientServerMessageOrdering::NoSuchOrdering,
            |_| Box::new(InvertingCompressor),
            |_| Box::new(InvertingDecompressor),
            Arc::new(&*SSL_KEY_LOG_FILE),
        ))
    }
}

balboa_inject!(OpensslEcho);
balboa_openssl_injection::balboa_inject_openssl_sslkeylogfile!(
    SSL_KEY_LOG_FILE: balboa_rewriter::sslkeylogfile::SSLKeyLogFile
);
