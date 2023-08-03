use balboa_injection::{balboa_inject, BalboaInterceptors};
use balboa_rewriter::{
    sslkeylogfile::SSLKeyLogFile,
    tls_rewriter::{ClientServerMessageOrdering, TLSRewriterMode},
    IncomingRewriter, OutgoingRewriter,
};
use balboa_testing_inverting_rewriter::{InvertingCompressor, InvertingDecompressor};
use std::{net::SocketAddr, sync::Arc};

struct GNUTLSEcho {
    ssl_key_log_file: Arc<SSLKeyLogFile>,
}
impl BalboaInterceptors for GNUTLSEcho {
    fn initialize() -> Self {
        GNUTLSEcho {
            ssl_key_log_file: SSLKeyLogFile::read_from_named_pipe(
                std::env::var("SSLKEYLOGFILE").unwrap(),
            )
            .unwrap(),
        }
    }

    fn listen_on_addr(&self, _addr: SocketAddr) -> bool {
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
            self.ssl_key_log_file.clone(),
        ))
    }

    fn rewriters_for_tcp_server(
        &self,
        client: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        Some(balboa_injection::make_rewriters(
            client,
            TLSRewriterMode::Server,
            ClientServerMessageOrdering::NoSuchOrdering,
            |_| Box::new(InvertingCompressor),
            |_| Box::new(InvertingDecompressor),
            self.ssl_key_log_file.clone(),
        ))
    }
}

balboa_inject!(GNUTLSEcho);
