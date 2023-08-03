//! Injection support for `vlc`.

use balboa_compression_rtsp::new_client_rewriters;
use balboa_injection::{balboa_inject, BalboaInterceptors};
use balboa_rewriter::{
    sslkeylogfile::SSLKeyLogFile,
    tls_rewriter::{ClientServerMessageOrdering, TLSRewriterMode},
    IncomingRewriter, OutgoingRewriter,
};
use std::{net::SocketAddr, sync::Arc};

struct FfplayRtspInjection {
    ssl_key_log_file: Arc<SSLKeyLogFile>,
}

impl BalboaInterceptors for FfplayRtspInjection {
    fn initialize() -> Self {
        FfplayRtspInjection {
            ssl_key_log_file: SSLKeyLogFile::read_from_named_pipe(
                std::env::var("SSLKEYLOGFILE").unwrap(),
            )
            .unwrap(),
        }
    }

    fn rewriters_for_tcp_client(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        let (c, d) = new_client_rewriters();
        Some(balboa_injection::make_rewriters(
            remote,
            TLSRewriterMode::Client,
            // Because RTSP is like HTTP.
            ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage,
            c,
            d,
            self.ssl_key_log_file.clone(),
        ))
    }
}

balboa_inject!(FfplayRtspInjection);
