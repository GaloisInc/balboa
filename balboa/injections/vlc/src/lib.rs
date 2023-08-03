//! Injection support for `vlc`.

use balboa_compression::NullCompressor;
use balboa_injection::{balboa_inject, BalboaInterceptors};
use balboa_rewriter::{
    sslkeylogfile::SSLKeyLogFile,
    tls_rewriter::{ClientServerMessageOrdering, TLSRewriterMode},
    IncomingRewriter, OutgoingRewriter,
};
use std::{net::SocketAddr, sync::Arc};

struct VLCInjection {
    ssl_key_log_file: Arc<SSLKeyLogFile>,
}

impl BalboaInterceptors for VLCInjection {
    const RUN_ON_CUSTOM_STACK: bool = true;
    fn initialize() -> Self {
        VLCInjection {
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
        if remote.port() != 8443 {
            return None;
        }
        Some(balboa_injection::make_rewriters(
            remote,
            TLSRewriterMode::Client,
            // Because Icecast/VLC are using HTTP.
            ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage,
            |_| Box::new(NullCompressor),
            |ctx| {
                let ogg_file =
                    std::env::var("OGG_FILE").expect("Missing OGG_FILE environment variable");
                let ogg_file = Some(ogg_file).filter(|x| x != "NO_REWRITE");
                conti::icecast2_ogg_vorbis::new_decompressor(ctx, ogg_file).unwrap()
            },
            self.ssl_key_log_file.clone(),
        ))
    }
}

balboa_inject!(VLCInjection);
