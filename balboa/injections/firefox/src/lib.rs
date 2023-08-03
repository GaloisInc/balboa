use balboa_compression_http::StaticFileDirectory;
use balboa_injection::{balboa_inject, BalboaInterceptors};
use balboa_rewriter::{
    sslkeylogfile,
    tls_rewriter::{ClientServerMessageOrdering, TLSRewriterMode, TlsSecretProvider},
    IncomingRewriter, OutgoingRewriter,
};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

struct SslKeylogFileReRead(PathBuf);
impl TlsSecretProvider for SslKeylogFileReRead {
    fn tls_secret(
        &self,
        label: balboa_rewriter::tls::TlsSecretLabel,
        client_random: &balboa_rewriter::tls::ClientRandom,
    ) -> balboa_rewriter::tls::TlsSecret {
        // TODO: we should do something better
        let mut f = BufReader::new(File::open(&self.0).unwrap());
        let mut buf = Vec::new();
        let key = (label, *client_random);
        loop {
            buf.clear();
            f.read_until(b'\n', &mut buf).unwrap();
            if buf.is_empty() {
                panic!("unable to find master secret for {:?}", client_random);
            }
            if let Ok(Some(entry)) = sslkeylogfile::parse_sslkeylogfile_entry(buf.as_slice()) {
                if entry.key == key {
                    return entry.master_secret;
                }
            }
        }
    }
}

struct FirefoxInjection {
    ssl_key_log_file: Arc<SslKeylogFileReRead>,
}

impl BalboaInterceptors for FirefoxInjection {
    const STALLONE_FOLLOW_FORKS: bool = true;
    const RUN_ON_CUSTOM_STACK: bool = true;
    fn initialize() -> Self {
        FirefoxInjection {
            ssl_key_log_file: Arc::new(SslKeylogFileReRead(PathBuf::from(
                std::env::var_os("SSLKEYLOGFILE").expect("SSLKEYLOGFILE must be set"),
            ))),
        }
    }

    fn rewriters_for_tcp_client(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        if remote.port() != 9443 {
            return None;
        }
        let (c, d) = balboa_compression_http::new_client_rewriters(
            Arc::new(
                StaticFileDirectory::new(&PathBuf::from(
                    std::env::var_os("STATIC_FILE_DIRECTORY")
                        .expect("STATIC_FILE_DIRECTORY env var missing"),
                ))
                .unwrap(),
            ),
            Arc::new(
                StaticFileDirectory::new(&PathBuf::from(
                    std::env::var_os("UPLOAD_FILE_DIRECTORY")
                        .expect("UPLOAD_FILE_DIRECTORY env var missing"),
                ))
                .unwrap(),
            ),
        );
        Some(balboa_injection::make_rewriters(
            remote,
            TLSRewriterMode::Client,
            // Because Icecast responds to HTTP
            ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage,
            c,
            d,
            self.ssl_key_log_file.clone(),
        ))
    }
}

balboa_inject!(FirefoxInjection);
