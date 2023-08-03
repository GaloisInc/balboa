use balboa_compression::{CompressContext, Compressor, DecompressContext, Decompressor};
use balboa_covert_signaling_types::{
    Capability, CovertSignalingToken, PinnedServerPubKey, RockySecret, ServerCovertSignalingSecret,
};
use balboa_rewriter::tls_rewriter::{ModeSpecificContext, TLSRewriterMode, TlsSecretProvider};
use balboa_rewriter::{tls_rewriter, IncomingRewriter, NullRewriter, OutgoingRewriter};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use stallone_common::{positioned_io_error, positioned_io_result, PositionedIOResult};
use std::fs::File;
use std::io::{Error, ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

lazy_static::lazy_static! {
    /// This contains the rocky secret keys, as well as the pinned public keys used in connections.
    /// The path of the directory is pulled from the `ROCKY_BASE_SECRETS_PATH` environment variable.
    /// See `mickey_balboa_ipc::crypto::RockyCryptoSecrets` for details on the directory.
    /// Accessing this variable will panic if the env var `ROCKY_BASE_SECRETS_PATH` has not been set.
    static ref ROCKY_SECRETS: mickey_balboa_ipc::crypto::RockyCryptoSecrets =
        mickey_balboa_ipc::crypto::RockyCryptoSecrets::new(std::env::var("ROCKY_BASE_SECRETS_PATH")
            .expect("ROCKY_BASE_SECRETS_PATH should be set").into());
    /// This contains a connection to the mickey server through the `MICKEY_BALBOA_IPC_SOCKET` environment variable.
    /// Accessing this variable will panic if the env var `MICKEY_BALBOA_IPC_SOCKET` has not been set.
    static ref MICKEY_BALBOA_IPC: mickey_balboa_ipc::balboa::BalboaMickeyIPC =
        mickey_balboa_ipc::balboa::BalboaMickeyIPC::open(std::env::var("MICKEY_BALBOA_IPC_SOCKET")
            .expect("MICKEY_BALBOA_IPC_SOCKET should have been set").into()).unwrap();
}

struct CapabilityMap {
    base_path: PathBuf,
}

impl CapabilityMap {
    pub fn new(base_path: PathBuf) -> Self {
        assert!(base_path.is_dir());
        CapabilityMap { base_path }
    }

    pub fn capability_for_ip(&self, ip: &Ipv4Addr) -> PositionedIOResult<Capability> {
        let path = self.base_path.join(format!("{}.capability", ip));
        let f = positioned_io_result!(std::fs::File::open(path))?;
        Ok(serde_json::from_reader(std::io::BufReader::new(f))
            .map_err(|e| positioned_io_error!(Error::new(ErrorKind::InvalidData, e)))?)
    }
}

lazy_static::lazy_static! {
    static ref ROCKY_CAPABILITIES: CapabilityMap = CapabilityMap::new(
        std::env::var("ROCKY_CAPABILITIES_PATH")
            .expect("ROCKY_CAPABILITIES_PATH should be set").into());
}

fn make_rewriters_for_mickey(
    remote: SocketAddr,
    mode: TLSRewriterMode,
    client_server_message_ordering: tls_rewriter::ClientServerMessageOrdering,
    compressor_factory: impl FnOnce(
        Box<dyn CompressContext + Send + 'static>,
    ) -> Box<dyn Compressor + Send + 'static>,
    decompressor_factory: impl FnOnce(
        Box<dyn DecompressContext + Send + 'static>,
    ) -> Box<dyn Decompressor + Send + 'static>,
    tls_sp: Arc<dyn TlsSecretProvider + Sync + Send>,
    enable_tls13: bool,
) -> (
    Box<dyn IncomingRewriter + Send>,
    Box<dyn OutgoingRewriter + Send>,
) {
    // If there's a mickey socket set, then we'll use it instead of the balboa socket stuff
    // TODO: support ipv6.
    let ipv4 = match remote.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => {
            stallone::error!(
                "Falling back to null rewriters. Got IPv6 address",
                ip: Ipv6Addr = ip,
            );
            return (Box::new(NullRewriter), Box::new(NullRewriter));
        }
    };
    let rocky_secret = match ROCKY_SECRETS.rocky_key(remote.ip()) {
        Ok(secret) => secret,
        Err(e) => {
            stallone::error!(
                "Falling back to null rewriters. Unable to get rocky secret.",
                ip: IpAddr = remote.ip(),
                error: String = format!("{}", e),
            );
            return (Box::new(NullRewriter), Box::new(NullRewriter));
        }
    };

    let hard_coded_server_secret = Arc::new(ServerCovertSignalingSecret::from_bytes([90; 16]));
    let hard_coded_identity = 91;
    let hard_coded_covert_signaling_token =
        hard_coded_server_secret.generate_token(hard_coded_identity);

    let mode_specific = match mode {
        TLSRewriterMode::Server => ModeSpecificContext::Server {
            server_secret: hard_coded_server_secret,
        },
        TLSRewriterMode::Client => {
            let server_pub_key = ROCKY_SECRETS.tls_key(remote.ip()).unwrap_or_else(|e| {
                stallone::warn!(
                    "Unable to get TLS key",
                    ip: IpAddr = remote.ip(),
                    error: String = format!("{}", e),
                );
                // An empty array ought to (but we should check) fail all signature verification
                Arc::new(PinnedServerPubKey::from_der(Vec::new()))
            });

            ModeSpecificContext::Client {
                server_pub_key,
                covert_signaling_token: hard_coded_covert_signaling_token,
            }
        }
    };
    let compress_context = Box::new(MICKEY_BALBOA_IPC.compress_context(ipv4).unwrap());
    let decompress_context = Box::new(MICKEY_BALBOA_IPC.decompress_context(ipv4).unwrap());

    let (o, i) = tls_rewriter::new_pair(
        remote,
        tls_rewriter::ContextualInfo {
            rocky_secret: RockySecret(rocky_secret),
            mode_specific,
            client_server_message_ordering,
            tls_secret_provider: tls_sp,
        },
        |_| (compress_context, decompress_context),
        compressor_factory,
        decompressor_factory,
        enable_tls13,
    );
    return (Box::new(i), Box::new(o));
}

fn make_rewriters_for_testing(
    remote: SocketAddr,
    mode: TLSRewriterMode,
    client_server_message_ordering: tls_rewriter::ClientServerMessageOrdering,
    compressor_factory: impl FnOnce(
        Box<dyn CompressContext + Send + 'static>,
    ) -> Box<dyn Compressor + Send + 'static>,
    decompressor_factory: impl FnOnce(
        Box<dyn DecompressContext + Send + 'static>,
    ) -> Box<dyn Decompressor + Send + 'static>,
    tls_sp: Arc<dyn TlsSecretProvider + Sync + Send>,
    enable_tls13: bool,
) -> (
    Box<dyn IncomingRewriter + Send>,
    Box<dyn OutgoingRewriter + Send>,
) {
    let ipv4 = match remote.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => {
            stallone::error!(
                "Falling back to null rewriters. Got IPv6 address",
                ip: Ipv6Addr = ip,
            );
            return (Box::new(NullRewriter), Box::new(NullRewriter));
        }
    };
    let data_dir = std::env::var("ROCKY_DATA_PATH")
        .map(|s| PathBuf::from(s))
        .expect("ROCKY_DATA_PATH is not set and is required.");

    struct TestingContext {
        backing_file: File,
        rng: StdRng,
    }

    enum FileMode {
        Incoming,
        Outgoing,
    }

    impl TestingContext {
        fn new(_token: CovertSignalingToken, data_dir: &PathBuf, mode: FileMode) -> Self {
            let mut rng = StdRng::from_entropy();
            let mut backing_file_path = data_dir.clone();
            std::fs::create_dir_all(&backing_file_path).expect("Unable to create token directory.");
            match mode {
                FileMode::Incoming => {
                    backing_file_path.push(format!("incoming-{:X}.bin", rng.gen::<u128>()))
                }
                FileMode::Outgoing => {
                    backing_file_path.push(format!("outgoing-{:X}.bin", rng.gen::<u128>()))
                }
            }
            let backing_file = File::create(backing_file_path).unwrap();
            TestingContext { backing_file, rng }
        }
    }

    impl CompressContext for TestingContext {
        fn recv_covert_bytes(&mut self, dst: &mut [u8]) {
            self.rng.fill(dst);
            self.backing_file.write_all(dst).unwrap();
            self.backing_file.flush().unwrap();
        }
    }

    impl DecompressContext for TestingContext {
        fn send_covert_bytes(&mut self, src: &[u8]) {
            self.backing_file.write_all(src).unwrap();
            self.backing_file.flush().unwrap();
        }
    }

    let (rocky_secret, mode_specific) = match mode {
        TLSRewriterMode::Server => {
            // We are the server, the following should be provided to us:
            let server_secret_encoded = std::env::var("ROCKY_SERVER_SECRET")
                .expect("ROCKY_SERVER_SECRET is not set and is required.");
            let server_secret_decoded = hex::decode(server_secret_encoded)
                .expect("Unable to parse ROCKY_SERVER_SECRET")
                .try_into()
                .unwrap();

            let rocky_secret_encoded = std::env::var("ROCKY_PRE_SHARED_SECRET")
                .expect("ROCKY_PRE_SHARED_SECRET is not set and is required.");

            let rocky_secret_decoded: [u8; 32] = hex::decode(rocky_secret_encoded)
                .map(|v| v.try_into().expect("Unable to decode secret."))
                .expect("Unable to parse pre-shared secret.");

            (
                RockySecret(rocky_secret_decoded),
                ModeSpecificContext::Server {
                    server_secret: Arc::new(ServerCovertSignalingSecret::from_bytes(
                        server_secret_decoded,
                    )),
                },
            )
        }
        TLSRewriterMode::Client => {
            // We are a client, most information should come from the
            // covert signaling token we use to connect to the server.

            // Use the most recent capability associated with the remote IP address.
            let capability = ROCKY_CAPABILITIES.capability_for_ip(&ipv4).expect(&format!(
                "Unable to get capability for IP {:?}",
                remote.ip()
            ));

            (
                capability.rocky_secret,
                ModeSpecificContext::Client {
                    server_pub_key: Arc::new(capability.pinned_server_pub_key),
                    covert_signaling_token: capability.covert_signaling_token,
                },
            )
        }
    };

    let (o, i) = tls_rewriter::new_pair(
        remote,
        tls_rewriter::ContextualInfo {
            rocky_secret,
            mode_specific,
            client_server_message_ordering,
            tls_secret_provider: tls_sp,
        },
        move |token| {
            (
                Box::new(TestingContext::new(
                    token.clone(),
                    &data_dir,
                    FileMode::Outgoing,
                )),
                Box::new(TestingContext::new(
                    token.clone(),
                    &data_dir,
                    FileMode::Incoming,
                )),
            )
        },
        compressor_factory,
        decompressor_factory,
        enable_tls13,
    );
    (Box::new(i), Box::new(o))
}

/// Create incoming and outgoing rewriters which operate on a TCP stream containing TLS ciphertexts
///
/// The plaintext of the outgoing TLS stream will be processed by the result of `compressor_factory`
/// and the plaintext of the incoming TLS stream will be processed by the result of
/// `decompressor_factory`.
///
/// * `remote` should be the IP, port pair of the peer
/// * `mode` should reflect whether the currently running process is the client or the server
/// * `client_server_message_ordering` should indicate whether the client will always send a
///   message before the server will. (See [`tls_rewriter::ClientServerMessageOrdering`] for
///   more info.)
/// * `compressor_factory` is a function which, when given the [`CompressContext`] will return
///   the [`Compressor`] to use.
/// * `decompressor_factory` is a function which, when given the [`DecompressContext`] will return
///   the [`Decompressor`] to use.
/// * `tls_sp` is the [`TlsSecretProvider`] which will be used to extract the TLS secrets, which
///   will allow for surgical rewriting of the TLS stream.
pub fn make_rewriters(
    remote: SocketAddr,
    mode: TLSRewriterMode,
    client_server_message_ordering: tls_rewriter::ClientServerMessageOrdering,
    compressor_factory: impl FnOnce(
        Box<dyn CompressContext + Send + 'static>,
    ) -> Box<dyn Compressor + Send + 'static>,
    decompressor_factory: impl FnOnce(
        Box<dyn DecompressContext + Send + 'static>,
    ) -> Box<dyn Decompressor + Send + 'static>,
    tls_sp: Arc<dyn TlsSecretProvider + Sync + Send>,
) -> (
    Box<dyn IncomingRewriter + Send>,
    Box<dyn OutgoingRewriter + Send>,
) {
    // Disable TLS 1.3 unless an environment variable is set.
    let enable_tls13 = std::env::var("BALBOA_ENABLE_TLS13").is_ok();
    if std::env::var("MICKEY_BALBOA_IPC_SOCKET").is_ok() {
        make_rewriters_for_mickey(
            remote,
            mode,
            client_server_message_ordering,
            compressor_factory,
            decompressor_factory,
            tls_sp,
            enable_tls13,
        )
    } else {
        make_rewriters_for_testing(
            remote,
            mode,
            client_server_message_ordering,
            compressor_factory,
            decompressor_factory,
            tls_sp,
            enable_tls13,
        )
    }
}
