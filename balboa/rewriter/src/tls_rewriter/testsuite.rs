use crate::balboa_rewriter::{
    read_state::{ReadIsPeek, ReadState},
    sslkeylogfile::SSLKeyLogFile,
    tls,
    tls_rewriter::{self, ClientServerMessageOrdering, TLSRewriterMode},
    IncomingRewriter, OutgoingRewriter,
};
use crate::tls_rewriter::{new_pair, ContextualInfo, IncomingOrOutgoing};
use balboa_compression::{
    CanPreviewPlaintextData, CompressContext, Compressor, DecompressContext, Decompressor,
    NullCompressContext, NullCompressor, NullDecompressContext, NullDecompressor,
};
use balboa_covert_signaling_types::{PinnedServerPubKey, RockySecret, ServerCovertSignalingSecret};
use nasty_workaround::DynReadAndWrite;
use os_pipe::{PipeReader, PipeWriter};
use parking_lot::Mutex;
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier, ServerName},
    Certificate, ClientConfig, ClientConnection, Error as TlsError, KeyLog, RootCertStore,
    ServerConfig, ServerConnection, StreamOwned, SupportedCipherSuite, SupportedProtocolVersion,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    io::{Cursor, Error, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Instant,
};

use crate::tls_rewriter::ModeSpecificContext;
use rand::{rngs::StdRng, SeedableRng};

fn initialize_logging_for_test(test_name: &str) {
    log::info!("Starting test {:?}", test_name);
    stallone::info!("Starting test", test_name: &str = test_name);
}

struct Duplex<R: Read, W: Write> {
    reader: R,
    writer: W,
    chunk_size: usize,
}
impl<R: Read, W: Write> Read for Duplex<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.reader.read(buf)
    }
}
impl<R: Read, W: Write> Write for Duplex<R, W> {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, Error> {
        if self.chunk_size == 0 {
            self.writer.write(buf)
        } else {
            let mut bytes_written = 0;
            while !buf.is_empty() {
                let write_size = self.chunk_size.min(buf.len());
                let actual_write_size = self.writer.write(&buf[..write_size])?;

                bytes_written += actual_write_size;
                buf = &buf[write_size..];

                // Stop writing if the writer doesn't do anything.
                if actual_write_size == 0 {
                    break;
                }

                // We need this, or `Duplex::read` will buffer multiple write calls into a single
                // read call.
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Ok(bytes_written)
        }
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.writer.flush()
    }
}

struct SSLKeyLogFileAdapter(Arc<SSLKeyLogFile>);
impl KeyLog for SSLKeyLogFileAdapter {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.0.add_entries(
            format!(
                "{} {} {}\n",
                label,
                hex::encode(client_random),
                hex::encode(secret)
            )
            .as_bytes(),
        );
    }
}

struct NullCertVerifier;
impl ServerCertVerifier for NullCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }
}

// These are from the build-a-ca.sh from rusttls. Rustls requires well-formed certs. OpenSSL tends
// not to make those, apparently.
const PRIVKEY_BYTES: &'static [u8] = include_bytes!("testsuite-privkey.pem");
const PUBCERT_BYTES: &'static [u8] = include_bytes!("testsuite-pubcert.pem");
const PUBKEY_DER_BYTES: &'static [u8] = include_bytes!("testsuite-pubkey.der");

struct Interceptor<O: OutgoingRewriter, T: Read + Write>(ReadState, O, T);
impl<O: OutgoingRewriter, T: Read + Write> Read for Interceptor<O, T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let start = Instant::now();
        let n = match self
            .0
            .rewrite_readv(buf.len(), ReadIsPeek::ConsumingRead, |new_buf| {
                match self.2.read(new_buf) {
                    Ok(n) => n as isize,
                    Err(_) => Error::last_os_error().raw_os_error().unwrap_or(-1) as isize,
                }
            }) {
            Ok(xs) => {
                buf[..xs.len()].copy_from_slice(xs);
                xs.len()
            }
            Err(i) => panic!("rewrite_readv error: {}", i),
        };
        log::info!("incoming rewrite {:?}", start.elapsed());
        Ok(n)
    }
}
impl<O: OutgoingRewriter, T: Read + Write> Write for Interceptor<O, T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let mut v = buf.to_vec();
        // TODO: we should probably implement some overlap stuff, but this is easier.
        let start = Instant::now();
        self.1.outgoing_rewrite(&mut v[..]);
        log::info!("outgoing rewrite {:?}", start.elapsed());
        self.2.write_all(&v)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.2.flush()
    }
}

struct NullContext;
impl DecompressContext for NullContext {
    fn send_covert_bytes(&mut self, _buf: &[u8]) {}
}
impl CompressContext for NullContext {
    fn recv_covert_bytes(&mut self, _buf: &mut [u8]) {}
}

mod nasty_workaround {
    use std::io::{Read, Write};

    // This is a NASTY workaround for not being able to write &mut dyn (Read + Write)
    trait ReadAndWriteTrait {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;
        fn flush(&mut self) -> std::io::Result<()>;
    }

    struct DynReadAndWriteHolder<'a, T: Read + Write>(&'a mut T);

    impl<'a, T: Read + Write> ReadAndWriteTrait for DynReadAndWriteHolder<'a, T> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }

        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    pub struct DynReadAndWrite<'a>(
        smallbox::SmallBox<dyn ReadAndWriteTrait + 'a, smallbox::space::S2>,
    );

    impl<'a, T: Read + Write> From<&'a mut T> for DynReadAndWrite<'a> {
        fn from(x: &'a mut T) -> Self {
            DynReadAndWrite(smallbox::smallbox!(DynReadAndWriteHolder(x)))
        }
    }

    impl<'a> Read for DynReadAndWrite<'a> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl<'a> Write for DynReadAndWrite<'a> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }
}

const ROCKY_SECRET: RockySecret = RockySecret([75; 32]);

struct RandomContext {
    generator: StdRng,
    counter: u8,
}

impl RandomContext {
    /// Provide an implementation to consistently fill random bytes,
    /// one at-a-time, regardless of the size of the input buffer.
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for i in dst.iter_mut() {
            eprintln!("{:#?} <=> {:#?}", *i, self.counter);
            *i = self.counter;
            self.counter = self.counter.wrapping_add(1);
            // self.generator.fill_bytes(std::slice::from_mut(i));
        }
    }
}

impl CompressContext for RandomContext {
    fn recv_covert_bytes(&mut self, dst: &mut [u8]) {
        eprintln!("recv_covert_bytes({})", dst.len());
        self.fill_bytes(dst);
    }
}

impl DecompressContext for RandomContext {
    fn send_covert_bytes(&mut self, src: &[u8]) {
        eprintln!("send_covert_bytes({})", src.len());
        let mut ground_truth = vec![0; src.len()];
        self.fill_bytes(&mut ground_truth);
        assert_eq!(src, &ground_truth);
    }
}

pub fn run_test<
    SC: Compressor + Send + 'static,
    SD: Decompressor + Send + 'static,
    CC: Compressor + Send + 'static,
    CD: Decompressor + Send + 'static,
>(
    num_times: usize,
    cso: ClientServerMessageOrdering,
    tls_version: &'static SupportedProtocolVersion,
    server_compressor: impl 'static + Send + Fn(Box<dyn CompressContext + Send>) -> SC,
    server_decompressor: impl 'static + Send + Fn(Box<dyn DecompressContext + Send>) -> SD,
    client_compressor: impl 'static + Send + Fn(Box<dyn CompressContext + Send>) -> CC,
    client_decompressor: impl 'static + Send + Fn(Box<dyn DecompressContext + Send>) -> CD,
    mut client: impl FnMut(&mut DynReadAndWrite) + Send + Sync + 'static,
    mut server: impl FnMut(&mut DynReadAndWrite) + Send + Sync + 'static,
    frame_fragment_size: usize,
    enable_tls13: bool,
) {
    let (c_send, c_recv) = std::sync::mpsc::channel::<(
        Arc<SSLKeyLogFile>,
        Duplex<PipeReader, PipeWriter>,
        ClientConnection,
    )>();
    let (s_send, s_recv) = std::sync::mpsc::channel::<(
        Arc<SSLKeyLogFile>,
        Duplex<PipeReader, PipeWriter>,
        ServerConnection,
    )>();
    let (finish_send, finish_recv) = std::sync::mpsc::channel();
    let finish_send2 = finish_send.clone();
    let server_covert_signaling_secret =
        Arc::new(ServerCovertSignalingSecret::from_bytes([10u8; 16]));
    let server_pub_key = Arc::new(PinnedServerPubKey::from_der(PUBKEY_DER_BYTES.to_vec()));
    let covert_signaling_token = server_covert_signaling_secret.generate_token(1);
    std::thread::spawn(move || {
        loop {
            // Servers
            let (sslkeylogfile, server_pipe, ss) = match s_recv.recv() {
                Ok(x) => x,
                Err(_) => {
                    return;
                }
            };
            let (o, i) = tls_rewriter::new_pair(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 631)),
                ContextualInfo {
                    mode_specific: ModeSpecificContext::Server {
                        server_secret: server_covert_signaling_secret.clone(),
                    },
                    client_server_message_ordering: cso,
                    rocky_secret: ROCKY_SECRET,
                    tls_secret_provider: sslkeylogfile.clone(),
                },
                move |token| {
                    assert_eq!(token, covert_signaling_token);
                    (
                        Box::new(RandomContext {
                            generator: StdRng::seed_from_u64(1),
                            counter: 0,
                        }),
                        Box::new(RandomContext {
                            generator: StdRng::seed_from_u64(0),
                            counter: 0,
                        }),
                    )
                },
                |ctx| Box::new(server_compressor(ctx)),
                |ctx| Box::new(server_decompressor(ctx)),
                enable_tls13,
            );
            let read_state = ReadState::new(Box::new(i));
            let intercepted = Interceptor(read_state, o, server_pipe);
            let mut stream = StreamOwned::new(ss, intercepted);
            server(&mut DynReadAndWrite::from(&mut stream));
            finish_send2.send(()).unwrap();
        }
    });
    let finish_send2 = finish_send.clone();
    std::thread::spawn(move || {
        loop {
            // Clients
            let (sslkeylogfile, client_pipe, cs) = match c_recv.recv() {
                Ok(x) => x,
                Err(_) => {
                    return;
                }
            };
            let (o, i) = tls_rewriter::new_pair(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 631)),
                ContextualInfo {
                    rocky_secret: ROCKY_SECRET,
                    mode_specific: ModeSpecificContext::Client {
                        server_pub_key: server_pub_key.clone(),
                        covert_signaling_token,
                    },
                    client_server_message_ordering: cso,
                    tls_secret_provider: sslkeylogfile.clone(),
                },
                move |token| {
                    assert_eq!(token, covert_signaling_token);
                    (
                        Box::new(RandomContext {
                            generator: StdRng::seed_from_u64(1),
                            counter: 0,
                        }),
                        Box::new(RandomContext {
                            generator: StdRng::seed_from_u64(0),
                            counter: 0,
                        }),
                    )
                },
                |ctx| Box::new(client_compressor(ctx)),
                |ctx| Box::new(client_decompressor(ctx)),
                enable_tls13,
            );
            let read_state = ReadState::new(Box::new(i));
            let intercepted = Interceptor(read_state, o, client_pipe);
            let mut stream = StreamOwned::new(cs, intercepted);
            client(&mut DynReadAndWrite::from(&mut stream));
            finish_send2.send(()).unwrap();
        }
    });
    let tls12_cipher_suites = [
        rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];
    let tls13_cipher_suites = [
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    let cipher_suites: &[SupportedCipherSuite] = if tls_version == &rustls::version::TLS12 {
        &tls12_cipher_suites
    } else if tls_version == &rustls::version::TLS13 {
        &tls13_cipher_suites
    } else {
        panic!("Unsupported TLS version: {:?}", tls_version);
    };
    for _ in 0..num_times {
        let mut privkey_bytes = Cursor::new(PRIVKEY_BYTES);
        let privkey = rustls_pemfile::rsa_private_keys(&mut privkey_bytes)
            .unwrap()
            .pop()
            .unwrap();
        let mut pubkey_bytes = Cursor::new(PUBCERT_BYTES);
        let certs = rustls_pemfile::certs(&mut pubkey_bytes).unwrap();
        let sslkeylogfile = Arc::new(SSLKeyLogFile::new());
        let mut sc = ServerConfig::builder()
            .with_cipher_suites(cipher_suites)
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[tls_version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                certs.iter().cloned().map(rustls::Certificate).collect(),
                rustls::PrivateKey(privkey.clone()),
            )
            .unwrap();
        sc.key_log = Arc::new(SSLKeyLogFileAdapter(sslkeylogfile.clone()));
        let ss = ServerConnection::new(Arc::new(sc)).unwrap();
        let mut cc = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        cc.dangerous()
            .set_certificate_verifier(Arc::new(NullCertVerifier));
        cc.key_log = Arc::new(SSLKeyLogFileAdapter(sslkeylogfile.clone()));
        let cs = ClientConnection::new(Arc::new(cc), ServerName::try_from("example.com").unwrap())
            .unwrap();
        let (r1, w1) = os_pipe::pipe().unwrap();
        let (r2, w2) = os_pipe::pipe().unwrap();
        let client_pipe = Duplex {
            reader: r1,
            writer: w2,
            chunk_size: frame_fragment_size,
        };
        let server_pipe = Duplex {
            reader: r2,
            writer: w1,
            chunk_size: frame_fragment_size,
        };
        c_send
            .send((sslkeylogfile.clone(), client_pipe, cs))
            .unwrap();
        s_send
            .send((sslkeylogfile.clone(), server_pipe, ss))
            .unwrap();
        finish_recv.recv().unwrap();
        finish_recv.recv().unwrap();
    }
}

/// Run a testsuite from a given transcript.
///
/// The transcript looks like:
/// ```text
/// (Who is sending?, What data are they sending?, MASK)
/// ```
/// `MASK` should contain an `X` for every byte that should be replaced with covert bytes and a `.`
/// otherwise. `MASK` and the data to send MUST be the same length.
fn run_test_from_transcript(
    name: &str,
    cso: ClientServerMessageOrdering,
    evts: &[(TLSRewriterMode, &[u8], &[u8])],
    tls_version: &'static SupportedProtocolVersion,
    frame_fragment_size: usize,
    enable_tls13: bool,
) {
    initialize_logging_for_test(name);
    let evts: Vec<(TLSRewriterMode, Vec<(u8, DataProvenance)>)> = evts
        .into_iter()
        .map(|(mode, data, mask)| {
            assert_eq!(mask.len(), data.len(), "{}", String::from_utf8_lossy(data));
            (
                *mode,
                data.iter()
                    .copied()
                    .zip(mask.iter().copied())
                    .map(|(byte, mask)| {
                        (
                            byte,
                            match mask {
                                b'x' => DataProvenance::CovertData,
                                b'.' => DataProvenance::OvertData,
                                _ => panic!("Unexpected mask byte {mask:?}"),
                            },
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    #[derive(Clone, Copy, Debug)]
    enum DataProvenance {
        OvertData,
        CovertData,
    }
    struct State {
        body: Vec<(u8, DataProvenance)>,
        stopped_previewing: bool,
        mode: TLSRewriterMode,
        ioo: IncomingOrOutgoing,
    }
    impl State {
        /// Check that the bytes of `buf` match the expected message.
        ///
        /// If `check_all` is `true`, then check that _all_ bytes match the expected body bytes.
        /// Otherwise, just check that the _overt_ bytes match.
        fn check(&mut self, buf: &[u8], check_all: bool) {
            assert!(self.body.len() >= buf.len());
            for ((expected, provenance), actual) in
                self.body.iter().copied().zip(buf.iter().copied())
            {
                if matches!(
                    (provenance, check_all),
                    (_, true) | (DataProvenance::OvertData, _)
                ) {
                    assert_eq!(expected, actual, "{buf:?}, {:?}", &self.body[0..buf.len()]);
                }
            }
            self.body.drain(0..buf.len());
        }
    }
    type StateHandle = Arc<Mutex<State>>;
    struct SimpleCompressor {
        state_handle: StateHandle,
        context: Box<dyn CompressContext + Send + 'static>,
    }
    struct SimpleDecompressor {
        state_handle: StateHandle,
        context: Box<dyn DecompressContext + Send + 'static>,
    }
    impl CanPreviewPlaintextData for SimpleCompressor {
        fn preview(&mut self, buf: &[u8]) {
            let mut state = self.state_handle.lock();
            assert!(!state.stopped_previewing);
            state.check(buf, true);
        }
    }
    impl CanPreviewPlaintextData for SimpleDecompressor {
        fn preview(&mut self, buf: &[u8]) {
            let mut state = self.state_handle.lock();
            assert!(!state.stopped_previewing);
            state.check(buf, true);
        }
    }
    impl Compressor for SimpleCompressor {
        fn compress(&mut self, buf: &mut [u8]) {
            let mut state = self.state_handle.lock();
            state.stopped_previewing = true;

            assert!(buf.len() <= state.body.len());

            for (elt, (_, provenance)) in buf.iter_mut().zip(state.body.iter()) {
                match provenance {
                    DataProvenance::CovertData => {
                        let slice = std::slice::from_mut(elt);
                        self.context.recv_covert_bytes(slice);
                    }
                    DataProvenance::OvertData => (),
                }
            }

            // We want to check that the overt bytes are correct after mangling.
            state.check(buf, false);
        }
    }
    impl Decompressor for SimpleDecompressor {
        fn decompress(&mut self, buf: &mut [u8]) {
            let mut state = self.state_handle.lock();
            state.stopped_previewing = true;

            for (elt, (_, provenance)) in buf.iter().zip(state.body.iter()) {
                match provenance {
                    DataProvenance::CovertData => {
                        self.context.send_covert_bytes(std::slice::from_ref(elt));
                    }
                    DataProvenance::OvertData => (),
                }
            }

            state.check(buf, false);
        }
    }

    fn apply_read_and_write(
        mode: TLSRewriterMode,
        stream: &mut DynReadAndWrite,
        evts: &[(TLSRewriterMode, Vec<(u8, DataProvenance)>)],
    ) {
        for (from, content) in evts {
            if *from == mode {
                stream
                    .write_all(
                        &content
                            .iter()
                            .copied()
                            .map(|(byte, _)| byte)
                            .collect::<Vec<u8>>(),
                    )
                    .unwrap();
                stream.flush().unwrap();
            } else {
                let mut buf = vec![0; content.len()];
                stream.read_exact(&mut buf[..]).unwrap();
                for (actual, (expected, provenance)) in
                    buf.iter().copied().zip(content.iter().copied())
                {
                    if matches!(provenance, DataProvenance::OvertData) {
                        assert_eq!(actual, expected);
                    }
                }
            }
            eprintln!(
                "{mode:?} Finished {from:?}, {:?}",
                String::from_utf8_lossy(
                    content
                        .iter()
                        .copied()
                        .map(|(byte, _)| byte)
                        .collect::<Vec<u8>>()
                        .as_slice()
                ),
            );
        }
    }
    fn make_state(
        mode: TLSRewriterMode,
        evts: &[(TLSRewriterMode, Vec<(u8, DataProvenance)>)],
    ) -> (StateHandle, StateHandle) {
        let mut incoming = Vec::new();
        let mut outgoing = Vec::new();
        for (from, body) in evts.iter() {
            (if *from == mode {
                &mut outgoing
            } else {
                &mut incoming
            })
            .extend_from_slice(body);
        }
        (
            Arc::new(Mutex::new(State {
                body: incoming,
                stopped_previewing: false,
                mode,
                ioo: IncomingOrOutgoing::Incoming,
            })),
            Arc::new(Mutex::new(State {
                body: outgoing,
                stopped_previewing: false,
                mode,
                ioo: IncomingOrOutgoing::Outgoing,
            })),
        )
    }
    let client_finished = Arc::new(AtomicBool::new(false));
    let server_finished = Arc::new(AtomicBool::new(false));
    let client_finished2 = client_finished.clone();
    let server_finished2 = server_finished.clone();
    let (server_state_incoming, server_state_outgoing) = make_state(TLSRewriterMode::Server, &evts);
    let (client_state_incoming, client_state_outgoing) = make_state(TLSRewriterMode::Client, &evts);
    run_test(
        1,
        cso,
        tls_version,
        move |ctx| SimpleCompressor {
            state_handle: server_state_outgoing.clone(),
            context: ctx,
        },
        move |ctx| SimpleDecompressor {
            state_handle: server_state_incoming.clone(),
            context: ctx,
        },
        move |ctx| SimpleCompressor {
            state_handle: client_state_outgoing.clone(),
            context: ctx,
        },
        move |ctx| SimpleDecompressor {
            state_handle: client_state_incoming.clone(),
            context: ctx,
        },
        {
            let evts = evts.clone();
            move |stream| {
                apply_read_and_write(TLSRewriterMode::Client, stream, evts.as_slice());
                client_finished2.store(true, Ordering::SeqCst);
            }
        },
        move |stream| {
            apply_read_and_write(TLSRewriterMode::Server, stream, evts.as_slice());
            server_finished2.store(true, Ordering::SeqCst);
        },
        frame_fragment_size,
        enable_tls13,
    );
    assert!(client_finished.load(Ordering::SeqCst));
    assert!(server_finished.load(Ordering::SeqCst));
}

const TEST1_EVENTS: &[(TLSRewriterMode, &[u8], &[u8])] = &[
    (TLSRewriterMode::Server, b"message 1", b"x.x.x.x.x"),
    (TLSRewriterMode::Server, b"message 2", b"....xx..."),
    (
        TLSRewriterMode::Client,
        b"i am the cool client",
        b".xxxxx.......xxxx.xx",
    ),
    (
        TLSRewriterMode::Client,
        b"the client is extra super cool",
        b"............x.................",
    ),
    (
        TLSRewriterMode::Server,
        b"the server is even cooler",
        b"xxxxx.xxxx.....xxxxx.....",
    ),
    (
        TLSRewriterMode::Server,
        b"for realzies, tho",
        b"xx...xxxxx....xxx",
    ),
    (
        TLSRewriterMode::Client,
        b"yeah, right. u r a scrub",
        b".....xxxxx...xx..xxx....",
    ),
];

const TEST2_EVENTS: &[(TLSRewriterMode, &[u8], &[u8])] = &[
    (
        TLSRewriterMode::Client,
        b"FIRST COMMENT!!",
        b"xxxx.xx.xxxxxxx",
    ),
    (TLSRewriterMode::Server, b"message 1", b"..x.x...."),
    (TLSRewriterMode::Server, b"message 2", b"xxxxxxxx."),
    (
        TLSRewriterMode::Client,
        b"i am the cool client",
        b"xx.x.xxx.x.xxx.....x",
    ),
    (
        TLSRewriterMode::Client,
        b"the client is extra super cool",
        b"xx.xx.x.xx......xx.x...x.x.x.x",
    ),
    (
        TLSRewriterMode::Server,
        b"the server is even cooler",
        b".......x.x...............",
    ),
    (
        TLSRewriterMode::Server,
        b"for realzies, tho",
        b"....x.......x.xxx",
    ),
    (
        TLSRewriterMode::Client,
        b"yeah, right. u r a scrub",
        b"xxxxxxxx.x.x.xxxxxxxx.xx",
    ),
];

#[test]
fn test1_tls12() {
    let enable_tls13 = false;
    run_test_from_transcript(
        "test1_tls12",
        ClientServerMessageOrdering::NoSuchOrdering,
        TEST1_EVENTS,
        &rustls::version::TLS12,
        0,
        enable_tls13,
    );
}

#[test]
fn test2_tls12() {
    let enable_tls13 = false;
    run_test_from_transcript(
        "test2_tls12",
        ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage,
        TEST2_EVENTS,
        &rustls::version::TLS12,
        0,
        enable_tls13,
    );
}

#[test]
fn test1_tls13_nofragment() {
    let enable_tls13 = true;
    run_test_from_transcript(
        "test1_tls13_nofragment",
        ClientServerMessageOrdering::NoSuchOrdering,
        TEST1_EVENTS,
        &rustls::version::TLS13,
        0,
        enable_tls13,
    );
}

#[test]
fn test1_tls13_fragment() {
    let enable_tls13 = true;
    run_test_from_transcript(
        "test1_tls13_fragment_10",
        ClientServerMessageOrdering::NoSuchOrdering,
        TEST1_EVENTS,
        &rustls::version::TLS13,
        10,
        enable_tls13,
    );

    run_test_from_transcript(
        "test1_tls13_fragment_1",
        ClientServerMessageOrdering::NoSuchOrdering,
        TEST1_EVENTS,
        &rustls::version::TLS13,
        1,
        enable_tls13,
    );
}

#[test]
fn test2_tls13_nofragment() {
    let enable_tls13 = true;
    run_test_from_transcript(
        "test2_tls13_nofragment",
        ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage,
        TEST2_EVENTS,
        &rustls::version::TLS13,
        0,
        enable_tls13,
    );
}

#[test]
fn test2_tls13_fragment() {
    let enable_tls13 = true;
    run_test_from_transcript(
        "test2_tls13_fragment_10",
        ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage,
        TEST2_EVENTS,
        &rustls::version::TLS13,
        10,
        enable_tls13,
    );

    run_test_from_transcript(
        "test2_tls13_fragment_1",
        ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage,
        TEST2_EVENTS,
        &rustls::version::TLS13,
        1,
        enable_tls13,
    );
}

#[test]
fn test_error_leads_to_passthru() {
    let server_covert_signaling_secret =
        Arc::new(ServerCovertSignalingSecret::from_bytes([10u8; 16]));
    let covert_signaling_token = server_covert_signaling_secret.generate_token(1);
    let enable_tls13 = false;
    let (mut o, mut i) = new_pair(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), 0)),
        ContextualInfo {
            rocky_secret: RockySecret([4; 32]),
            mode_specific: ModeSpecificContext::Server {
                server_secret: server_covert_signaling_secret,
            },
            client_server_message_ordering: ClientServerMessageOrdering::NoSuchOrdering,
            tls_secret_provider: Arc::new(SSLKeyLogFile::new()),
        },
        move |token| {
            assert_eq!(token, covert_signaling_token);
            (
                Box::new(NullCompressContext),
                Box::new(NullDecompressContext),
            )
        },
        |_| Box::new(NullCompressor),
        |_| Box::new(NullDecompressor),
        enable_tls13,
    );
    // Rewrite an invalid incoming TLS record.
    const BUF0: [u8; 5] = [0xff; 5];
    let mut buf0 = BUF0;
    i.incoming_rewrite(&mut buf0);
    assert_eq!(buf0, BUF0);
    assert!(i.helper.shared_state.is_invalid());
    o.outgoing_rewrite(&mut buf0);
    assert_eq!(buf0, BUF0);
}

#[test]
fn parsing_unencrypted_tls_alerts() {
    use tls::{Alert, AlertDescription, AlertLevel};
    use tls_rewriter::errors::TLSRewriterError;

    // send Alerts back over the channel from the rewriter to check they were parsed correctly
    // Since the coroutine writing to the channel is on the same thread, we used a channel
    // with an infinite buffer to avoid the test deadlocking.
    let (tx, rx) = std::sync::mpsc::channel();

    let mut rewriter = balboa_coroutine::CoroutineBasedStreamRewriter::new(|mut gs| async move {
        loop {
            let parser = tls_rewriter::tls_record_parser::AboutToParseHeader::<()>::new(&mut gs);
            match parser.parse_header().await {
                Err(e) => tx.send(e).unwrap(),
                _ => panic!("not a TLS alert"),
            }
        }
    });

    // create TLS records containing alerts
    // 21: alert type
    // 3,3: TLS version 1.2
    // 0,2: TLS record of length 2
    // x,x: the TLS alert itself (severity, description)

    fn extract_saw_alert_error(err: TLSRewriterError) -> Option<tls::Alert> {
        match err {
            TLSRewriterError::SawUnencryptedAlert { alert } => Some(alert),
            _ => None,
        }
    }

    rewriter.rewrite(&mut [21, 3, 3, 0, 2, 1, 0]);
    assert_eq!(
        extract_saw_alert_error(rx.try_recv().unwrap()).unwrap(),
        Alert {
            level: AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        }
    );

    rewriter.rewrite(&mut [21, 3, 3, 0, 2, 2, 44]);
    assert_eq!(
        extract_saw_alert_error(rx.try_recv().unwrap()).unwrap(),
        Alert {
            level: AlertLevel::Fatal,
            description: AlertDescription::CertificateRevoked,
        }
    );

    rewriter.rewrite(&mut [21, 3, 3, 0, 2, 3, 12]);
    assert_eq!(
        extract_saw_alert_error(rx.try_recv().unwrap()).unwrap(),
        Alert {
            level: AlertLevel::Unsupported(3),
            description: AlertDescription::Unsupported(12),
        }
    );
}
