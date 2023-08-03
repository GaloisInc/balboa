#![deny(unused_must_use)]
use crate::mickey_threads::ThreadSpawner;
use balboa_covert_signaling_types::{
    Address, Capability, CovertSignalingIdentity, Identity, PinnedServerPubKey, RockySecret,
    ServerCovertSignalingSecret,
};
use bytes::Bytes;
use crossbeam::channel;
use mickey_balboa_ipc::{
    chunk_allocator::ChunkAllocatorWriter,
    incoming::{IncomingWindowConsumer, IncomingWindowController},
    outgoing::OutgoingQueueProducer,
    types::{BalboaMickeyIPCMessage, HostId, MAX_BALBOA_MICKEY_IPC_MESSAGE_LENGTH},
};
use parking_lot::{Mutex, RwLock};
use scm_rights::ScmRightsExt;
use stallone::LoggableMetadata;
use stallone_common::{positioned_io_result, PositionedIOError, PositionedIOResult};
use std::{
    collections::{hash_map::Entry, HashMap},
    fs::File,
    hash::Hash,
    io::{Error, ErrorKind, Read, Seek, Write},
    net::Ipv4Addr,
    os::unix::{
        fs::OpenOptionsExt,
        io::{AsRawFd, FromRawFd},
        net::{UnixDatagram, UnixStream},
    },
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};
use structopt::StructOpt;
use systemd_ready::systemd_notify_ready;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[macro_use]
mod mickey_threads;

mod chunk_wire_protocol;
mod incoming;
mod outgoing;

pub(crate) struct DefaultMap<K: Hash + Eq, V: Clone>(RwLock<HashMap<K, V>>);
impl<K: Hash + Eq, V: Clone> DefaultMap<K, V> {
    pub(crate) fn new() -> Self {
        DefaultMap(RwLock::new(HashMap::new()))
    }
    pub(crate) fn get<E, IfEmpty: FnOnce() -> Result<V, E>>(
        &self,
        k: K,
        if_empty: IfEmpty,
    ) -> Result<V, E> {
        if let Some(x) = self.0.read().get(&k) {
            return Ok(x.clone());
        }
        match self.0.write().entry(k) {
            Entry::Occupied(x) => Ok(x.get().clone()),
            Entry::Vacant(x) => Ok(x.insert(if_empty()?).clone()),
        }
    }
}

#[derive(StructOpt)]
#[structopt(name = "mickey-server", about = "Mickey orchestrates Balboa instances")]
struct Opt {
    /// Path to the Mickey state directory, will be created if it
    /// doesn't exist already. Will be used to store various bits of
    /// Mickey persistent state, including mickey_master.sock, and
    /// balboa_mickey_ipc.sock.
    #[structopt(long)]
    state_directory: PathBuf,

    /// Path to the pinned server key to use for this Mickey.
    #[structopt(long)]
    pinned_server_key: PathBuf,

    #[structopt(long)]
    vlc_launcher: PathBuf,

    /// A path to a JSON map from IP addresses to hostnames
    #[structopt(long)]
    ip_hostname_map: PathBuf,

    /// The IPv4 address to use in capabilities to connect to this Mickey.
    #[structopt(long)]
    address: Ipv4Addr,

    /// The hostname to use for this Mickey.
    #[structopt(long)]
    hostname: String,
}

struct NodeState {
    outgoing_packages: channel::Sender<Bytes>,
    incoming_packages: channel::Receiver<Vec<Bytes>>,
    incoming_window_file: File,
    outgoing_queue_file: File,
}

struct GlobalState {
    thread_spawner: ThreadSpawner,
    vlc_launcher: PathBuf,
    state_directory: PathBuf,
    host_ip_map: HashMap<Ipv4Addr, String>,
    host_ids: DefaultMap<Ipv4Addr, HostId>,
    next_host_id: AtomicU32,
    node_states: DefaultMap<Ipv4Addr, Arc<NodeState>>,
    chunks: Arc<Mutex<ChunkAllocatorWriter>>,
    identity: Identity,
    address: Address,
    pinned_server_key: PinnedServerPubKey,
}
impl GlobalState {
    fn new(
        host_ip_map: HashMap<Ipv4Addr, String>,
        vlc_launcher: PathBuf,
        state_directory: PathBuf,
        address: Address,
        identity: Identity,
        pinned_server_key: PinnedServerPubKey,
    ) -> PositionedIOResult<Arc<Self>> {
        let services = Arc::new(GlobalState {
            thread_spawner: ThreadSpawner::new(),
            vlc_launcher,
            state_directory,
            host_ip_map,
            host_ids: DefaultMap::new(),
            next_host_id: AtomicU32::new(1),
            node_states: DefaultMap::new(),
            chunks: Arc::new(Mutex::new(ChunkAllocatorWriter::new()?)),
            address,
            identity,
            pinned_server_key,
        });
        Ok(services)
    }
    fn host_id(&self, ip: Ipv4Addr) -> HostId {
        self.host_ids
            .get::<(), _>(ip, || {
                let out = HostId(self.next_host_id.fetch_add(1, Ordering::Relaxed));
                stallone::info!(
                    "Picked host ID for IP",
                    host_id: HostId = out,
                    ip: Ipv4Addr = ip,
                );
                Ok(out)
            })
            .expect("This cannot fail")
    }
    fn node_state(
        self: &Arc<GlobalState>,
        ip_addr: Ipv4Addr,
    ) -> PositionedIOResult<Arc<NodeState>> {
        self.node_states.get::<PositionedIOError, _>(ip_addr, || {
            let host_id = self.host_id(ip_addr);
            let incoming_window = IncomingWindowController::new()?;
            let outgoing_queue = OutgoingQueueProducer::new()?;
            let (outgoing_packages_s, outgoing_packages_r) = channel::bounded(25);
            let (incoming_packages_s, incoming_packages_r) = channel::bounded(25);
            let (incoming_chunks_s, incoming_chunks_r) = channel::bounded(50);
            let (outgoing_chunks_s, outgoing_chunks_r) = channel::bounded(50);
            let incoming_window_file = positioned_io_result!(incoming_window.file().try_clone())?;
            let outgoing_queue_file = positioned_io_result!(outgoing_queue.file().try_clone())?;
            // TODO: burning two threads for this purpose is probably overkill.
            spawn_thread!(
                self.thread_spawner,
                thread OutgoingChunkPackageAdater {
                    host_id: HostId = host_id,
                },
                move || {
                    let _ = chunk_wire_protocol::process_outgoing_chunks(outgoing_packages_r, outgoing_chunks_s);
                }
            );
            spawn_thread!(
                self.thread_spawner,
                thread IncomingChunkPackageAdapter {
                    host_id: HostId = host_id,
                },
                move || {
                    let _ = chunk_wire_protocol::process_incoming_chunks(incoming_packages_s, incoming_chunks_r);
                }
            );
            let chunks = self.chunks.clone();
            let incoming_window_consumer = IncomingWindowConsumer::new(positioned_io_result!(incoming_window_file.try_clone())?)?;
            spawn_thread!(
                self.thread_spawner,
                thread OutgoingChunksController {
                    host_id: HostId = host_id,
                },
                move || {
                    let _ = outgoing::outgoing_thread(host_id, chunks, incoming_window_consumer, outgoing_queue, outgoing_chunks_r);
                }
            );
            let chunks = self.chunks.clone();
            spawn_thread!(
                self.thread_spawner,
                thread IncomingChunksController {
                    host_id: HostId = host_id,
                },
                move || {
                    let _ = incoming::incoming_thread(host_id, chunks, incoming_window, incoming_chunks_s);
                }
            );
            // TODO: control the VLCs, probably from the incoming window.
            let host_name = self.host_ip_map.get(&ip_addr).map(|x| x.clone()).unwrap_or_else(|| {
                log::error!("Unable to lookup hostname for ip {:?}", ip_addr);
                // We'll try do the best we can. This should only happen in misconfiguration,
                // since we only try to get node info after successful covert signaling.
                format!("icecast.{:?}.sslip.io", ip_addr)
            });
            let mut cmd = Command::new(&self.vlc_launcher).arg(host_name)
                .spawn()
                .unwrap();
            std::thread::spawn(move || {
                // Reap the zombie process.
                let _ = cmd.wait();
            });
            Ok(Arc::new(NodeState {
                outgoing_packages: outgoing_packages_s,
                incoming_packages: incoming_packages_r,
                incoming_window_file,
                outgoing_queue_file,
            }))
        })
    }

    /// Retrieve the ID to use for the next capability to be generated
    /// by this Mickey.
    /// IDs have a maximum value of MAX_COVERT_SIGNALING_IDENTITY and
    /// are retrieved from the previously stably stored value on disk.
    fn next_capability_id(&self) -> Result<CovertSignalingIdentity, std::io::Error> {
        let capability_id_path = self.state_directory.join("next_capability_id");
        if !capability_id_path.exists() {
            let next_capability_id: CovertSignalingIdentity = 2;
            std::fs::write(capability_id_path, &next_capability_id.to_be_bytes())?;
            return Ok(1);
        }

        let mut handle = std::fs::File::options()
            .read(true)
            .write(true)
            .open(capability_id_path)?;
        let mut buf = Vec::new();
        handle.read_to_end(&mut buf)?;

        let next_capability_id =
            CovertSignalingIdentity::from_be_bytes(buf.try_into().map_err(|_| {
                Error::new(
                    ErrorKind::InvalidData,
                    "Unable to read next_capability as integer.",
                )
            })?);
        handle.rewind()?;
        handle.write(&(next_capability_id + 1).to_be_bytes())?;
        Ok(next_capability_id)
    }

    /// Generate a new capability for this Mickey.
    /// Automatically retrives and uses the next available capability ID.
    fn new_capability(&self) -> PositionedIOResult<Capability> {
        let capability_id = self
            .next_capability_id()
            .expect("Unable to generate next capability ID.");
        let new_capability = self.identity.generate_capability(
            capability_id,
            self.pinned_server_key.clone(),
            self.address.clone(),
        );
        Ok(new_capability)
    }
}

#[derive(Debug, Clone, LoggableMetadata)]
enum MickeyMode {
    Receiver,
    Sender,
}

fn run_mickey_connection_sender(state: Arc<GlobalState>, ip: Ipv4Addr, stream: UnixStream) {
    let mut recv = mickey_protocol::Receiver::from_stream(stream);
    let host_id = state.host_id(ip);
    match state.node_state(ip) {
        Ok(node_state) => loop {
            let mut buf = Vec::new();
            match recv.recv(&mut buf) {
                Ok(recv2) => {
                    recv = recv2;
                    stallone::debug!(
                        "Got package from Rocky plugin. Sending",
                        len: usize = buf.len(),
                    );
                    let buf_len = buf.len();
                    if let Err(_) = node_state.outgoing_packages.send(buf.into()) {
                        log::warn!("Unable to send package of length {} to {:?}", buf_len, ip);
                        return;
                    }
                    stallone::debug!("Successfully sent package");
                }
                Err(e) => {
                    log::error!("error recving data from mickey {:?}: {}", ip, e);
                    return;
                }
            }
        },
        Err(e) => {
            log::error!("Error getting node state for {:?}/{:?}: {}", ip, host_id, e);
        }
    }
}

fn run_mickey_connection_receiver(state: Arc<GlobalState>, ip: Ipv4Addr, stream: UnixStream) {
    let mut send = mickey_protocol::Sender::from_stream(stream);
    let host_id = state.host_id(ip);
    match state.node_state(ip) {
        Ok(node_state) => loop {
            stallone::debug!("Going to wait for incoming package");
            let inc_pkg = node_state.incoming_packages.recv();
            stallone::debug!("Waited for incoming package.");
            match inc_pkg {
                Ok(pkg) => {
                    // TODO: if we fail to send this on the stream, then we should probably buffer it until we can
                    // see a stream that will let us send thie package. Otherwise we lose a package.
                    stallone::debug!("Starting to send recv'd package");
                    match send.send_vectored(&pkg[..]) {
                        Ok(send2) => {
                            stallone::debug!("Finished sending recv'd package");
                            send = send2;
                        }
                        Err(e) => {
                            log::error!("Error sending package to {:?}/{:?}: {}", ip, host_id, e,);
                            return;
                        }
                    }
                }
                Err(_) => {
                    // This means that this thread should exit since there's nothing more to send.
                    return;
                }
            }
        },
        Err(e) => {
            log::error!("Error getting node state for {:?}/{:?}: {}", ip, host_id, e);
        }
    }
}

fn mickey_server(services: Arc<GlobalState>, socket: UnixDatagram) {
    let mut buf = [0; 64];
    loop {
        match socket.recvmsg_file(&mut buf[..]) {
            Ok((fd, 5)) => {
                let ip = Ipv4Addr::from([buf[1], buf[2], buf[3], buf[4]]);
                let cmd = match buf[0] {
                    mickey_protocol::MICKEY_MODE_RECEIVER => MickeyMode::Receiver,
                    mickey_protocol::MICKEY_MODE_SENDER => MickeyMode::Sender,
                    cmd => {
                        log::error!(
                            "When processing mickey connection for IP {:?} got unknown command {}",
                            ip,
                            cmd
                        );
                        continue;
                    }
                };
                let unix_stream = match fd {
                    Some(fd) => {
                        // SAFETY: the fd comes from SCM_RIGHTS
                        unsafe { UnixStream::from_raw_fd(fd) }
                    }
                    None => {
                        log::error!(
                            "Mickey connection {:?} {:?} didn't get file descriptor",
                            ip,
                            cmd
                        );
                        continue;
                    }
                };
                let services2 = services.clone();
                match cmd {
                    MickeyMode::Sender => spawn_thread!(
                        services.thread_spawner,
                        thread MickeySender {
                            destination_ip: Ipv4Addr = ip,
                        },
                        move || run_mickey_connection_sender(services2, ip, unix_stream)
                    ),
                    MickeyMode::Receiver => spawn_thread!(
                        services.thread_spawner,
                        thread MickeyReceiver {
                            source_ip: Ipv4Addr = ip,
                        },
                        move || run_mickey_connection_receiver(services2, ip, unix_stream)
                    ),
                }
            }
            Ok((_, n)) => {
                log::error!(
                    "Expected 5 bytes in buffer for mickey connction. Got {} bytes",
                    n
                );
            }
            Err(e) => {
                log::error!("Error accepting mickey connection: {}", e);
            }
        }
    }
}

fn balboa_mickey_ipc_server(services: Arc<GlobalState>, balboa_mickey_ipc_sock: UnixDatagram) {
    // TODO: better error handling.
    // TODO: move message decode to mickey-balboa-ipc, and test it.
    let mut buf = vec![0; MAX_BALBOA_MICKEY_IPC_MESSAGE_LENGTH];
    loop {
        let (fd, len) = balboa_mickey_ipc_sock.recvmsg_file(&mut buf[..]).unwrap();
        if let None = fd {
            log::error!("[balboa_mickey_ipc_server] Got request without file");
            continue;
        }
        let fd = fd.expect("We just checked it");
        let sender = unsafe { UnixDatagram::from_raw_fd(fd) };
        let message = match bincode::deserialize::<BalboaMickeyIPCMessage>(&buf[..len]) {
            Ok(m) => m,
            Err(e) => {
                log::error!("Unable to deserialize IPC message: {:#?}", e);
                continue;
            }
        };
        log::debug!("[balboa_mickey_ipc_server] got request");
        // TODO: when sending files, should we be doing it non-blocking? Probably. Or with a timeout.
        if let BalboaMickeyIPCMessage::GetChunksFile = message {
            // Get chunks file
            #[derive(Clone, Copy)]
            struct RawFd(std::os::unix::io::RawFd);
            impl std::os::unix::io::AsRawFd for RawFd {
                fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
                    self.0
                }
            }
            // Technically this is racy, but we don't want to hold the chunks lock while we're
            // sending.
            let raw_fd = RawFd(services.chunks.lock().file().as_raw_fd());
            sender.sendmsg_file(&raw_fd, &[0][..]).unwrap();
            log::debug!("[balboa_mickey_ipc_server] chunk file request");
            continue;
        }
        let ip = match message {
            BalboaMickeyIPCMessage::GetIncomingFile(ip) => ip,
            BalboaMickeyIPCMessage::GetOutgoingFile(ip) => ip,
            _ => unreachable!("We already covered the remaining case."),
        };
        let node_state = services.node_state(ip).unwrap();
        let host_id = services.host_id(ip);
        sender
            .sendmsg_file(
                match message {
                    BalboaMickeyIPCMessage::GetIncomingFile(_) => {
                        // Get incoming file
                        log::debug!("[balboa_mickey_ipc_server] incoming file {:?}", ip);
                        &node_state.incoming_window_file
                    }
                    BalboaMickeyIPCMessage::GetOutgoingFile(_) => {
                        // Get outgoing file
                        log::debug!("[balboa_mickey_ipc_server] outgoing file {:?}", ip);
                        &node_state.outgoing_queue_file
                    }
                    _ => unreachable!("We already validated the command."),
                },
                &host_id.0.to_le_bytes()[..],
            )
            .unwrap();
    }
}

// Callers need to be sure to set ROCKY_BASE_SECRETS_PATH
fn main() {
    stderrlog::new()
        .verbosity(3) // set to 3 for debug, 2 for info
        .timestamp(stderrlog::Timestamp::Millisecond)
        .color(stderrlog::ColorChoice::Auto)
        .init()
        .unwrap();
    // TODO: cleanup threads.
    stallone::initialize(Default::default());
    let expanded_args = argfile::expand_args(argfile::parse_response, argfile::PREFIX)
        .expect("Unable to preprocess CLI arguments for argfiles.");
    let args: Opt = Opt::from_clap(&Opt::clap().get_matches_from(expanded_args));

    if !args.state_directory.is_dir() {
        std::fs::create_dir_all(&args.state_directory).expect("Unable to create state directory.");
    }

    let host_ip_map = serde_json::from_slice(
        &std::fs::read(&args.ip_hostname_map).expect("Can read IP hostname map path"),
    )
    .expect("can parse IP hostname map");

    let server_secret = if args.state_directory.join("server_secret").exists() {
        let raw = std::fs::read(args.state_directory.join("server_secret"))
            .expect("Unable to read secret key.");
        ServerCovertSignalingSecret::from_bytes(raw.try_into().unwrap())
    } else {
        // TODO: Generate on demand.
        ServerCovertSignalingSecret::from_bytes([0xae; 16])
    };

    let rocky_secret = if args.state_directory.join("rocky_secret").exists() {
        let raw = std::fs::read(args.state_directory.join("rocky_secret"))
            .expect("Unable to read shared key.");
        RockySecret(raw.try_into().unwrap())
    } else {
        // TODO: Generate on demand.
        RockySecret([0xae; 32])
    };
    let address = Address { ip: args.address };
    let identity = Identity {
        hostname: args.hostname,
        server_secret,
        rocky_secret,
    };
    let pinned_server_key = PinnedServerPubKey::from_der(
        std::fs::read(args.pinned_server_key).expect("Unable to read pinned server key."),
    );
    let services = GlobalState::new(
        host_ip_map,
        args.vlc_launcher.clone(),
        args.state_directory.clone(),
        address,
        identity,
        pinned_server_key,
    )
    .unwrap();
    let services2 = services.clone();
    let balboa_mickey_ipc_sock = UnixDatagram::bind(
        args.state_directory
            .join("balboa_mickey_ipc.sock")
            .as_path(),
    )
    .unwrap();
    spawn_thread!(
        services.thread_spawner,
        thread BalboaMickeyIPCServer {},
        move || {
            balboa_mickey_ipc_server(services2, balboa_mickey_ipc_sock);
        }
    );
    let services2 = services.clone();
    let mickey_socket =
        UnixDatagram::bind(args.state_directory.join("mickey_master.sock").as_path()).unwrap();
    spawn_thread!(
        services.thread_spawner,
        thread MickeyServer {},
        move || {
            mickey_server(services2, mickey_socket);
        }
    );
    systemd_notify_ready().expect("systemd_notify_ready");
    services.thread_spawner.wait_for_all();
    log::info!("Mickey server gracefully exiting.");
}

#[cfg(test)]
mod test {
    use super::*;
    use std::ops::Deref;
    use temp_testdir::TempDir;

    struct TestState {
        pub state: Arc<GlobalState>,
        temp_dir: TempDir,
    }

    impl TestState {
        fn new() -> Self {
            let temp_dir = TempDir::default();
            let test_server_secret = ServerCovertSignalingSecret::from_bytes([0xae; 16]);
            let test_rocky_secret = RockySecret([0xae; 32]);

            let test_identity: Identity = Identity {
                hostname: "test".to_string(),
                server_secret: test_server_secret,
                rocky_secret: test_rocky_secret,
            };
            let test_address = Address {
                ip: Ipv4Addr::new(127, 0, 0, 1),
            };
            let test_pinned_server_key = PinnedServerPubKey::from_der(vec![]);
            let mut vlc_spawner = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .mode(0o700)
                .open(temp_dir.as_ref().to_path_buf().join("vlc-spawner.sh"))
                .expect("Unable to create VLC spawner script.");
            vlc_spawner
                .write_all(b"#! /bin/sh\ntrue")
                .expect("Unable to write to VLC spawner script.");

            let state = GlobalState::new(
                HashMap::new(),
                PathBuf::from(temp_dir.as_ref().to_path_buf().join("vlc-spawner.sh")),
                temp_dir.as_ref().to_path_buf(),
                test_address,
                test_identity,
                test_pinned_server_key,
            )
            .unwrap();

            TestState { state, temp_dir }
        }

        fn start_protocol_server(&self) -> UnixDatagram {
            let (sender, receiver) = UnixDatagram::pair().unwrap();
            let state2 = self.state.clone();
            spawn_thread!(
                self.state.thread_spawner,
                thread MickeyServer {},
                move || {
                    mickey_server(state2, receiver);
                }
            );

            sender
        }
    }

    impl Deref for TestState {
        type Target = GlobalState;

        fn deref(&self) -> &Self::Target {
            &self.state
        }
    }

    #[test]
    fn test_initial_capability_id() {
        let state = TestState::new();
        let i = state.next_capability_id().unwrap();
        assert!(i == 1);
    }

    #[test]
    fn test_multiple_capabilities() {
        let state = TestState::new();
        for i in 1..5 {
            let capability_id = state.next_capability_id().unwrap();
            assert!(capability_id == i);
        }
    }
}
