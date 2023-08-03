//! Example code utilizing the `balboa` IPC protocol.

use balboa_ipc_protocol::ConnectionInfo;
use rand::Rng;
use std::{
    fs::File,
    io::{Error, Write},
    net::IpAddr,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    thread,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "testing_balboa_master", about = "Test balboa master")]
struct Opt {
    #[structopt(long, default_value = "balboa")]
    name: String,
    /// The UNIX socket path to listen on.
    #[structopt(long)]
    socket_path: PathBuf,
    /// The DER-encoded server public key. This REALLY OUGHT TO BE PROVIDED if this master will be
    /// servicing any clients.
    #[structopt(long)]
    server_pub_key_der_path: Option<PathBuf>,
    /// The pre-shared rocky secret to use. This should be 32 hex-encoded bytes.
    #[structopt(long, parse(try_from_str = parse_hex32))]
    secret: [u8; 32],
    /// The folder to write incoming and outgoing covert streams to.
    #[structopt(long)]
    destination: PathBuf,
}

fn parse_hex32(input: &str) -> Result<[u8; 32], String> {
    if input.len() != 64 {
        return Err(format!(
            "Expected the secret to be 32 hex-encoded bytes (so 64 characters long). Got {} chars",
            input.len()
        ));
    }
    let mut out = [0; 32];
    for (chunk, dst) in input.as_bytes().chunks_exact(2).zip(out.iter_mut()) {
        let chunk = std::str::from_utf8(chunk)
            .map_err(|e| format!("String sub-bytes are invalid utf-8: {}", e))?;
        *dst = u8::from_str_radix(chunk, 16).map_err(|e| format!("invalid hex bytes: {}", e))?;
    }
    Ok(out)
}

fn handle_client(
    pubkey: Option<Vec<u8>>,
    secret: [u8; 32],
    sock: UnixStream,
    mut destination: PathBuf,
) {
    use balboa_ipc_protocol::server::*;
    stallone::debug!("About to communicate connection info.");
    let (conn, ip) = Connection::new(sock, |_| ConnectionInfo {
        secret,
        der_formatted_server_pubkey: pubkey,
    })
    .unwrap();
    stallone::debug!("Communicated connection info");
    let mut rng = rand::thread_rng();
    match conn {
        Connection::ReceiveIncomingData(recv) => {
            stallone::debug!(
                "balboa master configured to RECV incoming data from",
                ip: IpAddr = ip,
            );
            destination.push(format!("incoming-{:X}.bin", rng.gen::<u128>()));
            let mut f = File::create(destination).unwrap();
            recv.handle_incoming_data(move |data| {
                stallone::debug!("Got bytes", n: usize = data.len());
                f.write_all(data).unwrap();
                f.flush().unwrap();
                Ok(())
            })
            .unwrap();
        }
        Connection::SendOutgoingData(send) => {
            destination.push(format!("outgoing-{:X}.bin", rng.gen::<u128>()));
            let f = File::create(destination).unwrap();
            stallone::debug!(
                "balboa master configured to SEND outgoing data to",
                ip: IpAddr = ip,
            );
            struct Provider {
                buf: Vec<u8>,
                f: File,
            }
            impl DataProvider for Provider {
                fn provide_data<F>(&mut self, n: usize, f: F) -> Result<(), Error>
                where
                    F: FnOnce(&[u8]) -> std::io::Result<()>,
                {
                    let mut rng = rand::thread_rng();
                    stallone::debug!("Providing bytes", n: usize = n);
                    self.buf.resize(n, 0);
                    rng.fill(self.buf.as_mut_slice());
                    self.f.write_all(&self.buf).unwrap();
                    self.f.flush().unwrap();
                    f(&self.buf)
                }
            }
            send.handle_outgoing_data(&mut Provider { buf: Vec::new(), f })
                .unwrap();
        }
    }
}

fn main() {
    let opt = Opt::from_args();
    stallone::initialize(Default::default());
    stallone::info!(
        "Balboa master name",
        secret: [u8; 32] = opt.secret,
        #[context(true)]
        balboa_master_name: String = opt.name,
    );
    let secret = opt.secret;
    let pubkey = opt
        .server_pub_key_der_path
        .map(|path| std::fs::read(path).expect("read server der pubkey"));
    let listener = UnixListener::bind(opt.socket_path).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                stallone::debug!("Accepted new connection");
                let pubkey = pubkey.clone();
                let name = opt.name.clone();
                let destination = opt.destination.clone();
                thread::spawn(move || {
                    stallone::info!(
                        "Balboa master name",
                        #[context(true)]
                        balboa_master_name: String = name,
                    );
                    handle_client(pubkey, secret, stream, destination)
                });
            }
            Err(err) => {
                panic!("failed to accept(): {}", err);
            }
        }
    }
}
