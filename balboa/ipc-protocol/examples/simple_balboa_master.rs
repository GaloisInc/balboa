//! Example code utilizing the `balboa` IPC protocol.

use balboa_ipc_protocol::ConnectionInfo;
use std::{
    io::{Error, Read, Write},
    net::IpAddr,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    thread,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "simple_balboa_master",
    about = "Be a balboa master. Read from stdin. Write to stdout."
)]
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

fn handle_client(pubkey: Option<Vec<u8>>, secret: [u8; 32], sock: UnixStream) {
    use balboa_ipc_protocol::server::*;
    stallone::debug!("About to communicate connection info.");
    let (conn, ip) = Connection::new(sock, |_| ConnectionInfo {
        secret,
        der_formatted_server_pubkey: pubkey,
    })
    .unwrap();
    stallone::debug!("Communicated connection info");
    match conn {
        Connection::ReceiveIncomingData(recv) => {
            stallone::debug!(
                "balboa master configured to RECV incoming data from",
                ip: IpAddr = ip,
            );
            recv.handle_incoming_data(move |data| {
                stallone::debug!("Got bytes", n: usize = data.len());
                let handle = std::io::stdout();
                let mut stdout = handle.lock();
                stdout.write_all(data).unwrap();
                stdout.flush().unwrap();
                Ok(())
            })
            .unwrap();
        }
        Connection::SendOutgoingData(send) => {
            stallone::debug!(
                "balboa master configured to SEND outgoing data to",
                ip: IpAddr = ip,
            );
            struct Provider {
                buf: Vec<u8>,
            }
            impl DataProvider for Provider {
                fn provide_data<F>(&mut self, n: usize, f: F) -> Result<(), Error>
                where
                    F: FnOnce(&[u8]) -> std::io::Result<()>,
                {
                    stallone::debug!("Providing bytes", n: usize = n);
                    self.buf.clear();
                    self.buf.extend(std::iter::repeat(0).take(n));
                    let handle = std::io::stdin();
                    handle.lock().read_exact(&mut self.buf[0..n]).unwrap();
                    f(&self.buf[0..n])
                }
            }
            send.handle_outgoing_data(&mut Provider { buf: Vec::new() })
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
                thread::spawn(move || {
                    stallone::info!(
                        "Balboa master name",
                        #[context(true)]
                        balboa_master_name: String = name,
                    );
                    handle_client(pubkey, secret, stream)
                });
            }
            Err(err) => {
                panic!("failed to accept(): {}", err);
            }
        }
    }
}
