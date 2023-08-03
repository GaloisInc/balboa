//! Simple injector which writes all `read`s and `write`s to the file specified by the env
//! variable `TRANSCRIPT_FILE`. Uses JSON serialization of the `Capture` enum.

use balboa_injection::{balboa_inject, BalboaInterceptors};
use balboa_rewriter::{IncomingRewriter, OutgoingRewriter, StreamChangeData};
use lazy_static::lazy_static;
use serde::Serialize;
use std::{
    fs::File,
    io::prelude::*,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
};

// Open the TRANSCRIPT file and use it as a global, which will be written to by the
// rewriters. Not that since there is one unique rewriter per port/ip combination, this
// file must be shared somehow, hence it is global.
lazy_static! {
    static ref TRANSCRIPT_FILE: Mutex<File> = {
        let name = std::env::var("TRANSCRIPT_FILE").expect("we need the TRANSCRIPT_FILE env var");
        let buf = File::create(&name).expect("couldn't open TRANSCRIPT_FILE");
        Mutex::new(buf)
    };
}

/// Rewriter which keeps track of IP and Port for serialization.
struct RecorderRewriter {
    ip: IpAddr,
    port: u16,
}

/// Transcript entry which gets serialized as JSON to the file at TRANSCRIPT_FILE.
#[derive(Serialize)]
enum Capture {
    Incoming {
        ip: IpAddr,
        port: u16,
        data: Vec<u8>,
    },
    Outgoing {
        ip: IpAddr,
        port: u16,
        data: Vec<u8>,
    },
}

impl IncomingRewriter for RecorderRewriter {
    fn incoming_rewrite(&mut self, buf: &mut [u8]) -> StreamChangeData {
        let entry = Capture::Incoming {
            ip: self.ip,
            port: self.port,
            data: buf.to_vec(),
        };
        let mut s = serde_json::to_string(&entry).unwrap();
        s.push('\n');
        let mut f = TRANSCRIPT_FILE.lock().unwrap();
        f.write_all(s.as_bytes()).unwrap();
        StreamChangeData::default()
    }
}

impl OutgoingRewriter for RecorderRewriter {
    fn outgoing_rewrite(&mut self, buf: &mut [u8]) {
        let entry = Capture::Outgoing {
            ip: self.ip,
            port: self.port,
            data: buf.to_vec(),
        };
        let mut s = serde_json::to_string(&entry).unwrap();
        s.push('\n');
        let mut f = TRANSCRIPT_FILE.lock().unwrap();
        f.write_all(s.as_bytes()).unwrap();
    }
}

struct Recorder;
impl BalboaInterceptors for Recorder {
    fn initialize() -> Self {
        Recorder
    }

    /// RecorderRewriter tracks all ports and IPs.
    fn listen_on_addr(&self, _remote: SocketAddr) -> bool {
        true
    }

    /// Create a new RecorderRewriter for each IP/port combination.
    fn rewriters_for_tcp_client(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        let ip = remote.ip();
        let port = remote.port();
        Some((
            Box::new(RecorderRewriter { ip, port }),
            Box::new(RecorderRewriter { ip, port }),
        ))
    }

    /// Create a new RecorderRewriter for each IP/port combination.
    fn rewriters_for_tcp_server(
        &self,
        remote: SocketAddr,
    ) -> Option<(
        Box<dyn IncomingRewriter + Send>,
        Box<dyn OutgoingRewriter + Send>,
    )> {
        let ip = remote.ip();
        let port = remote.port();
        Some((
            Box::new(RecorderRewriter { ip, port }),
            Box::new(RecorderRewriter { ip, port }),
        ))
    }
}

balboa_inject!(Recorder);
