use scm_rights::ScmRightsExt;
use std::{
    io::{self, Read, Write},
    net::Ipv4Addr,
    os::unix::net::{UnixDatagram, UnixStream},
    path::Path,
};

pub struct Mickey {
    datagram_socket: UnixDatagram,
}

pub const MAX_PACKAGE_SIZE: usize = 1024 * 1024 * 10; // 10 MB
pub const MICKEY_MODE_RECEIVER: u8 = 1;
pub const MICKEY_MODE_SENDER: u8 = 2;

impl Mickey {
    pub fn connect(path: &impl AsRef<Path>) -> io::Result<Self> {
        let datagram_socket = UnixDatagram::unbound()?;
        datagram_socket.connect(path)?;
        Ok(Mickey { datagram_socket })
    }

    fn make_and_send_stream(&self, ip: Ipv4Addr, mode: u8) -> io::Result<UnixStream> {
        let (a, b) = UnixStream::pair()?;
        let mut buf = [0; 5];
        buf[0] = mode;
        buf[1..5].copy_from_slice(&ip.octets());
        self.datagram_socket.sendmsg_file(&a, &buf)?;
        Ok(b)
    }

    pub fn receiver(&self, ip: Ipv4Addr) -> io::Result<Receiver> {
        Ok(Receiver {
            stream: self.make_and_send_stream(ip, MICKEY_MODE_RECEIVER)?,
        })
    }
    pub fn sender(&self, ip: Ipv4Addr) -> io::Result<Sender> {
        Ok(Sender {
            stream: self.make_and_send_stream(ip, MICKEY_MODE_SENDER)?,
        })
    }
}

pub struct Receiver {
    stream: UnixStream,
}
impl Receiver {
    pub fn from_stream(stream: UnixStream) -> Self {
        Receiver { stream }
    }

    /// Receive a datagram. It's recommended (for performance) to reuse the same buf across calls.
    /// If this function returns an error, it's likely that the protocol is out-of-sync, which is
    /// why this function consumes itself, to force users to reconnect on `Err`.
    pub fn recv(mut self, buf: &mut Vec<u8>) -> io::Result<Self> {
        buf.clear();
        let mut size_buf = [0; 4];
        self.stream.read_exact(&mut size_buf)?;
        let size = u32::from_le_bytes(size_buf) as usize;
        if size > MAX_PACKAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Refusing to read {} >= {} bytes", size, MAX_PACKAGE_SIZE),
            ));
        }
        buf.resize(size, 0);
        self.stream.read_exact(&mut buf[..])?;
        Ok(self)
    }
}

pub struct Sender {
    stream: UnixStream,
}
impl Sender {
    pub fn from_stream(stream: UnixStream) -> Self {
        Sender { stream }
    }
    /// Send a vectored datagram.
    /// If this function returns an error, it's likely that the protocol is out-of-sync, which is
    /// why this function consumes itself, to force users to reconnect on `Err`.
    pub fn send_vectored(mut self, bufs: &[impl AsRef<[u8]>]) -> io::Result<Self> {
        // TODO: investigate using vectorized I/O on the socket itself.
        let len: usize = bufs.iter().map(|buf| buf.as_ref().len()).sum();
        if len > MAX_PACKAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Refusing to send {} >= {} bytes", len, MAX_PACKAGE_SIZE),
            ));
        }
        self.stream.write_all(&(len as u32).to_le_bytes())?;
        for buf in bufs.iter() {
            self.stream.write_all(buf.as_ref())?;
        }
        Ok(self)
    }

    /// Send a datagram.
    /// If this function returns an error, it's likely that the protocol is out-of-sync, which is
    /// why this function consumes itself, to force users to reconnect on `Err`.
    pub fn send(self, buf: &[u8]) -> io::Result<Self> {
        self.send_vectored(&[buf])
    }
}

#[test]
fn test_sender_and_receiver() {
    const MSGS: &'static [&'static [u8]] = &[
        b"hello there",
        b"",
        b"general kenobi",
        &[10; MAX_PACKAGE_SIZE],
    ];
    let (send, recv) = UnixStream::pair().unwrap();
    let send = Sender::from_stream(send);
    let mut recv = Receiver::from_stream(recv);
    std::thread::spawn(move || {
        let mut send = send;
        for msg in MSGS {
            send = send.send(msg).unwrap();
        }
    });
    let mut buf = Vec::new();
    for msg in MSGS {
        recv = recv.recv(&mut buf).unwrap();
        assert_eq!(&buf[..], &msg[..]);
    }
}
