//! This crate defines an IPC protocol over UNIX sockets that `balboa` uses to
//! talk to an external process.
//!
//! When `balboa` starts intercepting a TCP connection, it makes two connections
//! to the external process's UNIX socket: one for receiving outgoing data, one
//! for sending incoming data. These streams are each represented by structs in
//! the `client` and `server` modules.

use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::IpAddr,
    os::unix::net::UnixStream,
};

/// Authentication information for the Balboa connection
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// The shared Balboa symmetric secret key which should be used to secure the connection.
    pub secret: [u8; 32],
    /// The DER-formatted public signature key which will be used by the server to sign the TLS
    /// handshake.
    ///
    /// If `None`, no server key verification will be performed.
    /// **THIS IS DANGEROUS. ONLY USE THIS OPTION FOR TESTING!!**
    pub der_formatted_server_pubkey: Option<Vec<u8>>,
}

pub mod client {
    //! IPC protocol for the client (running within the injected `balboa`
    //! instance).

    use super::*;

    /// Returns the shared 32-byte secret from `socket`, as well as the DER-formatted pinned
    /// public key.
    fn setup_initial_state(
        socket: &mut UnixStream,
        initial_message: &messages::InitialClientMessage,
    ) -> bincode::Result<ConnectionInfo> {
        let serialized_message = bincode::serialize(initial_message)?;
        stallone::debug!("Sending initial message to balboa master");
        socket.write_all(serialized_message.as_ref())?;
        socket.flush()?;
        stallone::debug!("Sent initial message to balboa master. Reading response.");
        let resp = bincode::deserialize_from(socket)?;
        stallone::debug!("Read response from balboa master.");
        Ok(resp)
    }

    /// A connection used for sending incoming data.
    pub struct SendIncomingData {
        socket: UnixStream,
    }

    impl SendIncomingData {
        /// Constructs a new connection for sending incoming data to the IPC
        /// server.
        ///
        /// `remote_ip` is the IP address for which the external connection was
        /// established. Returns both the new `SendIncomingData` object
        /// alongside the shared 32-byte secret.
        pub fn new(
            mut socket: UnixStream,
            remote_ip: IpAddr,
        ) -> bincode::Result<(Self, ConnectionInfo)> {
            let ci = setup_initial_state(
                &mut socket,
                &messages::InitialClientMessage::IncomingDataFrom(remote_ip),
            )?;
            Ok((SendIncomingData { socket }, ci))
        }

        /// Sends `buf` to the IPC server.
        pub fn send_incoming_data(&mut self, buf: &[u8]) -> std::io::Result<()> {
            /*let len_buf = (buf.len() as u64).to_le_bytes();
            let mut len: &[u8] = &len_buf[..];
            while !(len.is_empty() && buf.is_empty()) {
                let n = self
                    .socket
                    .write_vectored(&[IoSlice::new(len), IoSlice::new(buf)])?;
                let len_len = n.min(len.len());
                len = &len[len_len..];
                let buf_len = n - len_len;
                buf = &buf[buf_len..];
            }*/
            stallone::debug!(
                "Sending incoming data to balboa master",
                len: usize = buf.len()
            );
            self.socket
                .write_all(&(buf.len() as u64).to_le_bytes()[..])?;
            self.socket.write_all(buf)?;
            self.socket.flush()?;
            Ok(())
        }
    }

    /// A connection used for receiving outgoing data.
    pub struct ReceiveOutgoingData {
        socket: UnixStream,
    }

    impl ReceiveOutgoingData {
        /// Constructs a new connection for receiving outgoing data from the IPC
        /// server.
        ///
        /// `remote_ip` is the IP address for which the external connection was
        /// established. Returns both the new `ReceiveOutgoingData` object
        /// alongside the shared 32-byte secret.
        pub fn new(
            mut socket: UnixStream,
            remote_ip: IpAddr,
        ) -> bincode::Result<(Self, ConnectionInfo)> {
            let ci = setup_initial_state(
                &mut socket,
                &messages::InitialClientMessage::OutgoingDataFor(remote_ip),
            )?;
            Ok((ReceiveOutgoingData { socket }, ci))
        }

        /// Reads from the IPC server into `buf`.
        pub fn recv_outgoing_data(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
            stallone::debug!(
                "Receiving incoming data from balboa master",
                len: usize = buf.len()
            );
            self.socket
                .write_all(&(buf.len() as u64).to_le_bytes()[..])?;
            self.socket.flush()?;
            self.socket.read_exact(buf)?;
            Ok(())
        }
    }
}

pub mod server {
    //! IPC protocol for the server (running external to `balboa`).
    //!
    //! NOTE: the server should be LOW-LATENCY. Any latency in handling responses will be observed
    //! by the adversary. Care should be taken to avoid locks or memory allocation, because these
    //! will directly translate to increased latency.

    use super::*;
    use std::net::IpAddr;

    /// The type of connection that the server receives.
    pub enum Connection {
        ReceiveIncomingData(ReceiveIncomingData),
        SendOutgoingData(SendOutgoingData),
    }

    impl Connection {
        /// Accept a new connection over `socket`.
        ///
        /// `get_connection_info` looks up the connection info given the
        /// machine to communicate with.
        pub fn new<F>(
            mut socket: UnixStream,
            get_connection_info: F,
        ) -> bincode::Result<(Self, IpAddr)>
        where
            F: FnOnce(IpAddr) -> ConnectionInfo,
        {
            stallone::debug!("Reading initial message from balboa client");
            let msg = bincode::deserialize_from(&mut socket)?;
            stallone::debug!(
                "Got initial message from balboa client",
                msg: messages::InitialClientMessage = msg,
            );
            let ip = match &msg {
                messages::InitialClientMessage::IncomingDataFrom(ip) => ip,
                messages::InitialClientMessage::OutgoingDataFor(ip) => ip,
            };
            let ci = get_connection_info(*ip);
            stallone::debug!("Sending connection info back to balboa client");
            let serialized_message = bincode::serialize(&ci)?;
            socket.write_all(serialized_message.as_ref())?;
            socket.flush()?;
            stallone::debug!("Sent connection info back to balboa client");
            Ok((
                match msg {
                    messages::InitialClientMessage::IncomingDataFrom(_) => {
                        Connection::ReceiveIncomingData(ReceiveIncomingData { socket })
                    }
                    messages::InitialClientMessage::OutgoingDataFor(_) => {
                        Connection::SendOutgoingData(SendOutgoingData { socket })
                    }
                },
                *ip,
            ))
        }
    }

    /// A connection that will be yielding incoming data from the remote IP address.
    pub struct ReceiveIncomingData {
        socket: UnixStream,
    }

    impl ReceiveIncomingData {
        /// Called with received data when it is received. If `f` returns `Err`,
        /// then this function will return that `Err`. Otherwise, it will loop
        /// until the underlying socket is closed.
        pub fn handle_incoming_data<F>(self, mut f: F) -> std::io::Result<()>
        where
            F: FnMut(&[u8]) -> std::io::Result<()>,
        {
            let mut socket = std::io::BufReader::new(self.socket);
            let mut buffer = vec![0; 4096];
            loop {
                let mut len_buf = [0; 8];
                if socket.read(&mut len_buf[0..1])? == 0 {
                    break;
                }
                socket.read_exact(&mut len_buf[1..])?;
                let len = u64::from_le_bytes(len_buf) as usize;
                if len > buffer.len() {
                    buffer.extend(std::iter::repeat(0).take(len - buffer.len()));
                }
                socket.read_exact(&mut buffer[0..len])?;
                f(&buffer[0..len])?;
            }
            Ok(())
        }
    }

    /// A `DataProvider` is used to fill buffers with outgoing data.
    pub trait DataProvider {
        /// `provide_data` is called with a callback and a number of bytes. The callback should be
        /// called with a buffer containing `n` bytes of covert data to send.
        ///
        /// If `f` returns an `Err`, then that `Err` should be returned by `provide_data` as well.
        fn provide_data<F>(&mut self, n: usize, f: F) -> std::io::Result<()>
        where
            F: FnOnce(&[u8]) -> std::io::Result<()>;
    }

    /// A connection that will be yielding outgoing data to the remote IP address.
    pub struct SendOutgoingData {
        socket: UnixStream,
    }

    impl SendOutgoingData {
        /// Called when outgoing data is ready to be sent. Uses a `DataProvider`
        /// to receive data from the calling application.
        pub fn handle_outgoing_data<DP: DataProvider>(
            mut self,
            dp: &mut DP,
        ) -> std::io::Result<()> {
            loop {
                let mut len_buf = [0; 8];
                let n = self.socket.read(&mut len_buf[..])?;
                if n == 0 {
                    break;
                } else if n < len_buf.len() {
                    self.socket.read_exact(&mut len_buf[n..])?;
                }
                let len = u64::from_le_bytes(len_buf) as usize;
                dp.provide_data(len, |data| {
                    assert_eq!(data.len(), len);
                    self.socket.write_all(data)
                })?;
            }
            Ok(())
        }
    }
}

mod messages {
    use serde::{Deserialize, Serialize};
    use stallone::LoggableMetadata;
    use std::net::IpAddr;

    #[derive(Debug, Deserialize, Serialize, LoggableMetadata)]
    pub enum InitialClientMessage {
        IncomingDataFrom(IpAddr),
        OutgoingDataFor(IpAddr),
    }
}
