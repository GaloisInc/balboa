//! This module implements the protocol for the messages sent between the log producer and the
//! stallone mater
//!
//! We don't use serde because these are pretty simple structs, and serde+bincode is a lot to bring
//! in for just this purpose.
//!
//! The protocol is that the client connects and sends a setup message, then the server responds with
//! the epoch page. Then we can either send file descriptors or request messages. The server
//! never sends another message.
//!
//! The client sends to log messages over a ring buffer to the master. The master will consume these
//! messages and add additional metadata.
//!
//! The stallone base-path is a directory containing:
//!
//! * `s`: the unix socket. The name is intentionally short because unix socket paths are very
//!   limited in length.
//! * `epoch`: the epoch file
//! * "emergency log files" can be written into the `emerg` folder by processes. This is used in the
//!   event of a complete failure to establish contact with Stallone, we can still see _why_ that's
//!   occurring.
//!
//! Note that, for the moment, all file names contain the number "2" as in version 2 of
//! the Stallone protocol.
use crate::StallonePID;
use arrayvec::ArrayVec;
use uuid::Uuid;

/// The maximum size of a serialized message.
pub const BUFFER_SIZE: usize = 128;
pub const BUILD_ID_MAX_SIZE: usize = 64;

pub const SOCKET_FILE_NAME: &'static str = "2s";
pub const EPOCH_FILE_NAME: &'static str = "2epoch";
pub const STALLONE_EMERGENCY_LOG_EXT: &'static str = "stallone2-emergency-log";
pub const EMERGENCY_LOG_DIRECTORY_NAME: &'static str = "2emerg";

#[derive(Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub stallone_pid: StallonePID,
    pub parent_pid: Option<StallonePID>,
    pub build_id: ArrayVec<u8, BUILD_ID_MAX_SIZE>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    /// The FD that comes with this message will be closed to indicate that this process has died.
    ProcessInfo(ProcessInfo),
    /// The FD that comes with this message is a ring buffer (mmap-able file).
    ThreadRingBuffer { stallone_pid: StallonePID },
}

const MSG_TYPE_PROCESS_INFO: u8 = 1;
const MSG_TYPE_THREAD_RING_BUFFER: u8 = 2;

impl Message {
    pub fn serialize(&self) -> ArrayVec<u8, BUFFER_SIZE> {
        // This function shouldn't panic, since BUFFER_SIZE is big enough.
        let mut out = ArrayVec::new();
        match self {
            Message::ProcessInfo(ProcessInfo {
                pid,
                stallone_pid,
                parent_pid,
                build_id,
            }) => {
                out.push(MSG_TYPE_PROCESS_INFO);
                out.try_extend_from_slice(&pid.to_le_bytes()[..]).unwrap();
                out.try_extend_from_slice(stallone_pid.as_bytes()).unwrap();
                out.push(parent_pid.is_some() as u8);
                out.try_extend_from_slice(
                    parent_pid
                        .as_ref()
                        .map(|id| id.as_bytes())
                        .unwrap_or(&[0; 16]),
                )
                .unwrap();
                out.try_extend_from_slice(&build_id[..]).unwrap();
            }
            Message::ThreadRingBuffer { stallone_pid } => {
                out.push(MSG_TYPE_THREAD_RING_BUFFER);
                out.try_extend_from_slice(stallone_pid.as_bytes()).unwrap();
            }
        }
        out
    }
    // TODO: better error handling
    pub fn deserialize(buf: &[u8]) -> Result<Self, ()> {
        if buf.is_empty() {
            return Err(());
        }
        match buf[0] {
            MSG_TYPE_PROCESS_INFO => {
                let mut pid = [0; 4];
                pid.copy_from_slice(buf.get(1..5).ok_or(())?);
                let mut spid = [0; 16];
                spid.copy_from_slice(buf.get(5..5 + 16).ok_or(())?);
                let pspid_is_some = (*buf.get(5 + 16).ok_or(())?) != 0;
                let mut pspid = [0; 16];
                pspid.copy_from_slice(buf.get(5 + 16 + 1..5 + 16 + 16 + 1).ok_or(())?);
                Ok(Message::ProcessInfo(ProcessInfo {
                    pid: u32::from_le_bytes(pid),
                    stallone_pid: Uuid::from_bytes(spid),
                    parent_pid: Some(Uuid::from_bytes(pspid)).filter(|_| pspid_is_some),
                    build_id: buf[5 + 16 + 16 + 1..].iter().cloned().collect(),
                }))
            }
            MSG_TYPE_THREAD_RING_BUFFER => {
                let mut spid = [0; 16];
                spid.copy_from_slice(buf.get(1..17).ok_or(())?);
                Ok(Message::ThreadRingBuffer {
                    stallone_pid: Uuid::from_bytes(spid),
                })
            }
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_serialize_process_info(
            pid in any::<u32>(),
            stallone_pid in any::<[u8; 16]>(),
            parent_pid in any::<Option<[u8; 16]>>(),
            build_id in proptest::collection::vec(any::<u8>(), 0..BUILD_ID_MAX_SIZE),
        ) {
            let msg = Message::ProcessInfo(ProcessInfo {
                pid,
                stallone_pid: Uuid::from_bytes(stallone_pid),
                parent_pid: parent_pid.map(Uuid::from_bytes),
                build_id: build_id[..].iter().cloned().collect(),
            });
            prop_assert_eq!(&msg, &Message::deserialize(&msg.serialize()[..]).unwrap());
        }
    }

    proptest! {
        #[test]
        fn roundtrip_serialize_thread_ring_buffer(stallone_pid in any::<[u8; 16]>()) {
            let msg = Message::ThreadRingBuffer { stallone_pid: Uuid::from_bytes(stallone_pid) };
            prop_assert_eq!(&msg, &Message::deserialize(&msg.serialize()[..]).unwrap());
        }
    }
}
