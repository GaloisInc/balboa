#[cfg(test)]
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use stallone::LoggableMetadata;
use std::net::Ipv4Addr;

// TODO: unify these bit structs better so tryfrom stuff works better.
macro_rules! bit_int_struct {
    (
        $(
            pub struct $name:ident($holder:ty => $nbits:expr);
        )*
    ) => {
        $(
            #[derive(LoggableMetadata, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
            pub struct $name(pub $holder);
            impl From<$name> for $holder {
                fn from(x: $name) -> Self {
                    x.0
                }
            }
            #[cfg(test)]
            impl Arbitrary for $name {
                type Parameters = ();
                type Strategy = BoxedStrategy<Self>;
                fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                    ((0 as $holder)..(1<< $nbits)).prop_map(|x| $name(x)).boxed()
                }
            }
        )*
    };
}

pub const HOST_ID_BITS: u64 = 21;
pub const CHUNK_SEQNUM_BITS: u64 = 40;
bit_int_struct! {
    // NOTE: HostIDs aren't globally unique. They're only unique within a single mickey.
    pub struct HostId(u32 => HOST_ID_BITS);
    pub struct ChunkSeqnum(u64 => CHUNK_SEQNUM_BITS);
}

#[derive(LoggableMetadata, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkState {
    Unused,
    FilledOutgoing,
    // Claiming incoming will be done using a bit on the chunk, itself.
    EmptyIncoming,
    FilledIncoming,
}

#[cfg(test)]
impl Arbitrary for ChunkState {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use ChunkState::*;
        (0..4)
            .prop_map(|x| match x {
                0b00 => Unused,
                0b01 => FilledOutgoing,
                0b10 => EmptyIncoming,
                0b11 => FilledIncoming,
                _ => unreachable!(),
            })
            .boxed()
    }
}

#[derive(LoggableMetadata, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkControlWord {
    pub host_id: HostId,
    pub seqnum: ChunkSeqnum,
    // This bit is only used for incoming.
    pub reserved: bool,
    pub state: ChunkState,
}

impl From<u64> for ChunkControlWord {
    fn from(x: u64) -> Self {
        use ChunkState::*;
        ChunkControlWord {
            host_id: HostId(
                u32::try_from((x >> 2) & ((1 << HOST_ID_BITS) - 1)).expect("we masked stuff off!"),
            ),
            seqnum: ChunkSeqnum((x >> (2 + HOST_ID_BITS)) & ((1 << CHUNK_SEQNUM_BITS) - 1)),
            reserved: (x & (1 << (2 + HOST_ID_BITS + CHUNK_SEQNUM_BITS))) != 0,
            state: match x & 0b11 {
                0b00 => Unused,
                0b01 => FilledOutgoing,
                0b10 => EmptyIncoming,
                0b11 => FilledIncoming,
                _ => unreachable!(),
            },
        }
    }
}

impl From<ChunkControlWord> for u64 {
    fn from(ccw: ChunkControlWord) -> Self {
        use ChunkState::*;
        let state_bits: u64 = match ccw.state {
            Unused => 0b00,
            FilledOutgoing => 0b01,
            EmptyIncoming => 0b10,
            FilledIncoming => 0b11,
        };
        state_bits
            | (u64::from(ccw.host_id.0) << 2)
            | (ccw.seqnum.0 << (2 + HOST_ID_BITS))
            | (if ccw.reserved {
                1 << (2 + HOST_ID_BITS + CHUNK_SEQNUM_BITS)
            } else {
                0
            })
    }
}

#[test]
fn test_zero_control_word() {
    assert_eq!(
        ChunkControlWord::from(0u64),
        ChunkControlWord {
            host_id: HostId(0),
            seqnum: ChunkSeqnum(0),
            state: ChunkState::Unused,
            reserved: false,
        }
    );
}

#[cfg(test)]
proptest! {
    #[test]
    fn roundtrip_chunk_control_word(encoded in any::<u64>()) {
        let ccw = ChunkControlWord::from(encoded);
        prop_assert_eq!(u64::from(ccw), encoded);
    }
}

#[cfg(test)]
proptest! {
    #[test]
    fn roundtrip2_chunk_control_word(
        host_id in any::<HostId>(),
        seqnum in any::<ChunkSeqnum>(),
        state in any::<ChunkState>(),
        reserved in any::<bool>(),
    ) {
        let ccw = ChunkControlWord {
            host_id,
            seqnum,
            state,
            reserved,
        };
        prop_assert_eq!(ChunkControlWord::from(u64::from(ccw)), ccw);
    }
}

pub const MAX_BALBOA_MICKEY_IPC_MESSAGE_LENGTH: usize = 128;

// TODO: document this protocol.
#[derive(Debug, LoggableMetadata, Serialize, Deserialize)]
pub enum BalboaMickeyIPCMessage {
    GetChunksFile,
    GetIncomingFile(Ipv4Addr),
    GetOutgoingFile(Ipv4Addr),
}
// The response to a successful message is a 32-bit LE integer which is the ID that mickey is using
// for this host.
