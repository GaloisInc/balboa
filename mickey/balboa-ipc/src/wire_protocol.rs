//! The "wire protocol" used to encode the chunks over the covert channel that Balboa established.

use crate::{
    types::{ChunkSeqnum, CHUNK_SEQNUM_BITS},
    CHUNK_SIZE,
};
use balboa_coroutine::GenState;
use snafu::{ensure, Snafu};
use stallone::LoggableMetadata;

const PADDING_BITS: u64 = 22;
const PADDING: u64 = (1 << PADDING_BITS) - 1;

// TODO: this wire format needs to allow zero padding.
bit_struct_u64! {
    #[quickcheck_test(test_frame_header)]
    struct FrameHeader {
        // We set all these bits high to ensure that the first byte is non-zero.
        // TODO: take advantage of these bits for a selective ack, or a checksum?
        padding: PADDING_BITS,
        is_ack: 1,
        is_data: 1,
        // For the ack, this is the cumulative ack (exclusive).
        // For the data, this is the seqnum of the data.
        seqnum: CHUNK_SEQNUM_BITS,
    }
}

#[test]
fn padding_leads_to_non_zero_first_byte() {
    assert_ne!(
        u64::try_from(FrameHeader {
            is_ack: 0,
            is_data: 0,
            seqnum: 0,
            padding: PADDING,
        })
        .unwrap()
        .to_le_bytes()[0],
        0
    );
}

#[derive(Debug, Snafu, LoggableMetadata)]
pub(crate) enum FrameParseError {
    #[snafu(display("!(ack XOR data)"))]
    AckAndDataBitsSetIncorrectly,
}

pub(crate) enum Frame<'a> {
    Ack {
        /// Exclusive upper bound
        cumulative: ChunkSeqnum,
    },
    Chunk(ChunkSeqnum, &'a [u8; CHUNK_SIZE]),
}

pub(crate) struct ReaderOutput<'a> {
    pub(crate) frame: Frame<'a>,
    // We'll start reading from this once we start collecting stats on connections.
    #[allow(dead_code)]
    pub(crate) bytes_consumed: usize,
}

pub(crate) struct Reader {
    buf: [u8; CHUNK_SIZE],
}
impl Reader {
    pub(crate) fn new() -> Self {
        Reader {
            buf: [0; CHUNK_SIZE],
        }
    }

    pub(crate) async fn read<'a>(
        &'a mut self,
        gs: &mut GenState,
    ) -> Result<ReaderOutput<'a>, FrameParseError> {
        let mut buf = [0; 8];
        let mut bytes_consumed = 0;
        while buf[0] == 0 {
            // Skip padding.
            // TODO: is this compiled down to something fast?
            gs.read_exact(&mut buf[0..1]).await;
            bytes_consumed += 1;
        }
        bytes_consumed += 7;
        gs.read_exact(&mut buf[1..]).await;
        let hdr = FrameHeader::from(u64::from_le_bytes(buf));
        ensure!(
            (hdr.is_ack != 0) ^ (hdr.is_data != 0),
            AckAndDataBitsSetIncorrectlySnafu
        );
        if hdr.is_ack != 0 {
            Ok(ReaderOutput {
                frame: Frame::Ack {
                    cumulative: ChunkSeqnum(hdr.seqnum),
                },
                bytes_consumed,
            })
        } else {
            // Assured by the ensure! above
            debug_assert!(hdr.is_data != 0);
            gs.read_exact(&mut self.buf[..]).await;
            bytes_consumed += CHUNK_SIZE;
            Ok(ReaderOutput {
                frame: Frame::Chunk(ChunkSeqnum(hdr.seqnum), &self.buf),
                bytes_consumed,
            })
        }
    }
}

pub(crate) async fn write_frame<'a>(gs: &mut GenState, frame: &Frame<'a>) {
    match frame {
        Frame::Ack { cumulative } => {
            stallone::debug!("Writing ACK", cumulative: ChunkSeqnum = cumulative)
        }
        Frame::Chunk(seqnum, _) => stallone::debug!("Writing CHUNK", seqnum: ChunkSeqnum = seqnum),
    }
    gs.write_exact_ignoring_contents(
        &u64::try_from(match frame {
            Frame::Ack { cumulative } => FrameHeader {
                is_ack: 1,
                is_data: 0,
                seqnum: cumulative.0,
                padding: PADDING,
            },
            Frame::Chunk(seqnum, _) => FrameHeader {
                is_ack: 0,
                is_data: 1,
                seqnum: seqnum.0,
                padding: PADDING,
            },
        })
        .unwrap()
        .to_le_bytes()[..],
    )
    .await;
    if let Frame::Chunk(_, bytes) = frame {
        gs.write_exact_ignoring_contents(&bytes[..]).await;
    }
}

pub(crate) async fn write_padding(gs: &mut GenState, nbytes: usize) {
    stallone::debug!("Writing padding", nbytes: usize = nbytes);
    gs.advance_exact_with_modification(nbytes, |buf| {
        for byte in buf.iter_mut() {
            *byte = 0;
        }
    })
    .await;
}

// TODO: unit test the wire protocol.
