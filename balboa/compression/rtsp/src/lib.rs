#![deny(unused_must_use)]

//! This is the core balboa RTSP compression library.
//! It replaces every 3rd frame of an RTSP h264 stream with a
//! set of payloads marked as unimportant and unknown to ffplay.

use balboa_compression::{
    new_coroutine_compressor, new_coroutine_decompressor, CompressContext, Compressor,
    DecompressContext, Decompressor, NullCompressor, NullDecompressor,
};
use balboa_coroutine::{GenState, GenStateImmutable, StreamCoroutineShouldNeverExit};
use stallone;

const RTSP_MAGIC: u8 = 0x24; // '$'
const PADDING_FLAG: u8 = 0x20;
const EXTENSIONS_FLAG: u8 = 0x10;
const MARKER_FLAG: u8 = 0x80;

/// Skips over all of the RTSP stream headers looking for
/// an embedded RTP stream.
async fn skip_headers(gs: &mut GenStateImmutable) {
    //                        0     1     2     3           4
    let prefix: [u8; 5] = [0x0d, 0x0a, 0x0d, 0x0a, RTSP_MAGIC];
    let mut i = 0;

    while i < prefix.len() {
        let [byte] = gs.read_exact_array::<1>().await;

        if prefix[i] == byte {
            i += 1
        } else if i == 4 && byte == 0x0d {
            i = 3
        } else if prefix[0] == byte {
            i = 1
        } else {
            i = 0
        }
    }
}

enum Direction {
    Comp(Box<dyn CompressContext + Send>),
    Decomp(Box<dyn DecompressContext + Send>),
}

impl Direction {
    async fn channel(&mut self, gs: &mut GenState, mut example: &[u8]) {
        match self {
            Direction::Comp(ctx) => {
                stallone::debug!("compressing", n: usize = example.len());
                gs.advance_exact_with_modification(example.len(), |buf| {
                    ctx.recv_covert_bytes(buf);
                })
                .await;
            }
            Direction::Decomp(ctx) => {
                stallone::debug!("decompressing", n: usize = example.len());
                gs.advance_exact_with_modification(example.len(), |buf| {
                    ctx.send_covert_bytes(buf);
                    let (prefix, example_) = example.split_at(buf.len());
                    example = example_;
                    buf.copy_from_slice(prefix);
                })
                .await;
            }
        }
    }

    async fn channel_constant(&mut self, gs: &mut GenState, byte: u8, size: usize) {
        match self {
            Direction::Comp(ctx) => {
                stallone::debug!("compressing", n: usize = size);
                gs.advance_exact_with_modification(size, |buf| {
                    ctx.recv_covert_bytes(buf);
                })
                .await;
            }
            Direction::Decomp(ctx) => {
                stallone::debug!("decompressing", n: usize = size);
                gs.advance_exact_with_modification(size, |buf| {
                    ctx.send_covert_bytes(buf);
                    buf.fill(byte);
                })
                .await;
            }
        }
    }
}

/// Implements a covert channel over an arbitrary TCP-based RTSP stream
/// by compressing the redundancy in the sequence numbers and SSRC value
async fn rtsp_generic_stream(
    mut gs: GenStateImmutable,
    mut mode: Direction,
) -> StreamCoroutineShouldNeverExit {
    skip_headers(&mut gs).await;

    let mut gs = gs.into_mutable().unwrap_or_else(|_|
        // note: we can't use .expect because GenStateImmutable can't implement Debug
        panic!("rtsp failed to switch to mutable genstate. \
                It should be safe to switch to mutable state for a TLS server."));

    let mut saved_seq: Option<[u8; 2]> = None;
    let mut saved_ssrc: Option<[u8; 4]> = None;
    let mut saved_ts: Option<[u8; 4]> = None;
    let skip_period = 3;
    let mut skip = 50; // preserves the beginning of the video stream, which has setup parameters
    let mut skipping_frame = false;
    let mut first = true;

    loop {
        // RTSP: Channel(1) Length(2)  RRTP: Bitfields(1), Payload type(1)
        let [channel, len_hi, len_lo] = gs.read_exact_array().await;
        let rtp_len = u16::from_be_bytes([len_hi, len_lo]) as usize;

        if channel == 0 {
            let [rtp_tag, payload_type] = gs.read_exact_array().await;

            // Decode the rtp_tag byte
            let rtp_version = rtp_tag >> 6;
            let has_padding = rtp_tag & PADDING_FLAG == PADDING_FLAG;
            let has_extensions = rtp_tag & EXTENSIONS_FLAG == EXTENSIONS_FLAG;
            let csrc_used = 4 * (rtp_tag & 0xf) as usize;

            if rtp_version != 2 {
                stallone::warn!("Unexpected RTP version", v: u8 = rtp_version);
                break; // exit to the passthrough handler
            }
            if has_padding {
                stallone::warn!("Unexpected padding flag");
                break; // exit to the passthrough handler
            }

            // Decode payload_type byte
            let marker = payload_type & MARKER_FLAG == MARKER_FLAG;
            // payload_type &= 0x3f;

            // Sequence number (2)
            match &mut saved_seq {
                Some(seq) => {
                    *seq = u16::to_be_bytes(u16::from_be_bytes(*seq).wrapping_add(1));
                    mode.channel(&mut gs, seq).await;
                }
                None => saved_seq = Some(gs.read_exact_array().await),
            }

            // Timestamp(4)
            match &mut saved_ts {
                Some(ts) => mode.channel(&mut gs, ts).await,
                None => saved_ts = Some(gs.read_exact_array().await),
            }
            if marker {
                saved_ts = None
            }

            // SSRC(4)
            match &mut saved_ssrc {
                Some(ssrc) => mode.channel(&mut gs, ssrc).await,
                None => saved_ssrc = Some(gs.read_exact_array().await),
            }

            gs.advance_without_modifying(csrc_used).await; // CSRCs

            let ext_used = if has_extensions {
                // Defined-by-profile(2)
                gs.advance_without_modifying(2).await;

                // extension length (2) - 4-byte words count
                let ext_len_bytes = gs.read_exact_array::<2>().await;
                let ext_len = 4 * u16::from_be_bytes(ext_len_bytes) as usize;

                // extension words
                gs.advance_without_modifying(ext_len).await;

                4 + ext_len
            } else {
                0
            };

            // -12 accounts for all the static fields above
            let payload_length = rtp_len - 12 - ext_used - csrc_used;

            if first {
                // The target device consistently choses payload ID 35
                if payload_type != 35 {
                    skipping_frame = false;
                } else if skip > 0 {
                    skip -= 1;
                    skipping_frame = false;
                } else {
                    skipping_frame = true;
                    skip = skip_period
                }
            }

            if skipping_frame {
                // Constructs a low-importance NAL unit unknown to ffplay
                mode.channel_constant(&mut gs, 0x1f, payload_length).await;
            } else {
                gs.advance_without_modifying(payload_length).await;
            }

            first = marker;
        } else {
            // not channel 0
            stallone::debug!("Ignoring other channel", channel: u8 = channel);
            gs.advance_without_modifying(rtp_len).await;
        }

        // END OF FRAME

        let [magic] = gs.read_exact_array().await;
        if magic != RTSP_MAGIC {
            stallone::debug!("Searching for stream");
            skip_headers(&mut gs).await;
        }
    }

    // Passthrough logic in case RTP tracking fails
    loop {
        gs.advance_without_modifying(1024 * 1024).await
    }
}

/// This trait is used to transform the payloads of an RTSP stream
trait PayloadProcessor {
    /// start is called at the beginning of each RTSP frame with the RTP
    /// payload type and RTP payload length
    fn start(&mut self, length: usize);

    /// After a call to start, next_chunk will be called as many times as
    /// needed to process all of the chunks of the payload. The length of
    /// the chunks will sum up to the length provided to the leading start
    /// call.
    ///
    /// The covert function is used to inject or extract covert channel
    /// data as needed by this processor.
    fn next_chunk(&mut self, covert: &mut impl FnMut(&mut [u8]), chunk: &mut [u8]);
}

pub fn new_server_rewriters() -> (
    impl FnOnce(Box<dyn CompressContext + Send + 'static>) -> Box<dyn Compressor + Send + 'static>,
    impl FnOnce(Box<dyn DecompressContext + Send + 'static>) -> Box<dyn Decompressor + Send + 'static>,
) {
    (
        |ctx| new_coroutine_compressor(|gs| rtsp_generic_stream(gs, Direction::Comp(ctx))),
        |_| Box::new(NullDecompressor),
    )
}

pub fn new_client_rewriters() -> (
    impl FnOnce(Box<dyn CompressContext + Send + 'static>) -> Box<dyn Compressor + Send + 'static>,
    impl FnOnce(Box<dyn DecompressContext + Send + 'static>) -> Box<dyn Decompressor + Send + 'static>,
) {
    (
        |_| Box::new(NullCompressor),
        |ctx| new_coroutine_decompressor(|gs| rtsp_generic_stream(gs, Direction::Decomp(ctx))),
    )
}
