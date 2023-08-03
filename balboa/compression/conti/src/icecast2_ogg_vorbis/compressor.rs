use crate::icecast2_ogg_vorbis::{ogg_body_reader::read_ogg_bodies, utils};
use balboa_compression::{CompressContext, Compressor};
use balboa_coroutine::{GenState, StreamCoroutineShouldNeverExit};
use stallone::LoggableMetadata;
use std::path::Path;

pub(crate) const MIN_PAYLOAD_LENGTH_FOR_SEARCH: usize = 64;

#[derive(LoggableMetadata, Debug)]
enum NextStep {
    // Try to resynchronize using the "OggS" header.
    InvalidPage,
    // Figure out the length of the buffer without relying on it all being in one chunk.
    BufferTooShort,
    ReplacePlaintext { skip: usize, remaining_len: usize },
    DontReplacePlaintext { skip: usize },
}
use crate::icecast2_ogg_vorbis::utils::{read_payload_len, OGG_VERSION_DENOTING_ROCKY_MANGLING};
use NextStep::*;

fn try_to_compress_chunk(
    tmp_crc_buffer: &mut Vec<u8>,
    buf: &mut [u8],
    ogg_file: &[u8],
    start_search_from: &mut usize,
    old_bitstream_serial_number: &mut Option<u32>,
) -> NextStep {
    // This is guaranteed by the API of modify_current_chunk
    debug_assert!(!buf.is_empty());
    // Check the OGG page version
    if buf[0] != 0 {
        stallone::warn!("Invalid ogg page version", version: u8 = buf[0]);
        return InvalidPage;
    }
    // If the buffer is too short, then we won't rewrite this page.
    let num_page_segments = buf.get(22).cloned().map(usize::from);
    if num_page_segments.is_none() {
        stallone::debug!(
            "Buffer too short to have the number of page segments",
            len: usize = buf.len()
        );
        // Don't advance the position, at all. We'll use a different method to advance the
        // buffer.
        return BufferTooShort;
    }
    let num_page_segments = num_page_segments.unwrap();
    if buf.len() < 23 + num_page_segments {
        stallone::debug!(
            "Buffer too short to have the page segments",
            len: usize = buf.len(),
            num_page_segments: usize = num_page_segments,
        );
        return BufferTooShort;
    }
    let payload_len: usize = buf[23..23 + num_page_segments]
        .iter()
        .cloned()
        .map(usize::from)
        .sum();
    let payload_start = 23 + num_page_segments;
    let observed_bitstream_id = {
        let mut raw = [0; 4];
        // This is where the bitstream serial number lives.
        raw.copy_from_slice(&buf[10..14]);
        u32::from_le_bytes(raw)
    };
    if *old_bitstream_serial_number != Some(observed_bitstream_id) {
        // We'll skip this page to make sure that the receiver learns the actual bitstream id.
        stallone::debug!(
            "Not replacing plaintext due to bitstream change",
            old_bitstream_serial_number: Option<u32> = old_bitstream_serial_number,
            observed_bitstream_id: u32 = observed_bitstream_id,
        );
        *old_bitstream_serial_number = Some(observed_bitstream_id);
        return DontReplacePlaintext {
            skip: payload_start + payload_len,
        };
    }
    if payload_len < MIN_PAYLOAD_LENGTH_FOR_SEARCH
        || buf.len() < payload_start + MIN_PAYLOAD_LENGTH_FOR_SEARCH
        || buf[1] == 2
    {
        stallone::debug!(
            "WaitAtLeastForNextPage: Either (1) payload to small, or (2) first page of stream",
            first_page: bool = buf[1] == 2,
            num_page_segments: usize = num_page_segments,
            payload_len: usize = payload_len,
        );
        return DontReplacePlaintext {
            skip: payload_start + payload_len,
        };
    }
    let needle = &buf[payload_start..payload_start + payload_len.min(buf.len() - payload_start)];
    stallone::debug!(
        "Vorbis data needle length",
        needle_len: usize = needle.len()
    );
    let pos = twoway::find_bytes(&ogg_file[*start_search_from..], needle)
        .map(|pos| pos + *start_search_from)
        .or_else(|| {
            stallone::debug!("Failed to find ogg bytes from where we started. trying again.");
            twoway::find_bytes(ogg_file, needle)
        })
        .filter(|pos| ogg_file.get(*pos..(*pos + payload_len)).is_some());
    if pos.is_none() {
        stallone::warn!("Unable to find ogg needle in haystack.");
        return DontReplacePlaintext {
            skip: payload_start + payload_len,
        };
    }
    let pos = pos.unwrap();
    debug_assert_eq!(&ogg_file[pos..pos + needle.len()], needle);
    let header_crc32 = u32::from_le_bytes([buf[18], buf[19], buf[20], buf[21]]);
    // We need to zero out these bytes in the header when we compute the CRC32.
    buf[18..22].copy_from_slice(&[0, 0, 0, 0]);
    // See the TODO in the crc library about enabling incremental CRC.
    tmp_crc_buffer.clear();
    tmp_crc_buffer.extend_from_slice(b"OggS");
    tmp_crc_buffer.extend_from_slice(&buf[0..payload_start]);
    tmp_crc_buffer.extend_from_slice(&ogg_file[pos..pos + payload_len]);
    let data_crc32 = balboa_conti_crc_sys::compute(&tmp_crc_buffer[..]);
    buf[18..22].copy_from_slice(&header_crc32.to_le_bytes());
    if header_crc32 != data_crc32 {
        stallone::warn!(
            "CRC32 check failed",
            pos: usize = pos,
            header_crc32: u32 = header_crc32,
            data_crc32: u32 = data_crc32,
            payload_len: usize = payload_len,
        );
        return DontReplacePlaintext {
            skip: payload_start + payload_len,
        };
    }
    // The CRC checked out, so we're good to go.
    *start_search_from = pos;
    // Replace the version to indicate that we've done mangling.
    buf[0] = OGG_VERSION_DENOTING_ROCKY_MANGLING;
    // Replace the bitstream id with the start index.
    buf[10..14].copy_from_slice(&u32::try_from(pos).unwrap().to_le_bytes());
    ReplacePlaintext {
        skip: payload_start,
        remaining_len: payload_len,
    }
}

async fn compress(
    mut gs: GenState,
    ctx: &mut (dyn CompressContext + Send + 'static),
    ogg_file: Vec<u8>,
) -> StreamCoroutineShouldNeverExit {
    {
        // First we look for the end of the HTTP header response.
        stallone::debug!("Conti compressor looking for '\\r\\n\\r\\n'");
        utils::scan_for_four_byte_string(&mut gs, b"\r\n\r\n").await;
        stallone::debug!("Conti compressor found '\\r\\n\\r\\n'");
    }
    let mut start_search_from = 0;
    let mut tmp_crc_buffer = Vec::new();
    let mut old_bitstream_serial_number = None;
    loop {
        // Look for the ogg page header.
        let skipped_bytes_looking_for_ogg_page =
            utils::scan_for_four_byte_string(&mut gs, b"OggS").await;
        if skipped_bytes_looking_for_ogg_page != 0 {
            stallone::warn!(
                "Page didn't start with magic number",
                skipped_bytes: usize = skipped_bytes_looking_for_ogg_page
            );
        } else {
            stallone::info!("Page DID start with magic number");
        }
        let next_step = {
            let buf = gs.current_chunk().await;
            try_to_compress_chunk(
                &mut tmp_crc_buffer,
                buf,
                &ogg_file[..],
                &mut start_search_from,
                &mut old_bitstream_serial_number,
            )
        };
        stallone::debug!(
            "try_to_compress_chunk() next step",
            next_step: NextStep = next_step,
        );
        match next_step {
            InvalidPage => {
                // We'll just loop around and try to re-synchronize.
            }
            BufferTooShort => {
                // Figure out how big the payload is, and then skip it.
                // We've already read the capture pattern.
                gs.advance_without_modifying(22).await;
                let len = read_payload_len(&mut gs).await;
                stallone::debug!("Buffer too short, skipping", len: usize = len);
                gs.advance_without_modifying(len).await;
            }
            DontReplacePlaintext { skip } => gs.advance_without_modifying(skip).await,
            ReplacePlaintext {
                skip,
                remaining_len,
            } => {
                gs.advance_without_modifying(skip).await;
                gs.advance_exact_with_modification(remaining_len, |buf| ctx.recv_covert_bytes(buf))
                    .await;
            }
        }
    }
}

/// This compressor doesn't have a preview version.
pub fn new_compressor<P: AsRef<Path>>(
    mut ctx: Box<dyn CompressContext + Send + 'static>,
    ogg_file: P,
) -> std::io::Result<Box<dyn Compressor + Send + 'static>> {
    let ogg_file = read_ogg_bodies(ogg_file)?;
    Ok(balboa_compression::new_coroutine_compressor(
        |gs| async move {
            let gs = match gs.into_mutable() {
                Ok(gs) => gs,
                Err(_) => panic!("This compressor doesn't have a preview verison."),
            };
            compress(gs, ctx.as_mut(), ogg_file).await
        },
    ))
}
