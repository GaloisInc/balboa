use crate::icecast2_ogg_vorbis::{
    ogg_body_reader::read_ogg_bodies,
    utils::{self, read_payload_len},
};
use balboa_compression::{DecompressContext, Decompressor};
use balboa_coroutine::{GenState, StreamCoroutineShouldNeverExit};
use std::path::Path;

async fn decompress(
    mut gs: GenState,
    ctx: &mut (dyn DecompressContext + Send + 'static),
    ogg_file: Option<Vec<u8>>,
) -> StreamCoroutineShouldNeverExit {
    {
        // First we look for the end of the HTTP header response.
        stallone::debug!("Conti decompressor looking for '\\r\\n\\r\\n'");
        utils::scan_for_four_byte_string(&mut gs, b"\r\n\r\n").await;
        stallone::debug!("Conti decompressor found '\\r\\n\\r\\n'");
    }
    let mut actual_bitstream_serial_number: Option<u32> = None;
    loop {
        // Look for the ogg page header.
        let skipped_bytes_looking_for_ogg_page =
            utils::scan_for_four_byte_string(&mut gs, b"OggS").await;
        if skipped_bytes_looking_for_ogg_page != 0 {
            stallone::warn!(
                "Page didn't start with magic number",
                skipped_bytes: usize = skipped_bytes_looking_for_ogg_page
            );
        }
        // TODO: what should we be doing on invalid versions?
        // Now, we look at the version of the Ogg Page header
        let should_mangle_page = {
            let mut should_mangle: Option<bool> = None;
            gs.advance_exact_with_modification(1, |buf| {
                if !buf.is_empty() {
                    match buf[0] {
                        utils::OGG_VERSION_DENOTING_ROCKY_MANGLING => {
                            should_mangle = Some(true);
                            buf[0] = 0;
                        }
                        0 => {
                            should_mangle = Some(false);
                        }
                        version => {
                            stallone::warn!(
                                "Unexpected/unknown ogg version",
                                version: u8 = version
                            );
                            should_mangle = Some(false);
                        }
                    }
                }
            })
            .await;
            should_mangle.unwrap()
        };
        // Skip header type
        gs.advance_without_modifying(1).await;
        // Skip Granule position
        gs.advance_without_modifying(8).await;
        let mut offset: Option<u32> = None;
        if should_mangle_page {
            if let Some(actual_bitstream_serial_number) = actual_bitstream_serial_number {
                let outbuf = actual_bitstream_serial_number.to_le_bytes();
                let mut inbuf = [0; 4];
                let mut pos = 0;
                gs.advance_exact_with_modification(4, |dst| {
                    inbuf[pos..pos + dst.len()].copy_from_slice(dst);
                    dst.copy_from_slice(&outbuf[pos..pos + dst.len()]);
                    pos += dst.len();
                })
                .await;
                offset = Some(u32::from_le_bytes(inbuf));
            } else {
                stallone::error!(
                    "The conti decompressor hasn't yet seen a bitstream serial number"
                );
                gs.advance_without_modifying(4).await;
            }
        } else {
            let mut buf = [0; 4];
            gs.read_exact(&mut buf).await;
            actual_bitstream_serial_number = Some(u32::from_le_bytes(buf));
        }
        // Skip by the page sequence number.
        gs.advance_without_modifying(4).await;
        // Skip by the checksum
        gs.advance_without_modifying(4).await;
        let payload_len = read_payload_len(&mut gs).await;
        if let Some(range) = offset
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| offset.checked_add(payload_len).map(|end| offset..end))
        {
            // Valid range, so let's see if we need to rewrite.
            let mut pos = 0;
            if let Some(ogg_file) = ogg_file.as_ref() {
                // Do rewriting.
                if let Some(bytes) = ogg_file.get(range) {
                    // Bytes exist in ogg file.
                    stallone::debug!("Replacing page of length", payload_len: usize = payload_len);
                    gs.advance_exact_with_modification(payload_len, |buf| {
                        ctx.send_covert_bytes(buf);
                        buf.copy_from_slice(&bytes[pos..pos + buf.len()]);
                        pos += buf.len();
                    })
                    .await;
                } else {
                    // Bytes DO NOT exist in ogg file.
                    stallone::debug!("Skipping page of length", payload_len: usize = payload_len);
                    // Skip this page.
                    gs.advance_without_modifying(payload_len).await;
                }
            } else {
                // No rewriting: zero out the bytes and pass to the application.
                stallone::debug!(
                    "Replacing (but NOT rewriting) page of length",
                    payload_len: usize = payload_len
                );
                gs.advance_exact_with_modification(payload_len, |buf| {
                    ctx.send_covert_bytes(buf);
                    for b in buf.iter_mut() {
                        *b = 0;
                    }
                })
                .await;
            }
        } else {
            // Skip this page.
            stallone::debug!("Skipping page of length", payload_len: usize = payload_len);
            gs.advance_without_modifying(payload_len).await;
        }
    }
}

/// Creates a new decompressor for ogg vorbis.
/// This decompressor doesn't have a preview version.
pub fn new_decompressor<P: AsRef<Path>>(
    mut ctx: Box<dyn DecompressContext + Send + 'static>,
    ogg_file: Option<P>,
) -> std::io::Result<Box<dyn Decompressor + Send + 'static>> {
    let ogg_file = if let Some(ogg_file) = ogg_file {
        let ogg_file = read_ogg_bodies(ogg_file)?;
        Some(ogg_file)
    } else {
        None
    };
    Ok(balboa_compression::new_coroutine_decompressor(
        move |gs| async move {
            let gs = match gs.into_mutable() {
                Ok(gs) => gs,
                Err(_) => panic!("This decompressor doesn't have a preview verison."),
            };
            decompress(gs, ctx.as_mut(), ogg_file).await
        },
    ))
}
