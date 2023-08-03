use crate::{
    tls::{
        self,
        crypto::{KeyStream, Tag, TagComputer},
        RecordHeader, SequenceNumber,
    },
    tls_rewriter::{
        errors,
        rocky_crypto::{compute_rocky_aad, rocky_cipher_nonce},
        tls_record_parser, IncomingOrOutgoing, Result,
    },
    GetStreamChangeData, StreamChangeData,
};
use smallvec::SmallVec;
use snafu::ensure;
use subtle::ConstantTimeEq;

pub(crate) trait TaggerAndKeyStreamFactory {
    fn key_stream(
        &self,
        header: &tls::RecordHeader,
        explicit_nonce: &[u8],
        seqnum: SequenceNumber,
    ) -> tls::crypto::KeyStream;
    fn tagger(
        &self,
        header: &tls::RecordHeader,
        explicit_nonce: &[u8],
        seqnum: SequenceNumber,
        cs: &tls::CipherSuite,
    ) -> tls::crypto::TagComputer;
}

pub(crate) struct NormalTLSTaggerAndKeyStreamFactory<'a>(
    pub(crate) &'a tls::crypto::StreamPlusAEADKey,
);
impl<'a> TaggerAndKeyStreamFactory for NormalTLSTaggerAndKeyStreamFactory<'a> {
    fn key_stream(
        &self,
        _header: &RecordHeader,
        explicit_nonce: &[u8],
        seqnum: SequenceNumber,
    ) -> KeyStream {
        self.0.key_stream(explicit_nonce, seqnum)
    }

    fn tagger(
        &self,
        header: &RecordHeader,
        explicit_nonce: &[u8],
        seqnum: SequenceNumber,
        cs: &tls::CipherSuite,
    ) -> TagComputer {
        let aad = tls::crypto::Aad::new(seqnum, header, cs);
        self.0.compute_tag(explicit_nonce, seqnum, aad.as_ref())
    }
}

pub(crate) struct RockyTaggerAndKeyStreamFactory<'a>(pub(crate) &'a tls::crypto::StreamPlusAEADKey);
impl<'a> TaggerAndKeyStreamFactory for RockyTaggerAndKeyStreamFactory<'a> {
    fn key_stream(
        &self,
        _header: &RecordHeader,
        _explicit_nonce: &[u8],
        seqnum: SequenceNumber,
    ) -> KeyStream {
        self.0.key_stream(&rocky_cipher_nonce(seqnum), seqnum)
    }

    fn tagger(
        &self,
        header: &RecordHeader,
        explicit_nonce: &[u8],
        seqnum: SequenceNumber,
        _cs: &tls::CipherSuite,
    ) -> TagComputer {
        self.0.compute_tag(
            &rocky_cipher_nonce(seqnum),
            seqnum,
            &compute_rocky_aad(header, explicit_nonce)[..],
        )
    }
}

/// A strategy to verify an incoming Tag/TLS record MAC
pub(crate) trait InputTagVerifier {
    type Output;
    /// Given the correct and observed MACs, either error out, or return the `Self::Output` gleaned
    /// from the Tag.
    fn try_accept(self, correct: Tag, observed: Tag) -> Result<Self::Output>;
}
/// A strategy to mangle an outgoing Tag/TLS record MAC
pub(crate) trait OutputTagMangler {
    /// Given the correct MAC for the outgoing data, return the MAC that should be written on the
    /// wire.
    fn mangle(self, tag: Tag) -> Tag;
}

#[derive(Clone, Copy)]
pub(crate) struct DefaultInputMacVerifier;
impl InputTagVerifier for DefaultInputMacVerifier {
    type Output = ();
    fn try_accept(self, correct: Tag, observed: Tag) -> Result<Self::Output> {
        ensure!(
            bool::from(correct.0.as_slice().ct_eq(&observed.0)),
            errors::MismatchedMACSnafu { correct, observed }
        );
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PassthruOutputTagMangler;
impl OutputTagMangler for PassthruOutputTagMangler {
    fn mangle(self, tag: Tag) -> Tag {
        tag
    }
}

/// Controls the data we pass to the output key-stream and tagger in `mangle_application_data`.
enum Tls13KeystreamOp<'a> {
    Normal,
    RemoveFirstByte,
    AddByte(usize, u8, &'a mut StreamChangeData),
}

/// is_tls13_reordering_enabled: When true, reorder the TLS 1.3 true-record-type byte. On outgoing
/// connections, move this record type byte from the end of the record to the start. On incoming
/// connections, move this record type byte from the start back to the end. We set
/// `is_tls13_reordering_enabled` to false when we're not sure that two Balboa-enabled endpoints
/// are communicating, such as during the handshake process.
pub(crate) async fn mangle_application_data<
    'a,
    R: Default + GetStreamChangeData,
    ITV: InputTagVerifier,
>(
    hdr: tls::RecordHeader,
    cs: &tls::CipherSuite,
    mut body: tls_record_parser::ParseRecordBody<'a, R>,
    input: &impl TaggerAndKeyStreamFactory,
    input_tag_verifier: ITV,
    output: &impl TaggerAndKeyStreamFactory,
    output_tag_mangler: impl OutputTagMangler,
    mut mangle_plaintext: impl FnMut(&mut [u8]),
    ioo: IncomingOrOutgoing,
    is_tls13_reordering_enabled: bool,
) -> Result<(tls_record_parser::AboutToParseHeader<'a, R>, ITV::Output)> {
    assert_eq!(hdr.record_type, tls::RecordType::ApplicationData);
    ensure!(
        hdr.size >= cs.cipher.auth_tag_size() + cs.cipher.explicit_nonce_size(),
        errors::ApplicationRecordTooShortForNonceAndMACSnafu {
            actual: hdr.size,
            expected: cs.cipher.auth_tag_size() + cs.cipher.explicit_nonce_size(),
        }
    );
    let seqnum = body.sequence_number().unwrap();
    debug_assert_eq!(cs.cipher.auth_tag_size(), 16);
    let mut explicit_nonce: SmallVec<[u8; 16]> = SmallVec::new();
    for _ in 0..cs.cipher.explicit_nonce_size() {
        explicit_nonce.push(0);
    }
    body.passively_read_part_of_body(&mut explicit_nonce[..])
        .await;
    let body_size = hdr.size - cs.cipher.auth_tag_size() - cs.cipher.explicit_nonce_size();
    let mut input_ks = input.key_stream(&hdr, &explicit_nonce[..], seqnum);
    let mut input_tagger = input.tagger(&hdr, &explicit_nonce[..], seqnum, cs);
    let mut output_ks = output.key_stream(&hdr, &explicit_nonce[..], seqnum);
    let mut output_tagger = output.tagger(&hdr, &explicit_nonce[..], seqnum, cs);

    // Only for TLS 1.3: mutable state that will updated in the closure below. That closure might
    // be called multiple times on sub-segments of the TLS record body. This state will help us
    // track how far along we are in the TLS record body.
    let mut should_mangle: Option<bool> = None;
    let mut bytes_seen: usize = 0;
    let mut extra_byte: Option<u8> = None;

    // When operating on TLS 1.3 records, but when TLS 1.3 record-type reordering is disabled, we
    // need to buffer the TLS records in `advance_exact_with_modification_yielding`. That allows us
    // to examine the record-type byte at the end of the record (no matter how the record is
    // fragmented) to determine if we should call `mangle_plaintext` on this record.
    let mut maybe_preview_vec: Option<Vec<u8>> =
        if cs.version == tls::TlsVersion::Tls13 && !is_tls13_reordering_enabled {
            Some(Vec::with_capacity(body_size))
        } else {
            None
        };

    body.advance_exact_with_modification_yielding(body_size, |buf, value_to_yield, chunk_pos| {
        // How much of `buf` should be passed to `mangle_plaintext`. By default, all of `buf` will
        // be passed, but certain TLS 1.3 cases will restrict this size. This is because
        // `mangle_plaintext` expects to only receive application data, and not the "real record
        // type" byte in a TLS 1.3 payload.
        let mut buf_range = 0..buf.len();

        // When swapping the "real record type" byte around in the TLS 1.3 application data
        // payload, we need to take care about what data we pass to the output key-stream/tagger.
        // By default, pass the entire `buf` to the output key-stream and tagger.
        let mut tls13_keystream_op = Tls13KeystreamOp::Normal;

        // In TLS 1.3, the record-type byte is encrypted inside the TLS record payload, and is
        // located at the very end of that payload. However the incoming side depends on that
        // record-type byte being at the start of the payload (since the incoming side might only
        // receive a small amount of that TLS record at a time). So, the outgoing side will reorder
        // the record-type byte from the end to the start of the payload. For that to work, the
        // outgoing side must see the entire payload at once.
        //
        // This is a fair assumption to make, since applications should have their entire outgoing
        // payload prepared before calling out to the TLS stack.
        if cs.version == tls::TlsVersion::Tls13
            && matches!(ioo, IncomingOrOutgoing::Outgoing)
            && is_tls13_reordering_enabled
        {
            assert_eq!(
                buf.len(),
                body_size,
                "TLS 1.3 record type reordering depends on the entire record being present on the \
                 outgoing side, but only {} out of {} bytes are present",
                buf.len(),
                body_size
            );
        }

        input_tagger.update(buf);
        input_ks.xor(buf);

        // Now that the TLS record is decrypted, the outgoing side can perform the record-type byte
        // swap.
        if cs.version == tls::TlsVersion::Tls13
            && matches!(ioo, IncomingOrOutgoing::Outgoing)
            && is_tls13_reordering_enabled
            && !buf.is_empty()
        {
            buf.rotate_right(1);
            // We don't want to pass the record-type byte to `mangle_plaintext`.
            buf_range.start = 1;
        }

        // For TLS 1.2, we always call `mangle_plaintext`, because we know that the
        // `mangle_application_data` function is always called on Application Data.
        //
        // For TLS 1.3, the "real" record-type byte is encrypted, so we don't know until now (after
        // payload decryption) if this is actually Application Data. If it isn't, then we don't
        // want to call `mangle_plaintext` on it. Additionally, if `is_tls13_reordering_enabled` is
        // false, then we won't know the real record-type until the end of the record, so we have
        // to save the record data in `maybe_preview_vec`. That means we'll defer calling
        // `mangle_plaintext` until after `advance_exact_with_modification_yielding` exits, so
        // `local_should_mangle` should be false.
        let local_should_mangle = if cs.version == tls::TlsVersion::Tls13 {
            match should_mangle {
                // Once `should_mangle` is initialized, it'll stay the same throughout the record.
                Some(x) => x,
                None => {
                    // If `should_mangle` isn't initialized, that means we're at the start of a TLS
                    // record.
                    debug_assert_eq!(bytes_seen, 0);
                    debug_assert!(extra_byte.is_none());
                    let new_mangle = is_tls13_reordering_enabled
                        && match buf.first() {
                            Some(x) => match tls::RecordType::from(*x) {
                                tls::RecordType::ApplicationData => true,
                                _ => false,
                            },
                            None => true,
                        };
                    // Initialize `should_mangle` for all future calls to this closure on this same
                    // record.
                    should_mangle = Some(new_mangle);
                    new_mangle
                }
            }
        } else {
            true
        };

        // Perform TLS 1.3 incoming record reordering. We need to restore the record-type byte to
        // its original location (move it from the start of the record to the end). However, we
        // might not receive the entire record at once.
        if cs.version == tls::TlsVersion::Tls13
            && matches!(ioo, IncomingOrOutgoing::Incoming)
            && is_tls13_reordering_enabled
            && !buf.is_empty()
        {
            // If we did receive the entire record at once, this is easy, just move the record type
            // byte from the start to the end of the record.
            if buf.len() == body_size {
                buf.rotate_left(1);
                // We don't want to pass the record-type byte to `mangle_plaintext`.
                buf_range.end = buf.len() - 1;
            } else {
                // If we didn't receive the entire record at once, there are three cases to deal
                // with:
                //  1. We're at the start of the record. In this case we must save the record type
                //     byte, and prevent it from being sent to the application using the
                //     `StreamChangeData` API, which is consumed by `FdState::rewrite_readv`.
                //  2. We're in the middle of the record. In this case we don't need to make any
                //     changes to the record.
                //  3. We're at the end of the record. In this case we must append the record-type
                //     byte (which we saved in case 1) to the end of the record. We do this with
                //     the same `StreamChangeData` API.
                let is_start_of_record = bytes_seen == 0;
                let is_end_of_record = bytes_seen + buf.len() == body_size;
                debug_assert!(
                    !(is_start_of_record && is_end_of_record),
                    "These two conditions can't be true at the same time"
                );

                // Retrieve a mutable reference to the `StreamChangeData` object which is yielded
                // by the enclosing coroutine.
                //
                // Safe unwrap: this function will always return `Some(_)` for the `ioo ==
                // Incoming` case.
                let stream_change_data: &mut StreamChangeData =
                    value_to_yield.get_stream_change_data().unwrap();

                if is_start_of_record {
                    stallone::debug!(
                        "Removing TLS 1.3 record type byte from start of record",
                        first_byte: Option<&u8> = buf.first(),
                    );
                    debug_assert!(stream_change_data.remove_byte.is_none());
                    extra_byte = buf.first().copied();
                    // We want `ReadState` to remove the first byte in this application data
                    // payload, but the `remove_byte` index is relative to the coroutine's buffer
                    // position. So we need to offset from that buffer position, which is the value
                    // of `chunk_pos`.
                    stream_change_data.remove_byte = Some(chunk_pos);
                    // We don't want to pass the record-type byte to `mangle_plaintext`.
                    buf_range.start = 1;
                    // Make sure we don't encrypt/tag the record-type byte, since `ReadState` is
                    // going to remove it from the stream.
                    tls13_keystream_op = Tls13KeystreamOp::RemoveFirstByte;
                } else if is_end_of_record {
                    stallone::debug!(
                        "Appending TLS 1.3 record type byte to end of record",
                        last_byte: Option<u8> = extra_byte,
                    );
                    debug_assert!(stream_change_data.add_byte.is_none());
                    let last_byte = extra_byte.take().expect("No record-type byte available");
                    // The byte that `ReadState` adds back into the data stream needs to be
                    // encrypted. `last_byte` is currently decrypted, so we need to have
                    // `output_ks` re-encrypt it once `output_ks` is finished encrypting the end of
                    // the application payload.
                    //
                    // Additionally, just as in the `remove_byte` case above, we need to pass an
                    // index relative to the coroutine's buffer position.
                    tls13_keystream_op = Tls13KeystreamOp::AddByte(
                        buf.len() + chunk_pos,
                        last_byte,
                        stream_change_data,
                    );
                    // Note that we don't need to update `buf_range`, since `buf` already doesn't
                    // contain the trailing record-type byte.
                }
            }
        }

        // Always call `mangle_plaintext` in TLS 1.2. For TLS 1.3, only call `mangle_plaintext` if
        // we're operating on an Application Data record.
        if local_should_mangle {
            mangle_plaintext(&mut buf[buf_range]);
        } else {
            // If `maybe_preview_vec` exists, add this buffer's data to it.
            maybe_preview_vec.as_mut().map(|v| v.extend(&*buf));
        }

        // Run the output key-stream/tagger, adjusting behavior if we're rearranging the TLS 1.3
        // record-type byte.
        match tls13_keystream_op {
            Tls13KeystreamOp::Normal => {
                output_ks.xor(buf);
                output_tagger.update(buf);
            }
            Tls13KeystreamOp::RemoveFirstByte => {
                // When removing the TLS 1.3 record-type byte at the start of a partial incoming
                // record, we want the application to see the encrypted record-type byte at the end
                // of the record. So we need to prevent the record-type byte that's at the start of
                // `buf` from being encrypted/tagged. It will be taken care of in the `AddByte`
                // case.
                output_ks.xor(&mut buf[1..]);
                output_tagger.update(&buf[1..]);
            }
            Tls13KeystreamOp::AddByte(pos, raw_byte, stream_change_data) => {
                // When adding the TLS 1.3 record-type byte to the end of the incoming record, we
                // need to re-encrypt the record-type byte (`raw_byte` is decrypted) and pass that
                // encrypted byte to the tagger.
                //
                // First, encrypt the end of the application data payload.
                output_ks.xor(buf);
                output_tagger.update(buf);
                // Next re-encrypt and tag the record type byte.
                let mut raw_byte_buf = [raw_byte];
                output_ks.xor(&mut raw_byte_buf);
                output_tagger.update(&raw_byte_buf);
                // Finally add the encrypted byte into `StreamChangeData`, so `ReadState` will
                // append the byte onto the stream of data read by the incoming application.
                stream_change_data.add_byte = Some((pos, raw_byte_buf[0]));
            }
        }

        // Update number-of-bytes-seen-in-this-record counter.
        bytes_seen += buf.len();
    })
    .await;

    // If we collected an Application Data record into the preview Vec, then call
    // `mangle_plaintext` on it. Note that if `maybe_preview_vec` is `Some(...)`, then
    // `mangle_plaintext should never have been called during
    // `advance_exact_with_modification_yielding`.
    if let Some(mut preview_vec) = maybe_preview_vec {
        if let Some((x, record_bytes)) = preview_vec.split_last_mut() {
            if let tls::RecordType::ApplicationData = tls::RecordType::from(*x) {
                mangle_plaintext(record_bytes);
            }
        }
    }

    let correct_input_tag = input_tagger.finalize();
    let output_tag = output_tag_mangler.mangle(output_tagger.finalize());
    let mut observed_tag: SmallVec<[u8; 16]> = {
        let mut observed_tag = SmallVec::new();
        let mut tag_pos = 0;
        debug_assert_eq!(cs.cipher.auth_tag_size() - 1, 15);
        body.advance_exact_with_modification(cs.cipher.auth_tag_size() - 1, |buf| {
            observed_tag.extend_from_slice(buf);
            buf.copy_from_slice(&output_tag.0[tag_pos..tag_pos + buf.len()]);
            tag_pos += buf.len();
        })
        .await;
        observed_tag
    };
    // Now, the final byte!
    let mut output: Option<Result<ITV::Output>> = None;
    // The type of the closure to advance_exact_with_modification is FnMut. As a result, we can't
    // MOVE input_tag_mangler into a single loop iteration. To get around this, we use an Option.
    // The Option becomes None after the "first" loop iteration, and will panic on any subsequent
    // iterations. However, the loop body only gets called once, so we'll never panic.
    let mut input_tag_verifier = Some(input_tag_verifier);
    body.advance_exact_with_modification(1, |buf| {
        if buf.len() == 1 {
            assert!(output.is_none());
            assert_eq!(observed_tag.len(), 15);
            observed_tag.push(buf[0]);
            let observed_tag: [u8; 16] =
                *<&[u8; 16]>::try_from(observed_tag.as_slice()).expect("we checked the length!");
            let observed_tag = Tag(observed_tag);
            let output_result = input_tag_verifier
                .take()
                .expect("This loop body should be called at most once")
                .try_accept(correct_input_tag, observed_tag);
            buf[0] = output_tag.0[15] ^ (if output_result.is_ok() { 0 } else { 0xff });
            output = Some(output_result);
        }
    })
    .await;
    let rp = body.passively_discard_rest_of_body().await;
    Ok((
        rp,
        output.expect("We should've read the last byte of the mac")?,
    ))
}

#[test]
/// A regression test for [issue 57](https://gitlab-ext.galois.com/rocky/rocky/-/issues/57)
fn test_regression_issue_57() {
    use crate::tls::RecordType;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let finished = Arc::new(AtomicBool::new(false));
    let finished2 = finished.clone();
    let mut coro = balboa_coroutine::CoroutineBasedStreamRewriter::<()>::new(|mut gs| {
        async move {
            let cs = tls::CipherSuite::try_from(0xc02f).unwrap();
            let dk = tls::crypto::DerivedKeys::derive_from_tls12(
                &cs,
                &tls::MasterSecret12([0; 48]),
                &tls::ClientRandom([0; 32]),
                &tls::ServerRandom([0; 32]),
            );
            let ksf = NormalTLSTaggerAndKeyStreamFactory(&dk.client_to_server);
            // If this doesn't panic, then the test passes.
            let _ = mangle_application_data(
                tls::RecordHeader {
                    record_type: RecordType::ApplicationData,
                    version: 0,
                    size: 24,
                },
                // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                &cs,
                tls_record_parser::ParseRecordBody {
                    gen: &mut gs,
                    common: tls_record_parser::CommonState {
                        seqnum: tls_record_parser::SeqnumState::SequenceNumber(
                            tls::SequenceNumber(12),
                        ),
                    },
                    size: 24,
                },
                &ksf,
                DefaultInputMacVerifier,
                &ksf,
                PassthruOutputTagMangler,
                |_| (),
                IncomingOrOutgoing::Incoming,
                true,
            )
            .await;
            finished.store(true, Ordering::SeqCst);
            let _ = gs.advance_without_modifying(1).await;
            panic!("should not get here");
        }
    });
    let finished = finished2;
    let mut buf = Vec::new();
    buf.resize(23, 0);
    assert!(!finished.load(Ordering::SeqCst));
    coro.rewrite(&mut buf[..]);
    assert!(!finished.load(Ordering::SeqCst));
    coro.rewrite(&mut []);
    assert!(!finished.load(Ordering::SeqCst));
    coro.rewrite(&mut [0]);
    assert!(finished.load(Ordering::SeqCst));
}
