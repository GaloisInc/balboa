//! If client() or server() exits successfully, then covert signaling has successfully completed.
use std::io::{Cursor, Read, Seek, SeekFrom};

use super::{tls_record_parser, Result};
use crate::tls_rewriter::rocky_crypto::client_mac_mangling::{
    CovertSignalingInputTagVerifier, CovertSignalingOutputTagMangler,
};
use crate::{
    tls::{self, crypto::Tag},
    tls_rewriter::{
        errors::{self, TLSRewriterError},
        rocky_crypto::CryptoParameters,
        shared_state::TLSConnectionSharedState,
        utils::{
            mangle_application_data, DefaultInputMacVerifier, InputTagVerifier,
            NormalTLSTaggerAndKeyStreamFactory, OutputTagMangler, PassthruOutputTagMangler,
        },
        ClientServerMessageOrdering, ContextualInfo, IncomingOrOutgoing,
    },
    GetStreamChangeData,
};
use balboa_compression::CanPreviewPlaintextData;
use balboa_covert_signaling_types::{
    CovertSignalingIdentity, CovertSignalingToken, PinnedServerPubKey, ServerCovertSignalingSecret,
};
use smallvec::SmallVec;
use snafu::ensure;
use subtle::ConstantTimeEq;
use IncomingOrOutgoing::*;

async fn parse_server_hello<'a, R: Default>(
    ss: &TLSConnectionSharedState,
    rp: tls_record_parser::AboutToParseHeader<'a, R>,
    enable_tls13: bool,
) -> Result<(tls_record_parser::AboutToParseHeader<'a, R>, Vec<u8>)> {
    let (hdr, rp) = rp.parse_header().await?;
    if hdr.record_type != tls::RecordType::Handshake {
        return Err(TLSRewriterError::ExpectedHandshakeHeaderForServerHello { actual: hdr });
    }

    // Since we're ensuring the buffer is at least this large, we can safely unwrap/expect some
    // read/seek operations below.
    const N: usize = 39;
    if hdr.size < N {
        return Err(TLSRewriterError::ServerHelloTooShort {
            actual: hdr.size,
            expected: N,
        });
    }

    let mut buffer = vec![0; hdr.size];
    let mut rp = rp.passively_read_rest_of_body(&mut buffer).await;

    let mut buf_cursor = Cursor::new(buffer);

    // Check that this is a ServerHello message
    let mut handshake_message_type_buf = [0];
    buf_cursor
        .read_exact(&mut handshake_message_type_buf)
        .expect("read handshake_message_type");
    let handshake_message_type = tls::HandshakeType::from(handshake_message_type_buf[0]);
    if handshake_message_type != tls::HandshakeType::ServerHello {
        return Err(
            TLSRewriterError::FirstServerHandshakeRecordWasntServerHello {
                actual: handshake_message_type,
            },
        );
    }

    // Read the Server Random field
    buf_cursor
        .seek(SeekFrom::Start(6))
        .expect("seek to server_random");
    let mut server_random_buf = [0; 32];
    buf_cursor
        .read_exact(&mut server_random_buf)
        .expect("read server_random");
    let server_random = tls::ServerRandom(server_random_buf);

    // Skip the Session ID field
    buf_cursor
        .seek(SeekFrom::Start(38))
        .expect("seek to session_id_length");
    let mut session_id_length_buf = [0];
    buf_cursor
        .read_exact(&mut session_id_length_buf)
        .expect("read session_id_length");
    let session_id_length = i64::from(session_id_length_buf[0]);
    if buf_cursor
        .seek(SeekFrom::Current(session_id_length))
        .is_err()
    {
        return Err(TLSRewriterError::ServerHelloTooShort {
            actual: buf_cursor.get_ref().len(),
            expected: (buf_cursor.position() as usize) + (session_id_length as usize),
        });
    }

    // Read the negotiated cipher suite
    let mut cipher_suite_buf = [0, 0];
    if buf_cursor.read_exact(&mut cipher_suite_buf).is_err() {
        return Err(TLSRewriterError::ServerHelloTooShort {
            actual: buf_cursor.get_ref().len(),
            expected: (buf_cursor.position() as usize) + cipher_suite_buf.len(),
        });
    }

    let cipher_suite_id = u16::from_be_bytes(cipher_suite_buf);
    let cipher_suite = tls::CipherSuite::try_from(cipher_suite_id)?;
    if let tls::Cipher::Aes(_, tls::AesMode::CBC(_)) = cipher_suite.cipher {
        return Err(TLSRewriterError::CbcModeCiphersAreUnsupported);
    }
    if cipher_suite.version == tls::TlsVersion::Tls13 && !enable_tls13 {
        return Err(TLSRewriterError::TLS13IsUnsupported);
    }
    ss.transition_saw_server_random_and_cipher_suite(server_random, cipher_suite);

    // In TLS 1.3, we can't depend on the ChangeCipherSpec message to be sent between the initial
    // Client/Server Hello exchange and the start of encrypted handshake traffic. So we must
    // manually initialize the sequence counter.
    if cipher_suite.version == tls::TlsVersion::Tls13 {
        stallone::debug!("Finished initial TLS 1.3 handshake, initializing Seqnum");
        rp.start_new_sequence();
    }

    Ok((rp, buf_cursor.into_inner()))
}

// Return true if the server certificate was checked
// Return false if the handshake record is fine, but doesn't contain the server's signature
// Return err otherwise.
async fn check_server_certificate_tls12_inner<'a, R: Default>(
    ss: &TLSConnectionSharedState,
    hdr: tls::RecordHeader,
    pinned_server_key: Option<&PinnedServerPubKey>,
    rp: &mut tls_record_parser::ParseRecordBody<'a, R>,
) -> Result<bool> {
    // TODO: reduce code duplication with a helper function.
    // TODO: some of the parse errors should probably be actual errors, rather than just Ok(false)
    if hdr.record_type != tls::RecordType::Handshake {
        return Err(TLSRewriterError::SawNonHandshakeServerRecordBeforeKeyExchange { header: hdr });
    }
    {
        let mut handshake_header_buf = [0; 4];
        let size = rp
            .passively_read_part_of_body(&mut handshake_header_buf[..])
            .await;
        ensure!(
            size == 4,
            errors::RecordTooShortForHandshakeHeaderSnafu { header: hdr }
        );
        // The other bytes are length info that we don't need.
        let handshake_message_type = tls::HandshakeType::from(handshake_header_buf[0]);
        if handshake_message_type != tls::HandshakeType::ServerKeyExchange {
            stallone::debug!(
                "Server handshake record wasn't server key exchange",
                actual_handshake_record_type: tls::HandshakeType = handshake_message_type,
            );
            return Ok(false);
        }
    }
    let mut msg_buf: SmallVec<[u8; 512]> = Default::default();
    msg_buf.extend_from_slice(&ss.client_random().0[..]);
    msg_buf.extend_from_slice(&ss.server_random().0[..]);
    {
        let mut curve_info = [0; 3];
        let size = rp.passively_read_part_of_body(&mut curve_info[..]).await;
        ensure!(
            size == curve_info.len(),
            errors::ServerKeyExchangeTooShortForCurveTypeSnafu { header: hdr }
        );
        if curve_info[0] != 0x03 {
            return Err(TLSRewriterError::UnsupportedKeyExchangeCurveType {
                actual: curve_info[0],
            });
        }
        msg_buf.extend_from_slice(&curve_info[..]);
    }
    {
        let mut dh_pubkey_len_buf = [0];
        let size = rp
            .passively_read_part_of_body(&mut dh_pubkey_len_buf[..])
            .await;
        ensure!(
            dh_pubkey_len_buf.len() == size,
            errors::ServerKeyExchangeTooShortForDiffieHellmanPublicKeyLengthSnafu { header: hdr }
        );
        msg_buf.push(dh_pubkey_len_buf[0]);
        let pubkey_start = msg_buf.len();
        let pubkey_len: usize = dh_pubkey_len_buf[0].into();
        for _ in 0..pubkey_len {
            msg_buf.push(0);
        }
        ensure!(
            rp.passively_read_part_of_body(&mut msg_buf[pubkey_start..])
                .await
                == pubkey_len,
            errors::ServerKeyExchangeTooShortForDiffieHellmanPublicKeyBodySnafu { header: hdr }
        );
    }
    let signature_scheme = {
        let mut signature_scheme_buf = [0; 2];
        let size = rp
            .passively_read_part_of_body(&mut signature_scheme_buf[..])
            .await;
        ensure!(
            size == signature_scheme_buf.len(),
            errors::ServerKeyExchangeTooShortForSignatureTypeSnafu { header: hdr }
        );
        tls::signature_scheme::SignatureScheme::try_from(u16::from_be_bytes(signature_scheme_buf))?
    };
    let mut signature: SmallVec<[u8; 256]> = Default::default();
    {
        let mut siglen = [0; 2];
        let size = rp.passively_read_part_of_body(&mut siglen[..]).await;
        ensure!(
            size == siglen.len(),
            errors::ServerKeyExchangeTooShortForSignatureLengthSnafu { header: hdr }
        );
        let siglen = u16::from_be_bytes(siglen) as usize;
        ensure!(
            siglen <= hdr.size,
            errors::ServerKeyExchangeSignatureTooLongSnafu {
                header: hdr,
                siglen,
            }
        );
        for _ in 0..siglen {
            signature.push(0);
        }
        ensure!(
            rp.passively_read_part_of_body(&mut signature[..]).await == signature.len(),
            errors::ServerKeyExchangeTooShortForSignatureBodySnafu { header: hdr }
        );
    }
    // TODO: XXX: security: do we need to pin the algorithm as well?
    /* openssl rsa -pubin \
    -in public_key.pem \
    -inform PEM \
    -RSAPublicKey_out \
    -outform DER \
    -out public_key.der */
    if let Some(pinned_server_key) = pinned_server_key {
        let alg = signature_scheme.verification_algorithm();
        let pinned_pubkey =
            ring::signature::UnparsedPublicKey::new(alg, pinned_server_key.as_der());
        match pinned_pubkey.verify(&msg_buf[..], &signature[..]) {
            Ok(_) => {
                stallone::debug!("Successfully verified TLS 1.2 server signature");
                Ok(true)
            }
            Err(_) => {
                stallone::debug!(
                    "TLS server signature verification failed",
                    signature_scheme: tls::signature_scheme::SignatureScheme = signature_scheme,
                    msg: &[u8] = &msg_buf[..],
                    signature: &[u8] = &signature[..],
                    alg: String = format!("{:?}", alg),
                );
                Err(TLSRewriterError::ServerSignatureVerificationFailed { signature_scheme })
            }
        }
    } else {
        // TODO: XXX: SECURITY: we should more strongly enforce when this is and isn't safe.
        stallone::info!("No pinned server public key. Skipping validation.");
        Ok(true)
    }
}

async fn check_server_certificate_tls12<'a, R: Default>(
    pinned_server_pubkey: &PinnedServerPubKey,
    ss: &TLSConnectionSharedState,
    mut rp0: tls_record_parser::AboutToParseHeader<'a, R>,
) -> Result<tls_record_parser::AboutToParseHeader<'a, R>> {
    loop {
        let (hdr, mut rp) = rp0.parse_header().await?;
        let result =
            check_server_certificate_tls12_inner(ss, hdr, Some(pinned_server_pubkey), &mut rp)
                .await?;
        rp0 = rp.passively_discard_rest_of_body().await;
        if result {
            return Ok(rp0);
        }
    }
}

pub(crate) async fn server<'a, R: Default + GetStreamChangeData>(
    ctx_info: &ContextualInfo,
    ioo: IncomingOrOutgoing,
    preview_data: &mut (impl CanPreviewPlaintextData + Send + 'static + ?Sized),
    ss: &TLSConnectionSharedState,
    rp: tls_record_parser::AboutToParseHeader<'a, R>,
    enable_tls13: bool,
) -> Result<(
    CryptoParameters,
    tls::RecordHeader,
    tls_record_parser::ParseRecordBody<'a, R>,
)> {
    let (mut rp, server_hello_buffer) = parse_server_hello(ss, rp, enable_tls13).await?;

    let cipher_suite = ss.try_cipher_suite().unwrap();

    let (server_pubkey, covert_signaling_token) = match &ctx_info.mode_specific {
        super::ModeSpecificContext::Client {
            server_pub_key,
            covert_signaling_token,
        } => (Some(server_pub_key), Some(covert_signaling_token)),
        super::ModeSpecificContext::Server { .. } => (None, None),
    };

    // For TLS 1.3, there are a number of encrypted handshake records we need to receive before we
    // expect encrypted traffic records. Furthermore, the client node (when `ioo` is `Incoming`)
    // must verify the server's certificate, which involves hashing the decrypted contents of these
    // handshake records.
    if cipher_suite.version == tls::TlsVersion::Tls13 {
        let is_incoming = matches!(ioo, Incoming);

        // Grab the Client Hello message which the `client` coroutine should have recorded by now.
        let client_hello = ss
            .client_hello()
            .ok_or(TLSRewriterError::NeverSawClientHello)?;

        // Initialize the handshake-message-digest with the Client and Server Hello messages we've
        // received.
        let digest_algorithm =
            ring::hmac::Algorithm::from(cipher_suite.prf_hash).digest_algorithm();
        let mut digest_ctx = ring::digest::Context::new(digest_algorithm);
        if is_incoming {
            // Only both with this when we're the client node.
            digest_ctx.update(&client_hello);
            digest_ctx.update(&server_hello_buffer);
        }

        // Now we need to hash the Server Encrypted Extensions and Server Certificate messages, but
        // those will both be encrypted using the handshake keys. So we need to derive those keys
        // now.
        let tls_keys = {
            let tls_secret_provider = &*ctx_info.tls_secret_provider;
            let client_random = ss.try_client_random().unwrap();
            tls::crypto::DerivedKeys::derive_tls13_handshake_keys(
                tls_secret_provider,
                &client_random,
                &cipher_suite,
            )
        };
        let stream = tls_keys.server_to_client;

        // Wait for the remaining expected handshake messages. We expect:
        // - (Optional) Change Cipher Spec: This is not encrypted, so we can identify it by the
        //   header's `record_type` field. This message body should not be hashed, so we'll skip
        //   it.
        // - Server Encrypted Extensions: This is encrypted, and the decrypted body should be
        //   hashed.
        // - Server Certificate: This is encrypted, and the decrypted body should be hashed.
        // Once we receive those messages, we should then get an encrypted Server Certificate
        // Verify handshake message, which will contain the signature that we want to verify.
        let (rp_inner, certificate_verify_header, certificate_verify_body) =
            tls13::get_server_handshake_hash_inputs(rp, &mut digest_ctx, &stream, &cipher_suite)
                .await?;

        // At this point we've hashed all the messages we need, so we can compute the final digest.
        let handshake_hash = digest_ctx.finish();

        // Parse the Certificate Verify message and check it against our pinned public key.
        if is_incoming {
            // Only both with this when we're the client node.
            tls13::check_server_certificate(
                server_pubkey.expect("An incoming server-side means that we are the client!"),
                certificate_verify_header,
                &certificate_verify_body,
                handshake_hash,
            )?;
        }

        // Finally, wait for the Server Handshake Finished message to arrive.
        let (hdr, body) = rp_inner.parse_header().await?;
        if hdr.record_type != tls::RecordType::ApplicationData {
            return Err(TLSRewriterError::UnexpectedRecordType {
                actual: hdr.record_type,
                expected: tls::RecordType::ApplicationData,
            });
        }
        let (mut rp_inner, buffer) = tls13::read_and_decrypt_record(
            &hdr,
            body,
            &stream,
            &cipher_suite,
            tls::RecordType::Handshake,
        )
        .await?;
        let handshake_message_type = tls::HandshakeType::from(buffer[0]);
        if handshake_message_type != tls::HandshakeType::Finished {
            return Err(TLSRewriterError::UnexpectedHandshakeType {
                actual: handshake_message_type,
                expected: tls::HandshakeType::Finished,
            });
        }

        // For TLS 1.3, the sequence number needs to be reset once the traffic keys are used.
        stallone::debug!("Finished TLS 1.3 handshake, initializing Seqnum for traffic");
        rp_inner.start_new_sequence();

        rp = rp_inner;
    }

    match ioo {
        Incoming => {
            rp = match cipher_suite.version {
                tls::TlsVersion::Tls12 => {
                    check_server_certificate_tls12(
                        server_pubkey
                            .expect("An incoming server-side means that we are the client!"),
                        ss,
                        rp,
                    )
                    .await?
                }
                // We already took care of TLS 1.3 certificate verification above.
                tls::TlsVersion::Tls13 => rp,
            };

            // If we've successfully checked the server's cert, that means we can trust the party
            // on the other end. As a result, we transition, telling the client to covertly signal
            // the server.
            ss.transition_successfully_covertly_signaled(
                *covert_signaling_token
                    .expect("An incoming server-side means that we are the client!"),
            );
            // Now we know that the server is a rocky server. We wait until we're ready for the
            // mangling to start.
            match ctx_info.client_server_message_ordering {
                ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage => {
                    // This is the easy case. We know that, by the time we receive an
                    // ApplicationData record, the server will know that we're a ROCKY client.
                    // as a result, we just need to wait for the first ApplicationData record,
                    // and that's it.
                    stallone::debug!("Waiting for first incoming application data message");
                    loop {
                        let (hdr, body) = rp.parse_header().await?;
                        if hdr.record_type == tls::RecordType::ApplicationData {
                            if body.sequence_number().is_none() {
                                stallone::warn!("Application record isn't encrypted.");
                                return errors::AssertionFailureSnafu.fail();
                            }
                            stallone::debug!("Found first incoming application data message");
                            return Ok((
                                CryptoParameters::new(
                                    ctx_info.rocky_secret,
                                    &*ctx_info.tls_secret_provider,
                                    ss,
                                ),
                                hdr,
                                body,
                            ));
                        }
                        rp = body.passively_discard_rest_of_body().await;
                    }
                }
                ClientServerMessageOrdering::NoSuchOrdering => {
                    // RECALL: we know that the server is a ROCKY server, and we've told the server
                    // that we are a ROCKY client. It might not yet know that we're a ROCKY client.
                    // This is the hard case. Server messages can be ordered arbitrarily with
                    // respect to client messages. As a result, we'll need to scan/preview incoming
                    // application data messages in order to find a mangled MAC to signal that the
                    // mangling should begin in earnest. In the meantime, we decrypt the incoming
                    // traffic so that it can be used by the compressor to keep track of state.
                    struct XorInputMac<'a>(&'a CryptoParameters);
                    impl InputTagVerifier for XorInputMac<'_> {
                        type Output = bool;
                        fn try_accept(self, correct: Tag, observed: Tag) -> Result<Self::Output> {
                            let mut xored = correct;
                            for (a, b) in xored
                                .0
                                .iter_mut()
                                .zip(self.0.covert_signaling_server_to_client_one_time_pad)
                            {
                                *a ^= b;
                            }
                            if bool::from(xored.0.as_slice().ct_eq(&observed.0)) {
                                return Ok(true);
                            }
                            ensure!(
                                bool::from(correct.0.as_slice().ct_eq(&observed.0)),
                                errors::MismatchedMACWhileWaitingForCovertServerAckSnafu {
                                    actual: observed,
                                    correct_expected: correct,
                                    covert_expected: xored,
                                }
                            );
                            Ok(false)
                        }
                    }
                    stallone::debug!(
                        "Begin scanning for ApplicationData message in which the server signals \
                         that it knows that the client is a rocky client"
                    );
                    let mut cp_holder: Option<CryptoParameters> = None;
                    loop {
                        let (hdr, body) = rp.parse_header().await?;
                        if hdr.record_type == tls::RecordType::ApplicationData {
                            if body.sequence_number().is_none() {
                                return errors::ApplicationRecordIsntEncryptedSnafu { header: hdr }
                                    .fail();
                            }
                            let cp = cp_holder.get_or_insert_with(|| {
                                CryptoParameters::new(
                                    ctx_info.rocky_secret,
                                    &*ctx_info.tls_secret_provider,
                                    ss,
                                )
                            });
                            let (rp2, mac_result) = mangle_application_data(
                                hdr,
                                &cp.cipher_suite,
                                body,
                                &NormalTLSTaggerAndKeyStreamFactory(&cp.tls_keys.server_to_client),
                                XorInputMac(&cp),
                                &NormalTLSTaggerAndKeyStreamFactory(&cp.tls_keys.server_to_client),
                                PassthruOutputTagMangler,
                                |buf| {
                                    // We are just previewing the plaintext.
                                    let buf = &buf[..];
                                    preview_data.preview(buf);
                                },
                                ioo,
                                false, // Don't reorder TLS 1.3 records since we're previewing
                            )
                            .await?;
                            if mac_result {
                                stallone::debug!(
                                    "Got acknowledgement from the server of covert signal"
                                );
                                let (hdr, body) = rp2.parse_header().await?;
                                return Ok((cp_holder.take().unwrap(), hdr, body));
                            }
                            // Keep on looping, waiting for the ack.
                            stallone::debug!(
                                "Waiting for acknowledgement from the server of covert signal"
                            );
                            rp = rp2;
                        } else {
                            rp = body.passively_discard_rest_of_body().await;
                        }
                    }
                }
            }
        }
        Outgoing => {
            match ctx_info.client_server_message_ordering {
                ClientServerMessageOrdering::FirstClientMessagePrecedesFirstServerMessage => {
                    // If we know that the first client message precedes the first server message,
                    // then all we need to do is wait for the first ApplicationData record so that
                    // we can perform key derivation. Upon seeing the first server message, we'll
                    // assert that we've successfully covertly signaled. If we haven't, that means
                    // that it's untrue that the first client message will always precede the first
                    // server message. This is a misconfiguration/bug; the adversary can never cause
                    // this to happen because we are on the outgoing side. The only thing the
                    // adversary can do in this situation is influence the Client/Incoming channel.
                    // So long as FirstClientMessagePreceedsFirstServerMessage is true, we should
                    // only enter this code if a client message was received. If it was received,
                    // then it passed through the Client/Incoming covert signal check, which would
                    // make us enter INVALID if it failed.
                    stallone::debug!("Waiting for first outgoing server ApplicationData message");
                    let (hdr, body) = loop {
                        let (hdr, body) = rp.parse_header().await?;
                        if hdr.record_type == tls::RecordType::ApplicationData {
                            break (hdr, body);
                        }
                        rp = body.passively_discard_rest_of_body().await;
                    };
                    let _seqnum = body
                        .sequence_number()
                        .ok_or(TLSRewriterError::ApplicationRecordIsntEncrypted { header: hdr })?;
                    Ok((
                        CryptoParameters::new(
                            ctx_info.rocky_secret,
                            &*ctx_info.tls_secret_provider,
                            ss,
                        ),
                        hdr,
                        body,
                    ))
                }
                ClientServerMessageOrdering::NoSuchOrdering => {
                    // If there is no such ordering we must:
                    // (1) keep silently outputting data without modifying it, while waiting for the
                    //     covert signal. We preview as we go.
                    // (2) Once we see the covert signal, then we take the next ApplicationRecord,
                    //     and use its MAC to signal to the client, that we know that they're a
                    //     ROCKY client.
                    struct XorOutputMac([u8; 16]);
                    impl OutputTagMangler for XorOutputMac {
                        fn mangle(self, mut tag: Tag) -> Tag {
                            for (a, b) in tag.0.iter_mut().zip(self.0.into_iter()) {
                                *a ^= b;
                            }
                            tag
                        }
                    }
                    stallone::debug!("Waiting to hear that client has covertly signaled");
                    let mut cp_holder: Option<CryptoParameters> = None;
                    loop {
                        let (hdr, body) = rp.parse_header().await?;
                        if hdr.record_type != tls::RecordType::ApplicationData {
                            rp = body.passively_discard_rest_of_body().await;
                            continue;
                        }
                        let _seqnum = body.sequence_number().ok_or(
                            TLSRewriterError::ApplicationRecordIsntEncrypted { header: hdr },
                        )?;
                        let cp = cp_holder.get_or_insert_with(|| {
                            CryptoParameters::new(
                                ctx_info.rocky_secret,
                                &*ctx_info.tls_secret_provider,
                                ss,
                            )
                        });
                        let did_covertly_signal = ss.successfully_covertly_signaled();
                        stallone::debug!(
                            "did_covertly_signal",
                            did_covertly_signal: bool = did_covertly_signal,
                        );
                        let (rp2, ()) = mangle_application_data(
                            hdr,
                            &cp.cipher_suite,
                            body,
                            &NormalTLSTaggerAndKeyStreamFactory(&cp.tls_keys.server_to_client),
                            DefaultInputMacVerifier,
                            &NormalTLSTaggerAndKeyStreamFactory(&cp.tls_keys.server_to_client),
                            XorOutputMac(if did_covertly_signal {
                                cp.covert_signaling_server_to_client_one_time_pad
                            } else {
                                [0; 16]
                            }),
                            |buf| {
                                // We do not mangle the buffer at all.
                                let buf = &buf[..];
                                preview_data.preview(buf);
                            },
                            ioo,
                            false, // Don't reorder TLS 1.3 records since we're previewing
                        )
                        .await?;
                        rp = rp2;
                        if did_covertly_signal {
                            stallone::debug!(
                                "We're done with the outgoing server covert signaling"
                            );
                            break;
                        }
                    }
                    let cp = cp_holder.take().unwrap();
                    let (hdr, body) = rp.parse_header().await?;
                    Ok((cp, hdr, body))
                }
            }
        }
    }
}

async fn parse_client_hello<'a, R: Default>(
    ss: &TLSConnectionSharedState,
    rp: tls_record_parser::AboutToParseHeader<'a, R>,
) -> Result<tls_record_parser::AboutToParseHeader<'a, R>> {
    let (hdr, body) = rp.parse_header_without_checking_version().await?;
    if hdr.record_type != tls::RecordType::Handshake {
        return Err(TLSRewriterError::ExpectedHandshakeHeaderForClientHello { actual: hdr });
    }

    const N: usize = 38;
    if hdr.size < N {
        return Err(TLSRewriterError::ClientHelloTooShort {
            actual: hdr.size,
            expected: N,
        });
    }

    let mut buffer = vec![0; hdr.size];
    let rp = body.passively_read_rest_of_body(&mut buffer).await;

    // Check that this is a ClientHello message
    let handshake_message_type = tls::HandshakeType::from(buffer[0]);
    if handshake_message_type != tls::HandshakeType::ClientHello {
        return Err(
            TLSRewriterError::FirstClientHandshakeRecordWasntClientHello {
                actual: handshake_message_type,
            },
        );
    }

    // The Client Version field should indicate TLS 1.2 for both TLS 1.2 and 1.3 connections. The
    // actual connection protocol is negotiated through other fields (the cipher suite and the
    // Supported Versions extension).
    let tls_version = u16::from_be_bytes([buffer[4], buffer[5]]);
    if tls_version != tls::TLS_VERSION_1_2 {
        return Err(TLSRewriterError::ClientHelloTLSVersionMismatch { tls_version });
    }

    // Read the Client Random field
    let mut client_random_buf = [0; 32];
    client_random_buf.copy_from_slice(&buffer[6..6 + 32]);
    let client_random = tls::ClientRandom(client_random_buf);
    stallone::info!(
        "Got client random",
        #[context(true)]
        client_random: tls::ClientRandom = client_random,
    );
    ss.transition_saw_client_random(client_random, buffer);

    Ok(rp)
}

pub(crate) async fn client<'a, R: Default + GetStreamChangeData>(
    ctx_info: &ContextualInfo,
    ioo: IncomingOrOutgoing,
    preview_data: &mut (impl CanPreviewPlaintextData + Send + 'static + ?Sized),
    ss: &TLSConnectionSharedState,
    rp: tls_record_parser::AboutToParseHeader<'a, R>,
) -> Result<(
    CryptoParameters,
    tls::RecordHeader,
    tls_record_parser::ParseRecordBody<'a, R>,
)> {
    let mut rp = parse_client_hello(ss, rp).await?;

    // Let's look for the first application data message.
    let (hdr, mut body) = loop {
        let (hdr, body) = rp.parse_header().await?;
        if hdr.record_type == tls::RecordType::ApplicationData {
            break (hdr, body);
        }
        rp = body.passively_discard_rest_of_body().await;
    };

    // Once we've gotten a second message from the client after Client Hello, the server-side
    // coroutine must have parsed the Server Hello record, so the cipher suite will be available.
    let cipher_suite = match ss.try_cipher_suite() {
        Some(x) => x,
        None => return Err(TLSRewriterError::ApplicationRecordWasntEncrypted { header: hdr }),
    };

    // In TLS 1.2, we can count on the ChangeCipherSpec message being sent right before encrypted
    // application traffic is sent. That message is optional in TLS 1.3, so we need to manually
    // initialize the sequence counter after the initial Client/Server Hello exchange finishes.
    if cipher_suite.version == tls::TlsVersion::Tls13 {
        stallone::debug!("Finished initial TLS 1.3 handshake, initializing Seqnum");
        body.start_new_sequence();
    }

    if body.sequence_number().is_none() {
        return Err(TLSRewriterError::ApplicationRecordWasntEncrypted { header: hdr });
    }

    // For TLS 1.3, we should have just received the Client Handshake Finished message, which is
    // encrypted with the handshake keys. This is the final handshake message the client will
    // receive before the start of application payloads.
    let (hdr, body) = match cipher_suite.version {
        tls::TlsVersion::Tls12 => (hdr, body),
        tls::TlsVersion::Tls13 => {
            // Derive the handshake keys so we can decrypt this message.
            let tls_keys = {
                let tls_secret_provider = &*ctx_info.tls_secret_provider;
                let client_random = ss.try_client_random().unwrap();
                tls::crypto::DerivedKeys::derive_tls13_handshake_keys(
                    tls_secret_provider,
                    &client_random,
                    &cipher_suite,
                )
            };
            let stream = tls_keys.client_to_server;

            // Read, decrypt, and parse the TLS record payload.
            let (mut rp, buffer) = tls13::read_and_decrypt_record(
                &hdr,
                body,
                &stream,
                &cipher_suite,
                tls::RecordType::Handshake,
            )
            .await?;

            let handshake_message_type = tls::HandshakeType::from(buffer[0]);
            if handshake_message_type != tls::HandshakeType::Finished {
                return Err(TLSRewriterError::UnexpectedHandshakeType {
                    actual: handshake_message_type,
                    expected: tls::HandshakeType::Finished,
                });
            }

            // For TLS 1.3, the sequence number needs to be reset once the traffic keys are used.
            stallone::debug!("Finished TLS 1.3 handshake, initializing Seqnum for traffic");
            rp.start_new_sequence();

            // Parse the next header now that the TLS 1.2 and 1.3 code paths are in the same state.
            rp.parse_header().await?
        }
    };

    let cp = CryptoParameters::new(ctx_info.rocky_secret, &*ctx_info.tls_secret_provider, ss);
    stallone::debug!("Beginning to operate on client for covert signaling");
    match ioo {
        Incoming => {
            let secret: &ServerCovertSignalingSecret = match &ctx_info.mode_specific {
                super::ModeSpecificContext::Server { server_secret } => server_secret.as_ref(),
                super::ModeSpecificContext::Client { .. } => {
                    panic!("We're the server.")
                }
            };

            let (rp, mac_result) = mangle_application_data(
                hdr,
                &cp.cipher_suite,
                body,
                &NormalTLSTaggerAndKeyStreamFactory(&cp.tls_keys.client_to_server),
                CovertSignalingInputTagVerifier {
                    crypto_params: &cp,
                    secret: &secret,
                },
                &NormalTLSTaggerAndKeyStreamFactory(&cp.tls_keys.client_to_server),
                PassthruOutputTagMangler,
                |buf| {
                    // We do not mangle the buffer.
                    let buf = &buf[..];
                    preview_data.preview(buf);
                },
                ioo,
                false, // Don't reorder TLS 1.3 records since we're previewing
            )
            .await?;
            match mac_result {
                None => {
                    return errors::FailedToCovertlySignalSnafu.fail();
                }
                Some((id, token)) => {
                    ss.transition_successfully_covertly_signaled(token);
                    stallone::debug!(
                        "Server received successful covert signal from client",
                        identity: CovertSignalingIdentity = id,
                        token: CovertSignalingToken = token,
                    );
                    let (hdr, body) = rp.parse_header().await?;
                    Ok((cp, hdr, body))
                }
            }
        }
        Outgoing => {
            // By the time the client sees the first encrypted record, we should've already seen,
            // and made a decision about, whether the server is a ROCKY server. If it isn't a ROCKY
            // server, then we should've entered an INVALID state.
            stallone::warn_assert!(ss.successfully_covertly_signaled());
            if !ss.successfully_covertly_signaled() {
                return Err(TLSRewriterError::AssertionFailure);
            }

            let token = match &ctx_info.mode_specific {
                super::ModeSpecificContext::Client {
                    covert_signaling_token,
                    ..
                } => covert_signaling_token,
                super::ModeSpecificContext::Server { .. } => {
                    panic!("We are the client!")
                }
            };

            let (rp, ()) = mangle_application_data(
                hdr,
                &cp.cipher_suite,
                body,
                &NormalTLSTaggerAndKeyStreamFactory(&cp.tls_keys.client_to_server),
                DefaultInputMacVerifier,
                &NormalTLSTaggerAndKeyStreamFactory(&cp.tls_keys.client_to_server),
                CovertSignalingOutputTagMangler {
                    crypto_params: &cp,
                    token: *token,
                },
                |buf| {
                    // We do not mangle the buffer, but we do passively observe it.
                    let buf = &buf[..];
                    preview_data.preview(buf);
                },
                ioo,
                false, // Don't reorder TLS 1.3 records since we're previewing
            )
            .await?;
            let (hdr, body) = rp.parse_header().await?;
            Ok((cp, hdr, body))
        }
    }
}

mod tls13 {
    use super::*;

    enum ServerHandshakeState {
        ExpectEncryptedExtensions,
        ExpectCertificateOrCertificateRequest,
        ExpectCertificate,
        ExpectCertificateVerify,
    }

    /// Retrieve the server handshake messages (after Server Hello) which need to be hashed for
    /// server certificate verification. Return the raw Cerificate Verify handshake payload.
    pub(crate) async fn get_server_handshake_hash_inputs<'a, R: Default>(
        mut rp: tls_record_parser::AboutToParseHeader<'a, R>,
        digest_ctx: &mut ring::digest::Context,
        stream: &tls::crypto::StreamPlusAEADKey,
        cs: &tls::CipherSuite,
    ) -> Result<(
        tls_record_parser::AboutToParseHeader<'a, R>,
        tls::RecordHeader,
        Vec<u8>,
    )> {
        let mut state = ServerHandshakeState::ExpectEncryptedExtensions;
        let (hdr, certificate_verify_body) = loop {
            // Retrieve the next TLS record, ignoring ChangeCipherSpec messages. Those are
            // unencrypted, and aren't used for server certificate verification. We expect all
            // other records to be encrypted handshake messages, which will have a plaintext record
            // type of `ApplicationData`.
            let (hdr, body) = rp.parse_header().await?;
            if hdr.record_type == tls::RecordType::ChangeCipherSpec {
                rp = body.passively_discard_rest_of_body().await;
                continue;
            } else if hdr.record_type != tls::RecordType::ApplicationData {
                return Err(TLSRewriterError::ExpectedEncryptedHandshakeMessages { actual: hdr });
            }

            // Read and decrypt the TLS record payload.
            let result =
                read_and_decrypt_record(&hdr, body, stream, cs, tls::RecordType::Handshake).await?;
            rp = result.0;
            let buffer = result.1;

            // Ensure the handshake record we just received is legal for our current state.
            let handshake_message_type = tls::HandshakeType::from(buffer[0]);
            match state {
                ServerHandshakeState::ExpectEncryptedExtensions => {
                    if handshake_message_type == tls::HandshakeType::EncryptedExtensions {
                        state = ServerHandshakeState::ExpectCertificateOrCertificateRequest;
                    } else {
                        return Err(TLSRewriterError::UnexpectedHandshakeType {
                            actual: handshake_message_type,
                            expected: tls::HandshakeType::EncryptedExtensions,
                        });
                    }
                }

                ServerHandshakeState::ExpectCertificateOrCertificateRequest => {
                    if handshake_message_type == tls::HandshakeType::Certificate {
                        state = ServerHandshakeState::ExpectCertificateVerify;
                    } else if handshake_message_type == tls::HandshakeType::CertificateRequest {
                        state = ServerHandshakeState::ExpectCertificate;
                    } else {
                        return Err(TLSRewriterError::UnexpectedHandshakeType {
                            actual: handshake_message_type,
                            expected: tls::HandshakeType::Certificate,
                        });
                    }
                }

                ServerHandshakeState::ExpectCertificate => {
                    if handshake_message_type == tls::HandshakeType::Certificate {
                        state = ServerHandshakeState::ExpectCertificateVerify;
                    } else {
                        return Err(TLSRewriterError::UnexpectedHandshakeType {
                            actual: handshake_message_type,
                            expected: tls::HandshakeType::Certificate,
                        });
                    }
                }

                ServerHandshakeState::ExpectCertificateVerify => {
                    // Once we get this message, we're finished hashing messages and can return
                    // this payload for certificate verification.
                    if handshake_message_type == tls::HandshakeType::CertificateVerify {
                        break (hdr, buffer);
                    } else {
                        return Err(TLSRewriterError::UnexpectedHandshakeType {
                            actual: handshake_message_type,
                            expected: tls::HandshakeType::CertificateVerify,
                        });
                    }
                }
            }

            digest_ctx.update(&buffer);
        };

        Ok((rp, hdr, certificate_verify_body))
    }

    /// Attempt to verify the server's certificate against a pinned public key.
    pub(crate) fn check_server_certificate(
        pinned_server_key: &PinnedServerPubKey,
        certificate_verify_header: tls::RecordHeader,
        certificate_verify_body: &[u8],
        handshake_hash: ring::digest::Digest,
    ) -> Result<()> {
        // This is the message that we need to check the signature of.
        let message = {
            let mut msg = Vec::new();
            msg.resize(64, 0x20_u8);
            msg.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
            msg.extend_from_slice(handshake_hash.as_ref());
            msg
        };

        if certificate_verify_body.len() < 8 {
            return Err(
                TLSRewriterError::CertificateVerifyTooShortForSignatureLength {
                    header: certificate_verify_header,
                },
            );
        }

        // Parse all remaining fields in the payload.
        let signature_scheme =
            tls::signature_scheme::SignatureScheme::try_from(u16::from_be_bytes([
                certificate_verify_body[4],
                certificate_verify_body[5],
            ]))?;
        let signature_len = usize::from(u16::from_be_bytes([
            certificate_verify_body[6],
            certificate_verify_body[7],
        ]));
        let signature = &certificate_verify_body[8..];
        if signature_len != signature.len() {
            return Err(TLSRewriterError::CertificateVerifyWrongSignatureLength {
                actual: signature.len(),
                expected: signature_len,
            });
        }

        // Run certificate verification against the pinned key.
        let alg = signature_scheme.verification_algorithm();
        let pinned_pubkey =
            ring::signature::UnparsedPublicKey::new(alg, pinned_server_key.as_der());
        match pinned_pubkey.verify(&message, signature) {
            Ok(()) => {
                stallone::debug!("Successfully verified TLS 1.3 server signature");
                Ok(())
            }
            Err(_) => {
                stallone::debug!(
                    "TLS 1.3 server signature verification failed",
                    signature_scheme: tls::signature_scheme::SignatureScheme = signature_scheme,
                    msg: &[u8] = message.as_slice(),
                    signature: &[u8] = signature,
                    alg: String = format!("{:?}", alg),
                );
                Err(TLSRewriterError::ServerSignatureVerificationFailed { signature_scheme })
            }
        }
    }

    /// Read an encrypted TLS 1.3 record from the provided `hdr` and `body`, then decrypt the
    /// record's payload, and confirm that the decrypted payload's type matches
    /// `expected_record_type`. Return the header-parsing stream and the decrypted payload (which
    /// has all padding bytes and the record-type byte stripped).
    pub(crate) async fn read_and_decrypt_record<'a, R: Default>(
        hdr: &tls::RecordHeader,
        body: tls_record_parser::ParseRecordBody<'a, R>,
        stream: &tls::crypto::StreamPlusAEADKey,
        cs: &tls::CipherSuite,
        expected_record_type: tls::RecordType,
    ) -> Result<(tls_record_parser::AboutToParseHeader<'a, R>, Vec<u8>)> {
        // Prepare the AAD before consuming the `body`.
        let seqnum = match body.sequence_number() {
            Some(x) => x,
            None => return Err(TLSRewriterError::ApplicationRecordWasntEncrypted { header: *hdr }),
        };
        let aad = tls::crypto::Aad::new(seqnum, hdr, cs);

        // Read the TLS record payload.
        let mut buffer = vec![0; hdr.size];
        let rp = body.passively_read_rest_of_body(&mut buffer).await;

        // Decrypt the message.
        let plaintext_len = stream
            .aead_decrypt(&[], seqnum, aad.as_ref(), &mut buffer)
            .ok_or(TLSRewriterError::DecryptionError)?;
        buffer.truncate(plaintext_len);

        // Strip padding and the record type byte, and check that the record type is as expected.
        let record_type =
            tls::RecordType::unpad_tls13(&mut buffer).ok_or(TLSRewriterError::NoRecordType)?;
        if record_type != expected_record_type {
            return Err(TLSRewriterError::UnexpectedRecordType {
                actual: record_type,
                expected: expected_record_type,
            });
        }

        Ok((rp, buffer))
    }
}
