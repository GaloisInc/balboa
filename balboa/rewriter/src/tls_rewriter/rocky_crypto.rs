use crate::{
    tls,
    tls_rewriter::{shared_state::TLSConnectionSharedState, TLSRewriterMode, TlsSecretProvider},
};
use aes::{cipher::KeyInit, Aes128};
use balboa_covert_signaling_types::RockySecret;
use smallvec::SmallVec;

pub(crate) struct CryptoParameters {
    pub(crate) cipher_suite: tls::CipherSuite,
    pub(crate) tls_keys: tls::crypto::DerivedKeys,
    pub(crate) covert_signaling_client_to_server_auth: Aes128,
    pub(crate) covert_signaling_server_to_client_one_time_pad: [u8; 16],
    // NOTE: the IVs here are always going to be based on the sequence number.
    pub(crate) rocky_server_to_client_key: tls::crypto::StreamPlusAEADKey,
    pub(crate) rocky_client_to_server_key: tls::crypto::StreamPlusAEADKey,
}

impl CryptoParameters {
    /// It's important to only call this once you know that the SSLKEYLOGFILE has been populated.
    pub(crate) fn new(
        rocky_secret: RockySecret,
        tls_secret_provider: &dyn TlsSecretProvider,
        ss: &TLSConnectionSharedState,
    ) -> Self {
        assert!(ss.did_see_server_hello());
        // did_see_server_hello implies that we have this information:
        let client_random = ss.client_random();
        let server_random = ss.server_random();
        let cipher_suite = ss.try_cipher_suite().unwrap();

        let mut h = blake3::Hasher::new_derive_key("rocky 08/03/2022 KDF context");

        let (start, tls_keys) = match cipher_suite.version {
            tls::TlsVersion::Tls12 => {
                let master_secret = match tls_secret_provider
                    .tls_secret(tls::TlsSecretLabel::Tls12, &client_random)
                {
                    tls::TlsSecret::Tls12(x) => x,
                    e => panic!("Illegal entry for TLS 1.2 secret: {:?}", e),
                };
                stallone::debug!(
                    "Deriving TLS 1.2 CryptoParameters",
                    rocky_secret: RockySecret = rocky_secret,
                    client_random: tls::ClientRandom = client_random,
                    server_random: tls::ServerRandom = server_random,
                    cipher_suite: tls::CipherSuite = cipher_suite,
                    master_secret: tls::MasterSecret12 = master_secret,
                );
                let start = std::time::Instant::now();
                let tls_keys = tls::crypto::DerivedKeys::derive_from_tls12(
                    &cipher_suite,
                    &master_secret,
                    &client_random,
                    &server_random,
                );

                h.update(&master_secret.0);
                h.update(&rocky_secret.0);

                (start, tls_keys)
            }

            tls::TlsVersion::Tls13 => {
                let client_traffic_secret = match tls_secret_provider
                    .tls_secret(tls::TlsSecretLabel::Tls13ClientTraffic, &client_random)
                {
                    tls::TlsSecret::Tls13ClientTraffic(x) => x,
                    e => panic!("Illegal entry for TLS 1.3 client traffic secret: {:?}", e),
                };
                let server_traffic_secret = match tls_secret_provider
                    .tls_secret(tls::TlsSecretLabel::Tls13ServerTraffic, &client_random)
                {
                    tls::TlsSecret::Tls13ServerTraffic(x) => x,
                    e => panic!("Illegal entry for TLS 1.3 server traffic secret: {:?}", e),
                };

                stallone::debug!(
                    "Deriving TLS 1.3 Traffic CryptoParameters",
                    rocky_secret: RockySecret = rocky_secret,
                    client_random: tls::ClientRandom = client_random,
                    server_random: tls::ServerRandom = server_random,
                    cipher_suite: tls::CipherSuite = cipher_suite,
                    client_traffic_secret: tls::Tls13ClientTrafficSecret = client_traffic_secret,
                    server_traffic_secret: tls::Tls13ServerTrafficSecret = server_traffic_secret,
                );

                let start = std::time::Instant::now();
                let tls_keys = tls::crypto::DerivedKeys::derive_from_tls13(
                    &cipher_suite,
                    tls::Tls13ClientSecret::Traffic(&client_traffic_secret),
                    tls::Tls13ServerSecret::Traffic(&server_traffic_secret),
                );

                h.update(client_traffic_secret.0.as_slice());
                h.update(server_traffic_secret.0.as_slice());
                h.update(&rocky_secret.0);

                (start, tls_keys)
            }
        };

        let derived_key_material = {
            let mut out = [0; 16 * 4];
            h.finalize_xof().fill(&mut out);
            out
        };

        // TODO: implement and switch to TLS 1.3 keys
        let mut covert_signaling_client_to_server_auth = [0; 16];
        covert_signaling_client_to_server_auth.copy_from_slice(&derived_key_material[0..16]);
        assert_ne!(covert_signaling_client_to_server_auth, [0; 16]);
        let covert_signaling_client_to_server_auth =
            Aes128::new(&covert_signaling_client_to_server_auth.into());
        let mut covert_signaling_server_to_client_one_time_pad = [0; 16];
        covert_signaling_server_to_client_one_time_pad
            .copy_from_slice(&derived_key_material[0..16]);
        assert_ne!(covert_signaling_server_to_client_one_time_pad, [0; 16]);
        let out = CryptoParameters {
            cipher_suite,
            tls_keys,
            covert_signaling_client_to_server_auth,
            covert_signaling_server_to_client_one_time_pad,
            // TODO: XXX: Security: is it okay that our nonce prefix is zeros?
            rocky_server_to_client_key: tls::crypto::StreamPlusAEADKey::new_aes_gcm(
                tls::AesSize::Aes128,
                [0, 0, 0, 0],
                &derived_key_material[16..32],
            ),
            rocky_client_to_server_key: tls::crypto::StreamPlusAEADKey::new_aes_gcm(
                tls::AesSize::Aes128,
                [0, 0, 0, 0],
                &derived_key_material[32..48],
            ),
        };
        stallone::debug!(
            "Derived crypto parameters",
            duration: std::time::Duration = start.elapsed()
        );
        out
    }
    pub fn tls_key(&self, mode: TLSRewriterMode) -> &tls::crypto::StreamPlusAEADKey {
        match mode {
            TLSRewriterMode::Client => &self.tls_keys.client_to_server,
            TLSRewriterMode::Server => &self.tls_keys.server_to_client,
        }
    }

    pub fn rocky_key(&self, mode: TLSRewriterMode) -> &tls::crypto::StreamPlusAEADKey {
        match mode {
            TLSRewriterMode::Client => &self.rocky_client_to_server_key,
            TLSRewriterMode::Server => &self.rocky_server_to_client_key,
        }
    }
}

pub fn rocky_cipher_nonce(seqnum: tls::SequenceNumber) -> [u8; 8] {
    seqnum.0.to_be_bytes()
}

pub fn compute_rocky_aad(
    header: &tls::RecordHeader,
    packet_explicit_nonce: &[u8],
) -> SmallVec<[u8; 32]> {
    // The sequence number is the IV, so it doesn't need to be in AAD.
    let mut out = SmallVec::new();
    out.push(header.record_type.into());
    out.extend_from_slice(&header.version.to_be_bytes());
    out.extend_from_slice(&(header.size as u16).to_be_bytes());
    out.extend_from_slice(packet_explicit_nonce);
    out
}

pub(crate) mod client_mac_mangling;
