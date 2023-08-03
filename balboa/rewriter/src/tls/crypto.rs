use crate::{tls::*, tls_rewriter::TlsSecretProvider};
use aes::cipher::{
    generic_array::GenericArray, BlockEncrypt, InnerIvInit, KeyInit, KeyIvInit, StreamCipher,
    StreamCipherSeek,
};
use poly1305::Poly1305;
use smallvec::SmallVec;
use stallone::LoggableMetadata;

fn evaluate_prf(prf: Prf, mut result: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
    // We run P_hash with seed = label || seed
    let key = ring::hmac::Key::new(prf.into(), secret);
    let initial_ctx = ring::hmac::Context::with_key(&key);
    let mut ctx = initial_ctx.clone();
    ctx.update(label);
    ctx.update(seed);
    let mut a = ctx.sign();
    while !result.is_empty() {
        let mut ctx = initial_ctx.clone();
        ctx.update(a.as_ref());
        ctx.update(label);
        ctx.update(seed);
        let b = ctx.sign();
        let delta = result.len().min(b.as_ref().len());
        result[0..delta].copy_from_slice(&b.as_ref()[0..delta]);
        result = &mut result[delta..];
        let mut ctx = initial_ctx.clone();
        ctx.update(a.as_ref());
        a = ctx.sign();
    }
}

#[derive(Clone)]
enum RawAesKey {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}

enum StreamPlusAEADKeyInner {
    // TODO: support CBC mode, tho it'll be with a different API.
    ChaCha20Poly1305 {
        iv: [u8; 12],
        key: [u8; 32],
    },
    AesGCM {
        nonce_prefix: [u8; 4],
        // These two keys are the same.
        ring_key: ring::aead::LessSafeKey,
        aes_key: RawAesKey,
    },
    AesGCM13 {
        iv: [u8; 12],
        // These two keys are the same.
        ring_key: ring::aead::LessSafeKey,
        aes_key: RawAesKey,
    },
}

// All of our AEAD algorithms have a 16-bit tag
#[derive(Debug, LoggableMetadata, Clone, Copy)]
pub struct Tag(pub [u8; 16]);

/// Creates a new GCM nonce for use in TLS 1.2.
///
/// TLS 1.2 uses a 4-byte prefix concatenated with an 8-byte explicit value to construct the GCM
/// nonce.
fn new_gcm_nonce_tls12(nonce_prefix: &[u8; 4], explicit_nonce: &[u8]) -> [u8; 12] {
    assert_eq!(explicit_nonce.len(), 8);
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(nonce_prefix);
    nonce[4..].copy_from_slice(explicit_nonce);
    nonce
}

/// Initializes a new GCM counter from the given nonce.
///
/// A GCM counter is a big-endian counter, where the 12 most-significant bytes are set to the
/// provided nonce, and the 4 least-significant bytes are set to the value 1.
fn new_gcm_counter(nonce: [u8; 12]) -> [u8; 16] {
    let mut counter = [0; 16];
    counter[..12].copy_from_slice(&nonce);
    counter[15] = 1;
    counter
}

enum KeyStreamInner {
    Aes128(ctr::Ctr128BE<aes::Aes128>),
    Aes256(ctr::Ctr128BE<aes::Aes256>),
    ChaCha20(chacha20::ChaCha20),
}

pub struct KeyStream(KeyStreamInner);

impl std::fmt::Debug for KeyStream {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.0 {
            KeyStreamInner::Aes128(_) => write!(f, "<KeyStream: AES128>"),
            KeyStreamInner::Aes256(_) => write!(f, "<KeyStream: AES256>"),
            KeyStreamInner::ChaCha20(_) => write!(f, "<KeyStream: ChaCha20>"),
        }
    }
}

impl KeyStream {
    pub fn xor(&mut self, dst: &mut [u8]) {
        match &mut self.0 {
            KeyStreamInner::ChaCha20(x) => x.apply_keystream(dst),
            KeyStreamInner::Aes128(x) => x.apply_keystream(dst),
            KeyStreamInner::Aes256(x) => x.apply_keystream(dst),
        }
    }
}

enum TagComputerInner {
    Poly1305 {
        poly1305: Poly1305,
        aad_size: usize,
        content_size: usize,
        buffer: SmallVec<[u8; 16]>,
    },
    GCM {
        gcm: ring::aead::gcm::Context,
        aad_size: usize,
        content_size: usize,
        final_xor: ring::aead::block::Block,
        buffer: SmallVec<[u8; 16]>,
    },
}

pub struct TagComputer(TagComputerInner);
impl TagComputer {
    fn update_tag(
        h: &mut impl ghash::universal_hash::UniversalHash,
        content_size: &mut usize,
        buffer: &mut SmallVec<[u8; 16]>,
        mut input: &[u8],
    ) {
        // Luckily, GCM and Poly1305 both have block sizes of 16 bytes.
        *content_size = content_size.checked_add(input.len()).unwrap();
        while !input.is_empty() {
            debug_assert_ne!(buffer.len(), 16);
            debug_assert!(buffer.len() <= 16);
            if buffer.is_empty() && input.len() >= 16 {
                h.update(std::slice::from_ref(GenericArray::from_slice(
                    &input[0..16],
                )));
                input = &input[16..];
            } else {
                let remaining_space_in_buffer = 16 - buffer.len();
                let add_to_buffer = remaining_space_in_buffer.min(input.len());
                buffer.extend_from_slice(&input[0..add_to_buffer]);
                input = &input[add_to_buffer..];
                if buffer.len() == 16 {
                    h.update(std::slice::from_ref(GenericArray::from_slice(&buffer[..])));
                    buffer.clear();
                }
            }
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        match &mut self.0 {
            TagComputerInner::GCM {
                gcm,
                aad_size: _,
                content_size,
                final_xor: _,
                buffer,
            } => {
                *content_size = content_size.checked_add(input.len()).unwrap();
                debug_assert!(buffer.len() <= 16);
                if !buffer.is_empty() {
                    // If the buffer isn't empty, then we first need to try to fill the buffer.
                    let space_remaining_in_buffer = 16 - buffer.len();
                    let to_add = space_remaining_in_buffer.min(input.len());
                    buffer.extend_from_slice(&input[0..to_add]);
                    input = &input[to_add..];
                    if buffer.len() != 16 {
                        // If the buffer isn't full, then there's nothing that we can do.
                        return;
                    }
                    let mut arr = [0; 16];
                    arr.copy_from_slice(&buffer[..]);
                    gcm.update_block(ring::aead::block::Block::from(&arr));
                    buffer.clear();
                }
                let whole_blocks_to_take = input.len() / 16;
                if whole_blocks_to_take > 0 {
                    gcm.update_blocks(&input[0..whole_blocks_to_take * 16]);
                    input = &input[whole_blocks_to_take * 16..];
                }
                debug_assert!(input.len() < 16);
                buffer.extend_from_slice(input);
            }

            TagComputerInner::Poly1305 {
                poly1305,
                aad_size: _,
                content_size,
                buffer,
            } => {
                Self::update_tag(poly1305, content_size, buffer, input);
            }
        }
    }

    pub fn finalize(self) -> Tag {
        match self.0 {
            TagComputerInner::GCM {
                mut gcm,
                aad_size,
                content_size,
                final_xor,
                buffer,
            } => {
                if !buffer.is_empty() {
                    debug_assert!(buffer.len() < 16);
                    let mut block = [0; 16];
                    block[0..buffer.len()].copy_from_slice(&buffer[..]);
                    gcm.update_block((&block).into());
                }
                {
                    let mut block = [0; 16];
                    block[..8].copy_from_slice(&(aad_size.checked_shl(3).unwrap()).to_be_bytes());
                    block[8..]
                        .copy_from_slice(&(content_size.checked_shl(3).unwrap()).to_be_bytes());
                    gcm.update_block(ring::aead::block::Block::from(&block));
                }
                let mut out_block = [0; 16];
                out_block.copy_from_slice(
                    gcm.pre_finish(|mut pre_tag| {
                        use ring::aead::block::Block;
                        pre_tag.bitxor_assign(final_xor);
                        ring::aead::Tag(*Block::from(pre_tag).as_ref())
                    })
                    .as_ref(),
                );
                Tag(out_block)
            }

            TagComputerInner::Poly1305 {
                mut poly1305,
                aad_size,
                content_size,
                buffer,
            } => {
                use ghash::universal_hash::UniversalHash;
                if !buffer.is_empty() {
                    poly1305.update_padded(&buffer[..]);
                }
                let aad_size = aad_size as u64;
                let content_size = content_size as u64;
                let mut size_block = [0; 16];
                size_block[0..8].copy_from_slice(&aad_size.to_le_bytes());
                size_block[8..16].copy_from_slice(&content_size.to_le_bytes());
                poly1305.update(std::slice::from_ref(GenericArray::from_slice(
                    &size_block[..],
                )));
                let mut out_block = [0; 16];
                out_block[..].copy_from_slice(&poly1305.finalize());
                Tag(out_block)
            }
        }
    }
}

/// Creates a new nonce using the TLS sequence number.
///
/// This is used by all TLS 1.3 cipher suites, as well as the ChaCha20Poly1305 cipher suite in TLS
/// 1.2.
fn tls_seq_nonce(iv: &[u8; 12], sequence_number: SequenceNumber) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..12].copy_from_slice(&sequence_number.0.to_be_bytes()[..]);
    for (dst, src) in nonce.iter_mut().zip(iv.iter()) {
        *dst ^= *src;
    }
    nonce
}

pub struct StreamPlusAEADKey(StreamPlusAEADKeyInner);
impl StreamPlusAEADKey {
    pub fn new_chacha20_poly1305(iv: [u8; 12], key: [u8; 32]) -> Self {
        StreamPlusAEADKey(StreamPlusAEADKeyInner::ChaCha20Poly1305 { iv, key })
    }

    pub fn new_aes_gcm(size: AesSize, nonce_prefix: [u8; 4], key_bytes: &[u8]) -> Self {
        assert_eq!(key_bytes.len(), size.into());
        StreamPlusAEADKey(StreamPlusAEADKeyInner::AesGCM {
            nonce_prefix,
            ring_key: ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(
                    match size {
                        AesSize::Aes128 => &ring::aead::AES_128_GCM,
                        AesSize::Aes256 => &ring::aead::AES_256_GCM,
                    },
                    key_bytes,
                )
                .unwrap(),
            ),
            aes_key: match size {
                AesSize::Aes128 => {
                    RawAesKey::Aes128(aes::Aes128::new_from_slice(key_bytes).unwrap())
                }
                AesSize::Aes256 => {
                    RawAesKey::Aes256(aes::Aes256::new_from_slice(key_bytes).unwrap())
                }
            },
        })
    }

    pub fn new_aes_gcm13(size: AesSize, iv: [u8; 12], key_bytes: &[u8]) -> Self {
        assert_eq!(key_bytes.len(), size.into());
        StreamPlusAEADKey(StreamPlusAEADKeyInner::AesGCM13 {
            iv,
            ring_key: ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(
                    match size {
                        AesSize::Aes128 => &ring::aead::AES_128_GCM,
                        AesSize::Aes256 => &ring::aead::AES_256_GCM,
                    },
                    key_bytes,
                )
                .unwrap(),
            ),
            aes_key: match size {
                AesSize::Aes128 => {
                    RawAesKey::Aes128(aes::Aes128::new_from_slice(key_bytes).unwrap())
                }
                AesSize::Aes256 => {
                    RawAesKey::Aes256(aes::Aes256::new_from_slice(key_bytes).unwrap())
                }
            },
        })
    }

    pub fn compute_tag(
        &self,
        explicit_nonce: &[u8],
        sequence_number: SequenceNumber,
        aad: &[u8],
    ) -> TagComputer {
        fn new_gcm_tag_computer(
            ring_key: &ring::aead::LessSafeKey,
            aes_key: &RawAesKey,
            nonce: [u8; 12],
            aad: &[u8],
        ) -> TagComputer {
            let mut gcm_counter = GenericArray::from(new_gcm_counter(nonce));

            match aes_key {
                RawAesKey::Aes128(x) => x.encrypt_block(&mut gcm_counter),
                RawAesKey::Aes256(x) => x.encrypt_block(&mut gcm_counter),
            }

            let gcm_counter_array: [u8; 16] = gcm_counter.into();

            let cpu_featues = ring_key.key.cpu_features;
            let ring_key = match &ring_key.key.inner {
                ring::aead::KeyInner::AesGcm(key) => key,
                _ => panic!(" we have an AES key"),
            };
            let gcm = ring::aead::gcm::Context::new(
                &ring_key.gcm_key,
                ring::aead::Aad::from(aad),
                cpu_featues,
            );

            TagComputer(TagComputerInner::GCM {
                gcm,
                aad_size: aad.len(),
                content_size: 0,
                final_xor: ring::aead::block::Block::from(&gcm_counter_array),
                buffer: SmallVec::new(),
            })
        }

        match &self.0 {
            StreamPlusAEADKeyInner::AesGCM {
                nonce_prefix,
                ring_key,
                aes_key,
            } => {
                let nonce = new_gcm_nonce_tls12(nonce_prefix, explicit_nonce);
                new_gcm_tag_computer(ring_key, aes_key, nonce, aad)
            }

            StreamPlusAEADKeyInner::AesGCM13 {
                iv,
                ring_key,
                aes_key,
            } => {
                let nonce = tls_seq_nonce(iv, sequence_number);
                new_gcm_tag_computer(ring_key, aes_key, nonce, aad)
            }

            StreamPlusAEADKeyInner::ChaCha20Poly1305 { iv, key } => {
                use poly1305::universal_hash::UniversalHash;
                let mut mac_key = poly1305::Key::default();
                let nonce = tls_seq_nonce(iv, sequence_number);
                chacha20::ChaCha20::new_from_slices(&key[..], &nonce[..])
                    .unwrap()
                    .apply_keystream(&mut mac_key[..]);
                let mut poly1305 = Poly1305::new(&GenericArray::clone_from_slice(&mac_key[..]));
                poly1305.update_padded(aad);
                TagComputer(TagComputerInner::Poly1305 {
                    poly1305,
                    aad_size: aad.len(),
                    content_size: 0,
                    buffer: SmallVec::new(),
                })
            }
        }
    }

    // Packet_nonce is the nonce provided in the packet.
    pub fn aead_encrypt(
        &self,
        explicit_nonce: &[u8],
        sequence_number: SequenceNumber,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Tag {
        fn gcm_aead_encrypt(
            ring_key: &ring::aead::LessSafeKey,
            nonce: [u8; 12],
            aad: &[u8],
            buffer: &mut [u8],
        ) -> Tag {
            let ring_nonce = ring::aead::Nonce::assume_unique_for_key(nonce);
            let mut tag = Tag([0; 16]);
            tag.0.copy_from_slice(
                ring_key
                    .seal_in_place_separate_tag(ring_nonce, ring::aead::Aad::from(aad), buffer)
                    .unwrap()
                    .as_ref(),
            );
            tag
        }

        match &self.0 {
            StreamPlusAEADKeyInner::ChaCha20Poly1305 { iv, key } => {
                assert!(explicit_nonce.is_empty());
                let nonce = tls_seq_nonce(iv, sequence_number);
                let nonce = ring::aead::Nonce::assume_unique_for_key(nonce);
                let ring_key = ring::aead::LessSafeKey::new(
                    ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key[..]).unwrap(),
                );
                let mut tag = Tag([0; 16]);
                tag.0.copy_from_slice(
                    ring_key
                        .seal_in_place_separate_tag(nonce, ring::aead::Aad::from(aad), buffer)
                        .unwrap()
                        .as_ref(),
                );
                tag
            }

            StreamPlusAEADKeyInner::AesGCM {
                nonce_prefix,
                ring_key,
                ..
            } => {
                let nonce = new_gcm_nonce_tls12(nonce_prefix, explicit_nonce);
                gcm_aead_encrypt(ring_key, nonce, aad, buffer)
            }

            StreamPlusAEADKeyInner::AesGCM13 { iv, ring_key, .. } => {
                assert_eq!(explicit_nonce.len(), 0);
                let nonce = tls_seq_nonce(iv, sequence_number);
                gcm_aead_encrypt(ring_key, nonce, aad, buffer)
            }
        }
    }

    /// Decrypt an AEAD payload in-place, and return the length of the plaintext in the resulting
    /// buffer.
    pub fn aead_decrypt(
        &self,
        explicit_nonce: &[u8],
        sequence_number: SequenceNumber,
        aad_raw: &[u8],
        buffer: &mut [u8],
    ) -> Option<usize> {
        fn aead_decrypt_inner(
            ring_key: &ring::aead::LessSafeKey,
            nonce: [u8; 12],
            aad_raw: &[u8],
            buffer: &mut [u8],
        ) -> Option<usize> {
            let aad = ring::aead::Aad::from(aad_raw);
            let nonce = ring::aead::Nonce::assume_unique_for_key(nonce);
            let plain_len = ring_key.open_in_place(nonce, aad, buffer).ok()?.len();
            Some(plain_len)
        }

        match &self.0 {
            StreamPlusAEADKeyInner::ChaCha20Poly1305 { iv, key } => {
                assert!(explicit_nonce.is_empty());
                let nonce = tls_seq_nonce(iv, sequence_number);
                let ring_key = ring::aead::LessSafeKey::new(
                    ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key[..]).unwrap(),
                );
                aead_decrypt_inner(&ring_key, nonce, aad_raw, buffer)
            }

            StreamPlusAEADKeyInner::AesGCM {
                nonce_prefix,
                ring_key,
                ..
            } => {
                let nonce = new_gcm_nonce_tls12(nonce_prefix, explicit_nonce);
                aead_decrypt_inner(ring_key, nonce, aad_raw, buffer)
            }

            StreamPlusAEADKeyInner::AesGCM13 { iv, ring_key, .. } => {
                assert_eq!(explicit_nonce.len(), 0);
                let nonce = tls_seq_nonce(iv, sequence_number);
                aead_decrypt_inner(ring_key, nonce, aad_raw, buffer)
            }
        }
    }

    pub fn key_stream(&self, explicit_nonce: &[u8], sequence_number: SequenceNumber) -> KeyStream {
        fn new_gcm_key_stream(aes_key: &RawAesKey, nonce: [u8; 12]) -> KeyStreamInner {
            let gcm_counter = GenericArray::from(new_gcm_counter(nonce));
            match aes_key {
                RawAesKey::Aes128(x) => {
                    let mut stream = ctr::Ctr128BE::<aes::Aes128>::from_core(
                        ctr::CtrCore::inner_iv_init(x.clone(), &gcm_counter),
                    );
                    stream.seek(16_u128);
                    KeyStreamInner::Aes128(stream)
                }
                RawAesKey::Aes256(x) => {
                    let mut stream = ctr::Ctr128BE::<aes::Aes256>::from_core(
                        ctr::CtrCore::inner_iv_init(x.clone(), &gcm_counter),
                    );
                    stream.seek(16_u128);
                    KeyStreamInner::Aes256(stream)
                }
            }
        }

        KeyStream(match &self.0 {
            StreamPlusAEADKeyInner::AesGCM {
                nonce_prefix,
                aes_key,
                ..
            } => {
                let nonce = new_gcm_nonce_tls12(nonce_prefix, explicit_nonce);
                new_gcm_key_stream(aes_key, nonce)
            }

            StreamPlusAEADKeyInner::AesGCM13 { iv, aes_key, .. } => {
                assert!(explicit_nonce.is_empty());
                let nonce = tls_seq_nonce(iv, sequence_number);
                new_gcm_key_stream(aes_key, nonce)
            }

            StreamPlusAEADKeyInner::ChaCha20Poly1305 { key, iv } => {
                assert!(explicit_nonce.is_empty());
                let nonce = tls_seq_nonce(iv, sequence_number);
                let mut stream = chacha20::ChaCha20::new_from_slices(&key[..], &nonce[..]).unwrap();
                let mut skip = [0_u8; 64];
                // When used with Poly1305, the first 64 bytes of the stream won't be used for
                // encryption.
                stream.apply_keystream(&mut skip[..]);
                KeyStreamInner::ChaCha20(stream)
            }
        })
    }
}

pub struct DerivedKeys {
    pub server_to_client: StreamPlusAEADKey,
    pub client_to_server: StreamPlusAEADKey,
}

impl std::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "<DerivedKeys>")
    }
}

impl DerivedKeys {
    fn derive_keys(
        prf: &Prf,
        master_secret: &MasterSecret12,
        client_random: &ClientRandom,
        server_random: &ServerRandom,
        client_mac: &mut [u8],
        server_mac: &mut [u8],
        client_key: &mut [u8],
        server_key: &mut [u8],
        client_iv: &mut [u8],
        server_iv: &mut [u8],
    ) {
        let mut seed = [0; 32 + 32];
        seed[0..32].copy_from_slice(&server_random.0[..]);
        seed[32..64].copy_from_slice(&client_random.0[..]);
        let n = client_mac.len()
            + server_mac.len()
            + client_key.len()
            + server_key.len()
            + client_iv.len()
            + server_iv.len();
        let mut key_material_vec: smallvec::SmallVec<[u8; 1024]> = smallvec::smallvec!(0; n);
        evaluate_prf(
            *prf,
            &mut key_material_vec[..],
            &master_secret.0[..],
            b"key expansion",
            &seed[..],
        );
        let mut key_material: &[u8] = &key_material_vec[..];
        client_mac.copy_from_slice(&key_material[0..client_mac.len()]);
        key_material = &key_material[client_mac.len()..];
        server_mac.copy_from_slice(&key_material[0..server_mac.len()]);
        key_material = &key_material[server_mac.len()..];
        client_key.copy_from_slice(&key_material[0..client_key.len()]);
        key_material = &key_material[client_key.len()..];
        server_key.copy_from_slice(&key_material[0..server_key.len()]);
        key_material = &key_material[server_key.len()..];
        client_iv.copy_from_slice(&key_material[0..client_iv.len()]);
        key_material = &key_material[client_iv.len()..];
        server_iv.copy_from_slice(&key_material[0..server_iv.len()]);
        // key_material = &key_material[server_iv.len()..];
    }

    pub fn derive_from_tls12(
        suite: &CipherSuite,
        master_secret: &MasterSecret12,
        client_random: &ClientRandom,
        server_random: &ServerRandom,
    ) -> DerivedKeys {
        if suite.version != TlsVersion::Tls12 {
            panic!("This method is for TLS1.2");
        }
        match suite.cipher {
            Cipher::ChaCha20Poly1305 => {
                let mut server_iv = [0; 12];
                let mut client_iv = [0; 12];
                let mut server_key = [0; 32];
                let mut client_key = [0; 32];
                Self::derive_keys(
                    &suite.prf_hash,
                    master_secret,
                    client_random,
                    server_random,
                    &mut [],
                    &mut [],
                    &mut client_key[..],
                    &mut server_key[..],
                    &mut client_iv[..],
                    &mut server_iv[..],
                );
                DerivedKeys {
                    server_to_client: StreamPlusAEADKey::new_chacha20_poly1305(
                        server_iv, server_key,
                    ),
                    client_to_server: StreamPlusAEADKey::new_chacha20_poly1305(
                        client_iv, client_key,
                    ),
                }
            }
            Cipher::Aes(_, AesMode::GCM13) => panic!("This method is for TLS1.2"),
            Cipher::Aes(size, AesMode::GCM) => {
                let mut server_iv = [0; 4];
                let mut client_iv = [0; 4];
                let mut server_key = [0; 32];
                let mut client_key = [0; 32];
                Self::derive_keys(
                    &suite.prf_hash,
                    master_secret,
                    client_random,
                    server_random,
                    &mut [],
                    &mut [],
                    &mut client_key[0..size.into()],
                    &mut server_key[0..size.into()],
                    &mut client_iv[..],
                    &mut server_iv[..],
                );
                DerivedKeys {
                    server_to_client: StreamPlusAEADKey::new_aes_gcm(
                        size,
                        server_iv,
                        &server_key[0..size.into()],
                    ),
                    client_to_server: StreamPlusAEADKey::new_aes_gcm(
                        size,
                        client_iv,
                        &client_key[0..size.into()],
                    ),
                }
            }
            Cipher::Aes(_, AesMode::CBC(_)) => unimplemented!("CBC mode"),
        }
    }

    /// Derive bidirectional AEAD crypto streams for TLS 1.3. This works for both handshake and
    /// traffic crypto.
    pub fn derive_from_tls13(
        suite: &CipherSuite,
        client_secret: Tls13ClientSecret,
        server_secret: Tls13ServerSecret,
    ) -> DerivedKeys {
        if suite.version != TlsVersion::Tls13 {
            panic!("This method is for TLS1.3");
        }

        let client_secret_raw = match client_secret {
            Tls13ClientSecret::Handshake(x) => x.0,
            Tls13ClientSecret::Traffic(x) => x.0,
        };
        let server_secret_raw = match server_secret {
            Tls13ServerSecret::Handshake(x) => x.0,
            Tls13ServerSecret::Traffic(x) => x.0,
        };

        let prk_algorithm = suite.prf_hash.into();
        let client_secret_prk =
            ring::hkdf::Prk::new_less_safe(prk_algorithm, client_secret_raw.as_slice());
        let server_secret_prk =
            ring::hkdf::Prk::new_less_safe(prk_algorithm, server_secret_raw.as_slice());

        let aead_algorithm = suite
            .cipher
            .try_into()
            .unwrap_or_else(|e| panic!("Illegal cipher suite for TLS 1.3: {:?}", e));

        let client_key = tls13::derive_traffic_key(&client_secret_prk, aead_algorithm);
        let client_iv = tls13::derive_traffic_iv(&client_secret_prk);

        let server_key = tls13::derive_traffic_key(&server_secret_prk, aead_algorithm);
        let server_iv = tls13::derive_traffic_iv(&server_secret_prk);

        match suite.cipher {
            Cipher::ChaCha20Poly1305 => DerivedKeys {
                server_to_client: StreamPlusAEADKey::new_chacha20_poly1305(
                    server_iv.0,
                    server_key.0,
                ),
                client_to_server: StreamPlusAEADKey::new_chacha20_poly1305(
                    client_iv.0,
                    client_key.0,
                ),
            },

            Cipher::Aes(size, AesMode::GCM13) => DerivedKeys {
                server_to_client: StreamPlusAEADKey::new_aes_gcm13(
                    size,
                    server_iv.0,
                    &server_key.0[..size.into()],
                ),
                client_to_server: StreamPlusAEADKey::new_aes_gcm13(
                    size,
                    client_iv.0,
                    &client_key.0[..size.into()],
                ),
            },

            x @ Cipher::Aes(_, _) => panic!("Illegal cipher suite for TLS 1.3: {:?}", x),
        }
    }

    pub(crate) fn derive_tls13_handshake_keys(
        tls_secret_provider: &dyn TlsSecretProvider,
        client_random: &ClientRandom,
        suite: &CipherSuite,
    ) -> Self {
        let client_handshake_secret = match tls_secret_provider
            .tls_secret(TlsSecretLabel::Tls13ClientHandshake, client_random)
        {
            TlsSecret::Tls13ClientHandshake(x) => x,
            e => {
                panic!("Illegal entry for TLS 1.3 client handshake secret: {:?}", e)
            }
        };
        let server_handshake_secret = match tls_secret_provider
            .tls_secret(TlsSecretLabel::Tls13ServerHandshake, client_random)
        {
            TlsSecret::Tls13ServerHandshake(x) => x,
            e => {
                panic!("Illegal entry for TLS 1.3 server handshake secret: {:?}", e)
            }
        };

        stallone::debug!(
            "Deriving TLS 1.3 handshake keys",
            client_random: ClientRandom = client_random,
            cipher_suite: CipherSuite = suite,
            client_handshake_secret: Tls13ClientHandshakeSecret = client_handshake_secret,
            server_handshake_secret: Tls13ServerHandshakeSecret = server_handshake_secret,
        );

        let start = std::time::Instant::now();
        let tls_keys = DerivedKeys::derive_from_tls13(
            suite,
            Tls13ClientSecret::Handshake(&client_handshake_secret),
            Tls13ServerSecret::Handshake(&server_handshake_secret),
        );
        stallone::debug!(
            "Derived TLS 1.3 handshake keys",
            duration: std::time::Duration = start.elapsed()
        );
        tls_keys
    }
}

// TLS 1.3 key derivation key adapted from rustls. Mostly we've added the `RawKey` type so we can
// access the raw key bytes, but this `From<Okm ...>` implementation is almost identical to the one
// for `ring::aead::UnboundKey`.
//
// The code in this module is copied from rustls (see rustls/src/tls13/key_schedule.rs).
mod tls13 {
    pub(crate) struct RawKey(pub(crate) [u8; 32]);

    impl From<ring::hkdf::Okm<'_, &'static ring::aead::Algorithm>> for RawKey {
        fn from(okm: ring::hkdf::Okm<&'static ring::aead::Algorithm>) -> Self {
            let mut key_bytes_array = [0; 32];
            let key_bytes = &mut key_bytes_array[..okm.len().key_len()];
            okm.fill(key_bytes).unwrap();
            RawKey(key_bytes_array)
        }
    }

    #[derive(Default)]
    pub(crate) struct Iv(pub(crate) [u8; ring::aead::NONCE_LEN]);

    impl From<ring::hkdf::Okm<'_, IvLen>> for Iv {
        fn from(okm: ring::hkdf::Okm<IvLen>) -> Self {
            let mut r = Self(Default::default());
            okm.fill(&mut r.0[..]).unwrap();
            r
        }
    }

    struct IvLen;

    impl ring::hkdf::KeyType for IvLen {
        fn len(&self) -> usize {
            ring::aead::NONCE_LEN
        }
    }

    pub(crate) fn derive_traffic_key(
        secret: &ring::hkdf::Prk,
        aead_algorithm: &'static ring::aead::Algorithm,
    ) -> RawKey {
        hkdf_expand(secret, aead_algorithm, b"key", &[])
    }

    pub(crate) fn derive_traffic_iv(secret: &ring::hkdf::Prk) -> Iv {
        hkdf_expand(secret, IvLen, b"iv", &[])
    }

    fn hkdf_expand<T, L>(secret: &ring::hkdf::Prk, key_type: L, label: &[u8], context: &[u8]) -> T
    where
        T: for<'a> From<ring::hkdf::Okm<'a, L>>,
        L: ring::hkdf::KeyType,
    {
        hkdf_expand_info(secret, key_type, label, context, |okm| okm.into())
    }

    fn hkdf_expand_info<F, T, L>(
        secret: &ring::hkdf::Prk,
        key_type: L,
        label: &[u8],
        context: &[u8],
        f: F,
    ) -> T
    where
        F: for<'b> FnOnce(ring::hkdf::Okm<'b, L>) -> T,
        L: ring::hkdf::KeyType,
    {
        const LABEL_PREFIX: &[u8] = b"tls13 ";

        let output_len = u16::to_be_bytes(key_type.len() as u16);
        let label_len = u8::to_be_bytes((LABEL_PREFIX.len() + label.len()) as u8);
        let context_len = u8::to_be_bytes(context.len() as u8);

        let info = &[
            &output_len[..],
            &label_len[..],
            LABEL_PREFIX,
            label,
            &context_len[..],
            context,
        ];
        let okm = secret.expand(info, key_type).unwrap();

        f(okm)
    }
}

pub(crate) enum Aad {
    Tls12([u8; 13]),
    Tls13([u8; 5]),
}

impl Aad {
    pub(crate) fn new(seqnum: SequenceNumber, header: &RecordHeader, cs: &CipherSuite) -> Self {
        let len = header.size - cs.cipher.explicit_nonce_size();
        match cs.version {
            TlsVersion::Tls12 => {
                let len = len - cs.cipher.auth_tag_size();
                let mut aad = [0; 13];
                aad[0..8].copy_from_slice(&seqnum.0.to_be_bytes());
                aad[8] = header.record_type.into();
                aad[9..11].copy_from_slice(&header.version.to_be_bytes());
                aad[11..13].copy_from_slice(&(len as u16).to_be_bytes());
                Aad::Tls12(aad)
            }
            TlsVersion::Tls13 => {
                let mut aad = [0; 5];
                aad[0] = u8::from(RecordType::ApplicationData);
                aad[1..3].copy_from_slice(&TLS_VERSION_1_2.to_be_bytes());
                aad[3..].copy_from_slice(&(len as u16).to_be_bytes());
                Aad::Tls13(aad)
            }
        }
    }

    pub(crate) fn as_ref(&self) -> &[u8] {
        match self {
            Aad::Tls12(xs) => xs,
            Aad::Tls13(xs) => xs,
        }
    }
}

#[cfg(test)]
impl proptest::prelude::Arbitrary for SequenceNumber {
    type Parameters = ();
    type Strategy = proptest::prelude::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;
        (0..=0b0011111111111111111111111111111111111111111111111111111111111111_u64)
            .prop_map(|x| SequenceNumber(x))
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[derive(Debug)]
    struct PrfTestVector {
        n: usize,
        prf: Prf,
        master_secret: &'static [u8],
        seed: &'static [u8],
        expected: &'static [u8],
    }

    include!("prf.test_vectors");

    #[test]
    fn test_prf() {
        for (i, test_vector) in PRF_TEST_VECTORS.iter().enumerate() {
            let mut out = vec![0 as u8; test_vector.n];
            evaluate_prf(
                test_vector.prf,
                &mut out[..],
                test_vector.master_secret,
                b"key expansion",
                test_vector.seed,
            );
            assert_eq!(&out[..], test_vector.expected, "[{}] {:?}", i, test_vector);
        }
    }

    #[test]
    fn test_chacha_keystream_matches_ring() {
        let dk = StreamPlusAEADKey::new_chacha20_poly1305(
            [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
            [
                25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 25, 26, 27, 28, 29,
                30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            ],
        );
        let mut buf = [0; 5];
        buf.copy_from_slice(b"hello");
        let seqnum = SequenceNumber(573);
        let _tag = dk.aead_encrypt(&[], seqnum, &[], &mut buf[..]);
        let mut ks = dk.key_stream(&[], seqnum);
        ks.xor(&mut buf[..]);
        assert_eq!(&buf[..], b"hello");
    }

    #[test]
    fn test_aes_keystream_matches_ring() {
        let dk = StreamPlusAEADKey::new_aes_gcm(
            AesSize::Aes128,
            [1, 2, 3, 4],
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        );
        let mut buf = [0; 5];
        buf.copy_from_slice(b"hello");
        let packet_nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let seqnum = SequenceNumber(0);
        let _tag = dk.aead_encrypt(&packet_nonce, seqnum, &[], &mut buf[..]);
        let mut ks = dk.key_stream(&packet_nonce, seqnum);
        ks.xor(&mut buf[..]);
        assert_eq!(&buf[..], b"hello");
    }

    #[derive(Debug)]
    struct ChaChaTestVector {
        plaintext: &'static [u8],
        key: &'static [u8],
        nonce: &'static [u8],
        ciphertext: &'static [u8],
        tag: &'static [u8],
    }

    include!("chacha20.test_vectors");

    #[test]
    fn test_chacha20() {
        for (i, tv) in CHACHA20_TEST_VECTORS.iter().enumerate() {
            let mut stream = chacha20::ChaCha20::new_from_slices(tv.key, tv.nonce).unwrap();
            let mut skip = [0; 64];
            stream.apply_keystream(&mut skip[..]);
            let mut plaintext = tv.plaintext.to_vec();
            stream.apply_keystream(&mut plaintext[..]);
            assert_eq!(&plaintext[..], &tv.ciphertext[..], "[{}] {:?}", i, tv);
        }
    }

    #[test]
    fn test_chacha20_aead() {
        for tv in CHACHA20_TEST_VECTORS.iter() {
            let key = ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, tv.key).unwrap(),
            );
            let mut plaintext = tv.plaintext.to_vec();
            let actual_tag = key
                .seal_in_place_separate_tag(
                    ring::aead::Nonce::try_assume_unique_for_key(tv.nonce).unwrap(),
                    ring::aead::Aad::empty(),
                    &mut plaintext[..],
                )
                .unwrap();
            assert_eq!(actual_tag.as_ref(), tv.tag);
            assert_eq!(&plaintext[..], tv.ciphertext);
        }
    }

    fn helper_test_tag_computation(
        explicit_nonce: &[u8],
        seqnum: SequenceNumber,
        key: &StreamPlusAEADKey,
        mut body: Vec<Vec<u8>>,
        aad: Vec<u8>,
    ) -> bool {
        let mut combined_body = Vec::new();
        for x in body.iter() {
            combined_body.extend_from_slice(&x);
        }
        let expected_tag = key.aead_encrypt(
            &explicit_nonce[..],
            seqnum,
            &aad,
            &mut combined_body.clone(),
        );
        let mut tc = key.compute_tag(&explicit_nonce[..], seqnum, &aad);
        let mut ks = key.key_stream(&explicit_nonce[..], seqnum);
        for part in body.iter_mut() {
            ks.xor(part);
            tc.update(part);
        }
        let actual_tag = tc.finalize();
        actual_tag.0 == expected_tag.0
    }

    #[test]
    fn test_ring_matches_aes_gcm_lib() {
        use aes_gcm::aead::AeadInPlace;
        let key_bytes = [0; 16];
        let nonce = [0; 12];
        let ring_key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key_bytes[..]).unwrap(),
        );
        let lib_key = aes_gcm::Aes128Gcm::new(&GenericArray::clone_from_slice(&key_bytes[..]));
        let lib_tag = lib_key
            .encrypt_in_place_detached(&GenericArray::clone_from_slice(&nonce[..]), &[], &mut [])
            .unwrap()
            .to_vec();
        let ring_tag = ring_key
            .seal_in_place_separate_tag(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::empty(),
                &mut [],
            )
            .unwrap()
            .as_ref()
            .to_vec();
        let ring2_tag = StreamPlusAEADKey::new_aes_gcm(AesSize::Aes128, [0; 4], &key_bytes)
            .aead_encrypt(&[0; 8], SequenceNumber(0), &[], &mut [])
            .0
            .to_vec();
        assert_eq!(lib_tag, ring_tag);
        assert_eq!(ring2_tag, ring_tag);
    }

    proptest! {
    #[test]
        fn test_tag_computer_aes_gcm256(
            key in any::<[u8; 32]>(),
            explicit_nonce in any::<[u8; 8]>(),
            seqnum in any::<SequenceNumber>(),
            nonce_prefix in any::<[u8; 4]>(),
            aad in any::<Vec<u8>>(),
            body in any::<Vec<Vec<u8>>>(),
        ) {
            let key = StreamPlusAEADKey::new_aes_gcm(AesSize::Aes256, nonce_prefix, &key[..]);
            prop_assert!(helper_test_tag_computation(&explicit_nonce[..], seqnum, &key, body, aad));
        }
    }

    #[test]
    fn test_zero_tag_computer_aes_gcm128() {
        let key = StreamPlusAEADKey::new_aes_gcm(AesSize::Aes128, [0; 4], &[0; 16]);
        assert!(helper_test_tag_computation(
            &[0; 8],
            SequenceNumber(0),
            &key,
            vec![],
            vec![]
        ));
    }

    #[test]
    fn test_more_tests_tag_computer_aes_gcm128() {
        let key = StreamPlusAEADKey::new_aes_gcm(AesSize::Aes128, [0; 4], &[0; 16]);
        assert!(helper_test_tag_computation(
            &[0; 8],
            SequenceNumber(0),
            &key,
            vec![vec![5; 16], vec![5]],
            vec![],
        ));
        assert!(helper_test_tag_computation(
            &[0; 8],
            SequenceNumber(0),
            &key,
            vec![vec![5; 32]],
            vec![],
        ));
        assert!(helper_test_tag_computation(
            &[0; 8],
            SequenceNumber(0),
            &key,
            vec![vec![5; 33]],
            vec![],
        ));
        assert!(helper_test_tag_computation(
            &[0; 8],
            SequenceNumber(0),
            &key,
            vec![vec![], vec![], vec![3]],
            vec![],
        ));
    }

    #[test]
    fn test_simple_tag_computer_aes_gcm128() {
        let key = StreamPlusAEADKey::new_aes_gcm(AesSize::Aes128, [0; 4], &[0; 16]);
        assert!(helper_test_tag_computation(
            &[0; 8],
            SequenceNumber(0),
            &key,
            vec![vec![0, 1]],
            vec![],
        ));
        assert!(helper_test_tag_computation(
            &[0; 8],
            SequenceNumber(0),
            &key,
            vec![vec![0], vec![1]],
            vec![],
        ));
    }

    proptest! {
        #[test]
        fn test_tag_computer_aes_gcm128(
            key in any::<[u8; 16]>(),
            explicit_nonce in any::<[u8; 8]>(),
            seqnum in any::<SequenceNumber>(),
            nonce_prefix in any::<[u8; 4]>(),
            aad in any::<Vec<u8>>(),
            body in any::<Vec<Vec<u8>>>(),
        ) {
            let key = StreamPlusAEADKey::new_aes_gcm(AesSize::Aes128, nonce_prefix, &key[..]);
            prop_assert!(helper_test_tag_computation(&explicit_nonce[..], seqnum, &key, body, aad));
        }
    }

    proptest! {
        #[test]
        fn test_tag_computer_chacha20_poly1305(
            key in any::<[u8; 32]>(),
            iv in any::<[u8; 12]>(),
            seqnum in any::<SequenceNumber>(),
            aad in any::<Vec<u8>>(),
            body in any::<Vec<Vec<u8>>>(),
        ) {
            let key = StreamPlusAEADKey::new_chacha20_poly1305(iv, key);
            prop_assert!(helper_test_tag_computation(&[], seqnum, &key, body, aad));
        }
    }
}
