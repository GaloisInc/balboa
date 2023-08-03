use crate::tls;
use parking_lot::{Mutex, RwLock};
use stallone::{warn_assert_eq, warn_assert_ne, LoggableMetadata};
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc,
};

use balboa_covert_signaling_types::CovertSignalingToken;

use super::CovertSignalingContextInner;

#[derive(Debug, Default)]
struct Atomic32Bytes([AtomicU64; 32 / 8]);
impl Atomic32Bytes {
    // TODO: I think that we ought to be able to use relaxed ordering for our purposes, since we're
    // synchronizing on the control word. For now, better safe than sorry :)

    fn acquire_load(&self) -> [u8; 32] {
        let mut out = [0; 32];
        for (dst, word) in out.chunks_exact_mut(8).zip(self.0.iter()) {
            dst.copy_from_slice(&word.load(Ordering::Acquire).to_ne_bytes()[..]);
        }
        out
    }

    fn release_store(&self, buf: [u8; 32]) {
        for (src, word) in buf.chunks_exact(8).zip(self.0.iter()) {
            word.store(
                u64::from_ne_bytes(src.try_into().unwrap()),
                Ordering::Release,
            );
        }
    }
}

#[derive(Debug, LoggableMetadata, Clone, Copy)]
pub enum TLSConnectionSharedStateSnapshot {
    InitialState,
    /// Transitioning here requires that the previous state was `InitialState`
    SawClientRandom,
    /// This state implies that we've seen the client random.
    /// We can only transition to this state if the previous state was `SawClientRandom`
    SawServerRandomAndCipherSuite,
    /// This state implies that we've seen the client random, the server random, and the
    /// ciphersuite.
    /// We can only transition to this state if the previous state was
    /// `SawServerRandomAndCipherSuite`
    SuccessfullyCovertlySignaled,
    Invalid,
}

pub(crate) struct TLSConnectionSharedState {
    // We want to avoid using locks as much as possible, since we'll be injected.
    // This should be a CRDT.
    control_word: AtomicU32,
    client_random: Atomic32Bytes,
    server_random: Atomic32Bytes,

    covert_signaling_context: Arc<RwLock<CovertSignalingContextInner>>,
    client_hello: Mutex<Option<Vec<u8>>>,
}

// TODO: is it possible for the adversary to cause some of these stern warnings to be emitted.

impl TLSConnectionSharedState {
    const CONTROL_WORD_IS_INVALID: u32 = 1 << 0;
    const CONTROL_WORD_SAW_CLIENT_RANDOM: u32 = 1 << 1;
    const CONTROL_WORD_SAW_SERVER_RANDOM_AND_CIPHER_SUITE: u32 = 1 << 2;
    const CONTROL_WORD_SAW_SUCCESSFULLY_COVERTLY_SIGNALED: u32 = 1 << 3;

    pub(crate) fn new(covert_signaling_context: Arc<RwLock<CovertSignalingContextInner>>) -> Self {
        TLSConnectionSharedState {
            control_word: Default::default(),
            client_random: Default::default(),
            server_random: Default::default(),
            covert_signaling_context,
            client_hello: Mutex::new(None),
        }
    }

    pub fn transition_invalid(&self) {
        stallone::debug!("TLS connection state change: transition invalid");
        self.control_word
            .fetch_or(Self::CONTROL_WORD_IS_INVALID, Ordering::Release);
    }

    /// This signals that we can trust the party on the other end.
    /// # This function will emit a stern warning if
    /// This function will panic if we've already successfully covertly signaled, or if we
    /// haven't yet seen the client random or server random. This WILL NOT panic if the current
    /// state is invalid.
    pub fn transition_successfully_covertly_signaled(&self, token: CovertSignalingToken) {
        stallone::debug!(
            "TLS connection state change: successfully covertly signaled",
            token: CovertSignalingToken = token
        );
        let result = self.control_word.fetch_or(
            Self::CONTROL_WORD_SAW_SUCCESSFULLY_COVERTLY_SIGNALED,
            Ordering::Release,
        );
        warn_assert_ne!(
            lhs: u32 = result & Self::CONTROL_WORD_SAW_CLIENT_RANDOM,
            zero: u32 = 0,
        );
        warn_assert_ne!(
            lhs: u32 = result & Self::CONTROL_WORD_SAW_SERVER_RANDOM_AND_CIPHER_SUITE,
            zero: u32 = 0,
        );
        warn_assert_eq!(
            lhs: u32 = result & Self::CONTROL_WORD_SAW_SUCCESSFULLY_COVERTLY_SIGNALED,
            zero: u32 = 0,
        );

        self.covert_signaling_context
            .write()
            .covertly_signaled(token);
    }

    /// # This function will emit a stern warning if
    /// This function will panic if we've already seen the server random, or if we haven't yet seen
    /// the client random. This WILL NOT panic if the current state is invalid.
    pub fn transition_saw_server_random_and_cipher_suite(
        &self,
        server_random: tls::ServerRandom,
        cipher_suite: tls::CipherSuite,
    ) {
        stallone::debug!(
            "TLS connection state change: saw server random and ciphersuite",
            server_random: tls::ServerRandom = server_random,
            cipher_suite: tls::CipherSuite = cipher_suite,
        );
        self.server_random.release_store(server_random.0);
        let result = self.control_word.fetch_or(
            Self::CONTROL_WORD_SAW_SERVER_RANDOM_AND_CIPHER_SUITE
                | u32::from(u16::from(cipher_suite)) << 16,
            Ordering::Release,
        );
        warn_assert_ne!(
            lhs: u32 = result & Self::CONTROL_WORD_SAW_CLIENT_RANDOM,
            zero: u32 = 0,
        );
        warn_assert_eq!(
            lhs: u32 = result & Self::CONTROL_WORD_SAW_SERVER_RANDOM_AND_CIPHER_SUITE,
            zero: u32 = 0,
        );
    }

    /// # This function will emit a stern warning if
    /// This function will panic if we've already seen the client random. This WILL NOT panic
    /// if the current state is invalid.
    pub fn transition_saw_client_random(
        &self,
        client_random: tls::ClientRandom,
        client_hello_bytes: Vec<u8>,
    ) {
        stallone::debug!(
            "TLS connection state change: saw client random",
            client_random: tls::ClientRandom = client_random,
        );
        self.client_random.release_store(client_random.0);
        let result = self
            .control_word
            .fetch_or(Self::CONTROL_WORD_SAW_CLIENT_RANDOM, Ordering::Release);
        warn_assert_eq!(
            lhs: u32 = result & Self::CONTROL_WORD_SAW_CLIENT_RANDOM,
            zero: u32 = 0,
        );

        // Store ClientHello message for TLS 1.3 certificate verification
        {
            let mut client_hello_mutex = self.client_hello.lock();
            *client_hello_mutex = Some(client_hello_bytes);
        }
    }

    /// Retrieve the body of the Client Hello handshake message that we previously stored. Issue a
    /// warning if we haven't filled in this value yet.
    pub(crate) fn client_hello(&self) -> Option<Vec<u8>> {
        // We record Client Random and Client Hello at the same time
        let word = self.control_word.load(Ordering::Acquire);
        if (word & Self::CONTROL_WORD_SAW_CLIENT_RANDOM) == 0 {
            stallone::warn!("TLSConnectionSharedState is missing client hello");
        }
        self.client_hello.lock().clone()
    }

    /// # This function will emit a stern warning if
    /// This function will panic if the client random has not yet been set. As a result, callers
    /// of this function should call `snapshot()` to first make this check themselves. Note that,
    /// this function *WILL NOT* panic just because the state is `Invalid`. This is to avoid a race
    /// condition in which the state goes invalid between when `snapshot()` is called and when
    /// `server_random()` is called
    pub fn server_random(&self) -> tls::ServerRandom {
        let word = self.control_word.load(Ordering::Acquire);
        if (word & Self::CONTROL_WORD_SAW_SERVER_RANDOM_AND_CIPHER_SUITE) == 0 {
            stallone::warn!("TLSConnectionSharedState is missing server random");
        }
        tls::ServerRandom(self.server_random.acquire_load())
    }

    /// # This function will emit a stern warning if
    /// This function will panic if the client random has not yet been set. As a result, callers
    /// of this function should call `snapshot()` to first make this check themselves. Note that,
    /// this function *WILL NOT* panic just because the state is `Invalid`. This is to avoid a race
    /// condition in which the state goes invalid between when `snapshot()` is called and when
    /// `client_random()` is called
    pub fn client_random(&self) -> tls::ClientRandom {
        let word = self.control_word.load(Ordering::Acquire);
        if (word & Self::CONTROL_WORD_SAW_CLIENT_RANDOM) == 0 {
            stallone::warn!("TLSConnectionSharedState is missing client random");
        }
        tls::ClientRandom(self.client_random.acquire_load())
    }

    pub fn try_client_random(&self) -> Option<tls::ClientRandom> {
        let word = self.control_word.load(Ordering::Acquire);
        if (word & Self::CONTROL_WORD_SAW_CLIENT_RANDOM) == 0 {
            None
        } else {
            Some(tls::ClientRandom(self.client_random.acquire_load()))
        }
    }

    pub fn try_cipher_suite(&self) -> Option<tls::CipherSuite> {
        let word = self.control_word.load(Ordering::Acquire);
        if (word & Self::CONTROL_WORD_SAW_SERVER_RANDOM_AND_CIPHER_SUITE) != 0 {
            Some(tls::CipherSuite::try_from(u16::try_from(word >> 16).unwrap()).unwrap())
        } else {
            None
        }
    }

    pub fn is_invalid(&self) -> bool {
        let word = self.control_word.load(Ordering::Acquire);
        (word & Self::CONTROL_WORD_IS_INVALID) != 0
    }

    pub fn did_see_server_hello(&self) -> bool {
        let word = self.control_word.load(Ordering::Acquire);
        (word & Self::CONTROL_WORD_SAW_SERVER_RANDOM_AND_CIPHER_SUITE) != 0
    }

    pub fn successfully_covertly_signaled(&self) -> bool {
        let word = self.control_word.load(Ordering::Acquire);
        (word & Self::CONTROL_WORD_SAW_SUCCESSFULLY_COVERTLY_SIGNALED) != 0
    }

    pub fn snapshot(&self) -> TLSConnectionSharedStateSnapshot {
        use TLSConnectionSharedStateSnapshot::*;
        let word = self.control_word.load(Ordering::Acquire);
        if (word & Self::CONTROL_WORD_IS_INVALID) != 0 {
            Invalid
        } else if (word & Self::CONTROL_WORD_SAW_SUCCESSFULLY_COVERTLY_SIGNALED) != 0 {
            warn_assert_ne!(
                lhs: u32 = word & Self::CONTROL_WORD_SAW_CLIENT_RANDOM,
                zero: u32 = 0,
            );
            warn_assert_ne!(
                lhs: u32 = word & Self::CONTROL_WORD_SAW_SERVER_RANDOM_AND_CIPHER_SUITE,
                zero: u32 = 0,
            );
            SuccessfullyCovertlySignaled
        } else if (word & Self::CONTROL_WORD_SAW_SERVER_RANDOM_AND_CIPHER_SUITE) != 0 {
            warn_assert_ne!(
                lhs: u32 = word & Self::CONTROL_WORD_SAW_CLIENT_RANDOM,
                zero: u32 = 0,
            );
            // This check is redundant, because of the if. It's helpful for clarity, tho.
            warn_assert_eq!(
                lhs: u32 = word & Self::CONTROL_WORD_SAW_SUCCESSFULLY_COVERTLY_SIGNALED,
                zero: u32 = 0,
            );
            SawServerRandomAndCipherSuite
        } else if (word & Self::CONTROL_WORD_SAW_CLIENT_RANDOM) != 0 {
            // These checks are redundant because of the if. It's helpful for clarity, tho.
            warn_assert_eq!(
                lhs: u32 = word & Self::CONTROL_WORD_SAW_SERVER_RANDOM_AND_CIPHER_SUITE,
                zero: u32 = 0,
            );
            warn_assert_eq!(
                lhs: u32 = word & Self::CONTROL_WORD_SAW_SUCCESSFULLY_COVERTLY_SIGNALED,
                zero: u32 = 0,
            );
            SawClientRandom
        } else {
            // These checks are redundant because of the if. It's helpful for clarity, tho.
            warn_assert_eq!(
                lhs: u32 = word & Self::CONTROL_WORD_SAW_SERVER_RANDOM_AND_CIPHER_SUITE,
                zero: u32 = 0,
            );
            warn_assert_eq!(
                lhs: u32 = word & Self::CONTROL_WORD_SAW_CLIENT_RANDOM,
                zero: u32 = 0,
            );
            warn_assert_eq!(
                lhs: u32 = word & Self::CONTROL_WORD_SAW_SUCCESSFULLY_COVERTLY_SIGNALED,
                zero: u32 = 0,
            );
            InitialState
        }
    }
}
