#![deny(missing_docs)]

//! Identites for Balboa's covert signaling
//!
//! Initially, Balboa used the IP address of the peer of its TCP connection in order to establish
//! the _identity_ of the peer of the TCP connection. This has several problems:
//!
//! 1. It doesn't work with clients without stable IPs or clients behind NATs.
//! 2. It makes it hard to provision fresh identities for clients.
//!
//! [Balboa's initial covert signaling](https://www.usenix.org/system/files/sec21-rosen.pdf#subsection.2.6)
//! works by XOR-ing the MAC at the end of the first Application Data record with a secret value
//! derived from the TLS master secret and the Rocky secret (dependent on IP address). Balboa
//! will accept either the _actual_ valid MAC, or exactly one alternative which, since it's derived
//! from _both_ the actual MAC and the Rocky secret, will both prove to the server that the client
//! is a Balboa client, as well as authenticate the first application data record.
//!
//! To fix these problems, rather than only accepting _two_ MACs on the application data record, we
//! accept $`N + 1`$ MACs: the original MAC, sent by non-Balboa clients, and $`N`$ MACs for each of
//! $`N`$ possible identities that the Balboa server will allow.
//!
//! # Covert Signaling Protocol
//!
//! ## Initial Setup
//! Each balboa machine/server identity will generate two AES-128 keys, $`K_R,K_S`$. $`K_R`$ will
//! be shared, while $`K_S`$ _must_ remain secret.
//!
//! ## Connection Capability Generation
//! To create a connection capability/client identity, we take increment a counter of the number
//! of client identities that we've created. This counter shouldn't be allowed to increment past
//! $`2^{48}`$. It is critical that this incremented counter gets persisted to disk (e.g. via
//! `fdatasync()` or other means) before we consider the capability generated.
//!
//! Let $`i`$ be the contents of the counter.
//!
//! Let $`T`$, the "token", be $`\textsf{AES-Enc}_{K_S}(i)`$.
//!
//! The (cryptographic component of the) capability token is
//! $`T \| K_R \| \text{pinned server TLS public signing key}`$
//!
//! ## Covert Signaling (Client)
//!
//! Just like before, the client starts by verifying the server's public key signature on the TLS
//! handshake. If this fails, the client aborts.
//!
//! On the first outgoing Application Data record, the client will, just like before, manipulate
//! the MAC. However, the manipulation will look a bit different.
//!
//! Let $`K_M`$ be the TLS master secret. Let $`M`$ be the original/correct MAC. The client will
//! replace the outgoing MAC with $`M \oplus \textsf{AES-Enc}_{\textsf{KDF}(K_R \| K_M)}(T)`$.
//!
//! ## Covert Signaling (Server)
//!
//! Just like before, the server will look at the incoming MAC on the first application data record.
//!
//! Let $`M`$ be the _correct_ MAC for the incoming record. Let $`M'`$ be the incoming MAC.
//!
//! If $`M'=M`$, then the server will recognize the connection as a normal TLS connection, and
//! enter a transparent pass-thru state.
//!
//! Otherwise, the server will compute
//! $`T' \coloneqq \textsf{AES-Dec}_{\textsf{KDF}(K_R \| K_M)}(M' \oplus M)`$, the potential token.
//!
//! Next, the server will compute $`i'`$ as $`\textsf{AES-Dec}_{K_S}(T')`$. If $`i'`$ is under
//! $`2^{48}`$ then, with 80 bits of security, we can claim that the peer we're talking to was
//! given identity $`i'`$.

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use serde::{Deserialize, Serialize};
use stallone::LoggableMetadata;
use std::net::Ipv4Addr;
use subtle::ConstantTimeLess;

/// This corresponds to $`K_R`$ in the covert signaling protocol.
#[derive(LoggableMetadata, Debug, Clone, Copy, Hash, Serialize, Deserialize)]
pub struct RockySecret(pub [u8; 32]);

/// The identity (from the server's perspective) of a covert peer
pub type CovertSignalingIdentity = u64;
/// The maximum `CovertSignalingIdentity` value that is supported
pub const MAX_COVERT_SIGNALING_IDENTITY: u64 = 1 << 48;

/// An error returned if a covert signaling token is invalid.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidCovertSignalingToken;
impl std::fmt::Display for InvalidCovertSignalingToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for InvalidCovertSignalingToken {}

/// A server's covert signaling secret, corresponding to $`K_S`$ in the protocol.
#[derive(Clone, Debug)]
pub struct ServerCovertSignalingSecret(pub Aes128);
impl ServerCovertSignalingSecret {
    /// Load a covert signaling secret from bytes.
    pub fn from_bytes(key: [u8; 16]) -> Self {
        Self(Aes128::new((&key).into()))
    }
    /// Generate a `CovertSignalingToken` for a given identity.
    ///
    /// This function is deterministic. Calling it with the same `ident` will yield the same token.
    /// If your intention is to assign distinct identities to distinct tokens, then it is essential
    /// to _persist_ the counter that you're using for the identity.
    ///
    /// # Panics
    /// This function will panic if `ident >= MAX_COVERT_SIGNALING_IDENITY`
    pub fn generate_token(&self, ident: CovertSignalingIdentity) -> CovertSignalingToken {
        assert!(ident < MAX_COVERT_SIGNALING_IDENTITY);
        let ident = u128::from(ident);
        let ident = ident.to_le_bytes();
        let mut ident = aes::Block::from(ident);
        self.0.encrypt_block(&mut ident);
        CovertSignalingToken(ident.into())
    }

    /// Given a `token`, attempt to extract its identity, if it's valid, returning an `Err` if it's
    /// invalid.
    pub fn decode_token(
        &self,
        token: CovertSignalingToken,
    ) -> Result<CovertSignalingIdentity, InvalidCovertSignalingToken> {
        let mut block = GenericArray::from(token.0);
        self.0.decrypt_block(&mut block);
        let ident = u128::from_le_bytes(block.into());
        if bool::from(ident.ct_lt(&u128::from(MAX_COVERT_SIGNALING_IDENTITY))) {
            Ok(u64::try_from(ident).expect("We know that it's less than the max identity"))
        } else {
            Err(InvalidCovertSignalingToken)
        }
    }
}

/// A 16-byte token that will be used to authenticate the client to the server.
///
/// This corresponds to $`T`$ in the above protocol.
///
/// This is not _all_ the information that a client will need in order to connect to the server. The
/// client will also need the server's pinned TLS public key, $`K_R`$, among other information.
/// This token, however, is the only piece required for the covert _identification_.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, LoggableMetadata, Serialize, Deserialize)]
pub struct CovertSignalingToken(pub [u8; 16]);

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_covert_signaling_token(
            secret in any::<[u8; 16]>(),
            ident in 0_u64..MAX_COVERT_SIGNALING_IDENTITY
        ) {
            let secret = ServerCovertSignalingSecret::from_bytes(secret);
            prop_assert_eq!(Ok(ident), secret.decode_token(secret.generate_token(ident)));
        }
    }
}

/// The DER-encoded TLS public signature key of a server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PinnedServerPubKey(Vec<u8>);

impl PinnedServerPubKey {
    /// Wrap a DER-encoded RSA or EC public key in `Self`
    ///
    /// NOTE: due to limitations of `ring`, this public key won't be validated before it's used.
    pub fn from_der(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Get a reference to the DER-encoded bytes of the pubkey
    pub fn as_der(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Type representing the identity of the current Mickey.
#[derive(Clone, Debug)]
pub struct Identity {
    /// Hostname to use to connect to this Mickey.
    pub hostname: String,
    /// The secret $`K_S`$
    pub server_secret: ServerCovertSignalingSecret,
    /// The secret $`K_R`$
    pub rocky_secret: RockySecret,
}

impl Identity {
    /// Generate a capability to connect to the current Mickey.
    ///
    /// * `id` is the identity that will be presented when this capaiblity is used to connect to the
    ///   current Mickey.
    /// * `pinned_server_pub_key` is the TLS public key that this server will use to sign TLS
    ///   handshakes
    /// * `address` is the address that the receiver of the capability should use to connect to this
    ///   Mickey.
    pub fn generate_capability(
        &self,
        id: CovertSignalingIdentity,
        pinned_server_pub_key: PinnedServerPubKey,
        address: Address,
    ) -> Capability {
        Capability {
            covert_signaling_token: self.server_secret.generate_token(id),
            rocky_secret: self.rocky_secret,
            pinned_server_pub_key,
            address,
        }
    }
}

/// Type representing the address of a Mickey
///
/// i.e. information necessary for one Mickey to establish a connection to another Mickey via an
/// underlying carrier.
#[derive(Copy, Clone, Serialize, Deserialize, Debug, Hash, PartialEq, Eq, LoggableMetadata)]
pub struct Address {
    /// The IP address that should be used to connect to the Mickey.
    pub ip: Ipv4Addr,
}

/// A [capability](https://en.wikipedia.org/wiki/Capability-based_security) which allows the holder
/// to connect to a Mickey.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    /// The ID (token) of this capability.
    pub covert_signaling_token: CovertSignalingToken,

    /// The shared AES key of the Mickey which generated this capability.
    pub rocky_secret: RockySecret,

    /// The pinned server TLS signing key
    pub pinned_server_pub_key: PinnedServerPubKey,

    /// The address of the creator of this capability, at the time of
    /// creation.
    pub address: Address,
}
