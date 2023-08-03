//! Utilities to implement our covert signaling protocol.
//! # Covert Signaling Protocol
//! ## Initial Setup
//! Each balboa machine/server identity will generate two AES-128 keys, $`K_R,K_S`$. $`K_R`$ will be
//! shared, while $`K_S`$ _must_ remain secret.
//!
//! ## Connection Capability Generation
//! To create a connection capability/client identity, we increment a counter of the number of
//! client identities that we've created. This counter shouldn't be allowed to increment past
//! $`2^{48}`$ (`MAX_COVERT_SIGNALING_IDENITY`). It is critical that this incremented counter gets
//! persisted to disk (e.g. via `fdatasync()` or other means) before we consider the capability
//! generated.
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
//! On the first outgoing Application Data record, the client will, just like before, manipulate the
//! MAC. However, the manipulation will look a bit different.
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
//! If $`M'=M`$, then the server will recognize the connection as a normal TLS connection, and enter
//! a transparent pass-thru state.
//!
//! Otherwise, the server will compute
//! $`T' \coloneqq \textsf{AES-Dec}_{\textsf{KDF}(K_R \| K_M)}(M' \oplus M)`$, the potential token.
//!
//! Next, the server will compute $`i'`$ as $`\textsf{AES-Dec}_{K_S}(T')`$. If $`i'`$ is under
//! $`2^{48}`$ then, with 80 bits of security, we can claim that the peer we're talking to was given
//! identity $`i'`$.
use crate::tls::crypto::Tag;
use aes::{
    cipher::{BlockDecrypt, BlockEncrypt},
    Aes128,
};
use balboa_covert_signaling_types::{
    CovertSignalingIdentity, CovertSignalingToken, ServerCovertSignalingSecret,
    MAX_COVERT_SIGNALING_IDENTITY,
};
use subtle::ConstantTimeEq;
use subtle::ConstantTimeLess;

use crate::tls_rewriter::{
    errors,
    utils::{InputTagVerifier, OutputTagMangler},
};

fn mangle_output_tag(
    covert_signaling_client_to_server_auth: &Aes128,
    token: CovertSignalingToken,
    mut tag: Tag,
) -> Tag {
    let mut token: aes::Block = token.0.into();
    covert_signaling_client_to_server_auth.encrypt_block(&mut token);
    for (dst, x) in tag.0.iter_mut().zip(token.iter()) {
        *dst ^= *x;
    }
    tag
}

pub(crate) struct CovertSignalingOutputTagMangler<'a> {
    pub(crate) crypto_params: &'a super::CryptoParameters,
    pub(crate) token: CovertSignalingToken,
}
impl OutputTagMangler for CovertSignalingOutputTagMangler<'_> {
    fn mangle(self, tag: Tag) -> Tag {
        mangle_output_tag(
            &self.crypto_params.covert_signaling_client_to_server_auth,
            self.token,
            tag,
        )
    }
}

/// Implement `try_accept()` from `InputTagVerifier`
/// Given the correct and observed MACs, either error out, return `None` if the peer doesn't have
/// balboa enabled, or `Some(id)` if the peer has the identity `id`.
fn verify_input_tag(
    covert_signaling_client_to_server_auth: &Aes128,
    server_secret: &ServerCovertSignalingSecret,
    correct: Tag,
    observed: Tag,
) -> crate::tls_rewriter::Result<Option<(CovertSignalingIdentity, CovertSignalingToken)>> {
    if bool::from(observed.0.ct_eq(&correct.0)) {
        return Ok(None);
    }
    let mut block = correct.0;
    for (dst, src) in block.iter_mut().zip(observed.0.iter()) {
        *dst ^= *src;
    }
    let mut block = aes::Block::from(block);
    covert_signaling_client_to_server_auth.decrypt_block(&mut block);
    let token = CovertSignalingToken(block.into());
    server_secret.0.decrypt_block(&mut block);
    let ident = u128::from_le_bytes(block.into());
    if bool::from(ident.ct_lt(&u128::from(MAX_COVERT_SIGNALING_IDENTITY))) {
        Ok(Some((
            u64::try_from(ident).expect("We know that it's less than the max identity"),
            token,
        )))
    } else {
        Err(
            errors::TLSRewriterError::MismatchedMACDuringServerIncomingCovertSignaling {
                actual: observed,
                correct_expected: correct,
            },
        )
    }
}

pub(crate) struct CovertSignalingInputTagVerifier<'a> {
    pub(crate) crypto_params: &'a super::CryptoParameters,
    pub(crate) secret: &'a ServerCovertSignalingSecret,
}
impl InputTagVerifier for CovertSignalingInputTagVerifier<'_> {
    type Output = Option<(CovertSignalingIdentity, CovertSignalingToken)>;

    fn try_accept(self, correct: Tag, observed: Tag) -> crate::tls_rewriter::Result<Self::Output> {
        verify_input_tag(
            &self.crypto_params.covert_signaling_client_to_server_auth,
            self.secret,
            correct,
            observed,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::KeyInit;
    use balboa_covert_signaling_types::MAX_COVERT_SIGNALING_IDENTITY;
    use proptest::prelude::*;

    fn test_roundtrip_encoding_inner(
        correct_tag: [u8; 16],
        server_secret: [u8; 16],
        covert_signaling_client_to_server_auth: [u8; 16],
        identity: CovertSignalingIdentity,
    ) -> proptest::test_runner::TestCaseResult {
        let covert_signaling_client_to_server_auth =
            Aes128::new((&covert_signaling_client_to_server_auth).into());
        let server_secret = ServerCovertSignalingSecret::from_bytes(server_secret);
        let mut bad_tag = correct_tag;
        for x in bad_tag.iter_mut() {
            *x ^= 0xff;
        }
        let bad_tag = Tag(bad_tag);
        let correct_tag = Tag(correct_tag);
        let r = verify_input_tag(
            &covert_signaling_client_to_server_auth,
            &server_secret,
            correct_tag,
            bad_tag,
        );
        prop_assert!(
            r.is_err(),
            "result should've bene error for bad tag: {:?}",
            r
        );
        let token = server_secret.generate_token(identity);
        let out = mangle_output_tag(&covert_signaling_client_to_server_auth, token, correct_tag);
        match verify_input_tag(
            &covert_signaling_client_to_server_auth,
            &server_secret,
            correct_tag,
            out,
        ) {
            Ok(got_id) => {
                prop_assert_eq!(got_id, Some((identity, token)));
            }
            Err(e) => {
                prop_assert!(false, "Unexpected error {:?}", e);
            }
        }
        match verify_input_tag(
            &covert_signaling_client_to_server_auth,
            &server_secret,
            correct_tag,
            correct_tag,
        ) {
            Ok(got_id) => {
                prop_assert_eq!(got_id, None);
            }
            Err(e) => {
                prop_assert!(false, "Unexpected error {:?}", e);
            }
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn test_roundtrip_encoding(
            correct_tag in any::<[u8; 16]>(),
            server_secret in any::<[u8; 16]>(),
            covert_signaling_client_to_server_auth in any::<[u8; 16]>(),
            identity in 0..MAX_COVERT_SIGNALING_IDENTITY,
        ) {
            test_roundtrip_encoding_inner(
                correct_tag,
                server_secret,
                covert_signaling_client_to_server_auth,
                identity,
            )?;
        }
    }
}
