use stallone::LoggableMetadata;

#[derive(Clone, Copy, Debug, PartialEq, Eq, LoggableMetadata)]
pub enum SHA2 {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, LoggableMetadata)]
pub enum SignatureScheme {
    // RSA-PKCS1-v1_5
    RsaPkcs15(SHA2),
    RsaPss(SHA2),
    // TODO: support NIST curves with EcDSA
    Ed25519,
}

impl SignatureScheme {
    pub fn verification_algorithm(&self) -> &'static dyn ring::signature::VerificationAlgorithm {
        use ring::signature::*;
        use SignatureScheme::*;
        use SHA2::*;
        match self {
            Ed25519 => &ring::signature::ED25519,
            RsaPkcs15(Sha256) => &RSA_PKCS1_2048_8192_SHA256,
            RsaPkcs15(Sha384) => &RSA_PKCS1_2048_8192_SHA384,
            RsaPkcs15(Sha512) => &RSA_PKCS1_2048_8192_SHA512,
            RsaPss(Sha256) => &RSA_PSS_2048_8192_SHA256,
            RsaPss(Sha384) => &RSA_PSS_2048_8192_SHA384,
            RsaPss(Sha512) => &RSA_PSS_2048_8192_SHA512,
        }
    }
}

#[derive(Debug, Clone, Copy, LoggableMetadata)]
pub struct UnknownSignatureScheme(pub u16);

impl std::fmt::Display for UnknownSignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Unknown signature scheme: {:X}", self.0)
    }
}

impl std::error::Error for UnknownSignatureScheme {}

impl TryFrom<u16> for SignatureScheme {
    type Error = UnknownSignatureScheme;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        use SignatureScheme::*;
        use SHA2::*;
        Ok(match value {
            0x0401 => RsaPkcs15(Sha256),
            0x0501 => RsaPkcs15(Sha384),
            0x0601 => RsaPkcs15(Sha512),
            0x0804 => RsaPss(Sha256),
            0x0805 => RsaPss(Sha384),
            0x0806 => RsaPss(Sha512),
            0x0807 => Ed25519,
            _ => {
                return Err(UnknownSignatureScheme(value));
            }
        })
    }
}
