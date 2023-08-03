use stallone::LoggableMetadata;

pub mod crypto;

pub const RECORD_MAX_SIZE: usize = (1 << 14) + 2048;

#[derive(Debug, PartialEq, Eq, Clone, Copy, LoggableMetadata)]
pub enum RecordType {
    Handshake,
    ApplicationData,
    ChangeCipherSpec,
    Alert,
    Other(u8),
}

impl RecordType {
    /// Extract the RecordType from a TLS 1.3 record, removing any padding bytes.
    pub(crate) fn unpad_tls13(message: &mut Vec<u8>) -> Option<Self> {
        loop {
            match message.pop() {
                Some(0) => {}
                Some(x) => return Some(Self::from(x)),
                None => return None,
            }
        }
    }
}

impl From<u8> for RecordType {
    fn from(x: u8) -> Self {
        match x {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            _ => RecordType::Other(x),
        }
    }
}

impl From<RecordType> for u8 {
    fn from(x: RecordType) -> Self {
        match x {
            RecordType::ChangeCipherSpec => 20,
            RecordType::Alert => 21,
            RecordType::Handshake => 22,
            RecordType::ApplicationData => 23,
            RecordType::Other(x) => x,
        }
    }
}

#[derive(Debug, Clone, Copy, LoggableMetadata)]
pub struct RecordHeader {
    pub record_type: RecordType,
    pub version: u16,
    pub size: usize,
}

pub const TLS_VERSION_1_2: u16 = 0x0303;

#[derive(Debug, Clone, Copy, PartialEq, LoggableMetadata)]
pub enum HandshakeType {
    HelloRequest,
    ClientHello,
    ServerHello,
    HelloVerifyRequest,
    NewSessionTicket,
    EndOfEarlyData,
    HelloRetryRequest,
    EncryptedExtensions,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    CertificateURL,
    CertificateStatus,
    KeyUpdate,
    MessageHash,
    Unknown(u8),
}

impl From<u8> for HandshakeType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => HandshakeType::HelloRequest,
            0x01 => HandshakeType::ClientHello,
            0x02 => HandshakeType::ServerHello,
            0x03 => HandshakeType::HelloVerifyRequest,
            0x04 => HandshakeType::NewSessionTicket,
            0x05 => HandshakeType::EndOfEarlyData,
            0x06 => HandshakeType::HelloRetryRequest,
            0x08 => HandshakeType::EncryptedExtensions,
            0x0b => HandshakeType::Certificate,
            0x0c => HandshakeType::ServerKeyExchange,
            0x0d => HandshakeType::CertificateRequest,
            0x0e => HandshakeType::ServerHelloDone,
            0x0f => HandshakeType::CertificateVerify,
            0x10 => HandshakeType::ClientKeyExchange,
            0x14 => HandshakeType::Finished,
            0x15 => HandshakeType::CertificateURL,
            0x16 => HandshakeType::CertificateStatus,
            0x18 => HandshakeType::KeyUpdate,
            0xfe => HandshakeType::MessageHash,
            _ => HandshakeType::Unknown(value),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, LoggableMetadata)]
pub enum AesSize {
    Aes128,
    Aes256,
}

impl From<AesSize> for usize {
    fn from(x: AesSize) -> Self {
        match x {
            AesSize::Aes256 => 32,
            AesSize::Aes128 => 16,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, LoggableMetadata)]
pub enum CBCMac {
    SHA256,
    SHA1,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, LoggableMetadata)]
pub enum AesMode {
    GCM,
    // GCM for TLS 1.3
    GCM13,
    CBC(CBCMac),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, LoggableMetadata)]
pub enum Cipher {
    Aes(AesSize, AesMode),
    ChaCha20Poly1305,
}

impl Cipher {
    pub fn explicit_nonce_size(&self) -> usize {
        match self {
            Cipher::Aes(_, AesMode::GCM) => 8,
            Cipher::Aes(_, AesMode::GCM13) => 0,
            Cipher::ChaCha20Poly1305 => 0,
            _ => unimplemented!(),
        }
    }

    pub fn auth_tag_size(&self) -> usize {
        match self {
            Cipher::Aes(_, AesMode::GCM) => 16,
            Cipher::Aes(_, AesMode::GCM13) => 16,
            Cipher::ChaCha20Poly1305 => 16,
            _ => unimplemented!(),
        }
    }
}

/// Attempt to convert our TLS AEAD `Cipher` type to the analogous `ring` AEAD `Algorithm` type.
/// This is used by TLS 1.3 key derivation.
impl TryFrom<Cipher> for &'static ring::aead::Algorithm {
    type Error = Cipher;

    fn try_from(value: Cipher) -> Result<Self, Self::Error> {
        match value {
            Cipher::ChaCha20Poly1305 => Ok(&ring::aead::CHACHA20_POLY1305),
            Cipher::Aes(AesSize::Aes128, AesMode::GCM13) => Ok(&ring::aead::AES_128_GCM),
            Cipher::Aes(AesSize::Aes128, AesMode::GCM) => Ok(&ring::aead::AES_128_GCM),
            Cipher::Aes(AesSize::Aes256, AesMode::GCM13) => Ok(&ring::aead::AES_256_GCM),
            Cipher::Aes(AesSize::Aes256, AesMode::GCM) => Ok(&ring::aead::AES_256_GCM),
            _ => Err(value),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, LoggableMetadata)]
pub enum Prf {
    SHA256,
    SHA384,
}

/// Convert our TLS `Prf` type to the analogous `ring` HKDF `Algorithm` type. This is used by TLS
/// 1.3 key derivation.
impl From<Prf> for ring::hkdf::Algorithm {
    fn from(x: Prf) -> Self {
        match x {
            Prf::SHA256 => ring::hkdf::HKDF_SHA256,
            Prf::SHA384 => ring::hkdf::HKDF_SHA384,
        }
    }
}

impl From<Prf> for ring::hmac::Algorithm {
    fn from(x: Prf) -> Self {
        ring::hkdf::Algorithm::from(x).hmac_algorithm()
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, LoggableMetadata)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, LoggableMetadata)]
pub struct CipherSuite {
    // We don't care about key exchange or signature algorithms.
    pub cipher: Cipher,
    pub prf_hash: Prf,
    pub version: TlsVersion,
    /// The original 16-bit TLS ciphersuite number
    pub raw: u16,
}

impl From<CipherSuite> for u16 {
    fn from(cs: CipherSuite) -> Self {
        cs.raw
    }
}

#[derive(Debug, Clone, Copy, LoggableMetadata)]
pub struct UnknownCipherSuite(pub u16);

impl std::fmt::Display for UnknownCipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Unknown cipher suite: {:X}", self.0)
    }
}

impl std::error::Error for UnknownCipherSuite {}

impl TryFrom<u16> for CipherSuite {
    type Error = UnknownCipherSuite;

    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        use AesMode::*;
        use AesSize::*;
        use Cipher::*;
        use Prf::*;
        use TlsVersion::*;

        const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
        const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
        const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003c;
        const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
        const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
        const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xc009;
        const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xc00a;
        const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
        const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;
        const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xc023;
        const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xc027;
        const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
        const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
        const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
        const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
        const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305: u16 = 0xcca8;
        const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305: u16 = 0xcca9;
        // 1.3 cipher suites
        const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
        const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
        const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
        match raw {
            TLS_AES_128_GCM_SHA256 => Ok(CipherSuite {
                cipher: Aes(Aes128, GCM13),
                prf_hash: SHA256,
                version: Tls13,
                raw,
            }),
            TLS_AES_256_GCM_SHA384 => Ok(CipherSuite {
                cipher: Aes(Aes256, GCM13),
                prf_hash: SHA384,
                version: Tls13,
                raw,
            }),
            TLS_CHACHA20_POLY1305_SHA256 => Ok(CipherSuite {
                cipher: ChaCha20Poly1305,
                prf_hash: SHA256,
                version: Tls13,
                raw,
            }),
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 => {
                Ok(CipherSuite {
                    cipher: ChaCha20Poly1305,
                    prf_hash: SHA256,
                    version: Tls12,
                    raw,
                })
            }
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | TLS_RSA_WITH_AES_128_GCM_SHA256 => Ok(CipherSuite {
                cipher: Aes(Aes128, GCM),
                prf_hash: SHA256,
                version: Tls12,
                raw,
            }),
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | TLS_RSA_WITH_AES_256_GCM_SHA384 => Ok(CipherSuite {
                cipher: Aes(Aes256, GCM),
                prf_hash: SHA384,
                version: Tls12,
                raw,
            }),
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
            | TLS_RSA_WITH_AES_128_CBC_SHA256 => Ok(CipherSuite {
                cipher: Aes(Aes128, CBC(CBCMac::SHA256)),
                prf_hash: SHA256,
                version: Tls12,
                raw,
            }),
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
            | TLS_RSA_WITH_AES_128_CBC_SHA => Ok(CipherSuite {
                cipher: Aes(Aes128, CBC(CBCMac::SHA1)),
                prf_hash: SHA256,
                version: Tls12,
                raw,
            }),
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
            | TLS_RSA_WITH_AES_256_CBC_SHA => Ok(CipherSuite {
                cipher: Aes(Aes256, CBC(CBCMac::SHA1)),
                prf_hash: SHA256,
                version: Tls12,
                raw,
            }),
            _ => Err(UnknownCipherSuite(raw)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, LoggableMetadata)]
pub struct SequenceNumber(pub u64);

impl SequenceNumber {
    pub fn increment(&mut self) {
        // Golang also panics here. It's probably safe for us to do so as well.
        self.0 = self.0.checked_add(1).expect("TLS sequence number overflow");
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, LoggableMetadata)]
pub struct ClientRandom(pub [u8; 32]);

#[derive(Debug, Copy, Clone, LoggableMetadata)]
pub struct ServerRandom(pub [u8; 32]);

#[derive(Copy, Clone, Debug, LoggableMetadata)]
pub struct MasterSecret12(pub [u8; 48]);

#[derive(Copy, Clone, Debug, LoggableMetadata)]
pub enum Tls13Secret {
    B32([u8; 32]),
    B48([u8; 48]),
    B64([u8; 64]),
}

impl Tls13Secret {
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Tls13Secret::B32(xs) => xs,
            Tls13Secret::B48(xs) => xs,
            Tls13Secret::B64(xs) => xs,
        }
    }
}

#[derive(Copy, Clone, Debug, LoggableMetadata)]
pub struct Tls13ClientHandshakeSecret(pub Tls13Secret);

#[derive(Copy, Clone, Debug, LoggableMetadata)]
pub struct Tls13ServerHandshakeSecret(pub Tls13Secret);

#[derive(Copy, Clone, Debug, LoggableMetadata)]
pub struct Tls13ClientTrafficSecret(pub Tls13Secret);

#[derive(Copy, Clone, Debug, LoggableMetadata)]
pub struct Tls13ServerTrafficSecret(pub Tls13Secret);

/// Wrapper type over TLS 1.3 Client Secrets, to provide a uniform interface for TLS 1.3 key
/// material derivation (handshake and traffic key derivation is identical).
pub enum Tls13ClientSecret<'a> {
    Handshake(&'a Tls13ClientHandshakeSecret),
    Traffic(&'a Tls13ClientTrafficSecret),
}

/// Wrapper type over TLS 1.3 Server Secrets, to provide a uniform interface for TLS 1.3 key
/// material derivation (handshake and traffic key derivation is identical).
pub enum Tls13ServerSecret<'a> {
    Handshake(&'a Tls13ServerHandshakeSecret),
    Traffic(&'a Tls13ServerTrafficSecret),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, LoggableMetadata)]
pub enum TlsSecretLabel {
    Tls12,
    Tls13ClientHandshake,
    Tls13ServerHandshake,
    Tls13ClientTraffic,
    Tls13ServerTraffic,
}

#[derive(Copy, Clone, Debug, LoggableMetadata)]
pub enum TlsSecret {
    Tls12(MasterSecret12),
    Tls13ClientHandshake(Tls13ClientHandshakeSecret),
    Tls13ServerHandshake(Tls13ServerHandshakeSecret),
    Tls13ClientTraffic(Tls13ClientTrafficSecret),
    Tls13ServerTraffic(Tls13ServerTrafficSecret),
}

impl ring::hkdf::KeyType for MasterSecret12 {
    fn len(&self) -> usize {
        48
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, LoggableMetadata)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, LoggableMetadata)]
pub enum AlertLevel {
    Warning,
    Fatal,
    Unsupported(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, LoggableMetadata)]
pub enum AlertDescription {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMAC,
    DecryptionFailedRESERVED,
    RecordOverflow,
    DecompressionFailure,
    HandshakeFailure,
    NoCertificateRESERVED,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCA,
    AccessDenied,
    DecodeError,
    DecryptError,
    ExportRestrictionRESERVED,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    UserCanceled,
    NoRenegotiation,
    UnsupportedExtension,
    Unsupported(u8),
}

impl From<AlertLevel> for u8 {
    fn from(level: AlertLevel) -> u8 {
        match level {
            AlertLevel::Warning => 1,
            AlertLevel::Fatal => 2,
            AlertLevel::Unsupported(x) => x,
        }
    }
}

impl From<AlertDescription> for u8 {
    fn from(desc: AlertDescription) -> u8 {
        match desc {
            AlertDescription::CloseNotify => 0,
            AlertDescription::UnexpectedMessage => 10,
            AlertDescription::BadRecordMAC => 20,
            AlertDescription::DecryptionFailedRESERVED => 21,
            AlertDescription::RecordOverflow => 22,
            AlertDescription::DecompressionFailure => 30,
            AlertDescription::HandshakeFailure => 40,
            AlertDescription::NoCertificateRESERVED => 41,
            AlertDescription::BadCertificate => 42,
            AlertDescription::UnsupportedCertificate => 43,
            AlertDescription::CertificateRevoked => 44,
            AlertDescription::CertificateExpired => 45,
            AlertDescription::CertificateUnknown => 46,
            AlertDescription::IllegalParameter => 47,
            AlertDescription::UnknownCA => 48,
            AlertDescription::AccessDenied => 49,
            AlertDescription::DecodeError => 50,
            AlertDescription::DecryptError => 51,
            AlertDescription::ExportRestrictionRESERVED => 60,
            AlertDescription::ProtocolVersion => 70,
            AlertDescription::InsufficientSecurity => 71,
            AlertDescription::InternalError => 80,
            AlertDescription::UserCanceled => 90,
            AlertDescription::NoRenegotiation => 100,
            AlertDescription::UnsupportedExtension => 110,
            AlertDescription::Unsupported(x) => x,
        }
    }
}

impl From<u16> for Alert {
    fn from(raw: u16) -> Self {
        let raw_level = (raw >> 8) as u8;
        let raw_desc = raw as u8;

        let level = match raw_level {
            1 => AlertLevel::Warning,
            2 => AlertLevel::Fatal,
            x => AlertLevel::Unsupported(x),
        };

        let description = match raw_desc {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMAC,
            21 => AlertDescription::DecryptionFailedRESERVED,
            22 => AlertDescription::RecordOverflow,
            30 => AlertDescription::DecompressionFailure,
            40 => AlertDescription::HandshakeFailure,
            41 => AlertDescription::NoCertificateRESERVED,
            42 => AlertDescription::BadCertificate,
            43 => AlertDescription::UnsupportedCertificate,
            44 => AlertDescription::CertificateRevoked,
            45 => AlertDescription::CertificateExpired,
            46 => AlertDescription::CertificateUnknown,
            47 => AlertDescription::IllegalParameter,
            48 => AlertDescription::UnknownCA,
            49 => AlertDescription::AccessDenied,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptError,
            60 => AlertDescription::ExportRestrictionRESERVED,
            70 => AlertDescription::ProtocolVersion,
            71 => AlertDescription::InsufficientSecurity,
            80 => AlertDescription::InternalError,
            90 => AlertDescription::UserCanceled,
            100 => AlertDescription::NoRenegotiation,
            110 => AlertDescription::UnsupportedExtension,
            x => AlertDescription::Unsupported(x),
        };

        Alert { level, description }
    }
}

impl From<Alert> for u16 {
    fn from(alert: Alert) -> Self {
        let level_byte = u8::from(alert.level);
        let desc_byte = u8::from(alert.description);
        ((level_byte as u16) << 8) | (desc_byte as u16)
    }
}

pub mod signature_scheme;
