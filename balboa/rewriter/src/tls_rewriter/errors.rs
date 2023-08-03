use crate::tls;
use snafu::Snafu;
use stallone::LoggableMetadata;

// WARNING: These errors should reflect issues with the stream. An issue which is a bug should cause
// a panic! These errors will cause us to go into an invalid state and stop manipulating traffic.
// If this happens only on one side, and the connection continues, then it's a problem. If a MITM
// triggers one of these errors on only one side, then it should result in the connection being
// closed. See below for examples
#[derive(Debug, Snafu, LoggableMetadata)]
#[snafu(visibility(pub(crate)))]
pub enum TLSRewriterError {
    // An assertion failed. We could crash, but we'll just keep running and hope for the best...
    #[snafu(display("Assertion failed: INTERNAL BALBOA ERROR"))]
    AssertionFailure,
    // We'll enter a transparent pass-thru. The other side isn't running Balboa.
    #[snafu(display("Failure to receive covert signal"))]
    FailedToCovertlySignal,
    // This error can occur for one of two reasons:
    //   (1) an outgoing packet has a bad TLS version. If this is for an outgoing packet, then
    //       this is (I think) due to either a bug in the TLS library, or some sort of downgrade
    //       attack
    //   (2) a MITM adversary has messed with the TLS version number. If this happens once we've
    //       entered the encrypted mode, then the MAC should catch the issue. Otherwise, it's part
    //       of a downgrade attack, and we don't handle other TLS versions, so we don't want to get
    //       involved.
    #[snafu(display("Mismatched TLS version. Expected {:X}. Got {:X}", expected, actual))]
    TLSVersionMismatch {
        expected: u16,
        actual: u16,
    },
    // Valid TLS implementations should trigger a fatal alert for this case. As a result, it is okay
    // for us to enter the invalid state here.
    #[snafu(display("The TLS record with size {} exceeded the valid maximum.", size))]
    RecordTooBig {
        size: usize,
    },
    // This error should only occur before we do any interception. As a result, at least one party
    // will go INVALID before it ever signals that either party should enter "ROCKY Mode."
    #[snafu(display("Expected handshake record type for client hello. Got {:?}", actual))]
    ExpectedHandshakeHeaderForClientHello {
        actual: tls::RecordHeader,
    },
    // Ditto.
    #[snafu(display("The first observed ApplicationRecord wasn't encrypted. {:?}", header))]
    ApplicationRecordWasntEncrypted {
        header: tls::RecordHeader,
    },
    // Ditto.
    #[snafu(display("TLS 1.3 is unsupported"))]
    TLS13IsUnsupported,
    // Ditto.
    #[snafu(display("CBC mode ciphers are unsupported"))]
    CbcModeCiphersAreUnsupported,
    // Ditto.
    #[snafu(display(
        "Expected ClientHello record to be at least {} bytes. Actually {} bytes.",
        expected,
        actual
    ))]
    ClientHelloTooShort {
        actual: usize,
        expected: usize,
    },
    // Ditto.
    #[snafu(display(
        "Expected the first handshake record to be of type ClientHello (0x01). Got {:?}",
        actual
    ))]
    FirstClientHandshakeRecordWasntClientHello {
        actual: tls::HandshakeType,
    },
    // Ditto.
    #[snafu(display("Expected TLS version 1.2. Got version {:X}", tls_version))]
    ClientHelloTLSVersionMismatch {
        tls_version: u16,
    },
    // Ditto.
    #[snafu(display("Client Hello message was never stored"))]
    NeverSawClientHello,
    // Ditto.
    #[snafu(display("{}", source))]
    UnknownCipherSuite {
        source: tls::UnknownCipherSuite,
    },
    // Ditto.
    #[snafu(display("SawServerDataBeforeClientHelloFinished"))]
    SawServerDataBeforeClientHelloFinished,
    // Ditto.
    #[snafu(display("SawClientDataInBetweenClientHelloAndServerHello"))]
    SawClientDataInBetweenClientHelloAndServerHello,
    // Ditto.
    #[snafu(display("Expected handshake record type for server hello. Got {:?}", actual))]
    ExpectedHandshakeHeaderForServerHello {
        actual: tls::RecordHeader,
    },
    // Ditto.
    #[snafu(display("The record we expected to be ServerHello was empty"))]
    ServerHelloEmptyHandshakeRecord,
    // Ditto.
    #[snafu(display(
    "Expected the first handshake record from the server to be of type ServerHello (0x02). Got {:?}",
    actual
    ))]
    FirstServerHandshakeRecordWasntServerHello {
        actual: tls::HandshakeType,
    },
    // Ditto.
    #[snafu(display(
        "Expected ServerHello record to be at least {} bytes. Actually {} bytes.",
        expected,
        actual
    ))]
    ServerHelloTooShort {
        actual: usize,
        expected: usize,
    },
    // Ditto.
    #[snafu(display("Expected encrypted handshake messages. Got {:?}", actual))]
    ExpectedEncryptedHandshakeMessages {
        actual: tls::RecordHeader,
    },
    // Ditto.
    #[snafu(display("Couldn't find a TLS 1.3 Record Type, record is all zeros"))]
    NoRecordType,
    // Ditto.
    #[snafu(display("Expected record type {:?}. Got {:?}", expected, actual))]
    UnexpectedRecordType {
        actual: tls::RecordType,
        expected: tls::RecordType,
    },
    // Ditto.
    #[snafu(display("Expected handshake type {:?}. Got {:?}", expected, actual))]
    UnexpectedHandshakeType {
        actual: tls::HandshakeType,
        expected: tls::HandshakeType,
    },
    // The TLS library shouldn't be able to decrypt this, and will send an alert.
    #[snafu(display(
    "Expected ApplicationRecord record to be at least {} bytes to have a nonce and mac. Actually {} bytes.",
    expected,
    actual
    ))]
    ApplicationRecordTooShortForNonceAndMAC {
        actual: usize,
        expected: usize,
    },
    // The TLS library will fail to decrypt this, and will send an alert
    #[snafu(display("Mismatched MAC. Correct {:?}. Observed {:?}", correct, observed))]
    MismatchedMAC {
        correct: tls::crypto::Tag,
        observed: tls::crypto::Tag,
    },
    // Ditto.
    #[snafu(display(
        "Mismatched MAC during covert signaling. Got {:?}. Expected {:?} or {:?}",
        actual,
        correct_expected,
        covert_expected,
    ))]
    MismatchedMACDuringCovertSignaling {
        actual: tls::crypto::Tag,
        correct_expected: tls::crypto::Tag,
        covert_expected: tls::crypto::Tag,
    },
    // Ditto.
    #[snafu(display(
        "Mismatched MAC during server incoming covert signaling. Got {:?}. Expected {:?}",
        actual,
        correct_expected,
    ))]
    MismatchedMACDuringServerIncomingCovertSignaling {
        actual: tls::crypto::Tag,
        correct_expected: tls::crypto::Tag,
    },
    #[snafu(display(
        "Mismatched MAC while waiting for ocvert server ack. Got {:?}. Expected {:?} or {:?}",
        actual,
        correct_expected,
        covert_expected
    ))]
    MismatchedMACWhileWaitingForCovertServerAck {
        actual: tls::crypto::Tag,
        correct_expected: tls::crypto::Tag,
        covert_expected: tls::crypto::Tag,
    },
    #[snafu(display("Failed to decrypt TLS Record"))]
    DecryptionError,
    // If there is no MITM, then both sides will equally encounter a non-handshake TLS record before
    // seeing a ServerKeyExchange record. If there is a MITM, then the signature on the
    // ServerKeyExchange record that does appear will be invalid.
    #[snafu(display("Saw non-handshake record {:?} before ServerKeyExchange", header))]
    SawNonHandshakeServerRecordBeforeKeyExchange {
        header: tls::RecordHeader,
    },
    // This is validated as part of the hash to confirm that the handshake wan't tampered with.
    #[snafu(display(
        "Balboa only support the key-exchange curve type 0x03 (named curve). Got {:x}",
        actual
    ))]
    UnsupportedKeyExchangeCurveType {
        actual: u8,
    },
    // Ditto.
    #[snafu(display("Unknown signature scheme {:?}", source))]
    UnknownSignatureScheme {
        source: tls::signature_scheme::UnknownSignatureScheme,
    },
    // If the signature verification fails, then we'll never send any covert signal, and the
    // connection should look just like a standard TLS connection.
    #[snafu(display(
        "TLS signature verification failed. Signature scheme {:?}",
        signature_scheme
    ))]
    ServerSignatureVerificationFailed {
        signature_scheme: tls::signature_scheme::SignatureScheme,
    },
    // The client will never covertly signal to the server if this occurs.
    #[snafu(display(
        "The first encrypted record the client saw wasn't a handshake record. Saw {:?}",
        header
    ))]
    FirstEncryptedRecordWasntHandshake {
        header: tls::RecordHeader,
    },
    // Ditto.
    #[snafu(display(
        "The first encrypted record the client saw was too short to have a MAC. Saw {:?}",
        header
    ))]
    FirstEncryptedRecordTooShortForMAC {
        header: tls::RecordHeader,
    },
    // BEGIN errors coming from the client checking the server's certificate (for covert signaling
    // purposes). If any of these errors occur, the client will enter the INVALID state, and won't
    // covertly signal the server.
    #[snafu(display(
        "A TLS handshake record {:?} was too short to have the handshake header.",
        header
    ))]
    RecordTooShortForHandshakeHeader {
        header: tls::RecordHeader,
    },
    #[snafu(display(
        "A ServerKeyExchange record {:?} was too short to have the curve type.",
        header
    ))]
    ServerKeyExchangeTooShortForCurveType {
        header: tls::RecordHeader,
    },
    #[snafu(display(
        "A ServerKeyExchange record {:?} was too short to have the length of the DH public key.",
        header
    ))]
    ServerKeyExchangeTooShortForDiffieHellmanPublicKeyLength {
        header: tls::RecordHeader,
    },
    #[snafu(display(
        "A ServerKeyExchange record {:?} was too short to have the body of the DH public key.",
        header
    ))]
    ServerKeyExchangeTooShortForDiffieHellmanPublicKeyBody {
        header: tls::RecordHeader,
    },
    #[snafu(display(
        "A ServerKeyExchange record {:?} was too short to have the signature type",
        header
    ))]
    ServerKeyExchangeTooShortForSignatureType {
        header: tls::RecordHeader,
    },
    #[snafu(display(
        "A ServerKeyExchange record {:?} was too short to have the signature length",
        header
    ))]
    ServerKeyExchangeTooShortForSignatureLength {
        header: tls::RecordHeader,
    },
    #[snafu(display(
        "A ServerKeyExchange record {:?} was too short to have the signature body",
        header
    ))]
    ServerKeyExchangeTooShortForSignatureBody {
        header: tls::RecordHeader,
    },
    #[snafu(display(
        "A ServerKeyExchangeRecord {:?} contained a signature larger than the size of the message {}",
        header,
        siglen
    ))]
    ServerKeyExchangeSignatureTooLong {
        header: tls::RecordHeader,
        siglen: usize,
    },
    #[snafu(display(
        "A CertificateVerify record {:?} was too short to have the signature type",
        header
    ))]
    CertificateVerifyTooShortForSignatureLength {
        header: tls::RecordHeader,
    },
    #[snafu(display(
        "Expected CertificateVerify signature to be {} bytes long. Got {}",
        expected,
        actual
    ))]
    CertificateVerifyWrongSignatureLength {
        actual: usize,
        expected: usize,
    },
    // END
    //
    // This will only happen if we see ApplicationData before the ChangeCipherSpec message.
    // As a result, we won't have passively mangled anything yet.
    #[snafu(display("Application record isn't encrypted {:?}", header))]
    ApplicationRecordIsntEncrypted {
        header: tls::RecordHeader,
    },
    // The TLS libraries should stop responding
    #[snafu(display(
        "Received invalid TLS alert message of length {:?} (expected 2)",
        length
    ))]
    SawInvalidLengthAlert {
        length: usize,
    },
    // The TLS libraries should stop responding
    #[snafu(display("Received TLS alert message {:?}", alert))]
    SawUnencryptedAlert {
        alert: tls::Alert,
    },
    #[snafu(display("Recieved encryped TLS alert message"))]
    SawEncryptedAlert,
    // If we enter an invalid state on outgoing rewrite, then the next yield on the incoming
    // rewrite will return this error.
    OtherSideEnteredInvalidState,
}

impl From<tls::signature_scheme::UnknownSignatureScheme> for TLSRewriterError {
    fn from(source: tls::signature_scheme::UnknownSignatureScheme) -> Self {
        TLSRewriterError::UnknownSignatureScheme { source }
    }
}

impl From<tls::UnknownCipherSuite> for TLSRewriterError {
    fn from(source: tls::UnknownCipherSuite) -> Self {
        TLSRewriterError::UnknownCipherSuite { source }
    }
}
