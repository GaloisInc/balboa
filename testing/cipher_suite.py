import enum


class CipherSuite(enum.Enum):
    Aes128GCM = enum.auto()
    Aes256GCM = enum.auto()
    ChaCha20Poly1305 = enum.auto()
    # We rarely ever want to use this cipher. We just want to test one CBC cipher.
    Aes128CBC = enum.auto()

    @property
    def openssl_cipher_string(self) -> str:
        return _CIPHER_STRINGS_OPENSSL[self]

    @property
    def gnutls_cipher_string(self) -> str:
        """
        The returned cipher string is only valid for GnuTLS verions that support TLS 1.3.
        """
        return _CIPHER_STRINGS_GNUTLS[self]

    def is_tls13(self) -> bool:
        # TODO: Re-enable this logic once TLS 1.3 support is working
        return False

    def __str__(self) -> str:
        return self.name


_CIPHER_STRINGS_OPENSSL = {
    CipherSuite.Aes128GCM: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256",
    CipherSuite.Aes256GCM: "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
    CipherSuite.ChaCha20Poly1305: "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
    CipherSuite.Aes128CBC: "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA256",
}
_CIPHER_STRINGS_GNUTLS = {
    CipherSuite.Aes128GCM: "NONE:+VERS-TLS1.2:+MAC-ALL:+ECDHE-RSA:+ECDHE-ECDSA:+AES-128-GCM:+SIGN-ALL:+COMP-NULL:+GROUP-ALL",
    CipherSuite.Aes256GCM: "NONE:+VERS-TLS1.2:+MAC-ALL:+ECDHE-RSA:+ECDHE-ECDSA:+AES-256-GCM:+SIGN-ALL:+COMP-NULL:+GROUP-ALL",
    CipherSuite.ChaCha20Poly1305: "NONE:+VERS-TLS1.2:+MAC-ALL:+ECDHE-RSA:+ECDHE-ECDSA:+CHACHA20-POLY1305:+SIGN-ALL:+COMP-NULL:+GROUP-ALL",
    CipherSuite.Aes128CBC: "NONE:+VERS-TLS1.2:+MAC-ALL:+ECDHE-RSA:+ECDHE-ECDSA:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+GROUP-ALL",
}
