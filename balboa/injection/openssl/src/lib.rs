//! OpenSSL injection for SSLKEYLOGFILE handling.

#[doc(hidden)]
pub use balboa_injection;
use balboa_rewriter::sslkeylogfile::SSLKeyLogFile;
#[doc(hidden)]
pub use lazy_static::lazy_static;
#[doc(hidden)]
pub use libc;

pub trait KeyLogEntryConsumer: Default {
    fn consume_key_log_entry(&self, entry: &[u8]);
}
impl KeyLogEntryConsumer for SSLKeyLogFile {
    fn consume_key_log_entry(&self, entry: &[u8]) {
        self.add_entries(entry);
    }
}

#[doc(hidden)]
pub mod mini_openssl_binding {
    extern "C" {
        // Mini openssl binding :)
        pub fn SSL_new(ctx: *mut u8) -> *mut u8;
        pub fn SSL_CTX_set_keylog_callback(
            ctx: *mut u8,
            cb: Option<unsafe extern "C" fn(ssl: *const u8, line: *const libc::c_char)>,
        );
    }
}

/// Use dynamic library injection to extract `SSLKEYLOGFILE` entries from OpenSSL.
///
/// Since OpenSSL 1.1, OpenSSL has native support for `SSLKEYLOGFILE`-like functionality. The
/// function [`SSL_CTX_set_keylog_callback`](https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_keylog_callback.html)
/// can be used to specify a function which will be called with the contents of an `SSLKEYLOGFILE`
/// entry.
///
/// Suppporting the "normal" `SSLKEYLOGFILE` environment variable involves writing a callback such
/// which writes the line that it recieves as an argument to the path contained in the
/// `SSLKEYLOGFILE` environment variable.
///
/// Rather than implementing support for the `SSLKEYLOGFILE` environment variable with this
/// functionality, this macro takes two arguments: a name and a type. The type must implement the
/// [`KeyLogEntryConsumer`] trait. The macro defines a `lazy_static!` with the given name and type.
/// It will then populate this new global with SSLKEYLOGFILE entries.
#[macro_export]
macro_rules! balboa_inject_openssl_sslkeylogfile {
    // TODO: does this API suck?
    ($name:ident : $ty:ty) => {
        $crate::lazy_static! {
            static ref $name: $ty = <$ty as Default>::default();
        }
        #[cfg(not(test))]
        mod balboa_inject_openssl_sslkeylogfile_module {
            use super::*;
            use $crate::libc;
            use $crate::mini_openssl_binding;
            use std::ops::Deref;

            #[doc(hidden)]
            unsafe extern "C" fn openssl_keylog_callback(_ssl: *const u8, line: *const libc::c_char) {
                let entry = std::ffi::CStr::from_ptr(line);
                let entry = entry.to_bytes();
                <$ty as $crate::KeyLogEntryConsumer>::consume_key_log_entry($name.deref(), entry);
            }

            #[doc(hidden)]
            pub unsafe fn balboa_ssl_new(
                ssl_new: unsafe extern "C" fn(ctx: *mut u8) -> *mut u8,
                ctx: *mut u8,
            ) -> *mut u8 {
                mini_openssl_binding::SSL_CTX_set_keylog_callback(ctx, Some(openssl_keylog_callback));
                ssl_new(ctx)
            }
            $crate::balboa_injection::inject!(
                #[switch_stacks(false)]
                _BALBOA_SSL_NEW,
                balboa_ssl_new,
                fn mini_openssl_binding::SSL_new(ctx: *mut u8) -> *mut u8
            );
        }
    };
}
