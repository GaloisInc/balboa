use crate::{CompressContextWrapper, DecompressContextWrapper, HttpError};
use arrayvec::ArrayVec;
use balboa_compression::{CompressContext, DecompressContext};
use balboa_coroutine::{GenStateImmutable, NeedleNotFound};
use memchr::memchr;

/// Strip Optional WhiteSpace
///
/// See https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.3
fn strip_ows(mut input: &[u8]) -> &[u8] {
    while input.first() == Some(&b' ') || input.first() == Some(&b'\t') {
        input = &input[1..];
    }
    while input.last() == Some(&b' ') || input.last() == Some(&b'\t') {
        input = &input[0..input.len() - 1];
    }
    input
}

pub(crate) const HEADER_NAME_MAX_LENGTH: usize = 64;

pub(crate) type HeaderNameBuf = ArrayVec<u8, HEADER_NAME_MAX_LENGTH>;

/// Did the `HeaderNameCollector` see that the first character was a `\r` and abort? Or did it see
/// a header name, and then write it into the output buffer?
pub(crate) enum HeaderNameResult {
    WroteHeader,
    FoundCarriageReturn,
}

const HEADER_NAME_SENTINEL_MASK: u8 = 1 << 7;

#[test]
fn known_header_names_under_127() {
    assert!(balboa_http_header_names::length() <= 127);
}

#[test]
fn known_header_names_are_short() {
    for header in balboa_http_header_names::iter() {
        assert!(header.len() <= HEADER_NAME_MAX_LENGTH);
        assert!(!header.is_empty());
    }
}

/// A header name collector is responsible for reading the name of an HTTP header out of a stream.
/// It has the opportunity to rewrite the bytes of the header before they are written to the output
/// stream.
///
/// Unfortunately, due to `async` reasons, this needs to be an `enum` instead of a trait.
///
/// The `HeaderNameCollector` has two modes: `Standard`, which doesn't change header names at all,
/// and `ReplaceCovert` (both outgoing and incoming modes) which can transmit covert data in HTTP
/// requests.
///
/// # How `HeaderNameCollector` transmits covert data in HTTP requets
/// On the outgoing side, if the entirety of an HTTP header name is contained within a single chunk,
/// and that header name is in the list (see `header-names/src/lib.rs`), then we replace the first
/// byte of the header name with the index (as a `u8`) of the header name in the list. We also set
/// the most significant bit of the `u8` to denote that this is a compressed header. We're now free
/// to replace the remaining bytes of the header name with covert data.
///
/// Note that **no covert data will be sent** unless HTTP keep-alive is in used (not just enabled),
/// it must be actively in use.
#[derive(Default)]
pub(crate) enum HeaderNameCollector {
    #[default]
    Standard,
    ReplaceCovertOutgoing(CompressContextWrapper),
    ReplaceCovertIncoming(DecompressContextWrapper),
}

impl HeaderNameCollector {
    async fn standard_collect(
        gs: &mut GenStateImmutable,
        header_name: &mut HeaderNameBuf,
    ) -> Result<HeaderNameResult, HttpError> {
        let first_char: [u8; 1] = gs.read_exact_array().await;
        let first_char = first_char[0];
        if first_char == b'\r' {
            return Ok(HeaderNameResult::FoundCarriageReturn);
        }
        header_name.push(first_char);
        let remaining = htry!(
            gs.read_max_until_single_byte_needle::<{ HEADER_NAME_MAX_LENGTH - 1 }>(b':')
                .await,
            "header name": NeedleNotFound<{ HEADER_NAME_MAX_LENGTH - 1 }>
        );
        header_name
            .try_extend_from_slice(&remaining)
            .expect("the sizes should match!");
        Ok(HeaderNameResult::WroteHeader)
    }
    async fn replace_covert_outgoing(
        gs: &mut GenStateImmutable,
        header_name: &mut HeaderNameBuf,
        ctx: &mut CompressContextWrapper,
    ) -> Result<HeaderNameResult, HttpError> {
        let gs = if let Some(gs) = gs.as_mutable() {
            gs
        } else {
            return Self::standard_collect(gs, header_name).await;
        };
        let chunk = gs.current_chunk().await;
        hensure!(
            chunk[0] & HEADER_NAME_SENTINEL_MASK == 0,
            "ASSERTION: the sentinel mask shouldn't be pre-mutated set on header names"
        );
        if chunk[0] == b'\r' {
            return Self::standard_collect(gs, header_name).await;
        }
        let colon_idx = if let Some(colon_idx) =
            memchr(b':', chunk).filter(|colon_idx| *colon_idx <= HEADER_NAME_MAX_LENGTH)
        {
            colon_idx
        } else {
            return Self::standard_collect(gs, header_name).await;
        };
        header_name
            .try_extend_from_slice(&chunk[0..colon_idx])
            .expect("We made sure the length wasn't too big.");
        // If the header isn't found, no worries! We've already copied the header into header name.
        // So we don't need to do anything special.
        if let Some(idx) = balboa_http_header_names::to_index(&header_name) {
            let idx = u8::try_from(idx).expect("We test that there are <= 127 known headers");
            assert_eq!(idx & HEADER_NAME_SENTINEL_MASK, 0);
            chunk[0] = idx | HEADER_NAME_SENTINEL_MASK;
            ctx.recv_covert_bytes(&mut chunk[1..=colon_idx]);
        }
        // Add one for the colon
        gs.advance_without_modifying(header_name.len() + 1).await;
        Ok(HeaderNameResult::WroteHeader)
    }
    async fn replace_covert_incoming(
        gs: &mut GenStateImmutable,
        header_name: &mut HeaderNameBuf,
        ctx: &mut DecompressContextWrapper,
    ) -> Result<HeaderNameResult, HttpError> {
        let gs = if let Some(gs) = gs.as_mutable() {
            gs
        } else {
            return Self::standard_collect(gs, header_name).await;
        };
        let chunk = gs.current_chunk().await;
        if chunk[0] & HEADER_NAME_SENTINEL_MASK == 0 {
            return Self::standard_collect(gs, header_name).await;
        }
        let idx = usize::from(chunk[0] & (!HEADER_NAME_SENTINEL_MASK));
        let mut header = htry!(
            balboa_http_header_names::by_index(idx).ok_or(()),
            "ASSERTION FAILURE: unknown header name index": ()
        );
        header_name
            .try_extend_from_slice(header)
            .expect("We test that all header names are under the max size");
        // Replace the bytes, along with the colon, with the header bytes.
        gs.write_exact_ignoring_contents(&[header_name[0]]).await;
        header = &header[1..];
        gs.advance_exact_with_modification(header_name.len() - 1, |bytes| {
            ctx.send_covert_bytes(bytes);
            let (write_now, write_later) = header.split_at(bytes.len());
            bytes.copy_from_slice(write_now);
            header = write_later;
        })
        .await;
        gs.advance_exact_with_modification(1, |bytes| {
            if bytes.len() == 1 {
                ctx.send_covert_bytes(bytes);
                bytes[0] = b':';
            }
        })
        .await;
        Ok(HeaderNameResult::WroteHeader)
    }

    /// Read through the `:` of the header name, but not beyond, writing the header name into
    /// `header_name`.
    async fn collect(
        &mut self,
        gs: &mut GenStateImmutable,
        header_name: &mut HeaderNameBuf,
    ) -> Result<HeaderNameResult, HttpError> {
        match self {
            HeaderNameCollector::Standard => Self::standard_collect(gs, header_name).await,
            HeaderNameCollector::ReplaceCovertOutgoing(ctx) => {
                Self::replace_covert_outgoing(gs, header_name, ctx).await
            }
            HeaderNameCollector::ReplaceCovertIncoming(ctx) => {
                Self::replace_covert_incoming(gs, header_name, ctx).await
            }
        }
    }
}

/// Parse HTTP headers up to the final double CRLF. The visitor is called with lower-cased header
/// names, and (unmodified) header values.
///
/// The `header_name_collector` will be used to manipulate manipulate the keys of the HTTP headers.
pub(crate) async fn visit_http_headers<Visitor>(
    gs: &mut GenStateImmutable,
    header_name_collector: &mut HeaderNameCollector,
    mut visit: Visitor,
) -> Result<(), HttpError>
where
    for<'a> Visitor: FnMut(&'a [u8], &'a [u8]) -> Result<(), HttpError>,
{
    // See https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
    loop {
        let mut header_name: ArrayVec<u8, HEADER_NAME_MAX_LENGTH> = Default::default();
        if let HeaderNameResult::FoundCarriageReturn =
            header_name_collector.collect(gs, &mut header_name).await?
        {
            // We've hit the end of the request. The HTTP header name starts with a CR.
            let cr: [u8; 1] = gs.read_exact_array().await;
            hensure!(cr[0] == b'\n', "CR is followed by LF");
            return Ok(());
        }
        hensure!(
            header_name.first() != Some(&b' '),
            "The header name shouldn't start with a space"
        );
        header_name.make_ascii_lowercase();
        let raw_header_value: ArrayVec<u8, 1024> = htry!(
            gs.read_max_until_single_byte_needle(b'\r').await,
            "header value": NeedleNotFound<1024>,
        );
        let header_value = strip_ows(&raw_header_value);
        let lf: [u8; 1] = gs.read_exact_array().await;
        hensure!(lf[0] == b'\n', "header line doesn't end with CRLF");
        visit(&header_name, header_value)?;
    }
}

#[test]
fn test_strip_ows() {
    assert_eq!(strip_ows(b"abc"), b"abc");
    assert_eq!(strip_ows(b" abc"), b"abc");
    assert_eq!(strip_ows(b"\tabc"), b"abc");
    assert_eq!(strip_ows(b"  abc"), b"abc");
    assert_eq!(strip_ows(b" \t \tabc"), b"abc");
    assert_eq!(strip_ows(b"abc "), b"abc");
    assert_eq!(strip_ows(b"abc\t "), b"abc");
    assert_eq!(strip_ows(b"abc \t"), b"abc");
    assert_eq!(strip_ows(b" \t abc \t"), b"abc");
    assert_eq!(strip_ows(b" "), b"");
    assert_eq!(strip_ows(b"\t"), b"");
    assert_eq!(strip_ows(b" \t "), b"");
}
