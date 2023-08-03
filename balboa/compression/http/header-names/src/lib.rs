// This is a separate crate to avoid re-running the PHF generation logic all the time.

use phf::phf_ordered_set;

static HEADER_NAMES: phf::OrderedSet<&'static [u8]> = phf_ordered_set! {
    b"A-IM",
    b"Accept",
    b"Accept-Charset",
    b"Accept-Datetime",
    b"Accept-Encoding",
    b"Accept-Language",
    b"Access-Control-Request-Method",
    b"Access-Control-Request-Headers",
    b"Authorization",
    b"Cache-Control",
    b"Connection",
    b"Content-Encoding",
    b"Content-Length",
    b"Content-MD5",
    b"Content-Type",
    b"Cookie",
    b"Date",
    b"Expect",
    b"Forwarded",
    b"From",
    b"Host",
    b"If-Match",
    b"If-Modified-Since",
    b"If-None-Match",
    b"If-Range",
    b"If-Unmodified-Since",
    b"Max-Forwards",
    b"Origin",
    b"Pragma",
    b"Prefer",
    b"Proxy-Authorization",
    b"Range",
    b"Referer", // [sic]
    b"TE",
    b"Trailer",
    b"Transfer-Encoding",
    b"User-Agent",
    b"Upgrade",
    b"Via",
    b"Warning",
};

pub fn length() -> usize {
    HEADER_NAMES.len()
}

pub fn by_index(index: usize) -> Option<&'static [u8]> {
    HEADER_NAMES.index(index).map(|x| *x)
}

pub fn to_index(name: &[u8]) -> Option<usize> {
    HEADER_NAMES.get_index(name)
}

pub fn iter() -> impl Iterator<Item = &'static [u8]> {
    HEADER_NAMES.iter().copied()
}
