#![deny(unused_must_use)]

//! This is the core balboa HTTP compression library. It's currently specifically written to support
//! static file downloading, but we plan to extend this code in the future.
//!
//! To use this crate, at present, invoke the [`new_server_rewriters`] function with a
//! [`PathResolver`] argument. The [`PathResolver`] says how to turn a path into an
//! [ReplacerFactory`], which will be used to compress and decompress the stream.

use arrayvec::ArrayVec;
use balboa_compression::{
    new_coroutine_compressor, new_coroutine_decompressor, CompressContext, Compressor,
    DecompressContext, Decompressor,
};
use balboa_coroutine::{
    GenState, GenStateImmutable, NeedleNotFound, SkipThroughNeedle, StreamCoroutineShouldNeverExit,
};
use parking_lot::Mutex;
use rewriter_adapter::CompressorOrDecompressor;
use std::{collections::VecDeque, num::ParseIntError, ops::DerefMut, str::Utf8Error, sync::Arc};

/// A [`Sync`] wrapper for a [`CompressContext`]
///
/// # Rationale
///
/// What we really want is for the step() function of a coroutine to look like:
/// ```ignore
///     fn step(&mut self, buf: &mut [u8], ctx: &mut CompressContext)
/// ```
/// Unfortunately, we don't have support for extra arguments like this to the coroutine. We could
/// add support for them. But that's a more complicated solution. We've been working around this
/// by having the coroutine own the Compression and Decompression contexts. When it comes to our
/// replacers, we can't pass ownership of the context to their Compressors and Decompressors, since
/// due to HTTP pipelining, we might need to take the context back when we move onto the next
/// request. To work around this, we'll wrap our `CompressContext` in an `Arc`/`Mutex` dance.
#[derive(Clone)]
pub struct CompressContextWrapper(Arc<Mutex<Box<dyn CompressContext + Send>>>);
impl CompressContext for CompressContextWrapper {
    fn recv_covert_bytes(&mut self, dst: &mut [u8]) {
        self.0.lock().recv_covert_bytes(dst);
    }
}

/// A [`Sync`] wrapper for a [`CompressContext`]
///
/// See [`CompressContextWrapper`] for the rationale
#[derive(Clone)]
pub struct DecompressContextWrapper(Arc<Mutex<Box<dyn DecompressContext + Send>>>);
impl DecompressContext for DecompressContextWrapper {
    fn send_covert_bytes(&mut self, src: &[u8]) {
        self.0.lock().send_covert_bytes(src)
    }
}

/// Resolve a path into a strategy to replace its contents.
pub trait PathResolver: Send + Sync {
    /// Resolve a path into a strategy to replace its contents.
    ///
    /// This resolver should operate identically on both the client and the server.
    ///
    /// # Security
    /// `path` is processed before it's been authenticated. As a result, implementers of this
    /// function should concern themselves with path traversal attacks (e.g. if `..` is in the path)
    fn resolve_uri(&self, path: &[u8]) -> Option<Arc<dyn ReplacerFactory + Send + Sync + 'static>>;
}

/// For a given path, construct a compressor or decompressor to operate on the contents of an HTTP
/// response.
pub trait ReplacerFactory: 'static + Send + Sync {
    fn known_size(&self) -> Option<usize> {
        None
    }
    fn new_compressor(
        &self,
        compress_context: CompressContextWrapper,
    ) -> Box<dyn Compressor + Send>;
    fn new_decompressor(
        &self,
        decompress_context: DecompressContextWrapper,
    ) -> Box<dyn Decompressor + Send>;
}

/// An error which might occur during HTTP processing. Rather than populating this type with error
/// information, we `stallone`-log the reason for the error when it occurs.
struct HttpError;

/// This is like the try! macro (the question mark operator), except that it produces a stallone
/// warning on error.
macro_rules! htry {
    ($result:expr, $msg:literal: $errty:ty $(, $k:ident : $t:ty = $v:expr)* $(,)?) => {{
        match $result {
            Ok(x) => x,
            Err(e) => {
                stallone::warn!(
                    concat!("HTTP Error: ", $msg),
                    error: $errty = e,
                    $($k : $t = $v),*
                );
                return Err(HttpError);
            }
        }
    }};
}

/// Return an error if `$flag` is false.
macro_rules! hensure {
    ($flag:expr, $msg:literal $(, $k:ident : $t:ty = $v:expr)* $(,)?) => {htry!(
        if $flag { Ok(()) } else { Err(()) },
        $msg: () $(, $k:$t=$v)*
    )};
}

enum RequestQueueEntry {
    Rewrite(Arc<dyn ReplacerFactory + Send + Sync + 'static>),
    SkipRequest,
}
type RequestQueue = Arc<Mutex<Option<VecDeque<RequestQueueEntry>>>>;

async fn handle_http_requests(
    gs: &mut GenStateImmutable,
    request_queue: RequestQueue,
    download_path_resolver: Arc<dyn PathResolver + Send + Sync + 'static>,
    upload_path_resolver: Arc<dyn PathResolver + Send + Sync + 'static>,
    mut header_name_collector: HeaderNameCollector,
    // Should have known_size.
    mut setup_rewrite: impl FnMut(Arc<dyn ReplacerFactory>) -> CompressorOrDecompressor,
) -> Result<StreamCoroutineShouldNeverExit, HttpError> {
    // It's important to bear in mind where coroutine flips happen in relation to the push to the
    // request_queue. An errant flip before writing to the request queue could cause the response
    // handler to try to pop an empty request queue.
    loop {
        // According to https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.1
        // request-line   = method SP request-target SP HTTP-version CRLF
        let mut method: ArrayVec<u8, 6> = htry!(
            gs.read_max_until_single_byte_needle(b' ').await,
            "method": NeedleNotFound<6>
        );
        method.make_ascii_lowercase();
        let target: ArrayVec<u8, 8192> = htry!(
            gs.read_max_until_single_byte_needle(b' ').await,
            "target": NeedleNotFound<8192>
        );
        let mut version: ArrayVec<u8, 10> = htry!(
            gs.read_max_until_single_byte_needle(b'\r').await,
            "version": NeedleNotFound<10>
        );
        version.make_ascii_lowercase();
        hensure!(
            version.as_slice() == b"http/1.1" || version.as_slice() == b"http/1.0",
            "invalid http version",
            version: &[u8] = version.as_slice(),
        );
        let cr: [u8; 1] = gs.read_exact_array().await;
        hensure!(cr[0] == b'\n', "request line doesn't end with CRLF");
        // TODO: support more HTTP methods (issue #129)
        let is_post = method.as_slice() == b"post";
        hensure!(
            method.as_slice() == b"get" || is_post,
            "unsupported http method",
            method: &[u8] = method.as_slice()
        );
        stallone::debug!("is_post", is_post: bool = is_post);
        let mut content_length: Option<u64> = None;
        let mut multipart_boundary: Option<Vec<u8>> = None;
        visit_http_headers(gs, &mut header_name_collector, |k, v| {
            if k == b"content-length" {
                content_length = Some(htry!(
                    u64::from_str_radix(
                        htry!(std::str::from_utf8(v), "content-length is utf-8": Utf8Error),
                        10
                    ),
                    "content-length int parsing": ParseIntError
                ));
            } else if k == b"content-type" {
                // TODO: the space after the semicolon is probably not mandatory.
                const PREFIX: &'static [u8] = b"multipart/form-data; boundary=";
                if v.starts_with(PREFIX) {
                    multipart_boundary = Some(v[PREFIX.len()..].to_vec());
                } else {
                    stallone::debug!("post content-type wasn't multipart form data", v: &[u8] = v);
                }
            }
            // TODO: support expect and transfer-encoding (issue 126)
            hensure!(k != b"expect", "we don't support Expect, yet");
            hensure!(
                !(k == b"transfer-encoding" && v != b"identity"),
                "we don't support transfer-encoding",
                v: &[u8] = v,
            );
            Ok(())
        })
        .await?;
        if !is_post {
            hensure!(
                content_length.is_none(),
                "non-post shouldn't have content-length",
                content_length: Option<u64> = content_length
            );
        }
        let entry = if let Some(resolved) = download_path_resolver.resolve_uri(target.as_slice()) {
            stallone::debug!("Resolved url", target_url: &[u8] = target.as_slice());
            RequestQueueEntry::Rewrite(resolved)
        } else {
            stallone::warn!(
                "Failed to resolve url",
                target_url: &[u8] = target.as_slice()
            );
            RequestQueueEntry::SkipRequest
        };
        if let Some(queue) = request_queue.lock().as_mut() {
            queue.push_back(entry);
        }
        // Deal with the request body _after_ seeing the headers, but before we start parsing the
        // body.
        if is_post {
            if let Some(mut multipart_boundary_bytes) = multipart_boundary {
                let body_start = gs.bytes_consumed();
                hensure!(
                    !multipart_boundary_bytes.is_empty(),
                    "multipart boundary can't be empty"
                );
                // See https://datatracker.ietf.org/doc/html/rfc7578
                // We need to respect the Content-Length on the request if it's been set. Ideally we'd
                // check how many bytes we have left in Content-Length before consuming bytes. It
                // appears that any non-malformed multipart/form-data body ought to end with the
                // multipart-boundary. As a result, assuming that the client isn't generating malformed
                // POST requests, then we should be fine to check the content-length only at the
                // multipart boundaries.
                multipart_boundary_bytes.insert(0, b'-');
                multipart_boundary_bytes.insert(0, b'-');
                multipart_boundary_bytes.insert(0, b'\n');
                multipart_boundary_bytes.insert(0, b'\r');
                let mut multipart_boundary =
                    SkipThroughNeedle::new(multipart_boundary_bytes.as_slice());
                let needle_without_leading_crlf = &multipart_boundary.needle()[2..];
                let mut buffer = vec![0; needle_without_leading_crlf.len()];
                gs.read_exact(&mut buffer).await;
                hensure!(
                    buffer.as_slice() == needle_without_leading_crlf,
                    "POST request body should've started with boundary."
                );
                loop {
                    if let Some(content_length) = content_length {
                        let body_len = gs.bytes_consumed() - body_start;
                        hensure!(body_len < content_length, "body_len >= content_length");
                    }
                    // To denote the last multipart chunk, the HTTP request contains a final --, then a
                    // CRLF, instead of just a CRLF.
                    let next_2_bytes: [u8; 2] = gs.read_exact_array().await;
                    if next_2_bytes == *b"--" {
                        let crlf: [u8; 2] = gs.read_exact_array().await;
                        hensure!(crlf == *b"\r\n", "CRLF check");
                        if let Some(content_length) = content_length {
                            let body_len = gs.bytes_consumed() - body_start;
                            hensure!(body_len == content_length, "body_len != content_length");
                        }
                        break;
                    } else {
                        hensure!(next_2_bytes == *b"\r\n", "CRLF check");
                    }
                    let mut upload_factory: Option<(
                        Arc<dyn ReplacerFactory + Send + Sync + 'static>,
                        usize,
                    )> = None;
                    let mut saw_viable_filenames: bool = false;
                    visit_http_headers(gs, &mut HeaderNameCollector::default(), |k, v| {
                        if k == b"content-disposition" {
                            // TODO: improve the content-disposition parsing.
                            // Curl appears to use a backslash to escape quotes in a filename. I haven't
                            // been able to find an RFC which says that that should happen though.
                            // We'll be overly conservative for the filename parsing (see the TODO
                            // above), and abort if we see a backslash.
                            hensure!(memchr::memchr(b'\\', v).is_none(), "No backslashes");
                            const PREFIX: &'static [u8] = b"filename=\"";
                            if let Some(start_of_name) = memchr::memmem::find(v, PREFIX) {
                                let prefix_trimmed = &v[start_of_name + PREFIX.len()..];
                                if let Some(end_of_name) = memchr::memchr(b'"', prefix_trimmed) {
                                    let upload_name = &prefix_trimmed[0..end_of_name];
                                    saw_viable_filenames = true;
                                    let uf = upload_path_resolver.resolve_uri(upload_name);
                                    if let Some(uf) = uf {
                                        if let Some(len) = uf.known_size() {
                                            upload_factory = Some((uf, len));
                                        } else {
                                            stallone::warn!(
                                                "Upload factory didn't supply known size"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        hensure!(
                            k == b"content-disposition" || k == b"content-type",
                            "unknown upload header",
                            k: &[u8] = k
                        );
                        Ok(())
                    })
                    .await?;
                    if let Some((upload_factory, mut size)) = upload_factory {
                        stallone::debug!("Replacing POST-ed upload");
                        if let Some(content_length) = content_length {
                            let body_len = gs.bytes_consumed() - body_start;
                            hensure!(
                                body_len + (size as u64) < content_length,
                                "body_len + size >= content_length"
                            );
                        }
                        let mut rewriter = setup_rewrite(upload_factory);
                        while size > 0 {
                            gs.flip_while_empty().await;
                            if let Some(gs) = gs.as_mutable() {
                                let current_chunk = gs.current_chunk().await;
                                let to_take = size.min(current_chunk.len());
                                stallone::debug!(
                                    "Mutating bytes of file upload",
                                    to_take: usize = to_take
                                );
                                rewriter.mutate(&mut current_chunk[0..to_take]);
                                gs.advance_without_modifying(to_take).await;
                                size -= to_take;
                            } else {
                                let current_chunk = gs.current_buffer().await;
                                let to_take = size.min(current_chunk.len());
                                stallone::debug!(
                                    "Previewing file upload bytes which aren't mutable",
                                    to_take: usize = to_take
                                );
                                // to_take should never be zero. flip_while_empty ensures that the
                                // current chunk is non-empty. The call to current_chunk will
                                // ensure the same thing. The loop condition ensures that size != 0
                                // Thus, to_take = min(something over zero, something over zero) is
                                // over zero.
                                assert_ne!(to_take, 0);
                                rewriter.preview(&current_chunk[0..to_take]);
                                gs.advance_without_modifying(to_take).await;
                            }
                        }
                        buffer.resize(multipart_boundary_bytes.len(), 0);
                        gs.read_exact(&mut buffer).await;
                        hensure!(
                            buffer.as_slice() == multipart_boundary_bytes.as_slice(),
                            "the post request should conclude with the multipart boundary bytes",
                            expected: &[u8] = buffer.as_slice(),
                            actual: &[u8] = multipart_boundary_bytes.as_slice(),
                        );
                    } else {
                        if saw_viable_filenames {
                            stallone::warn!("Unable to replace contents of uploaded file.");
                        }
                        multipart_boundary.skip_through_needle(gs).await;
                    }
                }
            } else {
                let content_length = htry!(
                    content_length.ok_or(()),
                    "content-length isn't set for non-multipart post": ()
                );
                // TODO: this can panic on a 32-bit machine. On the one hand, there's no inherent
                // reason why a POST request can't have a more than 4GB body. However, it
                // violates the spec. IDK what happens in practice. It won't matter for a 64-bit
                // machine, tho.
                let content_length = usize::try_from(content_length).expect("64-bit machine");
                gs.advance_without_modifying(content_length).await;
                // TODO: when using POST with a persistent connection, does a CRLF follow the POST
                // body? (See issues #126, #129 and test_connection_reuse_upload)
            }
        }
    }
}

/// Mangle http responses. `setup_rewrite` is used to turn a `ReplacerFactory` into a
/// `CompressorOrDecompressor`, depending on whether we're preocessing incoming or outgoing data.
async fn handle_http_responses(
    gs: &mut GenState,
    request_queue: RequestQueue,
    mut setup_rewrite: impl FnMut(Arc<dyn ReplacerFactory>) -> CompressorOrDecompressor,
) -> Result<StreamCoroutineShouldNeverExit, HttpError> {
    loop {
        // Wait for us to have data before we interrogate the request queue.
        gs.current_chunk().await;
        let mut request_entry = htry!(
            request_queue
                .lock()
                .as_mut()
                .and_then(VecDeque::pop_front)
                .ok_or(()),
            "request queue is empty": (),
        );
        let mut version: ArrayVec<u8, 10> = htry!(
            gs.read_max_until_single_byte_needle(b' ').await,
            "version": NeedleNotFound<10>
        );
        version.make_ascii_lowercase();
        hensure!(
            version.as_slice() == b"http/1.1" || version.as_slice() == b"http/1.0",
            "invalid http version",
            version: &[u8] = version.as_slice(),
        );
        let status_code: ArrayVec<u8, 4> = htry!(
            gs.read_max_until_single_byte_needle(b' ').await,
            "status code": NeedleNotFound<4>,
        );
        let status_code = htry!(
            std::str::from_utf8(status_code.as_slice()),
            "status code utf-8": Utf8Error
        );
        let status_code = htry!(
            u32::from_str_radix(status_code, 10),
            "status code int parse": ParseIntError
        );
        // TODO: this is overly restrictive. But it's fine for now. (Issue #130)
        let status_ok = status_code == 200;
        hensure!(
            status_ok || status_code == 404,
            "status code is unexpected",
            status_code: u32 = status_code,
        );
        if status_code == 404 {
            stallone::debug!("Skipping response due to status code 404");
            request_entry = RequestQueueEntry::SkipRequest;
        }
        gs.skip_until_single_byte_needle(b'\r').await;
        // Finish reading status text
        let cr: [u8; 1] = gs.read_exact_array().await;
        hensure!(cr[0] == b'\n', "request line doesn't end with CRLF");
        let mut content_length: Option<u64> = None;
        visit_http_headers(
            gs.deref_mut(),
            &mut HeaderNameCollector::default(),
            |k, v| {
                if k == b"content-length" {
                    content_length = Some(htry!(
                        u64::from_str_radix(
                            htry!(
                                std::str::from_utf8(v),
                                "content-length isn't utf-8": Utf8Error
                            ),
                            10
                        ),
                        "content-length int parsing": ParseIntError
                    ));
                } else if k == b"content-type" {
                    hensure!(
                        !v.starts_with(b"multipart"),
                        "we don't support multipart encoding"
                    );
                }
                // TODO: support content-encoding (issue #131)
                hensure!(
                    k != b"content-encoding",
                    "we don't support content-encoding"
                );
                // TODO: support content-range (issue #132)
                hensure!(k != b"content-range", "we don't support content-range");
                Ok(())
            },
        )
        .await?;
        stallone::debug!(
            "content-length",
            content_length: Option<u64> = content_length
        );
        let mut rewriter = match request_entry {
            RequestQueueEntry::Rewrite(factory) => Some(setup_rewrite(factory)),
            RequestQueueEntry::SkipRequest => None,
        };
        while content_length != Some(0) {
            let chunk = gs.current_chunk().await;
            let to_take = usize::try_from(
                u64::try_from(chunk.len())
                    .expect("sizeof(usize) <= sizeof(u64)")
                    .min(content_length.unwrap_or(u64::MAX)),
            )
            .expect("This value is upper-bounded by chunk.len()");
            if let Some(ref mut rewriter) = rewriter {
                rewriter.mutate(&mut chunk[0..to_take]);
            }
            gs.advance_without_modifying(to_take).await;
            if let Some(content_length) = content_length.as_mut() {
                *content_length -= u64::try_from(to_take).expect("sizeof(usize) <= sizeof(u64)");
            }
        }
    }
}

pub fn new_server_rewriters(
    download_resolver: Arc<dyn PathResolver + Send + Sync + 'static>,
    upload_resolver: Arc<dyn PathResolver + Send + Sync + 'static>,
) -> (
    impl FnOnce(Box<dyn CompressContext + Send + 'static>) -> Box<dyn Compressor + Send + 'static>,
    impl FnOnce(Box<dyn DecompressContext + Send + 'static>) -> Box<dyn Decompressor + Send + 'static>,
) {
    let request_queue: RequestQueue = Arc::new(Mutex::new(Some(VecDeque::new())));
    (
        {
            let request_queue = request_queue.clone();
            move |ctx| {
                new_coroutine_compressor(|gs| async move {
                    let mut gs = if let Ok(gs) = gs.into_mutable() {
                        gs
                    } else {
                        panic!(concat!(
                            "Outgoing responses can be immediately mutable since the first ",
                            "client-sent message preceeds the first server-sent message."
                        ))
                    };
                    let ctx = CompressContextWrapper(Arc::new(Mutex::new(ctx)));
                    let rq = request_queue.clone();
                    let _ = handle_http_responses(&mut gs, request_queue, |factory| {
                        factory.new_compressor(ctx.clone()).into()
                    })
                    .await;
                    stallone::warn!("Ignoring further outgoing HTTP data");
                    *rq.lock() = None; // Don't waste memory queueing forever.
                    loop {
                        gs.advance_without_modifying(1024).await;
                    }
                })
            }
        },
        {
            let request_queue = request_queue.clone();
            move |ctx| {
                let ctx = DecompressContextWrapper(Arc::new(Mutex::new(ctx)));
                new_coroutine_decompressor(|mut gs| async move {
                    let _ = handle_http_requests(
                        &mut gs,
                        request_queue,
                        download_resolver,
                        upload_resolver,
                        HeaderNameCollector::ReplaceCovertIncoming(ctx.clone()),
                        |factory| factory.new_decompressor(ctx.clone()).into(),
                    )
                    .await;
                    stallone::warn!("Ignoring further incoming HTTP data");
                    loop {
                        gs.advance_without_modifying(1024).await;
                    }
                })
            }
        },
    )
}

pub fn new_client_rewriters(
    download_resolver: Arc<dyn PathResolver + Send + Sync + 'static>,
    upload_resolver: Arc<dyn PathResolver + Send + Sync + 'static>,
) -> (
    impl FnOnce(Box<dyn CompressContext + Send + 'static>) -> Box<dyn Compressor + Send + 'static>,
    impl FnOnce(Box<dyn DecompressContext + Send + 'static>) -> Box<dyn Decompressor + Send + 'static>,
) {
    let request_queue: RequestQueue = Arc::new(Mutex::new(Some(VecDeque::new())));
    (
        {
            let request_queue = request_queue.clone();
            move |ctx| {
                let ctx = CompressContextWrapper(Arc::new(Mutex::new(ctx)));
                new_coroutine_compressor(|mut gs| async move {
                    let _ = handle_http_requests(
                        &mut gs,
                        request_queue,
                        download_resolver,
                        upload_resolver,
                        HeaderNameCollector::ReplaceCovertOutgoing(ctx.clone()),
                        |factory| factory.new_compressor(ctx.clone()).into(),
                    )
                    .await;
                    stallone::warn!("Ignoring further outgoing HTTP data");
                    loop {
                        gs.advance_without_modifying(1024).await;
                    }
                })
            }
        },
        {
            let request_queue = request_queue.clone();
            move |ctx| {
                new_coroutine_decompressor(|gs| async move {
                    let mut gs = if let Ok(gs) = gs.into_mutable() {
                        gs
                    } else {
                        panic!(concat!(
                            "Incoming responses can be immediately mutable since the first ",
                            "client-sent message preceeds the first server-sent message."
                        ))
                    };
                    let ctx = DecompressContextWrapper(Arc::new(Mutex::new(ctx)));
                    let rq = request_queue.clone();
                    let _ = handle_http_responses(&mut gs, request_queue, |factory| {
                        factory.new_decompressor(ctx.clone()).into()
                    })
                    .await;
                    stallone::warn!("Ignoring further incoming HTTP data");
                    *rq.lock() = None; // Don't waste memory queueing forever.
                    loop {
                        gs.advance_without_modifying(1024).await;
                    }
                })
            }
        },
    )
}

mod static_files;
use crate::http_headers::{visit_http_headers, HeaderNameCollector};
pub use static_files::StaticFileDirectory;

mod http_headers;
mod rewriter_adapter;
