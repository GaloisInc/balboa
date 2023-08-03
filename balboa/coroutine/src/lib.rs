//! We need to write a lot of code which looks like:
//!
//! ```
//! struct MyState { /* fields */ }
//! impl MyState {
//!     pub fn rewrite_buffer(&mut self, buf: &mut [u8]) {
//!         // Rewrite the buffer.
//!     }
//! }
//! ```
//!
//! For this example, let's say that we want to, in a loop, read a little-endian 32-bit integer containing a
//! count of bytes: `n`. We then want to replace the next `n` bytes with `b'x'`'s. Because we are
//! exposing a stateful buffer interface, it's possible that the 4 bytes of `n` might not
//! necessarily all be contained in the same buffer. Similarly, the `n` bytes might be split
//! across multiple buffers. Or maybe we see `n` bytes, and then the first 2 bytes of the `n` for
//! the next iteration. All of these possibilities means that we need to track the current parse
//! state/position in our struct.
//!
//! But actually keeping track of state and where we are in the rewriting process is tedious and
//! error-prone. Instead, we take advantage of Rust's async/await support to writing code like:
//!
//! ```
//! use balboa_coroutine::CoroutineBasedStreamRewriter;
//!
//! pub fn rewriter() -> CoroutineBasedStreamRewriter {
//!     CoroutineBasedStreamRewriter::new(|mut gs| async move {
//!         loop {
//!             let mut size = [0; 4];
//!             gs.read_exact(&mut size).await;
//!             let size = u32::from_le_bytes(size);
//!             for _ in 0..size {
//!                 gs.write_exact_ignoring_contents(b"x").await;
//!             }
//!         }
//!     })
//! }
//!
//! pub fn use_rewriter(rewriter: &mut CoroutineBasedStreamRewriter, buf: &mut [u8]) {
//!     rewriter.rewrite(buf);
//! }
//! ```
//!
//! That is, we write code where we can directly say what rewriting operations we want to perform
//! on the buffers. The Rust compiler will then (through our use of the async/await syntax)
//! generate the `MyState` struct for us, which keeps track of where we currently are in the
//! rewrite step, so that subsequent invocations of the `.rewrite()` function resume where they left
//! off.
//!
//! With the coroutine-based API, the function `read_exact`, for example, will read 4 bytes even if
//! those bytes are split across multiple buffers/calls to `.rewrite()`.

#![deny(unused_must_use)]

// Internally, we say that our buffers are "flipped" when control yields back to the caller. This
// is an analogy to https://en.wikipedia.org/wiki/Multiple_buffering, stemming from the fact that
// the original implementation of this library did use multiple buffers.

// TODO: we have some use-cases now where buffer flips are important. We should explicitly document
// which coroutine functions do and don't flip buffers.

use arrayvec::ArrayVec;
use genawaiter::{
    sync::{Co, GenBoxed},
    GeneratorState,
};
use stallone::LoggableMetadata;
use std::{
    future::Future,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use unsafe_slice_holder::UnsafeSliceHolder;

mod unsafe_slice_holder {
    use super::*;

    /// An `UnsafeSliceHolder` is the same as `&[u8]` or `&mut [u8]`, except that the lifetime of
    /// the reference is not checked by the Rust compiler.
    pub(super) struct UnsafeSliceHolder(UnsafeSliceHolderInternal);

    enum UnsafeSliceHolderInternal {
        Immutable(*const [u8]),
        Mutable(*mut [u8]),
    }
    impl UnsafeSliceHolder {
        /// # Safety
        /// The resulting `PhantomData` _must_ be dropped after the `UnsafeSliceHolder` result.
        #[inline]
        pub(super) unsafe fn new_mutable<'a>(ptr: &'a mut [u8]) -> (Self, PhantomData<&'a mut ()>) {
            (
                UnsafeSliceHolder(UnsafeSliceHolderInternal::Mutable(ptr)),
                PhantomData,
            )
        }
        /// # Safety
        /// The resulting `PhantomData` _must_ be dropped after the `UnsafeSliceHolder` result.
        #[inline]
        pub(super) unsafe fn new_immutable<'a>(ptr: &'a [u8]) -> (Self, PhantomData<&'a mut ()>) {
            (
                UnsafeSliceHolder(UnsafeSliceHolderInternal::Immutable(ptr)),
                PhantomData,
            )
        }

        #[inline]
        pub(super) fn is_mutable(&self) -> bool {
            match &self.0 {
                UnsafeSliceHolderInternal::Immutable(_) => false,
                UnsafeSliceHolderInternal::Mutable(_) => true,
            }
        }

        #[inline]
        pub(super) fn mut_ref(&mut self) -> Option<&mut [u8]> {
            match &self.0 {
                UnsafeSliceHolderInternal::Immutable(_) => None,
                UnsafeSliceHolderInternal::Mutable(ptr) => {
                    let ptr = *ptr;
                    Some(unsafe { &mut *ptr })
                }
            }
        }
    }
    /// # Safety
    /// This is `Send` for the same reason that `&'a mut [u8]` is `Send`.
    unsafe impl Send for UnsafeSliceHolder {}
    impl AsRef<[u8]> for UnsafeSliceHolder {
        fn as_ref(&self) -> &[u8] {
            let ptr: *const [u8] = match self.0 {
                UnsafeSliceHolderInternal::Immutable(ptr) => ptr,
                UnsafeSliceHolderInternal::Mutable(ptr) => ptr,
            };
            unsafe { &*ptr }
        }
    }
}

/// A handle to preview and view bytes from a [`PreviewingCoroutineBasedStreamRewriter`].
///
/// The coroutine can yield an `R` value, along with its changes to the bytes, every time it
/// yields control back to the caller.
pub struct GenStateImmutable<R: Default = ()> {
    co: Co<(Option<UnsafeSliceHolder>, R), Option<UnsafeSliceHolder>>,
    whole_buffer: Option<UnsafeSliceHolder>,
    value_to_yield: R,
    position: usize,
    // This is a u64 so, even on a 32-bit platform, there's no issue with processing more than
    // 4GB of data.
    previous_chunks_consumed: u64,
}

/// Should the current iteration continue, or keep running?
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[must_use]
pub enum ShouldContinueIteration {
    KeepRunning,
    StopIteration,
}

/// A unit type denoting that the current iteration has stopped.
#[derive(Debug, Clone, Copy)]
pub struct IterationStopped;

/// The `needle` byte could not be found after looking in `MAX` bytes
#[derive(Debug, Clone, LoggableMetadata)]
pub struct NeedleNotFound<const MAX: usize> {
    /// The needle that was being searched for.
    pub needle: u8,
    // If the needle hasn't been found, it must be because we've observed MAX characters without
    // seeing the needle. So, we could technically use [u8; MAX], instead.
    /// The bytes that were read while looking for the needle.
    pub seen: ArrayVec<u8, MAX>,
}
impl<const MAX: usize> std::fmt::Display for NeedleNotFound<MAX> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The needle {:02X} could not be found in {} bytes. Saw {:?}",
            self.needle,
            MAX,
            self.seen.as_slice()
        )
    }
}
impl<const MAX: usize> std::error::Error for NeedleNotFound<MAX> {}

impl<R: Default> GenStateImmutable<R> {
    /// Overwrite the `R` value to be yielded back to the caller when the buffer gets flipped.
    ///
    /// After the buffer gets flipped, the value yielded on the next flip (unless this function
    /// gets called again), will be `R::default()`.
    pub fn yield_value(&mut self, r: R) {
        self.value_to_yield = r;
    }

    fn whole_immutable_buffer(&self) -> &[u8] {
        // TODO: if this unwrap influences performance, we can maybe use unsafe to remove them.
        self.whole_buffer.as_ref().unwrap().as_ref()
    }

    fn is_mutable(&self) -> bool {
        self.whole_buffer
            .as_ref()
            .map(|ush| ush.is_mutable())
            .unwrap_or(false)
    }

    async fn raw_flip_buffer(&mut self) {
        let was_mutable = self.is_mutable();
        self.whole_buffer = self
            .co
            .yield_((
                self.whole_buffer.take(),
                std::mem::take(&mut self.value_to_yield),
            ))
            .await;
        if was_mutable {
            assert!(self.is_mutable());
        }
    }

    async fn flip_buffer(&mut self) {
        debug_assert_eq!(self.position, self.whole_immutable_buffer().len());
        self.previous_chunks_consumed +=
            u64::try_from(self.position).expect("sizeof(u64) >= sizeof(usize)");
        self.position = 0;
        stallone::debug!(
            "Coroutine about to flip buffer",
            size: usize = self.whole_immutable_buffer().len(),
        );
        self.raw_flip_buffer().await;
        stallone::debug!(
            "Coroutine got new buffer of size flip buffer",
            size: usize = self.whole_immutable_buffer().len(),
        );
    }

    /// How many bytes has this coroutine consumed in total?
    pub fn bytes_consumed(&self) -> u64 {
        self.previous_chunks_consumed
            + u64::try_from(self.position).expect("sizeof(u64) >= sizeof(usize)")
    }

    /// How many bytes can we advance before we need to switch to the next buffer?
    pub fn buffer_size_remaining(&self) -> usize {
        self.whole_immutable_buffer().len() - self.position
    }

    /// Flip buffers until the current chunk is non-empty
    pub async fn flip_while_empty(&mut self) {
        while self.buffer_size_remaining() == 0 {
            self.flip_buffer().await;
        }
    }

    /// Return an immutable reference to the current buffer. The buffer WILL NOT be empty.
    pub async fn current_buffer(&mut self) -> &[u8] {
        loop {
            let n = self.buffer_size_remaining();
            if n == 0 {
                self.flip_buffer().await;
                continue;
            }
            let pos = self.position;
            break &self.whole_immutable_buffer()[pos..pos + n];
        }
    }

    /// Read `n` bytes exactly, calling `thunk` with the bytes.
    ///
    /// `thunk` might get called more than once. If `n` is 0, `thunk` might never get called. It's
    /// possible for `thunk` to get called with an empty buffer.
    ///
    /// The sum of the lengths of buffers that `thunk` gets called with will sum to `n`.
    pub async fn read_exact_chunked<F>(&mut self, mut n: usize, mut thunk: F)
    where
        for<'a> F: FnMut(&'a [u8]),
    {
        if n == 0 {
            return;
        }
        loop {
            let amount_to_take = self.buffer_size_remaining().min(n);
            thunk(&self.whole_immutable_buffer()[self.position..self.position + amount_to_take]);
            self.position += amount_to_take;
            n -= amount_to_take;
            if n == 0 {
                break;
            }
            self.flip_buffer().await;
        }
    }

    /// Read exactly enough bytes from the stream to fill `out`.
    pub async fn read_exact(&mut self, out: &mut [u8]) {
        let mut pos = 0;
        self.read_exact_chunked(out.len(), |buf| {
            let out = &mut out[pos..];
            let to_take = buf.len().min(out.len());
            out[0..to_take].copy_from_slice(&buf[0..to_take]);
            pos += to_take;
        })
        .await
    }

    /// Read exactly `N` bytes from the stream.
    pub async fn read_exact_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        self.read_exact(&mut out).await;
        out
    }

    /// Skip `n` bytes in the stream.
    pub async fn advance_without_modifying(&mut self, n: usize) {
        self.read_exact_chunked(n, |_| ()).await
    }

    /// Return the number of bytes skipped.
    pub async fn skip_until_single_byte_needle(&mut self, needle: u8) -> u64 {
        let mut out = 0;
        self.read_until_single_byte_needle_chunked(needle, |buf| {
            out += u64::try_from(buf.len()).expect("sizeof(usize) <= sizeof(u64)");
            ShouldContinueIteration::KeepRunning
        })
        .await
        .expect("this shouldn't Err, since we never break");
        out
    }

    /// Read at most `MAX` non-needle bytes until the `needle` is observed. If the needle isn't
    /// found within `MAX + 1` bytes, then `Err` is returned. Otherwise the bytes before the needle
    /// will be returned.
    pub async fn read_max_until_single_byte_needle<const MAX: usize>(
        &mut self,
        needle: u8,
    ) -> Result<ArrayVec<u8, MAX>, NeedleNotFound<MAX>> {
        let mut out = ArrayVec::new();
        match self
            .read_until_single_byte_needle_chunked(needle, |chunk| {
                match out.try_extend_from_slice(chunk) {
                    Ok(()) => ShouldContinueIteration::KeepRunning,
                    Err(_) => ShouldContinueIteration::StopIteration,
                }
            })
            .await
        {
            Ok(()) => Ok(out),
            Err(_) => Err(NeedleNotFound { needle, seen: out }),
        }
    }

    /// Read bytes until the single-byte `needle` appears in the stream. This single-byte needle
    /// will not be included in any of the buffers passed to `thunk`.
    ///
    /// The `thunk` will be called zero or more times with the contents of the stream before the
    /// `needle`. Whenever the `thunk` is called with a buffer, if it returns `StopIteration`, then
    /// this function will not consume any more bytes and will return `Err`. If no calls to `thunk`
    /// return `StopIteration`, then this function will return `Ok`.
    pub async fn read_until_single_byte_needle_chunked<F>(
        &mut self,
        needle: u8,
        mut thunk: F,
    ) -> Result<(), IterationStopped>
    where
        for<'a> F: FnMut(&'a [u8]) -> ShouldContinueIteration,
    {
        loop {
            let chunk = self.current_buffer().await;
            // Try to find the needle.
            if let Some(idx) = memchr::memchr(needle, chunk) {
                let result = thunk(&chunk[0..idx]);
                self.position += idx + 1;
                debug_assert!(self.position <= self.whole_immutable_buffer().len());
                return match result {
                    ShouldContinueIteration::KeepRunning => Ok(()),
                    ShouldContinueIteration::StopIteration => Err(IterationStopped),
                };
            }
            // The needle is only a single byte. Visit the entire chunk, and then move on
            // looking for the one byte needle in the next chunk.
            if let ShouldContinueIteration::StopIteration = thunk(chunk) {
                return Err(IterationStopped);
            }
            self.position += chunk.len();
            debug_assert!(self.position <= self.whole_immutable_buffer().len());
            // The current_chunk() call in the next iteration will flip the buffer.
            debug_assert_eq!(self.buffer_size_remaining(), 0);
        }
    }

    /// Attempt to enter the mutable state of the rewriter.
    ///
    /// This will succeed if [`PreviewingCoroutineBasedStreamRewriter::into_mutable()`] is called
    /// before this function is called.
    ///
    /// If this fails, then it will return itself as an `Err`. This returned value is still valid
    /// for use.
    pub fn into_mutable(self) -> Result<GenState<R>, Self> {
        if self.is_mutable() {
            Ok(GenState(self))
        } else {
            Err(self)
        }
    }

    /// If this coroutine has entered the mutable state, then mutably borrow the mutable state of
    /// this generator state.
    pub fn as_mutable(&mut self) -> Option<&mut GenState<R>> {
        if self.is_mutable() {
            debug_assert_eq!(
                std::mem::size_of::<Self>(),
                std::mem::size_of::<GenState<R>>()
            );
            debug_assert_eq!(
                std::mem::align_of::<Self>(),
                std::mem::align_of::<GenState<R>>()
            );
            Some(unsafe {
                // SAFETY: this is basically what
                // https://docs.rs/bytemuck/1.7.2/bytemuck/trait.TransparentWrapper.html does.
                // GenState is repr(transparent) over Self, which makes this operation safe.
                &mut *(self as *mut GenStateImmutable<R> as *mut GenState<R>)
            })
        } else {
            None
        }
    }
}

/// Skip through a stream until a (multi-byte) needle is found.
pub struct SkipThroughNeedle {
    finder: memchr::memmem::Finder<'static>,
    buffer: Vec<u8>,
}
impl SkipThroughNeedle {
    /// Pre-process a needle to skip past.
    ///
    /// This same pre-processed needle can be used across multiple `GenState`/`GenStateImmutable`
    /// instances.
    pub fn new(needle: &[u8]) -> Self {
        let finder = memchr::memmem::Finder::new(needle).into_owned();
        SkipThroughNeedle {
            finder,
            buffer: Vec::new(),
        }
    }

    /// The `needle` that was passed to the constructor.
    pub fn needle(&self) -> &[u8] {
        self.finder.needle()
    }

    /// Skip through the stream of `gs` until the `needle` has been seen (and skipped past).
    pub async fn skip_through_needle(&mut self, gs: &mut GenStateImmutable) {
        self.buffer.clear();
        loop {
            let prefix_length: usize = self.buffer.len();
            let chunk = gs.current_buffer().await;
            self.buffer.extend_from_slice(chunk);
            if let Some(buffer_idx) = self.finder.find(self.buffer.as_slice()) {
                let buffer_end_idx = buffer_idx + self.finder.needle().len();
                let end_idx = buffer_end_idx - prefix_length;
                // This could be equal if the needle is at the end of the chunk.
                debug_assert!(end_idx <= chunk.len());
                debug_assert!(end_idx <= gs.buffer_size_remaining());
                gs.position += end_idx;
                debug_assert!(gs.position <= gs.whole_immutable_buffer().len());
                return;
            } else if self.buffer.len() > self.finder.needle().len() {
                let end = self.buffer.len() - self.finder.needle().len();
                self.buffer.drain(0..end);
            }
            let chunk_len = chunk.len();
            gs.advance_without_modifying(chunk_len).await;
        }
    }
}

/// A handle to rewrite and view bytes from a [`CoroutineBasedStreamRewriter`].
///
/// The existence of a `GenState` value implies that we're no longer in "preview" mode.
#[repr(transparent)]
pub struct GenState<R: Default = ()>(GenStateImmutable<R>);
impl<R: Default> GenState<R> {
    fn mutable_buffer(&mut self) -> &mut [u8] {
        // TODO: if these unwraps influence performance, we can maybe use unsafe to remove them.
        self.0.whole_buffer.as_mut().unwrap().mut_ref().unwrap()
    }

    /// Overwrite the next `src.len()` bytes with the contents of `src`.
    pub async fn write_exact_ignoring_contents(&mut self, mut src: &[u8]) {
        self.advance_exact_with_modification(src.len(), |buf| {
            let (fst, src2) = src.split_at(buf.len().min(src.len()));
            src = src2;
            buf[0..fst.len()].copy_from_slice(fst);
        })
        .await
    }

    /// Swap the next `src.len()` bytes with the contents of `src`.
    ///
    /// Unlike `write_exact_ignoring_contents`, `src` will be filled with the original contents of
    /// the stream.
    pub async fn swap_exact(&mut self, src: &mut [u8]) {
        let mut offset = 0;
        self.advance_exact_with_modification(src.len(), |buf| {
            buf.swap_with_slice(&mut src[offset..offset + buf.len()]);
            offset += buf.len();
        })
        .await
    }

    /// Return a mutable reference to the current chunk. The chunk WILL NOT be empty.
    pub async fn current_chunk(&mut self) -> &mut [u8] {
        loop {
            let n = self.buffer_size_remaining();
            if n == 0 {
                self.flip_buffer().await;
                continue;
            }
            let pos = self.position;
            break &mut self.mutable_buffer()[pos..pos + n];
        }
    }

    /// Consume `n` bytes exactly, calling `thunk` with a mutable reference to the bytes and a
    /// mutable reference to the value yielded by the `self` coroutine.
    ///
    /// `thunk` might get called more than once. If `n` is 0, `thunk` might never get called. It's
    /// possible for `thunk` to get called with an empty buffer.
    ///
    /// The sum of the lengths of buffers that `thunk` gets called with will sum to `n`.
    pub async fn advance_exact_with_modification_yielding<F>(&mut self, mut n: usize, mut thunk: F)
    where
        for<'a, 'b> F: FnMut(&'a mut [u8], &'b mut R, usize),
    {
        if n == 0 {
            return;
        }
        loop {
            let amount_to_take = self.buffer_size_remaining().min(n);
            let pos = self.position;

            // Invoke the thunk with a mutable reference to whatever value we're yielding, so that
            // the thunk can update it as necessary. We need to inline the `self.mutable_buffer()`
            // function so that we can take two simultaneous mutable borrows to `self.0`. Otherwise
            // the borrow checker will flag an error.
            thunk(
                &mut self.0.whole_buffer.as_mut().unwrap().mut_ref().unwrap()
                    [pos..pos + amount_to_take],
                &mut self.0.value_to_yield,
                pos,
            );

            self.position += amount_to_take;
            n -= amount_to_take;
            if n == 0 {
                break;
            }
            self.flip_buffer().await;
        }
    }

    /// Identical to `advance_exact_with_modification_yielding`, except the `thunk` is only called
    /// with a mutable reference to the bytes.
    pub async fn advance_exact_with_modification<F>(&mut self, n: usize, mut thunk: F)
    where
        for<'a> F: FnMut(&'a mut [u8]),
    {
        self.advance_exact_with_modification_yielding(n, |buf, _value_to_yield, _chunk_pos| {
            thunk(buf);
        })
        .await;
    }
}
impl<R: Default> Deref for GenState<R> {
    type Target = GenStateImmutable<R>;
    #[inline]
    fn deref(&self) -> &<Self as std::ops::Deref>::Target {
        &self.0
    }
}
impl<R: Default> DerefMut for GenState<R> {
    #[inline]
    fn deref_mut(&mut self) -> &mut <Self as std::ops::Deref>::Target {
        &mut self.0
    }
}

// TODO: switch this to the Never type when it gets stabilized.
/// This is a type with no values which inhabit it. It can never be constructed.
///
/// It's used as the return type of coroutine closures to indicate that they should never exit.
#[derive(Debug)]
pub enum StreamCoroutineShouldNeverExit {}

/// A coroutine-based stream rewriter in the "Preview" state. In this state, it can be used to
/// only read an incoming stream. It can be converted to a [`CoroutineBasedStreamRewriter`] which
/// can read and manipulate an incoming stream.
pub struct PreviewingCoroutineBasedStreamRewriter<R: Default = ()> {
    gen: GenBoxed<
        (Option<UnsafeSliceHolder>, R),
        Option<UnsafeSliceHolder>,
        StreamCoroutineShouldNeverExit,
    >,
}
impl<R: Default + Send + 'static> PreviewingCoroutineBasedStreamRewriter<R> {
    /// Create a new coroutine from the closure.
    pub fn new<F: Future<Output = StreamCoroutineShouldNeverExit> + Send + 'static>(
        body: impl (FnOnce(GenStateImmutable<R>) -> F) + Send + 'static,
    ) -> Self {
        let mut gen = GenBoxed::new_boxed(|co| {
            async move {
                let mut gs = GenStateImmutable {
                    co,
                    whole_buffer: None,
                    position: 0,
                    value_to_yield: R::default(),
                    previous_chunks_consumed: 0,
                };
                // According to the genawaiter docs, "the first resume argument will be lost." As a result
                // it makes sense for us to immediately yield an empty Vec, so that we can get in sync.
                let _ = gs.raw_flip_buffer().await;
                body(gs).await
            }
        });
        match gen.resume_with(None) {
            GeneratorState::Complete(_) => panic!("coroutine shouldn't complete."),
            GeneratorState::Yielded((holder, _r)) => assert!(holder.is_none()),
        }
        PreviewingCoroutineBasedStreamRewriter { gen }
    }

    /// Run the coroutine for one step.
    /// This will make sure that `guard` gets dropped _after_ `ush`.
    ///
    /// # Rationale
    /// We need to use `UnsafeSliceHolder` since the coroutine consists of two parts:
    /// 1. The "state" of the coroutine. This _must_ have a `'static` lifetime, since the underlying
    ///    genawaiter coroutine structure is heap-allocated, and might be called at any time.
    /// 2. The buffer we're operating on. The coroutine shouldn't hold a reference to this buffer
    ///    across rewrites, and so it _should_ be completely fine for us to pass a reference to some
    ///    non-`'static` buffer into the coroutine to be rewritten.
    ///
    /// We turn a reference to the buffer into an `UnsafeSliceHelper`. The `UnsafeSliceHelper` is
    /// `'static`, hence why it is unsafe. Creating an `UnsafeSliceHelper` creates a `PhantomData`
    /// guard. If we can ensure (as we do in this function by using `drop` calls) that the
    /// `UnsafeSliceHelper` gets dropped _before_ the `guard`, then we know that the
    /// `UnsafeSliceHelper` that was produced is safe to use (since the borrow checker will ensure
    /// that the lifetime of the buffer is valid until the guard has been dropped).
    ///
    /// Lastly, to make sure that the `UnsafeSliceHelper` gets dropped at the right time, we require
    /// that coroutine give an `UnsafeSliceHolder` back to us when it yields. So long as the
    /// coroutine can't create an `UnsafeSliceHolder` out of the blue (which it can't, since it
    /// doesn't call any of the unsafe new functions, and `UnsafeSliceHolder` isn't `Clone` or
    /// `Copy`), then the `UnsafeSliceHolder` it yields is the same `UnsafeSliceHolder` that we gave
    /// it. Further, the coroutine doesn't hold any more references to the buffer (because the
    /// Rust borrow checker has ensured that the `UnsafeSliceHolder` has been moved out of the
    /// coroutine).
    ///
    /// Thus, the coroutine can safely access and mutate a buffer, while ensuring that it can't
    /// hold a reference to the buffer for too long.
    fn rewrite_internal<'a, 'b>(
        &'a mut self,
        ush: UnsafeSliceHolder,
        guard: PhantomData<&'b mut ()>,
    ) -> R {
        match self.gen.resume_with(Some(ush)) {
            GeneratorState::Yielded((ush, r)) => {
                assert!(ush.is_some());
                std::mem::drop(ush);
                std::mem::drop(guard);
                r
            }
            GeneratorState::Complete(_) => panic!("The generator shouldn't complete"),
        }
    }

    /// Step the coroutine on the _immutable_ buffer `buf`
    #[inline]
    pub fn preview(&mut self, buf: &[u8]) -> R {
        let (ush, guard) = unsafe {
            // SAFETY: ush can't outlive guard (without a panic). The only way an UnsafeSliceHolder
            // can be constructed is by calling UnsafeSliceHolder::new (it doesn't implement Clone
            // or Copy). In addition, that function is only called here. As a result, so long as the
            // coroutine yields a Some value, the only UnsafeSliceHolder that it has access to it
            // is the value created below. As a result, ush can't outlive the guard, since we drop
            // ush, and then the guard.
            // TODO: is this safe in the case of std::panic::catch_unwind?
            UnsafeSliceHolder::new_immutable(buf)
        };
        self.rewrite_internal(ush, guard)
    }

    /// Enter the "mutable" mode of the rewriter. After entering this mode, the coroutine can only
    /// consume mutable buffers.
    pub fn into_mutable(self) -> CoroutineBasedStreamRewriter<R> {
        CoroutineBasedStreamRewriter(self)
    }
}

/// A coroutine-based stream rewriter which can only operate on mutable buffers.
pub struct CoroutineBasedStreamRewriter<R: Default + Send + 'static = ()>(
    PreviewingCoroutineBasedStreamRewriter<R>,
);

impl<R: Default + Send + 'static> CoroutineBasedStreamRewriter<R> {
    /// Construct a new coroutine from the given closure.
    pub fn new<F: Future<Output = StreamCoroutineShouldNeverExit> + Send + 'static>(
        body: impl (FnOnce(GenState<R>) -> F) + Send + 'static,
    ) -> Self {
        CoroutineBasedStreamRewriter(PreviewingCoroutineBasedStreamRewriter::new(
            |gs| async move {
                match gs.into_mutable() {
                    Ok(gs) => body(gs).await,
                    Err(_) => panic!("This is a non-preview coroutine."),
                }
            },
        ))
    }

    /// Step the coroutine on the _mutable_ buffer `buf`
    #[inline]
    pub fn rewrite(&mut self, buf: &mut [u8]) -> R {
        let (ush, guard) = unsafe {
            // SAFETY: ush can't outlive guard (without a panic). The only way an UnsafeSliceHolder
            // can be constructed is by calling UnsafeSliceHolder::new (it doesn't implement Clone
            // or Copy). In addition, that function is only called here. As a result, so long as the
            // coroutine yields a Some value, the only UnsafeSliceHolder that it has access to is
            // the value created below. As a result, ush can't outlive the guard, since we drop
            // ush, and then the guard.
            // TODO: is this safe in the case of std::panic::catch_unwind?
            UnsafeSliceHolder::new_mutable(buf)
        };
        self.0.rewrite_internal(ush, guard)
    }
}

#[cfg(test)]
mod testsuite;
