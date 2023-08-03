use crate::{IncomingRewriter, StreamChangeData};

/// Is a given read operation "peek" or "consume"?
#[derive(Clone, Copy)]
pub enum ReadIsPeek {
    /// A read operation which advances the buffer, and reads from it.
    ConsumingRead,
    /// A read operation which reads from the buffer but  doesn't advance it.
    PeekingRead,
}

impl Default for ReadIsPeek {
    fn default() -> Self {
        ReadIsPeek::ConsumingRead
    }
}

impl ReadIsPeek {
    /// Return `PeekingRead` if the [`libc::MSG_PEEK`] bit is set in `flags.`
    /// Otherwise, return `ConsumingRead`.
    pub fn from_flags(flags: libc::c_int) -> Self {
        if (flags & libc::MSG_PEEK) == 0 {
            ReadIsPeek::ConsumingRead
        } else {
            ReadIsPeek::PeekingRead
        }
    }
}

pub struct ReadState {
    rewriter: Box<dyn IncomingRewriter + Send>,
    // This buffer should be cleared across reads.
    buffer: Vec<u8>,
    output_buffer: Vec<u8>,
    // This tracks the number of bytes that have been peeked-and-rewritten from the OS's data
    // stream, but haven't been consumed by a non-peeking read. Note that because of
    // `StreamChangeData` operations during peeking reads, this number can be different from
    // `ReadState::rewritten_bytes.len()`.
    already_peeked_bytes: usize,
    // This buffer stores any rewritten bytes which have either been peeked, or didn't fit in the
    // user's buffer and need to be saved for a future call to `rewrite_readv`.
    rewritten_bytes: Vec<u8>,
}

impl ReadState {
    pub fn new(rewriter: Box<dyn IncomingRewriter + Send>) -> Self {
        Self {
            rewriter,
            buffer: Vec::with_capacity(1024 * 9),
            output_buffer: Vec::with_capacity(1024),
            already_peeked_bytes: 0,
            rewritten_bytes: Vec::with_capacity(1024),
        }
    }

    pub fn rewrite_readv<F>(
        &mut self,
        input_buffer_size: usize,
        read_is_peek: ReadIsPeek,
        mut do_read: F,
    ) -> Result<&[u8], isize>
    where
        F: FnMut(&mut [u8]) -> isize,
    {
        // We don't want to keep any data around from a previous call to this function.
        self.buffer.clear();
        self.output_buffer.clear();

        // Size our internal read buffer to match the user-provided buffer.
        self.buffer.resize(input_buffer_size, 0);

        // Perform the provided read syscall. If we get an error, return immediately so we don't
        // overwrite `errno`.
        let mut bytes_read = match do_read(&mut self.buffer) {
            i if i <= 0 => return Err(i),
            i => i as usize, // safe coerce, since we know `i` is positive
        };
        debug_assert!(bytes_read > 0);
        debug_assert!(self.buffer.len() >= bytes_read);

        // Shrink the buffer down to the size of the data that was actually read by `do_read`. The
        // size of the input `iovecs` could be larger than the amount of data returned by
        // `do_read`.
        self.buffer.truncate(bytes_read);

        /* Run the rewriter. */

        // We've already rewritten `self.already_peeked_bytes` bytes in the OS stream (due to
        // previous peeking reads), and those bytes (in their un-rewritten state) were just read
        // again from `do_read` into the start of `self.buffer`. We don't want to pass those bytes to
        // the rewriter.
        let start_rewriting_index = self.already_peeked_bytes.min(self.buffer.len());
        let buffer_to_rewrite = &mut self.buffer[start_rewriting_index..];

        // Run the rewriter on the portion of the buffer that hasn't been rewritten yet.
        let mut stream_change_data = {
            let start = std::time::Instant::now();
            let stream_change_data = self.rewriter.incoming_rewrite(buffer_to_rewrite);
            stallone::info!(
                "INCOMING REWRITE DURATION",
                duration: std::time::Duration = start.elapsed(),
                bytes_rewritten: usize = buffer_to_rewrite.len(),
            );
            stream_change_data
        };

        // Apply the operations encoded in `stream_change_data`. The indices encoded in
        // `stream_change_data` point inside of the buffer that was just rewritten, so we must
        // offset them to appropriately point within `self.buffer`.

        if let Some((relative_add_index, byte_to_insert)) = stream_change_data.add_byte {
            let add_index = start_rewriting_index + relative_add_index;
            stallone::debug!(
                "Inserting byte into stream",
                stream_change_data: StreamChangeData = stream_change_data,
                start_rewriting_index: usize = start_rewriting_index,
                add_index: usize = add_index,
            );
            self.buffer.insert(add_index, byte_to_insert);
            if let Some(relative_remove_index) = stream_change_data.remove_byte.as_mut() {
                // For how we use these fields with TLS 1.3, this invariant should always hold
                // (since we remove a byte from the start of a TLS record, and add a byte to the
                // end of a TLS record).
                assert!(*relative_remove_index > relative_add_index);
                // The original remove index is now stale since we inserted an extra byte into this
                // stream. Move that index forward to reflect the byte we just added.
                *relative_remove_index += 1;
            }
        }

        if let Some(relative_remove_index) = stream_change_data.remove_byte {
            let remove_index = start_rewriting_index + relative_remove_index;
            stallone::debug!(
                "Removing byte from stream",
                stream_change_data: StreamChangeData = stream_change_data,
                start_rewriting_index: usize = start_rewriting_index,
                remove_index: usize = remove_index,
                byte_to_remove: Option<&u8> = self.buffer.get(*remove_index),
                buffer: String = format!("{:02x?}", self.buffer),
                // XXX It seems like this `buffer` doesn't match what I'm expecting from
                // `mangle_application_data`
            );
            self.buffer.remove(remove_index);
        }

        // If the rewrite exhausted the buffer, that means we ran a remove `StreamChangeData`
        // operation on a one-byte buffer. We can't return a zero-byte buffer, since the
        // application will interpret that as a this-file-descriptor-is-closed message. So, we will
        // manufacture an extra read-then-rewrite operation.
        if self.buffer.is_empty() {
            // The only way that `self.buffer` could be empty is if the only byte in the buffer was
            // removed. That means this byte had to have just been run through the rewriter, since
            // `StreamChangeData` can only operate on bytes that have been rewritten. This means
            // `start_rewriting_index` had to be 0.
            debug_assert_eq!(self.already_peeked_bytes, 0);
            debug_assert_eq!(start_rewriting_index, 0);

            // For a peeking read, we need to read past the single byte we just removed.
            let fake_read_size = match read_is_peek {
                ReadIsPeek::ConsumingRead => 1,
                ReadIsPeek::PeekingRead => 2,
            };
            stallone::debug!(
                "Calling do_read and the rewriter a second time",
                fake_read_size: usize = fake_read_size,
            );
            self.buffer.resize(fake_read_size, 0);
            let fake_bytes_read = match do_read(&mut self.buffer) {
                i if i <= 0 => return Err(i),
                i => i as usize, // safe coerce, since we know `i` is positive
            };

            if matches!(read_is_peek, ReadIsPeek::PeekingRead) {
                // If this fails, then we were only able to peek the byte that was already removed
                // from the stream, so we won't be able to return a byte.
                assert_eq!(fake_bytes_read, fake_read_size);

                // Remove the byte that we already peeked-and-rewrote-and-discarded from the
                // stream.
                self.buffer.remove(0);
            }

            // Update the number of bytes we've read from the OS.
            bytes_read = match read_is_peek {
                ReadIsPeek::ConsumingRead => bytes_read + fake_bytes_read,
                ReadIsPeek::PeekingRead => fake_bytes_read,
            };

            // Call the rewriter again on the result of the fake read. Note that we can pass the
            // entire `self.buffer`, since we know `start_rewriting_index` is 0, and we removed the
            // redundant first byte in the peeking read case.
            let fake_stream_change_data = self.rewriter.incoming_rewrite(&mut self.buffer);
            stallone::debug!(
                "Discarding fake StreamChangeData",
                fake_stream_change_data: StreamChangeData = fake_stream_change_data,
            );
            debug_assert!(fake_stream_change_data.add_byte.is_none());
            debug_assert!(fake_stream_change_data.remove_byte.is_none());
        }

        // After the above work, this should always be true.
        debug_assert!(!self.buffer.is_empty());

        self.already_peeked_bytes = match read_is_peek {
            // If there were some already-peeked-and-rewritten bytes in the OS's data stream, then
            // subtract from that the number of bytes that were just consumed from the OS's data
            // stream.
            ReadIsPeek::ConsumingRead => self.already_peeked_bytes.saturating_sub(bytes_read),
            // If we just peeked more bytes from the OS's data stream, then update our counter of
            // already-peeked-and-rewritten bytes.
            ReadIsPeek::PeekingRead => self.already_peeked_bytes.max(bytes_read),
        };

        // We want to replace the bytes that we've previously peeked (AKA all the bytes in
        // `self.buffer` that weren't passed to the rewriter) with the contents of
        // `self.rewritten_bytes`. Naively, we could assume that's equal to
        // `&self.buffer[..start_rewriting_index]`, since the `stream_change_data` operations above
        // only operate on `self.buffer` after `start_rewriting_index`. However, previous
        // `stream_change_data` operations on peeking reads invalidate that assumption. If a
        // previous peeking read happened during a `stream_change_data` operation, then
        // `self.rewritten_bytes` stores the peeked data _after_ that `stream_change_data` operation
        // was applied, so the length of `self.rewritten_bytes` is unpredictable relative to
        // `start_rewriting_index`.
        //
        // Instead, we'll use all of `self.rewritten_bytes`, and then append onto that all of the
        // bytes that were just rewritten, and potentially had `stream_change_data` operations
        // applied to them. This new buffer might be larger than the user-provided buffer.
        //
        // For consuming reads, we'll save all the newly-rewritten bytes that don't fit in the
        // user-provided buffer in `self.rewritten_bytes`.
        //
        // For peeking reads, we'll save all the rewritten-and-`stream_change_data`-applied bytes
        // in `self.rewritten_bytes`.

        let just_rewritten_bytes = &self.buffer[start_rewriting_index..];
        self.output_buffer.extend_from_slice(&self.rewritten_bytes);
        self.output_buffer.extend_from_slice(just_rewritten_bytes);

        // Note that we're using `input_buffer_size` here rather than `bytes_read`. If the OS returns
        // less data than we are able to store in the user's buffer, then take advantage of that.
        let output_size = self.output_buffer.len().min(input_buffer_size);

        stallone::debug!(
            "Preparing rewrite_readv result",
            bytes_read: usize = bytes_read,
            input_buffer_size: usize = input_buffer_size,
            rewritten_bytes_len: usize = self.rewritten_bytes.len(),
            just_rewritten_bytes_len: usize = just_rewritten_bytes.len(),
            output_buffer_len: usize = self.output_buffer.len(),
            output_size: usize = output_size,
        );

        match read_is_peek {
            ReadIsPeek::ConsumingRead => {
                // For a consuming read, get rid of all the previously-rewritten bytes that are
                // about to be copied into `self.buffer`.
                let rewritten_bytes_used = self.rewritten_bytes.len().min(output_size);
                if rewritten_bytes_used > 0 {
                    stallone::debug!(
                        "Dropping previously-rewritten bytes that have been consumed",
                        rewritten_bytes_used: usize = rewritten_bytes_used,
                    );
                }
                std::mem::drop(self.rewritten_bytes.drain(..rewritten_bytes_used));

                // Find the just-rewritten bytes that won't be returned to the user, and that we
                // need to save. If we didn't rewrite anything, then of course this is empty. If we
                // did some rewriting, then the `output_size` index splits `self.output_buffer` into two
                // parts: the part we'll return to the user, and the part we need to save.
                let just_rewritten_bytes_to_save = if just_rewritten_bytes.is_empty() {
                    &[]
                } else {
                    &self.output_buffer[output_size..]
                };
                if !just_rewritten_bytes_to_save.is_empty() {
                    stallone::debug!(
                        "Saving just-rewritten bytes that don't fit in user buffer",
                        num_just_rewritten_bytes_to_save: usize =
                            just_rewritten_bytes_to_save.len(),
                    );
                }

                // Save all the just-rewritten bytes that won't fit in the user-provided
                // buffer.
                self.rewritten_bytes
                    .extend_from_slice(just_rewritten_bytes_to_save);
            }
            ReadIsPeek::PeekingRead => {
                if !just_rewritten_bytes.is_empty() {
                    stallone::debug!(
                        "Saving just-rewritten bytes that were peeked",
                        num_just_rewritten_bytes: usize = just_rewritten_bytes.len(),
                    );
                }
                self.rewritten_bytes.extend_from_slice(just_rewritten_bytes);
            }
        }

        Ok(&self.output_buffer[..output_size])
    }
}
