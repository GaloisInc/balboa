use balboa_rewriter::{
    read_state::{ReadIsPeek, ReadState},
    IncomingRewriter, OutgoingRewriter,
};
use parking_lot::Mutex;
use std::ops::DerefMut;

use crate::fd_state::iovec_ext::IoVecExt;

mod iovec_ext;

/// The state for the "write"/outgoing side of the full-duplex TCP stream.
struct WriteState {
    rewriter: Box<dyn OutgoingRewriter + Send>,
    // This stores the bytes that were originally submitted. This is used to ensure that the
    // rewriter never needs to rewind.
    original_data_buffer: Vec<u8>,
    // This stores the bytes that will be actually outputted to underlying stream.
    outgoing_data_buffer: Vec<u8>,
}

impl WriteState {
    unsafe fn rewrite_write<F>(&mut self, original: &[libc::iovec], do_write: F) -> isize
    where
        F: FnOnce(&[u8]) -> isize,
    {
        debug_assert_eq!(
            self.original_data_buffer.len(),
            self.outgoing_data_buffer.len(),
        );
        let mut original_buffer = &self.original_data_buffer[..];
        let mut would_have_rewound = false;
        original.iterate_byte_slice(|bytes| {
            let overlap = original_buffer.len().min(bytes.len());
            if &original_buffer[0..overlap] != &bytes[0..overlap] {
                would_have_rewound = true;
            }
            original_buffer = &original_buffer[overlap..];
        });
        if would_have_rewound {
            stallone::error!("Would have rewound!");
            // TODO: we should set a flag to prevent further operations if we enter this state.
        }
        let original_total_bytes = original.total_bytes();
        // Assuming that we aren't in a rewind state, then we check to see if our existing buffer
        // has enough bytes to fulfill the write operation. If not, then we need to perform a
        // rewrite.
        if original_total_bytes > self.outgoing_data_buffer.len() {
            let start_new_data = self.original_data_buffer.len();
            original.copy_from_iovec(
                &mut self.original_data_buffer,
                self.outgoing_data_buffer.len()..original_total_bytes,
            );
            self.outgoing_data_buffer
                .extend_from_slice(&self.original_data_buffer[start_new_data..]);
            self.rewriter
                .outgoing_rewrite(&mut self.outgoing_data_buffer[start_new_data..]);
        }
        debug_assert_eq!(
            self.original_data_buffer.len(),
            self.outgoing_data_buffer.len(),
        );
        assert!(
            self.outgoing_data_buffer.len() >= original_total_bytes,
            "{}",
            self.original_data_buffer.len(),
        );
        // Now the outgoing data buffer is setup with all the bytes we need to complete the write.
        let result = do_write(&self.outgoing_data_buffer[0..original_total_bytes]);
        if result >= 1 {
            // If at least one byte was sent, then remove those bytes from all buffers.
            let bytes_written = usize::try_from(result).expect("We did the comparison.");
            self.outgoing_data_buffer.drain(0..bytes_written);
            self.original_data_buffer.drain(0..bytes_written);
        }
        result
    }
}

/// All the state that Balboa stores for a single file descriptor.
pub struct FdState {
    read_side: Mutex<ReadState>,
    write_side: Mutex<WriteState>,
}

impl FdState {
    pub fn new(
        read_side: Box<dyn IncomingRewriter + Send>,
        write_side: Box<dyn OutgoingRewriter + Send>,
    ) -> FdState {
        FdState {
            read_side: Mutex::new(ReadState::new(read_side)),
            write_side: Mutex::new(WriteState {
                rewriter: write_side,
                original_data_buffer: Vec::with_capacity(1024 * 9),
                outgoing_data_buffer: Vec::with_capacity(1024 * 9),
            }),
        }
    }

    /// Rewrite a (vectored/scatter) read.
    ///
    /// If `do_read` returns 0 or a negative number, then this function returns that number
    /// immediately without invoking the rewriter.
    pub unsafe fn rewrite_readv<F>(
        &self,
        iovecs: &[libc::iovec],
        read_is_peek: ReadIsPeek,
        do_read: F,
    ) -> isize
    where
        F: FnMut(&mut [u8]) -> isize,
    {
        let iovec_bytes = iovecs.total_bytes();

        let mut rs = self.read_side.lock();
        let rs = rs.deref_mut();

        let output_buffer = match rs.rewrite_readv(iovec_bytes, read_is_peek, do_read) {
            Ok(xs) => xs,
            Err(i) => return i,
        };

        // Copy the rewritten data to the user-provided buffer, `iovecs`.
        iovecs.copy_from_contigous_buffer(output_buffer);

        output_buffer.len() as isize
    }

    /// Rewrite a (vectored/gather) write.
    pub unsafe fn rewrite_write<F>(&self, original: &[libc::iovec], do_write: F) -> isize
    where
        F: FnOnce(&[u8]) -> isize,
    {
        let mut ws = self.write_side.lock();
        let start = std::time::Instant::now();
        let out = ws.rewrite_write(original, do_write);
        stallone::info!(
            "OUTGOING REWRITE DURATION",
            duration: std::time::Duration = start.elapsed()
        );
        out
    }
}

#[cfg(test)]
mod peeking_tests {
    use super::*;
    use balboa_rewriter::{NullRewriter, StreamChangeData};
    use proptest::{collection::SizeRange, prelude::*};
    use std::sync::Arc;

    #[derive(Clone, Copy, Debug)]
    enum Command {
        Read(usize),
        Peek(usize),
    }

    fn run_test(commands: &[Command]) {
        // We use the most significant bit to track whether or not a byte has been mutated or not.
        // If the MSBit is 0, then the byte hasn't passed through the incoming rewrite. If it's 1,
        // then it has passed through the incoming rewrite.
        struct IR(Arc<Mutex<Option<Vec<u8>>>>);
        impl IncomingRewriter for IR {
            fn incoming_rewrite(&mut self, buf: &mut [u8]) -> StreamChangeData {
                let mut guard = self.0.lock();
                assert!(guard.is_none());
                *guard = Some(buf.to_vec());
                for entry in buf {
                    assert_eq!(*entry & (1 << 7), 0);
                    *entry |= 1 << 7;
                }
                StreamChangeData::default()
            }
        }
        let state: Arc<Mutex<Option<Vec<u8>>>> = Default::default();
        let fd_state = FdState::new(Box::new(IR(state.clone())), Box::new(NullRewriter));
        let mut queue = Vec::<u8>::new();
        // What next byte do we generate. We try to avoid 0, since that tends to be used for
        // default values. We also can't set the high bit of this value.
        let mut next_byte = 1_u8;
        for command in commands.iter().cloned() {
            let n = match command {
                Command::Read(n) => n,
                Command::Peek(n) => n,
            };
            let incoming_rewrite_expected = if queue.len() < n {
                // We can't satisfy the command with just what we have in the buffer.
                let new_bytes_needed = n - queue.len();
                let mut new_bytes = Vec::new();
                for _ in 0..new_bytes_needed {
                    new_bytes.push(next_byte);
                    next_byte += 1;
                    if next_byte == 1 << 7 {
                        next_byte = 1;
                    }
                }
                new_bytes
            } else {
                Vec::new()
            };
            queue.extend_from_slice(incoming_rewrite_expected.as_slice());
            let mut client_buffer: Vec<u8> = Vec::new();
            client_buffer.extend_from_slice(&queue[0..n]);
            if client_buffer.len() < 500 {
                client_buffer.resize(500, 0)
            }
            unsafe {
                fd_state.rewrite_readv(
                    &[libc::iovec {
                        iov_base: client_buffer.as_mut_ptr() as *mut _,
                        iov_len: client_buffer.len(),
                    }],
                    match command {
                        Command::Read(_) => ReadIsPeek::ConsumingRead,
                        Command::Peek(_) => ReadIsPeek::PeekingRead,
                    },
                    |new_buf| {
                        new_buf[..n].copy_from_slice(&queue[..n]);
                        n as isize
                    },
                );
            }
            let incoming_rewrite_buffer = state.lock().take().unwrap();
            assert_eq!(incoming_rewrite_buffer, incoming_rewrite_expected);
            if let Command::Read(_) = command {
                std::mem::drop(queue.drain(0..n));
            }
        }
    }

    fn command_strategy() -> BoxedStrategy<Command> {
        (any::<bool>(), 1..10_usize)
            .prop_map(|(flag, size)| {
                if flag {
                    Command::Read(size)
                } else {
                    Command::Peek(size)
                }
            })
            .boxed()
    }

    #[test]
    fn predefined_tests() {
        use Command::Peek as P;
        use Command::Read as R;
        run_test(&[]);
        run_test(&[P(1)]);
        run_test(&[P(1), P(2), P(3)]);
        run_test(&[R(10)]);
        run_test(&[R(10), R(10)]);
        run_test(&[P(1), R(1)]);
        run_test(&[P(10), R(20)]);
        run_test(&[P(20), R(10), R(10), R(10)]);
        run_test(&[P(20), R(10), P(10), R(10), R(50)]);
    }

    proptest! {
        #[test]
        fn random_tests(commands in proptest::collection::vec(command_strategy(), SizeRange::default())) {
            run_test(commands.as_slice());
        }
    }
}

#[cfg(test)]
mod stream_change_data_tests {
    use super::*;
    use balboa_rewriter::{NullRewriter, StreamChangeData};
    use std::{mem, sync::Arc};

    struct TestIncomingRewriter {
        stream_change_data: Arc<Mutex<StreamChangeData>>,
        rewrite_data: Arc<Mutex<Vec<u8>>>,
    }

    impl TestIncomingRewriter {
        fn new(
            stream_change_data: Arc<Mutex<StreamChangeData>>,
            rewrite_data: Arc<Mutex<Vec<u8>>>,
        ) -> Self {
            Self {
                stream_change_data,
                rewrite_data,
            }
        }
    }

    impl IncomingRewriter for TestIncomingRewriter {
        fn incoming_rewrite(&mut self, buf: &mut [u8]) -> StreamChangeData {
            buf.copy_from_slice(self.rewrite_data.lock().drain(..buf.len()).as_slice());

            mem::take(&mut *self.stream_change_data.lock())
        }
    }

    #[derive(Debug)]
    struct TestCommand<'a> {
        read_size: Vec<usize>,
        user_buffer_size: usize,
        stream_change_data: StreamChangeData,
        is_peeking_read: bool,
        expected_data: &'a [u8],
        expected_rewritten_bytes: usize,
    }

    impl<'a> TestCommand<'a> {
        fn new(
            read_size: usize,
            user_buffer_size: usize,
            stream_change_data: StreamChangeData,
            is_peeking_read: bool,
            expected_data: &'a [u8],
            expected_rewritten_bytes: usize,
        ) -> Self {
            // `read_size` is the amount of data that will be read from the fake-OS-data-stream,
            // and `user_buffer_size` is the size of the buffer that will be provided to the `read`
            // syscall.
            assert!(read_size <= user_buffer_size);
            // It's illegal to run these tests with zero-sized buffers.
            assert!(user_buffer_size > 0);
            Self {
                read_size: vec![read_size],
                user_buffer_size,
                stream_change_data,
                is_peeking_read,
                expected_data,
                expected_rewritten_bytes,
            }
        }

        fn new_multiple_reads(
            read_size: Vec<usize>,
            user_buffer_size: usize,
            stream_change_data: StreamChangeData,
            is_peeking_read: bool,
            expected_data: &'a [u8],
            expected_rewritten_bytes: usize,
        ) -> Self {
            Self {
                read_size,
                user_buffer_size,
                stream_change_data,
                is_peeking_read,
                expected_data,
                expected_rewritten_bytes,
            }
        }
    }

    struct TestRunner {
        global_stream_change_data: Arc<Mutex<StreamChangeData>>,
        rewrite_data: Arc<Mutex<Vec<u8>>>,
        fd_state: FdState,
        input_data: Vec<u8>,
        input_data_index: u8,
    }

    impl TestRunner {
        fn new() -> Self {
            let global_stream_change_data: Arc<Mutex<StreamChangeData>> = Default::default();
            let rewrite_data = Arc::new(Mutex::new((129..=255).collect()));
            let fd_state = FdState::new(
                Box::new(TestIncomingRewriter::new(
                    global_stream_change_data.clone(),
                    rewrite_data.clone(),
                )),
                Box::new(NullRewriter),
            );
            Self {
                global_stream_change_data,
                rewrite_data,
                fd_state,
                input_data: Vec::with_capacity(256),
                input_data_index: 0,
            }
        }

        fn run_test(&mut self, test_command: TestCommand) {
            // Allocate sufficient data for the test.
            let max_read_size = if test_command.is_peeking_read {
                *test_command.read_size.iter().max().unwrap()
            } else {
                test_command.read_size.iter().sum()
            };
            if max_read_size > self.input_data.len() {
                self.input_data.resize_with(max_read_size, || {
                    self.input_data_index = self.input_data_index.wrapping_add(1);
                    self.input_data_index
                });
            }

            // Get the current size of the rewrite_data Vec, so we can confirm the right amount of
            // data was rewritten.
            let orig_rewrite_data_len = {
                let rewrite_data_lock = self.rewrite_data.lock();
                rewrite_data_lock.len()
            };

            // Send the new `StreamChangeData` from the test command to the rewriter.
            {
                let mut locked_command = self.global_stream_change_data.lock();
                *locked_command = test_command.stream_change_data;
            }

            let read_is_peek = if test_command.is_peeking_read {
                ReadIsPeek::PeekingRead
            } else {
                ReadIsPeek::ConsumingRead
            };

            let mut user_buffer: Vec<u8> = vec![0; test_command.user_buffer_size];

            let mut read_size_vec = test_command.read_size.clone();

            let result = unsafe {
                self.fd_state.rewrite_readv(
                    &[libc::iovec {
                        iov_base: user_buffer.as_mut_ptr() as *mut _,
                        iov_len: user_buffer.len(),
                    }],
                    read_is_peek,
                    |new_buf| {
                        assert!(!new_buf.is_empty());
                        let n = read_size_vec.remove(0);
                        new_buf[..n].copy_from_slice(&self.input_data[..n]);
                        n as isize
                    },
                )
            };

            assert_eq!(result, test_command.expected_data.len() as isize);
            assert!(read_size_vec.is_empty());

            assert_eq!(
                &user_buffer[..test_command.expected_data.len()],
                test_command.expected_data
            );

            // Confirm the right amount of data was rewritten.
            let final_rewrite_data_len = {
                let rewrite_data_lock = self.rewrite_data.lock();
                rewrite_data_lock.len()
            };
            let rewritten_bytes = orig_rewrite_data_len - final_rewrite_data_len;
            assert_eq!(rewritten_bytes, test_command.expected_rewritten_bytes);

            // Drop bytes from the beginning of `self.input_data` if this was a consuming read.
            if !test_command.is_peeking_read {
                mem::drop(self.input_data.drain(..max_read_size));
            }
        }
    }

    #[test]
    fn peek_consume_unit_tests() {
        /* Simple consuming read */
        let mut runner = TestRunner::new();
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData::default(),
            false,
            (129..139).collect::<Vec<u8>>().as_slice(),
            10,
        ));

        /* Simple peeking read */
        let mut runner = TestRunner::new();
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData::default(),
            true,
            (129..139).collect::<Vec<u8>>().as_slice(),
            10,
        ));

        /* Longer peeking read, then shorter peeking read, then longer peeking read */
        let mut runner = TestRunner::new();
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData::default(),
            true,
            (129..139).collect::<Vec<u8>>().as_slice(),
            10,
        ));
        runner.run_test(TestCommand::new(
            5,
            5,
            StreamChangeData::default(),
            true,
            (129..134).collect::<Vec<u8>>().as_slice(),
            0,
        ));
        runner.run_test(TestCommand::new(
            12,
            12,
            StreamChangeData::default(),
            true,
            (129..141).collect::<Vec<u8>>().as_slice(),
            2,
        ));

        /* Peeking read followed by consuming read (which overlaps the peeking read) followed by
         * another consuming read (which exceeds the size of the peeking read)
         */
        let mut runner = TestRunner::new();
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData::default(),
            true,
            (129..139).collect::<Vec<u8>>().as_slice(),
            10,
        ));
        runner.run_test(TestCommand::new(
            5,
            5,
            StreamChangeData::default(),
            false,
            (129..134).collect::<Vec<u8>>().as_slice(),
            0,
        ));
        runner.run_test(TestCommand::new(
            7,
            7,
            StreamChangeData::default(),
            false,
            (134..141).collect::<Vec<u8>>().as_slice(),
            2,
        ));

        /* Consuming read followed by peeking read */
        let mut runner = TestRunner::new();
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData::default(),
            false,
            (129..139).collect::<Vec<u8>>().as_slice(),
            10,
        ));
        runner.run_test(TestCommand::new(
            5,
            5,
            StreamChangeData::default(),
            true,
            (139..144).collect::<Vec<u8>>().as_slice(),
            5,
        ));
    }

    #[test]
    fn stream_change_unit_tests() {
        /* Remove byte */
        let mut runner = TestRunner::new();
        let mut expected_data: Vec<u8> = (129..139).collect();
        assert_eq!(expected_data.len(), 10);
        expected_data.remove(5);
        assert_eq!(expected_data.len(), 9);
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData {
                add_byte: None,
                remove_byte: Some(5),
            },
            false,
            &expected_data,
            10,
        ));

        /* Add byte */
        let mut runner = TestRunner::new();
        let mut expected_data: Vec<u8> = (129..139).collect();
        assert_eq!(expected_data.len(), 10);
        expected_data.insert(2, 42);
        assert_eq!(expected_data.len(), 11);
        // Note that the user-provided buffer is one byte larger than the amount of data we
        // "request" from the OS, so we have room for the extra inserted byte.
        runner.run_test(TestCommand::new(
            10,
            11,
            StreamChangeData {
                add_byte: Some((2, 42)),
                remove_byte: None,
            },
            false,
            &expected_data,
            10,
        ));

        /* Simultaneous add and remove */
        let mut runner = TestRunner::new();
        let mut expected_data: Vec<u8> = (129..139).collect();
        assert_eq!(expected_data.len(), 10);
        expected_data.insert(5, 42);
        expected_data.remove(7 + 1);
        assert_eq!(expected_data.len(), 10);
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData {
                add_byte: Some((5, 42)),
                remove_byte: Some(7),
            },
            false,
            &expected_data,
            10,
        ));

        /* Remove-then-add */
        let mut runner = TestRunner::new();
        let mut expected_data: Vec<u8> = (129..139).collect();
        assert_eq!(expected_data.len(), 10);
        expected_data.remove(1);
        assert_eq!(expected_data.len(), 9);
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData {
                add_byte: None,
                remove_byte: Some(1),
            },
            false,
            &expected_data,
            10,
        ));
        let mut expected_data: Vec<u8> = (139..149).collect();
        assert_eq!(expected_data.len(), 10);
        expected_data.insert(8, 50);
        assert_eq!(expected_data.len(), 11);
        // Note that the user-provided buffer is one byte larger than the amount of data we
        // "request" from the OS, so we have room for the extra inserted byte.
        runner.run_test(TestCommand::new(
            10,
            11,
            StreamChangeData {
                add_byte: Some((8, 50)),
                remove_byte: None,
            },
            false,
            &expected_data,
            10,
        ));
    }

    #[test]
    fn peeking_remove_test_1() {
        /* Remove a byte during a peeking read */
        let mut runner = TestRunner::new();
        // Remove a byte during a peeking read
        runner.run_test(TestCommand::new(
            3,
            3,
            StreamChangeData {
                add_byte: None,
                remove_byte: Some(1),
            },
            true,
            &[129, 131],
            3,
        ));
        // Peek more data, confirm byte is still removed
        runner.run_test(TestCommand::new(
            5,
            5,
            StreamChangeData::default(),
            true,
            &[129, 131, 132, 133],
            2,
        ));
        // Consume the stream before the byte removal
        runner.run_test(TestCommand::new(
            1,
            1,
            StreamChangeData::default(),
            false,
            &[129],
            0,
        ));
        // Peek at the point of the byte removal
        runner.run_test(TestCommand::new(
            3,
            3,
            StreamChangeData::default(),
            true,
            &[131, 132, 133],
            0,
        ));
        // Consume at the point of the byte removal
        runner.run_test(TestCommand::new(
            3,
            3,
            StreamChangeData::default(),
            false,
            &[131, 132, 133],
            0,
        ));
        // Consume all outstanding peeked data
        runner.run_test(TestCommand::new(
            2,
            2,
            StreamChangeData::default(),
            false,
            &[134],
            1,
        ));
        // Test a normal consuming read, now that all peeked data is gone
        runner.run_test(TestCommand::new(
            2,
            2,
            StreamChangeData::default(),
            false,
            &[135, 136],
            2,
        ));
    }

    #[test]
    fn peeking_remove_test_2() {
        /* Remove a byte during a peeking read, but start with a consuming read */
        let mut runner = TestRunner::new();
        // Start by consuming some data
        runner.run_test(TestCommand::new(
            2,
            2,
            StreamChangeData::default(),
            false,
            &[129, 130],
            2,
        ));
        // Remove a byte during a peeking read
        runner.run_test(TestCommand::new(
            6,
            6,
            StreamChangeData {
                add_byte: None,
                remove_byte: Some(2),
            },
            true,
            &[131, 132, 134, 135, 136],
            6,
        ));
        // Peek before the removed byte
        runner.run_test(TestCommand::new(
            1,
            1,
            StreamChangeData::default(),
            true,
            &[131],
            0,
        ));
        // Peek across the removed byte, but before the total amount of peeked bytes
        runner.run_test(TestCommand::new(
            4,
            4,
            StreamChangeData::default(),
            true,
            &[131, 132, 134, 135],
            0,
        ));
        // Consume before the removed byte
        runner.run_test(TestCommand::new(
            1,
            1,
            StreamChangeData::default(),
            false,
            &[131],
            0,
        ));
        // Peek across the removed byte, but before the total amount of peeked bytes
        runner.run_test(TestCommand::new(
            4,
            4,
            StreamChangeData::default(),
            true,
            &[132, 134, 135, 136],
            0,
        ));
        // Peek across the removed byte, up to the total amount of peeked bytes
        runner.run_test(TestCommand::new(
            5,
            5,
            StreamChangeData::default(),
            true,
            &[132, 134, 135, 136],
            0,
        ));
        // Peek past the total amount of peeked bytes
        runner.run_test(TestCommand::new(
            6,
            6,
            StreamChangeData::default(),
            true,
            &[132, 134, 135, 136, 137],
            1,
        ));
        // Consume all outstanding peeked data
        runner.run_test(TestCommand::new(
            6,
            6,
            StreamChangeData::default(),
            false,
            &[132, 134, 135, 136, 137],
            0,
        ));
        // Test a normal peeking read, now that all peeked data is gone
        runner.run_test(TestCommand::new(
            4,
            4,
            StreamChangeData::default(),
            true,
            (138..142).collect::<Vec<u8>>().as_slice(),
            4,
        ));
    }

    #[test]
    fn peeking_add_test() {
        /* Add a byte during a peeking read */
        let mut runner = TestRunner::new();
        // Add a byte during a peeking read
        runner.run_test(TestCommand::new(
            3,
            3,
            StreamChangeData {
                add_byte: Some((1, 42)),
                remove_byte: None,
            },
            true,
            &[129, 42, 130],
            3,
        ));
        // Peek more data, confirm byte is still added
        runner.run_test(TestCommand::new(
            5,
            6,
            StreamChangeData::default(),
            true,
            &[129, 42, 130, 131, 132, 133],
            2,
        ));
        // Consume the stream before the byte addition
        runner.run_test(TestCommand::new(
            1,
            1,
            StreamChangeData::default(),
            false,
            &[129],
            0,
        ));
        // Peek at the point of the byte addition (note that an extra byte gets read and rewritten)
        runner.run_test(TestCommand::new(
            5,
            5,
            StreamChangeData::default(),
            true,
            &[42, 130, 131, 132, 133],
            1,
        ));
        // Consume at the point of the byte addition
        runner.run_test(TestCommand::new(
            5,
            5,
            StreamChangeData::default(),
            false,
            &[42, 130, 131, 132, 133],
            0,
        ));
        // Consume all outstanding peeked data (note that an extra byte gets read and rewritten)
        runner.run_test(TestCommand::new(
            1,
            1,
            StreamChangeData::default(),
            false,
            &[134],
            1,
        ));
    }

    #[test]
    fn remove_one_byte_read() {
        /* Remove a byte on a one-byte consuming read */
        let mut runner = TestRunner::new();
        runner.run_test(TestCommand::new_multiple_reads(
            vec![1, 1],
            1,
            StreamChangeData {
                add_byte: None,
                remove_byte: Some(0),
            },
            false,
            &[130],
            2,
        ));

        /* Remove a byte on a one-byte peeking read */
        let mut runner = TestRunner::new();
        runner.run_test(TestCommand::new_multiple_reads(
            vec![1, 2],
            1,
            StreamChangeData {
                add_byte: None,
                remove_byte: Some(0),
            },
            true,
            &[130],
            2,
        ));
        // Now peek a few bytes to make sure the previously-peeked bytes are correctly tracked
        runner.run_test(TestCommand::new(
            3,
            3,
            StreamChangeData::default(),
            true,
            &[130, 131],
            1,
        ));
        // Now consume a few bytes to make sure the previously-peeked bytes are correctly tracked
        runner.run_test(TestCommand::new(
            3,
            3,
            StreamChangeData::default(),
            false,
            &[130, 131],
            0,
        ));
        runner.run_test(TestCommand::new(
            3,
            3,
            StreamChangeData::default(),
            false,
            &[132, 133, 134],
            3,
        ));
    }

    #[test]
    fn add_with_not_enough_room_1() {
        /* Add a byte, but don't provide enough `iovec` space for the extra byte */
        let mut runner = TestRunner::new();
        let mut expected_data: Vec<u8> = (129..138).collect();
        assert_eq!(expected_data.len(), 9);
        expected_data.insert(2, 42);
        assert_eq!(expected_data.len(), 10);
        // This first read should return nine of the ten rewritten bytes, plus the inserted byte.
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData {
                add_byte: Some((2, 42)),
                remove_byte: None,
            },
            false,
            &expected_data,
            10,
        ));
        // This second read should return the tenth rewritten byte, but another byte will be read
        // from the OS and rewritten. That byte will remain in the `rewritten_bytes` vec.
        runner.run_test(TestCommand::new(
            1,
            1,
            StreamChangeData::default(),
            false,
            &[138],
            1,
        ));
    }

    #[test]
    fn add_with_not_enough_room_2() {
        /* Same as `add_with_not_enough_room_1`, but now run a larger second read, so `do_read` and
         * the rewriter have to run */
        let mut runner = TestRunner::new();
        let mut expected_data: Vec<u8> = (129..138).collect();
        assert_eq!(expected_data.len(), 9);
        expected_data.insert(2, 42);
        assert_eq!(expected_data.len(), 10);
        // This first read should return nine of the ten rewritten bytes, plus the inserted byte.
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData {
                add_byte: Some((2, 42)),
                remove_byte: None,
            },
            false,
            &expected_data,
            10,
        ));
        // This second read should return the tenth rewritten byte plus a few extra bytes, which
        // will involve a call to `do_read` and the rewriter.
        runner.run_test(TestCommand::new(
            2,
            3,
            StreamChangeData::default(),
            false,
            &[138, 139, 140],
            2,
        ));
    }

    #[test]
    fn stream_change_real_use_case_test() {
        // First a remove at the start of the stream, then a normal read, then an add at the end of
        // the stream.
        let mut runner = TestRunner::new();
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData {
                add_byte: None,
                remove_byte: Some(0),
            },
            false,
            (130..139).collect::<Vec<u8>>().as_slice(),
            10,
        ));
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData::default(),
            false,
            (139..149).collect::<Vec<u8>>().as_slice(),
            10,
        ));
        let mut expected_data: Vec<u8> = (149..158).collect();
        expected_data.push(42);
        runner.run_test(TestCommand::new(
            9,
            10,
            StreamChangeData {
                add_byte: Some((9, 42)),
                remove_byte: None,
            },
            false,
            &expected_data,
            9,
        ));

        // Now we'll simulate running into a TLS record boundary, which will require and
        // remove-and-add operation.
        let mut runner = TestRunner::new();
        runner.run_test(TestCommand::new(
            10,
            10,
            StreamChangeData {
                add_byte: None,
                remove_byte: Some(0),
            },
            false,
            (130..139).collect::<Vec<u8>>().as_slice(),
            10,
        ));
        // Because there will always be a TLS header between the end of the previous record and the
        // start of the next one, we'll never have to add-and-remove two bytes that are
        // side-by-side.
        let mut expected_data: Vec<u8> = (139..148).collect();
        expected_data.push(42);
        expected_data.extend_from_slice(&[148, 150, 151, 152, 153]);
        runner.run_test(TestCommand::new(
            15,
            15,
            StreamChangeData {
                add_byte: Some((9, 42)),
                remove_byte: Some(10),
            },
            false,
            &expected_data,
            15,
        ));
        let mut expected_data: Vec<u8> = (154..163).collect();
        expected_data.push(43);
        runner.run_test(TestCommand::new(
            9,
            10,
            StreamChangeData {
                add_byte: Some((9, 43)),
                remove_byte: None,
            },
            false,
            &expected_data,
            9,
        ));
    }
}
