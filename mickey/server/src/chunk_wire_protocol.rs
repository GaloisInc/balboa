//! This module turns a stream of arbitrarily-sized byte-strings into a stream of 1KB-chunks
//! (and the reverse, as well).

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crossbeam::channel;
use mickey_balboa_ipc::CHUNK_SIZE;
use mickey_protocol::MAX_PACKAGE_SIZE;
use smallvec::SmallVec;
use std::time::Duration;

// Box<[u8; CHUNK_SIZE]> will allocate on the stack, and then copy.
/// This is a Bytes, with a known size.
pub struct HeapChunk(Bytes);
impl From<HeapChunk> for Bytes {
    #[inline]
    fn from(x: HeapChunk) -> Self {
        x.0
    }
}
#[derive(Debug)]
pub struct BytesWrongSizeForHeapChunk;

impl TryFrom<Bytes> for HeapChunk {
    type Error = BytesWrongSizeForHeapChunk;

    #[inline]
    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        if value.len() == CHUNK_SIZE {
            Ok(HeapChunk(value))
        } else {
            Err(BytesWrongSizeForHeapChunk)
        }
    }
}

pub struct ChunkWriter {
    chunks: channel::Sender<HeapChunk>,
    current_chunk: BytesMut,
}
impl ChunkWriter {
    pub fn new(chunks: channel::Sender<HeapChunk>) -> Self {
        ChunkWriter {
            chunks,
            current_chunk: BytesMut::with_capacity(CHUNK_SIZE),
        }
    }
    pub fn flush(&mut self) -> Result<(), channel::SendError<HeapChunk>> {
        if self.current_chunk.is_empty() {
            return Ok(());
        }
        assert_eq!(self.current_chunk.len(), CHUNK_SIZE);
        stallone::debug!("Start flushing current chunk");
        self.chunks.send(
            HeapChunk::try_from(
                std::mem::replace(&mut self.current_chunk, BytesMut::with_capacity(CHUNK_SIZE))
                    .freeze(),
            )
            .unwrap(),
        )?;
        stallone::debug!("Finished flushing current chunk");
        Ok(())
    }
    pub fn remaining_size(&self) -> usize {
        CHUNK_SIZE - self.current_chunk.len()
    }

    pub fn pad_remaining(&mut self) -> Result<(), channel::SendError<HeapChunk>> {
        if self.remaining_size() < CHUNK_SIZE && self.remaining_size() > 0 {
            static ZERO_CHUNK: [u8; CHUNK_SIZE] = [0; CHUNK_SIZE];
            let padding = Bytes::from_static(&ZERO_CHUNK[0..self.remaining_size()]);
            return self.put_bytes(padding);
        }

        Ok(())
    }
    pub fn put_bytes(&mut self, mut bytes: Bytes) -> Result<(), channel::SendError<HeapChunk>> {
        // We first put whatever we can into the current chunk, but only if it's not empty.
        // If it is empty, then we'll instead try to skip putting stuff in the current chunk,
        // and instead try to send whole chunks of bytes.
        if !self.current_chunk.is_empty() {
            let size = self.remaining_size().min(bytes.len());
            self.current_chunk.put(bytes.split_to(size));
        }
        // Then we put every whole chunk explicitly, while avoiding copying and extra allocation.
        while bytes.len() > CHUNK_SIZE {
            if !self.current_chunk.is_empty() {
                // If the current chunk isn't empty, then it's completely full, since the put
                // above would have filled the chunk completely, if there's anything left in the
                // current package.
                self.flush()?;
            }
            assert!(self.current_chunk.is_empty());
            self.chunks
                .send(HeapChunk::try_from(bytes.split_to(CHUNK_SIZE)).unwrap())?;
        }
        // Now we do a first pass at adding what remains of the current bytes.
        // We might not be able to put all the bytes in on one try, but we'll definitely be able to
        // do it in two tries, since bytes.len() <= CHUNK_SIZE.
        {
            let size = self.remaining_size().min(bytes.len());
            self.current_chunk.put(bytes.split_to(size));
        }
        if !bytes.is_empty() {
            // If bytes isn't empty, then the previous put() should have filled up the current
            // chunk.
            debug_assert_eq!(self.current_chunk.len(), CHUNK_SIZE);
            self.flush()?;
            let size = self.remaining_size().min(bytes.len());
            self.current_chunk.put(bytes.split_to(size));
        }
        Ok(())
    }
}

pub struct ChunkReader {
    chunks: channel::Receiver<HeapChunk>,
    current_chunk: Bytes,
}
impl ChunkReader {
    pub fn new(chunks: channel::Receiver<HeapChunk>) -> Self {
        ChunkReader {
            chunks,
            current_chunk: Bytes::new(),
        }
    }
    fn skip_padding(&mut self) -> Result<(), channel::RecvError> {
        loop {
            if self.current_chunk.is_empty() {
                self.current_chunk = self.chunks.recv()?.0;
            }
            if let Some(idx) = self.current_chunk.iter().enumerate().find_map(|(i, byte)| {
                if *byte != 0 {
                    Some(i)
                } else {
                    None
                }
            }) {
                self.current_chunk.advance(idx);
                return Ok(());
            } else {
                // We couldn't find ANY non-zero bytes. Read another chunk.
                self.current_chunk = Bytes::new();
            }
        }
    }
    fn read(&mut self, mut n: usize) -> Result<Vec<Bytes>, channel::RecvError> {
        let mut out = Vec::new();
        let n_orig = n;
        while n > 0 {
            if self.current_chunk.is_empty() {
                self.current_chunk = self.chunks.recv()?.0;
            }
            let sz = n.min(self.current_chunk.len());
            out.push(self.current_chunk.split_to(sz));
            n -= sz;
        }
        debug_assert_eq!(out.iter().map(|x| x.len()).sum::<usize>(), n_orig);
        let _ = n_orig;
        Ok(out)
    }
}

#[derive(Debug)]
pub struct SendOrRecvError;
impl From<channel::SendError<HeapChunk>> for SendOrRecvError {
    fn from(_: channel::SendError<HeapChunk>) -> Self {
        SendOrRecvError
    }
}
impl From<channel::SendError<Vec<Bytes>>> for SendOrRecvError {
    fn from(_: channel::SendError<Vec<Bytes>>) -> Self {
        SendOrRecvError
    }
}
impl From<channel::RecvError> for SendOrRecvError {
    fn from(_: channel::RecvError) -> Self {
        SendOrRecvError
    }
}

#[test]
fn test_max_package_size_fits_in_24_bits() {
    assert!(MAX_PACKAGE_SIZE < ((1 << 24) - 1));
}

pub fn process_one_outgoing_pkg(
    pkg: Bytes,
    chunk_writer: &mut ChunkWriter,
) -> Result<(), SendOrRecvError> {
    stallone::debug!("Starting new package", package_len: usize = pkg.len());
    // We want to ensure that we always flush before waiting (an indefinite period) for another
    // package.
    // We can do this since test_max_package_size_fits_in_24_bits passed.
    // We use big endian so the first byte (most significant) contains no meaningful data, so
    // we can use it to signal an end to padding.
    let mut len_bytes = (pkg.len() as u32).to_be_bytes();
    len_bytes[0] = 0xff;
    // TODO: we probably don't want to allocate all the time.
    chunk_writer.put_bytes(Bytes::copy_from_slice(&len_bytes))?;
    chunk_writer.put_bytes(pkg)?;
    Ok(())
}

pub fn process_outgoing_chunks(
    pkgs: channel::Receiver<Bytes>,
    chunks: channel::Sender<HeapChunk>,
) -> Result<(), SendOrRecvError> {
    let mut chunk_writer = ChunkWriter::new(chunks);
    let mut pkg = pkgs.recv()?;
    loop {
        process_one_outgoing_pkg(pkg, &mut chunk_writer)?;
        // Now, we'll try to see if there's another package on its way.
        if let Ok(pkg2) = pkgs.recv_timeout(Duration::from_micros(250)) {
            // If there is **WE DO NOT FLUSH**, and instead just start immediately operating on the
            // next package. We'll eventually send a chunk because the only place where we can block
            // is on a recv().
            pkg = pkg2;
        } else {
            // We didn't get another package. It's time to flush! We pad the current chunk, if needed.
            chunk_writer.pad_remaining()?;
            chunk_writer.flush()?;
            pkg = pkgs.recv()?;
        }
    }
}

pub fn process_one_incoming_pkg(
    pkgs: &channel::Sender<Vec<Bytes>>,
    chunk_reader: &mut ChunkReader,
) -> Result<(), SendOrRecvError> {
    chunk_reader.skip_padding()?;
    let mut header_bytes = SmallVec::<[u8; 4]>::new();
    for chunk in chunk_reader.read(4)? {
        header_bytes.extend_from_slice(&chunk[..]);
    }
    debug_assert_eq!(header_bytes[0], 0xff);
    // We INTENTIONALLY use BE. We also force the most significant byte to be zero.
    let len = u32::from_be_bytes([0, header_bytes[1], header_bytes[2], header_bytes[3]]) as usize;
    if len > MAX_PACKAGE_SIZE {
        // TODO: what can we do to recover from this error? If we see this, then we're
        // likely out-of-sync somehow with the sender, since the sender should've also
        // validated this.
        stallone::error!("Refusing to allocate for package of size", len: usize = len);
        return Ok(());
    }
    let current_pkg = chunk_reader.read(len)?;
    stallone::debug!("Sending package");
    pkgs.send(current_pkg)?;
    stallone::debug!("Sent package");
    Ok(())
}

pub fn process_incoming_chunks(
    pkgs: channel::Sender<Vec<Bytes>>,
    chunks: channel::Receiver<HeapChunk>,
) -> Result<(), SendOrRecvError> {
    let mut reader = ChunkReader::new(chunks);
    loop {
        process_one_incoming_pkg(&pkgs, &mut reader)?
    }
}

#[test]
fn test_chunk_wire_protocol() {
    fn combine(x: Vec<Bytes>) -> Bytes {
        let mut out = BytesMut::new();
        for chunk in x {
            out.put(chunk);
        }
        out.freeze()
    }

    let (out_pkg_s, out_pkg_r) = channel::bounded(1);
    let (chunks_s, chunks_r) = channel::bounded(1);
    let (in_pkg_s, in_pkg_r) = channel::bounded(1);
    std::thread::spawn(move || {
        let _ = process_outgoing_chunks(out_pkg_r, chunks_s);
    });
    std::thread::spawn(move || {
        let _ = process_incoming_chunks(in_pkg_s, chunks_r);
    });

    #[derive(Clone)]
    struct Ctx {
        send: channel::Sender<Bytes>,
        recv: channel::Receiver<Vec<Bytes>>,
    }
    impl Ctx {
        fn send(&self, bytes: Bytes) {
            self.send
                .send_timeout(bytes, Duration::from_millis(500))
                .unwrap();
        }
        fn recv(&self) -> Bytes {
            combine(self.recv.recv_timeout(Duration::from_millis(500)).unwrap())
        }
    }
    let ctx = Ctx {
        send: out_pkg_s,
        recv: in_pkg_r,
    };
    ctx.send(Bytes::from_static(b"hello"));
    assert_eq!(&ctx.recv()[..], b"hello");
    ctx.send(Bytes::from_static(b"hello2"));
    assert_eq!(&ctx.recv()[..], b"hello2");
    // Because 20 is MUCH higher than the amount of buffer in the channels, this tests whether we
    // are properly combining chunks.
    for i in 0..20 {
        ctx.send(Bytes::copy_from_slice(format!("{}", i).as_bytes()));
    }
    for i in 0..20 {
        assert_eq!(&ctx.recv()[..], format!("{}", i).as_bytes());
    }
    for i in 0..2 {
        ctx.send(Bytes::copy_from_slice(format!("x{}", i).as_bytes()));
        // We sleep to test the recv_timeout in process_outgoing_chunks
        std::thread::sleep(Duration::from_millis(1));
    }
    for i in 0..2 {
        assert_eq!(&ctx.recv()[..], format!("x{}", i).as_bytes());
    }
    for i in 0..20 {
        let short = Bytes::copy_from_slice(format!("short-{}", i).as_bytes());
        let mut long = format!("long-");
        for _ in 0..2048 {
            long.push_str(&format!("{}-", i));
        }
        let long = Bytes::copy_from_slice(long.as_bytes());
        let short2 = short.clone();
        let long2 = long.clone();
        let ctx2 = ctx.clone();
        let thr = std::thread::spawn(move || {
            assert_eq!(ctx2.recv(), short2);
            assert_eq!(ctx2.recv(), long2);
        });
        ctx.send(short);
        ctx.send(long);
        thr.join().unwrap();
    }
}
