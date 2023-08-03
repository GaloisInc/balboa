//! Evaluate SipHash in const fn

// NOTE: feel free to replace this with an external const fn siphash crate, if one becomes available

// We mark all the functions in this module as cold. They shouldn't be called at runtime
// (except in helper CLI tools for manipulating log data).

// NOTE: mutable references in const are unstable, so we `mut self` instead of `&mut self`.

// Based on https://github.com/jedisct1/rust-siphash/blob/146ba215aa787d676edcb0324082bc6e0608288e/src/sip.rs
// That code is Apache2/MIT dual-licensed

#[must_use]
#[derive(Clone)]
struct State {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
}

impl State {
    #[cold]
    const fn compress(mut self) -> Self {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
        self
    }
    #[cold]
    const fn c_rounds(mut self) -> Self {
        self = self.compress();
        self = self.compress();
        self
    }
    #[cold]
    const fn d_rounds(mut self) -> Self {
        self = self.compress();
        self = self.compress();
        self = self.compress();
        self = self.compress();
        self
    }
}

/// The state of a SipHash-2-4 hasher.
#[must_use]
#[derive(Clone)]
pub struct SipHash24 {
    length: u64,  // how many bytes we've processed
    state: State, // hash State
    tail: u64,    // unprocessed bytes le
    ntail: usize, // how many bytes in tail are valid
}

impl SipHash24 {
    #[cold]
    pub const fn new(key: u128) -> Self {
        let k0 = key as u64;
        let k1 = (key >> 64) as u64;
        SipHash24 {
            length: 0,
            state: State {
                v0: k0 ^ 0x736f6d6570736575,
                v1: k1 ^ 0x646f72616e646f6d,
                v2: k0 ^ 0x6c7967656e657261,
                v3: k1 ^ 0x7465646279746573,
            },
            tail: 0,
            ntail: 0,
        }
    }

    #[cold]
    pub const fn finish(self) -> u64 {
        let mut state = self.state;
        let b: u64 = ((self.length & 0xff) << 56) | self.tail;

        state.v3 ^= b;
        state = state.c_rounds();
        state.v0 ^= b;

        state.v2 ^= 0xff;
        state = state.d_rounds();

        state.v0 ^ state.v1 ^ state.v2 ^ state.v3
    }

    #[cold]
    pub const fn update_str(self, msg: &str) -> Self {
        self.update_bytes(msg.as_bytes())
    }

    #[cold]
    pub const fn update_bytes(mut self, msg: &[u8]) -> Self {
        self = self.update_usize(msg.len());
        self = self.update_raw(msg, 0, msg.len());
        self
    }

    #[cold]
    pub const fn update_usize(self, msg: usize) -> Self {
        self.update_u64(msg as u64)
    }

    #[cold]
    pub const fn update_u64(self, msg: u64) -> Self {
        self.update_raw(&msg.to_le_bytes(), 0, 8)
    }

    // Slicing isn't yet a const fn on stable Rust, so we take start and end arguments.
    #[cold]
    pub const fn update_raw(mut self, msg: &[u8], start: usize, end: usize) -> Self {
        // cmp::min isn't "const fn" since it invokes trait functions.
        #[cold]
        const fn min(a: usize, b: usize) -> usize {
            if a < b {
                a
            } else {
                b
            }
        }

        #[cold]
        const fn u8to64_le(buf: &[u8], start: usize, len: usize) -> u64 {
            let mut arr = [0; 8];
            let mut i = 0;
            while i < len {
                arr[i] = buf[start + i];
                i += 1;
            }
            u64::from_le_bytes(arr)
        }

        let length = end - start;
        self.length += length as u64;

        let mut needed = 0;

        if self.ntail != 0 {
            needed = 8 - self.ntail;
            self.tail |= u8to64_le(msg, start, min(length, needed)) << (8 * self.ntail);
            if length < needed {
                self.ntail += length;
                return self;
            } else {
                self.state.v3 ^= self.tail;
                self.state = self.state.c_rounds();
                self.state.v0 ^= self.tail;
                self.ntail = 0;
            }
        }

        // Buffered tail is now flushed, process new input.
        let len = length - needed;
        let left = len & 0x7;

        let mut i = needed;
        while i < len - left {
            let mi = u8to64_le(msg, i + start, 8);

            self.state.v3 ^= mi;
            self.state = self.state.c_rounds();
            self.state.v0 ^= mi;

            i += 8;
        }

        self.tail = u8to64_le(msg, i + start, left);
        self.ntail = left;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::hash::Hasher;

    proptest! {
        #[test]
        fn test_siphash(key in any::<u128>(), parts in any::<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>>()) {
            let mut expected_hasher = siphasher::sip::SipHasher24::new_with_keys(key as u64, (key >> 64) as u64);
            let mut actual_hasher = SipHash24::new(key);
            for (prefix, part, suffix) in parts.into_iter() {
                expected_hasher.write(&part[..]);
                let mut combined = Vec::new();
                combined.extend_from_slice(&prefix);
                combined.extend_from_slice(&part);
                combined.extend_from_slice(&suffix);
                actual_hasher = actual_hasher.update_raw(&combined[..], prefix.len(), prefix.len() + part.len());
            }
            assert_eq!(actual_hasher.finish(), expected_hasher.finish());
        }
    }
}
