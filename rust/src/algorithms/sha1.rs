//! A minimal implementation of SHA1 for rust.
//! Adapted from https://github.com/mitsuhiko/sha1-smol

// Basic operations for u32x4
use core::ops::{Add, BitAnd, BitOr, BitXor, Shl, Shr, Sub};

#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct u32x4(pub u32, pub u32, pub u32, pub u32);

impl Add for u32x4 {
    type Output = u32x4;

    fn add(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0.wrapping_add(rhs.0),
            self.1.wrapping_add(rhs.1),
            self.2.wrapping_add(rhs.2),
            self.3.wrapping_add(rhs.3),
        )
    }
}

impl Sub for u32x4 {
    type Output = u32x4;

    fn sub(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0.wrapping_sub(rhs.0),
            self.1.wrapping_sub(rhs.1),
            self.2.wrapping_sub(rhs.2),
            self.3.wrapping_sub(rhs.3),
        )
    }
}

impl BitAnd for u32x4 {
    type Output = u32x4;

    fn bitand(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0 & rhs.0,
            self.1 & rhs.1,
            self.2 & rhs.2,
            self.3 & rhs.3,
        )
    }
}

impl BitOr for u32x4 {
    type Output = u32x4;

    fn bitor(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0 | rhs.0,
            self.1 | rhs.1,
            self.2 | rhs.2,
            self.3 | rhs.3,
        )
    }
}

impl BitXor for u32x4 {
    type Output = u32x4;

    fn bitxor(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0 ^ rhs.0,
            self.1 ^ rhs.1,
            self.2 ^ rhs.2,
            self.3 ^ rhs.3,
        )
    }
}

impl Shl<usize> for u32x4 {
    type Output = u32x4;

    fn shl(self, amt: usize) -> u32x4 {
        u32x4(self.0 << amt, self.1 << amt, self.2 << amt, self.3 << amt)
    }
}

impl Shl<u32x4> for u32x4 {
    type Output = u32x4;

    fn shl(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0 << rhs.0,
            self.1 << rhs.1,
            self.2 << rhs.2,
            self.3 << rhs.3,
        )
    }
}

impl Shr<usize> for u32x4 {
    type Output = u32x4;

    fn shr(self, amt: usize) -> u32x4 {
        u32x4(self.0 >> amt, self.1 >> amt, self.2 >> amt, self.3 >> amt)
    }
}

impl Shr<u32x4> for u32x4 {
    type Output = u32x4;

    fn shr(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0 >> rhs.0,
            self.1 >> rhs.1,
            self.2 >> rhs.2,
            self.3 >> rhs.3,
        )
    }
}





















// Initial state
const INITIAL_STATE: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

// Chunk size for chunkifying padded message
const CHUNK_SIZE: usize = 64;

// Round key constants
const K0: u32 = 0x5A827999u32;
const K1: u32 = 0x6ED9EBA1u32;
const K2: u32 = 0x8F1BBCDCu32;
const K3: u32 = 0xCA62C1D6u32;

/// Not an intrinsic, but gets the first element of a u32x4.
#[inline]
fn sha1_first(w0: u32x4) -> u32 {
    w0.0
}

/// Not an intrinsic, but adds a word to the first element of a u32x4.
#[inline]
fn sha1_first_add(e: u32, w0: u32x4) -> u32x4 {
    let u32x4(a, b, c, d) = w0;
    u32x4(e.wrapping_add(a), b, c, d)
}

/// Emulates `llvm.x86.sha1msg1` intrinsic.
fn sha1msg1(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(_, _, w2, w3) = a;
    let u32x4(w4, w5, _, _) = b;
    a ^ u32x4(w2, w3, w4, w5)
}

/// Emulates `llvm.x86.sha1msg2` intrinsic.
fn sha1msg2(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(x0, x1, x2, x3) = a;
    let u32x4(_, w13, w14, w15) = b;

    let w16 = (x0 ^ w13).rotate_left(1);
    let w17 = (x1 ^ w14).rotate_left(1);
    let w18 = (x2 ^ w15).rotate_left(1);
    let w19 = (x3 ^ w16).rotate_left(1);

    u32x4(w16, w17, w18, w19)
}

/// Emulates `llvm.x86.sha1nexte` intrinsic.
#[inline]
fn sha1_first_half(abcd: u32x4, msg: u32x4) -> u32x4 {
    sha1_first_add(sha1_first(abcd).rotate_left(30), msg)
}

/// Emulates `llvm.x86.sha1rnds4` intrinsic.
/// Performs 4 rounds of the message block digest.
fn sha1_digest_round_x4(abcd: u32x4, work: u32x4, i: i8) -> u32x4 {
    const K0V: u32x4 = u32x4(K0, K0, K0, K0);
    const K1V: u32x4 = u32x4(K1, K1, K1, K1);
    const K2V: u32x4 = u32x4(K2, K2, K2, K2);
    const K3V: u32x4 = u32x4(K3, K3, K3, K3);

    match i {
        0 => sha1rnds4c(abcd, work + K0V),
        1 => sha1rnds4p(abcd, work + K1V),
        2 => sha1rnds4m(abcd, work + K2V),
        3 => sha1rnds4p(abcd, work + K3V),
        _ => u32x4(0u32, 0u32, 0u32, 0u32),
    }
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4c(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_202 {
        ($a:expr, $b:expr, $c:expr) => {
            ($c ^ ($a & ($b ^ $c)))
        };
    } // Choose, MD5F, SHA1C

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_202!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_202!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_202!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_202!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4p(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_150 {
        ($a:expr, $b:expr, $c:expr) => {
            ($a ^ $b ^ $c)
        };
    } // Parity, XOR, MD5H, SHA1P

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_150!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_150!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_150!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_150!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4m(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_232 {
        ($a:expr, $b:expr, $c:expr) => {
            ($a & $b) ^ ($a & $c) ^ ($b & $c)
        };
    } // Majority, SHA1M

    e = e
        .wrapping_add(a.rotate_left(5))
        .wrapping_add(bool3ary_232!(b, c, d))
        .wrapping_add(t);
    b = b.rotate_left(30);

    d = d
        .wrapping_add(e.rotate_left(5))
        .wrapping_add(bool3ary_232!(a, b, c))
        .wrapping_add(u);
    a = a.rotate_left(30);

    c = c
        .wrapping_add(d.rotate_left(5))
        .wrapping_add(bool3ary_232!(e, a, b))
        .wrapping_add(v);
    e = e.rotate_left(30);

    b = b
        .wrapping_add(c.rotate_left(5))
        .wrapping_add(bool3ary_232!(d, e, a))
        .wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

fn process(state: &mut [u32; 5], block: &[u8; 64]) {
  let mut words = [0u32; 16];
  let mut index = 0;
  while index < 16 {
      let off = index * 4;
      words[index] = (block[off + 3] as u32)
          | ((block[off + 2] as u32) << 8)
          | ((block[off + 1] as u32) << 16)
          | ((block[off] as u32) << 24);
      index += 1;
  }

  macro_rules! schedule {
      ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
          sha1msg2(sha1msg1($v0, $v1) ^ $v2, $v3)
      };
  }

  macro_rules! rounds4 {
      ($h0:ident, $h1:ident, $wk:expr, $i:expr) => {
          sha1_digest_round_x4($h0, sha1_first_half($h1, $wk), $i)
      };
  }

  // Rounds 0..20
  let mut h0 = u32x4(state[0], state[1], state[2], state[3]);
  let mut w0 = u32x4(words[0], words[1], words[2], words[3]);
  let mut h1 = sha1_digest_round_x4(h0, sha1_first_add(state[4], w0), 0);
  let mut w1 = u32x4(words[4], words[5], words[6], words[7]);
  h0 = rounds4!(h1, h0, w1, 0);
  let mut w2 = u32x4(words[8], words[9], words[10], words[11]);
  h1 = rounds4!(h0, h1, w2, 0);
  let mut w3 = u32x4(words[12], words[13], words[14], words[15]);
  h0 = rounds4!(h1, h0, w3, 0);
  let mut w4 = schedule!(w0, w1, w2, w3);
  h1 = rounds4!(h0, h1, w4, 0);

  // Rounds 20..40
  w0 = schedule!(w1, w2, w3, w4);
  h0 = rounds4!(h1, h0, w0, 1);
  w1 = schedule!(w2, w3, w4, w0);
  h1 = rounds4!(h0, h1, w1, 1);
  w2 = schedule!(w3, w4, w0, w1);
  h0 = rounds4!(h1, h0, w2, 1);
  w3 = schedule!(w4, w0, w1, w2);
  h1 = rounds4!(h0, h1, w3, 1);
  w4 = schedule!(w0, w1, w2, w3);
  h0 = rounds4!(h1, h0, w4, 1);

  // Rounds 40..60
  w0 = schedule!(w1, w2, w3, w4);
  h1 = rounds4!(h0, h1, w0, 2);
  w1 = schedule!(w2, w3, w4, w0);
  h0 = rounds4!(h1, h0, w1, 2);
  w2 = schedule!(w3, w4, w0, w1);
  h1 = rounds4!(h0, h1, w2, 2);
  w3 = schedule!(w4, w0, w1, w2);
  h0 = rounds4!(h1, h0, w3, 2);
  w4 = schedule!(w0, w1, w2, w3);
  h1 = rounds4!(h0, h1, w4, 2);

  // Rounds 60..80
  w0 = schedule!(w1, w2, w3, w4);
  h0 = rounds4!(h1, h0, w0, 3);
  w1 = schedule!(w2, w3, w4, w0);
  h1 = rounds4!(h0, h1, w1, 3);
  w2 = schedule!(w3, w4, w0, w1);
  h0 = rounds4!(h1, h0, w2, 3);
  w3 = schedule!(w4, w0, w1, w2);
  h1 = rounds4!(h0, h1, w3, 3);
  w4 = schedule!(w0, w1, w2, w3);
  h0 = rounds4!(h1, h0, w4, 3);

  let e = sha1_first(h1).rotate_left(30);
  let u32x4(a, b, c, d) = h0;

  state[0] = state[0].wrapping_add(a);
  state[1] = state[1].wrapping_add(b);
  state[2] = state[2].wrapping_add(c);
  state[3] = state[3].wrapping_add(d);
  state[4] = state[4].wrapping_add(e);
}

fn chunkify(msg: &[u8]) -> Vec<[u8; CHUNK_SIZE]> {
  // Assumes msg length is a multiple of CHUNK_SIZE
  let mut chunks = Vec::new();
  let mut msg_start = 0;
  while msg_start < msg.len() {
      // Init array with zeros
      let mut chunk = [0u8; CHUNK_SIZE]; 
      let msg_end = msg_start + CHUNK_SIZE;
      let msg_slice = &msg[msg_start..msg_end];
      // Copy the slice into the chunk array
      chunk[0..CHUNK_SIZE].copy_from_slice(msg_slice);
      chunks.push(chunk);
      msg_start += CHUNK_SIZE;
  }
  chunks
}

fn pad_message(msg: &[u8]) -> Vec<u8> {
  // Step 1: Compute message length in bits
  let msg_len_bits = (msg.len() as u64) * 8;

  // Step 2: Append the padding bit (0x80)
  let mut padded_msg = Vec::with_capacity(msg.len() + 1 + 64); // Allocate a buffer
  padded_msg.extend_from_slice(msg); // Copy original message
  padded_msg.push(0x80); // Append the '1' bit and seven '0' bits (0x80 in hex)

  // Step 3: Calculate zero-padding length
  let zero_padding_length = (56 - ((padded_msg.len()) % 64)) % 64;

  // Step 4: Append zero padding
  let mut i = 0;
  while i < zero_padding_length {
      padded_msg.push(0x00); // Append zero byte
      i += 1;
  }

  // Step 5: Append message length as 64-bit big-endian integer
  let mut length_bytes = [0u8; 8];
  length_bytes[0] = ((msg_len_bits >> 56) & 0xFF) as u8;
  length_bytes[1] = ((msg_len_bits >> 48) & 0xFF) as u8;
  length_bytes[2] = ((msg_len_bits >> 40) & 0xFF) as u8;
  length_bytes[3] = ((msg_len_bits >> 32) & 0xFF) as u8;
  length_bytes[4] = ((msg_len_bits >> 24) & 0xFF) as u8;
  length_bytes[5] = ((msg_len_bits >> 16) & 0xFF) as u8;
  length_bytes[6] = ((msg_len_bits >>  8) & 0xFF) as u8;
  length_bytes[7] = ((msg_len_bits >>  0) & 0xFF) as u8;
  padded_msg.extend_from_slice(&length_bytes);

  padded_msg
}

fn hash_to_vec(final_hash: [u32; 5]) -> Vec<u8> {
  let mut result_bytes = Vec::new();
  let mut index = 0;
  while index < final_hash.len() {
      let word = final_hash[index];
      result_bytes.push(((word >> 24) & 0xFF) as u8);
      result_bytes.push(((word >> 16) & 0xFF) as u8);
      result_bytes.push(((word >> 8) & 0xFF) as u8);
      result_bytes.push(((word >> 0) & 0xFF) as u8);
      index += 1;
  }
  result_bytes
}

fn hash(message: &[u8]) -> Vec<u8> {
  let padded_msg = pad_message(message);
  let chunks = chunkify(&padded_msg);
  let mut state = INITIAL_STATE;
  let mut chunk_index = 0;
  while chunk_index < chunks.len() {
      let chunk = &chunks[chunk_index];
      process(&mut state, chunk);
      chunk_index += 1;
  }
  hash_to_vec(state)
}
