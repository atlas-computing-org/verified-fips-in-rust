import VerifiedFipsCryptography.RustTranslations.FipsImplementations
import VerifiedFipsCryptography.Specs.SHA1
import VerifiedFipsCryptography.Equivalence.Lemmas

import Std
import Batteries
import Init.Data.ByteArray
import VerifiedFipsCryptography.Util.HexString

import Aeneas
-- open Aeneas.Std

namespace translate

def add_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ + a₂, b₁ + b₂, c₁ + c₂, d₁ + d₂)

def sub_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ - a₂, b₁ - b₂, c₁ - c₂, d₁ - d₂)

def bitand_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ &&& a₂, b₁ &&& b₂, c₁ &&& c₂, d₁ &&& d₂)

def bitor_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ ||| a₂, b₁ ||| b₂, c₁ ||| c₂, d₁ ||| d₂)

def bitxor_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ ^^^ a₂, b₁ ^^^ b₂, c₁ ^^^ c₂, d₁ ^^^ d₂)

def shl_u32x4_usize (self : u32x4) (amt : UInt32) : u32x4 :=
  let (a, b, c, d) := self
  (a <<< amt, b <<< amt, c <<< amt, d <<< amt)

def shl_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ <<< a₂, b₁ <<< b₂, c₁ <<< c₂, d₁ <<< d₂)

def shr_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ >>> a₂, b₁ >>> b₂, c₁ >>> c₂, d₁ >>> d₂)

def INITIAL_STATE : Array UInt32 :=
  #[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

def CHUNK_SIZE : Nat := 64

def K0 : UInt32 := 0x5A827999
def K1 : UInt32 := 0x6ED9EBA1
def K2 : UInt32 := 0x8F1BBCDC
def K3 : UInt32 := 0xCA62C1D6

def sha1_first (w0 : u32x4) : UInt32 :=
  let (x, _, _, _) := w0
  x

def sha1_first_add (e : UInt32) (w0 : u32x4) : u32x4 :=
  let (a, b, c, d) := w0
  (e + a, b, c, d)

def sha1msg1 (a b : u32x4) : u32x4 :=
  let (_, _, w2, w3) := a
  let (w4, w5, _, _) := b
  bitxor_u32x4 a (w2, w3, w4, w5)

def sha1msg2 (a b : u32x4) : u32x4 :=
  let (x0, x1, x2, x3) := a
  let (_, w13, w14, w15) := b
  let w16 := (x0 ^^^ w13).rotate_left 1
  let w17 := (x1 ^^^ w14).rotate_left 1
  let w18 := (x2 ^^^ w15).rotate_left 1
  let w19 := (x3 ^^^ w16).rotate_left 1
  (w16, w17, w18, w19)

def sha1_first_half (abcd msg : u32x4) : u32x4 :=
  sha1_first_add ((sha1_first abcd).rotate_left 30) msg

def sha1rnds4c (abcd msg : u32x4) : u32x4 :=
  let (a, b, c, d) := abcd
  let (t, u, v, w) := msg
  -- Complex SHA1 round function implementation
  let e := (a.rotate_left 5) + (d ^^^ (b &&& (c ^^^ d))) + t
  let b₁ := b.rotate_left 30
  let d₁ := d + (e.rotate_left 5) + (c ^^^ (a &&& (b₁ ^^^ c))) + u
  let a₁ := a.rotate_left 30
  let c₁ := c + (d₁.rotate_left 5) + (b₁ ^^^ (e &&& (a₁ ^^^ b₁))) + v
  let e₁ := e.rotate_left 30
  let b₂ := b₁ + (c₁.rotate_left 5) + (a₁ ^^^ (d₁ &&& (e₁ ^^^ a₁))) + w
  let d₂ := d₁.rotate_left 30
  (b₂, c₁, d₂, e₁)

def sha1rnds4p (abcd msg : u32x4) : u32x4 :=
  let (a, b, c, d) := abcd
  let (t, u, v, w) := msg

  let e := (a.rotate_left 5) + ((b ^^^ c) ^^^ d) + t
  let b₁ := b.rotate_left 30
  let d₁ := d + (e.rotate_left 5) + ((a ^^^ b₁) ^^^ c) + u
  let a₁ := a.rotate_left 30
  let c₁ := c + (d₁.rotate_left 5) + ((e ^^^ a₁) ^^^ b₁) + v
  let e₁ := e.rotate_left 30
  let b₂ := b₁ + (c₁.rotate_left 5) + ((d₁ ^^^ e₁) ^^^ a₁) + w
  let d₂ := d₁.rotate_left 30

  (b₂, c₁, d₂, e₁)

def sha1rnds4m (abcd msg : u32x4) : u32x4 :=
  let (a, b, c, d) := abcd
  let (t, u, v, w) := msg

  let e := (a.rotate_left 5) +
    (((b &&& c) ^^^ (b &&& d)) ^^^ (c &&& d)) + t
  let b₁ := b.rotate_left 30
  let d₁ := d + (e.rotate_left 5) +
    (((a &&& b₁) ^^^ (a &&& c)) ^^^ (b₁ &&& c)) + u
  let a₁ := a.rotate_left 30
  let c₁ := c + (d₁.rotate_left 5) +
    (((e &&& a₁) ^^^ (e &&& b₁)) ^^^ (a₁ &&& b₁)) + v
  let e₁ := e.rotate_left 30
  let b₂ := b₁ + (c₁.rotate_left 5) +
    (((d₁ &&& e₁) ^^^ (d₁ &&& a₁)) ^^^ (e₁ &&& a₁)) + w
  let d₂ := d₁.rotate_left 30

 (b₂, c₁, d₂, e₁)

def sha1_digest_round_x4 (abcd : u32x4) (work : u32x4) (i : UInt8) : u32x4 :=
  let k := match i with
    | 0 => (K0, K0, K0, K0)
    | 1 => (K1, K1, K1, K1)
    | 2 => (K2, K2, K2, K2)
    | 3 => (K3, K3, K3, K3)
    | _ => (0, 0, 0, 0)
  match i with
  | 0 => sha1rnds4c abcd (add_u32x4 work k)
  | 1 => sha1rnds4p abcd (add_u32x4 work k)
  | 2 => sha1rnds4m abcd (add_u32x4 work k)
  | 3 => sha1rnds4p abcd (add_u32x4 work k)
  | _ => (0, 0, 0, 0)

def process_loop_loop
  (block : Array UInt8) (block_size : block.size = 64)
  (words : Array UInt32) (words_size : words.size = 16)
  (index : Nat) : Array UInt32 :=
  if h : index < 16 then
    let off := index * 4
    let i := off + 3
    let i1 := block[i]
    let i2 := i1.toUInt32
    let i3 := off + 2
    let i4 := block[i3]
    let i5 := i4.toUInt32
    let i6 := i5 <<< 8
    let i7 := off + 1
    let i8 := block[i7]
    let i9 := i8.toUInt32
    let i10 := i9 <<< 16
    let i11 := block[off]
    let i12 := i11.toUInt32
    let i13 := i12 <<< 24
    let index1 := index + 1
    let words1 := words.set index (((i2 ||| i6) ||| i10) ||| i13)
    process_loop_loop block block_size words1 sorry index1
  else
    words

lemma process_loop_loop_size : (process_loop_loop block block_size words words_size index).size = 16 := by
  have h : index ≤ 16 := sorry
  induction h using Nat.decreasingInduction generalizing words with
  | self => simpa [process_loop_loop]
  | of_succ index hi ih =>
    unfold process_loop_loop
    simp [hi, ih]

def process_loop
  (block : Array UInt8) (hblock : block.size = 64) : Array UInt32 :=
  let words := ⟨List.replicate 16 0⟩
  process_loop_loop block hblock words sorry 0

lemma process_loop_size : (process_loop block block_size).size = 16 := by

  sorry

def process_rounds_0
  (h0 : u32x4) (state : Array UInt32) (hstate : state.size = 5)
  (words : Array UInt32) (hwords : words.size = 16) :
  u32x4 × u32x4 × u32x4 × u32x4 × u32x4 × u32x4 :=
  let w0_3 := (words[0], words[1], words[2], words[3])
  let w4_7 := (words[4], words[5], words[6], words[7])
  let w8_11 := (words[8], words[9], words[10], words[11])
  let w12_15 := (words[12], words[13], words[14], words[15])

  let ux := sha1_first_add state[4] w0_3
  let h1 := sha1_digest_round_x4 h0 ux 0

  let ux1 := sha1_first_half h0 w4_7
  let h01 := sha1_digest_round_x4 h1 ux1 0

  let ux2 := sha1_first_half h1 w8_11
  let h11 := sha1_digest_round_x4 h01 ux2 0

  let ux3 := sha1_first_half h01 w12_15
  let h02 := sha1_digest_round_x4 h11 ux3 0

  let ux4 := sha1msg1 w0_3 w4_7
  let ux5 := bitxor_u32x4 ux4 w8_11
  let w4 := sha1msg2 ux5 w12_15

  let ux6 := sha1_first_half h11 w4
  let h12 := sha1_digest_round_x4 h02 ux6 0

  (h02, h12, w4_7, w8_11, w12_15, w4)

def process_rounds_i (h0 h1 : u32x4) (w1 w2 w3 w4 : u32x4) (i : UInt8) :
  u32x4 × u32x4 × u32x4 × u32x4 × u32x4 × u32x4 :=
  -- First round
  let w0 := sha1msg2 (bitxor_u32x4 (sha1msg1 w1 w2) w3) w4
  let ux := sha1_first_half h0 w0
  let h01 := sha1_digest_round_x4 h1 ux i

  -- Second round
  let w11 := sha1msg2 (bitxor_u32x4 (sha1msg1 w2 w3) w4) w0
  let ux1 := sha1_first_half h1 w11
  let h11 := sha1_digest_round_x4 h01 ux1 i

  -- Third round
  let w21 := sha1msg2 (bitxor_u32x4 (sha1msg1 w3 w4) w0) w11
  let ux2 := sha1_first_half h01 w21
  let h02 := sha1_digest_round_x4 h11 ux2 i

  -- Fourth round
  let w31 := sha1msg2 (bitxor_u32x4 (sha1msg1 w4 w0) w11) w21
  let ux3 := sha1_first_half h11 w31
  let h12 := sha1_digest_round_x4 h02 ux3 i

  -- Fifth round
  let w41 := sha1msg2 (bitxor_u32x4 (sha1msg1 w0 w11) w21) w31
  let ux4 := sha1_first_half h02 w41
  let h03 := sha1_digest_round_x4 h12 ux4 i

  (h03, h12, w11, w21, w31, w41)

def process (state : Array UInt32) (state_size : state.size = 5)
  (block : Array UInt8) (block_size : block.size = 64) : Vector UInt32 5 :=

  -- Convert block bytes to words
  let words := process_loop block block_size
  have words_size : words.size = 16 := sorry

  -- Initial state
  let a := state[0]
  let b := state[1]
  let c := state[2]
  let d := state[3]
  let e := state[4]
  let h0 := (a, b, c, d) -- Initial u32x4

  let (h02, h12, w1, w2, w3, w4) := process_rounds_0 h0 state state_size words words_size
  let (h03, h13, w11, w21, w31, w41) := process_rounds_i h02 h12 w1 w2 w3 w4 1
  let (h04, h14, w12, w22, w32, w42) := process_rounds_i h03 h13 w11 w21 w31 w41 2
  let (h05, h15, _, _, _, _) := process_rounds_i h04 h14 w12 w22 w32 w42 3

  -- Final state update
  let e' := (sha1_first h15).rotate_left 30
  let (a', b', c', d') := h05
  #v[
    state[0] + a',
    state[1] + b',
    state[2] + c',
    state[3] + d',
    state[4] + e'
  ]

def chunkify_loop
  (msg : Array UInt8)
  (chunks : Array (Array UInt8)) (hchunks : ∀ chunk ∈ chunks, chunk.size = 64)
  (msg_start : Nat) : Array (Array UInt8) :=
  let i := msg.size
  if h : msg_start < i then
    let msg_end := msg_start + 64
    let msg_slice := msg[msg_start:msg_end].toArray
    let chunks1 := chunks.push msg_slice
    let msg_start1 := msg_start + 64
    chunkify_loop msg chunks1 sorry msg_start1
  else
    chunks
  termination_by (msg.size - msg_start)

def chunkify (msg : Array UInt8) : Array (Array UInt8) :=
  chunkify_loop msg #[] sorry 0

-- There's a bounds problem here. The Rust implementation needs to be more precise on how large the input message is.
-- If the message is large enough, then pushing back more elements to it will cause a capacity overflow error.
-- The spec needs to take this into account; for now I just sorry anything that requires this.
def pad_message_loop
  (padded_msg : Array UInt8) (zero_padding_length : Nat)
  (i : Nat) : Array UInt8 :=
  if h : i < zero_padding_length then
    let padded_msg1 := padded_msg.push 0
    let i1 := i + 1
    pad_message_loop padded_msg1 zero_padding_length i1
  else
    padded_msg

def pad_message (msg : Array UInt8) : Array UInt8 :=
  let msg_len := msg.size
  let msg_len_bits := (msg_len.toUInt64) * 8
  let padded_msg := msg.push 128
  let remainder := padded_msg.size % 64
  let zero_padding_length := (56 - remainder) % 64
  let padded_msg1 := pad_message_loop padded_msg zero_padding_length 0
  let length_bytes := #[
    ((msg_len_bits >>> 56) &&& 255).toUInt8,
    ((msg_len_bits >>> 48) &&& 255).toUInt8,
    ((msg_len_bits >>> 40) &&& 255).toUInt8,
    ((msg_len_bits >>> 32) &&& 255).toUInt8,
    ((msg_len_bits >>> 24) &&& 255).toUInt8,
    ((msg_len_bits >>> 16) &&& 255).toUInt8,
    ((msg_len_bits >>> 8) &&& 255).toUInt8,
    ((msg_len_bits >>> 0) &&& 255).toUInt8
  ]
  padded_msg1 ++ length_bytes

def hash_to_vec_loop
  (final_hash : Array UInt32) (final_hash_size : final_hash.size = 5)
  (result_bytes : Array UInt8)
  (index : Nat)
  (result_bytes_bound : result_bytes.size ≤ 4 * index) : Array UInt8 :=
  if h : index < final_hash.size then
    let word := final_hash[index]
    let bytes := #[
      ((word >>> 24) &&& 255).toUInt8,
      ((word >>> 16) &&& 255).toUInt8,
      ((word >>> 8) &&& 255).toUInt8,
      ((word >>> 0) &&& 255).toUInt8
    ]
    let result_bytes1 := result_bytes.append bytes
    let index1 := index + 1
    hash_to_vec_loop final_hash final_hash_size result_bytes1 index1 sorry
  else
    result_bytes

def hash_to_vec (final_hash : Array UInt32) (h : final_hash.size = 5) : Array UInt8 :=
  hash_to_vec_loop final_hash h #[] 0 (by decide)

def hash_loop
  (chunks : Array (Array UInt8)) (state : Array UInt32) (state_size : state.size = 5)
  (chunk_index : Nat) : Array UInt32 :=
  if h : chunk_index < chunks.size then
    let chunk := chunks[chunk_index]
    let ⟨state1, state1_size⟩ := process state state_size chunk sorry
    let chunk_index1 := chunk_index + 1
    hash_loop chunks state1 state1_size chunk_index1
  else
    state

lemma hash_loop_size : (hash_loop chunks state state_size 0).size = 5 := by sorry

def hash (message : Array UInt8) : Array UInt8 :=
  let padded_msg := pad_message message
  let chunks := chunkify padded_msg
  let state := hash_loop chunks INITIAL_STATE sorry 0
  hash_to_vec state hash_loop_size

end translate

namespace lean

def hash_to_vec_aux (final_hash : Array UInt32) (result_bytes : Array UInt8) : Array UInt8 :=
  let result_bytes := final_hash.foldl (init := result_bytes) fun acc (word : UInt32) =>
    let bytes := #[
      ((word >>> 24) &&& 255).toUInt8,
      ((word >>> 16) &&& 255).toUInt8,
      ((word >>> 8) &&& 255).toUInt8,
      ((word >>> 0) &&& 255).toUInt8
    ]
    acc ++ bytes
  result_bytes

end lean

namespace equivalence
open Aeneas.Std fips_implementations.algorithms alloc.vec core clone num

lemma add_u32x4_rust_to_translate
  (self_t rhs_t : u32x4)
  (self_r rhs_r : sha1.u32x4)
  (hself : self_r = self_t.toU32x4) (hrhs : rhs_r = rhs_t.toU32x4) :
  let res_t := translate.add_u32x4 self_t rhs_t
  let res_r := sha1.Addfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.add self_r rhs_r
  res_r = .ok res_t.toU32x4 :=
by
  sorry

@[simp]
lemma add_u32x4_rust_to_translate' :
  let res_t := translate.add_u32x4 (s1_t, s2_t, s3_t, s4_t) (r1_t, r2_t, r3_t, r4_t)
  let res_r := sha1.Addfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.add
    (s1_t.toU32, s2_t.toU32, s3_t.toU32, s4_t.toU32) (r1_t.toU32, r2_t.toU32, r3_t.toU32, r4_t.toU32)
  res_r = .ok res_t.toU32x4 := by
  rw [add_u32x4_rust_to_translate] <;> simp [u32x4.toU32x4]

lemma bitxor_u32x4_rust_to_translate
  (self_t rhs_t : u32x4)
  (self_r rhs_r : sha1.u32x4)
  (hself : self_r = self_t.toU32x4) (hrhs : rhs_r = rhs_t.toU32x4) :
  let res_t := translate.bitxor_u32x4 self_t rhs_t
  let res_r := sha1.BitXorfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.bitxor self_r rhs_r
  res_r = .ok res_t.toU32x4 := by sorry

@[simp]
lemma bitxor_u32x4_rust_to_translate' :
  let res_t := translate.bitxor_u32x4 s_t r_t
  let res_r := sha1.BitXorfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.bitxor
    s_t.toU32x4 r_t.toU32x4
  res_r = .ok res_t.toU32x4 := by
  rw [bitxor_u32x4_rust_to_translate] <;> simp [u32x4.toU32x4]

lemma sha1_first_rust_to_translate
  (w0_t : u32x4) (w0_r : sha1.u32x4) (hw0 : w0_r = w0_t.toU32x4) :
  let res_t := translate.sha1_first w0_t
  let res_r := sha1.sha1_first w0_r
  res_r = .ok res_t.toU32 :=
by
  unfold translate.sha1_first sha1.sha1_first
  rw [hw0]
  clear hw0 w0_r
  let (w0_t_0, w0_t_1, w0_t_2, w0_t_3) := w0_t
  dsimp [u32x4.toU32x4]

lemma sha1_first_add_rust_to_translate
  (e_t : UInt32) (e_r : U32) (he : e_r = e_t.toU32)
  (w0_t : u32x4)
  (w0_r : sha1.u32x4) (hw0 : w0_r = w0_t.toU32x4) :
  let res_t := translate.sha1_first_add e_t w0_t
  let res_r := sha1.sha1_first_add e_r w0_r
  res_r = .ok res_t.toU32x4 :=
by
  unfold translate.sha1_first_add sha1.sha1_first_add
  rw [hw0, he]
  clear hw0 w0_r he e_r
  let (w0_t_0, w0_t_1, w0_t_2, w0_t_3) := w0_t
  simp [u32x4.toU32x4]

@[simp]
lemma sha1_first_add_rust_to_translate' :
  let res_t := translate.sha1_first_add e_t w0_t
  let res_r := sha1.sha1_first_add e_t.toU32 w0_t.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  rw [sha1_first_add_rust_to_translate] <;> simp [u32x4.toU32x4]

lemma sha1msg1_rust_to_translate
  (a_t b_t : u32x4)
  (a_r b_r : sha1.u32x4)
  (ha : a_r = a_t.toU32x4) (hb : b_r = b_t.toU32x4) :
  let res_t := translate.sha1msg1 a_t b_t
  let res_r := sha1.sha1msg1 a_r b_r
  res_r = .ok res_t.toU32x4 :=
by
  unfold translate.sha1msg1 sha1.sha1msg1
  rw [ha, hb]
  clear ha a_r hb b_r
  let (a_t_0, a_t_1, a_t_2, a_t_3) := a_t
  let (b_t_0, b_t_1, b_t_2, b_t_3) := b_t
  simp [u32x4.toU32x4, sha1.BitXorfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.bitxor, translate.bitxor_u32x4]

@[simp]
lemma sha1msg1_rust_to_translate' :
  let res_t := translate.sha1msg1 a_t b_t
  let res_r := sha1.sha1msg1 a_t.toU32x4 b_t.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  rw [sha1msg1_rust_to_translate] <;> simp [u32x4.toU32x4]

lemma sha1msg2_rust_to_translate
  (a_t b_t : u32x4)
  (a_r b_r : sha1.u32x4)
  (ha : a_r = a_t.toU32x4) (hb : b_r = b_t.toU32x4) :
  let res_t := translate.sha1msg2 a_t b_t
  let res_r := sha1.sha1msg2 a_r b_r
  res_r = .ok res_t.toU32x4 :=
by
  unfold translate.sha1msg2 sha1.sha1msg2
  rw [ha, hb]
  clear ha a_r hb b_r
  let (a_t_0, a_t_1, a_t_2, a_t_3) := a_t
  let (b_t_0, b_t_1, b_t_2, b_t_3) := b_t
  rw [U32.ofUInt32_eq 1 1]
  simp [u32x4.toU32x4, sha1.BitXorfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.bitxor, translate.bitxor_u32x4]

@[simp]
lemma sha1msg2_rust_to_translate' :
  let res_t := translate.sha1msg2 a_t b_t
  let res_r := sha1.sha1msg2 a_t.toU32x4 b_t.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  rw [sha1msg2_rust_to_translate] <;> simp [u32x4.toU32x4]

lemma sha1_first_half_rust_to_translate
 (abcd_t msg_t : u32x4)
 (abcd_r msg_r : sha1.u32x4)
 (habcd : abcd_r = abcd_t.toU32x4) (hmsg : msg_r = msg_t.toU32x4) :
 let res_t := translate.sha1_first_half abcd_t msg_t
 let res_r := sha1.sha1_first_half abcd_r msg_r
 res_r = .ok res_t.toU32x4 := by sorry

lemma sha1_digest_round_x4_rust_to_translate
 (abcd_t work_t : u32x4)
 (abcd_r work_r : sha1.u32x4)
 (habcd : abcd_r = abcd_t.toU32x4) (hwork : work_r = work_t.toU32x4)
 (i_t : UInt8) (i_r : U8) (hi : i_r = i_t.toU8) :
 let res_t := translate.sha1_digest_round_x4 abcd_t work_t i_t
 let res_r := sha1.sha1_digest_round_x4 abcd_r work_r i_r
 res_r = .ok res_t.toU32x4 := by sorry

lemma sha1rnds4p_rust_to_translate
  (abcd_t : u32x4) (abcd_r : sha1.u32x4) (habcd : abcd_r = abcd_t.toU32x4)
  (msg_t : u32x4) (msg_r : sha1.u32x4) (hmsg : msg_r = msg_t.toU32x4) :
  let res_t := translate.sha1rnds4p abcd_t msg_t
  let res_r := sha1.sha1rnds4p abcd_r msg_r
  res_r = .ok res_t.toU32x4 :=
by
  unfold translate.sha1rnds4p sha1.sha1rnds4p
  rw [habcd, hmsg]
  clear habcd abcd_r hmsg msg_r
  let (a_t, b_t, c_t, d_t) := abcd_t
  let (msg_t_0, msg_t_1, msg_t_2, msg_t_3) := msg_t
  rw [U32.ofUInt32_eq 5 5, U32.ofUInt32_eq 0 0, U32.ofUInt32_eq 30 30]
  dsimp [u32x4.toU32x4]
  simp

lemma sha1rnds4m_rust_to_translate
  (abcd_t : u32x4) (abcd_r : sha1.u32x4) (habcd : abcd_r = abcd_t.toU32x4)
  (msg_t : u32x4) (msg_r : sha1.u32x4) (hmsg : msg_r = msg_t.toU32x4) :
  let res_t := translate.sha1rnds4m abcd_t msg_t
  let res_r := sha1.sha1rnds4m abcd_r msg_r
  res_r = .ok res_t.toU32x4 :=
by
  unfold translate.sha1rnds4m sha1.sha1rnds4m
  rw [habcd, hmsg]
  clear habcd abcd_r hmsg msg_r
  let (a_t, b_t, c_t, d_t) := abcd_t
  let (msg_t_0, msg_t_1, msg_t_2, msg_t_3) := msg_t
  rw [U32.ofUInt32_eq 5 5, U32.ofUInt32_eq 0 0, U32.ofUInt32_eq 30 30]
  dsimp [u32x4.toU32x4]
  simp

@[simp]
lemma sha1_first_half_rust_to_translate' :
  let res_t := translate.sha1_first_half abcd_t msg_t
  let res_r := sha1.sha1_first_half abcd_t.toU32x4 msg_t.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
 rw [sha1_first_half_rust_to_translate] <;> simp [u32x4.toU32x4]

@[simp]
lemma sha1_digest_round_x4_rust_to_translate' :
  let res_t := translate.sha1_digest_round_x4 abcd_t work_t i_t
  let res_r := sha1.sha1_digest_round_x4 abcd_t.toU32x4 work_t.toU32x4 i_t.toU8
  res_r = .ok res_t.toU32x4 :=
by
 rw [sha1_digest_round_x4_rust_to_translate] <;> simp [u32x4.toU32x4]

@[simp]
lemma sha1rnds4p_rust_to_translate' :
  let res_t := translate.sha1rnds4p abcd_t msg_t
  let res_r := sha1.sha1rnds4p abcd_t.toU32x4 msg_t.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
 rw [sha1rnds4p_rust_to_translate] <;> simp [u32x4.toU32x4]

@[simp]
lemma sha1rnds4m_rust_to_translate' :
  let res_t := translate.sha1rnds4m abcd_t msg_t
  let res_r := sha1.sha1rnds4m abcd_t.toU32x4 msg_t.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
 rw [sha1rnds4m_rust_to_translate] <;> simp [u32x4.toU32x4]

lemma process_rounds_0_rust_to_translate
  (h0_t : u32x4) (h0_r : sha1.u32x4) (h_h0 : h0_r = h0_t.toU32x4)
  (state_t : Array UInt32) (hstate_t : state_t.size = 5)
  (state_r : Array U32 5#usize) (hstate_r : state_r = state_t.toArrayU32 sorry)
  (words_t : Array UInt32) (hwords_t : words_t.size = 16)
  (words_r : Array U32 16#usize) (hwords_r : words_r = words_t.toArrayU32 sorry) :
  let res_t := translate.process_rounds_0 h0_t state_t hstate_t words_t hwords_t
  let res_r := sha1.process_rounds_0 h0_r state_r words_r
  res_r =
  .ok (
    let (res_0_t, res_1_t, res_2_t, res_3_t, res_4_t, res_5_t) := res_t
    (res_0_t.toU32x4, res_1_t.toU32x4, res_2_t.toU32x4, res_3_t.toU32x4, res_4_t.toU32x4, res_5_t.toU32x4)
  ) :=
by
  unfold translate.process_rounds_0 sha1.process_rounds_0
  rw [h_h0, hstate_r, hwords_r]
  simp_rw [
    Usize.ofNat_eq 0 0, Usize.ofNat_eq 1 1, Usize.ofNat_eq 2 2, Usize.ofNat_eq 3 3,
    Usize.ofNat_eq 4 4, Usize.ofNat_eq 5 5, Usize.ofNat_eq 6 6, Usize.ofNat_eq 7 7,
    Usize.ofNat_eq 8 8, Usize.ofNat_eq 9 9, Usize.ofNat_eq 10 10, Usize.ofNat_eq 11 11,
    Usize.ofNat_eq 12 12, Usize.ofNat_eq 13 13, Usize.ofNat_eq 14 14, Usize.ofNat_eq 15 15
  ]
  rw [U8.ofUInt8_eq 0 0]
  simp [Array.toArrayU32.index_usize_spec _ _ _ sorry, u32x4.toU32x4_unapply]

lemma process_rounds_0_rust_to_translate' :
  let res_t := translate.process_rounds_0 h0_t state_t hstate_t words_t hwords_t
  let res_r := sha1.process_rounds_0 h0_t.toU32x4 (state_t.toArrayU32 (by simp [hstate_t])) (words_t.toArrayU32 sorry)
  res_r =
  .ok (
    let (res_0_t, res_1_t, res_2_t, res_3_t, res_4_t, res_5_t) := res_t
    (res_0_t.toU32x4, res_1_t.toU32x4, res_2_t.toU32x4, res_3_t.toU32x4, res_4_t.toU32x4, res_5_t.toU32x4)
  ) :=
by
  rw [process_rounds_0_rust_to_translate] <;> simp

lemma process_rounds_i_rust_to_translate
  (h0_t h1_t w1_t w2_t w3_t w4_t : u32x4)
  (h0_r h1_r w1_r w2_r w3_r w4_r : sha1.u32x4)
  (h0 : h0_r = h0_t.toU32x4) (h1 : h1_r = h1_t.toU32x4)
  (w1 : w1_r = w1_t.toU32x4) (w2 : w2_r = w2_t.toU32x4)
  (w3 : w3_r = w3_t.toU32x4) (w4 : w4_r = w4_t.toU32x4)
  (i_t : UInt8) (i_r : U8) (hi : i_r = i_t.toU8) :
  let res_t := translate.process_rounds_i h0_t h1_t w1_t w2_t w3_t w4_t i_t
  let res_r := sha1.process_rounds_i h0_r h1_r w1_r w2_r w3_r w4_r i_r
  res_r =
  .ok (
    let (res_0_t, res_1_t, res_2_t, res_3_t, res_4_t, res_5_t) := res_t
    (res_0_t.toU32x4, res_1_t.toU32x4, res_2_t.toU32x4, res_3_t.toU32x4, res_4_t.toU32x4, res_5_t.toU32x4)
  ) :=
by
  unfold translate.process_rounds_i sha1.process_rounds_i
  rw [h0, h1, w1, w2, w3, w4, hi]
  -- YES!
  simp

lemma process_rounds_i_rust_to_translate' :
  let res_t := translate.process_rounds_i h0_t h1_t w1_t w2_t w3_t w4_t i_t
  let res_r := sha1.process_rounds_i h0_t.toU32x4 h1_t.toU32x4 w1_t.toU32x4 w2_t.toU32x4 w3_t.toU32x4 w4_t.toU32x4 i_t.toU8
  res_r =
  .ok (
    let (res_0_t, res_1_t, res_2_t, res_3_t, res_4_t, res_5_t) := res_t
    (res_0_t.toU32x4, res_1_t.toU32x4, res_2_t.toU32x4, res_3_t.toU32x4, res_4_t.toU32x4, res_5_t.toU32x4)
  )
  :=
by
  rw [process_rounds_i_rust_to_translate h0_t h1_t w1_t w2_t w3_t w4_t _ _ _ _ _ _ _ _ _ _ _ _ i_t _ _] <;>
  simp

/-!
# ############################################
# PROCESS_LOOP
# ############################################
-/

lemma process_loop_loop_rust_to_translate
  (block_t : Array UInt8) (block_len : block_t.size = 64) (block_r : Array U8 64#usize) (hblock : block_r = block_t.toArrayU8 sorry)
  (words_t : Array UInt32) (words_len : words_t.size = 16) (words_r : Array U32 16#usize) (hwords : words_r = words_t.toArrayU32 sorry)
  (index_t : Nat) (index_size : index_t < USize.size) (index_r : Usize) (hindex : index_r = index_t.toUsize) :
  let res_t := translate.process_loop_loop block_t block_len words_t words_len index_t
  let res_r := sha1.process_loop_loop block_r words_r index_r
  res_r = .ok (res_t.toArrayU32 sorry) :=
by
  rw [hblock, hwords, hindex]
  clear hblock block_r hwords words_r hindex index_r
  have h : index_t ≤ 16 := sorry
  induction h using Nat.decreasingInduction generalizing words_t with
  | self =>
    rw [sha1.process_loop_loop, translate.process_loop_loop]
    have this : ¬Nat.toUsize 16 < 16#usize := sorry
    simp [this]
  | of_succ index hi ih =>
    rw [sha1.process_loop_loop, translate.process_loop_loop]
    have : Nat.toUsize index < 16#usize := sorry
    simp [hi, this]
    -- All of this can be automatically done by a tactic.
    -- `simp` isn't quite good enough as there still needs to be some awareness of which order
    -- the rewriting needs to happen, and not all the bounds-proofs can be discharged.
    rw [Usize.ofNat_eq 4 4, Usize.ofNat_eq 3 3, Usize.ofNat_eq 2 2, Usize.ofNat_eq 1 1]
    rw [U32.ofUInt32_eq 24 24, U32.ofUInt32_eq 16 16, U32.ofUInt32_eq 8 8]
    simp [Usize.add_spec sorry, Usize.mul_spec sorry, Array.index_mut_usize,
      Array.U8.index_usize_spec _ _ _ sorry,
      Array.toArrayU32.index_usize_spec _ _ _ sorry, Array.toArrayU32.update_spec _ _ _ _ _]
    rw [Array.toArrayU32.update_spec _ _ _ _ _]
    rw [ih _ _ sorry]

lemma process_loop_rust_to_translate
  (block_t : Array UInt8) (block_len : block_t.size = 64) (block_r : Array U8 64#usize) (hblock : block_r = block_t.toArrayU8 sorry) :
  let res_t := translate.process_loop block_t block_len
  let res_r := sha1.process_loop block_r
  res_r = .ok (res_t.toArrayU32 (by simp [res_t, translate.process_loop_size])) :=
by
  sorry

@[simp]
lemma process_loop_rust_to_translate'
  (block_t : Array UInt8) (block_len : block_t.size = 64) :
  let res_t := translate.process_loop block_t block_len
  let res_r := sha1.process_loop (block_t.toArrayU8 (by simp [block_len]))
  res_r = .ok (res_t.toArrayU32 sorry) :=
by
  sorry

-- lemma process_loop_loop_translate_to_aux :
--   let res_t := translate.process_loop_loop final_hash final_hash_len result_bytes index result_bytes_bound
--   let res_l := lean.process_loop_aux final_hash[index:].toArray result_bytes
--   res_t = res_l :=
-- by
--   have h : index ≤ 5 := sorry
--   induction h using Nat.decreasingInduction generalizing result_bytes with
--   | self =>
--     have : final_hash[5:].toArray = #[] := sorry
--     simp [this]
--     rw [translate.hash_to_vec_loop, lean.hash_to_vec_aux]
--     simp_rw [final_hash_len]
--     simp
--   | of_succ index hi ih =>
--     rw [translate.hash_to_vec_loop]
--     simp [final_hash_len, hi, ih]
--     simp [lean.hash_to_vec_aux, ← Array.foldl_toList]
--     cases h : (final_hash.toSubarray index 5).toArray.toList with
--     | nil => sorry
--     | cons x xs =>
--       have h₀ : x = final_hash[index] := by sorry
--       have h₁ : xs = (final_hash.toSubarray (index + 1) 5).toArray.toList := by sorry
--       simp [h₀, h₁]

/-!
# ############################################
# PROCESS
# ############################################
-/

lemma process_rust_to_translate
  (state_t : Array UInt32) (hstate_t : state_t.size = 5)
  (state_r : Array U32 5#usize) (hstate_r : state_r = state_t.toArrayU32 (by simp [hstate_t]))
  (block_t : Array UInt8) (hblock_t : block_t.size = 64)
  (block_r : Array U8 64#usize) (hblock_r : block_r = block_t.toArrayU8 (by simp [hblock_t])) :
  let res_t := translate.process state_t hstate_t block_t hblock_t
  let res_r := sha1.process state_r block_r
  res_r = .ok (res_t.toArrayU32 (by simp)) :=
by
  unfold translate.process sha1.process
  rw [hstate_r, hblock_r]
  rw [Usize.ofNat_eq 0 0, Usize.ofNat_eq 1 1, Usize.ofNat_eq 2 2, Usize.ofNat_eq 3 3]
  simp [process_loop_rust_to_translate' block_t hblock_t, Array.toArrayU32.index_usize_spec _ _ _ sorry]
  sorry

lemma process_rust_to_translate' :
  let res_t := translate.process state_t hstate_t block_t hblock_t
  let res_r := sha1.process (state_t.toArrayU32 sorry) (block_t.toArrayU8 sorry)
  res_r = .ok (res_t.toArrayU32 sorry) :=
by
  rw [process_rust_to_translate] <;> simp

@[simp]
lemma process_translate_to_lean :
  let res_t := translate.process state_t hstate_t block_t hblock_t
  let res_l := SHA1.process ⟨state_t, hstate_t⟩ ⟨block_t⟩
  res_l = res_t :=
by
  -- Need a hammer
  rw [translate.process, SHA1.process]
  sorry

/-!
# ############################################
# CHUNKIFY_LOOP
# ############################################
-/

lemma chunkify_loop_rust_to_translate
  (msg_t : Array UInt8) (msg_r : Vec U8) (h_msg : msg_r = msg_t.toVecU8 sorry)
  (chunks_t : _root_.Array (_root_.Array UInt8)) (chunks_size : ∀ chunk ∈ chunks_t, chunk.size = 64)
  (chunks_r : Vec (Array U8 64#usize)) (hchunks : chunks_r = chunks_t.toVecArrayU8)
  (msg_start_t : ℕ) (msg_start_r : Usize) (h_msg_start : msg_start_r = msg_start_t.toUsize) :
  let res_t := translate.chunkify_loop msg_t chunks_t chunks_size msg_start_t
  let res_r := sha1.chunkify_loop msg_r chunks_r msg_start_r
  res_r = .ok res_t.toVecArrayU8 :=
by
  rw [h_msg, hchunks, h_msg_start]
  clear h_msg hchunks h_msg_start msg_r chunks_r msg_start_r
  have h : msg_start_t ≤ msg_t.size := sorry
  induction h using Nat.decreasingInduction generalizing chunks_t with
  | self =>
    rw [translate.chunkify_loop, sha1.chunkify_loop]
    have : ¬msg_start_t.toUsize < msg_t.size.toUsize := sorry
    simp [this]
  | of_succ index hi ih =>
    have : index.toUsize < msg_t.size.toUsize := sorry
    rw [translate.chunkify_loop, sha1.chunkify_loop]
    simp [hi, this, sha1.CHUNK_SIZE, sha1.CHUNK_SIZE_body, eval_global]
    simp_rw [Usize.ofNat_eq 64 64, Usize.ofNat_eq 0 0]
    simp [Usize.add_spec sorry]
    sorry

lemma chunkify_loop_translate_to_lean
  (msg_t : Array UInt8)
  (chunks_t : _root_.Array (_root_.Array UInt8)) (chunks_size : ∀ chunk ∈ chunks_t, chunk.size = 64)
  (msg_start_t : ℕ) :
  let res_t := translate.chunkify_loop msg_t chunks_t chunks_size msg_start_t
  let res_l := chunks_t ++ Array.map ByteArray.data
    (List.map (fun i ↦ (ByteArray.mk msg_t).extract (i * 64) ((i + 1) * 64)) (List.range' msg_start_t ((msg_t.size + 63) / 64 - msg_start_t))).toArray
  res_l = res_t :=
by
  sorry

/-!
# ############################################
# CHUNKIFY
# ############################################
-/

lemma chunkify_rust_to_translate
  (msg_t : Array UInt8) (msg_r : Vec U8) (h_msg : msg_r = msg_t.toVecU8 sorry) :
  let res_t := translate.chunkify msg_t
  let res_r := sha1.chunkify msg_r
  res_r = .ok res_t.toVecArrayU8 :=
by
  rw [h_msg, translate.chunkify, sha1.chunkify]
  sorry

  -- rw [h_padded_msg, h_zero_padding_length, h_i]
  -- clear h_padded_msg padded_msg_r h_zero_padding_length zero_padding_length_r h_i i_r
  -- have h : i_t ≤ zero_padding_length_t := sorry
  -- induction h using Nat.decreasingInduction generalizing padded_msg_t with
  -- | self =>
  --   rw [sha1.pad_message_loop_loop, translate.pad_message_loop]
  --   simp
  -- | of_succ index hi ih =>
  --   rw [sha1.pad_message_loop_loop, translate.pad_message_loop]
  --   have : index.toUsize < zero_padding_length_t.toUsize := sorry
  --   simp [this, hi]
  --   rw [U8.ofUInt8_eq 0, Usize.ofNat_eq 1]
  --   simp [Array.toVecU8.push_spec _ _ sorry, Usize.add_spec sorry]
  --   rw [ih _]

@[simp]
lemma chunkify_translate_to_lean
  (msg_t : Array UInt8) :
  let res_t := translate.chunkify msg_t
  let res_l := SHA1.chunkify ⟨msg_t⟩
  res_l.map ByteArray.data = res_t :=
by
  rw [translate.chunkify, SHA1.chunkify]
  have := chunkify_loop_translate_to_lean msg_t #[] (by decide) 0
  simp [ByteArray.size] at this ⊢
  rw [← this, List.range_eq_range']

@[simp]
lemma chunkify_translate_to_lean'
  (msg_t : Array UInt8) :
  let res_t := translate.chunkify msg_t
  let res_l := SHA1.chunkify ⟨msg_t⟩
  res_l = res_t.map ByteArray.mk :=
by
  have : ByteArray.mk ∘ ByteArray.data = id := by funext; simp
  simp [this, ← chunkify_translate_to_lean]


/-!
# ############################################
# PAD_MESSAGE_LOOP
# ############################################
-/

lemma pad_message_loop_loop_rust_to_translate
  (padded_msg_t : Array UInt8) (padded_msg_r : Vec U8) (h_padded_msg : padded_msg_r = padded_msg_t.toVecU8 sorry)
  (zero_padding_length_t : Nat) (zero_padding_length_r : Usize) (h_zero_padding_length : zero_padding_length_r = zero_padding_length_t.toUsize)
  (i_t : Nat) (i_r : Usize) (h_i : i_r = i_t.toUsize) :
  let res_t := translate.pad_message_loop padded_msg_t zero_padding_length_t i_t
  let res_r := sha1.pad_message_loop_loop padded_msg_r zero_padding_length_r i_r
  res_r = .ok (res_t.toVecU8 sorry) :=
by
  rw [h_padded_msg, h_zero_padding_length, h_i]
  clear h_padded_msg padded_msg_r h_zero_padding_length zero_padding_length_r h_i i_r
  have h : i_t ≤ zero_padding_length_t := sorry
  induction h using Nat.decreasingInduction generalizing padded_msg_t with
  | self =>
    rw [sha1.pad_message_loop_loop, translate.pad_message_loop]
    simp
  | of_succ index hi ih =>
    rw [sha1.pad_message_loop_loop, translate.pad_message_loop]
    have : index.toUsize < zero_padding_length_t.toUsize := sorry
    simp [this, hi]
    rw [U8.ofUInt8_eq 0 0, Usize.ofNat_eq 1 1]
    simp [Array.toVecU8.push_spec _ _ sorry, Usize.add_spec sorry]
    rw [ih _]

@[simp]
lemma pad_message_loop_translate_to_lean
  (padded_msg : Array UInt8) (zero_padding_length i : ℕ) :
  let res_t := translate.pad_message_loop padded_msg zero_padding_length i
  let res_l := padded_msg ++ Array.mkArray (zero_padding_length - i) (0 : UInt8)
  res_l = res_t :=
by
  unfold translate.pad_message_loop
  have h : i ≤ zero_padding_length := sorry
  induction h using Nat.decreasingInduction generalizing padded_msg with
  | self =>
    simp
  | of_succ i hi ih =>
    dsimp at ih
    simp [hi, ← ih (padded_msg.push 0)]
    sorry

/-!
# ############################################
# PAD_MESSAGE
# ############################################
-/

lemma pad_message_rust_to_translate
  (msg_t : Array UInt8) (msg_r : Vec U8) (h_msg : msg_r = msg_t.toVecU8 sorry) :
  let res_t := translate.pad_message msg_t
  let res_r := sha1.pad_message msg_r
  res_r = .ok (res_t.toVecU8 sorry) :=
by
  rw [h_msg, sha1.pad_message, translate.pad_message]
  clear h_msg msg_r
  rw [Usize.ofNat_eq 1 1, Usize.ofNat_eq 64 64, Usize.ofNat_eq 56 56]
  rw [U64.ofUInt64_eq 56 56, U64.ofUInt64_eq 48 48, U64.ofUInt64_eq 40 40, U64.ofUInt64_eq 32 32, U64.ofUInt64_eq 24 24, U64.ofUInt64_eq 16 16, U64.ofUInt64_eq 8 8, U64.ofUInt64_eq 0 0, U64.ofUInt64_eq 255 255]
  rw [U8.ofUInt8_eq 128 128]
  simp [Usize.add_spec sorry, Array.toVecU8.push_spec _ _ sorry]
  have h₀ := pad_message_loop_loop_rust_to_translate (msg_t.push 128) ((msg_t.push 128).toVecU8 sorry) rfl ((56 - (msg_t.size + 1) % 64) % 64) ((56 - (msg_t.size + 1) % 64) % 64).toUsize rfl 0 0#usize rfl
  dsimp at h₀
  rw [h₀]
  -- With the right simp lemmas, you can close pretty large goals :)
  simp

@[simp]
lemma pad_message_translate_to_lean
  (msg_t : Array UInt8) :
  let res_t := translate.pad_message msg_t
  let res_l := SHA1.pad_message ⟨msg_t⟩
  res_l.data = res_t :=
by
  unfold SHA1.pad_message translate.pad_message
  simp [ByteArray.data_append]
  simp [ByteArray.data_append, ← pad_message_loop_translate_to_lean, Array.push_eq_append_singleton, ByteArray.size]


/-!
# ############################################
# HASH_TO_VEC
# ############################################
-/

lemma hash_to_vec_loop_rust_to_translate
  (final_hash_t : Array UInt32) (final_hash_len : final_hash_t.size = 5) (final_hash_r : Array U32 5#usize) (hfinal_hash : final_hash_r = final_hash_t.toArrayU32 sorry)
  (result_bytes_t : Array UInt8) (result_bytes_r : Vec U8) (hresult_bytes : result_bytes_r = result_bytes_t.toVecU8 sorry)
  (index_t : Nat) (index_r : Usize) (hindex : index_r = index_t.toUsize)
  (result_bytes_t_bound : result_bytes_t.size ≤ 4 * index_t) :
  let res_t := translate.hash_to_vec_loop final_hash_t final_hash_len result_bytes_t index_t result_bytes_t_bound
  let res_r := sha1.hash_to_vec_loop final_hash_r result_bytes_r index_r
  res_r = .ok (res_t.toVecU8 sorry) :=
by
  rw [hfinal_hash, hresult_bytes, hindex]
  clear hfinal_hash final_hash_r hresult_bytes result_bytes_r hindex index_r
  have h : index_t ≤ 5 := sorry
  induction h using Nat.decreasingInduction generalizing result_bytes_t with
  | self =>
    rw [sha1.hash_to_vec_loop, translate.hash_to_vec_loop]
    have : ¬Nat.toUsize 5 < 5#usize := sorry
    simp [this, Array.to_slice, Array.toArrayU32, final_hash_len]
    sorry
  | of_succ index hi ih =>
    rw [sha1.hash_to_vec_loop, translate.hash_to_vec_loop]
    have : index.toUsize < (5 : ℤ) := sorry
    simp [hi, Array.to_slice, final_hash_len, this]
    rw [U32.ofUInt32_eq 255 255, U32.ofUInt32_eq 24 24, U32.ofUInt32_eq 16 16, U32.ofUInt32_eq 8 8, U32.ofUInt32_eq 0 0]
    rw [Usize.ofNat_eq 1 1]
    simp [Array.toArrayU32.index_usize_spec _ _ _ sorry, Array.toVecU8.push_spec _ _ sorry, Usize.add_spec sorry]
    rw [ih _ sorry]
    sorry

@[simp]
lemma hash_to_vec_loop_rust_to_translate' :
  let res_t := translate.hash_to_vec_loop final_hash_t final_hash_len result_bytes_t index_t result_bytes_t_bound
  let res_r := sha1.hash_to_vec_loop final_hash_t.toArrayU32 (result_bytes_t.toVecU8 sorry) index_t.toUsize
  res_r = .ok (res_t.toVecU8 sorry) :=
by
  rw [hash_to_vec_loop_rust_to_translate] <;> simp

lemma hash_to_vec_loop_translate_to_aux :
  let res_t := translate.hash_to_vec_loop final_hash final_hash_len result_bytes index result_bytes_bound
  let res_l := lean.hash_to_vec_aux final_hash[index:].toArray result_bytes
  res_l = res_t :=
by
  have h : index ≤ 5 := sorry
  induction h using Nat.decreasingInduction generalizing result_bytes with
  | self =>
    have : final_hash[5:].toArray = #[] := sorry
    simp [this]
    rw [translate.hash_to_vec_loop, lean.hash_to_vec_aux]
    simp_rw [final_hash_len]
    simp
  | of_succ index hi ih =>
    rw [translate.hash_to_vec_loop]
    simp [final_hash_len, hi, ih]
    simp [lean.hash_to_vec_aux, ← Array.foldl_toList]
    cases h : (final_hash.toSubarray index 5).toArray.toList with
    | nil => sorry
    | cons x xs =>
      have h₀ : x = final_hash[index] := by sorry
      have h₁ : xs = (final_hash.toSubarray (index + 1) 5).toArray.toList := by sorry
      simp [h₀, h₁]
      sorry

lemma hash_to_vec_loop_apply (final_hash_size : final_hash.size = 5) :
  (SHA1.hash_to_vec ⟨final_hash, final_hash_size⟩).data = lean.hash_to_vec_aux final_hash[0:].toArray #[] :=
by
  rw [lean.hash_to_vec_aux, SHA1.hash_to_vec]
  have : final_hash.toSubarray.toArray = final_hash := sorry
  simp [this]

lemma hash_to_vec_rust_to_translate
  (final_hash_t : Array UInt32) (final_hash_len : final_hash_t.size = 5) (final_hash_r : Array U32 5#usize) (hfinal_hash : final_hash_r = final_hash_t.toArrayU32 sorry) :
  let res_t := translate.hash_to_vec final_hash_t final_hash_len
  let res_r := sha1.hash_to_vec final_hash_r
  res_r = .ok (res_t.toVecU8 sorry) :=
by
  rw [hfinal_hash, sha1.hash_to_vec, translate.hash_to_vec, Usize.ofNat_eq 0 0]
  have := @hash_to_vec_loop_rust_to_translate' final_hash_t final_hash_len #[] 0 (by rfl)
  simp [this]

@[simp]
lemma hash_to_vec_rust_to_translate' :
  let res_t := translate.hash_to_vec final_hash_t final_hash_len
  let res_r := sha1.hash_to_vec final_hash_t.toArrayU32
  res_r = .ok (res_t.toVecU8 sorry):=
by
  rw [hash_to_vec_rust_to_translate]; simp

@[simp]
lemma hash_to_vec_translate_to_lean :
  let res_t := translate.hash_to_vec final_hash_t final_hash_len
  let res_l := SHA1.hash_to_vec ⟨final_hash_t, final_hash_len⟩
  res_l.data = res_t :=
by
  sorry

lemma hash_to_vec_total
  (final_hash_t : Array UInt32) (final_hash_len : final_hash_t.size = 5) (final_hash_r : Array U32 5#usize) (hfinal_hash : final_hash_r = final_hash_t.toArrayU32 sorry) :
  let res_t := SHA1.hash_to_vec ⟨final_hash_t, final_hash_len⟩
  let res_r := sha1.hash_to_vec final_hash_r
  res_r = .ok (res_t.data.toVecU8 sorry) :=
by
  dsimp
  have h₀ := @hash_to_vec_loop_translate_to_aux final_hash_t final_hash_len #[] 0 (by rfl)
  have h₁ := hash_to_vec_loop_rust_to_translate final_hash_t final_hash_len final_hash_r hfinal_hash #[] (Vec.new U8) (by rfl) 0 0#usize (by rfl) (by decide)
  rw [hash_to_vec_loop_apply, h₀, ← h₁, sha1.hash_to_vec]

/-!
# ############################################
# HASH_LOOP
# ############################################
-/

lemma hash_loop_rust_to_translate
  (chunks_t : Array (Array UInt8)) (chunks_r : Vec (Array U8 64#usize)) (hchunks : chunks_r = chunks_t.toVecArrayU8)
  (state_t : Array UInt32) (state_size : state_t.size = 5)
  (state_r : Array U32 5#usize) (hstate_r : state_r = state_t.toArrayU32 sorry)
  (index_t : Nat) (index_r : Usize) (hindex : index_r = index_t.toUsize) :
  let res_t := translate.hash_loop chunks_t state_t state_size index_t
  let res_r := sha1.hash_loop_loop chunks_r state_r index_r
  res_r = .ok (res_t.toArrayU32 sorry) :=
by
  sorry
  -- dsimp [translate.hash_loop]
  -- rw [hchunks, hstate_r, hindex, sha1.hash_loop_loop, translate.hash_loop]
  -- clear hchunks hstate_r hindex chunks_r state_r index_r
  -- have h : index_t ≤ chunks_t.size := sorry
  -- induction h using Nat.decreasingInduction with
  -- | self =>
  --   have : ¬chunks_t.size.toUsize < chunks_t.toVecArrayU8.len := sorry
  --   simp [this]
  --   dsimp [translate.hash_loop]
  --   sorry
  -- | of_succ i hi ih =>
  --   have : i.toUsize < chunks_t.toVecArrayU8.len := sorry
  --   simp [hi, this, ih]
  --   sorry

lemma hash_loop_rust_to_translate' :
  let res_t := translate.hash_loop chunks_t state_t state_size index_t
  let res_r := sha1.hash_loop_loop chunks_t.toVecArrayU8 state_t.toArrayU32 index_t.toUsize
  res_r = .ok (res_t.toArrayU32 sorry) :=
by
  rw [hash_loop_rust_to_translate] <;> simp

lemma hash_loop_translate_to_lean :
  let res_t := translate.hash_loop chunks_t state_t state_size index_t
  let ⟨res_l, _⟩ := (Array.foldl (fun h0 chunk ↦ SHA1.process h0 chunk) ⟨state_t, state_size⟩ (chunks_t.map ByteArray.mk))
  res_l = res_t :=
by

  sorry

/-!
# ############################################
# HASH
# ############################################
-/

lemma hash_rust_to_translate
  (msg_t : Array UInt8) (msg_r : Vec U8) (h_msg : msg_r = msg_t.toVecU8 sorry) :
  let res_t := translate.hash msg_t
  let res_r := sha1.hash msg_r
  res_r = .ok (res_t.toVecU8 sorry) :=
by
  rw [sha1.hash]
  sorry

@[simp]
lemma hash_rust_to_translate' :
  let res_t := translate.hash msg_t
  let res_r := sha1.hash (msg_t.toVecU8 sorry)
  res_r = .ok (res_t.toVecU8 sorry):=
by
  rw [hash_rust_to_translate]; simp

@[simp]
lemma hash_translate_to_lean :
  let res_t := translate.hash msg_t
  let res_l := SHA1.hash ⟨msg_t⟩
  res_l.data = res_t :=
by
  unfold translate.hash SHA1.hash
  dsimp
  have : ⟨translate.INITIAL_STATE, rfl⟩ = SHA1.initialHash := sorry
  rw [hash_to_vec_translate_to_lean]
  congr

  sorry
  -- chunkify_translate_to_lean', pad_message_translate_to_lean, hash_to_vec_translate_to_lean, hash_loop_translate_to_lean, this]

lemma hash
  (msg_t : Array UInt8) (msg_r : Vec U8) (h_msg : msg_r = msg_t.toVecU8 sorry) :
  let res_t := SHA1.hash ⟨msg_t⟩
  let res_r := sha1.hash msg_r
  res_r = .ok (res_t.data.toVecU8 sorry) :=
by
  simp only [h_msg, hash_rust_to_translate', hash_translate_to_lean]

end equivalence
