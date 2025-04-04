import VerifiedFipsCryptography.Specs.SHA1
import VerifiedFipsCryptography.Equivalence.Lemmas

/-!
# Translated SHA1 functions ########################
-/

namespace Translated

@[irreducible]
def add_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ + a₂, b₁ + b₂, c₁ + c₂, d₁ + d₂)

@[irreducible]
def sub_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ - a₂, b₁ - b₂, c₁ - c₂, d₁ - d₂)

@[irreducible]
def bitand_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ &&& a₂, b₁ &&& b₂, c₁ &&& c₂, d₁ &&& d₂)

@[irreducible]
def bitor_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ ||| a₂, b₁ ||| b₂, c₁ ||| c₂, d₁ ||| d₂)

@[irreducible]
def bitxor_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ ^^^ a₂, b₁ ^^^ b₂, c₁ ^^^ c₂, d₁ ^^^ d₂)

@[irreducible]
def shl_u32x4_usize (self : u32x4) (amt : UInt32) : u32x4 :=
  let (a, b, c, d) := self
  (a <<< amt, b <<< amt, c <<< amt, d <<< amt)

@[irreducible]
def shl_u32x4 (self rhs : u32x4) : u32x4 :=
  let (a₁, b₁, c₁, d₁) := self
  let (a₂, b₂, c₂, d₂) := rhs
  (a₁ <<< a₂, b₁ <<< b₂, c₁ <<< c₂, d₁ <<< d₂)

@[irreducible]
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

@[irreducible]
def sha1_first (w0 : u32x4) : UInt32 :=
  let (x, _, _, _) := w0
  x

@[irreducible]
def sha1_first_add (e : UInt32) (w0 : u32x4) : u32x4 :=
  let (a, b, c, d) := w0
  (e + a, b, c, d)

@[irreducible]
def sha1msg1 (a b : u32x4) : u32x4 :=
  let (_, _, w2, w3) := a
  let (w4, w5, _, _) := b
  bitxor_u32x4 a (w2, w3, w4, w5)

@[irreducible]
def sha1msg2 (a b : u32x4) : u32x4 :=
  let (x0, x1, x2, x3) := a
  let (_, w13, w14, w15) := b
  let w16 := (x0 ^^^ w13).rotate_left 1
  let w17 := (x1 ^^^ w14).rotate_left 1
  let w18 := (x2 ^^^ w15).rotate_left 1
  let w19 := (x3 ^^^ w16).rotate_left 1
  (w16, w17, w18, w19)

@[irreducible]
def sha1_first_half (abcd msg : u32x4) : u32x4 :=
  sha1_first_add ((sha1_first abcd).rotate_left 30) msg

@[irreducible]
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

@[irreducible]
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

@[irreducible]
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

@[irreducible]
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

@[irreducible]
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
    process_loop_loop block block_size words1 (by simp [words1, words_size]) index1
  else
    words

lemma process_loop_loop_size (index_size : index ≤ 16) :
  (process_loop_loop block block_size words words_size index).size = 16 :=
by
  induction index_size using Nat.decreasingInduction generalizing words with
  | self => simpa [process_loop_loop]
  | of_succ index hi ih =>
    unfold process_loop_loop
    simp [hi, ih]

@[irreducible]
def process_loop
  (block : Array UInt8) (block_size : block.size = 64) : Array UInt32 :=
  let words : Array UInt32 := ⟨List.replicate 16 0⟩
  process_loop_loop block block_size words (by simp [words]) 0

lemma process_loop_size : (process_loop block block_size).size = 16 := by
  unfold process_loop
  rw [process_loop_loop_size (Nat.zero_le 16)]

@[irreducible]
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

@[irreducible]
def process_rounds_i (args : u32x4x6) (i : UInt8) :
  u32x4x6 :=
  let (h0, h1, w1, w2, w3, w4) := args
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

-- Not sure why but adding this fixes a few determininistic timeout bugs.
-- I think Lean is unfolding to deeply in certain cases and getting stuck, adding this prevents that from happening.
@[irreducible]
def process (state : Array UInt32) (state_size : state.size = 5)
  (block : Array UInt8) (block_size : block.size = 64) : Array UInt32 :=

  -- Convert block bytes to words
  let words := process_loop block block_size
  have words_size : words.size = 16 := process_loop_size

  -- Initial state
  let a := state[0]
  let b := state[1]
  let c := state[2]
  let d := state[3]
  let e := state[4]
  let h0 := (a, b, c, d) -- Initial u32x4

  let args0 := process_rounds_0 h0 state state_size words words_size
  let args1 := process_rounds_i args0 1
  let args2 := process_rounds_i args1 2
  let (h05, h15, _, _, _, _) := process_rounds_i args2 3

  -- Final state update
  let e' := (sha1_first h15).rotate_left 30
  let (a', b', c', d') := h05
  #[
    state[0] + a',
    state[1] + b',
    state[2] + c',
    state[3] + d',
    state[4] + e'
  ]

@[simp]
lemma process_size : (process state state_size block block_size).size = 5 := by
  unfold process
  dsimp; split; split; simp

@[irreducible]
def chunkify_loop
  (msg : Array UInt8) (msg_size_dvd : 64 ∣ msg.size)
  (chunks : Array (Array UInt8)) (chunk_sizes : ∀ chunk ∈ chunks, chunk.size = 64)
  (msg_start : Nat) (msg_start_dvd : 64 ∣ msg_start) : Array (Array UInt8) :=
  let i := msg.size
  if h : msg_start < i then
    let msg_end := msg_start + 64
    let msg_slice := msg.extract msg_start msg_end
    let chunks1 := chunks.push msg_slice
    have : ∀ chunk ∈ chunks1, chunk.size = 64 := by
      simp [chunks1]; rintro chunk (h|h)
      · exact chunk_sizes chunk h
      · simp [h, msg_slice, msg_end]; omega
    let msg_start1 := msg_start + 64
    chunkify_loop msg msg_size_dvd chunks1 this msg_start1 (Nat.dvd_add_self_right.mpr msg_start_dvd)
  else
    chunks
  termination_by (msg.size - msg_start)

@[irreducible]
def chunkify_loop_aux
  (msg : Array UInt8) (msg_size_dvd : 64 ∣ msg.size)
  (chunks : Array (Array UInt8)) (chunk_sizes : ∀ chunk ∈ chunks, chunk.size = 64)
  (i : Nat) : Array (Array UInt8) :=
  if h : i * 64 < msg.size then
    let msg_slice := msg.extract (i * 64) ((i + 1) * 64)
    let chunks1 := chunks.push msg_slice
    have : ∀ chunk ∈ chunks1, chunk.size = 64 := by
      simp [chunks1]; rintro chunk (h|h)
      · exact chunk_sizes chunk h
      · simp [h, msg_slice]; omega
    let i1 := (i + 1)
    chunkify_loop_aux msg msg_size_dvd chunks1 this i1
  else
    chunks

lemma chunkify_loop.eq_aux (i_size : i * 64 ≤ msg.size) (msg_size_dvd : 64 ∣ msg.size) :
  chunkify_loop msg msg_size_dvd chunks chunk_sizes (i * 64) (Nat.dvd_mul_left 64 i)  = chunkify_loop_aux msg msg_size_dvd chunks chunk_sizes i :=
by
  have h0 := (Nat.dvd_iff_div_mul_eq msg.size 64).mp msg_size_dvd
  rw [← h0, mul_le_mul_right (Nat.zero_lt_succ 63)] at i_size
  induction i_size using Nat.decreasingInduction generalizing chunks with
  | self =>
    unfold chunkify_loop chunkify_loop_aux
    simp [h0]
  | of_succ i hi ih =>
    unfold chunkify_loop chunkify_loop_aux
    have : i * 64 < msg.size := by linarith
    simp [this, ← ih, add_mul]

lemma mem_chunkify_loop_aux_size (i_size : i * 64 ≤ msg.size) (msg_size_dvd : 64 ∣ msg.size) :
  ∀ chunk ∈ (chunkify_loop_aux msg msg_size_dvd chunks chunk_sizes i), chunk.size = 64 := fun chunk h ↦
by
  have h0 := (Nat.dvd_iff_div_mul_eq msg.size 64).mp msg_size_dvd
  rw [← h0, mul_le_mul_right (Nat.zero_lt_succ 63)] at i_size
  induction i_size using Nat.decreasingInduction generalizing chunks with
  | self =>
    unfold chunkify_loop_aux at h
    simp [h0] at h;
    exact chunk_sizes chunk h
  | of_succ i hi ih =>
    unfold chunkify_loop_aux at h
    have : i * 64 < msg.size := by linarith
    simp [this] at h
    rw [← ih h]

@[simp]
lemma chunkify_loop_aux_size (i_size : i * 64 ≤ msg.size) (msg_size_dvd : 64 ∣ msg.size) :
  (chunkify_loop_aux msg msg_size_dvd chunks chunk_sizes i).size = chunks.size + msg.size / 64 - i :=
by
  have h0 := (Nat.dvd_iff_div_mul_eq msg.size 64).mp msg_size_dvd
  rw [← h0, mul_le_mul_right (Nat.zero_lt_succ 63)] at i_size
  induction i_size using Nat.decreasingInduction generalizing chunks with
  | self =>
    unfold chunkify_loop_aux
    simp [h0]
  | of_succ i hi ih =>
    unfold chunkify_loop_aux
    have : i * 64 < msg.size := by linarith
    simp [this, ih]
    omega

@[irreducible]
def chunkify (msg : Array UInt8) (msg_size_dvd : 64 ∣ msg.size) : Array (Array UInt8) :=
  chunkify_loop msg msg_size_dvd #[] (by simp) 0 (Nat.dvd_zero 64)

@[simp]
lemma chunkify_sizes (msg_size_dvd : 64 ∣ msg.size) : ∀ chunk ∈ chunkify msg msg_size_dvd, chunk.size = 64 := fun chunk h ↦ by
  unfold chunkify at h
  conv at h => left; left; rw [← Nat.zero_mul 64]
  rw [chunkify_loop.eq_aux (by omega) msg_size_dvd] at h
  rw [mem_chunkify_loop_aux_size  (by omega) msg_size_dvd chunk h]

@[simp]
lemma chunkify_size (msg_size_dvd : 64 ∣ msg.size) : (chunkify msg msg_size_dvd).size = msg.size / 64 := by
  unfold chunkify
  conv => left; right; left; rw [← Nat.zero_mul 64]
  rw [chunkify_loop.eq_aux (by omega), chunkify_loop_aux_size (by omega) (by omega)]
  simp

-- There's a bounds problem here. The Rust implementation needs to be more precise on how large the input message is.
-- If the message is large enough, then pushing back more elements to it will cause a capacity overflow error.
@[irreducible]
def pad_message_loop
  (padded_msg : Array UInt8) (zero_padding_length : Nat)
  (i : Nat) : Array UInt8 :=
  if h : i < zero_padding_length then
    let padded_msg1 := padded_msg.push 0
    let i1 := i + 1
    pad_message_loop padded_msg1 zero_padding_length i1
  else
    padded_msg

@[simp]
lemma pad_message_loop_size (i_size : i ≤ zero_padding_length) :
  (pad_message_loop padded_msg zero_padding_length i).size = padded_msg.size + (zero_padding_length - i) :=
by
  induction i_size using Nat.decreasingInduction generalizing padded_msg with
  | self => unfold pad_message_loop; simp
  | of_succ i hi ih =>
    unfold pad_message_loop
    simp [hi, ih]
    omega

@[irreducible]
def pad_message (msg : Array UInt8) : Array UInt8 :=
  let msg_len := msg.size
  let msg_len_bits := (msg_len.toUInt64) * 8
  let padded_msg := msg.push 128
  let len := padded_msg.size
  let zero_padding_length := (64 - len % 64 + 56) % 64
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

@[simp]
lemma pad_message_size_dvd : 64 ∣ (pad_message msg).size := by
  unfold pad_message
  simp [-Nat.cast_add, -Nat.cast_one]
  set x := msg.size + 1
  have hx : x % 64 ≤ 64 := le_of_lt (Nat.mod_lt x (Nat.zero_lt_succ 63))
  interval_cases hmod : (x % 64) <;> simp <;> rw [Nat.dvd_iff_mod_eq_zero] <;> omega

@[simp]
lemma pad_message_size (msg_size : msg.size < USize.size - 72 - 1) : (pad_message msg).size < USize.size := by
  unfold pad_message
  simp [-Nat.cast_add, -Nat.cast_one]
  omega

@[irreducible]
def hash_to_vec_loop
  (final_hash : Array UInt32) (final_hash_size : final_hash.size = 5)
  (result_bytes : Array UInt8) (index : Nat) : Array UInt8 :=
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
    hash_to_vec_loop final_hash final_hash_size result_bytes1 index1
  else
    result_bytes

@[simp]
lemma hash_to_vec_loop_size (i_size : i ≤ final_hash.size) :
  (hash_to_vec_loop final_hash final_hash_size result_bytes i).size = result_bytes.size + (final_hash.size - i) * 4 :=
by
  induction i_size using Nat.decreasingInduction generalizing result_bytes with
  | self => unfold hash_to_vec_loop; simp
  | of_succ i hi ih =>
    unfold hash_to_vec_loop
    simp [hi, ih]
    omega

@[irreducible]
def hash_to_vec (final_hash : Array UInt32) (final_hash_size : final_hash.size = 5) : Array UInt8 :=
  hash_to_vec_loop final_hash final_hash_size #[] 0

@[simp]
lemma hash_to_vec_size :
  (hash_to_vec final_hash final_hash_size).size = final_hash.size * 4 :=
by simp [hash_to_vec]

@[irreducible]
def hash_loop
  (chunks : Array (Array UInt8)) (chunk_sizes : ∀ chunk ∈ chunks, chunk.size = 64)
  (state : Array UInt32) (state_size : state.size = 5)
  (chunk_index : Nat) : Array UInt32 :=
  if h : chunk_index < chunks.size then
    let chunk := chunks[chunk_index]
    have chunk_size : chunk.size = 64 := chunk_sizes chunk (Array.getElem_mem h)
    let state1 := process state state_size chunk chunk_size
    let chunk_index1 := chunk_index + 1
    hash_loop chunks chunk_sizes state1 process_size chunk_index1
  else
    state

@[simp]
lemma hash_loop_size (i_size : i ≤ chunks.size) : (hash_loop chunks chunk_sizes state state_size i).size = 5 := by
  induction i_size using Nat.decreasingInduction generalizing state with
  | self => unfold hash_loop; simpa
  | of_succ i hi ih =>
    unfold hash_loop
    simp [hi, ih]

@[irreducible]
def hash (message : Array UInt8) : Array UInt8 :=
  let padded_msg := pad_message message
  let chunks := chunkify padded_msg pad_message_size_dvd
  have chunk_sizes := chunkify_sizes pad_message_size_dvd
  let state := hash_loop chunks chunk_sizes INITIAL_STATE rfl 0
  hash_to_vec state (hash_loop_size (Nat.zero_le _))

@[simp]
lemma hash_size : (hash message).size < USize.size := by
  simp [hash]
  exact Nat.lt_usize (by omega)
