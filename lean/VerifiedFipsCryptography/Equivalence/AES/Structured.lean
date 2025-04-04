import VerifiedFipsCryptography.Specs.AES.AES
import VerifiedFipsCryptography.Equivalence.Lemmas

namespace Structured

def gf_mul_loop (a b result : UInt8) (i : Nat) : UInt8 := Id.run do
  let mut result : UInt8 := result
  let mut tempA := a
  let mut tempB := b
  for _ in [i:8] do
    if tempB &&& 0x01 == 0x01 then
      result := result ^^^ tempA
    tempA := AES.xtime tempA
    tempB := tempB >>> 1
  result

def gf_mul (a b : UInt8) : UInt8 :=
  gf_mul_loop a b 0 0

def copy_initial_key_loop (key w : Array UInt8) (nk i : Nat) : Array UInt8 := Id.run do
  let mut w := w
  -- Copy the original key into the first Nk words
  for i in [i:nk] do
    w := w ++ key.extract (4 * i) (4 * (i + 1))
  w

@[simp]
lemma copy_initial_key_loop_size (key_size : key.size = 4 * nk) :
  (copy_initial_key_loop key w nk i).size = w.size + 4 * (nk - i) :=
by
  simp [copy_initial_key_loop, Id.run]
  by_cases hi : i ≤ nk
  · induction hi using Nat.decreasingInduction generalizing w with
    | self => simp
    | of_succ i hi ih =>
      simp [hi, range'_eq_cons, ih, key_size]
      omega
  · by_cases hi : i = nk
    · simp [Aeneas.loop_append_form, hi]
    · have hi : ¬i < nk := by linarith
      have hn : nk - i = 0 := by omega
      simp [hi, hn]

def copy_initial_key (key : Array UInt8) (nk total_words : Nat) : Array UInt8 := Id.run do
  let mut w := Array.mkEmpty (total_words * 4)
  copy_initial_key_loop key w nk 0

@[simp]
lemma copy_initial_key_size (key_size : key.size = 4 * nk) :
  (copy_initial_key key nk total_words).size = 4 * nk :=
by
  simp [copy_initial_key, Id.run, copy_initial_key_loop_size key_size]

def expand_key_schedule_inner (w : Array UInt8) (nk i : Nat) (temp : Array UInt8) : Array UInt8 :=
  let prev_word := w.extract (4 * (i - nk)) (4 * (i - nk + 1))
  let temp := temp.zipWith prev_word (· ^^^ ·)
  w ++ temp

@[simp]
lemma expand_key_schedule_inner_size (hnk : 0 < nk) (h : nk ≤ i) (w_size : w.size = 4 * i) (temp_size : temp.size = 4) :
  (expand_key_schedule_inner w nk i temp).size = w.size + 4 :=
by
  simp [expand_key_schedule_inner, temp_size, w_size]
  omega

def expand_key_schedule_loop (w : Array UInt8) (nk total_words i : Nat) : Array UInt8 := Id.run do
  let mut w := w
  for i in [i:total_words] do
    let mut temp : Array UInt8 := w.extract (4 * (i - 1)) (4 * i)
    if i % nk == 0 then
      temp := AES.subWord (AES.rotWord temp)
      temp := temp.set! 0 (temp[0]! ^^^ AES.rcon[(i / nk) - 1]!)
    else if nk > 6 && i % nk == 4 then
      temp := AES.subWord temp
    w := expand_key_schedule_inner w nk i temp
  w

def expand_key_schedule (w : Array UInt8) (nk total_words : Nat) : Array UInt8 :=
  expand_key_schedule_loop w nk total_words nk

def key_expansion (key : Array UInt8) (nk nr : Nat) : Array UInt8 :=
  let nb := 4 -- Block size in words
  let total_words := nb * (nr + 1)

  -- Copy the original key into the first `nk` words
  let w := copy_initial_key key nk total_words
  -- Expand the key schedule
  expand_key_schedule w nk total_words

def mix_columns_loop (state result : Array UInt8) (i : Nat) : Array UInt8 := Id.run do
  let mut result := result
  for i in [i:4] do
    result := result ++ AES.mixColumn (#[state[4 * i]!, state[4 * i + 1]!, state[4 * i + 2]!, state[4 * i + 3]!])
  result

def mix_columns (state : Array UInt8) : Array UInt8 := Id.run do
  if state.size == 16 then
    mix_columns_loop state #[] 0
  else
    panic! "mix_columns requires an array of exactly 16 elements"

def inv_mix_columns_loop (state result : Array UInt8) (i : Nat) : Array UInt8 := Id.run do
  let mut result := result
  for i in [i:4] do
    result := result ++ AES.invMixColumn (#[state[4 * i]!, state[4 * i + 1]!, state[4 * i + 2]!, state[4 * i + 3]!])
  result

def inv_mix_columns (state : Array UInt8) : Array UInt8 := Id.run do
  if state.size == 16 then
    inv_mix_columns_loop state #[] 0
  else
    panic! "inv_mix_columns requires an array of exactly 16 elements"

def cipher_loop (state key_schedule : Array UInt8) (nr round : Nat) : Array UInt8 := Id.run do
  let mut state := state
  for round in [round:nr] do
    state := AES.subBytes state
    state := AES.shiftRows state
    state := mix_columns state
    state := AES.addRoundKey state (key_schedule.extract (round * 16) ((round + 1) * 16))
  state

-- Cipher function
def cipher (input : Array UInt8) (key_schedule : Array UInt8) (nr : Nat) : Array UInt8 := Id.run do
  let mut state := input
  state := AES.addRoundKey state (key_schedule.extract 0 16)
  state := cipher_loop state key_schedule nr 1
  state := AES.subBytes state
  state := AES.shiftRows state
  state := AES.addRoundKey state (key_schedule.extract (nr * 16) ((nr + 1) * 16))
  state

def inv_cipher_loop (state key_schedule : Array UInt8) (nr round_idx : Nat) : Array UInt8 := Id.run do
  let mut state := state
  for round_idx in [round_idx:nr] do
    let round := nr - round_idx
    state := AES.invShiftRows state
    state := AES.invSubBytes state
    state := AES.addRoundKey state (key_schedule.extract (round * 16) ((round + 1) * 16))
    state := inv_mix_columns state
  state

-- Inverse cipher function
def inv_cipher (input : Array UInt8) (key_schedule : Array UInt8) (nr : Nat) : Array UInt8 := Id.run do
  let mut state := input
  state := AES.addRoundKey state (key_schedule.extract (nr * 16) ((nr + 1) * 16))
  state := inv_cipher_loop state key_schedule nr 1
  state := AES.invShiftRows state
  state := AES.invSubBytes state
  state := AES.addRoundKey state (key_schedule.extract 0 16)
  state

end Structured
