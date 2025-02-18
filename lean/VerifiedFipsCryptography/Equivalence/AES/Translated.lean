import VerifiedFipsCryptography.Specs.AES.AES
import VerifiedFipsCryptography.Equivalence.Lemmas

/-!
# Translated functions ########################
-/

namespace Translated

def test_bit (b i : UInt8) : Bool :=
  ((b >>> i) &&& 1) = 1

def xtime (b : UInt8) : UInt8 :=
  if test_bit b 7 then
    (b <<< 1) ^^^ 27
  else
    b <<< 1

def gf_mul_loop (a b result : UInt8) (i : Nat) : UInt8 :=
  if i < 8 then
    if (b &&& 1) = 1 then
      let a' := xtime a
      let b' := b >>> 1
      gf_mul_loop a' b' (result ^^^ a) (i + 1)
    else
      let a' := xtime a
      let b' := b >>> 1
      gf_mul_loop a' b' result (i + 1)
  else
    result

def gf_mul (a b : UInt8) : UInt8 :=
  gf_mul_loop a b 0 0

def rot_word (word : Array UInt8) (word_size : word.size = 4) : Array UInt8 :=
  let w0 := word[0]
  let w1 := word[1]
  let w2 := word[2]
  let w3 := word[3]
  #[w1, w2, w3, w0]

set_option maxRecDepth 10000
def sub_word (word : Array UInt8) (word_size : word.size = 4) : Array UInt8 :=
  let w0 := word[0]
  have h0 : w0.toNat < AES.sBox.size := by simp [w0.toNat_lt_size]
  let w0 := AES.sBox[w0.toNat]
  let w1 := word[1]
  have h0 : w1.toNat < AES.sBox.size := by simp [w1.toNat_lt_size]
  let w1 := AES.sBox[w1.toNat]
  let w2 := word[2]
  have h2 : w2.toNat < AES.sBox.size := by simp [w2.toNat_lt_size]
  let w2 := AES.sBox[w2.toNat]
  let w3 := word[3]
  have h3 : w3.toNat < AES.sBox.size := by simp [w3.toNat_lt_size]
  let w3 := AES.sBox[w3.toNat]
  #[w0, w1, w2, w3]

def copy_initial_key_loop (w key : Array UInt8) (nk i : Nat) : Array UInt8 :=
  if i < nk then
    let w := w ++ key.extract (i * 4) ((i + 1) * 4)
    copy_initial_key_loop w key nk (i + 1)
  else
    w

@[simp]
lemma copy_initial_key_loop_size {key_size : key.size = nk * 4} :
  (copy_initial_key_loop w key nk i).size = w.size + (nk - i) * 4 :=
by
  by_cases hi : i ≤ nk
  · induction hi using Nat.decreasingInduction generalizing w with
    | self =>
      simp [copy_initial_key_loop]
    | of_succ i hi ih =>
      unfold copy_initial_key_loop
      simp [hi, range'_eq_cons, ih, key_size]
      omega
  · by_cases hi : i = nk
    · simp [copy_initial_key_loop, hi]
    · have hi : ¬i < nk := by linarith
      have hn : nk - i = 0 := by omega
      simp [copy_initial_key_loop, hi, hn]

def copy_initial_key_loop.loop_form (w key : Array UInt8) (nk i : Nat) : Array UInt8 :=
  Aeneas.loop_form w nk i (fun w i ↦ w ++ key.extract (i * 4) ((i + 1) * 4))

lemma copy_initial_key_loop.loop_form_eq :
  copy_initial_key_loop.loop_form = copy_initial_key_loop :=
by
  funext w key nk i
  unfold loop_form
  by_cases hi : i ≤ nk
  · induction hi using Nat.decreasingInduction generalizing w with
    | self => simp [Aeneas.loop_form, copy_initial_key_loop]
    | of_succ i hi ih =>
      unfold Aeneas.loop_form copy_initial_key_loop
      simp [hi, range'_eq_cons, ← ih _]
  · by_cases hi : i = nk
    · simp [Aeneas.loop_form, copy_initial_key_loop, hi]
    · have hi : ¬i < nk := by linarith
      have hn : nk - i = 0 := by omega
      simp [Aeneas.loop_form, copy_initial_key_loop, hi, hn]

def copy_initial_key (w key : Array UInt8) (nk : Nat) : Array UInt8 :=
  copy_initial_key_loop w key nk 0

@[simp]
lemma copy_initial_key_size {key_size : key.size = nk * 4} : (copy_initial_key w key nk).size = w.size + nk * 4 := by
  simp [copy_initial_key, copy_initial_key_loop_size, key_size]

def expand_key_schedule_inner (w : Array UInt8) (nk i : Nat) (temp : Array UInt8) (temp_size : temp.size = 4) : Array UInt8 :=
  let prev_word := #[
    w[(i - nk) * 4]!, -- FIXME: bounds
    w[(i - nk) * 4 + 1]!, -- FIXME: bounds
    w[(i - nk) * 4 + 2]!, -- FIXME: bounds
    w[(i - nk) * 4 + 3]! -- FIXME: bounds
  ]
  have : prev_word.size = 4 := rfl
  let w := w.push (temp[0] ^^^ prev_word[0])
  let w := w.push (temp[1] ^^^ prev_word[1])
  let w := w.push (temp[2] ^^^ prev_word[2])
  let w := w.push (temp[3] ^^^ prev_word[3])
  w

@[simp]
lemma expand_key_schedule_inner_size : (expand_key_schedule_inner w nk i temp temp_size).size = w.size + 4 := by
  simp [expand_key_schedule_inner]

def expand_key_schedule_loop (w : Array UInt8) (nk total_words i : Nat) :
  Array UInt8 :=
  if h : i < total_words then
    let temp0 := w[(i - 1) * 4]! -- FIXME: bounds
    let temp1 := w[(i - 1) * 4 + 1]! -- FIXME: bounds
    let temp2 := w[(i - 1) * 4 + 2]! -- FIXME: bounds
    let temp3 := w[(i - 1) * 4 + 3]! -- FIXME: bounds

    if i % nk = 0 then
      let temp := #[temp0, temp1, temp2, temp3]
      let temp := sub_word (rot_word temp rfl) rfl
      let temp := temp.set! 0 (temp[0]! ^^^ AES.rcon[(i / nk) - 1]!) -- FIXME: bounds
      have temp_size : temp.size = 4 := by rename_i temp₀ temp₁; simp [temp, temp₁, temp₀]; rfl
      let w := expand_key_schedule_inner w nk i temp temp_size
      expand_key_schedule_loop w nk total_words (i + 1)
    else if nk > 6 then
      if i % nk = 4 then
        let temp := sub_word #[temp0, temp1, temp2, temp3] rfl
        let w := expand_key_schedule_inner w nk i temp rfl
        expand_key_schedule_loop w nk total_words (i + 1)
      else
        let w := expand_key_schedule_inner w nk i #[temp0, temp1, temp2, temp3] rfl
        expand_key_schedule_loop w nk total_words (i + 1)
    else
      let w := expand_key_schedule_inner w nk i #[temp0, temp1, temp2, temp3] rfl
      expand_key_schedule_loop w nk total_words (i + 1)
  else
    w

@[simp]
lemma expand_key_schedule_loop_size : (expand_key_schedule_loop w nk total_words i).size = w.size + (total_words - i) * 4 := by
  by_cases hi : i ≤ total_words
  · induction hi using Nat.decreasingInduction generalizing w with
    | self =>
      simp [expand_key_schedule_loop]
    | of_succ i hi ih =>
      unfold expand_key_schedule_loop
      simp [hi, range'_eq_cons, ih]
      split_ifs with h₀ h₁ <;> simp [ih] <;> omega
  · by_cases hi : i = total_words
    · simp [expand_key_schedule_loop, hi]
    · have hi : ¬i < total_words := by linarith
      have hn : total_words - i = 0 := by omega
      simp [expand_key_schedule_loop, hi, hn]

def expand_key_schedule (w : Array UInt8) (nk total_words : Nat) : Array UInt8 :=
  expand_key_schedule_loop w nk total_words nk

@[simp]
lemma expand_key_schedule_size : (expand_key_schedule w nk total_words).size = w.size + (total_words - nk) * 4 := by
  simp [expand_key_schedule]

def key_expansion (key : Array UInt8) (nk nr : Nat) : Array UInt8 :=
  let nb := 4
  let total_words := nb * (nr + 1)
  let w := copy_initial_key #[] key nk
  expand_key_schedule w nk total_words

@[simp]
lemma key_expansion_size {h : nk < nr} {key_size : key.size = nk * 4} : (key_expansion key nk nr).size = (nr + 1) * 16 := by
  simp [key_expansion, key_size, mul_comm 4 _]; omega

def sub_bytes (state : Array UInt8) : Array UInt8 :=
  state.map (fun byte => AES.sBox[byte.toNat]!)

@[simp]
lemma sub_bytes_size : (sub_bytes state).size = state.size := by simp [sub_bytes]

def inv_sub_bytes (state : Array UInt8) : Array UInt8 :=
  state.map (fun byte => AES.invSBox[byte.toNat]!)
@[simp]
lemma inv_sub_bytes_size : (inv_sub_bytes state).size = state.size := by simp [inv_sub_bytes]

def shift_rows (state : Array UInt8) (state_size : state.size = 16) : Array UInt8 :=
  #[state[0],  state[5],  state[10], state[15],
    state[4],  state[9],  state[14], state[3],
    state[8],  state[13], state[2],  state[7],
    state[12], state[1],  state[6],  state[11]]

@[simp]
lemma shift_rows_size : (shift_rows state state_size).size = 16 := by rfl

def inv_shift_rows (state : Array UInt8) (state_size : state.size = 16) : Array UInt8 :=
  #[state[0],  state[13], state[10], state[7],
    state[4],  state[1],  state[14], state[11],
    state[8],  state[5],  state[2],  state[15],
    state[12], state[9],  state[6],  state[3]]

@[simp]
lemma inv_shift_rows_size : (inv_shift_rows state state_size).size = 16 := by rfl

def mix_column (col : Array UInt8) (_h : col.size = 4) : Array UInt8 :=
  #[gf_mul 2 col[0]! ^^^ gf_mul 3 col[1]! ^^^ gf_mul 1 col[2]! ^^^ gf_mul 1 col[3]!,
    gf_mul 1 col[0]! ^^^ gf_mul 2 col[1]! ^^^ gf_mul 3 col[2]! ^^^ gf_mul 1 col[3]!,
    gf_mul 1 col[0]! ^^^ gf_mul 1 col[1]! ^^^ gf_mul 2 col[2]! ^^^ gf_mul 3 col[3]!,
    gf_mul 3 col[0]! ^^^ gf_mul 1 col[1]! ^^^ gf_mul 1 col[2]! ^^^ gf_mul 2 col[3]!]

@[simp]
lemma mix_column_size : (mix_column col col_size).size = 4 := by rfl

def inv_mix_column (col : Array UInt8) (_h : col.size = 4) : Array UInt8 :=
  #[gf_mul 14 col[0]! ^^^ gf_mul 11 col[1]! ^^^ gf_mul 13 col[2]! ^^^ gf_mul 9 col[3]!,
    gf_mul 9 col[0]! ^^^ gf_mul 14 col[1]! ^^^ gf_mul 11 col[2]! ^^^ gf_mul 13 col[3]!,
    gf_mul 13 col[0]! ^^^ gf_mul 9 col[1]! ^^^ gf_mul 14 col[2]! ^^^ gf_mul 11 col[3]!,
    gf_mul 11 col[0]! ^^^ gf_mul 13 col[1]! ^^^ gf_mul 9 col[2]! ^^^ gf_mul 14 col[3]!]

@[simp]
lemma inv_mix_column_size : (inv_mix_column col col_size).size = 4 := by rfl

def mix_columns_loop (state result : Array UInt8) (i : Nat)
  (state_size : state.size = 16) (result_size : result.size = 16) : Array UInt8 :=
  if h : i < 4 then
    let col := #[
      state[4 * i]!,
      state[4 * i + 1]!,
      state[4 * i + 2]!,
      state[4 * i + 3]!
    ]
    let mixed := mix_column col rfl
    have mixed_size : mixed.size = 4 := mix_column_size
    let result0 := result.set (4 * i) mixed[0]! (by omega)
    let result1 := result0.set (4 * i + 1) mixed[1]! (by simp [result0]; omega)
    let result2 := result1.set (4 * i + 2) mixed[2]! (by simp [result0, result1]; omega)
    let result3 := result2.set (4 * i + 3) mixed[3]! (by simp [result0, result1, result2]; omega)
    have result3_size : result3.size = 16 := by simp [result3, result2, result1, result0, result_size]
    mix_columns_loop state result3 (i + 1) state_size result3_size
  else
    result

@[simp]
lemma mix_columns_loop_size : (mix_columns_loop state result i state_size result_size).size = 16 := by
  by_cases hi : i ≤ 4
  · induction hi using Nat.decreasingInduction generalizing result with
    | self =>
      simp [mix_columns_loop, result_size]
    | of_succ i hi ih =>
      unfold mix_columns_loop
      simp [hi, range'_eq_cons, result_size, ih]
  · by_cases hi : i = 4
    · simp [mix_columns_loop, hi, result_size]
    · have hi : ¬i < 4 := by linarith
      have hn : 4 - i = 0 := by omega
      simp [mix_columns_loop, hi, hn, result_size]

def mix_columns_loop.loop_form (state result : Array UInt8) (i : Nat)
  (_state_size : state.size = 16) (_result_size : result.size = 16) : Array UInt8 :=
  Aeneas.loop_form result 4 i (fun result i ↦
    let col := #[
      state[4 * i]!,
      state[4 * i + 1]!,
      state[4 * i + 2]!,
      state[4 * i + 3]!
    ]
    let mixed := mix_column col rfl
    let result := result.set! (4 * i) mixed[0]!
    let result := result.set! (4 * i + 1) mixed[1]!
    let result := result.set! (4 * i + 2) mixed[2]!
    let result := result.set! (4 * i + 3) mixed[3]!
    result)

lemma mix_columns_loop.loop_form_eq : mix_columns_loop.loop_form = mix_columns_loop := by
  funext state result i state_size result_size
  unfold loop_form
  by_cases hi : i ≤ 4
  · induction hi using Nat.decreasingInduction generalizing result with
    | self => simp [Aeneas.loop_form, mix_columns_loop]
    | of_succ i hi ih =>
      unfold Aeneas.loop_form mix_columns_loop
      simp [hi, range'_eq_cons, ← ih _, Array.set_eq_set!]
  · by_cases hi : i = 4
    · simp [Aeneas.loop_form, mix_columns_loop, hi]
    · have hi : ¬i < 4 := by linarith
      have hn : 4 - i = 0 := by omega
      simp [Aeneas.loop_form, mix_columns_loop, hi, hn]

def mix_columns (state : Array UInt8) (state_size : state.size = 16) : Array UInt8 :=
  mix_columns_loop state (Array.mkArray 16 0) 0 state_size (by simp)

@[simp]
lemma mix_columns_size : (mix_columns state state_size).size = 16 := by
  simp [mix_columns]

def inv_mix_columns_loop (state result : Array UInt8) (i : Nat)
    (state_size : state.size = 16) (result_size : result.size = 16) : Array UInt8 :=
  if h : i < 4 then
    let col := #[
      state[4 * i]!,
      state[4 * i + 1]!,
      state[4 * i + 2]!,
      state[4 * i + 3]!
    ]
    let mixed := inv_mix_column col rfl
    let result0 := result.set (4 * i) mixed[0]! (by omega)
    let result1 := result0.set (4 * i + 1) mixed[1]! (by simp [result0]; omega)
    let result2 := result1.set (4 * i + 2) mixed[2]! (by simp [result0, result1]; omega)
    let result3 := result2.set (4 * i + 3) mixed[3]! (by simp [result0, result1, result2]; omega)
    have result3_size : result3.size = 16 := by simp [result3, result2, result1, result0, result_size]
    inv_mix_columns_loop state result3 (i + 1) state_size result3_size
  else
    result

@[simp]
lemma inv_mix_columns_loop_size : (inv_mix_columns_loop state result i state_size result_size).size = 16 := by
  by_cases hi : i ≤ 4
  · induction hi using Nat.decreasingInduction generalizing result with
    | self =>
      simp [inv_mix_columns_loop, result_size]
    | of_succ i hi ih =>
      unfold inv_mix_columns_loop
      simp [hi, range'_eq_cons, result_size, ih]
  · by_cases hi : i = 4
    · simp [inv_mix_columns_loop, hi, result_size]
    · have hi : ¬i < 4 := by linarith
      have hn : 4 - i = 0 := by omega
      simp [inv_mix_columns_loop, hi, hn, result_size]

def inv_mix_columns_loop.loop_form (state result : Array UInt8) (i : Nat)
  (_state_size : state.size = 16) (_result_size : result.size = 16) : Array UInt8 :=
  Aeneas.loop_form result 4 i (fun result i ↦
    let col := #[
      state[4 * i]!,
      state[4 * i + 1]!,
      state[4 * i + 2]!,
      state[4 * i + 3]!
    ]
    let mixed := inv_mix_column col rfl
    let result := result.set! (4 * i) mixed[0]!
    let result := result.set! (4 * i + 1) mixed[1]!
    let result := result.set! (4 * i + 2) mixed[2]!
    let result := result.set! (4 * i + 3) mixed[3]!
    result)

lemma inv_mix_columns_loop.loop_form_eq : inv_mix_columns_loop.loop_form = inv_mix_columns_loop := by
  funext state result i state_size result_size
  unfold loop_form
  by_cases hi : i ≤ 4
  · induction hi using Nat.decreasingInduction generalizing result with
    | self => simp [Aeneas.loop_form, inv_mix_columns_loop]
    | of_succ i hi ih =>
      unfold Aeneas.loop_form inv_mix_columns_loop
      simp [hi, range'_eq_cons, ← ih _, Array.set_eq_set!]
  · by_cases hi : i = 4
    · simp [Aeneas.loop_form, inv_mix_columns_loop, hi]
    · have hi : ¬i < 4 := by linarith
      have hn : 4 - i = 0 := by omega
      simp [Aeneas.loop_form, inv_mix_columns_loop, hi, hn]

def inv_mix_columns (state : Array UInt8) (state_size : state.size = 16) : Array UInt8 :=
  inv_mix_columns_loop state (Array.mkArray 16 0) 0 state_size (by simp)

@[simp]
lemma inv_mix_columns_size : (inv_mix_columns state state_size).size = 16 := by
  simp [inv_mix_columns]

def add_round_key_loop (state round_key result : Array UInt8) (i : Nat)
    (state_size : state.size = 16) (round_key_size : round_key.size = 16) (result_size : result.size = 16) : Array UInt8 :=
  if i < 16 then
    let result := result.set! i (state[i]! ^^^ round_key[i]!)
    have result_size : result.size = 16 := by simp [result, result_size]
    add_round_key_loop state round_key result (i + 1) state_size round_key_size result_size
  else
    result

@[simp]
lemma add_round_key_loop_size : (add_round_key_loop state round_key result i state_size round_key_size result_size).size = 16 := by
  by_cases hi : i ≤ 16
  · induction hi using Nat.decreasingInduction generalizing result with
    | self =>
      simp [add_round_key_loop, result_size]
    | of_succ i hi ih =>
      unfold add_round_key_loop
      simp [hi, range'_eq_cons, result_size, ih]
  · by_cases hi : i = 16
    · simp [add_round_key_loop, hi, result_size]
    · have hi : ¬i < 16 := by linarith
      have hn : 16 - i = 0 := by omega
      simp [add_round_key_loop, hi, hn, result_size]

def add_round_key (state round_key : Array UInt8) (state_size : state.size = 16) (round_key_size : round_key.size = 16) : Array UInt8 :=
  add_round_key_loop state round_key (Array.mkArray 16 0) 0 state_size round_key_size (by simp)

@[simp]
lemma add_round_key_size : (add_round_key state round_key state_size round_key_size).size = 16 := by
  simp [add_round_key]

lemma key_schedule_extract_size₀ {key_schedule : Array UInt8}
  (key_schedule_size : key_schedule.size = (nr + 1) * 16) :
  (key_schedule.extract 0 16).size = 16 := by simp; omega

lemma key_schedule_extract_size {round nr : Nat} {key_schedule : Array UInt8}
  (key_schedule_size : key_schedule.size = (nr + 1) * 16) (h : round ≤ nr := by omega) :
  (key_schedule.extract (round * 16) ((round + 1) * 16)).size = 16 :=
by simp [key_schedule_size]; omega

def cipher_loop_loop (state key_schedule : Array UInt8) (nr round : Nat)
    (state_size : state.size = 16) (key_schedule_size : key_schedule.size = (nr + 1) * 16) : Array UInt8 :=
  if h : round < nr then
    let state := sub_bytes state
    let state := shift_rows state (by simp [state, state_size])
    let state := mix_columns state (by simp [state, state_size])
    let round_key := key_schedule.extract (round * 16) ((round + 1) * 16)
    let state := add_round_key state round_key (by simp [state, state_size]) (key_schedule_extract_size key_schedule_size)
    cipher_loop_loop state key_schedule nr (round + 1) (by simp [state, state_size]) key_schedule_size
  else
    state

@[simp]
lemma cipher_loop_loop_size {round : Nat} : (cipher_loop_loop state key_schedule nr round state_size key_schedule_size).size = 16 := by
  by_cases hi : round ≤ nr
  · induction hi using Nat.decreasingInduction generalizing state with
    | self =>
      simp [cipher_loop_loop, state_size]
    | of_succ i hi ih =>
      unfold cipher_loop_loop
      simp [hi, range'_eq_cons, state_size, ih]
  · by_cases hi : round = nr
    · simp [cipher_loop_loop, hi, state_size]
    · have hi : ¬round < nr := by linarith
      have hn : nr - round = 0 := by omega
      simp [cipher_loop_loop, hi, hn, state_size]

-- def cipher_loop_loop.loop_form (state key_schedule : Array UInt8) (nr round : Nat)
--     (state_size : state.size = 16) (key_schedule_size : key_schedule.size = (nr + 1) * 16) : Array UInt8 :=
--   Aeneas.loop_form state nr round fun state round ↦
--     let state := sub_bytes state
--     let state := shift_rows state sorry
--     let state := mix_columns state sorry
--     let round_key := key_schedule.extract (round * 16) ((round + 1) * 16)
--     let state := add_round_key state round_key sorry sorry
--     state

-- lemma cipher_loop_loop.loop_form_eq : cipher_loop_loop.loop_form = cipher_loop_loop := by
--   funext state key_schedule nr round state_size
--   unfold loop_form
--   by_cases hi : round ≤  nr
--   · induction hi using Nat.decreasingInduction generalizing state with
--     | self => simp [Aeneas.loop_form, cipher_loop_loop]
--     | of_succ i hi ih =>
--       unfold Aeneas.loop_form cipher_loop_loop
--       simp [hi, range'_eq_cons, ← ih _]
--   · by_cases hi : round = nr
--     · simp [Aeneas.loop_form, cipher_loop_loop, hi]
--     · have hi : ¬round < nr := by linarith
--       have hn : nr - round = 0 := by omega
--       simp [Aeneas.loop_form, cipher_loop_loop, hi, hn]

def cipher_loop (state key_schedule : Array UInt8) (nr : Nat)
    (state_size : state.size = 16) (key_schedule_size : key_schedule.size = (nr + 1) * 16) :=
  cipher_loop_loop state key_schedule nr 1 state_size key_schedule_size

@[simp]
lemma cipher_loop_size : (cipher_loop state key_schedule nr state_size key_schedule_size).size = 16 := by
  simp [cipher_loop]

def cipher (state key_schedule : Array UInt8) (nr : Nat)
  (state_size : state.size = 16) (key_schedule_size : key_schedule.size = (nr + 1) * 16) : Array UInt8 :=
  let state0 := add_round_key state (key_schedule.extract 0 16) state_size (key_schedule_extract_size₀ key_schedule_size)
  let state1 := cipher_loop state0 key_schedule nr (by simp [state0]) key_schedule_size
  let state2 := sub_bytes state1
  let state3 := shift_rows state2 (by simp [state2, state1])
  let round_key := key_schedule.extract (nr * 16) ((nr + 1) * 16)
  add_round_key state3 round_key (by simp [state3]) (key_schedule_extract_size key_schedule_size)

def inv_cipher_loop_loop (state key_schedule : Array UInt8) (nr round_idx : Nat)
    (state_size : state.size = 16) (key_schedule_size : key_schedule.size = (nr + 1) * 16) : Array UInt8 :=
  if round_idx < nr then
    let round := nr - round_idx
    let state0 := inv_shift_rows state state_size
    let state1 := inv_sub_bytes state0
    let round_key := key_schedule.extract (round * 16) ((round + 1) * 16)
    let state2 := add_round_key state1 round_key (by simp [state1, state0]) (key_schedule_extract_size key_schedule_size)
    let state3 := inv_mix_columns state2 (by simp [state2, state1, state0])
    inv_cipher_loop_loop state3 key_schedule nr (round_idx + 1) (by simp [state3, state2, state1, state0]) key_schedule_size
  else
    state

@[simp]
lemma inv_cipher_loop_loop_size {round : Nat} : (inv_cipher_loop_loop state key_schedule nr round state_size key_schedule_size).size = 16 := by
  by_cases hi : round ≤ nr
  · induction hi using Nat.decreasingInduction generalizing state with
    | self =>
      simp [inv_cipher_loop_loop, state_size]
    | of_succ i hi ih =>
      unfold inv_cipher_loop_loop
      simp [hi, range'_eq_cons, state_size, ih]
  · by_cases hi : round = nr
    · simp [inv_cipher_loop_loop, hi, state_size]
    · have hi : ¬round < nr := by linarith
      have hn : nr - round = 0 := by omega
      simp [inv_cipher_loop_loop, hi, hn, state_size]

-- def inv_cipher_loop_loop.loop_form (state key_schedule : Array UInt8) (nr round_idx : Nat)
--     (state_size : state.size = 16) (key_schedule_size : key_schedule.size = (nr + 1) * 16) : Array UInt8 :=
--   Aeneas.loop_form state nr round_idx fun state round_idx ↦
--     let round := nr - round_idx
--     let state := inv_shift_rows state sorry
--     let state := inv_sub_bytes state
--     let round_key := key_schedule.extract (round * 16) ((round + 1) * 16)
--     let state := add_round_key state round_key sorry (key_schedule_extract_size key_schedule_size)
--     let state := inv_mix_columns state sorry
--     state

-- lemma inv_cipher_loop_loop.loop_form_eq : inv_cipher_loop_loop.loop_form = inv_cipher_loop_loop := by
--   funext state key_schedule nr round_idx state_size
--   unfold loop_form
--   by_cases hi : round_idx ≤  nr
--   · induction hi using Nat.decreasingInduction generalizing state with
--     | self => simp [Aeneas.loop_form, inv_cipher_loop_loop]
--     | of_succ i hi ih =>
--       unfold Aeneas.loop_form inv_cipher_loop_loop
--       simp [hi, range'_eq_cons, ← ih _]
--   · by_cases hi : round_idx = nr
--     · simp [Aeneas.loop_form, inv_cipher_loop_loop, hi]
--     · have hi : ¬round_idx < nr := by linarith
--       have hn : nr - round_idx = 0 := by omega
--       simp [Aeneas.loop_form, inv_cipher_loop_loop, hi, hn]

def inv_cipher_loop (state key_schedule : Array UInt8) (nr : Nat)
    (state_size : state.size = 16) (key_schedule_size : key_schedule.size = (nr + 1) * 16) : Array UInt8 :=
  inv_cipher_loop_loop state key_schedule nr 1 state_size key_schedule_size

@[simp]
lemma inv_cipher_loop_size : (inv_cipher_loop state key_schedule nr state_size key_schedule_size).size = 16 := by
  simp [inv_cipher_loop]

def inv_cipher (state key_schedule : Array UInt8) (nr : Nat)
  (state_size : state.size = 16) (key_schedule_size : key_schedule.size = (nr + 1) * 16) : Array UInt8 :=
  let round_key := key_schedule.extract (nr * 16) ((nr + 1) * 16)
  let state0 := add_round_key state round_key state_size (key_schedule_extract_size key_schedule_size)
  let state1 := inv_cipher_loop state0 key_schedule nr (by simp [state0, state_size]) key_schedule_size
  let state2 := inv_shift_rows state1 (by simp [state0, state1, state_size])
  let state3 := inv_sub_bytes state2
  let round_key := key_schedule.extract 0 16
  add_round_key state3 round_key (by simp [state3, state2]) (key_schedule_extract_size₀ key_schedule_size)

def aes128 (input : Array UInt8) (key : Array UInt8) (input_size : input.size = 16) (key_size : key.size = 16) : Array UInt8 :=
  let key_schedule := key_expansion key 4 10
  cipher input key_schedule 10 input_size (by simp [key_schedule, key_size])

def aes192 (input : Array UInt8) (key : Array UInt8) (input_size : input.size = 16) (key_size : key.size = 24) : Array UInt8 :=
  let key_schedule := key_expansion key 6 12
  cipher input key_schedule 12 input_size (by simp [key_schedule, key_size])

def aes256 (input : Array UInt8) (key : Array UInt8) (input_size : input.size = 16) (key_size : key.size = 32) : Array UInt8 :=
  let key_schedule := key_expansion key 8 14
  cipher input key_schedule 14 input_size (by simp [key_schedule, key_size])

def aes128_inv (input : Array UInt8) (key : Array UInt8) (input_size : input.size = 16) (key_size : key.size = 16) : Array UInt8 :=
  let key_schedule := key_expansion key 4 10
  inv_cipher input key_schedule 10 input_size (by simp [key_schedule, key_size])

def aes192_inv (input : Array UInt8) (key : Array UInt8) (input_size : input.size = 16) (key_size : key.size = 24) : Array UInt8 :=
  let key_schedule := key_expansion key 6 12
  inv_cipher input key_schedule 12 input_size (by simp [key_schedule, key_size])

def aes256_inv (input : Array UInt8) (key : Array UInt8) (input_size : input.size = 16) (key_size : key.size = 32) : Array UInt8 :=
  let key_schedule := key_expansion key 8 14
  inv_cipher input key_schedule 14 input_size (by simp [key_schedule, key_size])



end Translated
