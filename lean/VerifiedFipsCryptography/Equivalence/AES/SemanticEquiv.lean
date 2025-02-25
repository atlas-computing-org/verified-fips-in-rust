import VerifiedFipsCryptography.Specs.AES.AES
import VerifiedFipsCryptography.Equivalence.AES.Translated
import VerifiedFipsCryptography.Equivalence.AES.Structured
import VerifiedFipsCryptography.Equivalence.AES.StructuralEquiv
import VerifiedFipsCryptography.Equivalence.AES.Lemmas
import VerifiedFipsCryptography.ForBatteries

namespace SemanticEquiv

lemma test_bit :
  let res_l := AES.testBit b i
  let res_t := Translated.test_bit b i
  res_t = res_l :=
by
  unfold AES.testBit Translated.test_bit
  -- Need better `bv_decide` support.
  sorry

lemma xtime :
  let res_l := AES.xtime b
  let res_t := Translated.xtime b
  res_t = res_l :=
by
  unfold AES.xtime Translated.xtime
  rw [← test_bit]

lemma gf_mul_loop :
  let res_l := Structured.gf_mul_loop a b result i
  let res_t := Translated.gf_mul_loop a b result i
  res_t = res_l :=
by
  unfold Structured.gf_mul_loop
  simp [Id.run]
  by_cases hi : i ≤ 8
  · induction hi using Nat.decreasingInduction generalizing a b result with
    | self => simp [Aeneas.loop_form, Translated.gf_mul_loop]
    | of_succ i hi ih =>
      unfold Translated.gf_mul_loop
      simp [hi, range'_eq_cons, ← xtime] at ih ⊢
      split_ifs with h <;> simp [← ih]
  · by_cases hi : i = 8
    · simp [Aeneas.loop_form, Translated.gf_mul_loop, hi]
    · have hi : ¬i < 8 := by linarith
      have hn : 8 - i = 0 := by omega
      simp [Translated.gf_mul_loop, hi, hn]

lemma gf_mul :
  let res_l := Structured.gf_mul a b
  let res_t := Translated.gf_mul a b
  res_t = res_l :=
by
  unfold Structured.gf_mul Translated.gf_mul
  rw [gf_mul_loop]

lemma rot_word :
  let res_l := AES.rotWord word
  let res_t := Translated.rot_word word word_size
  res_t = res_l :=
by
  dsimp [Translated.rot_word, AES.rotWord]
  have h0 : word.extract 1 4 = #[word[1], word[2], word[3]] := by match word, word_size with | ⟨[a, b, c, d]⟩, _ => simp
  have h1 : word.extract 0 1 = #[word[0]] := by match word, word_size with | ⟨[a, b, c, d]⟩, _ => simp
  simp [word_size, beq_self_eq_true, ↓reduceIte, h0, h1]

set_option maxRecDepth 1000 in
lemma sub_word :
  let res_l := AES.subWord word
  let res_t := Translated.sub_word word word_size
  res_t = res_l :=
by
  dsimp [Translated.sub_word, AES.subWord]
  -- Have to do a really weird `rw` here
  conv => right; rw [word.of_size_eq_4 word_size]
  simp

lemma copy_initial_key :
  let res_l := Structured.copy_initial_key key nk total_words
  let res_t := Translated.copy_initial_key #[] key nk
  res_t = res_l :=
by
  unfold Structured.copy_initial_key Structured.copy_initial_key_loop Translated.copy_initial_key
  rw [← Translated.copy_initial_key_loop.loop_form_eq]
  dsimp [Translated.copy_initial_key_loop.loop_form]
  simp_rw [← for_loop_eq_loop_form #[] _, Nat.mul_comm _ 4]
  dsimp [Id.run]

lemma expand_key_schedule_inner (hnk : 0 < nk) (h : nk ≤ i) (w_size : w.size = 4 * i) :
  let res_l := Structured.expand_key_schedule_inner w nk i temp
  let res_t := Translated.expand_key_schedule_inner w nk i temp temp_size
  res_t = res_l :=
by
  unfold Structured.expand_key_schedule_inner Translated.expand_key_schedule_inner
  dsimp
  have : w.extract (4 * (i - nk)) (4 * (i - nk + 1)) =
    #[w[(i - nk) * 4]!, w[(i - nk) * 4 + 1]!, w[(i - nk) * 4 + 2]!, w[(i - nk) * 4 + 3]!] :=
  by
    ext i hi hi'
    · simp [w_size]; omega
    -- This needs a hammer thingy for arrays.
    · sorry
  conv => right; right; rw [temp.of_size_eq_4 temp_size]
  simp [this]
  rfl

lemma expand_key_schedule_loop (hnk : 0 < nk) (h : nk ≤ i) (w_size : w.size = 4 * i) :
  let res_l := Structured.expand_key_schedule_loop w nk total_words i
  let res_t := Translated.expand_key_schedule_loop w nk total_words i
  res_t = res_l :=
by
  unfold Structured.expand_key_schedule_loop
  dsimp
  by_cases hi : i ≤ total_words
  · induction hi using Nat.decreasingInduction generalizing w with
    | self => simp [Translated.expand_key_schedule_loop, Id.run]
    | of_succ i hi ih =>
      unfold Translated.expand_key_schedule_loop
      simp [hi, range'_eq_cons hi]
      have : w.extract (4 * (i - 1)) (4 * i) = #[w[(i - 1) * 4]!, w[(i - 1) * 4 + 1]!, w[(i - 1) * 4 + 2]!, w[(i - 1) * 4 + 3]!] := by
        -- This needs a hammer thingy for arrays.
        sorry
      -- The `if/elseif/else` makes it very painful.
      by_cases h₀ : i % nk = 0
      · by_cases h₁ : 6 < nk ∧ i % nk = 4
        · simp [h₀, h₁] at *
        · simp [h₀, h₁] at ih ⊢
          rw [← ih (by omega), expand_key_schedule_inner hnk h w_size, sub_word, rot_word, this]
          rw [Structured.expand_key_schedule_inner_size hnk h w_size (by simp [this, Array.size_setIfInBounds])]
          omega
      · by_cases h₁ : 6 < nk ∧ i % nk = 4
        · simp [h₀, h₁] at ih ⊢
          rw [← ih (by omega), expand_key_schedule_inner hnk h w_size, sub_word, this]
          rw [Structured.expand_key_schedule_inner_size hnk h w_size (by simp [this])]
          omega
        · rw [not_and_or] at h₁
          cases h₁ with
          | inl h₁ =>
            simp [h₀, h₁] at ih ⊢
            rw [← ih (by omega), expand_key_schedule_inner hnk h w_size, this]
            rw [Structured.expand_key_schedule_inner_size hnk h w_size (by simp [this])]
            omega
          | inr h₁ =>
            simp [h₀, h₁] at ih ⊢
            rw [← ih (by omega), expand_key_schedule_inner hnk h w_size, this]
            rw [Structured.expand_key_schedule_inner_size hnk h w_size (by simp [this])]
            omega
  · by_cases hi : i = total_words
    · simp [hi, Translated.expand_key_schedule_loop, Id.run]
    · have hi : ¬i < total_words := by linarith
      have hn : total_words - i = 0 := by omega
      simp [hi, hn, Translated.expand_key_schedule_loop, Id.run]

lemma expand_key_schedule (hnk : 0 < nk) (w_size : w.size = 4 * nk) :
  let res_l := Structured.expand_key_schedule w nk total_words
  let res_t := Translated.expand_key_schedule w nk total_words
  res_t = res_l :=
by
  unfold Structured.expand_key_schedule Translated.expand_key_schedule
  rw [expand_key_schedule_loop hnk le_rfl w_size]


lemma key_expansion (hnk : 0 < nk) (key_size : key.size = 4 * nk) :
  let res_l := Structured.key_expansion key nk nr
  let res_t := Translated.key_expansion key nk nr
  res_t = res_l :=
by
  unfold Structured.key_expansion Translated.key_expansion
  rw [@copy_initial_key key nk (4 * (nr + 1)), expand_key_schedule hnk]
  rw [Structured.copy_initial_key_size key_size]

lemma sub_bytes :
  let res_l := AES.subBytes state
  let res_t := Translated.sub_bytes state
  res_t = res_l :=
by
  unfold AES.subBytes Translated.sub_bytes
  simp

lemma inv_sub_bytes :
  let res_l := AES.invSubBytes state
  let res_t := Translated.inv_sub_bytes state
  res_t = res_l :=
by
  unfold AES.invSubBytes Translated.inv_sub_bytes
  simp

lemma shift_rows :
  let res_l := AES.shiftRows state
  let res_t := Translated.shift_rows state state_size
  res_t = res_l :=
by
  unfold AES.shiftRows Translated.shift_rows
  simp [state_size]

lemma inv_shift_rows :
  let res_l := AES.invShiftRows state
  let res_t := Translated.inv_shift_rows state state_size
  res_t = res_l :=
by
  unfold AES.invShiftRows Translated.inv_shift_rows
  simp [state_size]

lemma mix_column :
  let res_l := AES.mixColumn col
  let res_t := Translated.mix_column col col_size
  res_t = res_l :=
by
  unfold AES.mixColumn Translated.mix_column
  simp [col_size, gf_mul, StructuralEquiv.gf_mul, Array.get!_eq_get]

lemma inv_mix_column :
  let res_l := AES.invMixColumn col
  let res_t := Translated.inv_mix_column col col_size
  res_t = res_l :=
by
  unfold AES.invMixColumn Translated.inv_mix_column
  simp [col_size, gf_mul, StructuralEquiv.gf_mul, Array.get!_eq_get]

lemma mix_columns_loop :
  let res_l := Structured.mix_columns_loop state (result.extract 0 (4 * i)) i
  let res_t := Translated.mix_columns_loop state result i state_size result_size
  res_t = res_l :=
by
  unfold Structured.mix_columns_loop
  rw [← Translated.mix_columns_loop.loop_form_eq, Translated.mix_columns_loop.loop_form, ← for_loop_eq_loop_form result _]
  simp [Id.run, ← mix_column]
  by_cases hi : i ≤ 4
  · induction hi using Nat.decreasingInduction generalizing result with
    | self => simp [Aeneas.loop_form, mix_columns_loop, ← result_size]
    | of_succ i hi ih =>
      let col := #[state[4 * i]!, state[4 * i + 1]!, state[4 * i + 2]!, state[4 * i + 3]!];
      let mixed := Translated.mix_column col rfl;
      let result0 := result.set! (4 * i) mixed[0]!;
      let result1 := result0.set! (4 * i + 1) mixed[1]!;
      let result2 := result1.set! (4 * i + 2) mixed[2]!;
      let result3 := result2.set! (4 * i + 3) mixed[3]!;
      have result3_size : result3.size = 16 := by simp [result3, result2, result1, result0, Array.size_set!, result_size]
      have ih := @ih result3 result3_size
      have : (result.extract 0 (4 * i) ++ mixed) = result3.extract 0 (4 * (i + 1)) := by
        -- Need more lemmas to reason about Array/Subarray + push/set!.
        sorry
      simp [hi, range'_eq_cons] at ih ⊢
      rw [this, ← ih]
      congr
  · by_cases hi : i = 4
    · simp [Aeneas.loop_form, mix_columns_loop, hi, ← result_size]
    · have hi : ¬i < 4 := by linarith
      have hn : 4 - i = 0 := by omega
      have hle : result.size ≤ (4 * i) := by omega
      simp [Aeneas.loop_form, mix_columns_loop, Array.extract_all' _ hle, hi, hn]

lemma mix_columns :
  let res_l := Structured.mix_columns state
  let res_t := Translated.mix_columns state state_size
  res_t = res_l :=
by
  unfold Structured.mix_columns Translated.mix_columns
  simp [state_size, mix_columns_loop, Id.run]

lemma inv_mix_columns_loop :
  let res_l := Structured.inv_mix_columns_loop state (result.extract 0 (4 * i)) i
  let res_t := Translated.inv_mix_columns_loop state result i state_size result_size
  res_t = res_l :=
by
  unfold Structured.inv_mix_columns_loop
  rw [← Translated.inv_mix_columns_loop.loop_form_eq, Translated.inv_mix_columns_loop.loop_form, ← for_loop_eq_loop_form result _]
  simp [Id.run, ← inv_mix_column]
  by_cases hi : i ≤ 4
  · induction hi using Nat.decreasingInduction generalizing result with
    | self => simp [Aeneas.loop_form, inv_mix_columns_loop, ← result_size]
    | of_succ i hi ih =>
      let col := #[state[4 * i]!, state[4 * i + 1]!, state[4 * i + 2]!, state[4 * i + 3]!];
      let mixed := Translated.inv_mix_column col rfl;
      let result0 := result.set! (4 * i) mixed[0]!;
      let result1 := result0.set! (4 * i + 1) mixed[1]!;
      let result2 := result1.set! (4 * i + 2) mixed[2]!;
      let result3 := result2.set! (4 * i + 3) mixed[3]!;
      have result3_size : result3.size = 16 := by simp [result3, result2, result1, result0, Array.size_set!, result_size]
      have ih := @ih result3 result3_size
      have : (result.extract 0 (4 * i) ++ mixed) = result3.extract 0 (4 * (i + 1)) := by
        -- Need more lemmas to reason about Array/Subarray + push/set!.
        sorry
      simp [hi, range'_eq_cons] at ih ⊢
      rw [this, ← ih]
      congr
  · by_cases hi : i = 4
    · simp [Aeneas.loop_form, mix_columns_loop, hi, ← result_size]
    · have hi : ¬i < 4 := by linarith
      have hn : 4 - i = 0 := by omega
      have hle : result.size ≤ (4 * i) := by omega
      simp [Aeneas.loop_form, mix_columns_loop, Array.extract_all' _ hle, hi, hn]

lemma inv_mix_columns :
  let res_l := Structured.inv_mix_columns state
  let res_t := Translated.inv_mix_columns state state_size
  res_t = res_l :=
by
  unfold Structured.inv_mix_columns Translated.inv_mix_columns
  simp [state_size, inv_mix_columns_loop, Id.run]

lemma add_round_key_loop :
  let res_l := (result.extract 0 i) ++ (state.extract i state.size).zipWith (round_key.extract i round_key.size) (· ^^^ ·)
  let res_t := Translated.add_round_key_loop state round_key result i state_size round_key_size result_size
  res_t = res_l :=
by
  by_cases hi : i ≤ 16
  · induction hi using Nat.decreasingInduction generalizing result with
    | self =>
      unfold Translated.add_round_key_loop
      nth_rw 1 [← result_size];
      nth_rw 2 [← round_key_size]; simp
      nth_rw 1 [← state_size]; simp
    | of_succ i hi ih =>
      unfold Translated.add_round_key_loop
      simp [hi]
      have h0 : (state.extract i state.size).zipWith (round_key.extract i round_key.size) (· ^^^ ·) =
              #[state[i]! ^^^ round_key[i]!] ++ (state.extract (i + 1) state.size).zipWith (round_key.extract (i + 1) round_key.size) (· ^^^ ·) :=
      by
        -- Need better array lemmas to reason about zipWith.
        sorry
      have h1 : result.extract 0 i ++ #[state[i]! ^^^ round_key[i]!] =
                (result.setIfInBounds i (state[i]! ^^^ round_key[i]!)).extract 0 (i + 1) :=
      by
        -- Need better array lemmas to reason about extract.
        sorry
      rw [h0, ← Array.append_assoc, h1, ← @ih _ (by simp [result_size])]
  · by_cases hi : i = 16
    · simp [Translated.add_round_key_loop, hi, state_size, round_key_size]; rw [← result_size]; simp
    · have hi : ¬i < 16 := by linarith
      have hn : 16 - i = 0 := by omega
      simp [hi]
      -- Missing extract lemmas but this is obviously true.
      sorry

lemma add_round_key :
  let res_l := AES.addRoundKey state round_key
  let res_t := Translated.add_round_key state round_key state_size round_key_size
  res_t = res_l :=
by
  unfold AES.addRoundKey Translated.add_round_key
  simp [add_round_key_loop]

lemma congr_add_round_key (h_state : state = state') (h_round_key : round_key = round_key') :
  let res_l := AES.addRoundKey state round_key
  let res_t := Translated.add_round_key state' round_key' state_size round_key_size
  res_t = res_l :=
by
  unfold AES.addRoundKey Translated.add_round_key
  simp [h_state, h_round_key, add_round_key_loop]

lemma cipher_loop {round : Nat} :
  let res_l := Structured.cipher_loop state key_schedule nr round
  let res_t := Translated.cipher_loop_loop state key_schedule nr round state_size key_schedule_size
  res_t = res_l :=
by
  by_cases hi : round ≤  nr
  · induction hi using Nat.decreasingInduction generalizing state with
    | self => simp [Translated.cipher_loop_loop, Structured.cipher_loop, Id.run]
    | of_succ i hi ih =>
      unfold Translated.cipher_loop_loop Structured.cipher_loop
      simp [Id.run, hi, range'_eq_cons, ih]
      unfold Structured.cipher_loop;
      simp [Id.run]
      rw [← sub_bytes, ← shift_rows, ← mix_columns, ← add_round_key]
  · by_cases hi : round = nr
    · simp [Translated.cipher_loop_loop, Structured.cipher_loop, Id.run, hi]
    · have hi : ¬round < nr := by linarith
      have hn : nr - round = 0 := by omega
      simp [Translated.cipher_loop_loop, Structured.cipher_loop, Id.run, hi, hn]

lemma cipher :
  let res_l := Structured.cipher input key_schedule nr
  let res_t := Translated.cipher input key_schedule nr input_size key_schedule_size
  res_t = res_l :=
by
  unfold Structured.cipher Translated.cipher
  simp only [Id.run, Translated.cipher_loop]
  rw [← @add_round_key input _ input_size (by simp [key_schedule_size])]
  rw [add_round_key, shift_rows, sub_bytes, cipher_loop]

lemma inv_cipher_loop :
  let res_l := Structured.inv_cipher_loop state key_schedule nr round_idx
  let res_t := Translated.inv_cipher_loop_loop state key_schedule nr round_idx state_size key_schedule_size
  res_t = res_l :=
by
  by_cases hi : round_idx ≤  nr
  · induction hi using Nat.decreasingInduction generalizing state with
    | self => simp [Translated.inv_cipher_loop_loop, Structured.inv_cipher_loop, Id.run]
    | of_succ i hi ih =>
      unfold Translated.inv_cipher_loop_loop Structured.inv_cipher_loop
      simp [Id.run, hi, range'_eq_cons, ih]
      unfold Structured.inv_cipher_loop;
      simp [Id.run]
      rw [← inv_shift_rows, ← inv_sub_bytes, ← add_round_key, ← inv_mix_columns]
  · by_cases hi : round_idx = nr
    · simp [Translated.inv_cipher_loop_loop, Structured.inv_cipher_loop, Id.run, hi]
    · have hi : ¬round_idx < nr := by linarith
      have hn : nr - round_idx = 0 := by omega
      simp [Translated.inv_cipher_loop_loop, Structured.inv_cipher_loop, Id.run, hi, hn]

lemma inv_cipher :
  let res_l := Structured.inv_cipher input key_schedule nr
  let res_t := Translated.inv_cipher input key_schedule nr input_size key_schedule_size
  res_t = res_l :=
by
  unfold Structured.inv_cipher Translated.inv_cipher
  simp only [Id.run, Translated.inv_cipher_loop]
  rw [← @add_round_key input _ input_size (Translated.key_schedule_extract_size key_schedule_size)]
  rw [add_round_key, inv_sub_bytes, inv_shift_rows, inv_cipher_loop]

lemma aes128 :
  let res_l := AES.AES128 input key
  let res_t := Translated.aes128 input key input_size key_size
  res_t = res_l :=
by
  unfold AES.AES128 Translated.aes128
  rw [cipher, ← StructuralEquiv.cipher, key_expansion, ← StructuralEquiv.key_expansion] <;> omega

lemma aes192 :
  let res_l := AES.AES192 input key
  let res_t := Translated.aes192 input key input_size key_size
  res_t = res_l :=
by
  unfold AES.AES192 Translated.aes192
  rw [cipher, ← StructuralEquiv.cipher, key_expansion, ← StructuralEquiv.key_expansion] <;> omega

lemma aes256 :
  let res_l := AES.AES256 input key
  let res_t := Translated.aes256 input key input_size key_size
  res_t = res_l :=
by
  unfold AES.AES256 Translated.aes256
  rw [cipher, ← StructuralEquiv.cipher, key_expansion, ← StructuralEquiv.key_expansion] <;> omega

lemma aes128_inv :
  let res_l := AES.AES128Inv input key
  let res_t := Translated.aes128_inv input key input_size key_size
  res_t = res_l :=
by
  unfold AES.AES128Inv Translated.aes128_inv
  rw [inv_cipher, ← StructuralEquiv.inv_cipher, key_expansion, ← StructuralEquiv.key_expansion] <;> omega

lemma aes192_inv :
  let res_l := AES.AES192Inv input key
  let res_t := Translated.aes192_inv input key input_size key_size
  res_t = res_l :=
by
  unfold AES.AES192Inv Translated.aes192_inv
  rw [inv_cipher, ← StructuralEquiv.inv_cipher, key_expansion, ← StructuralEquiv.key_expansion] <;> omega

lemma aes256_inv :
  let res_l := AES.AES256Inv input key
  let res_t := Translated.aes256_inv input key input_size key_size
  res_t = res_l :=
by
  unfold AES.AES256Inv Translated.aes256_inv
  rw [inv_cipher, ← StructuralEquiv.inv_cipher, key_expansion, ← StructuralEquiv.key_expansion] <;> omega

end SemanticEquiv
