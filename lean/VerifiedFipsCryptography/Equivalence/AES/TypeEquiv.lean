import VerifiedFipsCryptography.Specs.AES.AES
import VerifiedFipsCryptography.Equivalence.AES.Translated
import VerifiedFipsCryptography.RustTranslations.FipsImplementations

/-

# Sorry's

The `sorry`s in this file were agreed to be left. A proof-of-concept of how to fill out
these type-equiv `sorry`s can be found in the `SHA1` example.

-/

namespace TypeEquiv
open Aeneas.Std fips_implementations algorithms alloc.vec core clone num

lemma SBOX_body : aes.SBOX_body = Result.ok AES.sBox.toArrayU8 := by
  unfold aes.SBOX_body Array.toArrayU8; congr

lemma invSBOX_body : aes.INV_SBOX_body = Result.ok AES.invSBox.toArrayU8 := by
  unfold aes.INV_SBOX_body Array.toArrayU8; congr

lemma test_bit :
  let res_t := Translated.test_bit b i
  let res_r := aes.test_bit b.toU8 i.toU8
  res_r = .ok res_t :=
by
  sorry

lemma xtime :
  let res_t := Translated.xtime b
  let res_r := aes.xtime b.toU8
  res_r = .ok res_t.toU8 :=
by
  sorry

lemma gf_mul :
  let res_t := Translated.gf_mul a b
  let res_r := aes.gf_mul a.toU8 b.toU8
  res_r = .ok res_t.toU8 :=
by
  sorry

@[simp]
lemma rot_word_size : (Translated.rot_word word word_size).size = Usize.toNat 4#usize := by
  simp [Translated.rot_word_size]

lemma rot_word :
  let res_t := Translated.rot_word word word_size
  let res_r := aes.rot_word word.toArrayU8
  res_r = .ok (res_t.toArrayU8 rot_word_size) :=
by
  sorry

@[simp]
lemma sub_word_size : (Translated.sub_word word word_size).size = Usize.toNat 4#usize := by
  simp [Translated.sub_word_size]

lemma sub_word :
  let res_t := Translated.sub_word word word_size
  let res_r := aes.sub_word word.toArrayU8
  res_r = .ok (res_t.toArrayU8 sub_word_size) :=
by
  sorry

lemma expand_key_schedule_inner (w_size : w.size + 4 < USize.size) :
  let res_t := Translated.expand_key_schedule_inner w nk i temp temp_size
  let res_r := aes.expand_key_schedule_inner (w.toVecU8 (by omega)) nk.toUsize i.toUsize temp.toArrayU8
  res_r = .ok (res_t.toVecU8 (by simpa [res_t])) :=
by
  sorry

lemma expand_key_schedule_loop (w_size : w.size + (total_words - i) * 4 < USize.size) :
  let res_t := Translated.expand_key_schedule_loop w nk total_words i
  let res_r := aes.expand_key_schedule_loop (w.toVecU8 (by omega)) nk.toUsize total_words.toUsize i.toUsize
  res_r = .ok (res_t.toVecU8 (by simpa [res_t])) :=
by
  sorry

@[simp]
lemma expand_key_schedule_size (w_size : w.size + (total_words - nk) * 4 < USize.size) : (Translated.expand_key_schedule w nk total_words).size < USize.size := by
  simpa

lemma expand_key_schedule (w_size : w.size + (total_words - nk) * 4 < USize.size) :
  let res_t := Translated.expand_key_schedule w nk total_words
  let res_r := aes.expand_key_schedule (w.toVecU8 (by omega)) nk.toUsize total_words.toUsize
  res_r = .ok (res_t.toVecU8 (expand_key_schedule_size w_size)) :=
by
  sorry

lemma key_expansion (h : nk < nr) (key_size : key.size = nk * 4) (nr_size : (nr + 1) * 16 < USize.size
) :
  let res_t := Translated.key_expansion key nk nr
  let res_r := aes.key_expansion (key.toVecU8 key_size') nk.toUsize nr.toUsize
  res_r = .ok (res_t.toVecU8 (by rwa [Translated.key_expansion_size h key_size])) :=
by
  unfold Translated.key_expansion aes.key_expansion
  -- automation to deal with this
  sorry

lemma sub_bytes :
  let res_t := Translated.sub_bytes state
  let res_r := aes.sub_bytes (state.toVecU8 state_size)
  res_r = .ok (res_t.toVecU8 (by simpa [res_t])) :=
by
  sorry

lemma inv_sub_bytes :
  let res_t := Translated.inv_sub_bytes state
  let res_r := aes.inv_sub_bytes (state.toVecU8 state_size)
  res_r = .ok (res_t.toVecU8 (by simpa [res_t])) :=
by
  sorry

lemma shift_rows :
  let res_t := Translated.shift_rows state state_size
  let res_r := aes.shift_rows state.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma inv_shift_rows :
  let res_t := Translated.inv_shift_rows state state_size
  let res_r := aes.inv_shift_rows state.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma mix_column :
  let res_t := Translated.mix_column col col_size
  let res_r := aes.mix_column col.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma inv_mix_column :
  let res_t := Translated.inv_mix_column col col_size
  let res_r := aes.inv_mix_column col.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma mix_columns_loop :
  let res_t := Translated.mix_columns_loop state result i state_size result_size
  let res_r := aes.mix_columns_loop state.toArrayU8 result.toArrayU8 i.toUsize
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma mix_columns :
  let res_t := Translated.mix_columns state state_size
  let res_r := aes.mix_columns state.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma inv_mix_columns_loop :
  let res_t := Translated.inv_mix_columns_loop state result i state_size result_size
  let res_r := aes.inv_mix_columns_loop state.toArrayU8 result.toArrayU8 i.toUsize
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma inv_mix_columns :
  let res_t := Translated.inv_mix_columns state state_size
  let res_r := aes.inv_mix_columns state.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

@[simp]
lemma add_round_key_loop_size : (Translated.add_round_key_loop state round_key result i state_size round_key_size result_size).size = Usize.toNat 16#usize := by
  simp

lemma add_round_key_loop :
  let res_t := Translated.add_round_key_loop state round_key result i state_size round_key_size result_size
  let res_r := aes.add_round_key_loop state.toArrayU8 round_key.toArrayU8 result.toArrayU8  i.toUsize
  res_r = .ok (res_t.toArrayU8 add_round_key_loop_size) :=
by
  sorry

lemma add_round_key :
  let res_t := Translated.add_round_key state round_key state_size round_key_size
  let res_r := aes.add_round_key state.toArrayU8 round_key.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma cipher_loop_loop {round : Nat} :
  let res_t := Translated.cipher_loop_loop state key_schedule nr round state_size key_schedule_size
  let res_r := aes.cipher_loop_loop state.toArrayU8 (key_schedule.toVecU8 key_schedule_size') nr.toUsize round.toUsize
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry
lemma cipher_loop :
  let res_t := Translated.cipher_loop state key_schedule nr state_size key_schedule_size
  let res_r := aes.cipher_loop state.toArrayU8 (key_schedule.toVecU8 key_schedule_size') nr.toUsize
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma cipher :
  let res_t := Translated.cipher input key_schedule nr input_size key_schedule_size
  let res_r := aes.cipher input.toArrayU8 (key_schedule.toVecU8 key_schedule_size') nr.toUsize
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma inv_cipher_loop_loop :
  let res_t := Translated.inv_cipher_loop_loop state key_schedule nr round_idx state_size key_schedule_size
  let res_r := aes.inv_cipher_loop_loop state.toArrayU8 (key_schedule.toVecU8 key_schedule_size') nr.toUsize round_idx.toUsize
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma inv_cipher_loop :
  let res_t := Translated.inv_cipher_loop state key_schedule nr state_size key_schedule_size
  let res_r := aes.inv_cipher_loop state.toArrayU8 (key_schedule.toVecU8 key_schedule_size') nr.toUsize
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma inv_cipher :
  let res_t := Translated.inv_cipher input key_schedule nr input_size key_schedule_size
  let res_r := aes.inv_cipher input.toArrayU8 (key_schedule.toVecU8 key_schedule_size') nr.toUsize
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

@[simp]
lemma aes128_size : (Translated.aes128 input key input_size key_size).size = 16 := by simp

lemma aes128 :
  let res_t := Translated.aes128 input key input_size key_size
  let res_r := aes.aes128 input.toArrayU8 key.toArrayU8
  res_r = .ok (res_t.toArrayU8 aes128_size) :=
by
  sorry

lemma aes192 :
  let res_t := Translated.aes192 input key input_size key_size
  let res_r := aes.aes192 input.toArrayU8 key.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma aes256 :
  let res_t := Translated.aes256 input key input_size key_size
  let res_r := aes.aes256 input.toArrayU8 key.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma aes128_inv :
  let res_t := Translated.aes128_inv input key input_size key_size
  let res_r := aes.aes128_inv input.toArrayU8 key.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma aes192_inv :
  let res_t := Translated.aes192_inv input key input_size key_size
  let res_r := aes.aes192_inv input.toArrayU8 key.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

lemma aes256_inv :
  let res_t := Translated.aes256_inv input key input_size key_size
  let res_r := aes.aes256_inv input.toArrayU8 key.toArrayU8
  res_r = .ok (res_t.toArrayU8 (by simp [res_t])) :=
by
  sorry

end TypeEquiv
