import VerifiedFipsCryptography.Specs.SHA1
import VerifiedFipsCryptography.Equivalence.SHA1.Translated
import VerifiedFipsCryptography.RustTranslations.FipsImplementations

namespace TypeEquiv
open Aeneas.Std fips_implementations algorithms alloc.vec core clone num

@[simp]
lemma add_u32x4 :
  let res_t := Translated.add_u32x4 self rhs
  let res_r := sha1.Addfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.add self.toU32x4 rhs.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  unfold Translated.add_u32x4 sha1.Addfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.add
  let (x0, x1, x2, x3) := self
  let (y0, y1, y2, y3) := rhs
  simp [u32x4.toU32x4]

@[simp]
lemma bitxor_u32x4 :
  let res_t := Translated.bitxor_u32x4 s r
  let res_r := sha1.BitXorfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.bitxor s.toU32x4 r.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  unfold Translated.bitxor_u32x4 sha1.BitXorfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.bitxor
  let (x0, x1, x2, x3) := s
  let (y0, y1, y2, y3) := r
  simp [u32x4.toU32x4]

@[simp]
lemma sha1_first :
  let res_t := Translated.sha1_first w0
  let res_r := sha1.sha1_first w0.toU32x4
  res_r = .ok res_t.toU32 :=
by
  unfold Translated.sha1_first sha1.sha1_first
  let (w0_0, w0_1, w0_2, w0_3) := w0
  dsimp [u32x4.toU32x4]

@[simp]
lemma sha1_first_add :
  let res_t := Translated.sha1_first_add e w0
  let res_r := sha1.sha1_first_add e.toU32 w0.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  unfold Translated.sha1_first_add sha1.sha1_first_add
  let (w0_0, w0_1, w0_2, w0_3) := w0
  simp [u32x4.toU32x4]

@[simp]
lemma sha1msg1 :
  let res_t := Translated.sha1msg1 a b
  let res_r := sha1.sha1msg1 a.toU32x4 b.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  unfold Translated.sha1msg1 sha1.sha1msg1
  let (a_0, a_1, a_2, a_3) := a
  let (b_0, b_1, b_2, b_3) := b
  simp [u32x4.toU32x4, sha1.BitXorfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.bitxor, Translated.bitxor_u32x4]

@[simp]
lemma sha1msg2 :
  let res_t := Translated.sha1msg2 a b
  let res_r := sha1.sha1msg2 a.toU32x4 b.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  unfold Translated.sha1msg2 sha1.sha1msg2
  let (a_0, a_1, a_2, a_3) := a
  let (b_0, b_1, b_2, b_3) := b
  rw [U32.ofUInt32_eq 1 1]
  simp [u32x4.toU32x4, sha1.BitXorfips_implementationsalgorithmssha1u32x4fips_implementationsalgorithmssha1u32x4.bitxor, Translated.bitxor_u32x4]

@[simp]
lemma sha1_first_half :
  let res_t := Translated.sha1_first_half abcd msg
  let res_r := sha1.sha1_first_half abcd.toU32x4 msg.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  unfold Translated.sha1_first_half sha1.sha1_first_half
  rw [U32.ofUInt32_eq 30 30]
  simp

@[simp]
lemma sha1rnds4c :
  let res_t := Translated.sha1rnds4c abcd msg
  let res_r := sha1.sha1rnds4c abcd.toU32x4 msg.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  unfold Translated.sha1rnds4c sha1.sha1rnds4c
  let (a, b, c, d) := abcd
  let (msg_0, msg_1, msg_2, msg_3) := msg
  rw [U32.ofUInt32_eq 5 5, U32.ofUInt32_eq 0 0, U32.ofUInt32_eq 30 30]
  simp [u32x4.toU32x4]

@[simp]
lemma sha1rnds4p :
  let res_t := Translated.sha1rnds4p abcd msg
  let res_r := sha1.sha1rnds4p abcd.toU32x4 msg.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  unfold Translated.sha1rnds4p sha1.sha1rnds4p
  let (a, b, c, d) := abcd
  let (msg_0, msg_1, msg_2, msg_3) := msg
  rw [U32.ofUInt32_eq 5 5, U32.ofUInt32_eq 0 0, U32.ofUInt32_eq 30 30]
  dsimp [u32x4.toU32x4]
  simp

@[simp]
lemma sha1rnds4m :
  let res_t := Translated.sha1rnds4m abcd msg
  let res_r := sha1.sha1rnds4m abcd.toU32x4 msg.toU32x4
  res_r = .ok res_t.toU32x4 :=
by
  unfold Translated.sha1rnds4m sha1.sha1rnds4m
  let (a, b, c, d) := abcd
  let (msg_0, msg_1, msg_2, msg_3) := msg
  rw [U32.ofUInt32_eq 5 5, U32.ofUInt32_eq 0 0, U32.ofUInt32_eq 30 30]
  simp [u32x4.toU32x4]

@[simp]
lemma sha1_digest_round_x4 :
  let res_t := Translated.sha1_digest_round_x4 abcd work i
  let res_r := sha1.sha1_digest_round_x4 abcd.toU32x4 work.toU32x4 i.toU8
  res_r = .ok res_t.toU32x4 :=
by
  unfold Translated.sha1_digest_round_x4 sha1.sha1_digest_round_x4
  by_cases h : i = 0
  · simp [h, UInt8.toU8, sha1.sha1_digest_round_x4.K0V, eval_global, sha1.sha1_digest_round_x4.K0V_body]
    simp only [sha1.K0, eval_global, sha1.K0_body, Translated.K0]
    rw [U32.ofUInt32_eq 1518500249 1518500249, u32x4.toU32x4_unapply]
    simp
  · by_cases h : i = 1
    · simp [h, UInt8.toU8, sha1.sha1_digest_round_x4.K1V, eval_global, sha1.sha1_digest_round_x4.K1V_body]
      simp only [sha1.K1, eval_global, sha1.K1_body, Translated.K1]
      rw [U32.ofUInt32_eq 1859775393 1859775393, u32x4.toU32x4_unapply]
      simp
    · by_cases h : i = 2
      · simp [h, UInt8.toU8, sha1.sha1_digest_round_x4.K2V, eval_global, sha1.sha1_digest_round_x4.K2V_body]
        simp only [sha1.K2, eval_global, sha1.K2_body, Translated.K2]
        rw [U32.ofUInt32_eq 2400959708 2400959708, u32x4.toU32x4_unapply]
        simp
      · by_cases h : i = 3
        · simp [h, UInt8.toU8, sha1.sha1_digest_round_x4.K3V, eval_global, sha1.sha1_digest_round_x4.K3V_body]
          simp only [sha1.K3, eval_global, sha1.K3_body, Translated.K3]
          rw [U32.ofUInt32_eq 3395469782 3395469782, u32x4.toU32x4_unapply]
          simp
        · split; contradiction; contradiction; contradiction; contradiction; simp
          split;
          · rename_i heq; simp [UInt8.toU8] at heq; have : i = 0 := UInt8.toNat_inj.mp heq; contradiction
          · rename_i heq; simp [UInt8.toU8] at heq; have : i = 1 := UInt8.toNat_inj.mp heq; contradiction
          · rename_i heq; simp [UInt8.toU8] at heq; norm_cast at heq; have : i = 2 := UInt8.toNat_inj.mp heq; contradiction
          · rename_i heq; simp [UInt8.toU8] at heq; norm_cast at heq; have : i = 3 := UInt8.toNat_inj.mp heq; contradiction
          · rw [U32.ofUInt32_eq 0 0, u32x4.toU32x4_unapply]; rfl

@[simp]
lemma process_rounds_0 :
  let res_t := Translated.process_rounds_0 h0 state state_size words words_size
  let res_r := sha1.process_rounds_0 h0.toU32x4 state.toArrayU32 words.toArrayU32
  res_r =.ok (u32x4x6.toU32x4x6 res_t) :=
by
  unfold Translated.process_rounds_0 sha1.process_rounds_0
  simp_rw [
    Usize.ofNat_eq 0 0, Usize.ofNat_eq 1 1, Usize.ofNat_eq 2 2, Usize.ofNat_eq 3 3,
    Usize.ofNat_eq 4 4, Usize.ofNat_eq 5 5, Usize.ofNat_eq 6 6, Usize.ofNat_eq 7 7,
    Usize.ofNat_eq 8 8, Usize.ofNat_eq 9 9, Usize.ofNat_eq 10 10, Usize.ofNat_eq 11 11,
    Usize.ofNat_eq 12 12, Usize.ofNat_eq 13 13, Usize.ofNat_eq 14 14, Usize.ofNat_eq 15 15
  ]
  rw [U8.ofUInt8_eq 0 0]
  -- An example of why `simp` is not strong enough. Doing this doesn't work:
  -- `simp [Array.toArrayU32.index_usize_spec _ _ _ _. u32x4.toU32x4_unapply]`
  -- because `simp` can't pattern match on the last bounds proof.
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  simp [u32x4.toU32x4_unapply]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  simp [u32x4.toU32x4_unapply]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  simp [u32x4.toU32x4_unapply]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  rw [Array.toArrayU32.index_usize_spec _ _ _ (by omega), bind_tc_ok]
  simp [u32x4.toU32x4_unapply]
  congr

@[simp]
lemma process_rounds_i :
  let res_t := Translated.process_rounds_i args i
  let res_r := sha1.process_rounds_i args.toU32x4x6 i.toU8
  res_r = .ok (u32x4x6.toU32x4x6 res_t) :=
by
  unfold Translated.process_rounds_i sha1.process_rounds_i
  let (h0, h1, w1, w2, w3, w4) := args
  simp [u32x4x6.toU32x4x6]

@[simp]
lemma process_loop_loop_size (index_size : index ≤ 16) :
  (Translated.process_loop_loop block block_size words word_size index).size = Usize.toNat 16#usize :=
by simp; exact Translated.process_loop_loop_size index_size

@[simp]
lemma process_loop_loop (index_size : index ≤ 16) :
  let res_t := Translated.process_loop_loop block block_size words word_size index
  let res_r := sha1.process_loop_loop block.toArrayU8 words.toArrayU32 index.toUsize
  res_r = .ok (res_t.toArrayU32 (process_loop_loop_size index_size)) :=
by
  dsimp
  induction index_size using Nat.decreasingInduction generalizing words with
  | self =>
    unfold Translated.process_loop_loop; rw [sha1.process_loop_loop]
    simp [Nat.coe_toUsize_of_le]
  | of_succ i hi ih =>
    have : i.toUsize < 16#usize ↔ i < 16 := by
      simp [Nat.toUsize, USize.toUsize, USize.size] at *; norm_cast
      rw [Nat.mod_eq_of_lt (Nat.lt_usize (by omega))]
    unfold Translated.process_loop_loop; rw [sha1.process_loop_loop]
    simp [hi, this] at ih ⊢
    rw [Usize.ofNat_eq 4 4, Usize.ofNat_eq 3 3, Usize.ofNat_eq 2 2, Usize.ofNat_eq 1 1]
    rw [U32.ofUInt32_eq 8 8, U32.ofUInt32_eq 16 16, U32.ofUInt32_eq 24 24]
    simp [Usize.mul_spec sorry, Usize.add_spec sorry, Array.toArrayU8.index_usize_spec _ _ _ sorry, Array.index_mut_usize,
      Array.toArrayU32.index_usize_spec _ _ _ sorry, Array.toArrayU32.update_spec words _ i (by omega) _]
    rw [← ih]

@[simp]
lemma process_loop_size :
  (Translated.process_loop block block_size).size = Usize.toNat 16#usize :=
by simp [Translated.process_loop]

@[simp]
lemma process_loop :
  let res_t := Translated.process_loop block block_size
  let res_r := sha1.process_loop block.toArrayU8
  res_r = .ok (res_t.toArrayU32 process_loop_size) :=
by
  unfold Translated.process_loop sha1.process_loop
  have : Array.repeat 16#usize 0#u32 = (Array.mk $ List.replicate 16 0 ).toArrayU32 := by sorry
  rw [this, Usize.ofNat_eq 0 0, process_loop_loop]
  simp

@[simp]
lemma process_size :
  (Translated.process state state_size block block_size).size = Usize.toNat 5#usize :=
by simp [Translated.process_loop]

@[simp]
lemma process :
  let res_t := Translated.process state state_size block block_size
  let res_r := sha1.process state.toArrayU32 block.toArrayU8
  res_r = .ok (res_t.toArrayU32 process_size) :=
by
  rw [sha1.process, Usize.ofNat_eq 0 0, Usize.ofNat_eq 1 1, Usize.ofNat_eq 2 2, Usize.ofNat_eq 3 3, Usize.ofNat_eq 4 4]
  rw [U8.ofUInt8_eq 1 1, U8.ofUInt8_eq 2 2, U8.ofUInt8_eq 3 3, U32.ofUInt32_eq 30 30]
  simp [@process_loop _ block_size, Array.toArrayU32.index_usize_spec _ _ _ sorry, u32x4.toU32x4_unapply]
  have := @process_rounds_0 (state[0], state[1], state[2], state[3]) state state_size (Translated.process_loop block block_size) Translated.process_loop_size
  simp_rw [this, bind_tc_ok]
  simp [Array.toArrayU32.index_usize_spec _ _ _ sorry, sha1_first]
  set x := (Translated.process_rounds_i
              (Translated.process_rounds_i
                (Translated.process_rounds_i
                  (Translated.process_rounds_0 (state[0], state[1], state[2], state[3]) state state_size
                    (Translated.process_loop block block_size) _) 1) 2) 3) with hx
  let ((a, b, c, d), _) := x
  simp [u32x4.toU32x4, Array.toArrayU32.update_usize_spec _ _ _ sorry _, Array.toArrayU32.index_usize_spec _ _ _ sorry,
    Array.index_mut_usize, Array.toArrayU32.update_spec _ _ _ sorry _]
  unfold Translated.process;
  simp only [← hx]; congr
  match state, state_size with
  | ⟨[a, b, c, d, e]⟩, _ =>
    simp

@[simp]
lemma CHUNK_SIZE : sha1.CHUNK_SIZE = (64).toUsize := by
  simp [sha1.CHUNK_SIZE, eval_global, sha1.CHUNK_SIZE_body]
  rw [Usize.ofNat_eq 64 64]

@[simp]
lemma chunkify_loop.eq_aux (msg_size : msg.size < USize.size) (msg_size_dvd : 64 ∣ msg.size) (i_size : i * 64 < USize.size) :
  let res_t := Translated.chunkify_loop_aux msg msg_size_dvd chunks chunk_sizes i
  let res_r := sha1.chunkify_loop (msg.toVecU8 msg_size) (chunks.toVecArrayU8 sorry) (i * 64).toUsize
  res_r = .ok (res_t.toVecArrayU8 sorry) :=
by
  have : ∀ i, i * 64 < USize.size → ((i * 64).toUsize < msg.size.toUsize ↔ i * 64 < msg.size) := fun i hi ↦ by
    simp [Nat.toUsize, USize.toUsize, USize.size] at *; norm_cast
    rw [Nat.mod_eq_of_lt hi, Nat.mod_eq_of_lt msg_size]
  have h0 := (Nat.dvd_iff_div_mul_eq msg.size 64).mp msg_size_dvd
  by_cases hi : i ≤ msg.size / 64
  · induction hi using Nat.decreasingInduction generalizing chunks with
    | self =>
      unfold Translated.chunkify_loop_aux; rw [sha1.chunkify_loop]
      simp [Nat.coe_toUsize_of_le, h0]
    | of_succ i hi ih =>
      unfold Translated.chunkify_loop_aux; rw [sha1.chunkify_loop]
      have hi : i * 64 < msg.size := by linarith
      simp [hi, this i i_size] at ih ⊢
      simp [slice.index.Slice.index, Usize.add_spec sorry]
      sorry
  · by_cases hi : i = msg.size / 64
    · rw [sha1.chunkify_loop];
      simp_rw [Array.toVecU8_slice_len, this i i_size]
      simp [Translated.chunkify_loop_aux, h0, hi]
    · have hi : ¬i * 64 < msg.size := by linarith
      have hn : msg.size / 64 - i = 0 := by omega
      rw [sha1.chunkify_loop]
      simp_rw [Array.toVecU8_slice_len, this i i_size]
      simp [hi, hn, Translated.chunkify_loop_aux, h0]

@[simp]
lemma chunkify (msg_size : msg.size < USize.size) (msg_size_dvd : 64 ∣ msg.size) :
  let res_t := Translated.chunkify msg msg_size_dvd
  let res_r := sha1.chunkify (msg.toVecU8 msg_size)
  res_r = .ok (res_t.toVecArrayU8 sorry) :=
by
  rw [Translated.chunkify, sha1.chunkify, Usize.ofNat_eq 0 0, Vec.ArrayU8.new_spec]
  dsimp; conv => left; right; rw [← Nat.zero_mul 64]
  rw [chunkify_loop.eq_aux (chunk_sizes := by simp) msg_size msg_size_dvd (by omega), ← Translated.chunkify_loop.eq_aux (Nat.zero_le _)]

@[simp]
lemma pad_message_loop (padded_msg_size : padded_msg.size < USize.size - 64 + i) (i_size : i < USize.size) (zero_padding_length_size : zero_padding_length < 64) :
  let res_t := Translated.pad_message_loop padded_msg zero_padding_length i
  let res_r := sha1.pad_message_loop_loop (padded_msg.toVecU8 sorry) zero_padding_length.toUsize i.toUsize
  res_r = .ok (res_t.toVecU8 sorry) :=
by
  have : ∀ i < USize.size, i.toUsize < zero_padding_length.toUsize ↔ i < zero_padding_length := fun i hi ↦ by
    simp [Nat.toUsize, USize.toUsize, USize.size] at *; norm_cast
    have : zero_padding_length < USize.size := Nat.lt_usize (by omega)
    rw [Nat.mod_eq_of_lt hi, Nat.mod_eq_of_lt this]
  by_cases hi : i ≤ zero_padding_length
  · induction hi using Nat.decreasingInduction generalizing padded_msg with
    | self =>
      unfold Translated.pad_message_loop; rw [sha1.pad_message_loop_loop]
      simp [Nat.coe_toUsize_of_le]
    | of_succ i hi ih =>
      unfold Translated.pad_message_loop; rw [sha1.pad_message_loop_loop]
      simp [hi, this i i_size] at ih ⊢
      rw [Usize.ofNat_eq 1 1, U8.ofUInt8_eq 0 0]
      have h₁ : i + 1 < USize.size := Nat.lt_usize (by omega)
      rw [Array.toVecU8.push_spec _ _ (by omega), bind_tc_ok, Usize.add_spec h₁, bind_tc_ok, ← ih (by simp; omega) h₁]
  · by_cases hi : i = zero_padding_length
    · rw [sha1.pad_message_loop_loop]
      simp_rw [this i i_size]
      simp [Translated.pad_message_loop, hi]
    · have hi : ¬i < zero_padding_length := by linarith
      have hn : zero_padding_length - i = 0 := by omega
      rw [sha1.pad_message_loop_loop]
      simp_rw [this i i_size]
      simp [hi, hn, Translated.pad_message_loop]

@[simp]
lemma pad_message (msg_size : msg.size < USize.size - 64 - 1) :
  let res_t := Translated.pad_message msg
  let res_r := sha1.pad_message (msg.toVecU8 (lt_trans msg_size (by omega)))
  res_r = .ok (res_t.toVecU8 (Translated.pad_message_size msg_size)) :=
by
  rw [sha1.pad_message]; unfold Translated.pad_message
  rw [Usize.ofNat_eq 1 1, Usize.ofNat_eq 64 64, Usize.ofNat_eq 56 56]
  rw [U64.ofUInt64_eq 56 56, U64.ofUInt64_eq 48 48, U64.ofUInt64_eq 40 40, U64.ofUInt64_eq 32 32, U64.ofUInt64_eq 24 24, U64.ofUInt64_eq 16 16, U64.ofUInt64_eq 8 8, U64.ofUInt64_eq 0 0, U64.ofUInt64_eq 255 255]
  rw [U8.ofUInt8_eq 128 128]
  simp [Usize.add_spec sorry, Nat.Usize.sub_spec sorry, Array.toVecU8.push_spec _ _ sorry, UInt64.U64.mul_spec sorry, Vec.U8.extend_from_slice_spec sorry]
  rw [sha1.pad_message_loop, Usize.ofNat_eq 0 0, pad_message_loop (by simp; omega) (by simp) (by omega)]
  simp [Vec.U8.extend_from_slice_spec sorry]

lemma hash_to_vec_loop_size (index_size : index ≤ final_hash.size) (result_bytes_size : result_bytes.size ≤ 4 * index) :
  (Translated.hash_to_vec_loop final_hash final_hash_size result_bytes index).size < USize.size :=
by
  rw [Translated.hash_to_vec_loop_size index_size]
  exact Nat.lt_usize (by omega)

@[simp]
lemma hash_to_vec_loop (index_size : index ≤ final_hash.size) (result_bytes_size : result_bytes.size ≤ 4 * index) :
  let res_t := Translated.hash_to_vec_loop final_hash final_hash_size result_bytes index
  let res_r := sha1.hash_to_vec_loop final_hash.toArrayU32 (result_bytes.toVecU8 (Nat.lt_usize (by omega))) index.toUsize
  res_r = .ok (res_t.toVecU8 (hash_to_vec_loop_size index_size result_bytes_size)) :=
by
  induction index_size using Nat.decreasingInduction generalizing result_bytes with
  | self =>
    rw [sha1.hash_to_vec_loop]
    rw [Array.toArrayU32.to_slice_spec, bind_tc_ok, Array.toVecU32_slice_len]
    simp [Aeneas.loop_form, Translated.process_loop_loop, Translated.hash_to_vec_loop]
  | of_succ index hi ih =>
    rw [sha1.hash_to_vec_loop]
    rw [Array.toArrayU32.to_slice_spec, bind_tc_ok, Array.toVecU32_slice_len]
    have : index.toUsize < final_hash.size.toUsize ↔ index < final_hash.size := by
      simp [Nat.toUsize, USize.toUsize, USize.size] at *; norm_cast
      have h0 : index < USize.size := Nat.lt_usize (by omega)
      have h1 : final_hash.size < USize.size := Nat.lt_usize (by omega)
      rw [Nat.mod_eq_of_lt h0, Nat.mod_eq_of_lt h1]
    simp [hi, this] at ih ⊢
    rw [Usize.ofNat_eq 1 1, U32.ofUInt32_eq 0 0, U32.ofUInt32_eq 8 8, U32.ofUInt32_eq 16 16, U32.ofUInt32_eq 24 24, U32.ofUInt32_eq 255 255]
    simp [Array.toArrayU32.index_usize_spec _ _ _ sorry, Array.toVecU8.push_spec _ _ sorry, Usize.add_spec sorry]
    unfold Translated.hash_to_vec_loop; rw [ih (by simp; omega)]
    simp [hi]
    rfl

lemma hash_to_vec_size : (Translated.hash_to_vec final_hash final_hash_size).size < USize.size := by
  rw [Translated.hash_to_vec_size]
  exact Nat.lt_usize (by omega)

@[simp]
lemma hash_to_vec :
  let res_t := Translated.hash_to_vec final_hash final_hash_size
  let res_r := sha1.hash_to_vec final_hash.toArrayU32
  res_r = .ok (res_t.toVecU8 hash_to_vec_size) :=
by
  unfold Translated.hash_to_vec
  rw [sha1.hash_to_vec, Usize.ofNat_eq 0 0]
  simp; rw [hash_to_vec_loop] <;> simp

@[simp]
lemma INITIAL_STATE : sha1.INITIAL_STATE = Translated.INITIAL_STATE.toArrayU32 (by rfl) := by
  simp [sha1.INITIAL_STATE, eval_global, sha1.INITIAL_STATE_body, Translated.INITIAL_STATE, Array.make, Array.toArrayU32]
  rw [U32.ofUInt32_eq 1732584193 1732584193, U32.ofUInt32_eq 4023233417 4023233417, U32.ofUInt32_eq 2562383102 2562383102, U32.ofUInt32_eq 271733878 271733878, U32.ofUInt32_eq 3285377520 3285377520]

@[simp]
lemma hash_loop (chunks_size : chunks.size < USize.size) (index_size : index < USize.size) :
  let res_t := Translated.hash_loop chunks chunk_sizes state state_size index
  let res_r := sha1.hash_loop_loop (chunks.toVecArrayU8 chunks_size) state.toArrayU32 index.toUsize
  res_r = .ok (res_t.toArrayU32 sorry) :=
by
  have : ∀ i < USize.size, i.toUsize < chunks.size.toUsize ↔ i < chunks.size := fun i hi ↦ by
    simp [Nat.toUsize, USize.toUsize, USize.size] at *; norm_cast
    rw [Nat.mod_eq_of_lt hi, Nat.mod_eq_of_lt chunks_size]
  by_cases hi : index ≤ chunks.size
  · induction hi using Nat.decreasingInduction generalizing state with
    | self =>
      unfold Translated.hash_loop; rw [sha1.hash_loop_loop]
      simp
    | of_succ index hi ih =>
      unfold Translated.hash_loop; rw [sha1.hash_loop_loop]
      simp [hi, this index index_size] at ih ⊢
      rw [Usize.ofNat_eq 1 1]
      simp [Array.toVecArrayU8.index_usize_spec _ _ _ sorry, Array.toVecU8.push_spec _ _ sorry, Usize.add_spec sorry,
        @process state state_size chunks[index] (chunk_sizes _ (Array.getElem_mem _))]
      rw [← ih (by omega)]
  · by_cases hi : index = chunks.size
    · rw [sha1.hash_loop_loop]
      simp_rw [Array.toVecArrayU8_len, this index index_size]
      simp [Translated.hash_loop, hi]
    · have hi : ¬index < chunks.size := by linarith
      have hn : chunks.size - index = 0 := by omega
      rw [sha1.hash_loop_loop]
      simp_rw [Array.toVecArrayU8_len, this index index_size]
      simp [hi, hn, Translated.hash_loop]

@[simp]
lemma hash (msg_size : msg.size < USize.size - 64 - 1) :
  let res_t := Translated.hash msg
  let res_r := sha1.hash (msg.toVecU8 (lt_trans msg_size (by omega)))
  res_r = .ok (res_t.toVecU8 sorry) :=
by
  rw [Translated.hash, sha1.hash]
  simp [DerefVec.deref]
  -- have h0 : msg.size < USize.size := lt_trans msg_size (by omega)
  simp [pad_message msg_size, chunkify _ Translated.pad_message_size_dvd, sha1.hash_loop, Usize.ofNat_eq 0 0]
  rw [hash_loop (chunk_sizes := Translated.chunkify_sizes Translated.pad_message_size_dvd) (state_size := by rfl) sorry (by simp), bind_tc_ok, hash_to_vec]

end TypeEquiv
