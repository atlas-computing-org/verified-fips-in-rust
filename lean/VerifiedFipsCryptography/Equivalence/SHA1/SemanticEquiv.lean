import VerifiedFipsCryptography.Specs.SHA1
import VerifiedFipsCryptography.Equivalence.SHA1.Translated
import VerifiedFipsCryptography.Equivalence.SHA1.Structured
import VerifiedFipsCryptography.Equivalence.SHA1.Lemmas
import VerifiedFipsCryptography.ForBatteries

namespace SemanticEquiv

lemma pad_message_loop (i_size : i ≤ zero_padding_length) :
  let res_l := padded_msg ++ (List.replicate (zero_padding_length - i) (0 : UInt8)).toArray
  let res_t := Translated.pad_message_loop padded_msg zero_padding_length i
  res_t = res_l :=
by
  induction i_size using Nat.decreasingInduction generalizing padded_msg with
  | self =>
    unfold Translated.pad_message_loop
    simp
  | of_succ i hi ih =>
    unfold Translated.pad_message_loop
    have : zero_padding_length - i = zero_padding_length - (i + 1) + 1 := by omega
    simp only [hi, ↓reduceDIte, ih, this, List.replicate_succ, ← List.push_append_toArray]

lemma pad_message :
  let res_l := Structured.pad_message msg
  let res_t := Translated.pad_message msg
  res_t = res_l :=
by
  unfold Structured.pad_message Translated.pad_message
  have : msg.push 128 = msg ++ #[128] := by exact rfl
  simp; rw [pad_message_loop (by omega), this, Array.append_assoc msg]
  simp

lemma chunkify_loop (i_size : i * 64 ≤ msg.size) :
  let res_l := Structured.chunkify_loop msg chunks i
  let res_t := Translated.chunkify_loop_aux msg msg_size_dvd chunks chunk_sizes i
  res_t = res_l :=
by
  have h0 := (Nat.dvd_iff_div_mul_eq msg.size 64).mp msg_size_dvd
  rw [← h0, mul_le_mul_right (Nat.zero_lt_succ 63)] at i_size
  induction i_size using Nat.decreasingInduction generalizing chunks with
  | self =>
    unfold Translated.chunkify_loop_aux Structured.chunkify_loop
    simp [h0]
  | of_succ i hi ih =>
    unfold Translated.chunkify_loop_aux Structured.chunkify_loop
    have : i * 64 < msg.size := by linarith
    simp [this, range'_eq_cons hi, ih, ← List.push_append_toArray, Structured.chunkify_loop]

lemma chunkify :
  let res_l := Structured.chunkify msg
  let res_t := Translated.chunkify msg msg_size_dvd
  res_t = res_l :=
by
  unfold Structured.chunkify Translated.chunkify
  have : (msg.size + 63) / 64 = msg.size / 64 := by omega
  simp [this]
  rw [← chunkify_loop (by omega) (chunk_sizes := by simp) (msg_size_dvd := msg_size_dvd), ← Translated.chunkify_loop.eq_aux (by omega)]

lemma process :
  let res_l := Structured.process ⟨state, state_size⟩ chunk
  let res_t := Translated.process state state_size chunk chunk_size
  ⟨res_t, Translated.process_size⟩ = res_l :=
by
  -- We need an arithmetic hammer to unroll the loop and grind out that all the operations
  -- end up assigning the same values in the array.
  sorry

lemma hash_to_vec_loop (index_size : index ≤ final_hash.size) :
  let res_l := Structured.hash_to_vec_loop ⟨final_hash, final_hash_size⟩ result_bytes index
  let res_t := Translated.hash_to_vec_loop final_hash final_hash_size result_bytes index
  res_t = res_l :=
by
  induction index_size using Nat.decreasingInduction generalizing result_bytes with
  | self =>
    unfold Translated.hash_to_vec_loop Structured.hash_to_vec_loop
    simp [final_hash_size]
  | of_succ i hi ih =>
    unfold Translated.hash_to_vec_loop Structured.hash_to_vec_loop
    simp [hi, ih, -Array.size_extract, Array.foldl_eq_extract_succ, Structured.hash_to_vec_loop]

lemma hash_to_vec :
  let res_l := Structured.hash_to_vec ⟨final_hash, final_hash_size⟩
  let res_t := Translated.hash_to_vec final_hash final_hash_size
  res_t = res_l :=
by
  unfold Structured.hash_to_vec Translated.hash_to_vec
  simp [hash_to_vec_loop, Structured.hash_to_vec_loop]

lemma hash_loop (i_size : i ≤ chunks.size) :
  let res_l := Structured.hash_loop chunks ⟨state, state_size⟩ i
  let res_t := Translated.hash_loop chunks chunk_sizes state state_size i
  ⟨res_t, Translated.hash_loop_size i_size⟩ = res_l :=
by
  induction i_size using Nat.decreasingInduction generalizing state with
  | self =>
    dsimp
    unfold Translated.hash_loop Structured.hash_loop
    simp
  | of_succ i hi ih =>
    dsimp
    unfold Translated.hash_loop Structured.hash_loop
    simp [hi, ih, process, -Array.size_extract, Array.foldl_eq_extract_succ, Structured.hash_loop]

lemma hash :
  let res_l := Structured.hash msg
  let res_t := Translated.hash msg
  res_t = res_l :=
by
  unfold Structured.hash Translated.hash
  dsimp
  rw [← pad_message, ← chunkify (msg_size_dvd := Translated.pad_message_size_dvd)]
  rw [← hash_loop (chunk_sizes := Translated.hash.proof_1 msg) (by omega)]
  rw [← hash_to_vec]
  rfl

end SemanticEquiv
