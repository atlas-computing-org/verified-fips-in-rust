import VerifiedFipsCryptography.Specs.SHA1
import VerifiedFipsCryptography.Equivalence.SHA1.Structured
import VerifiedFipsCryptography.Equivalence.SHA1.SemanticEquiv
import VerifiedFipsCryptography.ForBatteries

namespace StructuralEquiv

lemma pad_message :
  let res_l := SHA1.pad_message msg
  let res_t := Structured.pad_message msg.data
  res_t = res_l.data :=
by
  unfold SHA1.pad_message Structured.pad_message
  simp; congr

lemma chunkify (msg_size_dvd : 64 ∣ msg.data.size) :
  let res_l := SHA1.chunkify msg
  let res_t := Structured.chunkify msg.data
  res_t = res_l.map (fun b ↦ b.data) :=
by
  unfold SHA1.chunkify Structured.chunkify Structured.chunkify_loop
  have : (msg.data.size + 63) / 64 = msg.data.size / 64 := by omega
  simp [ByteArray.size, this, List.range_eq_range']

lemma bytes_to_word :
  let res_l := SHA1.bytesToWord msg
  let res_t := Structured.bytes_to_word msg.data
  res_t = res_l :=
by
  unfold SHA1.bytesToWord Structured.bytes_to_word
  simp [ByteArray.foldl_toArray]

lemma process_loop {chunk : ByteArray} :
  let res_l := (List.range 16).map (fun i ↦ SHA1.bytesToWord (chunk.extract (i * 4) ((i + 1) * 4)))
  let res_t := Structured.process_loop chunk.data
  res_t = res_l :=
by
  unfold Structured.process_loop
  simp; intro i hi
  unfold Structured.bytes_to_word SHA1.bytesToWord
  rw [ByteArray.foldl_toArray]; simp

lemma process :
  let res_l := SHA1.process state chunk
  let res_t := Structured.process state chunk.data
  res_t = res_l :=
by
  -- Lean gets stuck due to the term sizes getting too large.
  unfold SHA1.process Structured.process
  rw [process_loop]

lemma hash_to_vec :
  let res_l := SHA1.hash_to_vec final_hash
  let res_t := Structured.hash_to_vec final_hash
  res_t = res_l.data :=
by
  unfold SHA1.hash_to_vec Structured.hash_to_vec
  simp

lemma hash_loop {chunks : Array ByteArray} (i_size : i ≤ chunks.size) :
  let res_l := Array.foldl (fun h0 chunk ↦ SHA1.process h0 chunk) state (chunks.extract i chunks.size)
  let chunks_t := chunks.map fun chunk ↦ chunk.data
  let res_t := Structured.hash_loop chunks_t state i
  res_t = res_l :=
by
  induction i_size using Nat.decreasingInduction generalizing state with
  | self => simp [Structured.hash_loop]
  | of_succ i hi ih =>
    unfold Structured.hash_loop
    rw [Array.foldl_eq_extract_succ _ hi]; dsimp; rw [Array.foldl_eq_extract_succ _ (by simp [hi])]
    simp at ih ⊢
    simp [← ih, Structured.hash_loop, process]

lemma hash :
  let res_l := SHA1.hash b
  let res_t := Structured.hash b.data
  res_t = res_l.data :=
by
  unfold SHA1.hash Structured.hash
  rw [hash_to_vec]; congr
  rw [pad_message, chunkify, hash_loop (by omega), Array.extract_all]
  -- This is a cool trick lol
  · rw [← pad_message, ← SemanticEquiv.pad_message]
    exact Translated.pad_message_size_dvd

end StructuralEquiv
