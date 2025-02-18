import VerifiedFipsCryptography.Specs.SHA1
import VerifiedFipsCryptography.Equivalence.SHA1.Structured
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

lemma process :
  let res_l := SHA1.process state chunk
  let res_t := Structured.process state chunk.data
  res_t = res_l :=
by
  -- Lean gets stuck due to the term sizes getting too large.
  sorry

lemma hash_to_vec :
  let res_l := SHA1.hash_to_vec final_hash
  let res_t := Structured.hash_to_vec final_hash
  res_t = res_l.data :=
by
  unfold SHA1.hash_to_vec Structured.hash_to_vec
  simp

lemma hash_loop :
  let res_l := Array.foldl (fun h0 chunk ↦ SHA1.process h0 chunk) state chunks
  let res_t := Structured.hash_loop (chunks.map fun chunk ↦ chunk.data) state i
  res_t = res_l :=
by
  unfold Structured.hash_loop
  -- TODO: ack didn't finish this
  sorry

lemma hash :
  let res_l := SHA1.hash b
  let res_t := Structured.hash b.data
  res_t = res_l.data :=
by
  unfold SHA1.hash Structured.hash
  -- TODO: ack didn't finish this
  sorry


end StructuralEquiv
