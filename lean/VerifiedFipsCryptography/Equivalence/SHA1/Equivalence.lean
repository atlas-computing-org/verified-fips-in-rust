import VerifiedFipsCryptography.Specs.SHA1
import VerifiedFipsCryptography.Equivalence.SHA1.Translated
import VerifiedFipsCryptography.Equivalence.SHA1.Structured
import VerifiedFipsCryptography.RustTranslations.FipsImplementations
import VerifiedFipsCryptography.Equivalence.SHA1.TypeEquiv
import VerifiedFipsCryptography.Equivalence.SHA1.SemanticEquiv
import VerifiedFipsCryptography.Equivalence.SHA1.StructuralEquiv

/-!
# Final Equivalences
-/

open Aeneas.Std fips_implementations algorithms alloc.vec core clone num

lemma hash_size : (SHA1.hash msg).size < USize.size := by
  rw [ByteArray.size, ← StructuralEquiv.hash, ← SemanticEquiv.hash]; simp only [Translated.hash_size]

lemma hash (msg_size : msg.data.size < USize.size - 72 - 1) :
  let res_l := SHA1.hash msg
  let res_r := sha1.hash (msg.data.toVecU8 (lt_trans msg_size (by omega)))
  res_r = .ok (res_l.data.toVecU8 hash_size) :=
by
  rw [TypeEquiv.hash msg_size]; congr; rw [← StructuralEquiv.hash, ← SemanticEquiv.hash]
