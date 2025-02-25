import VerifiedFipsCryptography.Specs.AES.AES
import VerifiedFipsCryptography.Equivalence.AES.Translated
import VerifiedFipsCryptography.Equivalence.AES.Structured
import VerifiedFipsCryptography.RustTranslations.FipsImplementations
import VerifiedFipsCryptography.Equivalence.AES.TypeEquiv
import VerifiedFipsCryptography.Equivalence.AES.SemanticEquiv
import VerifiedFipsCryptography.Equivalence.AES.StructuralEquiv

/-!
# Final Equivalences
-/

open Aeneas.Std fips_implementations algorithms alloc.vec core clone num

lemma aes128_size (input_size : input.size = 16) (key_size : key.size = 16) : (AES.AES128 input key).size = Usize.toNat 16#usize := by
  rw [← @SemanticEquiv.aes128 input key input_size key_size]
  simp

lemma aes128 (input_size : input.size = 16) (key_size : key.size = 16) :
  let res_l := AES.AES128 input key
  let res_r := aes.aes128 input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 (aes128_size input_size key_size)) :=
by
  rw [TypeEquiv.aes128 (input_size := input_size) (key_size := key_size)]
  have := @SemanticEquiv.aes128 input key input_size key_size
  dsimp at this ⊢; refine congr_arg _ ?_; congr 1

lemma aes192_size (input_size : input.size = 16) (key_size : key.size = 24) : (AES.AES192 input key).size = Usize.toNat 16#usize := by
  rw [← @SemanticEquiv.aes192 input key input_size key_size]
  simp

lemma aes192 (input_size : input.size = 16) (key_size : key.size = 24) :
  let res_l := AES.AES192 input key
  let res_r := aes.aes192 input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 (aes192_size input_size key_size)) :=
by
  rw [TypeEquiv.aes192 (input_size := input_size) (key_size := key_size)]
  have := @SemanticEquiv.aes192 input key input_size key_size
  dsimp at this ⊢; refine congr_arg _ ?_; congr 1

lemma aes256_size (input_size : input.size = 16) (key_size : key.size = 32) : (AES.AES256 input key).size = Usize.toNat 16#usize := by
  rw [← @SemanticEquiv.aes256 input key input_size key_size]
  simp

lemma aes256 (input_size : input.size = 16) (key_size : key.size = 32) :
  let res_l := AES.AES256 input key
  let res_r := aes.aes256 input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 (aes256_size input_size key_size)) :=
by
  rw [TypeEquiv.aes256 (input_size := input_size) (key_size := key_size)]
  have := @SemanticEquiv.aes256 input key input_size key_size
  dsimp at this ⊢; refine congr_arg _ ?_; congr 1

lemma aes128_inv_size (input_size : input.size = 16) (key_size : key.size = 16) : (AES.AES128Inv input key).size = Usize.toNat 16#usize := by
  rw [← @SemanticEquiv.aes128_inv input key input_size key_size]
  simp

lemma aes128_inv (input_size : input.size = 16) (key_size : key.size = 16) :
  let res_l := AES.AES128Inv input key
  let res_r := aes.aes128_inv input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 (aes128_inv_size input_size key_size)) :=
by
  rw [TypeEquiv.aes128_inv (input_size := input_size) (key_size := key_size)]
  have := @SemanticEquiv.aes128_inv input key input_size key_size
  dsimp at this ⊢; refine congr_arg _ ?_; congr 1

lemma aes192_inv_size (input_size : input.size = 16) (key_size : key.size = 24) : (AES.AES192Inv input key).size = Usize.toNat 16#usize := by
  rw [← @SemanticEquiv.aes192_inv input key input_size key_size]
  simp

lemma aes192_inv (input_size : input.size = 16) (key_size : key.size = 24) :
  let res_l := AES.AES192Inv input key
  let res_r := aes.aes192_inv input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 (aes192_inv_size input_size key_size)) :=
by
  rw [TypeEquiv.aes192_inv (input_size := input_size) (key_size := key_size)]
  have := @SemanticEquiv.aes192_inv input key input_size key_size
  dsimp at this ⊢; refine congr_arg _ ?_; congr 1

lemma aes256_inv_size (input_size : input.size = 16) (key_size : key.size = 32) : (AES.AES256Inv input key).size = Usize.toNat 16#usize := by
  rw [← @SemanticEquiv.aes256_inv input key input_size key_size]
  simp

lemma aes256_inv (input_size : input.size = 16) (key_size : key.size = 32) :
  let res_l := AES.AES256Inv input key
  let res_r := aes.aes256_inv input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 (aes256_inv_size input_size key_size)) :=
by
  rw [TypeEquiv.aes256_inv (input_size := input_size) (key_size := key_size)]
  have := @SemanticEquiv.aes256_inv input key input_size key_size
  dsimp at this ⊢; refine congr_arg _ ?_; congr 1
