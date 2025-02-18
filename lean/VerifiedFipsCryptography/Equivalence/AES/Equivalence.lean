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

lemma aes128 (input_size : input.size = 16) (key_size : key.size = 16) :
  let res_l := AES.AES128 input key
  let res_r := aes.aes128 input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 sorry) :=
by rw [TypeEquiv.aes128, SemanticEquiv.aes128] <;> assumption

lemma aes192 (input_size : input.size = 16) (key_size : key.size = 24) :
  let res_l := AES.AES192 input key
  let res_r := aes.aes192 input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 sorry) :=
by rw [TypeEquiv.aes192, SemanticEquiv.aes192] <;> assumption

lemma aes256 (input_size : input.size = 16) (key_size : key.size = 32) :
  let res_l := AES.AES256 input key
  let res_r := aes.aes256 input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 sorry) :=
by rw [TypeEquiv.aes256, SemanticEquiv.aes256] <;> assumption

lemma aes128_inv (input_size : input.size = 16) (key_size : key.size = 16) :
  let res_l := AES.AES128Inv input key
  let res_r := aes.aes128_inv input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 sorry) :=
by rw [TypeEquiv.aes128_inv, SemanticEquiv.aes128_inv] <;> assumption

lemma aes192_inv (input_size : input.size = 16) (key_size : key.size = 24) :
  let res_l := AES.AES192Inv input key
  let res_r := aes.aes192_inv input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 sorry) :=
by rw [TypeEquiv.aes192_inv, SemanticEquiv.aes192_inv] <;> assumption

lemma aes256_inv (input_size : input.size = 16) (key_size : key.size = 32) :
  let res_l := AES.AES256Inv input key
  let res_r := aes.aes256_inv input.toArrayU8 key.toArrayU8
  res_r = .ok (res_l.toArrayU8 sorry) :=
by rw [TypeEquiv.aes256_inv, SemanticEquiv.aes256_inv] <;> assumption
