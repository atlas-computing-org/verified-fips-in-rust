import VerifiedFipsCryptography.Specs.AES.AES
import VerifiedFipsCryptography.Equivalence.AES.Structured
import VerifiedFipsCryptography.ForBatteries

namespace StructuralEquiv

lemma gf_mul :
  let res_a := Structured.gf_mul a b
  let res_l := AES.gfMul a b
  res_l = res_a :=
by rfl

lemma key_expansion :
  let res_a := Structured.key_expansion w nk nr
  let res_l := AES.keyExpansion w nk nr
  res_l = res_a :=
by rfl

lemma mix_columns :
  let res_a := Structured.mix_columns state
  let res_l := AES.mixColumns state
  res_l = res_a :=
by
  unfold Structured.mix_columns AES.mixColumns Structured.mix_columns_loop
  simp [Id.run]

lemma inv_mix_columns :
  let res_a := Structured.inv_mix_columns state
  let res_l := AES.invMixColumns state
  res_l = res_a :=
by
  unfold Structured.inv_mix_columns AES.invMixColumns Structured.inv_mix_columns_loop
  simp [Id.run]

lemma cipher :
  let res_a := Structured.cipher state
  let res_l := AES.cipher state
  res_l = res_a :=
by
  unfold Structured.cipher AES.cipher Structured.cipher_loop
  simp [Id.run, Array.toArray_eq_extract, ← mix_columns]

lemma inv_cipher :
  let res_a := Structured.inv_cipher state
  let res_l := AES.invCipher state
  res_l = res_a :=
by
  unfold Structured.inv_cipher AES.invCipher Structured.inv_cipher_loop
  simp [Id.run, Array.toArray_eq_extract, ← inv_mix_columns]

end StructuralEquiv
