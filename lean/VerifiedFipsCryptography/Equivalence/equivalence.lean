import «VerifiedFipsCryptography»

import Mathlib
open Primitives
open Nat

def UInt8_to_U8 (x : UInt8) : U8 := by
  let n := Int.ofNat x.val.val
  have xn : (↑x.toNat : Int) = n := by rfl
  let isLt := Int.ofNat_le_ofNat_of_le x.val.isLt
  apply U8.ofIntCore n
  simp [Scalar.min, Scalar.max, U8.max]
  simp [xn] at isLt
  apply And.intro <;> linarith

def U8_to_UInt8 (x : U8) : UInt8 := by
  let n := x.val.toNat
  have xn : x.val = (↑n : Int) := by aesop
  let hmax := x.hmax
  simp [Scalar.max, ScalarTy.U8, U8.max, xn] at hmax
  have hhmax : n < 256 := by linarith
  apply UInt8.ofNatCore n
  simp [UInt8.size]
  aesop

def lifted_testBit (b : U8) (i : U8) : Result Bool :=
  let lb := U8_to_UInt8 b
  let li := U8_to_UInt8 i
  Result.ok (AES.testBit lb li)

-- Can't proceed because ">>>" or Scalar.shiftr is defined with
-- a sorry in aeneas/backends/lean/Base/Primitives/Scalar.lean

theorem eq_test_bit : lifted_testBit = fips_implementations.algorithms.aes.test_bit := by
  funext b i
  simp [fips_implementations.algorithms.aes.test_bit, lifted_testBit, AES.testBit, decide]
  simp [HAnd.hAnd, HShiftRight.hShiftRight]
