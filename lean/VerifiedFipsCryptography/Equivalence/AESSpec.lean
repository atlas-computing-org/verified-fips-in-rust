import VerifiedFipsCryptography.RustTranslations.FipsImplementations
import VerifiedFipsCryptography.Specs.AES.AES

import Std
import Init.Data.ByteArray
import VerifiedFipsCryptography.Util.HexString

import Base
open Primitives

-- todo: more standard way of doing this
def Result.map {α β : Type} (f : α → β) : Result α → Result β
  | Result.ok v => Result.ok (f v)
  | Result.fail e => Result.fail e
  | Result.div => Result.div

-- the standard pattern is: forall input1 input2, input1 `R_in` input2 -> output1 `R_out` output2
def AES128.equivalence : Prop :=
  ∀ (input_spec : Array UInt8) (key_spec : Array UInt8) (input_rust : Array U8 16#usize) (key_rust : Array U8 16#usize),
    (input_spec.toList.map UInt8.toNat = input_rust.val.map U8.toNat) →
    (key_spec.toList.map UInt8.toNat = key_rust.val.map U8.toNat) →
    let result_spec := AES.AES128 input_spec key_spec
    let result_rust := fips_implementations.algorithms.aes.aes128 input_rust key_rust
    Result.ok (result_spec.toList.map UInt8.toNat) = Result.map (fun result => result.val.map U8.toNat) result_rust
