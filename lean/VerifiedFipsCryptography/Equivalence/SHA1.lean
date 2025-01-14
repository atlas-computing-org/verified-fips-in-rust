import VerifiedFipsCryptography.RustTranslations.FipsImplementations
import VerifiedFipsCryptography.Specs.SHA1

import Std
import Init.Data.ByteArray
import VerifiedFipsCryptography.Util.HexString

import Base
open Primitives fips_implementations algorithms

-- todo: branch in Aeneas
def Result.map {α β : Type} (f : α → β) : Result α → Result β
  | Result.ok v => Result.ok (f v)
  | Result.fail e => Result.fail e
  | Result.div => Result.div

def Array.toVec : Array UInt8 → alloc.vec.Vec U8 := fun v ↦ ⟨v.data.map toU8, sorry⟩
def ByteArray.toVec : ByteArray → alloc.vec.Vec U8 := fun v ↦ Array.toVec v.data
def Array.toSlice : Array UInt8 → Slice U8 := fun v ↦ ⟨v.data.map toU8, sorry⟩
def ByteArray.toSlice : ByteArray → Slice U8 := fun v ↦ Array.toSlice v.data
def Mathlib.Vector.toArrayU32 {n : ℕ} {m : Usize} (h : m = toUsize n.toUSize) : Mathlib.Vector UInt32 n → Array U32 m := sorry
def Mathlib.Vector.toArrayU8 {n : ℕ} {m : Usize} (h : m = toUsize n.toUSize) : Mathlib.Vector UInt8 n → Array U8 m := sorry
def Mathlib.Vector.set (v : Mathlib.Vector α n) (i : ℕ) (a : α) : Mathlib.Vector α n := ⟨v.1.set i a, by simp [v.2]⟩
-- ### This does not typecheck ###
-- Here we have the following error:
-- type mismatch
--   v₁
-- has type
--   Primitives.Array ℕ (toUsize 8) : Type
-- but is expected to have type
--   Primitives.Array ℕ 8#usize : Type
-- If you uncomment `bad_types`, the Lean compiler will complain that the types are not equal.
-- However, they clearly are! This becomes extremely difficult to work with because you can't
-- write in normal equalities.

lemma bad_types {v₀ : Primitives.Array ℕ 8#usize} {v₁ : Primitives.Array ℕ (toUsize 8)} : 
  v₀ = v₁ := by sorry

-- really need to automate these with a normalization tactic
@[simp]
lemma U8.ofNat (x : ℕ) [OfNat ℤ x] (h : Scalar.cMin ScalarTy.U8 ≤ (OfNat.ofNat x) ∧ (OfNat.ofNat x) ≤ Scalar.cMax ScalarTy.U8 := by decide) :
    U8.ofInt (OfNat.ofNat x) h = toU8 x.toUInt8 := by sorry
@[simp]
lemma U64.ofNat (x : ℕ) [OfNat ℤ x] (h : Scalar.cMin ScalarTy.U64 ≤ (OfNat.ofNat x) ∧ (OfNat.ofNat x) ≤ Scalar.cMax ScalarTy.U64 := by decide) :
    U64.ofInt (OfNat.ofNat x) h = toU64 x.toUInt64 := by sorry
@[simp]
lemma Usize.ofNat (x : ℕ) [OfNat ℤ x] (h : Scalar.cMin ScalarTy.Usize ≤ (OfNat.ofNat x) ∧ (OfNat.ofNat x) ≤ Scalar.cMax ScalarTy.Usize := by decide) :
    Usize.ofInt (OfNat.ofNat x) h = toUsize x.toUSize := by sorry

-- The issue is that this isn't technically true ;-;
-- The Lean/Rust semantics on how overflow is handled is different.
@[simp]
lemma U64.add_spec {x y : UInt64} : toU64 x + toU64 y = Result.ok (toU64 (x + y)) := by sorry
-- Maybe some of the rest of these are true, but I haven't checked closely.
@[simp]
lemma U64.mul_spec {x y : UInt64} : toU64 x * toU64 y = Result.ok (toU64 (x * y)) := by sorry
@[simp]
lemma U64.shiftr_spec {x y : UInt64} : toU64 x >>> toU64 y = Result.ok (toU64 (x >>> y)) := by sorry
@[simp]
lemma U64.and_spec {x y : UInt64} : toU64 x &&& toU64 y = toU64 (x &&& y) := by sorry
@[simp]
lemma Usize.add_spec {x y : USize} : toUsize x + toUsize y = Result.ok (toUsize (x + y)) := by sorry
@[simp]
lemma Usize.sub_spec {x y : USize} : toUsize x - toUsize y = Result.ok (toUsize (x - y)) := by sorry
@[simp]
lemma Usize.mod_spec {x y : USize} : toUsize x % toUsize y = Result.ok (toUsize (x % y)) := by sorry
@[simp]
lemma Usize.lt_spec {x y : USize} : toUsize x < toUsize y ↔ x < y := by sorry

-- Mathlib.Vector is really painful to work with here. Maybe just using List everywhere would be better?
-- It would be at the expense of carrying around `<length` proofs everywhere though.
@[simp]
lemma Array.index_mut_usize_spec {n : ℕ} {m : Usize} {v : Mathlib.Vector UInt8 n} (h : m = toUsize n.toUSize) (i : USize) (hi : i.toNat < n):
  (v.toArrayU8 h).index_mut_usize (toUsize i) = Result.ok (toU8 v[i.toNat], fun x ↦ (v.set i.toNat (toUInt8 x)).toArrayU8 h) := by sorry

@[simp]
lemma ByteArray.toSlice_len {b : ByteArray} : b.toSlice.len = toUsize b.size.toUSize := by sorry
@[simp]
lemma Array.toSlice_len {b : Array UInt8} : b.toSlice.len = toUsize b.size.toUSize := by sorry

@[simp]
lemma cast_U64_Usize_spec {n : ℕ} : Scalar.cast ScalarTy.U64 (toUsize n.toUSize) = Result.ok (toU64 n.toUInt64) := by
  sorry
@[simp]
lemma cast_U8_U64_spec {n : UInt64} : Scalar.cast ScalarTy.U8 (toU64 n) = Result.ok (toU8 n.toUInt8) := by
  sorry

def arraySpec
    {rust : Array U32 5#usize} {spec : Mathlib.Vector SHA1.Word 5}
    (heq : rust = spec.toArrayU32 sorry) (i : Usize) (hi : i.toNat < 5) :
    rust.index_usize i = Result.ok (toU32 spec[i.toNat]) := by sorry

def shiftrSpec
    {spec : SHA1.Word} (i : U32) :
    toU32 spec >>> i = Result.ok (toU32 (spec >>> toUInt32 i)) := by sorry

def and255Spec
    {spec : SHA1.Word}:
    Scalar.cast ScalarTy.U8 (toU32 spec &&& 255#u32) = Result.ok (toU8 (spec &&& 255).toUInt8) := by sorry

@[simp]
lemma Vec.new_spec : alloc.vec.Vec.new U8 = Array.toVec #[] := by sorry

@[simp]
lemma Vec.push_spec
    {spec : Array UInt8} (i : U8) :
    (Array.toVec spec).push i = Result.ok (Array.toVec (spec.push (toUInt8 i))) := by sorry

@[simp]
lemma Vec.len_spec
    {spec : Array UInt8} :
    spec.toVec.len = toUsize spec.size.toUSize := by sorry

@[simp]
lemma Vec.extend_from_slice_spec {spec₀ spec₁ : Array UInt8} :
  alloc.vec.Vec.extend_from_slice core.clone.CloneU8 spec₀.toVec spec₁.toSlice = Result.ok (spec₀ ++ spec₁).toVec := by sorry

lemma padMessageLoop.equivalence
    (msgLenBitsRust : U64) (msgLenBitsSpec : UInt64)
    (hMsgLen : msgLenBitsRust = toU64 msgLenBitsSpec)
    (paddedMsgRust : alloc.vec.Vec U8) (paddedMsgSpec : Array UInt8)
    (hPaddedMsg : paddedMsgRust = Array.toVec paddedMsgSpec)
    (zeroPaddingLengthRust : Usize) (zeroPaddingLengthSpec : ℕ)
    (hZeroPaddingLength : zeroPaddingLengthRust = toUsize zeroPaddingLengthSpec.toUSize)
    (iRust : Usize) (iSpec : ℕ)
    (hI : iRust = toUsize iSpec.toUSize) :
    let resultRust := sha1.pad_message_loop msgLenBitsRust paddedMsgRust zeroPaddingLengthRust iRust
    let resultSpec := SHA1.padMessageLoop msgLenBitsSpec paddedMsgSpec zeroPaddingLengthSpec iSpec
    resultRust = Result.ok (Array.toVec resultSpec) :=
by
  rw [sha1.pad_message_loop, SHA1.padMessageLoop, hMsgLen, hPaddedMsg, hZeroPaddingLength, hI]
  by_cases hlt : iSpec < zeroPaddingLengthSpec
  · have : iSpec.toUSize < zeroPaddingLengthSpec.toUSize := by sorry
    simp [-Scalar.lt_equiv, this, hlt, Usize.ofNat 1, U8.ofNat 0]
    sorry
  · have : ¬(iSpec.toUSize < zeroPaddingLengthSpec.toUSize) := by sorry
    simp [-Scalar.lt_equiv, this, hlt, Usize.ofNat 1, U8.ofNat 0]
    rw [U64.ofNat 56, U64.ofNat 48, U64.ofNat 40, U64.ofNat 32, U64.ofNat 24, U64.ofNat 16, U64.ofNat 8, U64.ofNat 0, U64.ofNat 255]
    simp [and255Spec]

    sorry

lemma padMessage.equivalence (messageRust : Slice U8) (messageSpec : ByteArray)
    (hmessage : messageRust = ByteArray.toSlice messageSpec) :
    let resultRust := sha1.pad_message messageRust
    let resultSpec := SHA1.padMessage messageSpec
    resultRust = Result.ok (ByteArray.toVec resultSpec)
    :=
by
  let ⟨messageSpec⟩ := messageSpec
  rw [sha1.pad_message, SHA1.padMessage, hmessage]
  simp [U64.ofNat 8, Usize.ofNat 1, Usize.ofNat 64, alloc.vec.Vec.with_capacity, ByteArray.toSlice, -alloc.vec.Vec.len]
  simp [Usize.ofNat 56, Usize.ofNat 0]
  sorry

-- The presence of `sorry`s in hypothesese are pretty ugly. I should discharge them automatically with default args,
-- but in general managing scalars like this is not very fun :(
lemma hashToVecLoop.equivalence
    (finalHashRust : Array U32 5#usize) (finalHashSpec : Mathlib.Vector SHA1.Word 5)
    (hFinalHash : finalHashRust = finalHashSpec.toArrayU32 sorry)
    (resultBytesRust : alloc.vec.Vec U8) (resultBytesSpec : Array UInt8)
    (hResultBytes : resultBytesRust = Array.toVec resultBytesSpec)
    (indexRust : Usize) (indexSpec : ℕ)
    (hIndex : indexRust = toUsize indexSpec.toUSize) :
    let resultRust := sha1.hash_to_vec_loop finalHashRust resultBytesRust indexRust
    let resultSpec := SHA1.hashToVecLoop finalHashSpec resultBytesSpec indexSpec
    resultRust = Result.ok (Array.toVec resultSpec)
    :=
by
  have hlength : finalHashRust.val.length = 5 := by sorry
  rw [hIndex]; clear hIndex
  by_cases h : indexSpec ≤ 5
  · induction h using Nat.decreasingInduction generalizing resultBytesRust resultBytesSpec with
    | self =>
      rw [sha1.hash_to_vec_loop, SHA1.hashToVecLoop]
      -- have hnotle : ¬(↑(toUsize k.toUSize) < (5 : ℤ)) := by sorry
      simp [Array.to_slice, hlength]
      sorry
    | of_succ k hk ih =>
      rw [sha1.hash_to_vec_loop, SHA1.hashToVecLoop]
      have hle : ↑(toUsize k.toUSize) < (5 : ℤ) := by sorry
      simp [Array.to_slice, hlength, hle, hk]
      have heq₀ := arraySpec hFinalHash (toUsize k.toUSize) sorry
      have x₀ : toUInt32 0#u32 = 0 := by simp [toUInt32]; rfl
      have x₁ : toUInt32 8#u32 = 8 := by simp [toUInt32]; rfl
      have x₂ : toUInt32 16#u32 = 16 := by simp [toUInt32]; rfl
      have x₃ : toUInt32 24#u32 = 24 := by simp [toUInt32]; rfl
      have hkeq : ((toUsize k.toUSize) : ℤ).toNat = k := by sorry
      have hindex : toUsize k.toUSize + 1#usize = Result.ok (toUsize (k + 1).toUSize) := by sorry
      -- simp will work well if you have the right set of lemmas and nudge it enough to reduce everything properly
      simp [heq₀, hResultBytes, shiftrSpec, and255Spec, toUInt8_toU8, hkeq, hindex]
      rw [x₀, x₁, x₂, x₃]
      refine ih ?_ ?_ ?_
      rfl
  · sorry

lemma hashToVec.equivalence (finalHashRust : Array U32 5#usize) (finalHashSpec : Mathlib.Vector SHA1.Word 5)
    (hFinalHash : finalHashRust = finalHashSpec.toArrayU32 sorry) :
    let resultRust := sha1.hash_to_vec finalHashRust
    let resultSpec := SHA1.hashToVec finalHashSpec
    resultRust = Result.ok (ByteArray.toVec resultSpec)
    :=
by
  rw [sha1.hash_to_vec, SHA1.hashToVec]
  have := hashToVecLoop.equivalence finalHashRust finalHashSpec hFinalHash (alloc.vec.Vec.new U8) #[] sorry 0#usize 0 sorry
  simp only [this, Result.ok.injEq]
  rfl

lemma SHA1.equivalence (message_rust : Slice U8) (message_spec : ByteArray)
    (hmessage : message_rust = ByteArray.toSlice message_spec) :
    let resultRust := sha1.hash message_rust
    let resultSpec := SHA1.hash message_spec
    resultRust = Result.ok (ByteArray.toVec resultSpec)
    :=
by
  simp [sha1.hash, hashToVecLoop.equivalence]

  sorry
