import Aeneas
import VerifiedFipsCryptography.RustTranslations.FipsImplementations
import Mathlib.Tactic

open Aeneas.Std fips_implementations.algorithms alloc.vec core clone num

-- # `UInt8` <> `U8`

def UInt32.rotate_left (x n : UInt32) : UInt32 :=
  ⟨x.toBitVec.rotateLeft n.toNat⟩

-- See `RustTranslations/FipsImplementations.lean`:
-- lemma UInt8.U8_min_le {x : UInt8} : U8.min ≤ x.toNat := by simp [U8.min]
-- lemma UInt8.le_U8_max {x : UInt8} : x.toNat ≤ U8.max := by
--   simp only [U8.max, Nat.cast_le_ofNat]
--   exact Nat.le_of_lt_succ (UInt8.toNat_lt_size x)

-- def UInt8.toU8 (x : UInt8) : U8 := ⟨x.toNat, x.U8_min_le, x.le_U8_max⟩
-- def Nat.toU8 (x : Nat) : U8 := x.toUInt8.toU8

def UInt8.ofU8 (x : U8) : UInt8 := x.toNat.toUInt8

@[simp] lemma UInt8.ofU8_toU8 {x : UInt8} : UInt8.ofU8 x.toU8 = x := by simp [UInt8.toU8, UInt8.ofU8]

lemma UInt8.U8.coe_toU8 {x : UInt8} : (x.toU8 : ℤ) = (x.toNat : ℤ) := by
  simp [Nat.toU8, UInt8.toU8]

lemma Nat.U8.coe_toU8 {x : ℕ} : (x.toU8 : ℤ) = (x.toUInt8.toNat : ℤ) := by
  simp [Nat.toU8, UInt8.toU8]

-- # `Int8` <> `I8`

-- See `UInt8.U8_min_le` for similar proof
def Int8.toI8 (x : Int8) : I8 := ⟨x.toNat, sorry, sorry⟩
def Nat.toI8 (x : Nat) : I8 := x.toInt8.toI8

def Int8.ofI8 (x : I8) : Int8 := x.toNat.toInt8
-- See `UInt8.ofU8_toU8` for similar proof
@[simp] lemma Int8.ofI8_toI8 {x : Int8} : Int8.ofI8 x.toI8 = x := sorry

-- See `UInt8.toU8` for similar proof
def UInt32.toU32 (x : UInt32) : U32 := ⟨x.toNat, sorry, sorry⟩
def Nat.toU32 (x : Nat) : U32 := x.toUInt32.toU32

-- See `Usize.le_max` for similar proof
@[simp]
lemma U32.le_max {x : ℕ} : x ≤ U32.max ↔ x < UInt32.size := by
  sorry

def u32x4 := UInt32 × UInt32 × UInt32 × UInt32

def u32x4.toU32x4 (x : u32x4) : sha1.u32x4 :=
  let (a, b, c, d) := x
  (a.toU32, b.toU32, c.toU32, d.toU32)

lemma u32x4.toU32x4_apply (x : u32x4) : x.toU32x4 = (x.1.toU32, x.2.1.toU32, x.2.2.1.toU32, x.2.2.2.toU32) := by rfl
lemma u32x4.toU32x4_unapply {a b c d : UInt32} : (a.toU32, b.toU32, c.toU32, d.toU32) = u32x4.toU32x4 (a, b, c, d) := by rfl

def fips_implementations.algorithms.sha1.u32x4x6 := sha1.u32x4 × sha1.u32x4 × sha1.u32x4 × sha1.u32x4 × sha1.u32x4 × sha1.u32x4

def u32x4x6 := u32x4 × u32x4 × u32x4 × u32x4 × u32x4 × u32x4

def u32x4x6.toU32x4x6 (x : u32x4x6) : sha1.u32x4x6 :=
  let (x0, x1, x2, x3, x4, x5) := x
  (x0.toU32x4, x1.toU32x4, x2.toU32x4, x3.toU32x4, x4.toU32x4, x5.toU32x4)

@[simp]
def u32x4x6.toU32x4x6_apply_2_1 (x : u32x4x6) : (u32x4x6.toU32x4x6 x).2.1 = u32x4.toU32x4 x.2.1 := by
  let (x0, x1, x2, x3, x4, x5) := x
  simp [toU32x4x6]

@[simp]
def u32x4x6.toU32x4x6_apply_1 (x : u32x4x6) : (u32x4x6.toU32x4x6 x).1 = u32x4.toU32x4 x.1 := by
  let (x0, x1, x2, x3, x4, x5) := x
  simp [toU32x4x6]

-- See `UInt8.toU8` for similar proof
def UInt64.toU64 (x : UInt64) : U64 := ⟨x.toNat, sorry, sorry⟩
def Nat.toU64 (x : Nat) : U64 := x.toUInt64.toU64

-- See `UInt8.toU8` for similar proof
def USize.toUsize (x : USize) : Usize := ⟨x.toNat, sorry, sorry⟩
def Nat.toUsize (x : Nat) : Usize := x.toUSize.toUsize

lemma Usize.coe_toUsize {x : ℕ} : (x.toUsize : ℤ) = (x.toUSize.toNat : ℤ) := by
  simp [Nat.toUsize, USize.toUsize]

lemma Nat.coe_toUsize_of_le {x : ℕ} (h : x < 2 ^ 32) : (x.toUsize : ℤ) = (x : ℤ) := by
  simp [Nat.toUsize, USize.toUsize]
  cases System.Platform.numBits_eq <;> simp_all <;> omega

@[simp]
lemma Usize.le_max {x : ℕ} : x ≤ Usize.max ↔ x < USize.size := by
  cases System.Platform.numBits_eq <;>
  unfold System.Platform.numBits at * <;>
  simp [Usize.max, Usize.refined_max, Usize.smax, USize.size, System.Platform.numBits, System.Platform.getNumBits, *] <;>
  omega

@[simp]
lemma U8.ofUInt8_eq_aux (x : ℕ) [OfNat ℤ x] (h : Scalar.cMin ScalarTy.U8 ≤ (OfNat.ofNat x) ∧ (OfNat.ofNat x) ≤ Scalar.cMax ScalarTy.U8 := by decide) :
    U8.ofInt (OfNat.ofNat x) h = (@OfNat.ofNat UInt8 x).toU8 :=
by

  simp [U8.ofInt, Scalar.ofInt, Scalar.ofIntCore, UInt8.toU8, UInt8.toNat]
  sorry

-- This is a set of unfortunate lemmas that are used to manually rewrite Aeneas' scalars.
-- I've tried various things, and this seems to be an OK solution for now.
-- A better one would be to write a tactic that goes in and applies these rewrites automatically.

@[simp]
lemma U8.ofUInt8_eq (x : ℤ) (y : UInt8) (h : Scalar.cMin ScalarTy.U8 ≤ x ∧ x ≤ Scalar.cMax ScalarTy.U8 := by decide) (hxy : x = y.toNat := by rfl) :
    U8.ofInt x h = y.toU8 := by simp [UInt8.toU8, U8.ofInt, Scalar.ofInt, Scalar.ofIntCore, hxy]

-- See `U8.ofUInt8_eq` for similar proof
@[simp]
lemma U32.ofUInt32_eq (x : ℤ) (y : UInt32) (h : Scalar.cMin ScalarTy.U32 ≤ x ∧ x ≤ Scalar.cMax ScalarTy.U32 := by decide) (hxy : x = y.toNat := by rfl) :
    U32.ofInt x h = y.toU32 := by simp [UInt32.toU32, U32.ofInt, Scalar.ofInt, Scalar.ofIntCore, hxy]

-- See `U8.ofUInt8_eq` for similar proof
@[simp]
lemma U64.ofUInt64_eq (x : ℤ) (y : UInt64) (h : Scalar.cMin ScalarTy.U64 ≤ x ∧ x ≤ Scalar.cMax ScalarTy.U64 := by decide) (hxy : x = y.toNat := by rfl) :
    U64.ofInt x h = y.toU64 := by simp [UInt64.toU64, U64.ofInt, Scalar.ofInt, Scalar.ofIntCore, hxy]

-- See `U8.ofUInt8_eq` for similar proof
@[simp]
lemma Usize.ofUSize_eq (x : ℤ) (y : USize) (h : Scalar.cMin ScalarTy.Usize ≤ x ∧ x ≤ Scalar.cMax ScalarTy.Usize := by decide) (hxy : x = y.toNat := by rfl) :
    Usize.ofInt x h = y.toUsize := by simp [USize.toUsize, Usize.ofInt, Scalar.ofInt, Scalar.ofIntCore, hxy]

@[simp]
lemma U8.ofNat_eq (x : ℤ) (y : ℕ) (h : Scalar.cMin ScalarTy.U8 ≤ x ∧ x ≤ Scalar.cMax ScalarTy.U8 := by decide) (hxy : x = y := by rfl) :
    U8.ofInt x h = y.toU8 :=
by
  simp [Nat.toU8, UInt8.toU8, U8.ofInt, Scalar.ofInt, Scalar.ofIntCore, hxy]
  simp_rw [Scalar.cMin, Scalar.min, Scalar.cMax, Scalar.max, autoParam, U8.min, U8.max] at h
  simp_all [← Nat.lt_succ]
  norm_cast
  exact Eq.symm (Nat.mod_eq_of_lt h)

-- See `U8.ofNat_eq` for similar proof
@[simp]
lemma U32.ofNat_eq (x : ℤ) (y : ℕ) (h : Scalar.cMin ScalarTy.U32 ≤ x ∧ x ≤ Scalar.cMax ScalarTy.U32 := by decide) (hxy : x = y := by rfl) :
    U32.ofInt x h = y.toU32 := by sorry

-- See `U8.ofNat_eq` for similar proof
@[simp]
lemma U64.ofNat_eq (x : ℤ) (y : ℕ) (h : Scalar.cMin ScalarTy.U64 ≤ x ∧ x ≤ Scalar.cMax ScalarTy.U64 := by decide) (hxy : x = y := by rfl) :
    U64.ofInt x h = y.toU64 := by sorry

-- See `U8.ofNat_eq` for similar proof
@[simp]
lemma Usize.ofNat_eq (x : ℤ) (y : ℕ) (h : Scalar.cMin ScalarTy.Usize ≤ x ∧ x ≤ Scalar.cMax ScalarTy.Usize := by decide) (hxy : x = y := by rfl) :
    Usize.ofInt x h = y.toUsize := by sorry

-- XOR is sorry'ed in Aeneas
@[simp]
lemma UInt32.U32.xor_spec {x y : UInt32} : x.toU32 ^^^ y.toU32 = (x ^^^ y).toU32 := by sorry
-- OR is sorry'ed in Aeneas
@[simp]
lemma UInt32.U32.or_spec {x y : UInt32} : x.toU32 ||| y.toU32 = (x ||| y).toU32 := by sorry
-- SHL is sorry'ed in Aeneas
@[simp]
lemma Nat.U32.shift_left_spec {x y : ℕ} : x.toU32 <<< y.toU32 = Result.ok (x <<< y).toU32 := by sorry
-- SHL is sorry'ed in Aeneas
@[simp]
lemma UInt32.U32.shift_left_spec {x y : UInt32} : x.toU32 <<< y.toU32 = Result.ok (x <<< y).toU32 := by sorry
-- SHR is sorry'ed in Aeneas
@[simp]
lemma Nat.U32.shift_right_spec {x y : ℕ} : x.toU32 >>> y.toU32 = Result.ok (x >>> y).toU32 := by sorry
-- SHR is sorry'ed in Aeneas
@[simp]
lemma UInt32.U32.shift_right_spec {x y : UInt32} : x.toU32 >>> y.toU32 = Result.ok (x >>> y).toU32 := by sorry
-- ROTL is sorry'ed in Aeneas
@[simp]
lemma UInt32.U32.rotate_left_spec {x y : UInt32} : U32.rotate_left x.toU32 y.toU32 = (x.rotate_left y).toU32 := by sorry
-- AND is sorry'ed in Aeneas
@[simp]
lemma Nat.U32.and_spec {x y : ℕ} : x.toU32 &&& y.toU32 = (x &&& y).toU32 := by sorry
-- AND is sorry'ed in Aeneas
@[simp]
lemma UInt32.U32.and_spec {x y : UInt32} : x.toU32 &&& y.toU32 = (x &&& y).toU32 := by sorry
-- wrapping_add is sorry'ed in Aeneas
@[simp]
lemma UInt32.U32.wrapping_add_spec {x y : UInt32} : U32.wrapping_add x.toU32 y.toU32 = (x + y).toU32 := by sorry

-- sorry'ed in Aeneas
@[simp]
lemma UInt64.U64.xor_spec {x y : UInt64} : x.toU64 ^^^ y.toU64 = (x ^^^ y).toU64 := by sorry

-- sorry'ed in Aeneas
@[simp]
lemma UInt64.U64.or_spec {x y : UInt64} : x.toU64 ||| y.toU64 = (x ||| y).toU64 := by
  sorry
-- sorry'ed in Aeneas
@[simp]
lemma Nat.U64.shift_left_spec {x y : ℕ} : x.toU64 <<< y.toU64 = Result.ok (x <<< y).toU64 := by sorry
-- sorry'ed in Aeneas
@[simp]
lemma UInt64.U64.shift_left_spec {x y : UInt64} : x.toU64 <<< y.toU64 = Result.ok (x <<< y).toU64 := by sorry
-- sorry'ed in Aeneas
@[simp]
lemma Nat.U64.shift_right_spec {x y : ℕ} : x.toU64 >>> y.toU64 = Result.ok (x >>> y).toU64 := by sorry
-- sorry'ed in Aeneas
@[simp]
lemma UInt64.U64.shift_right_spec {x y : UInt64} : x.toU64 >>> y.toU64 = Result.ok (x >>> y).toU64 := by sorry
-- sorry'ed in Aeneas
@[simp]
lemma Nat.U64.and_spec {x y : ℕ} : x.toU64 &&& y.toU64 = (x &&& y).toU64 := by sorry
-- sorry'ed in Aeneas
@[simp]
lemma UInt64.U64.and_spec {x y : UInt64} : x.toU64 &&& y.toU64 = (x &&& y).toU64 := by sorry
-- sorry'ed in Aeneas
@[simp]
lemma Nat.U64.add_spec {x y : ℕ} : x.toU64 + y.toU64 = Result.ok (x + y).toU64 := by sorry
-- sorry'ed in Aeneas
@[simp]
lemma UInt64.U64.add_spec {x y : UInt64} : x.toU64 + y.toU64 = Result.ok (x + y).toU64 := by sorry

-- See `Usize.add_spec` for similar proof
@[simp]
lemma Nat.U64.mul_spec {x y : ℕ} (hsize : x * y < USize.size) : x.toU64 * y.toU64 = Result.ok (x * y).toU64 := by sorry
-- See `Usize.add_spec` for similar proof
@[simp]
lemma UInt64.U64.mul_spec {x y : UInt64} (hsize : x.toNat * y.toNat < USize.size) : x.toU64 * y.toU64 = Result.ok (x * y).toU64 := by sorry

@[simp]
lemma Usize.coe_eq_iff {x y : Usize} : (x : ℤ) = (y : ℤ) ↔ x = y := by
  scalar_tac

-- Example proof for the `Scalar.{add/sub/mul}_spec` types lemmas.
@[simp]
lemma Usize.add_spec {x y : ℕ} (hsize : x + y < USize.size) : x.toUsize + y.toUsize = Result.ok (x + y).toUsize := by
  have h₀ : x.toUsize + y.toUsize ≤ Usize.max := by
    simp only [coe_toUsize, USize.toNat_ofNat, ← Int.natCast_add, Usize.le_max]
    exact lt_of_le_of_lt (add_le_add (Nat.mod_le _ _) (Nat.mod_le _ _)) hsize
  have h₁ : (x.toUsize : ℤ) + y.toUsize = (x + y).toUsize := by
    simp only [coe_toUsize, USize.toNat_ofNat, ← Int.natCast_add, Usize.le_max, USize.size] at hsize ⊢
    norm_cast
    have hx : x < 2 ^ System.Platform.numBits := by omega
    have hy : y < 2 ^ System.Platform.numBits := by omega
    rw [Nat.mod_eq_of_lt hsize, Nat.mod_eq_of_lt hx, Nat.mod_eq_of_lt hy]
  obtain ⟨z, h, hz⟩ := Aeneas.Std.Usize.add_spec h₀
  simp [h, hz]
  rwa [h₁, Usize.coe_eq_iff] at hz

-- See `Usize.add_spec` for similar proof
@[simp]
lemma Nat.Usize.sub_spec {x y : ℕ} (hsize : x ≥ y) : x.toUsize - y.toUsize = Result.ok (x - y).toUsize := by sorry
-- See `Usize.add_spec` for similar proof
@[simp]
lemma USize.Usize.sub_spec {x y : USize} : x.toUsize - y.toUsize = Result.ok (x - y).toUsize := by sorry
-- See `Usize.add_spec` for similar proof
@[simp]
lemma Usize.mul_spec {x y : Nat} (hsize : x * y < USize.size) : x.toUsize * y.toUsize = Result.ok (x * y).toUsize := by sorry
-- See `Usize.add_spec` for similar proof
@[simp]
lemma Nat.Usize.mod_spec {x y : ℕ} : x.toUsize % y.toUsize = Result.ok (x % y).toUsize := by sorry
-- See `Usize.add_spec` for similar proof
@[simp]
lemma USize.Usize.mod_spec {x y : USize} : x.toUsize % y.toUsize = Result.ok (x % y).toUsize := by sorry
-- See `Usize.add_spec` for similar proof
@[simp]
lemma Usize.lt_spec {x y : USize} : x.toUsize < y.toUsize ↔ x < y := by sorry

@[simp]
lemma U32.try_mk_spec {n : ℕ} (h : n < UInt32.size) : Scalar.tryMk ScalarTy.U32 n = Result.ok n.toU32 := by
  simp_rw [Scalar.tryMk, Scalar.tryMkOpt, Scalar.check_bounds_eq_in_bounds]
  simp [Scalar.min, Scalar.max, h, Scalar.ofIntCore, Nat.toU32, UInt32.toU32]
  norm_cast
  exact Eq.symm (Nat.mod_eq_of_lt h)

-- See `UInt8.U8.cast_U32_spec` for similar proof
@[simp]
lemma Nat.U8.cast_U32_spec {n : ℕ} : Scalar.cast ScalarTy.U32 n.toU8 = Result.ok n.toUInt8.toNat.toU32 := by sorry

@[simp]
lemma UInt8.U8.cast_U32_spec {n : UInt8} : Scalar.cast ScalarTy.U32 n.toU8 = Result.ok n.toUInt32.toU32 := by
  simp [Scalar.cast, UInt8.U8.coe_toU8, UInt8.toUInt32, U32.try_mk_spec (lt_trans n.toNat_lt_size (by decide)), Nat.toU32, UInt32.toU32]
  norm_cast
  rw [Nat.mod_eq_of_lt (lt_trans n.toNat_lt_size (by decide))]

-- See `UInt8.U8.cast_U32_spec` for similar proof
@[simp]
lemma UInt32.U32.cast_U8_spec {n : UInt32} : Scalar.cast ScalarTy.U8 n.toU32 = Result.ok n.toUInt8.toU8 := by sorry

-- See `UInt8.U8.cast_U32_spec` for similar proof
@[simp]
lemma UInt64.U64.cast_U8_spec {n : UInt64} : Scalar.cast ScalarTy.U8 n.toU64 = Result.ok n.toUInt8.toU8 := by sorry

-- See `UInt8.U8.cast_U32_spec` for similar proof
@[simp]
lemma Nat.Usize.cast_U64_spec {n : ℕ} : Scalar.cast ScalarTy.U64 n.toUsize = Result.ok n.toUInt64.toU64 := by sorry

lemma Array.toVecU8_aux {v : Array UInt8} (h : v.size < USize.size) : (List.map UInt8.toU8 v.toList).length ≤ Usize.max := by simp [h]

def Array.toVecU8 (v : Array UInt8) (h : v.size < USize.size) : Vec U8 := ⟨v.toList.map UInt8.toU8, v.toVecU8_aux h⟩

-- See `Array.toVecU8` for similar proof
def Array.toVecU32 (v : Array UInt32) (h : v.size < USize.size) : Vec U32 := ⟨v.toList.map UInt32.toU32, sorry⟩

-- See `Array.toVecU8` for similar proof
def Array.toArrayU8 (arr : Array UInt8) (h : arr.size = n.toNat := by simp_all) : Array U8 n :=
  ⟨arr.toList.map UInt8.toU8, sorry⟩

-- See `Array.toVecU8` for similar proof
@[irreducible]
def Array.toArrayU32 (arr : Array UInt32) (h : arr.size = n.toNat := by simp_all) : Array U32 n :=
  ⟨arr.toList.map UInt32.toU32, sorry⟩

-- See `Array.toVecU8` for similar proof
def Array.toVecArrayU8 (v : Array (Array UInt8)) (h : v.size < USize.size) : Vec (Array U8 n) :=
  ⟨v.toList.map (fun v ↦ v.toArrayU8 sorry), sorry⟩

-- The awkward thing is that you have to start carrying proofs around in your {List/Array}.to{Array/Vec} definitions.
-- Ideally this should be refactored.
lemma Array.toVecU8.push_spec (arr : Array UInt8) (x : UInt8) (h : arr.size + 1 < USize.size) :
  (arr.toVecU8 (Nat.lt_of_succ_lt h)).push x.toU8 = .ok ((arr.push x).toVecU8 (by simp [h])) :=
by
  simp [Array.toVecU8, Vec.push]
  split_ifs with h
  · simp_all
  · norm_cast at h
    simp_rw [Usize.le_max] at h
    simp_all

-- See `Array.toVecU8.push_spec` for similar proof
@[simp]
lemma Array.toVecU8_slice_len (arr : Array UInt8) (h : arr.size < USize.size) :
  Slice.len (arr.toVecU8 h) = arr.size.toUsize := by sorry

@[simp]
lemma Array.toVecU8.RangeUsize.get_spec (arr : Array UInt8) (h : arr.size < USize.size) (a b : Nat) :
  slice.index.RangeUsize.get (core.ops.range.Range.mk a.toUsize b.toUsize) (arr.toVecU8 h) = .ok (.some ((arr.extract a b).toVecU8 (by simp; omega))) := by sorry

-- See `Array.toVecU8.push_spec` for similar proof
@[simp]
lemma Array.toVecU32_slice_len (arr : Array UInt32) :
  Slice.len (arr.toVecU32 sorry) = arr.size.toUsize := by sorry

-- See `Array.toVecU8.push_spec` for similar proof
@[simp]
lemma Array.toVecArrayU8_len (arr : Array (Array UInt8)) :
  ((arr.toVecArrayU8 sorry) : Vec (Array U8 n)).len = arr.size.toUsize := by sorry

@[simp]
lemma Vec.U8.new_spec : Vec.new U8 = #[].toVecU8 (by simp) := by rfl

@[simp]
lemma Vec.U8.with_capacity_spec : Vec.with_capacity U8 n = #[].toVecU8 (by simp) := by rfl

-- `Vec.extend_from_slice` is sorry'ed in Aeneas
-- See `Array.toVecU8.push_spec` for similar proof
@[simp]
lemma Vec.U8.extend_from_slice_spec {arr slice : Array UInt8} (h : arr.size + slice.size < USize.size) :
  Vec.extend_from_slice CloneU8 (arr.toVecU8 sorry) (slice.toVecU8 sorry) = Result.ok ((arr ++ slice).toVecU8 sorry) := by sorry

@[simp]
lemma Vec.ArrayU8.new_spec : Vec.new (Array U8 n) = #[].toVecArrayU8 (by simp) := by rfl

-- See `Array.toVecU8.push_spec` for similar proof
@[simp]
lemma Array.U8.make_spec {n : Usize} {arr : List U8} {hl : arr.length = n.val} : Array.make n arr hl = (arr.map UInt8.ofU8).toArray.toArrayU8 sorry := by sorry

-- See `Array.toVecU8.push_spec` for similar proof
@[simp]
lemma Array.toArrayU8.to_slice_spec {n : Usize} {arr : Array UInt8} {h : arr.size = n.toNat} :
  (arr.toArrayU8 h).to_slice = Result.ok (arr.toVecU8 sorry) := by sorry

-- See `Array.toVecU8.push_spec` for similar proof
lemma Array.toArrayU8.index_usize_spec {n : Usize} (arr : Array UInt8) (h : arr.size = n.toNat := by scalar_tac) (i : ℕ) (hi : i < arr.size) :
  (arr.toArrayU8 h).index_usize i.toUsize = .ok arr[i].toU8 := by sorry

-- See `Array.toVecU8.push_spec` for similar proof
@[simp]
lemma Array.toArrayU32.to_slice_spec {n : Usize} {arr : Array UInt32} {h : arr.size = n.toNat} :
  (arr.toArrayU32 h).to_slice = Result.ok (arr.toVecU32 sorry) := by sorry

-- See `Array.toVecU8.push_spec` for similar proof
@[simp]
lemma Array.toArrayU32.length_spec {n : Usize} (arr : Array UInt32) (h : arr.size = n.toNat := by scalar_tac) :
  (arr.toArrayU32 h).length = arr.size := sorry

-- See `Array.toVecU8.push_spec` for similar proof
lemma Array.toArrayU32.index_usize_spec {n : Usize} (arr : Array UInt32) (h : arr.size = n.toNat := by scalar_tac) (i : ℕ) (hi : i < arr.size) :
  (arr.toArrayU32 h).index_usize i.toUsize = .ok arr[i].toU32 := by sorry

-- See `Array.toVecU8.push_spec` for similar proof
lemma Array.toArrayU32.update_spec {n : Usize} (arr : Array UInt32) (h : arr.size = n.toNat := by scalar_tac) (i : ℕ) (hi : i < arr.size) (v : UInt32) :
  (arr.toArrayU32 h).update i.toUsize v.toU32 = (arr.set i v).toArrayU32 sorry := by sorry

-- See `Array.toVecU8.push_spec` for similar proof
lemma Array.toArrayU32.update_usize_spec {n : Usize} (arr : Array UInt32) (h : arr.size = n.toNat := by scalar_tac) (i : ℕ) (hi : i < arr.size) (v : UInt32) :
  (arr.toArrayU32 h).update_usize i.toUsize v.toU32 = .ok ((arr.set i v).toArrayU32 sorry) := by sorry

-- See `Array.toVecU8.push_spec` for similar proof
lemma Array.toArrayU32.repeat_spec (i : ℕ) (x : UInt32) :
  Array.repeat i.toUsize x.toU32 = (Array.mk (List.replicate i x)).toArrayU32 sorry := by sorry

-- See `Array.toVecU8.push_spec` for similar proof
lemma Array.toVecArrayU8.index_usize_spec {n : Usize} (arr : Array (Array UInt8)) (h : arr.size < USize.size) (i : ℕ) (hi : i < arr.size) :
  ((arr.toVecArrayU8 h) : Vec (Array U8 n)).index_usize i.toUsize = .ok (arr[i].toArrayU8 sorry) := by sorry

-- # FromLean instances

class FromLean (α : Type u) (β : Type v) where
  fromLean : α → β

instance : FromLean UInt8 U8 where
  fromLean := UInt8.toU8

instance : FromLean UInt32 U32 where
  fromLean := UInt32.toU32

lemma range'_eq_cons (h : i < n) : List.range' i (n - i) 1 = i :: List.range' (i + 1) (n - (i + 1)) 1 := by
  induction n with
  | zero =>
    have := Nat.zero_le i
    contradiction
  | succ n ih =>
    have : n + 1 - i = n - i + 1 := by omega
    simp [this, List.range']

def Aeneas.loop_form (arr : Array α) (n i : Nat) (f : Array α → Nat → Array α) : Array α :=
  if i < n then
    let arr := f arr i
    Aeneas.loop_form arr n (i + 1) f
  else
    arr

lemma for_loop_eq_loop_form (arr : Array α) (f : Array α → Nat → Array α) :
  Id.run (do
    let mut a := arr
    for j in [i:n] do
      a := f a j
    a
  ) =
  Aeneas.loop_form arr n i f := by
  simp [Id.run]
  by_cases hi : i ≤ n
  · induction hi using Nat.decreasingInduction generalizing arr with
    | self => simp [Aeneas.loop_form]
    | of_succ i hi ih =>
      unfold Aeneas.loop_form
      simp [hi, range'_eq_cons, ← ih (f arr i)]
  · by_cases hi : i = n
    · simp [Aeneas.loop_form, hi]
    · have hi : ¬i < n := by linarith
      have hn : n - i = 0 := by omega
      simp [Aeneas.loop_form, hi, hn]

def Aeneas.loop_append_form (arr : Array α) (n i : Nat) (f : Array α → Nat → Array α) : Array α :=
  if i < n then
    let arr := arr ++ f arr i
    Aeneas.loop_append_form arr n (i + 1) f
  else
    arr

lemma for_loop_append_eq_loop_append_form (arr : Array α) (f : Array α → Nat → Array α) :
  Id.run (do
    let mut a := arr
    for i in [0:n] do
      a := a ++ f a i
    a
  ) =
  Aeneas.loop_append_form arr n 0 f := by
  simp [Id.run]
  nth_rw 1 [← Nat.sub_zero n]
  generalize 0 = i
  by_cases hi : i ≤ n
  · induction hi using Nat.decreasingInduction generalizing arr with
    | self => simp [Aeneas.loop_append_form]
    | of_succ i hi ih =>
      unfold Aeneas.loop_append_form
      simp [hi, range'_eq_cons, ← ih (arr ++ f arr i)]
  · by_cases hi : i = n
    · simp [Aeneas.loop_append_form, hi]
    · have hi : ¬i < n := by linarith
      have hn : n - i = 0 := by omega
      simp [Aeneas.loop_append_form, hi, hn]

lemma Array.of_size_eq_4 (arr : Array α) (h : arr.size = 4) :
  arr = #[arr[0], arr[1], arr[2], arr[3]] :=
by
  ext i hi hi'
  · exact h
  · rw [h] at hi
    interval_cases i <;> rfl

lemma Array.get!_eq_get [Inhabited α] (arr : Array α) (i : Nat) (h : i < arr.size := by get_elem_tactic) :
  arr[i]! = arr[i] :=
by
  simp [getElem!_def, getElem?_def, h]

lemma Array.set_eq_set! [Inhabited α] (arr : Array α) (i : Nat) (v : α) (h : i < arr.size := by get_elem_tactic) :
  arr.set i v = arr.set! i v :=
by simp [setIfInBounds, h]

lemma Nat.eq_mod_usize {x : ℕ} (h : x < 2 ^ 32) : x % 2 ^ System.Platform.numBits = x := by
  cases System.Platform.numBits_eq <;> simp_all; omega

lemma Nat.lt_usize {x : ℕ} (h : x < 2 ^ 32) : x < USize.size := by
  simp [USize.size]
  cases System.Platform.numBits_eq <;> simp_all; omega


namespace Nat

@[elab_as_elim]
def decreasingBlockInduction {n} {motive : (m : ℕ) → m ≤ n → Sort*}
    (of_succ : ∀ k (h : k < n), motive (k + 1) h → motive k (le_of_succ_le h))
    (self : motive n le_rfl) {m} (mn : m ≤ n) : motive m mn := by
  induction mn using leRec with
  | refl => exact self
  | @le_succ_of_le k _ ih =>
    apply ih (fun i hi => of_succ i (le_succ_of_le hi)) (of_succ k (lt_succ_self _) self)

end Nat
