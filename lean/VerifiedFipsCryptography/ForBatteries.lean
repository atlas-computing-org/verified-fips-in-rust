import Batteries
import Mathlib

namespace Subarray

-- @[simp]
-- theorem toArray_iff (arr : Array α) : arr[i:j].toArray = (arr.take j) := by
--   sorry


@[simp]
theorem toArray_size (arr : Array α) : arr[i:j].toArray.size = j - i := by
  sorry

@[simp]
theorem toArray_eq_empty (arr : Array α) : arr[i:i].toArray = #[] := by
  unfold Array.toSubarray
  split_ifs with h0 h1
  · simp [toArray, Array.ofSubarray, Id.run]
    sorry
  · sorry
  · sorry

@[simp]
theorem toArray_eq_self (arr : Array α) (hn : arr.size ≤ n) : arr[0:n].toArray = arr := by
  sorry

end Subarray

namespace Array

theorem toArray_eq_extract (arr : Array α) (i j : Nat) : arr[i:j].toArray = arr.extract i j := by sorry

theorem toArray_getElem_size (arr : Array α) (i j k : Nat) (h : k < arr[i:j].toArray.size) :
  i + k < arr.size :=
by
  simp_all
  sorry

-- theorem toArray_getElem (arr : Array α) (i j k : Nat) (h : k < arr[i:j].toArray.size) :
--   arr[i:j].toArray[k] = arr[i + k]

-- theorem set!_toSubarray (arr : Array α) (i j : Nat) (v : α) (hj : j + 1 < arr.size) :
--   (arr.set! (j + 1) v)[i:j+1].toArray = arr[i:j].toArray.push v :=
-- by
--   ext k hk hk'
--   ·
--     sorry
--   · simp [setIfInBounds]
--     sorry

-- theorem foldlM_extract_last (arr : Array α) (h : 0 < arr.size) :
--   (arr.extract (arr.size - 1) arr.size).foldl f init = (arr.extract (i + 1) arr.size).foldl f (f init arr[i]) :=
-- by
--   simp [foldl, foldlM, Id.run]
--   unfold foldlM.loop
--   simp [h]; split
--   · have : ¬i < arr.size := by omega
--     contradiction
--   · split
--     ·
--       sorry
--     · have : i + 1 = arr.size := by omega
--       have : i = arr.size - 1 := by omega
--       simp_rw [this]
--       simp
--       sorry

theorem extract_toList_eq_cons (arr : Array α) (h : i < arr.size) :
  (arr.extract i arr.size).toList = arr[i] :: (arr.extract (i + 1) arr.size).toList :=
by
  simp only [toList_extract]
  rw [← List.getElem_cons_drop _ _ (by simpa), List.take_cons (by omega)]
  congr 1

theorem foldl_eq_extract_succ (arr : Array α) (h : i < arr.size) :
  (arr.extract i arr.size).foldl f init = (arr.extract (i + 1) arr.size).foldl f (f init arr[i]) :=
by
  rw [← foldl_toList, ← foldl_toList, extract_toList_eq_cons]
  simp; assumption

end Array

namespace ByteArray

theorem foldl_toArray (b : ByteArray) : b.foldl f init = b.data.foldl f init := by
  sorry

end ByteArray
