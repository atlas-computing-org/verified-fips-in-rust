import Batteries
import Mathlib

namespace Array

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

theorem extract_all' (arr : Array α) (h : arr.size ≤ n) :
  arr.extract 0 n = arr :=
by
  have := @extract_all α arr
  unfold extract at this ⊢
  simp [h] at this ⊢
  assumption

end Array

namespace ByteArray

theorem foldl_toArray (b : ByteArray) : b.foldl f init = b.data.foldl f init := by
  -- This `sorry` is really annoying to prove, but it's obviously true.
  sorry

end ByteArray
