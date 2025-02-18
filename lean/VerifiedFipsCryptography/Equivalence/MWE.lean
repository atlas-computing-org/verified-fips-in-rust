import Mathlib

lemma Fin_is_hard (x y n : Nat) : x + (y - x) = y := by
  have : 2^32 ≤ USize.size := by sorry
  omega
  sorry
