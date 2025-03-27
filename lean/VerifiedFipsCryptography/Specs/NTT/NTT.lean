import Std
import Mathlib.Data.ZMod.Defs

open Std

/-- q = 3329 as in FIPS 203. -/
def q : Nat := 3329

/-- We work in the ring ZMod q. -/
abbrev ModQ := ZMod q

/--
Precomputed ζBitRev7 values for i = 1,…,127, as given in Appendix A of FIPS 203 :contentReference[oaicite:4]{index=4}&#8203;:contentReference[oaicite:5]{index=5}.
Note: the pseudocode uses indices 1..127 but our array is 0-indexed so that
the value for i = 1 is stored at index 0.
-/
def zetaBitRev7 : Vector ModQ 128 :=
  ⟨ #[
    1,    1729, 2580, 3289, 2642, 630,  1897, 848,
    1062, 1919, 193,  797,  2786, 3260, 569,  1746,
    296,  2447, 1339, 1476, 3046, 56,   2240, 1333,
    1426, 2094, 535,  2882, 2393, 2879, 1974, 821,
    289,  331,  3253, 1756, 1197, 2304, 2277, 2055,
    650,  1977, 2513, 632,  2865, 33,   1320, 1915,
    2319, 1435, 807,  452,  1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648,  2474, 3110, 1227, 910,
    17,   2761, 583,  2649, 1637, 723,  2288, 1100,
    1409, 2662, 3281, 233,  756,  2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952,  1461, 2687,
    939,  2308, 2437, 2388, 733,  2337, 268,  641,
    1584, 2298, 2037, 3220, 375,  2549, 2090, 1645,
    1063, 319,  2773, 757,  2099, 561,  2466, 2594,
    2804, 1092, 403,  1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885,  2154
  ], rfl ⟩

/--
Forward Number-Theoretic Transform (NTT) as in Algorithm 9 :contentReference[oaicite:6]{index=6}&#8203;:contentReference[oaicite:7]{index=7}.

This function takes an array f of 256 coefficients (representing f ∈ R₍q₎) and returns the NTT
representation (an array in ZMod q of length 256). The algorithm iterates over groups of butterflies
with lengths 128, 64, …, 2. In each butterfly, the precomputed factor ζBitRev7 (indexed by i)
is used and i is incremented as specified.
-/
def ntt (f : Vector ModQ 256) : Vector ModQ 256 :=
  let n := 256
  -- The list of group sizes (len) in descending order.
  let groups : List Nat := [128, 64, 32, 16, 8, 4, 2]
  Id.run do
    let mut i := 1  -- i will range from 1 to 127 (we use i-1 for 0-indexing into zetaBitRev7)
    for len in groups do
      let step := 2 * len
      let numGroups := n / step
      for g in List.range numGroups do
        let start := g * step
        let zeta := zetaBitRev7.get! (i - 1)
        i := i + 1
        for j in List.range len do
          let idx := start + j
          let v : ModQ := (← f.get! (idx + len))
          let t : ModQ := zeta * v
          let x : ModQ := (← f.get! idx)
          let _ ← f.set! (idx + len) (x - t)
          let _ ← f.set! idx (x + t)
    f

/--
Inverse Number-Theoretic Transform (NTT⁻¹) as in Algorithm 10 :contentReference[oaicite:8]{index=8}&#8203;:contentReference[oaicite:9]{index=9}.

This function takes an array f of 256 coefficients (representing an element of T₍q₎, the NTT
representation) and returns the corresponding polynomial in R₍q₎. The algorithm loops over group
sizes in ascending order (2, 4, …, 128) and uses the precomputed ζBitRev7 values in reverse order.
Finally, every coefficient is multiplied by 3303, which is congruent to 128⁻¹ modulo q.
-/
def nttInv (f : Vector ModQ 256) : Vector ModQ 256 :=
  let n := 256
  -- Group sizes in ascending order.
  let groups : List Nat := [2, 4, 8, 16, 32, 64, 128]
  Id.run do
    let mut i := 127  -- i starts at 127 and decrements
    for len in groups do
      let step := 2 * len
      let numGroups := n / step
      for g in List.range numGroups do
        let start := g * step
        let zeta := zetaBitRev7.get! (i - 1)
        i := i - 1
        for j in List.range len do
          let idx := start + j
          let t : ModQ ← f.get! idx
          let u : ModQ ← f.get! (idx + len)
          let _ ← f.set! idx (t + u)
          let _ ← f.set! (idx + len) (zeta * (u - t))
    -- Multiply every entry by 3303 (which is 128⁻¹ mod q)
    for idx in List.range n do
      let x : ModQ ← f.get! idx
      let _ ← f.set! idx (x * 3303)
    f
