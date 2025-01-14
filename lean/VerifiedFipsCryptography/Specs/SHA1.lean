-- SHA1.lean
import Init.Data.ByteArray
import Init.Data.Repr
import Mathlib.Data.UInt
import Mathlib.Data.Vector.Defs
import Init.Data.Nat.Basic
import VerifiedFipsCryptography.Util.HexString

namespace SHA1
open Mathlib

-- Type alias for 32-bit words
abbrev Word := UInt32

-- Initial hash values (H0) as per FIPS 180-4
def initialHash : Mathlib.Vector Word 5 :=
  ⟨[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0], rfl⟩

-- Constants K for each iteration
def K (t : Nat) : Word :=
  if t ≤ 19 then 0x5A827999
  else if t ≤ 39 then 0x6ED9EBA1
  else if t ≤ 59 then 0x8F1BBCDC
  else 0xCA62C1D6

-- Left rotate operation using mathlib's rotateLeft
def ROTL (n : Nat) (x : Word) : Word :=
  let nn : UInt32 := n.toUInt32
  ((x <<< nn) ||| (x >>> (32 - nn)))

/-
This is not ideal, but given how Aeneas generates the looping code in `algorithms.sha1.pad_message_loop`,
it's incredibly difficult to untangle the reasoning and show equivalence to the pure FP implementation.
-/
def padMessageLoop (ml : UInt64) (paddedMsg : Array UInt8) (zeroPaddingLength : ℕ) (i : ℕ) : Array UInt8 :=
  if i < zeroPaddingLength then
    let paddedMsg1 := paddedMsg.push 0
    let i1 := i + 1
    padMessageLoop ml paddedMsg1 zeroPaddingLength i1
  else
    let lengthBytes := Array.mkArray 8 (0 : UInt8)
    let i1 := ml >>> 56
    let i2 := UInt64.toUInt8 (i1 &&& 255)
    let i3 := ml >>> 48
    let lengthBytes1 := lengthBytes.set (0 : Fin 8) i2
    let i4 := UInt64.toUInt8 (i3 &&& 255)
    let i5 := ml >>> 40
    let lengthBytes2 := lengthBytes1.set (1 : Fin 8) i4
    let i6 := UInt64.toUInt8 (i5 &&& 255)
    let i7 := ml >>> 32
    let lengthBytes3 := lengthBytes2.set (2 : Fin 8) i6
    let i8 := UInt64.toUInt8 (i7 &&& 255)
    let i9 := ml >>> 24
    let lengthBytes4 := lengthBytes3.set (3 : Fin 8) i8
    let i10 := UInt64.toUInt8 (i9 &&& 255)
    let i11 := ml >>> 16
    let lengthBytes5 := lengthBytes4.set (4 : Fin 8) i10
    let i12 := UInt64.toUInt8 (i11 &&& 255)
    let i13 := ml >>> 8
    let lengthBytes6 := lengthBytes5.set (5 : Fin 8) i12
    let i14 := UInt64.toUInt8 (i13 &&& 255)
    let i15 := ml >>> 0
    let lengthBytes7 := lengthBytes6.set (6 : Fin 8) i14
    let i16 := UInt64.toUInt8 (i15 &&& 255)
    let lengthBytes8 := lengthBytes7.set (7 : Fin 8) i16
    paddedMsg ++ lengthBytes8

/-
We use this one when showing equivalence.
The natural next step would be to show equivalence to `padMessage'` (the old FP version)
and thus derive the full equivalence transitively. Not sure how hard that would be,
but working purely in Lean types definitely makes it easier.
-/
def padMessage (msg : ByteArray) : ByteArray :=
  -- Step 1: Compute message length in bits
  let ml := UInt64.ofNat (msg.size * 8) -- Message length in bits
  -- Step 2: Append the padding bit (0x80)
  let padding : ByteArray := ByteArray.mk #[0x80]
  -- Step 3: Calculate zero-padding length
  let zeroPaddingLength := (56 - ((msg.size + 1) % 64)) % 64
  -- Step 4: Append zero padding
  ⟨padMessageLoop ml (msg ++ padding).1 zeroPaddingLength 0⟩

-- Padding function
def padMessage' (msg : ByteArray) : ByteArray :=
  -- Step 1: Compute message length in bits
  let ml := UInt64.ofNat (msg.size * 8) -- Message length in bits
  -- Step 2: Append the padding bit (0x80)
  let padding : ByteArray := ByteArray.mk #[0x80]
  -- Step 3: Calculate zero-padding length
  let zeroPaddingLength := (56 - ((msg.size + 1) % 64)) % 64
  -- Step 4: Append zero padding
  let zeroPadding := ByteArray.mk (List.replicate zeroPaddingLength 0).toArray
  -- Step 5: Append message length as 64-bit big-endian integer
  let lengthBytes := ByteArray.mk $ ((List.range 8).reverse.map fun (i: Nat) =>
    ((ml >>> (i * 8).toUInt64) &&& 0xFF).toUInt8).toArray
  msg ++ padding ++ zeroPadding ++ lengthBytes

-- Break message into 512-bit (64-byte) chunks
def chunkify (msg : ByteArray) : Array ByteArray :=
  let chunkSize := 64
  let numChunks := (msg.size + chunkSize - 1) / chunkSize
  let chunks := List.range numChunks |>.map
    fun i => msg.extract (i * chunkSize) ((i + 1) * chunkSize)
  chunks.toArray

-- Convert a 4-byte slice to a Word (UInt32)
def bytesToWord (bytes : ByteArray) : Word :=
  bytes.foldl (fun acc b => (acc <<< 8) ||| b.toUInt32) 0

def hashToVecLoop (finalHash : Vector Word 5) (resultBytes : Array UInt8) (index : ℕ) : Array UInt8 :=
  if h : index < 5 then
    let word := finalHash[index]
    let i1 := word >>> 24
    let i2 := UInt32.toUInt8 (i1 &&& 255)
    let resultBytes1 := resultBytes.push i2
    let i3 := word >>> 16
    let i4 := UInt32.toUInt8 (i3 &&& 255)
    let resultBytes2 := resultBytes1.push i4
    let i5 := word >>> 8
    let i6 := UInt32.toUInt8 (i5 &&& 255)
    let resultBytes3 := resultBytes2.push i6
    let i7 := word >>> 0
    let i8 := UInt32.toUInt8 (i7 &&& 255)
    let resultBytes4 := resultBytes3.push i8
    let index1 := index + 1
    hashToVecLoop finalHash resultBytes4 index1
  else
    resultBytes

def hashToVec (finalHash : Vector Word 5) : ByteArray :=
  ⟨hashToVecLoop finalHash #[] 0⟩

-- Replace again.
-- def hashToVec (finalHash : Vector Word 5) : ByteArray :=
--   finalHash.toList.foldl (init := ByteArray.empty) fun acc (h: Word) =>
--     let tmp := (List.range 4).toArray.reverse.map
--       (fun (i: Nat) => ((h >>> (i.toUInt32 * 8)) &&& 0xFF).toUInt8)
--       |> ByteArray.mk
--     acc ++ tmp

-- Main hash function
def hash (message : ByteArray) : ByteArray :=
  let paddedMsg := padMessage message
  let chunks := chunkify paddedMsg
  let H := initialHash

  let finalHash := chunks.foldl (init := H) fun h0 chunk =>
    -- Prepare the message schedule W
    let words := List.range 16 |>.map fun i =>
      let bytes := chunk.extract (i * 4) ((i + 1) * 4)
      bytesToWord bytes
    let W := Id.run do
      let mut W := words
      for t in [16:80] do
        let wt := ROTL 1 (W[t - 3]! ^^^ W[t - 8]! ^^^ W[t - 14]! ^^^ W[t - 16]!)
        W := W.append [wt]
      W
    Id.run do
    -- Initialize working variables
    let mut a := h0[0]!
    let mut b := h0[1]!
    let mut c := h0[2]!
    let mut d := h0[3]!
    let mut e := h0[4]!
    -- Main loop
    for t in [0:80] do
      let f :=
        if t ≤ 19 then (b &&& c) ||| ((~~~b) &&& d)
        else if t ≤ 39 then b ^^^ c ^^^ d
        else if t ≤ 59 then (b &&& c) ||| (b &&& d) ||| (c &&& d)
        else b ^^^ c ^^^ d
      let temp := (ROTL 5 a) + f + e + K t + W[t]!
      e := d
      d := c
      c := ROTL 30 b
      b := a
      a := temp
    -- Compute the new hash values
    return ⟨h0.toList.zipWith (· + ·) [a, b, c, d, e], by simp⟩

  -- Concatenate the final hash values into a ByteArray
  hashToVec finalHash

end SHA1

-- Example usage: SHA-1 hash
-- "Hello World" => 0a 4d 55 a8 d7 78 e5 02 2f ab 70 19 77 c5 d8 40 bb c4 86 d0
-- #eval (SHA1.hash ("Hello World".toUTF8)).toHexString
