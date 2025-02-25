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
def initialHash : Vector Word 5 :=
  #v[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

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

-- Padding function
def pad_message (msg : ByteArray) : ByteArray :=
  -- Step 1: Compute message length in bits
  let ml := (msg.size.toUInt64 * 8) -- Message length in bits
  -- Step 2: Append the padding bit (0x80)
  let padding : ByteArray := ByteArray.mk #[0x80]
  -- Step 3: Calculate zero-padding length
  let len := msg.size + 1
  -- TODO: highlight this fix
  let zeroPaddingLength := (64 - len % 64 + 56) % 64
  -- Step 4: Append zero padding
  let zeroPadding := ByteArray.mk (List.replicate zeroPaddingLength 0).toArray
  -- Step 5: Append message length as 64-bit big-endian integer
  let lengthBytes := ByteArray.mk $ #[
    ((ml >>> 56) &&& 255).toUInt8,
    ((ml >>> 48) &&& 255).toUInt8,
    ((ml >>> 40) &&& 255).toUInt8,
    ((ml >>> 32) &&& 255).toUInt8,
    ((ml >>> 24) &&& 255).toUInt8,
    ((ml >>> 16) &&& 255).toUInt8,
    ((ml >>> 8) &&& 255).toUInt8,
    ((ml >>> 0) &&& 255).toUInt8
  ]
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

def process (h0 : Vector Word 5) (chunk : ByteArray) :=
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
  let mut a := h0[0]
  let mut b := h0[1]
  let mut c := h0[2]
  let mut d := h0[3]
  let mut e := h0[4]
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
  return #v[h0[0] + a, h0[1] + b, h0[2] + c, h0[3] + d, h0[4] + e]

def hash_to_vec (final_hash : Vector Word 5) : ByteArray :=
  let result_bytes := final_hash.foldl (init := #[]) fun acc (word : Word) =>
    let bytes := #[
      ((word >>> 24) &&& 255).toUInt8,
      ((word >>> 16) &&& 255).toUInt8,
      ((word >>> 8) &&& 255).toUInt8,
      ((word >>> 0) &&& 255).toUInt8
    ]
    acc ++ bytes
  ⟨result_bytes⟩

-- Main hash function
def hash (message : ByteArray) : ByteArray :=
  let paddedMsg := pad_message message
  let chunks := chunkify paddedMsg
  let H := initialHash

  let finalHash := chunks.foldl (init := H) fun h0 chunk =>
    process h0 chunk

  -- Concatenate the final hash values into a ByteArray
  hash_to_vec finalHash

end SHA1

-- Example usage: SHA-1 hash
-- "Hello World" => 0a 4d 55 a8 d7 78 e5 02 2f ab 70 19 77 c5 d8 40 bb c4 86 d0
-- #eval (SHA1.hash ("Hello World".toUTF8)).toHexString
