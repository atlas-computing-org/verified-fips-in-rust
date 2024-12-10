import Mathlib.Data.UInt

def UInt8.toHexString (i : UInt8) : String := Char.quoteCore.smallCharToHex i.toChar

def hexCharToUInt8 (c : Char) : UInt8 :=
  if '0' ≤ c ∧ c ≤ '9' then
    UInt8.ofNat (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then
    UInt8.ofNat (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then
    UInt8.ofNat (c.toNat - 'A'.toNat + 10)
  else
    panic! "Invalid hex character"

def hexStringToUInt8Array (hex : String) : Array UInt8 :=
  if hex.length % 2 ≠ 0 then
    panic! "Hex string must have an even number of characters"
  else
    Id.run do
    let mut result := #[]
    let str := hex.toList
    for i in [0:str.length:2] do
      let high := hexCharToUInt8 (str.get! i)
      let low := hexCharToUInt8 (str.get! (i + 1))
      result := result.push ((high <<< 4) ||| low)
    result

def ByteArray.toHexString (ba : ByteArray) : String :=
  ba.foldl (fun acc b => acc ++ s!" {b.toHexString}") ""

def toHexString (ua : Array UInt8) : String :=
  (ByteArray.mk ua).toHexString

def String.toUInt8Array (s : String) : Array UInt8 := s.toUTF8.toList.toArray

def String.fromUInt8Array (ua : Array UInt8) : String := String.fromUTF8! (ByteArray.mk ua)
