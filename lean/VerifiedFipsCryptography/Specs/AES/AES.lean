import Std
import Init.Data.ByteArray
import VerifiedFipsCryptography.Util.HexString

/-
TODO: Make types more explicit.
  - Use fixed-length arrays instead of Array UInt8.
  - For key schedule, use a 2D array.
-/

namespace AES

def testBit (b: UInt8) (i: UInt8): Bool :=
  (b >>> i) % 2 == 1

-- Finite field GF(2^8) operations
def xtime (b : UInt8) : UInt8 :=
  if testBit b 7 then
    (b <<< 1) ^^^ 0x1B
  else
    b <<< 1

def gfMul (a b : UInt8) : UInt8 := Id.run do
  let mut result : UInt8 := 0
  let mut tempA := a
  let mut tempB := b
  for _ in [0:8] do
    if tempB &&& 0x01 == 0x01 then
      result := result ^^^ tempA
    tempA := xtime tempA
    tempB := tempB >>> 1
  result

-- S-box values (Table 4 from FIPS 197)
def sBox : Array UInt8 := #[
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

-- Inverse S-box values (Table 5 from FIPS 197)
def invSBox : Array UInt8 := #[
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

-- Constants for key expansion
def rcon : Array UInt8 := #[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

-- Helper functions for key expansion
def rotWord (word : Array UInt8) : Array UInt8 :=
  if word.size == 4 then
    word[1:4] ++ word[0:1]
  else
    panic! s!"{word.size} is not a valid word size"

def subWord (word : Array UInt8) : Array UInt8 :=
  word.map (fun byte => sBox.get! byte.toNat)

-- Key expansion function
def keyExpansion (key : Array UInt8) (Nk Nr : Nat) : Array UInt8 := Id.run do
  let Nb := 4 -- Block size in words
  let totalWords := Nb * (Nr + 1)
  let mut w := Array.mkEmpty (totalWords * 4)

  -- Copy the original key into the first Nk words
  for i in [0:Nk] do
    w := w ++ (key[(4 * i):(4 * (i + 1))] : Array UInt8)

  -- Expand the key schedule
  for i in [Nk:totalWords] do
    let mut temp : Array UInt8 := w[(4 * (i - 1)):(4 * i)]
    if i % Nk == 0 then
      temp := subWord (rotWord temp)
      temp := temp.zipWith #[rcon[(i / Nk) - 1]!, 0, 0, 0] (· ^^^ ·)
    else if Nk > 6 && i % Nk == 4 then
      temp := subWord temp
    let prevWord := w[(4 * (i - Nk)):(4 * (i - Nk + 1))]
    temp := temp.zipWith prevWord (· ^^^ ·)
    w := w ++ temp

  w

-- SubBytes
def subBytes (state : Array UInt8) : Array UInt8 :=
  state.map (fun byte => sBox.get! byte.toNat)

def invSubBytes (state : Array UInt8) : Array UInt8 :=
  state.map (fun byte => invSBox.get! byte.toNat)

-- ShiftRows
def shiftRows (state : Array UInt8) : Array UInt8 :=
  if _: state.size = 16 then
    #[state[0],  state[5],  state[10], state[15],
      state[4],  state[9],  state[14], state[3],
      state[8],  state[13], state[2],  state[7],
      state[12], state[1],  state[6],  state[11]]
  else
    panic! "shiftRows requires an array of exactly 16 elements"

def invShiftRows (state : Array UInt8) : Array UInt8 :=
  if _: state.size = 16 then
    #[state[0],  state[13], state[10], state[7],
      state[4],  state[1],  state[14], state[11],
      state[8],  state[5],  state[2],  state[15],
      state[12], state[9],  state[6],  state[3]]
  else
    panic! "invShiftRows requires an array of exactly 16 elements"

def mixColumn (col : Array UInt8) : Array UInt8 :=
  if _: col.size = 4 then
    #[gfMul 0x02 col[0] ^^^ gfMul 0x03 col[1] ^^^ gfMul 0x01 col[2] ^^^ gfMul 0x01 col[3],
      gfMul 0x01 col[0] ^^^ gfMul 0x02 col[1] ^^^ gfMul 0x03 col[2] ^^^ gfMul 0x01 col[3],
      gfMul 0x01 col[0] ^^^ gfMul 0x01 col[1] ^^^ gfMul 0x02 col[2] ^^^ gfMul 0x03 col[3],
      gfMul 0x03 col[0] ^^^ gfMul 0x01 col[1] ^^^ gfMul 0x01 col[2] ^^^ gfMul 0x02 col[3]]
  else
    panic! "mixColumn requires an array of exactly 4 elements"

def invMixColumn (col : Array UInt8) : Array UInt8 :=
  if _: col.size = 4 then
    #[gfMul 0x0E col[0] ^^^ gfMul 0x0B col[1] ^^^ gfMul 0x0D col[2] ^^^ gfMul 0x09 col[3],
      gfMul 0x09 col[0] ^^^ gfMul 0x0E col[1] ^^^ gfMul 0x0B col[2] ^^^ gfMul 0x0D col[3],
      gfMul 0x0D col[0] ^^^ gfMul 0x09 col[1] ^^^ gfMul 0x0E col[2] ^^^ gfMul 0x0B col[3],
      gfMul 0x0B col[0] ^^^ gfMul 0x0D col[1] ^^^ gfMul 0x09 col[2] ^^^ gfMul 0x0E col[3]]
  else
    panic! "invMixColumn requires an array of exactly 4 elements"

def mixColumns (state : Array UInt8) : Array UInt8 := Id.run do
  if state.size == 16 then
    let mut result := #[]
    for i in [0:4] do
      result := result ++ mixColumn (#[state[4 * i]!, state[4 * i + 1]!, state[4 * i + 2]!, state[4 * i + 3]!])
    result
  else
    panic! "mixColumns requires an array of exactly 16 elements"

def invMixColumns (state : Array UInt8) : Array UInt8 := Id.run do
  if state.size == 16 then
    let mut result := #[]
    for i in [0:4] do
      result := result ++ invMixColumn (#[state[4 * i]!, state[4 * i + 1]!, state[4 * i + 2]!, state[4 * i + 3]!])
    result
  else
    panic! "invMixColumns requires an array of exactly 16 elements"

-- AddRoundKey
def addRoundKey (state : Array UInt8) (roundKey : Array UInt8) : Array UInt8 :=
  state.zipWith roundKey (· ^^^ ·)

-- Cipher function
def cipher (input : Array UInt8) (keySchedule : Array UInt8) (Nr : Nat) : Array UInt8 := Id.run do
  let mut state := input
  state := addRoundKey state keySchedule[0:16]
  for round in [1:Nr] do
    state := subBytes state
    state := shiftRows state
    state := mixColumns state
    state := addRoundKey state keySchedule[round * 16 : (round + 1) * 16]
  state := subBytes state
  state := shiftRows state
  state := addRoundKey state keySchedule[Nr * 16 : (Nr + 1) * 16]
  state

-- Inverse cipher function
def invCipher (input : Array UInt8) (keySchedule : Array UInt8) (Nr : Nat) : Array UInt8 := Id.run do
  let mut state := input
  state := addRoundKey state (keySchedule[Nr * 16 : (Nr + 1) * 16])
  for roundIdx in [1:Nr] do
    let round := Nr - roundIdx
    state := invShiftRows state
    state := invSubBytes state
    state := addRoundKey state keySchedule[round * 16 : (round + 1) * 16]
    state := invMixColumns state
  state := invShiftRows state
  state := invSubBytes state
  state := addRoundKey state (keySchedule[0:16])
  state

-- AES-128 encryption
def AES128 (input : Array UInt8) (key : Array UInt8) : Array UInt8 :=
  let Nr := 10
  let Nk := 4
  let keySchedule := keyExpansion key Nk Nr
  cipher input keySchedule Nr

-- AES-192 encryption
def AES192 (input : Array UInt8) (key : Array UInt8) : Array UInt8 :=
  let Nr := 12
  let Nk := 6
  let keySchedule := keyExpansion key Nk Nr
  cipher input keySchedule Nr

-- AES-256 encryption
def AES256 (input : Array UInt8) (key : Array UInt8) : Array UInt8 :=
  let Nr := 14
  let Nk := 8
  let keySchedule := keyExpansion key Nk Nr
  cipher input keySchedule Nr

-- AES-128 decryption
def AES128Inv (input : Array UInt8) (key : Array UInt8) : Array UInt8 :=
  let Nr := 10
  let Nk := 4
  let keySchedule := keyExpansion key Nk Nr
  invCipher input keySchedule Nr

-- AES-192 decryption
def AES192Inv (input : Array UInt8) (key : Array UInt8) : Array UInt8 :=
  let Nr := 12
  let Nk := 6
  let keySchedule := keyExpansion key Nk Nr
  invCipher input keySchedule Nr

-- AES-256 decryption
def AES256Inv (input : Array UInt8) (key : Array UInt8) : Array UInt8 :=
  let Nr := 14
  let Nk := 8
  let keySchedule := keyExpansion key Nk Nr
  invCipher input keySchedule Nr

end AES

-- Example usage: AES-128 with key "A length-128 key"
-- "Two One Nine Two" <=> 22 da fc ee 82 96 34 17 d2 8e 99 5c cd de dc ae
-- def key128 : Array UInt8 := "A length-128 key".toUInt8Array
-- #eval AES.AES128 "Two One Nine Two".toUInt8Array key128 |> toHexString
-- #eval AES.AES128Inv (AES.AES128 "Two One Nine Two".toUInt8Array key128) key128 |> toHexString
