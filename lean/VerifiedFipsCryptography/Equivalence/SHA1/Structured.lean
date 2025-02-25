import VerifiedFipsCryptography.Specs.SHA1
import VerifiedFipsCryptography.Equivalence.Lemmas

namespace Structured

def pad_message (msg : Array UInt8) : Array UInt8 :=
  let ml := (msg.size.toUInt64 * 8) -- Message length in bits
  let padding : Array UInt8 := #[0x80]
  let len := msg.size + 1
  let zero_padding_length := (64 - (len % 64) + 56) % 64
  let zero_padding := (List.replicate zero_padding_length (0 : UInt8)).toArray
  let length_bytes := #[
    ((ml >>> 56) &&& 255).toUInt8,
    ((ml >>> 48) &&& 255).toUInt8,
    ((ml >>> 40) &&& 255).toUInt8,
    ((ml >>> 32) &&& 255).toUInt8,
    ((ml >>> 24) &&& 255).toUInt8,
    ((ml >>> 16) &&& 255).toUInt8,
    ((ml >>> 8) &&& 255).toUInt8,
    ((ml >>> 0) &&& 255).toUInt8
  ]
  msg ++ padding ++ zero_padding ++ length_bytes

def chunkify_loop (msg : Array UInt8) (chunks : Array (Array UInt8)) (i : Nat) : Array (Array UInt8) :=
  let new_chunks := List.range' i (msg.size / 64 - i) |>.map
    fun i => msg.extract (i * 64) ((i + 1) * 64)
  chunks ++ new_chunks.toArray

-- Break message into 512-bit (64-byte) chunks
def chunkify (msg : Array UInt8) : Array (Array UInt8) :=
  chunkify_loop msg #[] 0

-- Convert a 4-byte slice to a Word (UInt32)
def bytes_to_word (bytes : Array UInt8) : UInt32 :=
  bytes.foldl (fun acc b => (acc <<< 8) ||| b.toUInt32) 0

def process_loop (chunk : Array UInt8) :=
  List.range 16 |>.map fun i =>
    let bytes := chunk.extract (i * 4) ((i + 1) * 4)
    bytes_to_word bytes

def process (h0 : Vector UInt32 5) (chunk : Array UInt8) :=
  let words := process_loop chunk
  let W := Id.run do
    let mut W := words
    for t in [16:80] do
      let wt := SHA1.ROTL 1 (W[t - 3]! ^^^ W[t - 8]! ^^^ W[t - 14]! ^^^ W[t - 16]!)
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
    let temp := (SHA1.ROTL 5 a) + f + e + SHA1.K t + W[t]!
    e := d
    d := c
    c := SHA1.ROTL 30 b
    b := a
    a := temp
  -- Compute the new hash values
  return #v[h0[0] + a, h0[1] + b, h0[2] + c, h0[3] + d, h0[4] + e]

def hash_to_vec_loop (final_hash : Vector UInt32 5) (result_bytes : Array UInt8) (index : Nat) : Array UInt8 :=
  let result_bytes := (final_hash.extract index final_hash.size).foldl (init := result_bytes) fun acc (word : UInt32) =>
    let bytes := #[
      ((word >>> 24) &&& 255).toUInt8,
      ((word >>> 16) &&& 255).toUInt8,
      ((word >>> 8) &&& 255).toUInt8,
      ((word >>> 0) &&& 255).toUInt8
    ]
    acc ++ bytes
  result_bytes

def hash_to_vec (final_hash : Vector UInt32 5) : Array UInt8 :=
  let result_bytes := final_hash.foldl (init := #[]) fun acc (word : UInt32) =>
    let bytes := #[
      ((word >>> 24) &&& 255).toUInt8,
      ((word >>> 16) &&& 255).toUInt8,
      ((word >>> 8) &&& 255).toUInt8,
      ((word >>> 0) &&& 255).toUInt8
    ]
    acc ++ bytes
  result_bytes

def hash_loop (chunks : Array (Array UInt8)) (state : Vector UInt32 5) (i : Nat) :=
  (chunks.extract i chunks.size).foldl (init := state) fun state chunk =>
    process state chunk

@[irreducible]
def hash (message : Array UInt8) : Array UInt8 :=
  let paddedMsg := pad_message message
  let chunks := chunkify paddedMsg
  let H := SHA1.initialHash

  let finalHash := hash_loop chunks H 0

  hash_to_vec finalHash

end Structured
