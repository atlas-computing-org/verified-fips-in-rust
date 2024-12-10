// Check if the `i`-th bit of `b` is set
fn test_bit(b: u8, i: u8) -> bool {
    (b >> i) & 1 == 1
}

// Finite field GF(2^8) multiplication by 2 (xtime operation)
fn xtime(b: u8) -> u8 {
    if test_bit(b, 7) {
        (b << 1) ^ 0x1B
    } else {
        b << 1
    }
}

// Finite field GF(2^8) multiplication of `a` and `b`
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut i = 0;
    while i < 8 {
        if b & 0x01 == 0x01 {
            result ^= a;
        }
        a = xtime(a);
        b >>= 1;
        i += 1;
    }
    result
}

// AES S-box (Table 4 from FIPS 197)
const SBOX: [u8; 256] = [
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
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

// AES Inverse S-box (Table 5 from FIPS 197)
const INV_SBOX: [u8; 256] = [
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
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
];

// AES Rcon values for key expansion
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

// Perform the RotWord operation (rotate a 4-byte word left by one byte)
fn rot_word(word: &[u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

// Perform the SubWord operation (substitute each byte using the AES S-box)
fn sub_word(word: &[u8; 4]) -> [u8; 4] {
    [
        SBOX[word[0] as usize],
        SBOX[word[1] as usize],
        SBOX[word[2] as usize],
        SBOX[word[3] as usize],
    ]
}

// Copy the original key into the first Nk words of the key schedule
fn copy_initial_key(w: &mut Vec<u8>, key: &[u8], nk: usize) {
    let mut i = 0;
    while i < nk {
        w.extend_from_slice(&key[i * 4..(i + 1) * 4]);
        i += 1;
    }
}

// Expand the key schedule
fn expand_key_schedule(w: &mut Vec<u8>, nk: usize, total_words: usize) {
    let mut i = nk;
    while i < total_words {
        let mut temp = [w[(i - 1) * 4], w[(i - 1) * 4 + 1], w[(i - 1) * 4 + 2], w[(i - 1) * 4 + 3]];

        if i % nk == 0 {
            temp = sub_word(&rot_word(&temp));
            temp[0] ^= RCON[(i / nk) - 1];
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(&temp);
        }

        let prev_word = [
            w[(i - nk) * 4],
            w[(i - nk) * 4 + 1],
            w[(i - nk) * 4 + 2],
            w[(i - nk) * 4 + 3],
        ];

        w.push(temp[0] ^ prev_word[0]);
        w.push(temp[1] ^ prev_word[1]);
        w.push(temp[2] ^ prev_word[2]);
        w.push(temp[3] ^ prev_word[3]);

        i += 1;
    }
}

// Key expansion function for AES
fn key_expansion(key: &[u8], nk: usize, nr: usize) -> Vec<u8> {
    let nb = 4; // Block size in words
    let total_words = nb * (nr + 1);
    let mut w: Vec<u8> = Vec::with_capacity(total_words * 4);

    // Copy the original key into the first Nk words
    copy_initial_key(&mut w, key, nk);

    // Expand the key schedule
    expand_key_schedule(&mut w, nk, total_words);

    w
}

// Substitute a byte using the AES S-box
fn sub_byte(byte: u8) -> u8 {
    SBOX[byte as usize]
}

// Substitute each byte in a state using the AES S-box
fn sub_bytes(state: &mut [u8]) {
    let mut i = 0;
    while i < state.len() {
        state[i] = sub_byte(state[i]);
        i += 1;
    }
}

// Substitute a byte using the AES Inverse S-box
fn inv_sub_byte(byte: u8) -> u8 {
    INV_SBOX[byte as usize]
}

// Substitute each byte in a state using the AES Inverse S-box
fn inv_sub_bytes(state: &mut [u8]) {
    let mut i = 0;
    while i < state.len() {
        state[i] = inv_sub_byte(state[i]);
        i += 1;
    }
}

// Performs the ShiftRows transformation on a 16-byte AES state.
fn shift_rows(state: &[u8; 16]) -> [u8; 16] {
    [
        state[0],  state[5],  state[10], state[15],
        state[4],  state[9],  state[14], state[3],
        state[8],  state[13], state[2],  state[7],
        state[12], state[1],  state[6],  state[11],
    ]
}

// Performs the Inverse ShiftRows transformation on a 16-byte AES state.
fn inv_shift_rows(state: &[u8; 16]) -> [u8; 16] {
    [
        state[0],  state[13], state[10], state[7],
        state[4],  state[1],  state[14], state[11],
        state[8],  state[5],  state[2],  state[15],
        state[12], state[9],  state[6],  state[3],
    ]
}

// Performs the MixColumn transformation on a 4-byte column.
fn mix_column(col: &[u8; 4]) -> [u8; 4] {
    [
        gf_mul(0x02, col[0]) ^ gf_mul(0x03, col[1]) ^ gf_mul(0x01, col[2]) ^ gf_mul(0x01, col[3]),
        gf_mul(0x01, col[0]) ^ gf_mul(0x02, col[1]) ^ gf_mul(0x03, col[2]) ^ gf_mul(0x01, col[3]),
        gf_mul(0x01, col[0]) ^ gf_mul(0x01, col[1]) ^ gf_mul(0x02, col[2]) ^ gf_mul(0x03, col[3]),
        gf_mul(0x03, col[0]) ^ gf_mul(0x01, col[1]) ^ gf_mul(0x01, col[2]) ^ gf_mul(0x02, col[3]),
    ]
}

// Performs the Inverse MixColumn transformation on a 4-byte column.
fn inv_mix_column(col: &[u8; 4]) -> [u8; 4] {
    [
        gf_mul(0x0E, col[0]) ^ gf_mul(0x0B, col[1]) ^ gf_mul(0x0D, col[2]) ^ gf_mul(0x09, col[3]),
        gf_mul(0x09, col[0]) ^ gf_mul(0x0E, col[1]) ^ gf_mul(0x0B, col[2]) ^ gf_mul(0x0D, col[3]),
        gf_mul(0x0D, col[0]) ^ gf_mul(0x09, col[1]) ^ gf_mul(0x0E, col[2]) ^ gf_mul(0x0B, col[3]),
        gf_mul(0x0B, col[0]) ^ gf_mul(0x0D, col[1]) ^ gf_mul(0x09, col[2]) ^ gf_mul(0x0E, col[3]),
    ]
}

// Performs the MixColumns transformation on a 16-byte AES state.
fn mix_columns(state: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut i = 0;
    while i < 4 {
        let col = [
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ];
        let mixed = mix_column(&col);
        result[4 * i] = mixed[0];
        result[4 * i + 1] = mixed[1];
        result[4 * i + 2] = mixed[2];
        result[4 * i + 3] = mixed[3];
        i += 1;
    }
    result
}

// Performs the Inverse MixColumns transformation on a 16-byte AES state.
fn inv_mix_columns(state: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut i = 0;
    while i < 4 {
        let col = [
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ];
        let mixed = inv_mix_column(&col);
        result[4 * i] = mixed[0];
        result[4 * i + 1] = mixed[1];
        result[4 * i + 2] = mixed[2];
        result[4 * i + 3] = mixed[3];
        i += 1;
    }
    result
}

// Performs the AddRoundKey operation: XOR the state with the round key.
fn add_round_key(state: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        result[i] = state[i] ^ round_key[i];
        i += 1;
    }
    result
}

// Ideally this function would be replaced with the following code and inlined,
// but Aeneas does not currently support it:
//   arr[i..i + 16].try_into().unwrap()
// See https://aeneas-verif.zulipchat.com/#narrow/channel/349819-general/topic/Converting.20a.20Rust.20slice.20into.20an.20array.20fails
fn extract_array_16(arr: &[u8], i: usize) -> [u8; 16] {
    [
        arr[i + 0], arr[i + 1], arr[i + 2], arr[i + 3],
        arr[i + 4], arr[i + 5], arr[i + 6], arr[i + 7],
        arr[i + 8], arr[i + 9], arr[i + 10], arr[i + 11],
        arr[i + 12], arr[i + 13], arr[i + 14], arr[i + 15],
    ]
}

// AES Cipher (encryption) function
fn cipher(input: &[u8; 16], key_schedule: &[u8], nr: usize) -> [u8; 16] {
    let mut state = add_round_key(input, &extract_array_16(key_schedule, 0));
    let mut round = 1;

    // Clone the key_schedule to work around Aeneas's lack of support for nested borrows.
    // See https://aeneas-verif.zulipchat.com/#narrow/channel/349819-general/topic/Workaround.20for.20unsupported.20nested.20borrows
    while round < nr {
        sub_bytes(&mut state);
        state = shift_rows(&state);
        state = mix_columns(&state);
        state = add_round_key(&state, &extract_array_16(key_schedule, round * 16));
        round += 1;
    }

    sub_bytes(&mut state);
    state = shift_rows(&state);
    state = add_round_key(&state, &extract_array_16(key_schedule, nr * 16));

    state
}

// AES Inverse Cipher (decryption) function
fn inv_cipher(input: &[u8; 16], key_schedule: &[u8], nr: usize) -> [u8; 16] {
    let mut state = add_round_key(&input, &extract_array_16(key_schedule, nr * 16));
    let mut round_idx = 1;

    // Clone the key_schedule to work around Aeneas's lack of support for nested borrows.
    // See https://aeneas-verif.zulipchat.com/#narrow/channel/349819-general/topic/Workaround.20for.20unsupported.20nested.20borrows
    while round_idx < nr {
        let round = nr - round_idx;
        state = inv_shift_rows(&state);
        inv_sub_bytes(&mut state);
        state = add_round_key(&state, &extract_array_16(key_schedule, round * 16));
        state = inv_mix_columns(&state);
        round_idx += 1;
    }

    state = inv_shift_rows(&state);
    inv_sub_bytes(&mut state);
    state = add_round_key(&state, &extract_array_16(key_schedule, 0));

    state
}

// AES-128 Encryption
pub fn aes128(input: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let nr = 10;
    let nk = 4;
    let key_schedule = key_expansion(key, nk, nr);
    cipher(input, &key_schedule, nr)
}

// AES-192 Encryption
pub fn aes192(input: &[u8; 16], key: &[u8; 24]) -> [u8; 16] {
    let nr = 12;
    let nk = 6;
    let key_schedule = key_expansion(key, nk, nr);
    cipher(input, &key_schedule, nr)
}

// AES-256 Encryption
pub fn aes256(input: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let nr = 14;
    let nk = 8;
    let key_schedule = key_expansion(key, nk, nr);
    cipher(input, &key_schedule, nr)
}

// AES-128 Decryption
pub fn aes128_inv(input: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let nr = 10;
    let nk = 4;
    let key_schedule = key_expansion(key, nk, nr);
    inv_cipher(input, &key_schedule, nr)
}

// AES-192 Decryption
pub fn aes192_inv(input: &[u8; 16], key: &[u8; 24]) -> [u8; 16] {
    let nr = 12;
    let nk = 6;
    let key_schedule = key_expansion(key, nk, nr);
    inv_cipher(input, &key_schedule, nr)
}

// AES-256 Decryption
pub fn aes256_inv(input: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let nr = 14;
    let nk = 8;
    let key_schedule = key_expansion(key, nk, nr);
    inv_cipher(input, &key_schedule, nr)
}


#[cfg(test)]
mod tests {
    use hex;
    use crate::{aes128, aes128_inv, aes192, aes192_inv, aes256, aes256_inv};

    // Helper function to convert a hex string to a fixed-size byte array.
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("Invalid hex string")
    }

    // Helper function to convert a hex string to a fixed-size array of length N.
    fn hex_to_fixed_array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex_to_bytes(hex);
        bytes.try_into().expect("Hex string has incorrect length")
    }

    // AES-128 Tests
    #[test]
    fn test_aes128_ecbgfsbox128_0() {
        let key = hex_to_fixed_array::<16>("00000000000000000000000000000000");
        let plain = hex_to_fixed_array::<16>("f34481ec3cc627bacd5dc3fb08f273e6");
        let cipher = hex_to_fixed_array::<16>("0336763e966d92595a567cc9ce537f5e");

        assert_eq!(aes128(&plain, &key), cipher);
        assert_eq!(aes128_inv(&cipher, &key), plain);
        assert_eq!(aes128_inv(&aes128(&plain, &key), &key), plain);
    }

    #[test]
    fn test_aes128_ecbkeysbox128_0() {
        let key = hex_to_fixed_array::<16>("10a58869d74be5a374cf867cfb473859");
        let plain = hex_to_fixed_array::<16>("00000000000000000000000000000000");
        let cipher = hex_to_fixed_array::<16>("6d251e6944b051e04eaa6fb4dbf78465");

        assert_eq!(aes128(&plain, &key), cipher);
        assert_eq!(aes128_inv(&cipher, &key), plain);
        assert_eq!(aes128_inv(&aes128(&plain, &key), &key), plain);
    }

    #[test]
    fn test_aes128_ecbvarkey128_0() {
        let key = hex_to_fixed_array::<16>("80000000000000000000000000000000");
        let plain = hex_to_fixed_array::<16>("00000000000000000000000000000000");
        let cipher = hex_to_fixed_array::<16>("0edd33d3c621e546455bd8ba1418bec8");

        assert_eq!(aes128(&plain, &key), cipher);
        assert_eq!(aes128_inv(&cipher, &key), plain);
        assert_eq!(aes128_inv(&aes128(&plain, &key), &key), plain);
    }

    #[test]
    fn test_aes128_ecbvartxt128_0() {
        let key = hex_to_fixed_array::<16>("00000000000000000000000000000000");
        let plain = hex_to_fixed_array::<16>("80000000000000000000000000000000");
        let cipher = hex_to_fixed_array::<16>("3ad78e726c1ec02b7ebfe92b23d9ec34");

        assert_eq!(aes128(&plain, &key), cipher);
        assert_eq!(aes128_inv(&cipher, &key), plain);
        assert_eq!(aes128_inv(&aes128(&plain, &key), &key), plain);
    }

    // AES-192 Tests

    #[test]
    fn test_aes192_ecbgfsbox192_0() {
        let key = hex_to_fixed_array::<24>("000000000000000000000000000000000000000000000000");
        let plain = hex_to_fixed_array::<16>("1b077a6af4b7f98229de786d7516b639");
        let cipher = hex_to_fixed_array::<16>("275cfc0413d8ccb70513c3859b1d0f72");

        assert_eq!(aes192(&plain, &key), cipher);
        assert_eq!(aes192_inv(&cipher, &key), plain);
        assert_eq!(aes192_inv(&aes192(&plain, &key), &key), plain);
    }

    #[test]
    fn test_aes192_ecbkeysbox192_0() {
        let key = hex_to_fixed_array::<24>("e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd");
        let plain = hex_to_fixed_array::<16>("00000000000000000000000000000000");
        let cipher = hex_to_fixed_array::<16>("0956259c9cd5cfd0181cca53380cde06");

        assert_eq!(aes192(&plain, &key), cipher);
        assert_eq!(aes192_inv(&cipher, &key), plain);
        assert_eq!(aes192_inv(&aes192(&plain, &key), &key), plain);
    }

    #[test]
    fn test_aes192_ecbvarkey192_0() {
        let key = hex_to_fixed_array::<24>("800000000000000000000000000000000000000000000000");
        let plain = hex_to_fixed_array::<16>("00000000000000000000000000000000");
        let cipher = hex_to_fixed_array::<16>("de885dc87f5a92594082d02cc1e1b42c");

        assert_eq!(aes192(&plain, &key), cipher);
        assert_eq!(aes192_inv(&cipher, &key), plain);
        assert_eq!(aes192_inv(&aes192(&plain, &key), &key), plain);
    }

    #[test]
    fn test_aes192_ecbvartxt192_0() {
        let key = hex_to_fixed_array::<24>("000000000000000000000000000000000000000000000000");
        let plain = hex_to_fixed_array::<16>("80000000000000000000000000000000");
        let cipher = hex_to_fixed_array::<16>("6cd02513e8d4dc986b4afe087a60bd0c");

        assert_eq!(aes192(&plain, &key), cipher);
        assert_eq!(aes192_inv(&cipher, &key), plain);
        assert_eq!(aes192_inv(&aes192(&plain, &key), &key), plain);
    }

    // AES-256 Tests

    #[test]
    fn test_aes256_ecbgfsbox256_0() {
        let key = hex_to_fixed_array::<32>("0000000000000000000000000000000000000000000000000000000000000000");
        let plain = hex_to_fixed_array::<16>("014730f80ac625fe84f026c60bfd547d");
        let cipher = hex_to_fixed_array::<16>("5c9d844ed46f9885085e5d6a4f94c7d7");

        assert_eq!(aes256(&plain, &key), cipher);
        assert_eq!(aes256_inv(&cipher, &key), plain);
        assert_eq!(aes256_inv(&aes256(&plain, &key), &key), plain);
    }

    #[test]
    fn test_aes256_ecbkeysbox256_0() {
        let key = hex_to_fixed_array::<32>("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");
        let plain = hex_to_fixed_array::<16>("00000000000000000000000000000000");
        let cipher = hex_to_fixed_array::<16>("46f2fb342d6f0ab477476fc501242c5f");

        assert_eq!(aes256(&plain, &key), cipher);
        assert_eq!(aes256_inv(&cipher, &key), plain);
        assert_eq!(aes256_inv(&aes256(&plain, &key), &key), plain);
    }

    #[test]
    fn test_aes256_ecbvarkey256_0() {
        let key = hex_to_fixed_array::<32>("8000000000000000000000000000000000000000000000000000000000000000");
        let plain = hex_to_fixed_array::<16>("00000000000000000000000000000000");
        let cipher = hex_to_fixed_array::<16>("e35a6dcb19b201a01ebcfa8aa22b5759");

        assert_eq!(aes256(&plain, &key), cipher);
        assert_eq!(aes256_inv(&cipher, &key), plain);
        assert_eq!(aes256_inv(&aes256(&plain, &key), &key), plain);
    }

    #[test]
    fn test_aes256_ecbvartxt256_0() {
        let key = hex_to_fixed_array::<32>("0000000000000000000000000000000000000000000000000000000000000000");
        let plain = hex_to_fixed_array::<16>("80000000000000000000000000000000");
        let cipher = hex_to_fixed_array::<16>("ddc6bf790c15760d8d9aeb6f9a75fd4e");

        assert_eq!(aes256(&plain, &key), cipher);
        assert_eq!(aes256_inv(&cipher, &key), plain);
        assert_eq!(aes256_inv(&aes256(&plain, &key), &key), plain);
    }
}

