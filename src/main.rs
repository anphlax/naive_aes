// author: anphlax
// Naive and unsecure AES implementation for learning

/*
AES Process

Input
N-Rounds with
    SubBytes
    ShiftRows
    MixColumns
    AddRoundKey
Output
 */
use constants::{BLOCK_SIZE, RCON};
use sbox::S_BOX;

mod sbox;
mod constants;

// 128-bit block size

struct AES {
    key: [u8; BLOCK_SIZE], // for AES-128
    state: [[u8; 4]; 4],   // 4x4 State Matrix
}

impl AES {
    fn new(key: [u8; BLOCK_SIZE], input: [u8; BLOCK_SIZE]) -> Self {
        // Wandelt das Eingangs-Array in eine 4x4-Matrix um
        let state = [
            [input[0], input[1], input[2], input[3]],
            [input[4], input[5], input[6], input[7]],
            [input[8], input[9], input[10], input[11]],
            [input[12], input[13], input[14], input[15]],
        ];

        AES { key, state }
    }

    fn add_round_key(&mut self, round_key: &[[u8; 4]; 4]) {
        for i in 0..4 {
            for j in 0..4 {
                self.state[i][j] ^= round_key[i][j];
            }
        }
    }

    fn sub_bytes(&mut self) {
        for i in 0..4 {
            for j in 0..4 {
                self.state[i][j] = sbox_lookup(self.state[i][j]);
            }
        }
    }

    fn shift_rows(&mut self) {
        for i in 1..4 {
            self.state[i].rotate_left(i);
        }
    }

    fn mix_columns(&mut self) {
        for i in 0..4 {
            let s0 = self.state[0][i];
            let s1 = self.state[1][i];
            let s2 = self.state[2][i];
            let s3 = self.state[3][i];

            self.state[0][i] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3;
            self.state[1][i] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
            self.state[2][i] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3);
            self.state[3][i] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2);
        }
    }
    fn aes_round(&mut self, round_key: &[[u8; 4]; 4]) {
        self.sub_bytes();
        self.shift_rows();
        self.mix_columns();
        self.add_round_key(round_key);
    }

    fn final_round(&mut self, round_key: &[[u8; 4]; 4]) {
        self.sub_bytes();
        self.shift_rows();
        self.add_round_key(round_key);
    }

    fn encrypt(&mut self, expanded_key: &[[u8; 4]; 44]) -> [u8; BLOCK_SIZE] {
        self.add_round_key(&[
            expanded_key[0],
            expanded_key[1],
            expanded_key[2],
            expanded_key[3],
        ]);

        for round in 1..10 {
            self.aes_round(&[
                expanded_key[4 * round],
                expanded_key[4 * round + 1],
                expanded_key[4 * round + 2],
                expanded_key[4 * round + 3],
            ]);
        }

        self.final_round(&[
            expanded_key[40],
            expanded_key[41],
            expanded_key[42],
            expanded_key[43],
        ]);

        let mut output = [0u8; BLOCK_SIZE];
        for i in 0..4 {
            for j in 0..4 {
                output[4 * i + j] = self.state[i][j];
            }
        }
        output
    }
}

fn aes_encrypt(input: &[u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let expanded_key = key_expansion(key);
    let mut aes = AES::new(*key, *input);
    aes.encrypt(&expanded_key)
}

fn key_expansion(key: &[u8; 16]) -> [[u8; 4]; 44] {
    let mut expanded_key = [[0u8; 4]; 44];

    // Kopiere den Originalschlüssel in die ersten 4 Wörter des erweiterten Schlüssels
    for i in 0..4 {
        expanded_key[i][0] = key[4 * i];
        expanded_key[i][1] = key[4 * i + 1];
        expanded_key[i][2] = key[4 * i + 2];
        expanded_key[i][3] = key[4 * i + 3];
    }

    // Erweitere den Schlüssel auf insgesamt 44 Wörter (176 Bytes)
    for i in 4..44 {
        let mut temp = expanded_key[i - 1];

        // Jede 4. Iteration (also bei jedem 4. Wort) wird eine spezielle Transformation angewendet
        if i % 4 == 0 {
            // Rotiere das vorherige Wort und wende die S-Box darauf an
            temp = sub_word(rotate_word(temp));
            // XOR das erste Byte mit der entsprechenden RCON-Rundenkonstante
            temp[0] ^= RCON[(i / 4) - 1];
        }

        // XOR das erweiterte Wort mit dem Wort 4 Positionen vorher
        for j in 0..4 {
            expanded_key[i][j] = expanded_key[i - 4][j] ^ temp[j];
        }
    }

    expanded_key
}

fn sbox_lookup(byte: u8) -> u8 {
    S_BOX[byte as usize]
}

fn sub_word(word: [u8; 4]) -> [u8; 4] {
    [
        sbox_lookup(word[0]), // S-Box-Wert für das erste Byte
        sbox_lookup(word[1]), // S-Box-Wert für das zweite Byte
        sbox_lookup(word[2]), // S-Box-Wert für das dritte Byte
        sbox_lookup(word[3]), // S-Box-Wert für das vierte Byte
    ]
}

fn rotate_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]] // Rotiert die Bytes des 4-Byte-Worts
}

/// Galois Field (GF(2^8)) multiplication of two bytes.
fn gmul(a: u8, b: u8) -> u8 {
    let mut p = 0; // Product of multiplication
    let mut a = a; // First multiplicand
    let mut b = b; // Second multiplicand

    for _ in 0..8 {
        // If the least significant bit of b is set, XOR p with a
        if (b & 1) != 0 {
            p ^= a;
        }

        // Check if the most significant bit of a is set
        let hi_bit_set = a & 0x80 != 0;

        // Left shift a (equivalent to multiplication by 2 in GF(2^8))
        a <<= 1;

        // If the high bit was set, reduce by the AES irreducible polynomial (0x1b)
        if hi_bit_set {
            a ^= 0x1b;
        }

        // Shift b right to process the next bit
        b >>= 1;
    }

    p
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_new() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xcf, 0x9f, 0x71, 0x61,
            0x2c, 0x20,
        ];
        let input = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];

        let aes = AES::new(key, input);

        let expected_state = [
            [0x32, 0x43, 0xf6, 0xa8],
            [0x88, 0x5a, 0x30, 0x8d],
            [0x31, 0x31, 0x98, 0xa2],
            [0xe0, 0x37, 0x07, 0x34],
        ];

        assert_eq!(aes.state, expected_state);
        assert_eq!(aes.key, key);
    }

    #[test]
    fn test_key_expansion_initialization() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xcf, 0x9f, 0x71, 0x61,
            0x2c, 0x20,
        ];
        let expanded_key = key_expansion(&key);

        let expected_initial_key: [[u8; 4]; 4] = [
            [0x2b, 0x7e, 0x15, 0x16],
            [0x28, 0xae, 0xd2, 0xa6],
            [0xab, 0xf7, 0xcf, 0x9f],
            [0x71, 0x61, 0x2c, 0x20],
        ];

        assert_eq!(&expanded_key[0..4], &expected_initial_key);
    }

    #[test]
    fn test_rotate_word() {
        let word = [0x09, 0xcf, 0x4f, 0x3c];
        let rotated = rotate_word(word);
        let expected = [0xcf, 0x4f, 0x3c, 0x09];
        assert_eq!(rotated, expected);
    }

    #[test]
    fn test_sub_word_with_sbox_lookup() {
        let word = [0x09, 0xcf, 0x4f, 0x3c];
        let substituted = sub_word(word);

        // Diese Werte basieren auf der S-Box aus dem Bild:
        let expected = [
            sbox_lookup(0x09), // 0x01
            sbox_lookup(0xcf), // 0x18
            sbox_lookup(0x4f), // 0x9d
            sbox_lookup(0x3c), // 0x87
        ];

        assert_eq!(
            substituted, expected,
            "sub_word failed for input [0x09, 0xcf, 0x4f, 0x3c] using sbox_lookup"
        );
    }

    #[test]
    fn test_sbox_lookup_cf() {
        let input = 0xcf;
        let expected_output = 0x8a;
        let result = sbox_lookup(input);
        assert_eq!(result, expected_output, "S-Box lookup for 0xcf failed!");
    }

    #[test]
    fn test_sbox_lookup_4f() {
        let input = 0x4f;
        let expected_output = 0x84;
        let result = sbox_lookup(input);
        assert_eq!(result, expected_output, "S-Box lookup for 0x4f failed!");
    }

    #[test]
    fn test_sbox_lookup_3c() {
        let input = 0x3c;
        let expected_output = 0xeb;
        let result = sbox_lookup(input);
        assert_eq!(result, expected_output, "S-Box lookup for 0x3c failed!");
    }

    #[test]
    fn test_key_expansion_128_bit() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];

        let expanded_key = key_expansion(&key);

        // Checking first few rounds from the key expansion table
        assert_eq!(expanded_key[0], [0x2b, 0x7e, 0x15, 0x16]);
        assert_eq!(expanded_key[1], [0x28, 0xae, 0xd2, 0xa6]);
        assert_eq!(expanded_key[2], [0xab, 0xf7, 0x15, 0x88]);
        assert_eq!(expanded_key[3], [0x09, 0xcf, 0x4f, 0x3c]);

        // Check the next few expanded key values (from the image)
        assert_eq!(expanded_key[4], [0xa0, 0xfa, 0xfe, 0x17]);
        assert_eq!(expanded_key[5], [0x88, 0x54, 0x2c, 0xb1]);
        assert_eq!(expanded_key[6], [0x23, 0xa3, 0x39, 0x39]);
        assert_eq!(expanded_key[7], [0x2a, 0x6c, 0x76, 0x05]);

        // Additional rounds can be verified similarly by adding more assertions.
    }

    #[test]
    fn test_key_expansion_128_bit_different_key() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];

        let expanded_key = key_expansion(&key);

        // Verify initial key (w0 to w3)
        assert_eq!(expanded_key[0], [0x2b, 0x7e, 0x15, 0x16]);
        assert_eq!(expanded_key[1], [0x28, 0xae, 0xd2, 0xa6]);
        assert_eq!(expanded_key[2], [0xab, 0xf7, 0x15, 0x88]);
        assert_eq!(expanded_key[3], [0x09, 0xcf, 0x4f, 0x3c]);

        // Verify expanded key (w4 to w7) from the table
        assert_eq!(expanded_key[4], [0xa0, 0xfa, 0xfe, 0x17]);
        assert_eq!(expanded_key[5], [0x88, 0x54, 0x2c, 0xb1]);
        assert_eq!(expanded_key[6], [0x23, 0xa3, 0x39, 0x39]);
        assert_eq!(expanded_key[7], [0x2a, 0x6c, 0x76, 0x05]);

        // You can add further rounds as needed.
    }
    #[test]
    fn test_aes_add_round_key() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xcf, 0x9f, 0x71, 0x61,
            0x2c, 0x20,
        ];
        let input = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];

        let mut aes = AES::new(key, input);
        let round_key = [
            [0xa0, 0x88, 0x23, 0x2a],
            [0xfa, 0x54, 0xa3, 0x6c],
            [0xfe, 0x2c, 0x39, 0x76],
            [0x17, 0xb1, 0x39, 0x05],
        ];

        aes.add_round_key(&round_key);

        let expected_state = [
            [0x92, 0xcb, 0xd5, 0x82],
            [0x72, 0x0e, 0x93, 0xe1],
            [0xcf, 0x1d, 0xa1, 0xd4],
            [0xf7, 0x86, 0x3e, 0x31],
        ];

        assert_eq!(aes.state, expected_state);
    }

    #[test]
    fn test_aes_sub_bytes() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xcf, 0x9f, 0x71, 0x61,
            0x2c, 0x20,
        ];
        let input = [
            0x19, 0xa0, 0x9a, 0xe9, 0x3d, 0xf4, 0xc6, 0xf8, 0xe3, 0xe2, 0x8d, 0x48, 0xbe, 0x2b,
            0x2a, 0x08,
        ];

        let mut aes = AES::new(key, input);

        aes.sub_bytes();

        let expected_state = [
            [0xd4, 0xe0, 0xb8, 0x1e],
            [0x27, 0xbf, 0xb4, 0x41],
            [0x11, 0x98, 0x5d, 0x52],
            [0xae, 0xf1, 0xe5, 0x30],
        ];

        assert_eq!(aes.state, expected_state);
    }

    #[test]
    fn test_aes_shift_rows() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xcf, 0x9f, 0x71, 0x61,
            0x2c, 0x20,
        ];
        let input = [
            0xd4, 0xe0, 0xb8, 0x1e, 0xbf, 0xb4, 0x41, 0x27, 0x5d, 0x52, 0x11, 0x98, 0x30, 0xae,
            0xf1, 0xe5,
        ];

        let mut aes = AES::new(key, input);

        aes.shift_rows();

        let expected_state = [
            [0xd4, 0xe0, 0xb8, 0x1e],
            [0xb4, 0x41, 0x27, 0xbf],
            [0x11, 0x98, 0x5d, 0x52],
            [0xe5, 0x30, 0xae, 0xf1],
        ];

        assert_eq!(aes.state, expected_state);
    }

    #[test]
    fn test_aes_mix_columns() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xcf, 0x9f, 0x71, 0x61,
            0x2c, 0x20,
        ];
        let input = [
            0xd4, 0xe0, 0xb8, 0x1e, 0xbf, 0xb4, 0x41, 0x27, 0x5d, 0x52, 0x11, 0x98, 0x30, 0xae,
            0xf1, 0xe5,
        ];

        let mut aes = AES::new(key, input);

        aes.mix_columns();

        let expected_state = [
            [0x04, 0xe0, 0x48, 0x28],
            [0x66, 0xcb, 0xf8, 0x06],
            [0x81, 0x19, 0xd3, 0x26],
            [0xe5, 0x9a, 0x7a, 0x4c],
        ];

        assert_eq!(aes.state, expected_state);
    }

    #[test]
    fn test_aes_encrypt() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xcf, 0x9f, 0x71, 0x61,
            0x2c, 0x20,
        ];
        let input = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];

        let expanded_key = key_expansion(&key);
        let mut aes = AES::new(key, input);

        let ciphertext = aes.encrypt(&expanded_key);

        let expected_ciphertext = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];

        assert_eq!(ciphertext, expected_ciphertext);
    }

    #[test]
    fn test_gmul_multiply_by_2() {
        let a: u8 = 0x57; // Example byte value
        let b: u8 = 0x02; // Multiply by 2 in Galois Field

        let result = gmul(a, b);

        let expected_result = 0xae; // Precomputed result of 0x57 * 2 in GF(2^8)

        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_gmul_multiply_by_3() {
        let a: u8 = 0x57; // Example byte value
        let b: u8 = 0x03; // Multiply by 3 in Galois Field

        let result = gmul(a, b);

        let expected_result = 0xf9; // Precomputed result of 0x57 * 3 in GF(2^8)

        assert_eq!(result, expected_result);
    }
}
