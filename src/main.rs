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
mod tests;
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

