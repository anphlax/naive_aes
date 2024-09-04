#[cfg(test)]
mod tests {
    use crate::*;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_add_round_key() {
            // Initial state (4x4 matrix)
            let input = [
                [0x32, 0x88, 0x31, 0xe0], // row 1
                [0x43, 0x5a, 0x31, 0x37], // row 2
                [0xf6, 0x30, 0x98, 0x07], // row 3
                [0xa8, 0x8d, 0xa2, 0x34], // row 4
            ];

            // Round key (4x4 matrix)
            let round_key = [
                [0x2b, 0x28, 0xab, 0x09], // word 1
                [0x7e, 0xae, 0xf7, 0xcf], // word 2
                [0x15, 0xd2, 0x15, 0x4f], // word 3
                [0x16, 0xa6, 0x88, 0x3c], // word 4
            ];

            // Correct expected state after XORing state with round key
            let expected_state = [
                [0x19, 0xa0, 0x9a, 0xe9], // row 1
                [0x3d, 0xf4, 0xc6, 0xf8], // row 2
                [0xe3, 0xe2, 0x8d, 0x48], // row 3
                [0xbe, 0x2b, 0x2a, 0x08], // row 4
            ];

            // Create AES instance with dummy key and input (only state matters)
            let mut aes = AES {
                key: [0u8; BLOCK_SIZE], // key doesn't matter for this test
                state: input,
            };

            // Call add_round_key method
            aes.add_round_key(&round_key);

            // Assert that the modified state matches the expected state
            assert_eq!(aes.state, expected_state, "AddRoundKey operation failed!");
        }
    }

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
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
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
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
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

    #[test]
    fn test_aes_encrypt() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0xcf, 0x9f, 0x71, 0x61, 0x2c, 0x20,
        ];

        let input = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ];

        let mut aes = AES::new(key, input);

        // Expanding the key using the key expansion function
        let expanded_key = key_expansion(&key);

        // Perform AES encryption
        let ciphertext = aes.encrypt(&expanded_key);

        // Expected ciphertext based on the S-box and AES process
        let expected_ciphertext = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
        ];

        // Asserting that the output is as expected
        assert_eq!(ciphertext, expected_ciphertext, "AES encryption failed!");
    }

    #[test]
    fn test_aes_encrypt_128bit_specification() {
        // Plaintext: 00112233445566778899aabbccddeeff
        let input = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];

        // Key: 000102030405060708090a0b0c0d0e0f
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];

        // Expected ciphertext from the specification: 69c4e0d86a7b0430d8cdb78070b4c55a
        let expected_ciphertext = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];

        // Initialize AES instance with the key and input (plaintext)
        let mut aes = AES::new(key, input);

        // Expand the key for 10 rounds (AES-128 uses 10 rounds)
        let expanded_key = key_expansion(&key);

        // Encrypt the input
        let ciphertext = aes.encrypt(&expanded_key);

        // Assert the result matches the expected ciphertext
        assert_eq!(ciphertext, expected_ciphertext, "AES encryption did not produce the expected ciphertext!");
    }
}
