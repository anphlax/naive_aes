# Naive AES-128 Implementation

This is a simple, naive, and unsecure implementation of the AES-128 (Advanced Encryption Standard) algorithm for educational purposes. The implementation is not optimized and should not be used in production or in any security-sensitive contexts.

## Features

AES-128 Encryption: Implements the core AES-128 encryption process, including key expansion and all standard AES transformations (SubBytes, ShiftRows, MixColumns, and AddRoundKey).
Key Expansion: Expands a 128-bit key into 44 4-byte words for use in the 10 rounds of AES encryption.
Tests: Includes unit tests to verify the correctness of the implementation, based on official AES example vectors and intermediate results.

## Contribute
This will likely be not maintained, but if you like open a PR with your additions :)
