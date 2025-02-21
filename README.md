# Tiny-Encryption-Algorithm (TEA) Implementation
Implementation of TEA encryption and decryption in both ECB and CBC modes.

## Summary
The Tiny Encryption Algorithm (TEA) is a symmetric key block cipher known for its simplicity and efficiency, especially in resource-constrained environments. TEA operates on 64-bit blocks with a 128-bit key and uses a Feistel structure with 32 rounds for encryption and decryption.

This project implements TEA encryption in both Electronic Code Book (ECB) mode and Cipher Block Chaining (CBC) mode. The implementation ensures that the first 10 blocks remain unencrypted and allows users to input encryption parameters.

## Specifications
This application should be able to perform the following tasks:
1. Implement TEA encryption and decryption with 32 rounds.
2. Support both ECB and CBC encryption modes.
3. Accept user input for key, plaintext/ciphertext, and initialization vector (IV) (for CBC mode).
4. Encrypt and decrypt a provided linked image to verify implementation correctness.
5. Leave the first 10 blocks unencrypted.
6. Display and output results analogous to diagrams presented in Chapter 4, Slides 12 and 21.

## Input Format
- The program should prompt the user to enter:
  - 128-bit encryption key
  - Plaintext or ciphertext
  - Initialization vector (IV) for CBC mode

## Output Format
- Encrypted and decrypted text or image output.
- Visualization of encryption and decryption results.

## Author
Qusay Taradeh
