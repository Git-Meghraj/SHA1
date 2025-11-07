/**
 * @file sha1.c
 * @brief C implementation of SHA-1 cryptographic hash function.
 *
 * This program demonstrates how SHA-1 converts any input string
 * into a fixed 160-bit hash, showing concepts like message padding,
 * bitwise rotations, and logical functions.
 *
 * @author Meghraj Tandurkar
 * @date 2025
 * @note SHA-1 is no longer recommended for new security-critical applications.
 *       This implementation is for educational purposes.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Function to perform left bitwise rotation
uint32_t rotate_left(uint32_t value, uint32_t bits) {
    return (value << bits) | (value >> (32 - bits));
}

// Function to assign f(t)
uint32_t assign_f(int t, uint32_t B, uint32_t C, uint32_t D) {
    if (t >= 0 && t < 20) {
        return (B & C) ^ (~B & D);  // Ch function for t = 0 to 19
    } else if (t >= 20 && t < 40) {
        return (B ^ C ^ D);  // Parity function for t = 20 to 39
    } else if (t >= 40 && t < 60) {
        return (B & C) ^ (B & D) ^ (C & D);  // Maj function for t = 40 to 59
    } else {
        return (B ^ C ^ D);  // Parity function for t = 60 to 79
    }
}

// Function to assign Kt
uint32_t assign_Kt(int t) {
    if (t >= 0 && t < 20) {
        return 0x5a827999;
    } else if (t >= 20 && t < 40) {
        return 0x6ed9eba1;
    } else if (t >= 40 && t < 60) {
        return 0x8f1bbcdc;
    } else {
        return 0xca62c1d6;
    }
}

// Main processing function
void sha_1(uint32_t *hash_ptr, const uint32_t *message, const uint32_t *prev_hash) {
    uint32_t H[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};  // initial hash values
    uint32_t A, B, C, D, E;
    uint32_t Wt[80];
    uint32_t T;

    // Creating the 80 words for processing
    for (int i = 0; i < 16; i++) {
        Wt[i] = message[i];  // For first 16 words directly copy from the message.
    }

    // Extending the first 16 words for the remaining 64 words using the below formula
    for (int i = 16; i < 80; i++) {
        Wt[i] = rotate_left(Wt[i - 3] ^ Wt[i - 8] ^ Wt[i - 14] ^ Wt[i - 16], 1);
    }

    // Initialize working variables
    A = H[0];
    B = H[1];
    C = H[2];
    D = H[3];
    E = H[4];

    // Main loop for 80 rounds
    for (int t = 0; t < 80; t++) {
        T = rotate_left(A, 5) + assign_f(t, B, C, D) + E + Wt[t] + assign_Kt(t);
        E = D;
        D = C;
        C = rotate_left(B, 30);
        B = A;
        A = T;
    }

    // Update the hash values
    H[0] += A;
    H[1] += B;
    H[2] += C;
    H[3] += D;
    H[4] += E;

    // Store the full hash value (160 bits: H[0], H[1], H[2], H[3], H[4])
    for (int i = 0; i < 5; i++) {
        hash_ptr[i] = H[i];
    }

    /// prev_hash = hash_ptr; TO DO
}

int main() {
    char input[64];
    printf("Enter input string: ");
    fflush(stdout);
    fgets(input, sizeof(input), stdin);


    // Remove newline if present
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
        len--;
    }

    // Prepare message (512 bits = 64 bytes)
    uint8_t block[64] = {0};
    memcpy(block, input, len);
    block[len] = 0x80; // append '1' bit (10000000)
    uint64_t bit_len = len * 8;

    // Append message length in bits (big-endian)
    block[63] = (uint8_t)(bit_len);
    block[62] = (uint8_t)(bit_len >> 8);
    block[61] = (uint8_t)(bit_len >> 16);
    block[60] = (uint8_t)(bit_len >> 24);

    // Convert block into 16 32-bit words
    uint32_t msg[16];
    for (int i = 0; i < 16; i++) {
        msg[i] = (block[i * 4] << 24) |
                 (block[i * 4 + 1] << 16) |
                 (block[i * 4 + 2] << 8) |
                 (block[i * 4 + 3]);
    }

    uint32_t final_hash[5];  // Array to store the 160-bit hash

    // Calculate SHA-1 hash
    sha_1(final_hash, msg, NULL);

    // Print the full 160-bit hash (5 × 32-bit values)
    printf("SHA1 Hash: ");
    for (int i = 0; i < 5; i++) {
        printf("%08x", final_hash[i]);
    }
    printf("\n");

    return 0;
}

