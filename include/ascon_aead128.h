#ifndef ASCON_AEAD128_H
#define ASCON_AEAD128_H

#include <stddef.h>
#include <stdint.h>

#define ASCON128_KEY_SIZE 16U
#define ASCON128_NONCE_SIZE 16U
#define ASCON128_TAG_SIZE 16U

enum ascon_status {
    ASCON_OK = 0,
    ASCON_ERR_INVALID_ARG = -1,
    ASCON_ERR_AUTH_FAILED = -2,
};

int ascon_aead128_encrypt(
    uint8_t *ciphertext,
    uint8_t tag[ASCON128_TAG_SIZE],
    const uint8_t key[ASCON128_KEY_SIZE],
    const uint8_t nonce[ASCON128_NONCE_SIZE],
    const uint8_t *ad,
    size_t ad_len,
    const uint8_t *plaintext,
    size_t pt_len
);

int ascon_aead128_decrypt(
    uint8_t *plaintext,
    const uint8_t tag[ASCON128_TAG_SIZE],
    const uint8_t key[ASCON128_KEY_SIZE],
    const uint8_t nonce[ASCON128_NONCE_SIZE],
    const uint8_t *ad,
    size_t ad_len,
    const uint8_t *ciphertext,
    size_t ct_len
);

#endif
