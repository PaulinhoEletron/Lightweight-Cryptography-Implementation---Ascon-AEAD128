#ifndef ASCON_API_H
#define ASCON_API_H

#include <stddef.h>
#include <stdint.h>

#include "ascon_aead128.h"

/*
 * Stable top-level Ascon-128 AEAD API.
 *
 * These helpers perform strict argument validation and delegate the
 * actual encrypt/decrypt to the core Ascon-AEAD128 implementation.
 *
 * Validation rules:
 * - key, nonce, and tag pointers MUST be non-NULL.
 * - ciphertext/plaintext MAY be NULL only when their length is zero.
 * - associated data pointer MAY be NULL only when ad_len is zero.
 *
 * On invalid arguments, ASCON_ERR_INVALID_ARG is returned and the
 * underlying core is not invoked.
 */
int ascon128_encrypt(
    uint8_t *ciphertext,
    uint8_t tag[ASCON128_TAG_SIZE],
    const uint8_t key[ASCON128_KEY_SIZE],
    const uint8_t nonce[ASCON128_NONCE_SIZE],
    const uint8_t *ad,
    size_t ad_len,
    const uint8_t *plaintext,
    size_t pt_len
);

int ascon128_decrypt(
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
