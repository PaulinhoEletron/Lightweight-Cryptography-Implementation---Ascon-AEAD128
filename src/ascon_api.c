#include "../include/ascon_api.h"
#include <stddef.h>
#include <stdint.h>

#include "../include/ascon_aead128.h"

static int validate_common_api_inputs(
    const uint8_t key[ASCON128_KEY_SIZE],
    const uint8_t nonce[ASCON128_NONCE_SIZE]
) {
    if (key == NULL || nonce == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    return ASCON_OK;
}

static int validate_buffer_and_length(const uint8_t *buf, size_t len) {
    if (len == 0U) {
        return ASCON_OK;
    }
    if (buf == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    return ASCON_OK;
}

int ascon128_encrypt(
    uint8_t *ciphertext,
    uint8_t tag[ASCON128_TAG_SIZE],
    const uint8_t key[ASCON128_KEY_SIZE],
    const uint8_t nonce[ASCON128_NONCE_SIZE],
    const uint8_t *ad,
    size_t ad_len,
    const uint8_t *plaintext,
    size_t pt_len
) {
    int rc;

    if (tag == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    rc = validate_common_api_inputs(key, nonce);
    if (rc != ASCON_OK) {
        return rc;
    }
    if (validate_buffer_and_length(ad, ad_len) != ASCON_OK) {
        return ASCON_ERR_INVALID_ARG;
    }
    if (validate_buffer_and_length(plaintext, pt_len) != ASCON_OK) {
        return ASCON_ERR_INVALID_ARG;
    }
    /* ciphertext shares the same length as plaintext. */
    if (pt_len != 0U && ciphertext == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }

    return ascon_aead128_encrypt(
        ciphertext,
        tag,
        key,
        nonce,
        ad,
        ad_len,
        plaintext,
        pt_len
    );
}

int ascon128_decrypt(
    uint8_t *plaintext,
    const uint8_t tag[ASCON128_TAG_SIZE],
    const uint8_t key[ASCON128_KEY_SIZE],
    const uint8_t nonce[ASCON128_NONCE_SIZE],
    const uint8_t *ad,
    size_t ad_len,
    const uint8_t *ciphertext,
    size_t ct_len
) {
    int rc;

    if (tag == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    rc = validate_common_api_inputs(key, nonce);
    if (rc != ASCON_OK) {
        return rc;
    }
    if (validate_buffer_and_length(ad, ad_len) != ASCON_OK) {
        return ASCON_ERR_INVALID_ARG;
    }
    if (validate_buffer_and_length(ciphertext, ct_len) != ASCON_OK) {
        return ASCON_ERR_INVALID_ARG;
    }
    /* plaintext shares the same length as ciphertext. */
    if (ct_len != 0U && plaintext == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }

    return ascon_aead128_decrypt(
        plaintext,
        tag,
        key,
        nonce,
        ad,
        ad_len,
        ciphertext,
        ct_len
    );
}
