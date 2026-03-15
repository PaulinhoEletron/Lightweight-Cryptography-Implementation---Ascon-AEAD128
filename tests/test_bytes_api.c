#include "../include/ascon_bytes.h"
#include "../include/ascon_api.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static void test_bytes_helpers(void) {
    uint8_t in[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    uint8_t out[8] = {0};
    uint64_t x = ascon_load64_le(in);

    ascon_store64_le(out, x);
    for (int i = 0; i < 8; i++) {
        assert(out[i] == in[i]);
    }

    uint8_t block[8];
    memset(block, 0x00, sizeof block);
    ascon_pad_block(block, 3U, 8U);
    assert(block[3] == 0x01U);
    for (int i = 4; i < 8; i++) {
        assert(block[i] == 0x00U);
    }

    /* Out-of-range "used" should not write into the buffer. */
    memset(block, 0xAA, sizeof block);
    ascon_pad_block(block, 8U, 8U);
    for (int i = 0; i < 8; i++) {
        assert(block[i] == 0xAAU);
    }

    /* NULL block must be handled safely. */
    ascon_pad_block(NULL, 0U, 8U);
}

static void test_api_validation_and_flow(void) {
    uint8_t key[ASCON128_KEY_SIZE] = {0};
    uint8_t nonce[ASCON128_NONCE_SIZE] = {0};
    uint8_t tag[ASCON128_TAG_SIZE] = {0};
    uint8_t ct[4] = {0};
    uint8_t pt[4] = {0};

    /* Happy-path call with zero-length message and AD is allowed. */
    int enc_rc = ascon128_encrypt(
        NULL,
        tag,
        key,
        nonce,
        NULL,
        0U,
        NULL,
        0U
    );
    assert(enc_rc == ASCON_OK);

    int dec_rc = ascon128_decrypt(
        NULL,
        tag,
        key,
        nonce,
        NULL,
        0U,
        NULL,
        0U
    );
    assert(dec_rc == ASCON_ERR_AUTH_FAILED || dec_rc == ASCON_OK);

    /* Non-zero lengths require non-NULL buffers. */
    enc_rc = ascon128_encrypt(
        NULL,
        tag,
        key,
        nonce,
        NULL,
        0U,
        pt,
        1U
    );
    assert(enc_rc == ASCON_ERR_INVALID_ARG);

    dec_rc = ascon128_decrypt(
        pt,
        tag,
        key,
        nonce,
        NULL,
        0U,
        NULL,
        1U
    );
    assert(dec_rc == ASCON_ERR_INVALID_ARG);

    /* AD pointer must be non-NULL when ad_len > 0. */
    enc_rc = ascon128_encrypt(
        ct,
        tag,
        key,
        nonce,
        NULL,
        4U,
        pt,
        4U
    );
    assert(enc_rc == ASCON_ERR_INVALID_ARG);

    /* Key/nonce/tag must not be NULL. */
    enc_rc = ascon128_encrypt(
        ct,
        NULL,
        key,
        nonce,
        NULL,
        0U,
        pt,
        0U
    );
    assert(enc_rc == ASCON_ERR_INVALID_ARG);

    enc_rc = ascon128_encrypt(
        ct,
        tag,
        NULL,
        nonce,
        NULL,
        0U,
        pt,
        0U
    );
    assert(enc_rc == ASCON_ERR_INVALID_ARG);

    enc_rc = ascon128_encrypt(
        ct,
        tag,
        key,
        NULL,
        NULL,
        0U,
        pt,
        0U
    );
    assert(enc_rc == ASCON_ERR_INVALID_ARG);
}

int main(void) {
    test_bytes_helpers();
    test_api_validation_and_flow();
    return 0;
}
