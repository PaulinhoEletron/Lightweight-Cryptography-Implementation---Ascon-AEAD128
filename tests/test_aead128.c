#include "../include/ascon_aead128.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void test_roundtrip_empty(void) {
    uint8_t key[ASCON128_KEY_SIZE] = {0};
    uint8_t nonce[ASCON128_NONCE_SIZE] = {0};
    uint8_t tag[ASCON128_TAG_SIZE] = {0};
    uint8_t ct[1] = {0};
    uint8_t pt[1] = {0};

    int enc_rc = ascon_aead128_encrypt(ct, tag, key, nonce, NULL, 0U, NULL, 0U);
    int dec_rc = ascon_aead128_decrypt(pt, tag, key, nonce, NULL, 0U, ct, 0U);

    assert(enc_rc == ASCON_OK);
    assert(dec_rc == ASCON_OK);
}

static void test_roundtrip_various_lengths(void) {
    uint8_t key[ASCON128_KEY_SIZE] = {1};
    uint8_t nonce[ASCON128_NONCE_SIZE] = {2};
    uint8_t tag[ASCON128_TAG_SIZE];
    uint8_t tag2[ASCON128_TAG_SIZE];
    uint8_t ad[17];
    uint8_t pt[33];
    uint8_t ct[33];
    uint8_t dec[33];
    size_t i;

    for (i = 0U; i < sizeof(ad); i++) {
        ad[i] = (uint8_t)i;
    }
    for (i = 0U; i < sizeof(pt); i++) {
        pt[i] = (uint8_t)(0xAAU ^ i);
    }

    int enc_rc = ascon_aead128_encrypt(
        ct,
        tag,
        key,
        nonce,
        ad,
        sizeof(ad),
        pt,
        sizeof(pt)
    );
    assert(enc_rc == ASCON_OK);

    int dec_rc = ascon_aead128_decrypt(
        dec,
        tag,
        key,
        nonce,
        ad,
        sizeof(ad),
        ct,
        sizeof(ct)
    );
    assert(dec_rc == ASCON_OK);
    assert(memcmp(pt, dec, sizeof(pt)) == 0);

    {
        uint8_t short_pt[7] = {0, 1, 2, 3, 4, 5, 6};
        uint8_t short_ct[7];
        uint8_t short_dec[7];

        enc_rc = ascon_aead128_encrypt(
            short_ct,
            tag2,
            key,
            nonce,
            ad,
            sizeof(ad),
            short_pt,
            sizeof(short_pt)
        );
        assert(enc_rc == ASCON_OK);

        dec_rc = ascon_aead128_decrypt(
            short_dec,
            tag2,
            key,
            nonce,
            ad,
            sizeof(ad),
            short_ct,
            sizeof(short_ct)
        );
        assert(dec_rc == ASCON_OK);
        assert(memcmp(short_pt, short_dec, sizeof(short_pt)) == 0);
    }
}

static void test_tag_mismatch_fails(void) {
    uint8_t key[ASCON128_KEY_SIZE] = {3};
    uint8_t nonce[ASCON128_NONCE_SIZE] = {4};
    uint8_t tag[ASCON128_TAG_SIZE] = {0};
    uint8_t bad_tag[ASCON128_TAG_SIZE];
    uint8_t pt[8] = {0};
    uint8_t ct[8];
    uint8_t dec[8];
    int rc;

    rc = ascon_aead128_encrypt(
        ct,
        tag,
        key,
        nonce,
        NULL,
        0U,
        pt,
        sizeof(pt)
    );
    assert(rc == ASCON_OK);

    (void)memcpy(bad_tag, tag, sizeof(tag));
    bad_tag[0] ^= 0x01U;

    rc = ascon_aead128_decrypt(
        dec,
        bad_tag,
        key,
        nonce,
        NULL,
        0U,
        ct,
        sizeof(ct)
    );
    assert(rc == ASCON_ERR_AUTH_FAILED);
}

int main(void) {
    test_roundtrip_empty();
    test_roundtrip_various_lengths();
    test_tag_mismatch_fails();
    return 0;
}
