#include "../include/ascon_aead128.h"
#include "ascon_bytes.h"
#include "ascon_permutation.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Initialization vector for Ascon-AEAD128 (see NIST SP 800-232). */
#define ASCON128_IV 0x00001000808c0001ULL

static int validate_common_inputs(
    const uint8_t key[ASCON128_KEY_SIZE],
    const uint8_t nonce[ASCON128_NONCE_SIZE]
) {
    if (key == NULL || nonce == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    return ASCON_OK;
}

static int validate_encrypt_args(
    uint8_t *ciphertext,
    uint8_t tag[ASCON128_TAG_SIZE],
    const uint8_t *ad,
    size_t ad_len,
    const uint8_t *plaintext,
    size_t pt_len
) {
    if (tag == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    if (pt_len > 0U && ciphertext == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    if (ad_len > 0U && ad == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    if (pt_len > 0U && plaintext == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    return ASCON_OK;
}

static int validate_decrypt_args(
    uint8_t *plaintext,
    const uint8_t tag[ASCON128_TAG_SIZE],
    const uint8_t *ad,
    size_t ad_len,
    const uint8_t *ciphertext,
    size_t ct_len
) {
    if (tag == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    if (ct_len > 0U && ciphertext == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    if (ad_len > 0U && ad == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    if (ct_len > 0U && plaintext == NULL) {
        return ASCON_ERR_INVALID_ARG;
    }
    return ASCON_OK;
}

static void ascon128_init_state(
    ascon_state_t *s,
    const uint8_t key[ASCON128_KEY_SIZE],
    const uint8_t nonce[ASCON128_NONCE_SIZE]
) {
    const uint64_t k0 = ascon_load64_le(key);
    const uint64_t k1 = ascon_load64_le(key + 8U);
    const uint64_t n0 = ascon_load64_le(nonce);
    const uint64_t n1 = ascon_load64_le(nonce + 8U);

    s->x0 = ASCON128_IV;
    s->x1 = k0;
    s->x2 = k1;
    s->x3 = n0;
    s->x4 = n1;

    ascon_permute12(s);

    s->x3 ^= k0;
    s->x4 ^= k1;
}

static void ascon128_absorb_ad(
    ascon_state_t *s,
    const uint8_t *ad,
    size_t ad_len
) {
    uint8_t block[16];
    size_t offset = 0U;

    if (ad == NULL || ad_len == 0U) {
        return;
    }

    while (ad_len - offset >= 16U) {
        s->x0 ^= ascon_load64_le(ad + offset);
        s->x1 ^= ascon_load64_le(ad + offset + 8U);
        ascon_permute8(s);
        offset += 16U;
    }

    /* Always process a final padded block when AD is non-empty. */
    {
        const size_t rem = ad_len - offset;
        (void)memset(block, 0, sizeof(block));
        if (rem > 0U) {
            (void)memcpy(block, ad + offset, rem);
        }
        ascon_pad_block(block, rem, sizeof(block));
        s->x0 ^= ascon_load64_le(block);
        s->x1 ^= ascon_load64_le(block + 8U);
        ascon_permute8(s);
    }
}

static void ascon128_separate_ad_payload(ascon_state_t *s) {
    s->x4 ^= 0x8000000000000000ULL;
}

static void ascon128_process_encrypt(
    ascon_state_t *s,
    uint8_t *ciphertext,
    const uint8_t *plaintext,
    size_t pt_len
) {
    uint8_t block[16];
    uint8_t s_bytes[16];
    size_t offset = 0U;

    while (pt_len - offset >= 16U) {
        const uint64_t p0 = ascon_load64_le(plaintext + offset);
        const uint64_t p1 = ascon_load64_le(plaintext + offset + 8U);

        s->x0 ^= p0;
        s->x1 ^= p1;

        ascon_store64_le(ciphertext + offset, s->x0);
        ascon_store64_le(ciphertext + offset + 8U, s->x1);

        ascon_permute8(s);
        offset += 16U;
    }

    /* Final padded block (always processed, even for empty remainder). */
    {
        const size_t rem = pt_len - offset;
        (void)memset(block, 0, sizeof(block));
        if (rem > 0U) {
            (void)memcpy(block, plaintext + offset, rem);
        }
        ascon_pad_block(block, rem, sizeof(block));

        s->x0 ^= ascon_load64_le(block);
        s->x1 ^= ascon_load64_le(block + 8U);

        ascon_store64_le(s_bytes, s->x0);
        ascon_store64_le(s_bytes + 8U, s->x1);

        if (rem > 0U) {
            (void)memcpy(ciphertext + offset, s_bytes, rem);
        }
    }
}

static void ascon128_process_decrypt(
    ascon_state_t *s,
    uint8_t *plaintext,
    const uint8_t *ciphertext,
    size_t ct_len
) {
    uint8_t s_bytes[16];
    size_t offset = 0U;

    while (ct_len - offset >= 16U) {
        const uint64_t c0 = ascon_load64_le(ciphertext + offset);
        const uint64_t c1 = ascon_load64_le(ciphertext + offset + 8U);
        const uint64_t p0 = s->x0 ^ c0;
        const uint64_t p1 = s->x1 ^ c1;

        ascon_store64_le(plaintext + offset, p0);
        ascon_store64_le(plaintext + offset + 8U, p1);

        s->x0 = c0;
        s->x1 = c1;
        ascon_permute8(s);
        offset += 16U;
    }

    /* Final padded block (always processed, even for empty remainder). */
    {
        const size_t rem = ct_len - offset;
        size_t i;

        ascon_store64_le(s_bytes, s->x0);
        ascon_store64_le(s_bytes + 8U, s->x1);

        for (i = 0U; i < rem; i++) {
            const uint8_t c = ciphertext[offset + i];
            const uint8_t p = (uint8_t)(s_bytes[i] ^ c);
            plaintext[offset + i] = p;
            s_bytes[i] = c;
        }
        if (rem < sizeof(s_bytes)) {
            s_bytes[rem] ^= 0x01U;
        }

        s->x0 = ascon_load64_le(s_bytes);
        s->x1 = ascon_load64_le(s_bytes + 8U);
    }
}

static void ascon128_finalize(
    ascon_state_t *s,
    const uint8_t key[ASCON128_KEY_SIZE],
    uint8_t out_tag[ASCON128_TAG_SIZE]
) {
    const uint64_t k0 = ascon_load64_le(key);
    const uint64_t k1 = ascon_load64_le(key + 8U);

    s->x2 ^= k0;
    s->x3 ^= k1;

    ascon_permute12(s);

    s->x3 ^= k0;
    s->x4 ^= k1;

    ascon_store64_le(out_tag, s->x3);
    ascon_store64_le(out_tag + 8U, s->x4);
}

static int ascon128_constant_time_tag_verify(
    const uint8_t expected[ASCON128_TAG_SIZE],
    const uint8_t provided[ASCON128_TAG_SIZE]
) {
    size_t i;
    uint8_t diff = 0U;

    for (i = 0U; i < ASCON128_TAG_SIZE; i++) {
        diff |= (uint8_t)(expected[i] ^ provided[i]);
    }

    return (diff == 0U) ? ASCON_OK : ASCON_ERR_AUTH_FAILED;
}

int ascon_aead128_encrypt(
    uint8_t *ciphertext,
    uint8_t tag[ASCON128_TAG_SIZE],
    const uint8_t key[ASCON128_KEY_SIZE],
    const uint8_t nonce[ASCON128_NONCE_SIZE],
    const uint8_t *ad,
    size_t ad_len,
    const uint8_t *plaintext,
    size_t pt_len
) {
    ascon_state_t state;
    int rc;

    rc = validate_common_inputs(key, nonce);
    if (rc != ASCON_OK) {
        return rc;
    }
    rc = validate_encrypt_args(ciphertext, tag, ad, ad_len, plaintext, pt_len);
    if (rc != ASCON_OK) {
        return rc;
    }

    ascon128_init_state(&state, key, nonce);
    ascon128_absorb_ad(&state, ad, ad_len);
    ascon128_separate_ad_payload(&state);
    ascon128_process_encrypt(&state, ciphertext, plaintext, pt_len);
    ascon128_finalize(&state, key, tag);

    return ASCON_OK;
}

int ascon_aead128_decrypt(
    uint8_t *plaintext,
    const uint8_t tag[ASCON128_TAG_SIZE],
    const uint8_t key[ASCON128_KEY_SIZE],
    const uint8_t nonce[ASCON128_NONCE_SIZE],
    const uint8_t *ad,
    size_t ad_len,
    const uint8_t *ciphertext,
    size_t ct_len
) {
    ascon_state_t state;
    uint8_t computed_tag[ASCON128_TAG_SIZE];
    int rc;

    rc = validate_common_inputs(key, nonce);
    if (rc != ASCON_OK) {
        return rc;
    }
    rc = validate_decrypt_args(plaintext, tag, ad, ad_len, ciphertext, ct_len);
    if (rc != ASCON_OK) {
        return rc;
    }

    ascon128_init_state(&state, key, nonce);
    ascon128_absorb_ad(&state, ad, ad_len);
    ascon128_separate_ad_payload(&state);
    ascon128_process_decrypt(&state, plaintext, ciphertext, ct_len);
    ascon128_finalize(&state, key, computed_tag);

    rc = ascon128_constant_time_tag_verify(computed_tag, tag);
    if (rc != ASCON_OK) {
        size_t i;
        for (i = 0U; i < ct_len; i++) {
            plaintext[i] = 0U;
        }
        return ASCON_ERR_AUTH_FAILED;
    }

    return ASCON_OK;
}
