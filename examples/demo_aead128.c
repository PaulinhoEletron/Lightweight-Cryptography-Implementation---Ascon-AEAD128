#include "ascon_api.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    size_t i;
    printf("%s", label);
    for (i = 0U; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

int main(void) {
    uint8_t key[ASCON128_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    uint8_t nonce[ASCON128_NONCE_SIZE] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    const uint8_t ad[] = "demo-associated-data";
    const uint8_t plaintext[] = "hello from ascon128";

    uint8_t ciphertext[sizeof(plaintext) - 1U];
    uint8_t tag[ASCON128_TAG_SIZE];
    uint8_t decrypted[sizeof(plaintext) - 1U];

    int rc = ascon128_encrypt(
        ciphertext,
        tag,
        key,
        nonce,
        ad,
        sizeof(ad) - 1U,
        plaintext,
        sizeof(plaintext) - 1U
    );
    if (rc != ASCON_OK) {
        printf("encrypt failed: %d\n", rc);
        return 1;
    }

    print_hex("ciphertext = ", ciphertext, sizeof(ciphertext));
    print_hex("tag        = ", tag, sizeof(tag));

    rc = ascon128_decrypt(
        decrypted,
        tag,
        key,
        nonce,
        ad,
        sizeof(ad) - 1U,
        ciphertext,
        sizeof(ciphertext)
    );
    if (rc != ASCON_OK) {
        printf("decrypt failed: %d\n", rc);
        return 1;
    }

    if (memcmp(decrypted, plaintext, sizeof(plaintext) - 1U) != 0) {
        printf("decrypt mismatch\n");
        return 1;
    }

    printf("decrypt ok: %.*s\n", (int)(sizeof(plaintext) - 1U), decrypted);
    return 0;
}
