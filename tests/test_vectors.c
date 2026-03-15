#include "../include/ascon_aead128.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *trim(char *s) {
    char *end;

    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    end = s + strlen(s) - 1U;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static int parse_hex_alloc(const char *hex, uint8_t **out, size_t *out_len) {
    size_t len = strlen(hex);
    size_t i;

    if (len == 0U) {
        *out = NULL;
        *out_len = 0U;
        return 0;
    }
    if ((len & 1U) != 0U) {
        return -1;
    }

    *out_len = len / 2U;
    *out = (uint8_t *)malloc(*out_len);
    if (*out == NULL) {
        return -1;
    }

    for (i = 0U; i < *out_len; i++) {
        int hi = hex_nibble(hex[2U * i]);
        int lo = hex_nibble(hex[2U * i + 1U]);
        if (hi < 0 || lo < 0) {
            free(*out);
            *out = NULL;
            *out_len = 0U;
            return -1;
        }
        (*out)[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static int parse_hex_fixed(const char *hex, uint8_t *out, size_t expected_len) {
    uint8_t *tmp = NULL;
    size_t tmp_len = 0U;
    int rc = parse_hex_alloc(hex, &tmp, &tmp_len);

    if (rc != 0 || tmp_len != expected_len) {
        free(tmp);
        return -1;
    }
    memcpy(out, tmp, expected_len);
    free(tmp);
    return 0;
}

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    size_t i;
    fprintf(stderr, "%s", label);
    for (i = 0U; i < len; i++) {
        fprintf(stderr, "%02X", buf[i]);
    }
    fprintf(stderr, "\n");
}

static int match_field(char *line, const char *field, const char **value) {
    const size_t len = strlen(field);
    const char *p;

    if (strncmp(line, field, len) != 0) {
        return 0;
    }
    p = line + len;
    while (*p == ' ') {
        p++;
    }
    if (*p != '=') {
        return 0;
    }
    p++;
    while (*p == ' ') {
        p++;
    }
    *value = p;
    return 1;
}

static FILE *open_vectors_file(void) {
    const char *paths[] = {
        "vectors/LWC_AEAD_KAT_128_128.txt",
        "../vectors/LWC_AEAD_KAT_128_128.txt"
    };
    size_t i;

    for (i = 0U; i < sizeof(paths) / sizeof(paths[0]); i++) {
        FILE *fp = fopen(paths[i], "r");
        if (fp != NULL) {
            return fp;
        }
    }
    return NULL;
}

static int run_case(
    unsigned long count,
    const uint8_t key[ASCON128_KEY_SIZE],
    const uint8_t nonce[ASCON128_NONCE_SIZE],
    const uint8_t *ad,
    size_t ad_len,
    const uint8_t *pt,
    size_t pt_len,
    const uint8_t *ct,
    size_t ct_len
) {
    uint8_t tag[ASCON128_TAG_SIZE];
    uint8_t *ct_out = NULL;
    uint8_t *pt_out = NULL;
    size_t msg_len;
    int rc;

    if (ct_len < ASCON128_TAG_SIZE) {
        fprintf(stderr, "Count %lu: CT too short\n", count);
        return -1;
    }

    msg_len = ct_len - ASCON128_TAG_SIZE;
    if (msg_len != pt_len) {
        fprintf(stderr, "Count %lu: PT length mismatch (pt=%zu ct=%zu)\n", count, pt_len, msg_len);
        return -1;
    }

    if (pt_len > 0U) {
        ct_out = (uint8_t *)malloc(pt_len);
        pt_out = (uint8_t *)malloc(pt_len);
        if (ct_out == NULL || pt_out == NULL) {
            free(ct_out);
            free(pt_out);
            fprintf(stderr, "Count %lu: allocation failed\n", count);
            return -1;
        }
    }

    rc = ascon_aead128_encrypt(
        ct_out,
        tag,
        key,
        nonce,
        ad_len > 0U ? ad : NULL,
        ad_len,
        pt_len > 0U ? pt : NULL,
        pt_len
    );
    if (rc != ASCON_OK) {
        fprintf(stderr, "Count %lu: encrypt failed (rc=%d)\n", count, rc);
        free(ct_out);
        free(pt_out);
        return -1;
    }

    if (pt_len > 0U && memcmp(ct_out, ct, pt_len) != 0) {
        fprintf(stderr, "Count %lu: ciphertext mismatch\n", count);
        print_hex("expected CT = ", ct, pt_len);
        print_hex("computed CT = ", ct_out, pt_len);
        free(ct_out);
        free(pt_out);
        return -1;
    }
    if (memcmp(tag, ct + pt_len, ASCON128_TAG_SIZE) != 0) {
        fprintf(stderr, "Count %lu: tag mismatch\n", count);
        print_hex("expected TAG = ", ct + pt_len, ASCON128_TAG_SIZE);
        print_hex("computed TAG = ", tag, ASCON128_TAG_SIZE);
        free(ct_out);
        free(pt_out);
        return -1;
    }

    rc = ascon_aead128_decrypt(
        pt_out,
        ct + pt_len,
        key,
        nonce,
        ad_len > 0U ? ad : NULL,
        ad_len,
        msg_len > 0U ? ct : NULL,
        msg_len
    );
    if (rc != ASCON_OK) {
        fprintf(stderr, "Count %lu: decrypt failed (rc=%d)\n", count, rc);
        free(ct_out);
        free(pt_out);
        return -1;
    }
    if (pt_len > 0U && memcmp(pt_out, pt, pt_len) != 0) {
        fprintf(stderr, "Count %lu: plaintext mismatch\n", count);
        free(ct_out);
        free(pt_out);
        return -1;
    }

    {
        uint8_t bad_tag[ASCON128_TAG_SIZE];
        memcpy(bad_tag, ct + pt_len, ASCON128_TAG_SIZE);
        bad_tag[0] ^= 0x01U;
        rc = ascon_aead128_decrypt(
            pt_out,
            bad_tag,
            key,
            nonce,
            ad_len > 0U ? ad : NULL,
            ad_len,
            msg_len > 0U ? ct : NULL,
            msg_len
        );
        if (rc != ASCON_ERR_AUTH_FAILED) {
            fprintf(stderr, "Count %lu: expected auth failure\n", count);
            free(ct_out);
            free(pt_out);
            return -1;
        }
    }

    free(ct_out);
    free(pt_out);
    return 0;
}

int main(void) {
    FILE *fp = open_vectors_file();
    char line[8192];
    unsigned long count = 0U;
    uint8_t key[ASCON128_KEY_SIZE];
    uint8_t nonce[ASCON128_NONCE_SIZE];
    uint8_t *pt = NULL;
    uint8_t *ad = NULL;
    uint8_t *ct = NULL;
    size_t pt_len = 0U;
    size_t ad_len = 0U;
    size_t ct_len = 0U;
    unsigned long total = 0U;

    if (fp == NULL) {
        fprintf(stderr, "Unable to open KAT file (vectors/LWC_AEAD_KAT_128_128.txt)\n");
        return 1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *cursor = trim(line);
        const char *value = NULL;

        if (*cursor == '\0') {
            continue;
        }
        if (match_field(cursor, "Count", &value)) {
            errno = 0;
            count = strtoul(value, NULL, 10);
            if (errno != 0) {
                fprintf(stderr, "Invalid Count line\n");
                fclose(fp);
                return 1;
            }
            continue;
        }
        if (match_field(cursor, "Key", &value)) {
            if (parse_hex_fixed(value, key, ASCON128_KEY_SIZE) != 0) {
                fprintf(stderr, "Count %lu: invalid Key\n", count);
                fclose(fp);
                return 1;
            }
            continue;
        }
        if (match_field(cursor, "Nonce", &value)) {
            if (parse_hex_fixed(value, nonce, ASCON128_NONCE_SIZE) != 0) {
                fprintf(stderr, "Count %lu: invalid Nonce\n", count);
                fclose(fp);
                return 1;
            }
            continue;
        }
        if (match_field(cursor, "PT", &value)) {
            free(pt);
            pt = NULL;
            pt_len = 0U;
            if (parse_hex_alloc(value, &pt, &pt_len) != 0) {
                fprintf(stderr, "Count %lu: invalid PT\n", count);
                fclose(fp);
                return 1;
            }
            continue;
        }
        if (match_field(cursor, "AD", &value)) {
            free(ad);
            ad = NULL;
            ad_len = 0U;
            if (parse_hex_alloc(value, &ad, &ad_len) != 0) {
                fprintf(stderr, "Count %lu: invalid AD\n", count);
                fclose(fp);
                return 1;
            }
            continue;
        }
        if (match_field(cursor, "CT", &value)) {
            free(ct);
            ct = NULL;
            ct_len = 0U;
            if (parse_hex_alloc(value, &ct, &ct_len) != 0) {
                fprintf(stderr, "Count %lu: invalid CT\n", count);
                fclose(fp);
                return 1;
            }
            if (run_case(count, key, nonce, ad, ad_len, pt, pt_len, ct, ct_len) != 0) {
                fclose(fp);
                free(pt);
                free(ad);
                free(ct);
                return 1;
            }
            total++;
            continue;
        }
    }

    fclose(fp);
    free(pt);
    free(ad);
    free(ct);

    printf("Ascon-AEAD128 KATs passed: %lu\n", total);
    return 0;
}
