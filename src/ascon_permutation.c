#include "../include/ascon_permutation.h"

#include <stddef.h>

static inline uint64_t ascon_rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64U - n));
}

static void ascon_round(ascon_state_t *s, uint8_t rc)
{
    uint64_t x0 = s->x0;
    uint64_t x1 = s->x1;
    uint64_t x2 = s->x2;
    uint64_t x3 = s->x3;
    uint64_t x4 = s->x4;
    uint64_t t0, t1, t2, t3, t4;

    /* pC: add round constant */
    x2 ^= (uint64_t)rc;

    /* pS: substitution layer (5-bit S-box, bit-sliced) */
    x0 ^= x4;
    x4 ^= x3;
    x2 ^= x1;

    t4 = x0 & ~x4;
    t3 = x4 & ~x3;
    t2 = x3 & ~x2;
    t1 = x2 & ~x1;
    t0 = x1 & ~x0;

    x0 ^= t1;
    x1 ^= t2;
    x2 ^= t3;
    x3 ^= t4;
    x4 ^= t0;

    x1 ^= x0;
    x0 ^= x4;
    x3 ^= x2;
    x2 = ~x2;

    /* pL: linear diffusion layer */
    x0 ^= ascon_rotr64(x0, 19) ^ ascon_rotr64(x0, 28);
    x1 ^= ascon_rotr64(x1, 61) ^ ascon_rotr64(x1, 39);
    x2 ^= ascon_rotr64(x2, 1) ^ ascon_rotr64(x2, 6);
    x3 ^= ascon_rotr64(x3, 10) ^ ascon_rotr64(x3, 17);
    x4 ^= ascon_rotr64(x4, 7) ^ ascon_rotr64(x4, 41);

    s->x0 = x0;
    s->x1 = x1;
    s->x2 = x2;
    s->x3 = x3;
    s->x4 = x4;
}

static void ascon_permute(ascon_state_t *s, uint8_t rounds) {
    static const uint8_t round_constants[12] = {
        0xf0, 0xe1, 0xd2, 0xc3,
        0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b,
    };
    uint8_t start = (uint8_t)(12U - rounds);
    uint8_t i;

    for (i = start; i < 12U; i++) {
        ascon_round(s, round_constants[i]);
    }
}

void ascon_permute12(ascon_state_t *s) {
    ascon_permute(s, 12U);
}

void ascon_permute8(ascon_state_t *s) {
    ascon_permute(s, 8U);
}
