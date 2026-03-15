#include "ascon_bytes.h"

#include <stddef.h>
#include <stdint.h>

uint64_t ascon_load64_le(const uint8_t in[8]) {
    uint64_t x = 0U;
    size_t i;
    for (i = 0U; i < 8U; i++) {
        x |= ((uint64_t)in[i]) << (8U * i);
    }
    return x;
}

void ascon_store64_le(uint8_t out[8], uint64_t x) {
    size_t i;
    for (i = 0U; i < 8U; i++) {
        out[i] = (uint8_t)(x & 0xffU);
        x >>= 8;
    }
}

void ascon_pad_block(uint8_t *block, size_t used, size_t block_size) {
    size_t i;
    if (block == NULL || used >= block_size) {
        return;
    }
    block[used] = 0x01U;
    for (i = used + 1U; i < block_size; i++) {
        block[i] = 0U;
    }
}
