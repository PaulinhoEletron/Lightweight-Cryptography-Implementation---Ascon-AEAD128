#ifndef ASCON_BYTES_H
#define ASCON_BYTES_H

#include <stddef.h>
#include <stdint.h>

uint64_t ascon_load64_le(const uint8_t in[8]);
void ascon_store64_le(uint8_t out[8], uint64_t x);
void ascon_pad_block(uint8_t *block, size_t used, size_t block_size);

#endif
