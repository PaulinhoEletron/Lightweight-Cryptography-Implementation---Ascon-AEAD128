#ifndef ASCON_PERMUTATION_H
#define ASCON_PERMUTATION_H

#include <stdint.h>

typedef struct {
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
} ascon_state_t;

void ascon_permute12(ascon_state_t *s);
void ascon_permute8(ascon_state_t *s);

#endif
