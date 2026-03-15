#include "../include/ascon_permutation.h"

#include <assert.h>

static void test_zero_state(void)
{
    ascon_state_t s = {0U, 0U, 0U, 0U, 0U};

    ascon_permute12(&s);
    ascon_permute8(&s);

    assert(s.x0 == 0xa0e7ca6993d4f09bULL);
    assert(s.x1 == 0x7b69157d1925064bULL);
    assert(s.x2 == 0xc9cbd355a5f88808ULL);
    assert(s.x3 == 0x5a45bb795b3b2e14ULL);
    assert(s.x4 == 0x9dbe2674999cb1c6ULL);
}

static void test_patterned_state(void)
{
    ascon_state_t s = {
        0x0123456789abcdefULL,
        0xfedcba9876543210ULL,
        0x0f1e2d3c4b5a6978ULL,
        0x8877665544332211ULL,
        0x1122334455667788ULL,
    };

    ascon_permute12(&s);

    assert(s.x0 == 0x44586ae53169ed5bULL);
    assert(s.x1 == 0x3ac4014444089683ULL);
    assert(s.x2 == 0xacca3f44b90c67b1ULL);
    assert(s.x3 == 0x699bc66dffd029beULL);
    assert(s.x4 == 0x24d8073af44ed8b9ULL);
}

int main(void)
{
    test_zero_state();
    test_patterned_state();
    return 0;
}
