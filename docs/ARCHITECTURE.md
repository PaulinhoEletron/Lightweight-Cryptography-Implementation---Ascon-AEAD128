# Architecture Notes

## Layers
1. `ascon_permutation` - core 320-bit permutation logic.
2. `ascon_aead128` - AEAD mode orchestration (init, absorb, squeeze/finalize).
3. `ascon_bytes` - conversion and padding helpers.
4. `ascon_api` - stable external API boundary.

## Rules
- No duplication of permutation logic outside `ascon_permutation.c`.
- `ascon_aead128` uses helpers from `ascon_bytes` and permutation only.
- Constant-time comparisons for authentication checks.
- Public headers in `include/`, internal helpers `static` in `.c` files.

## Coding Standard
- C99, `-Wall -Wextra -Wpedantic -Werror`.
- Small functions with single-responsibility.
- Explicit integer widths for crypto-critical code.
