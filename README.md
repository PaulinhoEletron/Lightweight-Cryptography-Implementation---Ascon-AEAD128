# Lightweight Cryptography Implementation - Ascon-AEAD128

Implementation of Ascon-AEAD128 per NIST SP 800-232, with conformance vectors and a minimal C API for integration into larger systems.

## Build
```bash
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Usage (API)
Public API header: `include/ascon_api.h`

```c
#include "ascon_api.h"

int rc = ascon128_encrypt(
    ciphertext,
    tag,
    key,
    nonce,
    ad,
    ad_len,
    plaintext,
    pt_len
);
```

```c
int rc = ascon128_decrypt(
    plaintext,
    tag,
    key,
    nonce,
    ad,
    ad_len,
    ciphertext,
    ct_len
);
```

## Demo
```bash
cmake -S . -B build
cmake --build build
./build/demo_aead128
```
Source: `examples/demo_aead128.c`

## Structure
- `include/` public headers
- `src/` implementation files
- `tests/` unit and vector tests
- `vectors/` conformance vectors
- `examples/` usage examples
- `docs/` design and security notes

## Conformance
- Official Ascon-AEAD128 KATs pass (1089 vectors).

## Security Notes
- Nonce must be unique per key; nonce reuse breaks confidentiality.
- Tag verification is constant-time.
- No secure zeroization of key material is currently performed.

## Credits
- NIST SP 800-232 Ascon-Based Lightweight Cryptography (Aug 2025).
- Ascon reference implementation (vector source).
# Lightweight-Cryptography-Implementation---Ascon-AEAD128
