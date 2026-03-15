## Ascon128 Implementation Task Board

### Scope
- Standard target: NIST SP 800-232 (August 2025)
- Primary primitive in this phase: Ascon-AEAD128
- Language baseline: C99

### Team Allocation
1. Junior Agent 1 (`J1`) - Permutation Core
2. Junior Agent 2 (`J2`) - AEAD128 Core Flow
3. Junior Agent 3 (`J3`) - Encoding, API, and Input Validation
4. Security/Test Agent (`QA-Sec`) - Conformance, fuzzing, and side-channel checks
5. Architect (`Lead`) - Integration, design review, release gate

### Milestones
1. M1: Interfaces frozen
2. M2: Unit tests green per module
3. M3: Integration tests green
4. M4: Security review complete and issues closed

### Work Breakdown (Equalized for Juniors)
#### J1 - Permutation Core
- **Files owned**:
  - `include/ascon_permutation.h`
  - `src/ascon_permutation.c`
  - `tests/test_permutation.c`
- **Responsibilities**:
  - Implement state as five 64-bit words.
  - Implement `ascon_permute12()` and `ascon_permute8()`.
  - Implement constant-addition, substitution, and linear diffusion layers.
  - Add deterministic round-level tests (smoke + known vectors when available).
- **Acceptance criteria**:
  - Builds with no warnings under `-Wall -Wextra -Wpedantic`.
  - `tests/test_permutation.c` passes.
  - Public API matches header contract.

#### J2 - AEAD128 Core Flow
- **Files owned**:
  - `include/ascon_aead128.h`
  - `src/ascon_aead128.c`
  - `tests/test_aead128.c`
- **Responsibilities**:
  - Implement encrypt/decrypt flow per SP 800-232 Section 4.1.
  - Use permutation APIs from J1 only (no duplicated permutation code).
  - Handle empty AD, empty message, and partial final blocks correctly.
  - Enforce constant-time tag verification path.
- **Acceptance criteria**:
  - Encrypt/decrypt roundtrip tests pass.
  - Tag mismatch must fail cleanly.
  - Tests include empty/short/multi-block AD and plaintext cases.

#### J3 - Encoding/API/Input Validation
- **Files owned**:
  - `include/ascon_bytes.h`
  - `src/ascon_bytes.c`
  - `include/ascon_api.h`
  - `src/ascon_api.c`
  - `tests/test_bytes_api.c`
- **Responsibilities**:
  - Implement endian-safe load/store helpers and padding helpers.
  - Implement stable top-level API wrappers and argument validation.
  - Define and document error codes for invalid inputs and auth failures.
  - Keep API documentation synced with behavior.
- **Acceptance criteria**:
  - Conversion utility tests pass.
  - API returns deterministic status codes.
  - Null-pointer/length edge cases are covered by tests.

### Security/Test Agent (QA-Sec)
- **Files owned**:
  - `tests/test_vectors.c`
  - `tests/test_fuzz_harness.c`
  - `docs/SECURITY_REVIEW.md`
- **Responsibilities**:
  - Validate implementation with official/known-good vectors in `vectors/`.
  - Build differential tests against a trusted reference.
  - Add malformed-input and mutation tests.
  - Review constant-time behavior for tag compare and sensitive data handling.
  - Output severity-ranked findings and remediation guidance.
- **Exit criteria**:
  - All conformance vectors pass.
  - No open high-severity issues.

### Architect (Lead)
- **Files owned**:
  - `docs/ARCHITECTURE.md`
  - `README.md`
- **Responsibilities**:
  - Freeze interfaces and coding standards.
  - Review module boundaries and dependency direction.
  - Integrate and maintain CI build/test commands.
  - Approve release only when M1-M4 are complete.

### Dependency Graph
1. `J1` can start immediately.
2. `J3` can start immediately.
3. `J2` starts with stub permutation calls, then binds to J1 finalized interface.
4. `QA-Sec` starts once J2 has functional encrypt/decrypt and basic vectors.

### Definition of Done (Project)
- AEAD128 implementation matches SP 800-232 behavior.
- Unit/integration/vector/fuzz tests pass.
- Security review completed with documented residual risks.
- Public API documented and stable.
# Ascon128 Implementation Task Board

## Scope
- Standard target: NIST SP 800-232 (August 2025)
- Primary primitive in this phase: Ascon-AEAD128
- Language baseline: C99

## Team Allocation
1. Junior Agent 1 (`J1`) - Permutation Core
2. Junior Agent 2 (`J2`) - AEAD128 Core Flow
3. Junior Agent 3 (`J3`) - Encoding, API, and Input Validation
4. Security/Test Agent (`QA-Sec`) - Conformance, fuzzing, and side-channel checks
5. Architect (`Lead`) - Integration, design review, release gate

## Milestones
1. M1: Interfaces frozen
2. M2: Unit tests green per module
3. M3: Integration tests green
4. M4: Security review complete and issues closed

## Work Breakdown (Equalized for Juniors)
### J1 - Permutation Core
- Files owned:
- `include/ascon_permutation.h`
- `src/ascon_permutation.c`
- `tests/test_permutation.c`
- Responsibilities:
- Implement state as five 64-bit words.
- Implement `ascon_permute12()` and `ascon_permute8()`.
- Implement constant-addition, substitution, and linear diffusion layers.
- Add deterministic round-level tests (smoke + known vectors when available).
- Acceptance criteria:
- Builds with no warnings under `-Wall -Wextra -Wpedantic`.
- `tests/test_permutation.c` passes.
- Public API matches header contract.

### J2 - AEAD128 Core Flow
- Files owned:
- `include/ascon_aead128.h`
- `src/ascon_aead128.c`
- `tests/test_aead128.c`
- Responsibilities:
- Implement encrypt/decrypt flow per SP 800-232 Section 4.1.
- Use permutation APIs from J1 only (no duplicated permutation code).
- Handle empty AD, empty message, and partial final blocks correctly.
- Enforce constant-time tag verification path.
- Acceptance criteria:
- Encrypt/decrypt roundtrip tests pass.
- Tag mismatch must fail cleanly.
- Tests include empty/short/multi-block AD and plaintext cases.

### J3 - Encoding/API/Input Validation
- Files owned:
- `include/ascon_bytes.h`
- `src/ascon_bytes.c`
- `include/ascon_api.h`
- `src/ascon_api.c`
- `tests/test_bytes_api.c`
- Responsibilities:
- Implement endian-safe load/store helpers and padding helpers.
- Implement stable top-level API wrappers and argument validation.
- Define and document error codes for invalid inputs and auth failures.
- Keep API documentation synced with behavior.
- Acceptance criteria:
- Conversion utility tests pass.
- API returns deterministic status codes.
- Null-pointer/length edge cases are covered by tests.

## Security/Test Agent (QA-Sec)
- Files owned:
- `tests/test_vectors.c`
- `tests/test_fuzz_harness.c`
- `docs/SECURITY_REVIEW.md`
- Responsibilities:
- Validate implementation with official/known-good vectors in `vectors/`.
- Build differential tests against a trusted reference.
- Add malformed-input and mutation tests.
- Review constant-time behavior for tag compare and sensitive data handling.
- Output severity-ranked findings and remediation guidance.
- Exit criteria:
- All conformance vectors pass.
- No open high-severity issues.

## Architect (Lead)
- Files owned:
- `docs/ARCHITECTURE.md`
- `README.md`
- Responsibilities:
- Freeze interfaces and coding standards.
- Review module boundaries and dependency direction.
- Integrate and maintain CI build/test commands.
- Approve release only when M1-M4 are complete.

## Dependency Graph
1. `J1` can start immediately.
2. `J3` can start immediately.
3. `J2` starts with stub permutation calls, then binds to J1 finalized interface.
4. `QA-Sec` starts once J2 has functional encrypt/decrypt and basic vectors.

## Definition of Done (Project)
- AEAD128 implementation matches SP 800-232 behavior.
- Unit/integration/vector/fuzz tests pass.
- Security review completed with documented residual risks.
- Public API documented and stable.
