# Security Review Template

## Checklist
- [x] Official vectors pass for all AEAD cases.
- [x] Decrypt rejects invalid tags.
- [x] Tag compare is constant-time.
- [ ] No key/nonce-dependent branches in sensitive paths.
- [x] Nonce reuse risks documented in API docs.
- [ ] Sensitive buffers cleared where practical.

## Findings
- None recorded (as of vector validation). Remaining items are tracked in the checklist.
