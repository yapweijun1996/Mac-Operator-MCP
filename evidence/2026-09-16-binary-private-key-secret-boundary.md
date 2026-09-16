# Binary private-key secret boundary

Date: 2026-09-16

## Boundary

The content secret policy now rejects bounded DER private-key containers that
parse as PKCS#8, PKCS#1, or SEC1 keys, and the OpenSSH `openssh-key-v1` binary
envelope. The same detection is applied to bounded Base64 candidates used in
content and log redaction. Public SubjectPublicKeyInfo DER remains allowed.
Private-key parsing is capped at 128 KiB and Base64 candidates remain capped at
512 per value.

## Verification

Commands run on the physical Darwin host:

```text
npm run typecheck --silent
npm run build --silent
node --test packages/broker/dist/secret-policy.test.js
node --test packages/broker/dist/security-fuzz.test.js --test-name-pattern='secret|path'
npm run lint --silent
npm run verify:matrix --silent
npm run verify:docs --silent
```

Result: secret-policy 9/9 and focused security-fuzz 8/8 passed. The broader
Broker/ProcessSupervisor/task-profile/guest/Edge regression passed 209/209
with six explicit skips. The parser is conservative: it denies only a
validated private-key container or the fixed OpenSSH private-key envelope,
not arbitrary binary or public DER data.

