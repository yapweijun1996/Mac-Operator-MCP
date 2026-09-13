# Secret-zone and evidence redaction hardening

Status: PASS for the fixed path/signature redaction slice; VT-SEC-01 and
VT-SEC-02 remain OPEN for the broader secret corpus and release gate.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Source commit: `0bcd893409bb07ad274fe61b704f00da2256b115`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: none; no credential or private-data content was opened

## Boundary changes

The Broker secret policy now denies additional fixed zones before content I/O:

- all `.docker` metadata, not only `.docker/config.json`;
- GitHub CLI `.config/gh` state;
- Brave, Microsoft Edge, and Google Chrome application data;
- containerized macOS Mail, Messages, and Safari data;
- `/private/var/root` and `/private/Users` forms in evidence-path redaction.

Content and log evidence also rejects or redacts Bearer tokens, Basic
credentials, JWT-shaped values, cloud/API/GitHub/OpenAI/Slack tokens, private
keys, credential assignments, and protected paths containing spaces such as
`Library/Application Support/Google/Chrome/...`. Redaction remains bounded by
the existing UTF-8 byte cap.

## Verification

- Focused policy tests: `node --test packages/broker/dist/secret-policy.test.js` — 4/4 passed.
- Default full suite: `npm test` — 362 tests, 360 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 362/362 passed, 0 skipped.
- Type/build: `npm run typecheck -- --pretty false` and `npm run build` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary negatives cover case/Unicode-normalized path zones, protected paths
  with spaces, private-root path forms, Bearer/Basic/JWT values, and bounded
  UTF-8 redaction. Tests use synthetic strings only.

## Source hashes

```text
2bf7242d18ce2b6ec86e604340e58e1594a5e877e4788e97019b92cf126b0dd6  packages/broker/src/secret-policy.ts
82c3be20ba7790e4b4d8f5fdc78174ded7af9ebcb5a2dc448072a7ff4838c2f4  packages/broker/src/secret-policy.test.ts
```

## Remaining limits

This does not prove complete credential-store coverage, split/binary encodings,
false-positive analysis, removable-volume behavior, configurable operator
classification, or audit retention/access control. Protected content remains
unreadable by default; no new tool or capability was enabled.
