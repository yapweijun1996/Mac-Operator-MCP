# Replay Ledger Retention Rerun

Date: 2026-09-22T11:58:58Z

Scope: durable replay-ledger capacity, exact-expiry reclamation, and
fail-closed persisted-row validation for the Broker protocol channels.

Environment:

- Host: Darwin 25.2.0 arm64
- Node: v25.5.0
- Source revision: `540541cb44a290ea512070796004e9129ff0ab36`
- Worktree: dirty; this record describes the current source and generated test
  artifact, not a release commit

## Verification

Command:

```text
npm run build && node --test --test-timeout=120000 \
  packages/broker/dist/replay-capacity.test.js \
  packages/broker/dist/replay-row-invariants.test.js \
  packages/broker/dist/persistence.test.js
```

Result: **74 passed, 0 failed, 0 skipped**.

The rerun adds capacity/retention coverage for the policy-signer,
authority-control, Broker-status, virtualization-guest, Edge-revocation, and
approval-issuance ledgers. Each ledger is filled to the configured bound,
rejects a new admission while non-expired rows remain, and admits a new
identity exactly at the stored expiry boundary after transactional
reclamation. Approval issuance is exercised through the full
`issueAuthenticatedApproval()` validation and persistence path. Existing
request, privileged-helper, and Keychain-delivery capacity tests remain green.

The paired row-invariant suite continues to reject malformed persisted rows
for all nine replay-ledger families, including approval issuance. This is
local persistence evidence only: a production remote-issuer chain remains
open for `VT-AUTH-02`.

Artifact SHA-256:

```text
packages/broker/src/replay-capacity.test.ts
2d41d32e23eac7f2f91e400e0a54fc78f37af4c35d23ee03de691f879e61dea2

packages/broker/dist/replay-capacity.test.js
04fea9e6ead2d3ffdafc5ed364a82c959e623b8e27822664290c66acce14cb88

packages/broker/dist/persistence.js
1a6d4f8fb1490409a1c34247b381860abb6d0c8025955865f078ec6cf0dfb6b9
```

No live service, OAuth grant, Keychain item, launchd label, or host
permission was changed.
