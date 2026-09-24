# Browser approval staging boundary evidence — 2026-09-22

## Result

The browser approval controller now has a real staging test against a durable
Broker preview, an activated temporary owner issuer key, and the separate
authenticated approval Unix socket. The live personal R1 deployment remains
unchanged and the approval issuer is not enabled there.

## Boundary covered

- The controller reads only the still-pending non-secret preview from
  `BrokerStore`.
- It requires exactly one active attended issuer key and derives a deterministic
  approval ID from the request ID.
- It sends the exact binding through `ApprovalIpcClient` to the separate
  approval channel and verifies the signed issuance response.
- It links the approval back to the durable preview as `issued`; the preview
  is no longer available for a second browser approval.
- A second issue attempt is rejected because the preview is no longer pending.
- The temporary key, socket, SQLite store, and runtime directory are removed
  during test cleanup.

## Verification

The focused test is:

```text
npm run build
node --test --test-timeout=120000 packages/auth/dist/personal-approval-browser-controller.test.js
```

Result: 1 test passed, 0 failed. The complete repository regression then
passed 1,052/1,067 tests with 15 explicit skips and 0 failures.

This closes the real staging controller-to-approval-IPC boundary only. Full
personal-supervisor child-process evidence, an explicitly enabled protected
issuer configuration, public OAuth/tools-list parity, ChatGPT mutation calls,
and production lifecycle/signing gates remain open by design.
