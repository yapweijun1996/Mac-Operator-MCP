# Privileged Helper Response-Schema Evidence

- Date: 2026-09-16
- Host: physical macOS host used by the repository test harness
- Source revision: `cd80e0d`
- Contract/policy versions: 0.1
- Evidence class: local and physical privileged-helper boundary regression

## Decision

Treat every privileged-helper response as a versioned data envelope with an
exact field set. Unknown top-level or nested fields are rejected after
authentication, so an authenticated helper cannot smuggle ungoverned control
or evidence data across the Broker boundary.

## Implemented controls

`validatePrivilegedHelperExecutionResult` now requires the exact result fields
and an exact verification record with only the documented optional summary and
readback hash. `authenticatePrivilegedHelperResponse` and
`authenticatePrivilegedHelperStatusResponse` require response-shape-specific
top-level fields, exact failure records, bounded error messages, and the
existing HMAC identity/proof checks. The response validators continue to
reject accessors, inherited records, raw execution fields, and unsupported
result classes.

## Verification

Focused command:

```text
npm run build
node --test --test-concurrency=1 packages/broker/dist/privileged-helper.test.js
npm run lint
npm run typecheck
git diff --check
```

Result: 15/15 privileged-helper tests passed, with no skips or failures.

The serial physical regression ran with install, sandbox, and Keychain opt-ins
and passed 640/640 tests, with zero skips and failures. The pre-existing
long-running Broker, persistence, and privileged-helper IPC suites were
excluded and left undisturbed. Run log: `/tmp/mops-helper-response-schema-physical-regression.log`.

Artifact SHA-256:

```text
packages/broker/src/privileged-helper.ts
a5575cace5bebc9f821aed7e79e9b984df33b1d2b207bf555135f542116eec47
packages/broker/src/privileged-helper.test.ts
f1bf4dd3c132af08c0237255aebb960c48aa858ad25aad4a4901dda8ee4e22ea
```

## Boundary status

This closes the response-schema and nested failure-record omission for the
implemented helper IPC contract. It does not enable the helper, prove
production Developer ID/root-domain installation, establish real privileged
adapters, or close the remaining independent-review and host-evidence gates.
