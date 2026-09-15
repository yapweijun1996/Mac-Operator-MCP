# Guest Admission Evidence Snapshot

Date: 2026-09-16
Status: implemented and locally verified; virtualization capability remains disabled unless the existing host gates and native evidence are enabled
Source revision: `b726d692377297b3f4dec933615d4c8a14eeeaa1`

## Boundary

`VirtualizationGuestTransportExecutor` now recursively freezes the bounded
`VirtualizationGuestTaskAdmission` snapshot before delivering it to the Broker
Job persistence callback. Request ID, nonce, request digest, guest identity,
profile/task digests, and resource budgets therefore cannot be rewritten by a
callback before they are recorded as the Job's admitted guest request.

This is an in-process evidence-handoff boundary. It does not claim native
Virtualization.framework isolation, signed-attestation enablement, or
production virtualization capability.

## Host and source evidence

- Host: macOS Darwin 25.2.0 arm64, macOS 26.2 build 25C56.
- Source SHA-256: `6439d0e2728a44295f45fb9e9a550f618fe042b7e126d7f7cf6e18a7f52dd2e2` (`packages/broker/src/task-runner.ts`).
- Test SHA-256: `88ccc570731ac4045dfaffd356b87205c5bd4c82ad38033441b0e7909a647602` (`packages/broker/src/task-runner.test.ts`).
- Working tree was clean after the source commit before this evidence addendum.

## Verification

Focused Guest/Runner/Agent suites:

```text
node --test packages/broker/dist/task-runner.test.js \
  packages/broker/dist/virtualization-guest-agent.test.js
17 tests, 17 passed, 0 failed, 0 skipped
```

The transport test proves the admission object and nested guest identity are
frozen and that a runtime request-ID mutation raises `TypeError`; digest and
response-binding checks remain unchanged.

Repository checks:

```text
npm run build
npm run typecheck
npm run lint
git diff --check
```

All passed. The serial physical regression (with the three pre-existing
long-running suites excluded and left untouched) passed:

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
node --test --test-concurrency=1 $(find packages -path '*/dist/*.test.js' \
  ! -name 'broker.test.js' ! -name 'persistence.test.js' \
  ! -name 'privileged-helper-authority-ipc.test.js' | sort)
671 tests, 666 passed, 0 failed, 5 skipped
```

The five skips are the explicit descriptor-capability tests already documented
as unavailable without the native launcher boundary.

## Rollback

Revert source revision `b726d69` to restore the previous admission callback
handoff, then rerun the focused Guest suites and serial regression. No host
files, Job state, credentials, or virtualization capability enablement were
changed.
