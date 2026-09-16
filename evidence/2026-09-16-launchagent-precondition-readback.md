# Evidence: LaunchAgent Precondition Readback

Date: 2026-09-16
Scope: Broker and HTTPS Edge macOS LaunchAgent install-plan executors

## Implemented boundary

- `createMacOsExistingServiceReader` derives the precondition from a
  host-owned Launchd observer rather than trusting a caller-supplied snapshot.
- The observer requests the exact `gui/<uid>/<label>` identity and rejects a
  missing or conflicting service ID, domain, label, `LaunchAgent` type,
  program, argument vector, plist path, or truncated readback.
- Install accepts only an absent service. Upgrade, rollback, and uninstall
  require a present service and read the prior source revision from the
  authenticated Broker or Edge runtime channel.
- `readMacOsExistingServiceSnapshot` samples the host source twice and fails
  closed on malformed data or any state/revision change.
- Host-observer factories assemble these readers from the same bounded Launchd
  adapter and authenticated Broker/Edge status source used for final readback.
- The executor checks the host-owned sample before signature verification,
  plist mutation, or `launchctl` transition. An optional caller snapshot is a
  consistency hint and cannot authorize the operation.

## Verification

- `npm run typecheck --silent`: passed.
- `npm run build --silent`: passed.
- `node --test packages/broker/dist/macos-install-plan.test.js`: 24 passed,
  0 failed.
- `node --test packages/broker/dist/privileged-helper-package.test.js`: 20
  passed, 0 failed.
- `npm test --silent`: 877 tests, 863 passed, 14 skipped, 0 failed.
- The focused suite covers absent services, exact LaunchAgent identity,
  target substitution, prior revision readback, observer failures, and
  double-sample drift.

## Host evidence and limits

No real LaunchAgent was installed, bootstrapped, stopped, or removed during
this verification. The tests use bounded command/readback seams. Physical-Mac
launchd ownership, signed production packaging, and live upgrade/rollback
evidence remain open.

## Rollback

Revert the local commit containing this change. No persistent host state was
created or changed by the tests.
