# Root-helper snapshot plan CLI evidence

Date: 2026-09-22

## Result

The repository now provides a strict, non-executing root-helper plan compiler
and a separate explicit host-only apply handoff:

```text
npm run plan:root-helper -- --manifest <absolute-path>
npm run apply:root-helper -- --manifest <absolute-path> --confirm install
# use upgrade, rollback, or uninstall for those exact operations
```

The command accepts only an owner-only regular JSON manifest, delegates all
root-domain, native-artifact, socket-boundary, release-evidence, and rollback
validation to `buildRootHelperSnapshotPackagePlan`, and emits the exact
LaunchDaemon, plist digest, command, protected-path, socket, release-evidence,
and preflight summary. Its output always reports `apply.available: false`.
The apply handoff requires root, an exact operation confirmation, fixed package
commands, authenticated root-helper status readback for non-install
preconditions, and post-action readback or verified absence.
The service entrypoint binds its status metadata before startup; a configured
status socket without bound metadata fails closed.

The manifest contains paths and release metadata only; the command never reads
or prints helper private keys, HMAC material, attestation private material, or
other secret bytes.

## Verification

- `npm run build` passed.
- `node --check scripts/plan-root-helper-snapshot.mjs` passed.
- `node --check scripts/apply-root-helper-snapshot.mjs` passed.
- The root-helper package and status focused tests pass 14/14 across the
  package boundary and the authenticated status contract.
- A missing-manifest probe failed closed before importing or invoking a plan
  mutator.
- The package-plan tests verify that the compiler emits four distinct socket
  endpoints, including the separate root-helper status endpoint.
- The service/runtime/status integration slice passes 12/12, including the
  fail-closed check for an unbound status metadata socket and service-entrypoint
  metadata binding before startup.
- The current physical-Darwin native self-test passes with peer credentials,
  process identity, frame, and FD transfer verified; availability remains
  `false` and production serving remains disabled.
- The current physical-Darwin boundary probe passes while reporting the
  root-owned snapshot gate unavailable, server start `POLICY_DENIED`, and the
  public task scope disabled. This is the expected fail-closed result.
- The full regression reports 1,089 total, 1,074 passed, 15 skipped, and 0 failed.
- The compiler does not write `/Library/LaunchDaemons`, call `launchctl`,
  install a package, load key material, or change live R1/root-helper state.

## Remaining gates

This is a reproducible handoff artifact, not production installation evidence.
Developer ID/notarization, protected production material, root-domain apply and
rollback, live process/socket readback, Accessibility, and independent P0/P1
review remain open. The apply handoff was not run; no root-domain or live R1
state changed.
