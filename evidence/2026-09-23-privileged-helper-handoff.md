# Privileged Helper Handoff Boundary

Date: 2026-09-23

Status: PASS for the local plan/apply handoff contract; root-domain
installation, Developer ID/notarization, Keychain provisioning, live service
readback, and capability enablement remain host-gated.

## Implemented boundary

- `plan:privileged-helper` accepts one owner-only strict manifest and emits a
  bounded, read-only plan for the exact
  `system/com.mac-operator.privileged-helper` LaunchDaemon.
- The manifest is identity-checked before and after reading, allows only the
  package-plan fields, and cannot select a user-domain service, shell,
  interpreter, arbitrary argv, or a reused helper/Broker/authority socket.
- `apply:privileged-helper` is a separate host-only command. It requires the
  exact operation confirmation and a root process before any host mutation,
  loads the protected helper key, and uses the existing package executor.
- Apply verifies the existing service twice, signs/notarizes before the plist
  write, uses the descriptor-relative plist writer, executes fixed `launchctl`
  commands, performs authenticated helper status/readback, and invokes the
  existing inverse recovery path on failure.
- The package plan still requires an explicit host-verified capability release;
  no privileged capability is enabled by this handoff by default.

## Verification

- The plan CLI smoke emits a read-only root-domain plan and rejects an
  unsupported manifest field.
- The apply CLI refuses a non-root caller before host mutation.
- `npm run build`, `npm run typecheck`, `npm run lint`, and the full repository
  regression pass after this change: 1,164 total, 1,149 passed, 15 skipped,
  and 0 failed. The apply command itself is not run.

## Remaining limits

This evidence is a code and disposable-manifest boundary, not proof of a real
root LaunchDaemon, Developer ID identity, notarization, protected Keychain
ACL, native helper transport, or enabled privileged adapter. Those remain
open under `VT-PRIV-01`, `VT-PKG-01`, and the production acceptance gate.

## Rollback

Remove the two CLI entrypoints and their package scripts together. The existing
privileged-helper package APIs remain independently testable and no host state
is changed by the read-only plan command.
