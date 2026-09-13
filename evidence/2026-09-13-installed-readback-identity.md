# Installed Broker readback identity evidence

- Source commit: `4cb4e1a`
- Working tree: clean before this evidence document update
- Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
- Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Contract/policy: tool contracts `0.1`; Broker policy fixtures `policy-0.1`
- Scope: installer post-bootstrap validation only; no LaunchAgent installation,
  bootstrap, privilege escalation, credential access, or external network

## Implemented boundary

`MacOsInstallReadback` now requires a positive launchd PID and a native
`PeerProcessIdentity` containing the same PID and a positive start-time
identity. `validateMacOsInstallReadback` rejects missing, malformed, mismatched,
or non-positive identities before an install/upgrade/rollback result can be
reported as ready. This prevents a readback that merely says Broker is running
from silently accepting a missing PID or a PID-reuse/target-substitution
identity supplied by the host composition layer.

`composeMacOsInstallReadback` now binds the parsed launchd service ID, per-user
domain, LaunchAgent type, running state, PID, program path, and plist path to
the native identity before validating Broker metadata and code-signature
readback. It does not manufacture a launchd observation: the caller must supply
the bounded `LaunchdJobReadback` produced by the fixed `launchctl print`
adapter.

The caller remains responsible for obtaining the identity through the native
macOS process observer (for example, `capturePeerProcessIdentity`) after
launchd supplies the PID. The repository does not claim installed-service
evidence until a real host installer composes that native readback and performs
the final launchd/Broker/signature verification.

## Verification

- `npm run typecheck` — passed.
- `npm test` — 395 tests, 392 passed, 3 opt-in sandbox tests skipped.
- Focused install-plan tests reject PID mismatch, missing identity, invalid
  start-time values, and substituted launchd service identities while accepting
  a matching PID/start-time pair.
- `git diff --check` — passed.

## Interpretation and limits

This is a repository-level contract and negative-boundary result. It does not
prove LaunchAgent installation/bootstrap, launchd process ownership on an
installed service, Developer ID signing, notarization, crash recovery, or
physical remount durability. Those remain release evidence requirements.

Source hashes at capture:

```text
b2579e109241374780090bbf70ed7c7acd33ce2a08fe0fb8c4e4a6b3dc28c0d0  packages/broker/src/macos-install-plan.ts
06e25e462197e918d6bb33828fcafc60ed0a04d9a72f74049b87ebb636a25629  packages/broker/src/macos-install-plan.test.ts
```
