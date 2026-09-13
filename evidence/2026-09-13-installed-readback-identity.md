# Installed Broker readback identity evidence

- Source commit: `70ca1e9`
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

The composition now also requires a descriptor-backed `MacOsPlistReadback`
whose canonical path, device/inode, byte count, and SHA-256 match the exact
rendered plan. `readMacOsPlistReadback` reads through the protected filesystem
inspector, rejects target changes and truncation, and refuses tampered content.
The macOS `/var` to `/private/var` canonical-path projection is normalized
before comparison.

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
- The plist readback test verifies canonical identity/digest and rejects a
  tampered plist before it can join final service readback.
- `git diff --check` — passed.

## Interpretation and limits

This is a repository-level contract and negative-boundary result. It does not
prove LaunchAgent installation/bootstrap, launchd process ownership on an
installed service, Developer ID signing, notarization, crash recovery, or
physical remount durability. Those remain release evidence requirements.

Source hashes at capture:

```text
84929e6ee2ac1dd67c76128cecb56c39aa0c54f44a6a20dccb62959919dbe67b  packages/broker/src/macos-install-plan.ts
2ea379d46d28d25573c2eb0a3af8c1bf407fa4074cbce148dc5931aa3742305b  packages/broker/src/macos-install-plan.test.ts
```
