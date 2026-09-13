# Installed Broker readback identity evidence

- Source commit: `9d90138`
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

The bounded launchd parser now extracts an optional `arguments = { ... }`
block. Broker installation composition requires that block to be present and
to match the exact planned Node binary plus JavaScript entrypoint; malformed,
oversized, incomplete, missing, or substituted argument lists fail closed.
Generic system-service readback remains compatible when launchd omits its
arguments block.

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
- Launchd parser and installer composition tests cover exact arguments and
  substitution rejection; the existing system-service smoke still passes.
- `git diff --check` — passed.

## Interpretation and limits

This is a repository-level contract and negative-boundary result. It does not
prove LaunchAgent installation/bootstrap, launchd process ownership on an
installed service, Developer ID signing, notarization, crash recovery, or
physical remount durability. Those remain release evidence requirements.

Source hashes at capture:

```text
3fb219cba3561b3bf1b1575d368522775781cc21a36773a7079db7ccd351e8ff  packages/broker/src/launchd.ts
c35742690b2c241e8fe1d1049df8a3bdaf9c14e584870b1b857ba2f4adbd66c9  packages/broker/src/launchd-readback.ts
4687e1c489938f7cc0da7a9e26f9506384d3ef9ced10f9e2d586268abebe6c46  packages/broker/src/launchd.test.ts
40037d48691afe653f0e009f65d8c3bb7c222b844f152987d54edc49307009e6  packages/broker/src/launchd-readback.test.ts
09af01924288f15462cc8e379c89c271182bb0232c64b8144be31205e68d5c41  packages/broker/src/macos-install-plan.ts
534a7bdf42908439d06d4905efb3141a9eef5ad560ec0cc3acbbe36cb98de25d  packages/broker/src/macos-install-plan.test.ts
```
