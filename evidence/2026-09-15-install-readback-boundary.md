# macOS Install Readback Boundary Evidence

Date: 2026-09-15
Source revision: `61e7357`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:47:37Z
Artifact hashes: `packages/broker/src/macos-install-plan.ts` SHA-256
`c841070509589fb6eeefaa6f4347058bd4977d91752296c0162d64b1cc62b699`;
`packages/broker/src/macos-install-plan.test.ts` SHA-256
`3d6f03f82fd7bdded600a0a90cb4c8882f2088534bc638a11b6d4fb276690d91`.

## Decision

Launchd, process, plist, Broker, Edge, and signature observations are
independent authority inputs for install readback. They must be plain data
records before service identity, code identity, or capability readback is
accepted.

## Implemented controls

- Install-plan readback and source-shape checks now reject inherited,
  accessor, symbolic, and non-record observations before nested validation.
- Existing-service preconditions, component readbacks, and code-signature
  expectations share the same data-only boundary without changing fixed
  command arguments or operation confirmation requirements.
- Final readback still composes only independent launchd/native/plist/
  Broker/signature observations and retains exact PID/start-time, artifact,
  policy, and capability matching.

## Verification

Focused command:

```text
npm run build && node --test packages/broker/dist/macos-install-plan.test.js
```

Result: 22 tests passed, 0 failed, 0 skipped. Hostile inherited/accessor
readback fixtures fail with stable `INVALID_READBACK`; existing install,
upgrade, rollback, uninstall, signature, and real temporary artifact tests
remain green.

## Boundary status

This proves local install-readback representation integrity only. It does not
prove Developer ID provenance, persistent installed-service lifecycle,
upgrade/rollback on a production host, root-domain helper execution, or final
capability enablement. Those gates remain fail-closed and incomplete.
