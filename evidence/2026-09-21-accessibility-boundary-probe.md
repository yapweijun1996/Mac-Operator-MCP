# macOS Accessibility Boundary Probe Evidence

Date: 2026-09-21

Scope: MOP-103 / VT-UI-01 read-only Accessibility observation boundary.

## Physical-host result

The fixed probe targets only the running Finder bundle identity
`bundle:com.apple.finder`, requests at most 50 opaque nodes, and uses the
Broker-owned `MacUiInspectorImpl`. It accepts no JXA, window title, input text,
or action from the caller. It performs observation only.

Command:

```text
npm run build && npm run probe:accessibility
```

Observed output on the physical Darwin arm64 host:

```json
{
  "schemaVersion": "0.1",
  "mechanism": "macos-accessibility-boundary-v1",
  "targetApp": "bundle:com.apple.finder",
  "status": "permission-denied",
  "failClosed": true
}
```

The adapter returned the stable `POLICY_DENIED` result before publishing any
Accessibility tree data. No UI action, focus, typing, clipboard access, or
permission change was attempted.

## Boundary conclusion

This verifies the real host's missing-permission failure boundary and confirms
that GUI observation remains fail-closed. It does not prove granted
Accessibility observation, app/window target freshness under a real app, or
any UI mutation. The G1 profile and GUI scopes remain disabled until the owner
explicitly grants Accessibility permission and the permission-granted,
target-swap, sensitive-target, and rollback evidence is collected.

## Verification

- Native/TypeScript build passed before the probe.
- The fixed physical-host probe returned `permission-denied` with
  `failClosed: true`.
- No persistent host state was changed.

## Rollback

Rollback removes the probe script, package script, and this evidence. No
permission, OAuth grant, policy, or GUI state was changed.
