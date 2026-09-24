# Current Host Release and GUI Readiness Evidence

Date: 2026-09-22

Scope: production release, persistent service identity, and G1 Accessibility
readiness gates for the physical Darwin arm64 host.

## Read-only host result

Host identity:

```text
Darwin arm64, macOS 26.2, uid 501
```

Code-signing and Gatekeeper checks:

```text
security find-identity -v -p codesigning
0 valid identities found

spctl --status
assessments enabled
```

Gatekeeper being enabled does not prove a Developer ID or notarized artifact.
The production release gate therefore remains unavailable and fail-closed.

Accessibility boundary:

```json
{
  "mechanism": "macos-accessibility-boundary-v1",
  "targetApp": "bundle:com.apple.finder",
  "status": "permission-denied",
  "failClosed": true
}
```

No Accessibility permission was changed, and no GUI action or sensitive UI
data was accessed.

Persistent service readback:

```text
gui/501/com.mac-operator.edge                  absent
gui/501/com.mac-operator.broker                absent
gui/501/com.mac-operator.root-helper-snapshot   absent
personal PM2 service                            online, 0 restarts
```

The existing personal R1 service remains the separate PM2 snapshot deployment;
the absent LaunchAgent labels do not represent a failed rollback.

## Boundary conclusion

The next release/GUI actions require external state: a valid Developer ID
identity with notarization credentials and explicit owner-granted Accessibility
permission. This evidence does not authorize either change and does not enable
D1, G1, P1, a root helper, or persistent LaunchAgents.

## Verification

- The reproducible read-only gate is `npm run probe:host-readiness`. It emits
  schema `macos-host-readiness-v1` and exits non-zero while any release, GUI,
  or persistent-install prerequisite is missing.
- The current run exited with status `1` and reported `readyForRelease=false`,
  `readyForGui=false`, and `persistentServiceVerified=false`; it observed zero
  valid identities, `permission-denied` Accessibility, and all three target
  launchd labels absent.
- `npm run probe:accessibility` returned `permission-denied` with
  `failClosed: true`.
- `security find-identity -v -p codesigning` returned zero valid identities.
- `/usr/sbin/spctl --status` reported assessments enabled.
- `launchctl print` found none of the target service labels.
- PM2 readback reported the personal deployment online with zero restarts.
- All checks were read-only.

## Rollback

No rollback is required. No permission, certificate, service label, OAuth
grant, policy, or persistent host configuration was changed.
