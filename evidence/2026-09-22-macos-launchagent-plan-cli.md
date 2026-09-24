# macOS LaunchAgent Plan CLI Evidence

Date: 2026-09-22

Status: `PASS` for the read-only two- and three-component deployment handoff;
production installation and persistent service enablement remain open.

Source revision: `540541c` plus the uncommitted working-tree changes recorded
in this evidence update. Target: macOS 26.2, Darwin arm64, owner UID 501.
Runtime: Node.js 25.5.0. Contract: `macos-launchagent-plan-v1`.

## Scope

`scripts/plan-macos-launchagents.mjs` is the declarative handoff for the
owner-domain Edge, Broker, and optional Authority LaunchAgent plans. It accepts
one canonical, owner-only regular JSON manifest and delegates component
validation to the existing plan builders, including
`buildMacOsAuthorityInstallPlan` when the Authority component is present.
The package command is:

```text
npm run plan:macos:launchagents -- --manifest /absolute/path/manifest.json
```

Development ad-hoc signatures require the explicit staging-only flag:

```text
npm run plan:macos:launchagents -- --manifest /absolute/path/manifest.json --development-probe
```

The command has no `--apply` implementation. It never writes a plist, calls
`launchctl`, installs a package, or changes service state. The output reports
`apply.available: false` and includes the exact component service IDs, plist
SHA-256 digests, launchd argv, signature policy, metadata, enabled
capabilities, and preflight data that a future host-owned installer must
review.

## Manifest boundary

The manifest is strict UTF-8 JSON, capped at 256 KiB, canonical absolute-path
addressed, owner-owned, and not group/other writable. The top-level schema is
`schemaVersion`, `operation`, `edge`, and `broker`, with an optional `authority`
component. Unknown top-level or component fields are rejected. All present
components must share the same UID, user-home, and install-root identity. The
Authority component requires exact `authorityConfigPath` and
`authorityOperatorSocketPath` fields and has no status-channel substitution.
The builder remains authoritative for service labels, user-domain plist paths,
package roots, entrypoints, signature policy, and capability constraints.

## Verification

The positive probe used a disposable owner-only two-component manifest with
`operation: install`, matching owner/install identity, valid Edge listener
fields, zero enabled capabilities, and explicit `development-ad-hoc` signatures
under `--development-probe`. It emitted:

```text
mechanism=macos-launchagent-plan-v1
mode=read-only-plan
components=gui/501/com.mac-operator.edge,gui/501/com.mac-operator.broker
apply.available=false
```

Negative probes verified that:

- ad-hoc planning without `--development-probe` is rejected;
- an unknown manifest field is rejected;
- an unsupported `--apply` flag is rejected by the usage gate.

The positive and negative probes completed without changing launchd, plist,
package, Keychain, or live R1 state. Production planning remains fail-closed
until the exact signed/notarized release evidence is available. Applying a
plan remains a separate future host-owned boundary requiring authenticated
component status readback, explicit confirmation, rollback authority, and
postcondition verification.

Follow-up smoke coverage now runs the plan compiler as a real child process
with a disposable three-component manifest. It verifies emitted order
`Authority -> Edge -> Broker`, all three component identities, `apply.available:
false`, and rejection when `authorityOperatorSocketPath` is missing. Separate
apply-handoff smoke coverage runs the apply CLI as a real child process and
verifies ad-hoc release rejection before runtime import plus duplicate
Authority socket-alias rejection. The plan tests pass 2/2 and the apply tests
pass 2/2; no live service state changed.

## Reproduction

```text
node --check scripts/plan-macos-launchagents.mjs
npm run plan:macos:launchagents -- --manifest /absolute/path/manifest.json --development-probe
```
