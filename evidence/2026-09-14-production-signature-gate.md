# macOS production signature gate evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: Broker/Edge LaunchAgent install-plan identity gating; no service mutation

## Decision

`buildMacOsInstallPlan` and `buildMacOsEdgeInstallPlan` now default to the
`developer-id` signature policy. The plan requires the exact component bundle
identifier, a 10-character Developer ID Team Identifier, and a bounded CDHash
before it can produce any install, upgrade, rollback, or uninstall actions.

The only exception is an explicit `development-ad-hoc` policy for temporary
host fixtures. That policy cannot carry enabled capabilities, so an ad-hoc
artifact cannot become a capability-bearing production installation through
this boundary.

## Verification

```text
npm run build
node --test packages/broker/dist/macos-install-plan.test.js
```

The focused install-plan suite passed 21/21. It covers missing Developer ID
identity, component identifier substitution, explicit ad-hoc development mode,
ad-hoc capability rejection, fixed `codesign` argv, signature details parsing,
and final signature/readback matching. A real temporary ad-hoc app bundle was
verified on macOS only under the explicit development policy.

## Boundary checks

- Production is the default when no signature policy is supplied.
- Broker and Edge signatures must use their exact component identifiers.
- Missing TeamIdentifier or CDHash fails before a plan can render a plist or
  expose launchd mutation actions.
- Development ad-hoc plans reject every enabled capability.
- Readback still requires the exact artifact path and every signature field
  present in the selected expectation.

## Limitations

This host has no production Developer ID certificate, notarized artifact, or
installed service authorization. The gate proves fail-closed plan construction
and temporary ad-hoc compatibility; it does not prove Apple signing,
notarization, launchd installation, or production identity provenance.
