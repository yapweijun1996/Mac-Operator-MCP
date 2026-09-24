# Broker signed launch-target binding

## Finding

The Broker install plan verified and assessed `signedArtifactPath`, but did not
require the LaunchAgent executable or JavaScript entrypoint to be part of that
artifact. A plan could therefore verify one bundle while launchd executed a
different file outside it. This also left the host executable that must carry
the Virtualization.framework entitlement ambiguous.

## Change

`buildMacOsInstallPlan` now rejects a Broker plan unless both `service.program`
and its JavaScript entrypoint are descendants of `signedArtifactPath`. The
Edge and Authority plan policies are unchanged. Broker test fixtures and the
declarative handoff fixture now model a signed app bundle containing
`Contents/MacOS/broker` and `Contents/Resources/runtime/service-entrypoint.js`.
The opt-in disposable LaunchAgent probe stages Node and its entrypoint in that
same bundle.

The entitlement remains a property of the unprivileged Broker executable that
hosts the native bridge; this change does not grant an entitlement to the root
helper or enable virtualization.

## Verification

- Focused install-plan and three-component handoff suites: 30 passed, 0 failed.
- Full repository regression: 1,196 passed, 16 skipped, 0 failed (1,212 total).
- Lint, documentation links, verification matrix, process-boundary audit, and
  `git diff --check` all pass; the process audit reports zero unreviewed
  entries.
- The macOS temporary-bundle test performed ad-hoc signing, strict signature
  verification, and identifier/CDHash readback successfully.
- The plan rejects an executable outside the signed artifact and, separately,
  an entrypoint outside the signed artifact.
- No production bundle was built or installed; no Developer ID signing,
  notarization, LaunchAgent bootstrap, VM boot, or capability enablement was
  performed.
- Overall completion remains 92% (2/29 PASS, 23 OPEN, 4 BLOCKED, 0 FAIL).
- The read-only completion audit exits fail-closed with `partial`: the host has
  no Developer ID identity, Accessibility authorization is denied, production
  LaunchAgent/LaunchDaemon labels are absent, and the protected production
  acceptance record is absent.
