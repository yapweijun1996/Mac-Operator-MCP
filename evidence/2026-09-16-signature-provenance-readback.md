# Signature provenance readback evidence

Date: 2026-09-16
Host: physical Darwin arm64 development host
Scope: macOS Broker/Edge package plans and separately packaged privileged helper

## Change

The shared `codesign -dv --verbose=4` readback parser now classifies the
artifact provenance as either `developer-id` or `development-ad-hoc`. A
Developer ID result must expose a `Developer ID Application: <name> (<TeamID>)`
authority whose Team ID exactly matches `TeamIdentifier`, and it must include a
bounded CDHash. An ad-hoc result is accepted only when `Signature=adhoc`, the
team identifier is unset, and no authority is present. Ambiguous, missing, or
conflicting provenance fails closed as `SIGNATURE_MISMATCH`.

Both unprivileged package readback and the privileged-helper package observer
use this parser. Production plans still require the expected Team ID and
CDHash, so a typed identity without a Developer ID authority cannot satisfy the
release gate. The parser returns only bounded identity fields and never raw
`codesign` output.

## Verification

- `npm run typecheck --silent` passed.
- Broker install-plan and privileged-helper package tests passed 45/45.
- `npm test --silent` passed 870/870 with 14 explicit skips (884 total).
- `npm run build --silent` passed before the focused and full test runs.
- The real temporary ad-hoc macOS artifact is classified as
  `development-ad-hoc`; it remains invalid for production plans.

## Evidence boundary

No Developer ID certificate, notarized artifact, persistent LaunchAgent or
LaunchDaemon, root helper, Keychain item, or capability was installed or
enabled. The remaining release evidence is a real Developer ID/notarization
readback on the target distribution artifact plus installed lifecycle and
rollback proof.

## Rollback

Revert the signature parser/readback contract and its fixtures in the focused
commit. No host state was changed.
