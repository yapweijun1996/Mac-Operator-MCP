# Privileged Helper Signed Launch Target Binding

Date: 2026-09-23

## Finding

The privileged-helper package plan independently accepted a LaunchDaemon
`Program` path and a `signedArtifactPath`. Signature verification and
notarization assessed the latter, but the service could point at a different
native executable elsewhere under `helperRoot`. A passing signature check
therefore did not prove that launchd would execute the assessed artifact.

## Change

- Package-plan construction now requires the launch target to equal the signed
  artifact path or be a descendant inside the signed bundle.
- Existing argv constraints still require exactly the same native executable
  path, with no script, interpreter, or extra arguments.
- The package and CLI fixtures now point into
  `MacOperatorPrivilegedHelper.app/Contents/MacOS/` and include a regression
  rejecting a different in-root native executable.

This binds the plan's signature/notarization evidence to the path launchd will
execute; it does not prove the artifact is currently signed or installed.

## Verification

- `npm run typecheck` — passed.
- `npm run lint` — passed (821 tracked files).
- `npm test` — passed, 1,188/1,203 tests, 15 skipped, 0 failed. This includes
  the native ACL regressions and privileged-helper plan CLI tests.
- No root helper was installed or started; no host service state changed.

## Remaining evidence

Developer ID signature and notarization, immutable artifact provenance, actual
LaunchDaemon installation/readback, rollback, and production capability
acceptance remain open. Project completion remains partial at 92%.
