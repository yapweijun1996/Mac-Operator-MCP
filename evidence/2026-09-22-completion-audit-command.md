# Machine-readable completion audit

Date: 2026-09-22
Scope: read-only current-state acceptance audit; no service, permission, OAuth, Keychain, or policy mutation

## Command

```text
npm run verify:completion
```

## Result

The command emitted schema `mac-operator-completion-audit-v1` with
`status: partial`, `failClosed: true`, and `overallProgressPercent: 92`.
It intentionally exited with status `1` because completion is not proven.

The current host readback reported:

- zero valid Developer ID signing identities;
- Gatekeeper assessments enabled, which is not sufficient for release;
- Accessibility `permission-denied` with fail-closed behavior;
- absent `gui/501/com.mac-operator.edge`,
  `gui/501/com.mac-operator.broker`, and
  `system/com.mac-operator.root-helper-snapshot` labels.

The audit also verified that the current completion, release, lifecycle,
Keychain, packaged-startup, root-helper, and process-boundary evidence files
are present. The production-material/rollback/security-review gate remains
explicitly incomplete until external acceptance evidence exists.

The audit now reads the optional owner-only `evidence/production-acceptance.json`
record through the strict `mac-operator-production-acceptance-v1` boundary.
The current host has no such record, so the gate reports the explicit reason
`owner-only production acceptance record is absent`. A future record must still
agree with the current host and reference regular non-symlink evidence files;
it cannot bypass the dynamic Developer ID, Accessibility, or persistent
service checks.

## Safety boundary

The audit invokes only the repository's read-only host-readiness probe with an
explicit `shell: false` child boundary. It does not grant permissions, sign or
notarize artifacts, bootstrap services, read secrets, or change public scopes.

## Latest physical recheck

The following read-only or disposable self-tests were rerun after the audit:

- `npm run probe:root-helper-native` passed peer credentials, peer process
  identity, bounded framing, and descriptor transfer; production serve remained
  disabled.
- `npm run probe:root-helper-native-auth` passed HMAC response authentication,
  snapshot materialization, bounded sandbox child execution, native authority
  polling, revocation fail-closed behavior, freshness, attestation digest and
  signature rejection, malformed request-id rejection, and forged-HMAC
  rejection; production execution remained disabled.
- `npm run probe:root-helper-snapshot` returned `server_start=POLICY_DENIED`,
  `available=false`, and `public_task_scope=disabled`.
- `npm run probe:accessibility` returned `permission-denied` with
  `failClosed=true`.
- `npm run probe:user-service-readback` returned a bounded readback for the
  separate personal LaunchAgent without changing it.
- `npm audit --omit=dev --audit-level=high` found zero vulnerabilities.

The disposable LaunchAgent probe was not run because it requires the explicit
`MOPS_REAL_INSTALL_PLAN=1` opt-in and would mutate temporary launchd state.
