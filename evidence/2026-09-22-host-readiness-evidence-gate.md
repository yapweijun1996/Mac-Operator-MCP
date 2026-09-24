# Host Readiness Evidence Gate

Date: 2026-09-22

Status: `IMPLEMENTED / CURRENT HOST BLOCKED`

Production GUI or D1 public exposure now requires a protected
`macos-host-readiness-v1` JSON record. Broker startup validates:

- owner-only regular-file permissions and current host UID;
- exact schema/mechanism and data-only record shape;
- matching Darwin platform and architecture;
- freshness within ten minutes;
- consistent signing, Gatekeeper, and Accessibility projections;
- the requested release and GUI readiness flags.

The record is written through:

```text
npm run record:host-readiness -- <absolute-path>
```

The recorder uses a fixed child invocation, an owner-only temporary file,
`0600` permissions, and an atomic rename. A blocked probe result is still
recorded for diagnosis but returns non-zero and cannot satisfy production
startup.

## Current host result

The physical Darwin arm64 host currently reports:

- `readyForRelease: false` with zero valid Developer ID identities;
- `readyForGui: false` with Accessibility permission denied;
- `persistentServiceVerified: false` with target launchd labels absent.

The result is therefore fail-closed. No permission, policy, OAuth grant,
launchd service, or live R1 deployment state was changed.

## Verification

- Host-readiness validator tests passed: 2/2.
- Production startup rejects both missing evidence and a structurally valid
  but blocked evidence record.
- Temporary recorder test produced an owner-only `0600` record, returned the
  expected blocked/non-zero result, and left no temporary state.
- Full repository regression passed: 1,089 total; 1,074 passed, 15 skipped,
  0 failed.
