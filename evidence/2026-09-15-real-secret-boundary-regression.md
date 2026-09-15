# Physical Secret Boundary Regression Evidence

Date: 2026-09-15

Source revision: `356ebd4`

## Host

- Darwin arm64 Mac mini.
- `MOPS_REAL_SANDBOX=1`.
- `MOPS_REAL_KEYCHAIN=1`.
- `MOPS_REAL_INSTALL=1`.

## Verification

- Native fault-test adapter build: passed.
- Non-overlapping built test set: 598 total, 598 passed, 0 skipped,
  0 failed.
- Real sandbox checks ran, including protected-surface, credential-canary,
  fork/`setsid`, TCP/UDP allowlist, and active cancellation coverage.
- Real temporary Keychain ACL retirement and per-user Edge/Broker LaunchAgent
  bootstrap/authentication/bootout ran successfully.
- Process ownership tests now await the asynchronous `onStarted` snapshot with
  a bounded timeout and assert cancellation when shutdown wins the race.
- The existing Broker/Persistence test process remained undisturbed.

This is physical host regression evidence for the implemented boundaries. It
does not prove production Developer ID provenance, VM isolation, remote issuer
deployment, root-domain helper installation, or production `mac_task_run`
enablement.
