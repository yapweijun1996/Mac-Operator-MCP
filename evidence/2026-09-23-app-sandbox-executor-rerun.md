# App Sandbox executor physical rerun

Date: 2026-09-23

Status: PARTIAL — filesystem/network probe passed, but process-tree
containment failed under the double-fork/`setsid` adversarial case. VT-SBX-01/02
and production `mac_task_run` remain gated.

## Scope and result

- Host: physical macOS arm64. The existing helper bundle was reused; the
  destructive helper-bundle builder was not run.
- Helper SHA-256:
  `8531eae9911b19fb93018af962a8665acfed76f6608bcd5540cea29ff543432c`.
  Strict code-signature verification passed, but the bundle is ad-hoc signed
  with no Team ID and is not a production release artifact.
- `npm run build` passed. It rebuilt the Broker native adapters and TypeScript
  output without replacing the App Sandbox helper bundle.
- The default executor probe passed helper authentication, descriptor
  attestation, fixed `/bin/sh` execution, staged-root read/write, and denial of
  outside-file reads, control-material access, direct network access, a
  LaunchAgents write, and `.ssh` access.
- The latest combined hostile probe passed the exact Broker-owned loopback
  proxy request and returned `UNKNOWN_OUTCOME` in 12 ms. It proved that a
  double-forked grandchild could call `setsid`, leave the task process group,
  and remain alive after the helper returned. The host authenticated that
  process by PID and start time, killed only that exact identity, and verified
  it was absent afterward. The probe therefore reports
  `hostile_process_tree: failed`, with `detachedIdentityObserved: true` and
  `escapedAfterTaskResponse: true`; cleanup succeeded. An immediate repeat
  reproduced the same outcome in 15 ms.
- The simpler background-fork run had returned `UNKNOWN_OUTCOME` and showed its
  sampled process absent afterward, but that case did not establish recursive
  descendant ownership. The stronger double-fork case supersedes that narrower
  result for the process-tree gate.
- The other reported probes still passed: helper authentication, descriptor
  attestation, fixed `/bin/sh` execution, staged-root read/write, outside-file
  denial, control-material denial, direct-network denial, persistence denial,
  credential-zone denial, and the one allowlisted Broker loopback request.

## Re-verification after proof-contract correction

The opt-in executor probe and Auth integration canary previously supplied the
unsupported `app-sandbox`/`owned` process-tree claim. Both now use
`observer-only`, matching the current validator. On the physical macOS arm64
host:

- `npm test` passed 1,212 tests, skipped 16, and failed 0.
- `node scripts/probe-app-sandbox-executor.mjs` passed helper authentication,
  descriptor attestation, fixed-interpreter execution, filesystem/credential/
  network-denial checks, and cleanup.
- The opt-in Auth→Edge→Broker App Sandbox canary passed 1/1.
- `MOP_PROBE_HOSTILE_PROCESS_TREE=1 node scripts/probe-app-sandbox-executor.mjs`
  returned exit 1 because containment failed, as expected for this adversarial
  case. The task returned `UNKNOWN_OUTCOME` in 27 ms; two child identities were
  observed, the detached identity remained alive after the task response, and
  the probe then killed only that PID/start-time identity and verified it was
  absent. Probe cleanup also passed.

The harness correction makes current physical evidence reproducible; it does
not fix the confirmed escape. No production service was installed, and public
task execution remains gated.

The probe now uses a random UUID for host canaries and exclusive creation for
the outside-file canary. It no longer removes a PID-named LaunchAgents file
before starting, so a pre-existing user file cannot be overwritten or deleted
by the setup phase. The hostile-fork probe samples only descendants of the
authenticated task PID and its unique process group, records exact
PID/start-time identities, and verifies them after targeted cleanup; process
IDs are not printed into the evidence output.

## Limits

Confirmed security gap: the helper detects a fork and returns an uncertain
outcome, but cleanup covers the original process group and observed direct
fork PIDs. The double-fork grandchild escaped with `setsid` and was still alive
after the helper returned. This is a failure of the current single-process
containment policy, not merely missing production-signing evidence. Do not
enable this executor for public task execution until the process-tree boundary
is replaced or strengthened and the double-fork fixture passes repeatedly.

This is evidence for the fixed development-probe path only. It does not prove
production signing/notarization, broader credential and Docker isolation,
descendant ownership under all races, production startup wiring, or release
acceptance. No persistent service was installed or started, and
`mac_task_run` remains disabled.
