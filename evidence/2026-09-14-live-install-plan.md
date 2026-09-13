# Live macOS install-plan and Broker readback evidence

Status: Partial real-host package lifecycle; production release gates remain open

## Scope

This smoke exercised the current host-only install coordinator against a unique,
owner-only temporary per-user package and LaunchAgent. It was removed in a
`finally` path; no persistent service, remote Edge, privileged helper, or
production signing key was used.

## Procedure and result

- Built the current Broker and copied the Node runtime, required dynamic
  library, Broker/contracts output, and production dependencies into the
  temporary package root. The package entrypoint loaded the real
  `createBrokerServiceFromStartupConfig` assembly rather than a waiting-process
  stub.
- Bootstrapped a temporary `/bin/sleep` LaunchAgent as the Edge identity and
  activated a temporary owner-only Edge key plus a signed policy trusting only
  that Edge. The Broker package used a zero-enabled-capability policy and
  owner-only data/runtime roots.
- Built a real `MacOsInstallPlan`, verified an ad-hoc signed temporary bundle,
  and called `executeMacOsInstallPlan`. The readback callback returned only
  independent launchd, native PID/start-time, plist, Broker-status, and
  signature sources. The executor composed the final readback internally.
- The collector waited through launchd's transient `launching` state, then
  double-read launchd identity, native process start time, and plist device/
  inode/hash before accepting `running` Broker state. The signature reader
  accepted Apple's ad-hoc `TeamIdentifier=not set` as an absent optional team
  identifier while still requiring strict verification and exact identifier.
- The result reported `runtimeState=running`, `nativeTransportRequired=true`,
  zero enabled capabilities, a mode-`0600` Broker socket, and a positive
  launchd/native process identity. An exact uninstall plan then booted out the
  service, removed the plist, and returned a null final readback.

## Acceptance boundary

This proves on the physical Mac that the install executor can publish and
bootstrap a real user LaunchAgent, start the packaged Broker assembly, verify
independent post-bootstrap sources, and perform exact uninstall cleanup. It
also covers launchd startup-state normalization, native PID/start-time
stability, descriptor-backed plist identity, strict ad-hoc signature details,
and fail-closed source composition. The package layout was created owner-only;
the separate filesystem-preflight contract remains covered by focused tests.

It does not prove Developer ID provenance, notarization, persistent production
installation, remote Edge request exchange, upgrade/rollback of a released
artifact, root-domain helper installation, Keychain ACL review, or capability
enablement. The Broker status source used by the host observer is an explicit
owner-only fixture for this host smoke; production deployment must bind it to
an authenticated or same-process Broker-owned status channel.

## Verification context

- Host: Darwin arm64, macOS `26.2` build `25C56`.
- Runtime: Node `v25.5.0`.
- Source revision: the locally committed install-readback hardening change.
- Focused install-plan suite: 16 passed, 0 failed.
- Default suite: 423 tests, 420 passed, 3 opt-in sandbox tests skipped.
- `MOPS_REAL_SANDBOX=1 npm test`: 423/423 passed.
- Typecheck, contract validation (44 unique contracts plus the ledger schema),
  high-severity dependency audit, and `git diff --check` passed.
- No secret bytes, private signing keys, or temporary paths were recorded.
