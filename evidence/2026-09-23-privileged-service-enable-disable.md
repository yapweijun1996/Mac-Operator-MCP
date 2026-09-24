# Privileged Service Enable/Disable Boundary Evidence

Date: 2026-09-23

Scope: MOP-062 service-control action completeness and VT-PRIV-01 helper
boundary evidence.

## Verified change

The Broker argument parser and versioned `mac_priv_service_control` contract
already accepted `start`, `stop`, `restart`, `enable`, and `disable`, but the
privileged service adapter rejected the last two actions before dispatch. The
adapter now supports all five actions without accepting a caller-provided
executable, environment, or arbitrary argument vector:

- `start`, `stop`, and `restart` retain their fixed `launchctl` argv and
  service-state postcondition checks.
- `enable` and `disable` use fixed `/bin/launchctl enable|disable
  system/<label>` argv and read the domain's state using
  `launchctl print-disabled system`.
- The enablement parser accepts only the bounded dictionary format observed on
  the current host. Duplicate labels, malformed entries, unknown formats,
  non-system service targets, and truncated command output fail closed.
- An absent override is interpreted as enabled by default, consistent with
  the current `launchctl` output and service enablement semantics. This is an
  interpretation of the command's override map, not an independent Service
  Management API readback.
- `expected_state` must match the requested action. A post-action readback
  mismatch never reports success.
- A service command interrupted by cancellation, timeout, output-limit, or
  unresolved process cleanup is classified as `UNKNOWN_OUTCOME`, not as a
  definitive cancellation or failure. The existing authenticated Job
  readback path can then inspect the state without replaying the mutation.

## Verification

- Local `man launchctl` and `launchctl help` document `enable`/`disable` as
  persistent service-target operations and `print-disabled` as the domain
  readback command.
- The current-host read-only `print-disabled system` output was successfully
  parsed; no service enablement, disablement, bootstrap, or bootout was run.
- `npm run build` passed, including native adapter builds and TypeScript build.
- Focused service-inspector, service-control, privileged-helper,
  helper-executor, and contract-conformance tests passed 51/51.
- Full `npm test` passed 1,180/1,195 tests, with 15 skipped and 0 failures.

## Limitations

The privileged helper remains disabled by default. No live privileged service
was enabled or disabled, and this evidence does not prove Developer ID
provenance, a root-domain helper installation, a production service allowlist,
or independent P0/P1 review. The textual `print-disabled` output is parsed
strictly and fails closed on format drift; a future supported macOS version
should receive explicit readback regression evidence before release.

## Rollback

Rollback removes enablement handling and its readback parser/tests and restores
the prior adapter behavior that rejected `enable` and `disable`. No host
service state, LaunchDaemon, credential, policy, OAuth scope, or database was
changed by this implementation.
