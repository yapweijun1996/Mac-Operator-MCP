# Virtualization guest startup composition evidence

Date: 2026-09-15

## Decision

The Broker now has one startup-owned composition seam for the native guest
VM, lifecycle controller, virtio channel, optional guest-initiated listener
source, authenticated guest transport, and virtualization task runner. The
seam is opt-in and requires independent
`enabled` and `hostEvidenceAccepted` gates. MCP request arguments never reach
the image path, image digest, guest port, authentication key path, attestation,
or isolation proof.

## Implementation

`packages/broker/src/virtualization-guest-startup.ts` loads a protected image
and authentication key only after the gates pass, verifies the image identity,
creates the native VM adapter, binds one fixed virtio port (`38765`) and bounded
frame/deadline budgets, optionally creates a startup-owned listener source,
then constructs `VirtualizationGuestTransportClient`
with a caller-supplied durable replay guard. The loaded key is wiped after the
transport copies it. VM start is exposed as a `RuntimeChannel`, status is an
explicit recovery readback, and close drains transport before lifecycle/VM
resources.

`createBrokerServiceFromStartupConfig` accepts this seam only as a startup
argument. When present and available, it injects the resulting task runner,
starts the guest before Job Ledger recovery, adds the guest lifecycle channel
to the native runtime, and closes it before the Broker store. The persisted
service document and MCP request schema remain unchanged; absent startup input
keeps the existing fail-closed runner.

## Verification

- Focused startup tests: 3/3 pass.
- Startup service tests: 3/3 pass.
- Full physical-Darwin suite:
  `MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
  — 555/555 pass, 0 skipped.
- `npm run typecheck` passes.
- `npm run lint` passes.
- `git diff --check` passes.

The host still rejects the synthetic guest image before VM creation because a
valid entitled boot image is not available. Therefore this addendum proves
startup composition, ordering, cleanup, and fail-closed gates only; it does not
claim a production VM boot, guest server handshake, isolation evidence, signed
attestation production, or `mac_task_run` enablement.

## Rollback

Remove the optional `virtualizationGuest` startup argument and the service
returns to its prior `FailClosedTaskRunner` path without changing persisted
configuration or MCP contracts. The new module can then be removed as a
focused follow-up; no data migration is required.
