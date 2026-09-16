# Privileged helper capability release contract

- Date: 2026-09-16
- Scope: root LaunchDaemon package capability projection

## Implementation

The root-helper package plan now accepts an explicit host-owned capability
release record. The release is not part of MCP input and cannot be derived
from service-control arguments. It must identify the `host-verified` source,
an exact canonical capability list, an adapter-availability boolean, and a
bounded evidence reference.

Only the currently implemented `mac_priv_service_control` capability can be
released. Package-install and power capabilities remain rejected until their
adapters are implemented. The default plan still carries zero capabilities
and `adapterAvailable: false`.

Final helper readback now compares both `adapterAvailable` and the exact
enabled-capability list against the plan. A helper that reports an added,
removed, reordered, or otherwise different capability fails with stable
`SERVICE_MISMATCH` behavior.

## Verification

- `npm run typecheck --silent` passed.
- Focused package and service-control suites passed 22/22.
- Capability release tests reject unimplemented capabilities and inconsistent
  availability/list projections.
- Existing disabled-helper readback tests remain green.

This closes package-plan projection drift only. It does not prove root
installation, Developer ID signing, descriptor execution, or live privileged
enablement on the physical Mac.

## Rollback

Revert the capability-release implementation and its documentation. No host
service, filesystem, signing identity, or credential store was changed.
