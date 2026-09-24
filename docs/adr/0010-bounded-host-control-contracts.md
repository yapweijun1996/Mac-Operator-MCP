# ADR-0010: Bounded host-control contracts

- Status: contract design with a disabled service-control candidate; not enabled
- Date: 2026-09-21
- Scope: MOP-104 host-control expansion

## Decision

Define six independent host-control contract families without adding their
scopes to the current runtime scope union, OAuth grants, default Broker policy,
or MCP tool list. Each family must receive its own adapter, target model,
approval class, rollback behavior, and real-Mac readback before it becomes a
planned runtime tool.

The user-domain service-control candidate is implemented as an isolated,
versioned contract, adapter, Broker admission seam, durable Job metadata model,
and disabled Job executor/test seam. It does not materialize a public
`mac_service_control` scope, policy entry, OAuth grant, or MCP capability.

The Broker remains the final authority. Request arguments may select only a
target and bounded action inside a previously signed policy; they cannot select
an executable, socket, shell string, privilege, credential, or approval.

## Contract matrix

| Proposed tool | Scope | Target | Safety / approval | Required readback |
| --- | --- | --- | --- | --- |
| `mac_process_control` | `mac.process.control` | finite process identity or Broker-owned Job | destructive / `trusted_write` | PID plus start-time identity and terminal process state |
| `mac_docker_control` | `mac.docker.control` | finite Docker object identity | destructive / `trusted_write` | object ID, daemon state, and desired lifecycle state |
| `mac_network_control` | `mac.network.control` | finite interface, route, DNS, or firewall object | destructive / `explicit_privileged_policy` | exact pre-state, post-state, and rollback status |
| `mac_system_settings` | `mac.system.settings` | finite allowlisted setting identity | writes_local / `explicit_privileged_policy` | setting-specific normalized value and permission state |
| `mac_package_manage` | `mac.package.write` | approved package identity plus exact version | writes_local / `trusted_write` | package identity/version and install database readback |
| `mac_service_control` | `mac.service.control` | user-domain allowlisted service identity | writes_local / `trusted_write` | launchd service identity, state, and source revision |

## Shared contract requirements

Every future contract must use version `0.1` initially and declare:

- one exact scope, one normalized target type, a bounded action enum, timeout,
  output cap, no-network or explicit allowlist, and secret policy;
- a Broker-owned precondition snapshot and an idempotency key for every
  mutation;
- a durable Job for work that can outlive the request, with `mac_job_status`
  readback and `mac_job_cancel` where cancellation is meaningful;
- redacted audit intent before mutation, completion audit after readback, and
  `UNKNOWN_OUTCOME` whenever execution or rollback cannot be established;
- kill-switch and revocation checks before admission, before dispatch, during
  long operations, and before publishing success;
- target identity revalidation after the adapter returns, including PID
  start-time, Docker object ID, launchd source revision, package version, or
  setting identity as applicable.

## Family-specific boundaries

### `mac_process_control`

Allowed actions are `terminate_owned_job`, `stop_allowlisted_process`, and
`restart_allowlisted_process`. A raw PID is never sufficient: the policy must
bind an executable identity, owner, and process start time. Arbitrary signal
numbers, process groups, descendant traversal, and controller-owned processes
are denied. Broker-owned Jobs use the existing Supervisor cancellation path.

### `mac_docker_control`

Allowed actions are `start`, `stop`, and `restart` for an exact container or
compose-free approved object identity. The adapter must use a fixed Docker API
client boundary and never expose the Docker socket, arbitrary `exec`, image
build, volume mutation, network creation, or raw CLI arguments. Object ID and
daemon identity are rechecked after the action.

### `mac_network_control`

This family is helper-owned. Actions are separately reviewed per platform
surface; no generic route, firewall, DNS, or interface command is accepted.
Each action requires an exact pre-state, an explicit rollback descriptor, and
post-state readback. Privacy/security settings and credential stores are not
targets of this contract.

### `mac_system_settings`

Only named, non-security settings may be added. The contract must reject TCC,
Accessibility, Keychain, firewall, SIP, FileVault, account, and other privacy
or security bypass targets. A setting adapter must expose typed values rather
than preference-domain strings or arbitrary plist writes.

### `mac_package_manage`

The input is an approved package identity and exact version, not an installer
path or command. Package provenance, digest, signature authority, and expected
install scope are checked before mutation. Removal is a separate destructive
contract decision and cannot be inferred from an update request.

### `mac_service_control`

The first implementation may cover only user-domain services whose launchd
identity and rendered plist are already policy-bound. System/root services,
plist path selection, arbitrary launchd arguments, and service installation are
helper-owned or denied. Start/stop/restart must verify the exact source
revision and final service identity.

## Release gate

No proposed scope is added to `packages/contracts/src/types.ts` until all of
the following exist in the same change set:

1. public tool contract and contract-policy parity;
2. Broker target normalization and default-deny policy entry;
3. adapter implementation with fixed command/API boundary;
4. approval, durable Job, idempotency, cancellation, rollback, and audit
   tests;
5. real-Mac target-swap, permission-failure, timeout, revocation, rollback,
   and postcondition readback evidence;
6. public OAuth/tools-list evidence for the exact newly enabled scope.

Until then, the six names remain roadmap vocabulary only. This preserves the
current 45-tool catalog and prevents a design proposal from becoming remote
authority by accident.

## Consequences

The design closes the ownership and safety vocabulary for MOP-104 without
pretending that adapters or release evidence exist. It intentionally leaves
the current deployed R1 profile unchanged and keeps all six families outside
the public MCP surface.
