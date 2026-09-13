# ADR-0009: Separately Authenticated Privileged Helper Boundary

- Status: Proposed
- Date: 2026-09-13
- Affected tasks: MOP-060, MOP-061, MOP-062, MOP-063, MOP-064
- Verification: VT-PRIV-01, VT-COMP-01

## Decision

Privileged operations must cross a separate helper IPC channel. The unprivileged Broker remains the final authority and sends a Broker-generated, HMAC-authenticated command over an owner-only Unix socket. The helper authenticates the OS peer before parsing, validates a versioned command envelope, admits each request and nonce exactly once through a durable replay ledger, and dispatches only the fixed operation names `service_control`, `package_install`, and `power`. A Broker-owned authority callback is mandatory and is checked before dispatch, during cancellation polling, and before response publication; a revoked or expired active operation cannot be returned as success.

The command carries only the normalized target, the digest of Broker-validated arguments, the active policy version, approval identity, and mutation-intent identity. It never carries shell text, executable paths, arbitrary arguments, filesystem roots, or credential material. Responses are bound to the complete command digest, bounded to flat redacted evidence, and require an allowlisted postcondition status before success is accepted.

The repository currently provides the protocol, peer/authentication boundary, durable nonce adapter, bounded response validation, explicit handler-map validation, a Broker-owned command factory that binds signed commands to persisted approved running Jobs, and a fail-closed default adapter. No real root process, privileged command, package installer, service mutation, reboot, launchd registration, signing, or production enablement is included.

## Consequences and rollback

- A helper implementation cannot be enabled merely by supplying tool arguments; it must provide an explicit operation handler and an accepted isolation/packaging review.
- Replay state is separate from Edge and Broker request replay so a helper socket cannot be reused after restart.
- Helper failure, timeout, cancellation, or unverifiable postcondition must remain a stable failure or `UNKNOWN_OUTCOME`; the Broker must not infer privileged success from connection loss.
- Rollback is to remove the helper channel and revoke the `privileged` kill switch/authority; the MCP Edge has no direct helper route.

## Open evidence

Caller identity, root-domain packaging, code signing/notarization, protected key distribution, service/package/power adapters, crash recovery, real-host caller-spoof tests, and independent P0/P1 review remain open. This ADR is not an acceptance of privileged capability.
