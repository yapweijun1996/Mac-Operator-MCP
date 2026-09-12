# ADR-0001: Runtime and Package Structure

Status: Accepted for Edge/Broker baseline
Date: 2026-09-12
Task: MOP-003

## Context

The project has no runtime baseline. The Edge, Broker, shared contracts, adapters, policy validation, persistence, and test harness need clear package ownership and dependency direction.

## Options

1. TypeScript/Node for Edge and Broker, with native helpers only where macOS APIs require them.
2. Swift for Broker and native adapters, with a separate Edge runtime.
3. Rust for Broker and isolation-critical components, with a separate Edge runtime.

## Decision criteria

MCP ecosystem compatibility, schema tooling, macOS API access, secure IPC, process control, packaging/signing, sandbox integration, operational simplicity, dependency risk, and contributor maintainability.

## Decision

Use TypeScript on Node.js 24 or newer for the Edge, unprivileged Broker, shared contracts, policy, and test harness. Keep packages dependency-directed: Edge may depend on shared contracts and an IPC client; Broker may depend on shared contracts and adapters; adapters do not own authorization. Native macOS adapters and the separately authenticated privileged helper may use Swift when platform APIs, signing, or packaging require it. They cannot move final authority out of the Broker.

The repository uses npm workspaces with `packages/contracts` and `packages/broker`. Build, typecheck, contract validation, and test commands are owned by the root package.

## Evidence

The arm64 macOS prototype builds with strict TypeScript, transports an authenticated request over a mode-`0600` Unix socket, persists replay and revocation state, and passes the tests recorded in `evidence/2026-09-12-local-broker-foundation.md`.

## Trade-offs and follow-up

Node minimizes MCP/schema duplication and contributor complexity. Swift remains preferable for APIs that require native frameworks or signed privileged packaging. Rust is not selected because it is unavailable on the verified host and would add a second general runtime before an isolation need proves it necessary.

`node:sqlite` emitted an experimental-feature warning on Node 25.5.0. ADR-0005 remains responsible for accepting or replacing the persistence backend. ADR-0006 remains responsible for child-process isolation; this runtime decision does not authorize task execution.

## Rollback

The current packages are not installed or launched as services. Rollback is removal of the uncommitted package baseline. After deployment exists, ADR-0007 and `ROLLBACK.md` must define artifact-level rollback without restoring revoked authority.
