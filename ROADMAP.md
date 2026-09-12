# Mac-Operator-MCP Roadmap

Status: Active planning
Version: 0.1
Last verified: 2026-09-12

## Current position

The repository exists but has no implementation baseline. Work is in Phase 0. Documentation is being materialized from the initial project SSOT and refined architecture review.

## Phase 0 — Foundation and contracts

Status: `IN_PROGRESS`

Confirm runtime and package strategy; create project structure; freeze shared request/result/error schemas; define principal, scope, policy, target, job, idempotency, audit, and revocation contracts; create the threat model and executable test fixtures; establish formatting, lint, typecheck, unit, security, and CI checks.

Exit: documentation and schemas agree; the baseline is reproducible; security invariants have failing-then-passing tests; no host mutation capability is enabled.

## Phase 1 — Local Broker vertical slice

Status: `PLANNED`

Implement protected local IPC, Broker health and capabilities, policy explanation, principal validation, replay defense, target normalization, policy evaluation, audit events, kill switches, and one safe file-read adapter.

Exit: local integration tests and real-Mac evidence cover success, unauthorized access, secret denial, path escape, target swap, output cap, timeout, lock, revocation, and restart behavior.

## Phase 2 — Remote MCP Edge

Status: `PLANNED`

Implement MCP transport, remote authentication, principal projection, tool-state discovery, request signing, rate limits, revocation, and a deployment-independent local test mode. Select and configure the authenticated HTTPS/tunnel path after the local boundary passes.

Exit: a real authorized client reaches the Phase 1 slice remotely; forged, replayed, expired, revoked, and scope-invalid calls fail closed.

## Phase 3 — L0/L1 inspection expansion

Status: `PLANNED`

Add system, storage, process, service, network, approved log, directory, search, hash, recent-file metadata, project discovery, summary, and bounded tree tools. Expand secret, filesystem-race, redaction, and resource-exhaustion tests.

Exit: the Mac can be diagnosed safely through released read-only tools with exact-revision evidence.

## Phase 4 — L2 developer operations

Status: `PLANNED`

Add Git, package, and Docker inspection; then named test/build profiles and Broker-owned jobs. Prove filesystem, network, environment, process-tree, and credential isolation before enabling controlled writes. Add atomic file writes, patching, explicit staging, and local commits with preconditions and verification.

Exit: approved real-project workflows pass without exposing a generic shell or controller credentials.

## Phase 5 — L3/L4 apps and GUI

Status: `PLANNED`

Add app inventory/open/focus and structured native automation, followed by Accessibility observation and actions. Implement target identity, freshness, focus, app/action scopes, sensitive-surface rules, and macOS permission recovery.

Exit: approved workflows pass real-application tests and sensitive or stale targets fail closed.

## Phase 6 — L5 privileged helper

Status: `PLANNED`

Finalize helper protocol, local caller authentication, package/signing model, operation allowlist, preconditions, verification, rollback, audit, compatibility, and emergency disable. Implement the smallest approved operation set.

Exit: independent review and adversarial real-host tests pass; no arbitrary root execution path exists.

## Phase 7 — Production hardening and controlled expansion

Status: `PLANNED`

Complete fuzzing, denial-of-service controls, audit privacy/integrity, credential rotation, crash and upgrade recovery, packaging, signing, observability, backups, rollback, operator runbooks, and release review. Add capabilities only through the same policy, scope, audit, and evidence model.

Exit: P0=0 and P1=0 for affected boundaries, release checklist green, rollback verified.

## Dependency order

```text
Contracts
  -> Local authority boundary
  -> Remote identity boundary
  -> Read-only host capabilities
  -> Isolated developer execution
  -> Controlled writes
  -> App and GUI control
  -> Privileged operations
  -> Broader operator capabilities
```

## Priority rule

Authority and credential defects take priority over functional expansion. Then address broken core behavior, secret boundaries, reliability, read-only capabilities, developer operations, GUI control, privileged operations, and convenience features.

## Current blockers and decisions required

- Confirm implementation runtime; TypeScript/Node is the current candidate.
- Select Edge-to-Broker authentication and replay mechanism.
- Select an enforceable macOS child-process sandbox.
- Define initial filesystem allow and deny roots.
- Select policy and audit storage formats.
- Decide read-only behavior during audit-store failure.
- Select remote authentication/tunnel only after the local vertical slice is verified.
- Define packaging/signing before GUI and privileged distribution.
