# Mac-Operator-MCP Roadmap

Status: Active planning
Version: 0.1
Last verified: 2026-09-13

## Current position

The repository has a committed TypeScript/Node implementation baseline. Work spans Phase 1 and the early Phase 2/4/5 slices: the authenticated Edge/Broker foundation, MCP discovery/error mapping, bounded post-authentication rate limiting, bounded L0/L1 plus Git/package/Docker inspection, and read-only app inventory are implemented locally, while production enablement remains closed.

## Phase 0 — Foundation and contracts

Status: `IN_PROGRESS`

Materialize locked KB security, filesystem, and tool contracts; confirm runtime and package strategy; create project structure; freeze request/result/error schemas and principal, scope, identity/IPC, approval, policy, persistence, job, idempotency, audit, and revocation contracts; complete sandbox research; maintain the threat and verification matrices; establish formatting, lint, typecheck, unit, security, and CI checks.

Exit: documentation and schemas agree; the baseline is reproducible; security invariants have failing-then-passing tests; no host mutation capability is enabled.

## Phase 1 — Local Broker vertical slice

Status: `IN_PROGRESS`

Implement protected local IPC, Broker health and capabilities, policy explanation, principal validation, replay defense, target normalization, policy evaluation, audit events, kill switches, and one safe file-read adapter.

Exit: local integration tests and real-Mac evidence cover success, unauthorized access, secret denial, path escape, target swap, output cap, timeout, lock, revocation, and restart behavior.

## Phase 2 — Remote MCP Edge

Status: `IN_PROGRESS`

Implement MCP transport, remote authentication, principal projection, tool-state discovery, request signing, rate limits, revocation, and a deployment-independent local test mode. Select and configure the authenticated HTTPS/tunnel path after the local boundary passes.

Exit: a real authorized client reaches the Phase 1 slice remotely; forged, replayed, expired, revoked, and scope-invalid calls fail closed.

## Phase 3 — L0/L1 inspection expansion

Status: `IN_PROGRESS`

Add system, storage, process, service, network, approved log, directory, search, hash, recent-file metadata, project discovery, summary, and bounded tree tools. Expand secret, filesystem-race, redaction, and resource-exhaustion tests.

Exit: the Mac can be diagnosed safely through released read-only tools with exact-revision evidence.

## Phase 4 — L2 developer operations

Status: `IN_PROGRESS`

Bounded Git, package, and fixed local-only Docker inspection are implemented with independent scopes and target authorization. Continue with named test/build profiles and Broker-owned jobs only after sandbox evidence; prove filesystem, network, environment, process-tree, and credential isolation before enabling controlled writes. Add atomic file writes, patching, explicit staging, and local commits with preconditions and verification.

Exit: approved real-project workflows pass without exposing a generic shell or controller credentials.

## Phase 5 — L3/L4 apps and GUI

Status: `IN_PROGRESS`

App inventory, disabled-by-default approval-bound app launch/focus slices, the read-only Accessibility observation boundary, and a disabled-by-default snapshot-bound `mac_ui_action` boundary are implemented with stable bundle identities and exact app/window/element target rules. Add structured native automation next. Extend app/action scopes, sensitive-surface rules, and macOS permission recovery before any GUI capability is enabled.

Exit: approved workflows pass real-application tests and sensitive or stale targets fail closed.

## Phase 6 — L5 privileged helper

Status: `PLANNED`

The proposed helper protocol and separately authenticated IPC boundary are implemented as a fail-closed candidate: OS peer authorization precedes parsing, HMAC commands/responses are digest-bound, helper request/nonce replay is durable, only three operation names are representable, and a Broker-owned factory signs commands only for matching explicit-approval, intent-linked running Jobs after active authority checks. Finalize local caller identity, package/signing model, operation-specific preconditions/verification, rollback, audit, compatibility, and emergency disable before implementing any privileged adapter.

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

The 44 contracts use `tool_delivery_wave` (`wave_1` through `wave_5`) for capability sequencing. This is intentionally distinct from the project lifecycle `Phase 0` through `Phase 7` used by this roadmap. The migration and evidence are recorded in `CONFLICTS.md` and `KB_SYNC.md`.

## Priority rule

Authority and credential defects take priority over functional expansion. Then address broken core behavior, secret boundaries, reliability, read-only capabilities, developer operations, GUI control, privileged operations, and convenience features.

## Current blockers and decisions required

- Confirm implementation runtime through ADR-0001; TypeScript/Node is the current candidate.
- Accept identity and Edge-to-Broker IPC through ADR-0002.
- Accept remote authentication through ADR-0003.
- Freeze policy/config and audit persistence through ADR-0004 and ADR-0005.
- Select an enforceable macOS child-process sandbox.
- Close scope and approval semantics through `MOP-080` and `MOP-082`.
- Complete input/output schema detail and automated validation for all 44 machine-readable tool contracts; the mandatory audit/postcondition fields and delivery-wave naming are already closed.
- Decide read-only behavior during audit-store failure.
- Select remote authentication/tunnel only after the local vertical slice is verified.
- Define packaging/signing before GUI and privileged distribution.

## Related documents

See `EPIC.md`, `TASK.md`, `PROGRESS.md`, `VERIFICATION.md`, and `docs/adr/README.md`.
