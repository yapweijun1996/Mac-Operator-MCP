# Mac-Operator-MCP Epics

Status: Planning
Version: 0.1
Last verified: 2026-09-12

No Epic has implementation evidence yet. Status values are `PLANNED`, `IN_PROGRESS`, `BLOCKED`, or `DONE`.

## EPIC-001 — Project and Contract Foundation

Status: `IN_PROGRESS`

Establish the repository structure, runtime decision, shared schemas, error model, policy vocabulary, threat model, audit contract, verification matrix, ADR system, test strategy, CI, and synchronized repo/KB documentation. Materialize the locked security, filesystem, tool-standard, catalog, and individual tool contracts without treating documentation as runtime implementation. Contract capability sequencing uses `tool_delivery_wave`; project lifecycle sequencing remains the roadmap's `Phase 0` through `Phase 7`.

Dependencies: none.
Exit: all locked KB contracts are represented and validated in the repo; open decisions are accepted or explicitly deferred; baseline builds and tests pass; authority invariants are represented by executable tests; documentation matches repository state.

## EPIC-002 — Secure Remote MCP Edge

Status: `PLANNED`

Deliver MCP protocol handling, authenticated remote transport, principal derivation, scope projection, rate limits, request IDs, bounded tool discovery, revocation, and signed requests to the Broker.

Dependencies: EPIC-001.
Exit: valid clients can reach the Broker; forged, expired, replayed, revoked, and unauthorized requests fail closed.

## EPIC-003 — Local Broker and Policy Engine

Status: `PLANNED`

Implement protected local IPC, independent request authentication, target normalization, deterministic authorization, capability switches, budgets, adapter dispatch, idempotency, job lifecycle, audit coordination, result verification, and restart reconciliation.

Dependencies: EPIC-001; integrates with EPIC-002.
Exit: a local vertical slice proves policy decisions, execution limits, audit records, kill switches, revocation behavior, and uncertain-outcome handling.

## EPIC-004 — L0/L1 Observe, Files, and Projects

Status: `PLANNED`

Implement safe host health, storage, process, service, network, approved-log, directory, file, search, hash, project discovery, and project summary tools. Add canonical path, deny-root, symlink, target-swap, secret-content, output, and time-limit protections.

Dependencies: EPIC-003; remote release also depends on EPIC-002.
Exit: a real Mac can be inspected through released tools while protected targets remain unreadable.

## EPIC-005 — L2 Developer Operations

Status: `PLANNED`

Implement Git inspection, package inspection, Docker inspection, named test/build profiles, bounded jobs, and controlled local writes. Prove that repository code and child processes cannot access controller credentials or exceed effective filesystem and network policy.

Dependencies: EPIC-003, EPIC-004, and verified child-process isolation.
Exit: approved development workflows pass real-project tests without a generic unrestricted host shell.

## EPIC-006 — L3/L4 App and GUI Control

Status: `PLANNED`

Implement app inventory, launch, focus, native automation adapters, Accessibility-tree observation, and target-bound UI actions. Add app scopes, freshness/focus checks, sensitive-surface denial, macOS permission handling, and real-application tests.

Dependencies: EPIC-003 and stable audit/revocation behavior.
Exit: approved workflows pass real-Mac tests and deny sensitive or stale targets.

## EPIC-007 — L5 Privileged Helper

Status: `PLANNED`

Implement a separately authenticated helper with versioned schemas for a minimal allowlist of privileged operations. Define preconditions, verification, recovery, audit, version compatibility, and emergency disable.

Dependencies: EPIC-002 through EPIC-005 security evidence and an approved helper design.
Exit: selected operations pass adversarial and recovery tests; arbitrary root command execution is impossible by contract and implementation.

## EPIC-008 — Security, Operations, and Release Assurance

Status: `PLANNED`

Deliver threat-model coverage, fuzzing, path and replay attacks, prompt-injection simulations, rate and denial-of-service controls, audit integrity/privacy, credential rotation, crash recovery, packaging/signing, upgrades, rollback, telemetry, runbooks, and independent review.

Dependencies: continuous across all Epics.
Exit: the release checklist is green, exact-revision evidence is available, and affected boundaries have no unresolved P0/P1 findings.

## Completion rule

An Epic is `DONE` only when code, required tests, real-host evidence, documentation, operational procedures, and release-state readback are complete. Design documents or tool registration alone do not satisfy completion.

## Related documents

See `ROADMAP.md`, `TASK.md`, `VERIFICATION.md`, `THREAT_MODEL.md`, and `docs/adr/README.md`.
