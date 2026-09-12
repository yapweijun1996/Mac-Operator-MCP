# Mac-Operator-MCP Task Ledger

Status: Active
Version: 0.1
Last verified: 2026-09-12

Status values: `DONE`, `IN_PROGRESS`, `PLANNED`, `BLOCKED`. Completion requires repository evidence. The current repository contains no implementation or tests.

## P0 — Foundation

- `MOP-001` — `IN_PROGRESS` — Bootstrap repository. Git repository, `main`, remote tracking, initial commit, and `.gitattributes` exist. Package/runtime structure, developer commands, and CI are pending.
- `MOP-002` — `DONE` — Materialized and synchronized GOAL, DESIGN, SPEC, EPIC, ROADMAP, TASK, PROGRESS, and GOAL_PROMPT with repository-state, consistency, whitespace, task-ID, and prompt-length checks.
- `MOP-003` — `PLANNED` — Confirm TypeScript/Node or select another runtime; define packages and dependency direction.
- `MOP-004` — `PLANNED` — Define versioned request, result, failure, principal, scope, target, policy-decision, job, and audit schemas.
- `MOP-005` — `PLANNED` — Define capability taxonomy, scope naming, tool lifecycle (`planned`, `implemented`, `enabled`), and the 44-tool delivery matrix.
- `MOP-006` — `PLANNED` — Create threat model for remote client, Edge, IPC, Broker, adapters, child processes, GUI, helper, audit, policy, and secret stores.
- `MOP-007` — `PLANNED` — Establish format, lint, typecheck, unit, integration, security, and CI baseline.
- `MOP-008` — `PLANNED` — Define evidence format that binds verification to source revision, host profile, policy version, and tool contract version.

## P1 — Local Broker vertical slice

- `MOP-010` — `PLANNED` — Implement Broker lifecycle, `mac_health`, and `mac_capabilities`.
- `MOP-011` — `PLANNED` — Implement protected local IPC and independent caller authentication.
- `MOP-012` — `PLANNED` — Implement timestamp, nonce, canonical payload binding, replay window, and request ledger.
- `MOP-013` — `PLANNED` — Implement normalized target types and deterministic policy evaluation.
- `MOP-014` — `PLANNED` — Implement `mac_policy_explain` as a non-executing policy dry run.
- `MOP-015` — `PLANNED` — Implement audit intent, decision, completion, redaction, and audit-failure behavior.
- `MOP-016` — `PLANNED` — Implement global and capability-specific kill switches, revocation checks, and active-job behavior.
- `MOP-017` — `PLANNED` — Implement timeout, output cap, cancellation, idempotency, uncertain outcome, and restart reconciliation primitives.
- `MOP-018` — `PLANNED` — Implement safe `mac_read_file` vertical slice with canonical target binding.
- `MOP-019` — `PLANNED` — Verify local success and adversarial cases on the real Mac.

## P2 — Remote Edge

- `MOP-020` — `PLANNED` — Implement MCP initialize, tool discovery, health, and stable error mapping.
- `MOP-021` — `PLANNED` — Implement remote authentication and immutable principal projection.
- `MOP-022` — `PLANNED` — Implement Edge-to-Broker signed request construction.
- `MOP-023` — `PLANNED` — Implement client/session rate limits and bounded discovery.
- `MOP-024` — `PLANNED` — Implement credential revocation and session expiry.
- `MOP-025` — `PLANNED` — Select authenticated HTTPS/tunnel deployment and verify a real client end to end.

## P3 — L0/L1 inspection

- `MOP-030` — `PLANNED` — Implement `mac_system_summary`, `mac_storage_analysis`, and storage bounds.
- `MOP-031` — `PLANNED` — Implement process, network, service, and approved-log inspection tools.
- `MOP-032` — `PLANNED` — Implement directory listing, path stat, bounded tree, and recent-file metadata.
- `MOP-033` — `PLANNED` — Implement file discovery and bounded text search.
- `MOP-034` — `PLANNED` — Implement file hash and expand safe file read.
- `MOP-035` — `PLANNED` — Implement project discovery and project summary.
- `MOP-036` — `PLANNED` — Complete path traversal, encoding, symlink, mount, target-swap, file-type, and resource-limit tests.
- `MOP-037` — `PLANNED` — Complete secret-zone classification and no-secret-output regression suite.

## P4 — L2 developer operations

- `MOP-040` — `PLANNED` — Implement Git status, diff, log, and branch metadata.
- `MOP-041` — `PLANNED` — Implement package-manager inspection.
- `MOP-042` — `PLANNED` — Implement Docker status, object inspection, and bounded logs without arbitrary socket proxying.
- `MOP-043` — `BLOCKED` — Implement named task profiles after selecting and proving the child-process sandbox.
- `MOP-044` — `BLOCKED` — Implement job status and cancellation after process-tree ownership and termination semantics are defined.
- `MOP-045` — `BLOCKED` — Prove child processes cannot access Edge/Broker/controller credentials or exceed filesystem/network policy.
- `MOP-046` — `BLOCKED` — Implement atomic file write and patch only after policy, audit, idempotency, and verification primitives pass.
- `MOP-047` — `BLOCKED` — Implement explicit Git staging and local commit after controlled-write release gates pass.

## P5 — L3/L4 applications and GUI

- `MOP-050` — `PLANNED` — Implement app inventory, launch, and focus with stable app identities.
- `MOP-051` — `PLANNED` — Implement structured AppleScript/JXA/Shortcuts adapters without raw script input.
- `MOP-052` — `PLANNED` — Implement Accessibility-tree observation and freshness-bound target identities.
- `MOP-053` — `BLOCKED` — Implement UI actions and typing after sensitive-target and focus protections pass.
- `MOP-054` — `PLANNED` — Define sensitive-dialog, credential-UI, security-setting, clipboard, and cross-app data policies.
- `MOP-055` — `PLANNED` — Verify macOS permission-denied, revoked-permission, stale-target, and real-app workflows.

## P6 — L5 privileged helper

- `MOP-060` — `BLOCKED` — Freeze helper protocol after lower-level identity and authorization evidence is green.
- `MOP-061` — `BLOCKED` — Select packaging/signing and implement local caller authentication.
- `MOP-062` — `BLOCKED` — Implement approved service control with preconditions and postconditions.
- `MOP-063` — `BLOCKED` — Implement approved package installation with exact identity/version policy.
- `MOP-064` — `BLOCKED` — Implement reboot/shutdown with explicit policy and verified audit intent.

## P7 — Hardening and release

- `MOP-070` — `PLANNED` — Fuzz schemas and test traversal, replay, revocation, prompt injection, resource exhaustion, and policy downgrade.
- `MOP-071` — `PLANNED` — Verify crash, restart, partial mutation, audit outage, credential rotation, and kill-switch recovery.
- `MOP-072` — `PLANNED` — Add packaging, signing, upgrade, rollback, observability, retention, and operator runbooks.
- `MOP-073` — `PLANNED` — Perform independent security and architecture review; resolve all reproducible P0/P1 findings.
- `MOP-074` — `PLANNED` — Produce exact-revision release candidate and real-client/real-Mac evidence.

## Immediate next steps

1. Decide `MOP-003` and create the runtime/package baseline.
2. Define shared schemas in `MOP-004` before implementing protocol handlers.
3. Build the threat model and tests in `MOP-006` and `MOP-007`.
4. Implement the local Broker vertical slice before selecting production remote transport.

## Definition of Done

A task is `DONE` only when implementation, focused verification, affected regression and security checks, real-Mac evidence where relevant, documentation updates, and final repository readback are complete. Code existence alone is insufficient.
