# Mac-Operator-MCP Task Ledger

Status: Active
Version: 0.1
Last verified: 2026-09-12

Status values: `DONE`, `IN_PROGRESS`, `PLANNED`, `BLOCKED`. Completion requires repository evidence. The current repository contains no implementation or tests. `BLOCKED` is reserved for an evidenced unmet prerequisite, not merely future-phase placement. Every blocked task records `blocked_by`, `unblock_condition`, and `expected_evidence`.

## P0 — Foundation

- `MOP-001` — `IN_PROGRESS` — Bootstrap repository. Git repository, `main`, remote tracking, initial commit, and `.gitattributes` exist. Package/runtime structure, developer commands, and CI are pending.
- `MOP-002` — `DONE` — Materialized and synchronized GOAL, DESIGN, SPEC, EPIC, ROADMAP, TASK, PROGRESS, and GOAL_PROMPT with repository-state, consistency, whitespace, task-ID, and prompt-length checks.
- `MOP-003` — `PLANNED` — Confirm TypeScript/Node or select another runtime; define packages and dependency direction.
- `MOP-004` — `PLANNED` — Define versioned request, result, failure, principal, scope, target, policy-decision, job, and audit schemas.
- `MOP-005` — `DONE` — Materialized the locked capability taxonomy, lifecycle, catalog, standard, and all 44 KB tool contracts with unique provenance, deterministic mandatory fields, and canonical delivery-wave naming. Upstream KB writeback is tracked separately in `KB_SYNC.md`.
- `MOP-006` — `DONE` — Created the initial threat model for remote client, Edge, IPC, Broker, adapters, child processes, GUI, helper, audit, policy, and secret stores, with verification targets.
- `MOP-007` — `PLANNED` — Establish format, lint, typecheck, unit, integration, security, and CI baseline.
- `MOP-008` — `IN_PROGRESS` — Established the initial evidence and verification matrix; machine enforcement and real evidence remain pending the test baseline.

## P0 — Architecture closure

- `MOP-080` — `IN_PROGRESS` — Freeze exact scope, principal, session, parameterized-target, wildcard, inheritance, and revocation semantics. Depends on ADR-0002 and ADR-0004 acceptance.
- `MOP-081` — `IN_PROGRESS` — Decide principal identity and Edge-to-Broker IPC authentication, key lifecycle, replay persistence, concurrency, version negotiation, and Edge replacement detection. Depends on `MOP-003` runtime evidence.
- `MOP-082` — `IN_PROGRESS` — Freeze approval binding, TTL, single-use, mutation invalidation, unattended execution, privileged approval, and atomic consumption. Depends on `MOP-083` persistence decision.
- `MOP-083` — `IN_PROGRESS` — Freeze Request Ledger, Job, Nonce, Idempotency, Approval, Audit, retention, transaction, concurrency, crash-window, and `UNKNOWN` reconciliation models. Depends on ADR-0005 acceptance.
- `MOP-084` — `IN_PROGRESS` — Contract envelope schema is complete and validated for all 44 tools. Per-tool functional `input_schema` and `output_schema` objects remain incomplete, along with their automated API validation. The mandatory audit taxonomy, structured postcondition field, and `tool_delivery_wave` migration are closed. Depends on `MOP-004`, `MOP-005`, `MOP-080`, and `MOP-082`.
- `MOP-085` — `IN_PROGRESS` — Maintain Requirement -> Threat -> Task -> Test -> Evidence -> Release Gate traceability. Depends on test IDs from `MOP-007` and contracts from `MOP-084`.
- `MOP-086` — `PLANNED` — Execute the real-macOS child-process sandbox research and hostile PoC in `SANDBOX_RESEARCH.md`. Depends on `MOP-003`; blocks `MOP-043`, `MOP-045`, and `mac_task_run` enablement. No sandbox guarantee is claimed before this evidence exists.
- `MOP-087` — `IN_PROGRESS` — Complete README navigation and testing, configuration, deployment, operations, incident, rollback, and kill-switch runbooks. Verified commands depend on runtime and packaging work.
- `MOP-088` — `DONE` — Resolved the two repo representation conflicts, recorded decision/rationale/migration/evidence, and prepared `KB_SYNC.md` for owner-reviewed upstream writeback. This documentation-only task does not mutate KB-MCP.

## P1 — Local Broker vertical slice

- `MOP-010` — `PLANNED` — Implement Broker lifecycle, `mac_health`, and `mac_capabilities`.
- `MOP-011` — `BLOCKED` — Implement protected local IPC and independent caller authentication. `blocked_by: MOP-003, MOP-081`; `unblock_condition: runtime/package baseline and identity/IPC contract are selected`; `expected_evidence: ADR-0001/0002 plus protected local IPC and forged-principal tests (VT-AUTH-01, VT-COMP-01)`.
- `MOP-012` — `BLOCKED` — Implement timestamp, nonce, canonical payload binding, replay window, and request ledger. `blocked_by: MOP-081, MOP-083`; `unblock_condition: authenticated envelope and durable nonce/idempotency model are accepted`; `expected_evidence: duplicate nonce, stale timestamp, altered payload, restart, and crash-window tests (VT-AUTH-02, VT-REL-01)`.
- `MOP-013` — `BLOCKED` — Implement normalized target types and deterministic policy evaluation. `blocked_by: MOP-080, ADR-0004`; `unblock_condition: scope/target semantics and policy/config format are accepted`; `expected_evidence: policy negative matrix, filesystem precedence, traversal, and target-race tests (VT-AUTH-03, VT-FS-01, VT-FS-02)`.
- `MOP-014` — `PLANNED` — Implement `mac_policy_explain` as a non-executing policy dry run.
- `MOP-015` — `BLOCKED` — Implement audit intent, decision, completion, redaction, and audit-failure behavior. `blocked_by: MOP-083, ADR-0005`; `unblock_condition: persistence backend, transaction boundaries, retention, and audit-outage policy are accepted`; `expected_evidence: durable-intent crash/outage tests and audit privacy/integrity tests (VT-AUD-01, VT-AUD-02)`.
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
- `MOP-043` — `BLOCKED` — Implement named task profiles. `blocked_by: MOP-084, MOP-086`; `unblock_condition: per-tool functional schemas are complete and sandbox/credential-isolation evidence passes`; `expected_evidence: hostile task-profile PoC, resource-bound tests, and L2 release-gate evidence (VT-SBX-01, VT-SBX-02)`.
- `MOP-044` — `BLOCKED` — Implement job status and cancellation. `blocked_by: MOP-017, MOP-083, MOP-086`; `unblock_condition: job lifecycle, persistence, cancellation, and process-tree ownership are accepted and tested`; `expected_evidence: job state, cancellation, crash recovery, and process termination tests (VT-REL-01, VT-SBX-02)`.
- `MOP-045` — `BLOCKED` — Prove child processes cannot access Edge/Broker/controller credentials or exceed filesystem/network policy. `blocked_by: MOP-086`; `unblock_condition: real-Mac hostile sandbox PoC passes or task capability is restricted/removed`; `expected_evidence: credential canary, filesystem, network, process, Docker, and persistence isolation evidence (VT-SBX-01, VT-SBX-02)`.
- `MOP-046` — `BLOCKED` — Implement atomic file write and patch. `blocked_by: MOP-013, MOP-015, MOP-017, MOP-082, MOP-083, MOP-084`; `unblock_condition: policy, approval, persistence, idempotency, functional schemas, and verification primitives pass`; `expected_evidence: path-race, precondition, approval, audit-intent, crash-recovery, and hash/readback tests (VT-FS-01, VT-FS-02, VT-APR-01, VT-AUD-01, VT-REL-01)`.
- `MOP-047` — `BLOCKED` — Implement explicit Git staging and local commit. `blocked_by: MOP-046`; `unblock_condition: controlled-write release gate passes and staged-content/identity rules are implemented`; `expected_evidence: explicit-path staging, staged-diff hash, commit parent/precondition, redaction, and no-push negative tests (write gate, VT-DOS-01)`.

## P5 — L3/L4 applications and GUI

- `MOP-050` — `PLANNED` — Implement app inventory, launch, and focus with stable app identities.
- `MOP-051` — `PLANNED` — Implement structured AppleScript/JXA/Shortcuts adapters without raw script input.
- `MOP-052` — `PLANNED` — Implement Accessibility-tree observation and freshness-bound target identities.
- `MOP-053` — `BLOCKED` — Implement UI actions and typing. `blocked_by: MOP-052, MOP-054`; `unblock_condition: fresh-target, focus, sensitive-target, credential-UI, and security-setting protections pass`; `expected_evidence: stale-reference, focus-race, sensitive-dialog, secure-input, and permission tests (VT-UI-01, VT-UI-02)`.
- `MOP-054` — `PLANNED` — Define sensitive-dialog, credential-UI, security-setting, clipboard, and cross-app data policies.
- `MOP-055` — `PLANNED` — Verify macOS permission-denied, revoked-permission, stale-target, and real-app workflows.

## P6 — L5 privileged helper

- `MOP-060` — `BLOCKED` — Freeze helper protocol after lower-level identity and authorization evidence is green. `blocked_by: MOP-011, MOP-013, MOP-081`; `unblock_condition: local caller identity, Broker authority, and helper boundary are accepted and tested`; `expected_evidence: helper schema fuzzing, caller-spoof, operation-bypass, and no-arbitrary-root tests (VT-PRIV-01)`.
- `MOP-061` — `BLOCKED` — Select packaging/signing and implement local caller authentication. `blocked_by: MOP-003, MOP-081, ADR-0007`; `unblock_condition: runtime, IPC identity, package/signing, launch ownership, and credential-cleanup decisions are accepted`; `expected_evidence: signature, install/upgrade/rollback, helper mismatch, uninstall, and caller-auth tests (VT-PRIV-01, VT-OPS-01)`.
- `MOP-062` — `BLOCKED` — Implement approved service control with preconditions and postconditions. `blocked_by: MOP-060, MOP-061`; `unblock_condition: authenticated helper protocol and service allowlist are released`; `expected_evidence: allowlist, precondition, service-state readback, audit, rollback, and bypass tests (VT-PRIV-01)`.
- `MOP-063` — `BLOCKED` — Implement approved package installation with exact identity/version policy. `blocked_by: MOP-060, MOP-061`; `unblock_condition: authenticated helper, package source policy, and version allowlist are released`; `expected_evidence: package identity/version, source, approval, installed-version, rollback, and bypass tests (VT-PRIV-01)`.
- `MOP-064` — `BLOCKED` — Implement reboot/shutdown with explicit policy and verified audit intent. `blocked_by: MOP-060, MOP-061, MOP-082, MOP-083`; `unblock_condition: helper auth, privileged approval, durable audit intent, and handoff semantics are released`; `expected_evidence: accepted/scheduled handoff, policy denial, audit-intent, cancellation/reconciliation, and recovery tests (VT-PRIV-01, VT-AUD-01)`.

## P7 — Hardening and release

- `MOP-070` — `PLANNED` — Fuzz schemas and test traversal, replay, revocation, prompt injection, resource exhaustion, and policy downgrade.
- `MOP-071` — `PLANNED` — Verify crash, restart, partial mutation, audit outage, credential rotation, and kill-switch recovery.
- `MOP-072` — `PLANNED` — Add packaging, signing, upgrade, rollback, observability, retention, and operator runbooks.
- `MOP-073` — `PLANNED` — Perform independent security and architecture review; resolve all reproducible P0/P1 findings.
- `MOP-074` — `PLANNED` — Produce exact-revision release candidate and real-client/real-Mac evidence.

## Immediate next steps

1. Complete input/output schema detail and automated contract validation under `MOP-084`.
2. Review the `KB_SYNC.md` writeback manifest before any upstream KB mutation.
3. Decide `MOP-003` and create the runtime/package baseline.
4. Close `MOP-080` through `MOP-084` before implementing authority-sensitive handlers.
5. Establish test IDs and automated matrix checks through `MOP-007` and `MOP-085`.
6. Execute `MOP-086` before implementing `mac_task_run`.
7. Implement the local Broker vertical slice before selecting production remote transport.

## Definition of Done

A task is `DONE` only when implementation, focused verification, affected regression and security checks, real-Mac evidence where relevant, documentation updates, and final repository readback are complete. Code existence alone is insufficient.

## Related documents

See `EPIC.md`, `ROADMAP.md`, `PROGRESS.md`, `VERIFICATION.md`, and `docs/adr/README.md`.
