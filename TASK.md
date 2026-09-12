# Mac-Operator-MCP Task Ledger

Status: Active
Version: 0.1
Last verified: 2026-09-12

Status values: `DONE`, `IN_PROGRESS`, `PLANNED`, `BLOCKED`. Completion requires repository evidence. Current implementation, test, and working-tree state is owned by `PROGRESS.md`; this ledger records task status and acceptance evidence. `BLOCKED` is reserved for an evidenced unmet prerequisite, not merely future-phase placement. Every blocked task records `blocked_by`, `unblock_condition`, and `expected_evidence`.

## P0 — Foundation

- `MOP-001` — `DONE` — Git repository, npm workspace/package baseline, developer commands, dependency lockfile, ignore rules, and a least-privilege macOS CI definition exist. First remote CI execution remains verification evidence rather than bootstrap scope.
- `MOP-002` — `DONE` — Materialized and synchronized GOAL, DESIGN, SPEC, EPIC, ROADMAP, TASK, PROGRESS, and GOAL_PROMPT with repository-state, consistency, whitespace, task-ID, and prompt-length checks.
- `MOP-003` — `DONE` — Accepted TypeScript/Node 24+ for Edge/Broker/shared contracts; Swift remains available for native adapters/helper. Package direction and prototype evidence are recorded in ADR-0001.
- `MOP-004` — `IN_PROGRESS` — Versioned request/result/failure/principal/scope types, signed policy schemas, and a shared stable failure schema exist. Job, mutation, approval, persistence, and audit record schemas remain incomplete.
- `MOP-005` — `DONE` — Materialized the locked capability taxonomy, lifecycle, catalog, standard, and all 44 KB tool contracts with unique provenance, deterministic mandatory fields, and canonical delivery-wave naming. Upstream KB writeback is tracked separately in `KB_SYNC.md`.
- `MOP-006` — `DONE` — Created the initial threat model for remote client, Edge, IPC, Broker, adapters, child processes, GUI, helper, audit, policy, and secret stores, with verification targets.
- `MOP-007` — `IN_PROGRESS` — Strict typecheck, build, Node test, AJV contract validation, dependency audit, unit/integration/adversarial foundation tests, and a least-privilege macOS CI workflow exist. Format/lint and first remote CI evidence remain pending.
- `MOP-008` — `IN_PROGRESS` — Established the initial evidence and verification matrix; machine enforcement and real evidence remain pending the test baseline.

## P0 — Architecture closure

- `MOP-080` — `IN_PROGRESS` — Freeze exact scope, principal, session, parameterized-target, wildcard, inheritance, and revocation semantics. Depends on ADR-0002 and ADR-0004 acceptance.
- `MOP-081` — `IN_PROGRESS` — Exact Edge/key identity, signed key metadata, protected/exclusive key provisioning, revoke-before-retire deletion, overlapping rotation, validity windows, key-specific revocation, request/response policy-key binding, replay persistence, forged-socket response rejection, macOS UID/GID/PID peer verification, legacy revocation migration, and a BrokerStore-backed monotonic activation/restore guard are implemented and tested. Native packaging/Node-fd compatibility, Edge PID lifecycle, Keychain-backed secret distribution, physical-erasure limits, session concurrency, cross-runtime canonicalization, and general corruption/migration handling remain open.
- `MOP-082` — `IN_PROGRESS` — Broker-owned single-use approval records bind approver/requester, tool/contract, normalized target, arguments digest, policy version, approval class, attended mode and TTL. Exact consumption is atomic with request intent; substitution, expiry, revocation, exhaustion, competing use, missing approval, and pre-dispatch invalidation tests pass. A separately authenticated issuer prototype now binds issuer/key identity, signed payload, preview digest, issuance nonce, attended/unattended policy, and decision/completion provenance before persistence. Owner-only issuer-key file loading/provisioning and a separate durable `approval_key` revocation kind pass revoke-before-retire tests. A versioned owner-only metadata config atomically rotates and reloads non-secret key paths with revision/digest readback; BrokerStore activation history now rejects rollback and startup restore requires the exact persisted identity. Protected Keychain/cross-process storage, human approval UI/channel, unattended profile ownership, privileged approval, active-work semantics and ADR acceptance remain.
- `MOP-083` — `IN_PROGRESS` — SQLite Request records atomically bind nonce admission, request/payload identity, lifecycle, decisions, approval-backed mutation intent, completion, and restart-safe recovery to audit evidence. Single-use Approval records and Job records persist their bounded identities and state. `admitApprovedJob` now atomically binds approval/intent/idempotency/new-job creation with idempotent reuse and conflict rollback. Fault-injected rollback and restart readback now pass; retention, lease/process ownership, general migrations, backup and ADR-0005 acceptance remain.
- `MOP-084` — `DONE` — Contract envelope and per-tool functional `input_schema`/`output_schema` objects are complete for all 44 tools. Envelope validation, functional schema compilation, semantic review, authority-surface review, and catalog parity pass. The mandatory audit taxonomy, structured postcondition field, and `tool_delivery_wave` migration are closed. This documentation/schema closure does not implement runtime behavior or close `MOP-004` or `MOP-080..083`.
- `MOP-085` — `IN_PROGRESS` — Maintain Requirement -> Threat -> Task -> Test -> Evidence -> Release Gate traceability. Depends on test IDs from `MOP-007` and contracts from `MOP-084`.
- `MOP-086` — `IN_PROGRESS` — Initial real-macOS sandbox probe is recorded in `SANDBOX_RESEARCH.md` and `evidence/2026-09-12-sandbox-research.json`. Filesystem/symlink, executable-allowlist, network-deny, and fake credential-canary behavior are partial evidence; inherited environment visibility, file descriptors, sandbox-only process-tree ownership (child survived parent termination), real credential/Docker/persistence isolation, cleanup, and allowlisted-network behavior remain open. A disabled Broker `ProcessSupervisor` plus named `TaskProfileRegistry` now prove explicit profile-owned executable/cwd/args/environment/stdio budgets and process-group cleanup in controlled tests, but they are not task-handler integration or sandbox selection. Still blocks `MOP-043`, `MOP-045`, and `mac_task_run` enablement.
- `MOP-087` — `IN_PROGRESS` — Complete README navigation and testing, configuration, deployment, operations, incident, rollback, and kill-switch runbooks. Verified commands depend on runtime and packaging work.
- `MOP-088` — `DONE` — Resolved the two repo representation conflicts, recorded decision/rationale/migration/evidence, and prepared `KB_SYNC.md` for owner-reviewed upstream writeback. This documentation-only task does not mutate KB-MCP.

## P1 — Local Broker vertical slice

- `MOP-010` — `IN_PROGRESS` — Broker core plus local `mac_health`, `mac_capabilities`, `mac_policy_explain`, `mac_stat_path`, and bounded `mac_read_file` handlers exist and pass tests. Installed lifecycle, operator startup, and production enablement remain open.
- `MOP-011` — `IN_PROGRESS` — Mode-`0600` Unix IPC, macOS `getpeereid`/`LOCAL_PEERPID`, and domain-separated request/response HMAC authentication pass prototype tests, including OS identity denial and rejection of a replacement socket using another key. Production key lifecycle, native packaging/code identity, stable fd access, and compatibility evidence remain open under ADR-0002.
- `MOP-012` — `IN_PROGRESS` — Timestamp/session expiry, canonical payload binding, atomic nonce/request admission, persistent replay denial, terminal request lookup, and restart replay/reconciliation tests exist. Corruption, canonicalization cross-runtime, retention, and accepted persistence design remain open.
- `MOP-013` — `IN_PROGRESS` — Ed25519-signed policy loading, Broker-owned principal grants, exact typed target rules, deny-over-allow, default deny, immutable request snapshots, durable activation/rollback, policy-version binding, filesystem-root authorization, and unimplemented-tool enable rejection pass tests. Other stable resource identities, signer lifecycle, operational reload wiring, and the complete filesystem policy matrix remain open.
- `MOP-014` — `IN_PROGRESS` — A non-executing `mac_policy_explain` handler reports allow/deny, normalized query target, required/missing scopes, reason codes, and policy version. Path queries are mapped to Broker-owned signed root identities before authorization; remaining target types depend on MOP-013.
- `MOP-015` — `IN_PROGRESS` — Broker-owned request states commit atomically with decision, mutation-intent, and completion audit records; recursive redaction, a SHA-256 event chain, startup tamper rejection, and transactional policy intent/completion are implemented as prototype behavior. Crash/outage injection, retention, access control, stronger integrity/anchoring, and ADR-0005 acceptance remain open.
- `MOP-016` — `IN_PROGRESS` — Persistent global/capability-family switches plus principal/session/Edge revocation checks exist. Filesystem workers poll active authority, request termination, revalidate before returning success, and audit active revocation as `CANCELLED`. General queued jobs, process trees, restart behavior, and operator controls await the Job Manager.
- `MOP-017` — `IN_PROGRESS` — Bounded filesystem workers implement concurrency admission, per-tool deadline, active cancellation polling, termination requests, output caps, and post-result authority revalidation. Persistent job identity/status, queued cancellation, idempotency, unknown outcome, process-tree termination, and restart reconciliation remain.
- `MOP-018` — `IN_PROGRESS` — A descriptor-backed bounded regular-file `mac_read_file` slice has canonical target binding, independent content-root enablement, final-symlink/special-file denial, single-link enforcement, local-volume restriction, canonical secret checks before I/O, post-read identity stability, strict encoding handling, range hashing, and audit identity. Remount identity, configurable secret corpus, syscall timeout/cancellation, packaging, and release evidence remain.
- `MOP-019` — `IN_PROGRESS` — Bounded local success and adversarial metadata/content-read cases pass on the real Mac; clean-revision, installed-service, full filesystem/secret, and production policy evidence remain.

## P2 — Remote Edge

- `MOP-020` — `PLANNED` — Implement MCP initialize, tool discovery, health, and stable error mapping.
- `MOP-021` — `IN_PROGRESS` — The MCP Edge accepts an injected OAuth verifier, requires expiry and exact resource binding, projects only known scopes into immutable Broker principal context, and proves bearer tokens do not cross IPC. Real issuer integration, subject mapping policy, revocation latency, rate limits, and client interoperability remain open.
- `MOP-022` — `PLANNED` — Implement Edge-to-Broker signed request construction.
- `MOP-023` — `PLANNED` — Implement client/session rate limits and bounded discovery.
- `MOP-024` — `IN_PROGRESS` — Broker session/principal/Edge/key revocation and request/session expiry pass local tests. Remote issuer revocation, refresh/session lifecycle, propagation latency, and active-work behavior remain open.
- `MOP-025` — `PLANNED` — Select authenticated HTTPS/tunnel deployment and verify a real client end to end.

## P3 — L0/L1 inspection

- `MOP-030` — `IN_PROGRESS` — Implemented bounded `mac_system_summary` with sanitized host facts and optional load; storage analysis, volume bounds, and release evidence remain.
- `MOP-031` — `PLANNED` — Implement process, network, service, and approved-log inspection tools.
- `MOP-032` — `IN_PROGRESS` — Descriptor-backed `mac_stat_path` is implemented with signed metadata roots, canonical readback, same-volume containment, deny-zone revalidation, and audit identity. Directory listing, bounded tree, recent-file metadata, packaging, and release evidence remain.
- `MOP-033` — `PLANNED` — Implement file discovery and bounded text search.
- `MOP-034` — `IN_PROGRESS` — The initial bounded safe-file-read handler is implemented. Full-file/range hash semantics, binary policy, secret controls, and expanded read behavior remain.
- `MOP-035` — `PLANNED` — Implement project discovery and project summary.
- `MOP-036` — `IN_PROGRESS` — Traversal, root/target symlink, deny-inside-allow alias, root `/`, metadata target-swap, content-read intermediate-symlink target-swap, multiply-linked inode denial, and post-authorization mutation tests pass. Unicode/case behavior, remount identity, broader special files, create-target races, and resource exhaustion remain.
- `MOP-037` — `IN_PROGRESS` — Broker-mandatory F0/F1 path rules cover representative SSH, GPG, cloud, Docker, Kubernetes, Keychain, Mail, Messages, Safari, Chrome, Photos, dot-env, and credential files; returned byte ranges are denied on representative private-key/token/credential signatures without audit leakage. Configurable classification, split-range signatures, false-positive corpus, and broader no-secret-output regressions remain.

## P4 — L2 developer operations

- `MOP-040` — `PLANNED` — Implement Git status, diff, log, and branch metadata.
- `MOP-041` — `PLANNED` — Implement package-manager inspection.
- `MOP-042` — `PLANNED` — Implement Docker status, object inspection, and bounded logs without arbitrary socket proxying.
- `MOP-043` — `BLOCKED` — Implement named task profiles. `blocked_by: MOP-086`; `unblock_condition: per-tool functional schemas remain complete and sandbox/credential-isolation evidence passes`; `expected_evidence: hostile task-profile PoC, resource-bound tests, and L2 release-gate evidence (VT-SBX-01, VT-SBX-02)`.
- `MOP-044` — `IN_PROGRESS` — Owner-bound `mac_job_status` and `mac_job_cancel` handlers, bounded output, durable cancellation intent, queued cancellation, terminal idempotency, and restart reconciliation are implemented and schema-tested. Running cancellation remains accepted/pending until MOP-086 provides process-tree ownership and verified termination evidence.
- `MOP-045` — `BLOCKED` — Prove child processes cannot access Edge/Broker/controller credentials or exceed filesystem/network policy. `blocked_by: MOP-086`; `unblock_condition: real-Mac hostile sandbox PoC passes or task capability is restricted/removed`; `expected_evidence: credential canary, filesystem, network, process, Docker, and persistence isolation evidence (VT-SBX-01, VT-SBX-02)`.
- `MOP-046` — `IN_PROGRESS` — Implemented a disabled `mac_write_file_atomic` Broker/native prototype with independent write-root policy, exact approval binding, secret-content denial, descriptor identity checks, atomic same-directory rename, expected hash/create-only preconditions, explicit idempotency key, Broker Job Ledger linkage/status lookup, restart-to-`UNKNOWN` recovery, readback verification, and focused tests. Release remains gated by controlled-write recovery, crash/partial-mutation, target-swap, and final readback evidence (`MOP-013, MOP-015, MOP-017, MOP-082, MOP-083`; VT-FS-01, VT-FS-02, VT-APR-01, VT-AUD-01, VT-REL-01).
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

1. Close `MOP-080` through `MOP-083` before implementing authority-sensitive handlers.
2. Establish test IDs and automated matrix checks through `MOP-007` and `MOP-085`.
3. Execute `MOP-086` before implementing or enabling `mac_task_run`.
4. Decide `MOP-003` and create the runtime/package baseline.
5. Review the `KB_SYNC.md` writeback manifest before any upstream KB mutation.
6. Implement the local Broker vertical slice before selecting production remote transport.

## Definition of Done

A task is `DONE` only when implementation, focused verification, affected regression and security checks, real-Mac evidence where relevant, documentation updates, and final repository readback are complete. Code existence alone is insufficient.

## Related documents

See `EPIC.md`, `ROADMAP.md`, `PROGRESS.md`, `VERIFICATION.md`, and `docs/adr/README.md`.
