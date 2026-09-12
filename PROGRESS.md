# Mac-Operator-MCP Progress

Status: Phase 1 Broker and authenticated MCP Edge foundation in progress
Version: 0.1
Last verified: 2026-09-12

## Current situation

The accepted documentation baseline is commit `2e389b8`; the current committed implementation baseline is `8bc038a`, which adds governed L0/L1 recent-file metadata alongside file discovery, process inspection, file hashing, directory listing, and depth/entry-bounded directory trees with same-volume entry filtering. Shared contracts, a Broker core, authenticated Unix-socket transport, an authenticated MCP 2026-07-28 HTTPS Edge factory, SQLite prototype persistence, tests, and developer commands are present. No public deployment, installed service, deployment artifact, privileged helper, or production-enabled tool exists.

## Completed work

- Created the Git repository and initial commit.
- Established LF text normalization through `.gitattributes`.
- Created the initial KB planning set for goal, design, specification, security, Epics, roadmap, tasks, progress, tool contracts, and the 44-tool catalog.
- Selected the high-level topology: Remote MCP Edge to authenticated local IPC to Mac Local Broker to adapters, with separate audit and privileged boundaries.
- Selected the governing security direction: Broker final authority, default deny, secret deny zones, bounded execution, redacted audit, kill switches, and no unrestricted shell or root interface.
- Completed an architecture deep dive identifying identity-chain, path-race, child-process isolation, active revocation, mutation recovery, GUI target, and tool-lifecycle requirements.
- Materialized, reviewed, verified, and committed the repository documentation baseline through `MOP-002`.
- Started documentation-only remediation against the newer KB SSOT: repaired stale dynamic-state ownership; materialized locked Security, Filesystem Policy, Tool Contract Standard, and Tool Catalog documents; added threat, scope, persistence, verification, ADR, sandbox-research, navigation, testing, configuration, deployment, operations, incident, rollback, and kill-switch documents.
- Resolved the two representation conflicts: every contract now has deterministic `audit_class` and structured `postcondition_verification`, and the legacy contract `phase` field is now canonical `tool_delivery_wave`.
- Completed MOP-084 functional API schema materialization: all 44 planned tools now have explicit bounded `input_schema` and tool-specific `output_schema` objects integrated with the common result envelope. Envelope validation, functional schema compilation, semantic review, authority-surface review, and catalog parity pass; runtime compatibility remains a separate gate.
- Prepared the KB writeback manifest without changing KB-MCP; orchestration review is still required before upstream synchronization.
- Accepted TypeScript/Node 24+ for the Edge/Broker baseline under ADR-0001 and created npm workspaces for shared contracts and Broker code.
- Implemented signed payload binding, strict request parsing, timestamp/session expiry, persistent nonce/request replay denial, exact scope authorization, revocation, independent kill-switch primitives, bounded structured outputs, recursive audit redaction, and hash-linked audit records.
- Implemented local handlers for `mac_health`, `mac_capabilities`, `mac_policy_explain`, `mac_stat_path`, bounded `mac_read_file`, descriptor-backed `mac_hash_file`, bounded descriptor-backed `mac_list_directory`, and bounded `mac_directory_tree`; production defaults keep the filesystem handlers disabled.
- Implemented bounded `mac_system_summary` and `mac_process_list` Broker handlers and adapters. Host summary returns sanitized OS version, architecture, CPU, memory, uptime, and optional load facts; process inventory uses native metadata, bounded output, numeric owner labels, and no argv/environment exposure.
- Implemented bounded `mac_find_files` over explicitly authorized filesystem roots. Search runs in Broker-owned filesystem workers, uses metadata-only descriptor-backed traversal, filters protected entries before result construction, caps roots/results/visited entries/depth, and authorizes every requested root independently.
- Implemented bounded `mac_recent_files` over explicitly authorized metadata roots. Recent-file results use a Broker-owned worker, a Broker-bound time window, fixed traversal/result budgets, protected-entry filtering, independent per-root authorization, and no content reads.
- Implemented a mode-`0600` Unix-domain socket prototype with application-layer HMAC authentication and a 1 MiB request cap.
- Added functional input/output schemas for all 44 planned tools, a common stable failure schema, automated compilation/uniqueness checks, and implemented-handler conformance tests.
- Added an owner/mode/symlink/identity-checked authentication-key loader and a least-privilege macOS CI workflow; neither installs or enables a service.
- Implemented the signed-policy candidate: JSON Schema 2020-12, Ed25519 verification with a protected pinned public key, monotonic revisions, Broker-owned grants, exact typed target rules, deny-over-allow, static kill switches, atomic in-memory activation, and request-to-policy-version binding.
- Implemented Edge key IDs and overlapping HMAC-key rotation windows. Signed policy authorizes exact Edge/key validity metadata, protected local files provide secret bytes, and persisted key-specific revocation overrides both.
- Implemented an MCP SDK v2 Edge candidate for the 2026-07-28 protocol: OAuth bearer verification is injected, token resources are checked, bearer secrets never cross IPC, capability discovery is caller-filtered, a fresh MCP server is built per request, legacy protocol traffic is rejected, and HTTPS requires TLS 1.3 plus Host/Origin allowlists.
- Added bidirectional request/response HMAC domain separation. Edge verifies the socket owner/mode and a response proof bound to the exact request and complete Broker result, so a replaced socket cannot forge success.
- Added startup verification for the redacted audit hash chain and an atomic migration from the legacy revocation table to key-specific Edge revocation support.
- Added a macOS N-API peer-credential adapter using `getpeereid` and `LOCAL_PEERPID`. Broker IPC now requires an injected UID/GID/PID policy and drops the connection before parsing when OS identity is denied or unavailable.
- Added Broker-owned HMAC key provisioning and retirement primitives: protected parent directories, exclusive `0600` creation, file/directory fsync, digest preconditions, mandatory persisted key revocation, quarantine rename, and unlink. No physical overwrite guarantee is claimed for APFS/SSD storage.
- Added signed filesystem metadata roots and a descriptor-backed macOS `mac_stat_path` handler. The native adapter opens and identifies the configured root and target, enforces same-volume canonical containment, reapplies deny zones after descriptor readback, and records canonical path plus device/inode evidence.
- Added adversarial metadata tests for traversal, root and target symlinks, deny-inside-allow aliases, root `/` containment, and a 2,000-iteration atomic symlink target-swap race. These are bounded dirty-tree prototype results, not closure of the L0/L1 filesystem gate.
- Added an independently enabled signed content-read root flag and a descriptor-backed `mac_read_file` prototype for regular files. It rejects final symlinks and special files, bounds byte ranges, validates UTF-8 strictly, caps base64 expansion, and records the opened device/inode; an intermediate-directory symlink race confirms successful reads never escape the root.
- Hardened content reads with Broker-mandatory secret path/signature rules that signed policy cannot disable, canonical-path authorization before descriptor I/O, single-link inode enforcement, local-volume enforcement, and post-read inode/link/size/mtime/ctime stability checks. Successful ranges carry a SHA-256 readback hash and consistent truncation state.
- Implemented a disabled `mac_write_file_atomic` L2 filesystem handler. Broker-owned policy roots must opt into `write`, exact approvals bind the canonical arguments and root target, content/path secret rules run before mutation, and the macOS native adapter uses same-volume descriptor identity, `openat` temporary files, `fsync`, atomic rename, create-only exclusion, expected identity/hash preconditions, and readback hash verification. Each write now requires an explicit idempotency key, creates a Broker-owned Job Ledger record, exposes its durable `job_id` for `mac_job_status`, and marks unresolved running outcomes `UNKNOWN` on restart. The handler is not enabled by default and its contract remains planned until controlled-write rollback, crash, and final readback gates are complete.
- Moved filesystem stat/read execution into Broker-owned worker threads with an empty environment, empty argv/execArgv, V8 memory/stack limits, a four-worker admission cap, per-tool deadlines, 25 ms active-authority polling, termination requests, and post-result authority revalidation. Timed-out workers retain capacity until actual exit, preventing unbounded timeout-driven thread creation.
- Moved process inventory execution into a separate Broker-owned worker boundary with empty environment/arguments, bounded V8 memory/stack settings, a two-worker admission cap, per-tool deadlines, active-authority polling, termination requests, and strict result validation. This keeps native process enumeration off the Broker event loop; it is still not a process-memory or OS sandbox boundary.
- Added bounded `mac_find_files` traversal to the same worker boundary with empty environment/arguments, a fixed 50,000-entry/32-level search budget, output validation, deadline/cancellation handling, and metadata-only root planning. It does not read file contents and protected paths are excluded before output or audit evidence.
- Added bounded `mac_recent_files` traversal to the filesystem worker with empty environment/arguments, metadata-only output validation, Broker-supplied clock binding, deadline/cancellation handling, and the same fixed traversal budget. It returns only canonical path, type, size, and modified time.
- Added runtime validation for worker success/error messages and tests for completion, capacity exhaustion, timeout, cancellation, environment canary isolation, and session revocation during execution. Worker threads protect the Broker event loop but are not a filesystem/network sandbox or process-memory isolation boundary.
- Started MOP-086 real-Mac sandbox research. A redacted host record proves partial canonical filesystem/symlink, executable-allowlist, network-deny, and fake credential-canary behavior with deprecated `sandbox-exec`; it also proves inherited environment visibility and that a child can survive parent termination, leaving process-tree, real credential, Docker, persistence, cleanup, and allowlisted-network guarantees unresolved. `mac_task_run` remains disabled.
- Added a disabled `ProcessSupervisor` prototype for the future Broker-owned task boundary. It requires a Broker-resolved canonical executable/cwd, no shell string, explicit allowlisted and size-bounded environment, detached process group, fixed stdio, bounded arguments/output, timeout, cancellation, TERM/KILL escalation, descendant cleanup, and capacity accounting; it is not connected to `mac_task_run` or a production policy.
- Added a disabled Broker-owned `TaskProfileRegistry` boundary for named L2 tasks. It resolves only fixed profile executables, canonical cwd roots, profile-owned environment, fixed filesystem/network declarations, anchored argument allowlists, sandbox profile IDs, and bounded budgets; user arguments cannot choose an executable or inject environment. It produces a `ProcessExecutionRequest` for a future sandboxed executor but does not execute or enable `mac_task_run`.
- Added a SQLite Job Ledger with principal-scoped payload-bound idempotency, revision-checked transitions, owner/session/tool/target/policy identity, bounded secret-sanitized output, cancellation state, and terminal outcome invariants. Startup recovery maps abandoned queued jobs to `cancelled` and running jobs to `unknown`, with hash-linked recovery audit events.
- Implemented local `mac_job_status` and `mac_job_cancel` handlers against Broker-owned job identity. Dynamic job IDs resolve to the Broker-owned `job:owned` policy target; foreign jobs return `TARGET_NOT_FOUND`. Cancellation writes a payload-digest audit intent before state mutation, is idempotent for terminal jobs, and reports termination as pending for running jobs until an executor confirms it.
- Added a SQLite Request Ledger with atomic nonce/request admission, canonical payload binding, revisioned lifecycle states, and state-plus-audit transactions for decisions, mutation intent, and completion. Startup recovery fails interrupted reads/pre-dispatch mutations and marks dispatched mutations `UNKNOWN`; authenticated denials remain replay-reserved and no recovery path infers success.
- Added a Broker-owned Approval Ledger prototype. Single-use records bind both principals, tool/contract, normalized target, canonical arguments digest, policy version, approval class, attended mode and TTL. `mac_job_cancel` now fails closed without an exact approval; consumption, request linkage, mutation intent, and redacted audit evidence commit in one transaction, while revocation before `RUNNING` prevents dispatch.
- Added a separately authenticated `ApprovalAuthority` plus dedicated owner-only `ApprovalIpcServer` prototype for operator-issued approvals. Issuer/key identity, validity window, signed canonical payload, bounded preview digest, attended/unattended policy, durable issuance nonce, and approval decision/completion provenance are verified before one transaction persists the approval and audit evidence. Approval issuer key files reuse owner-only non-symlink `0600` loading/provisioning and revoke-before-retire deletion, with a separate durable `approval_key` revocation kind. A versioned owner-only key metadata document now atomically writes and reloads non-secret paths, revision, validity, and unattended flags with canonical payload digest readback; a BrokerStore-backed manager persists activation history, audits intent/completion, rejects revision rollback, and restores only an exact revision/digest after restart. Key bytes remain in separate protected files. It is not exposed through the remote MCP Edge and does not claim protected Keychain storage or a production UI.
- Materialized and compiled the versioned internal approval-issuance envelope at `schemas/approval-issuance.schema.json`; it rejects unknown fields and binds the approval payload, preview digest, issuance digest, and proof fields.
- Added `BrokerStore.admitApprovedJob`, an atomic future-task admission primitive that links nonce/request admission, authorized decision, exact approval consumption, mutation intent, principal-scoped idempotency reservation and queued Job creation. Idempotent retries return the original Job without consuming approval again; conflicting reuse rolls back the entire admission.
- Added a default-off, test-only fault-injection hook for the atomic admission phases. Reopening the SQLite store after failures at request, authorization, approval-consumption, and Job-insert boundaries verified that no request, audit event, approval consumption, or Job half-commits.

## Implementation status

- Runtime implementation: local foundation only; no meaningful whole-program percentage is claimed.
- Released tools: 0 of 44 planned.
- Implemented local Broker handlers: 15 of 44 planned.
- Enabled tools: 0 of 44 planned.
- Automated tests: 131 passing.
- Real-Mac execution evidence: bounded local foundation and partial sandbox research records on Mac mini M4/macOS 26.2; both are dirty-tree prototype evidence, not release evidence.
- Remote MCP deployment: none.
- Privileged helper: none.
- Machine-readable tool contracts: 44 of 44 materialized with unique KB provenance; all remain planned, not implemented or enabled.

Percentages beyond these objective counts are intentionally omitted because the delivery scope and estimates are not yet baselined.

## Contract schema status

- Contract envelope schema: complete and validated for all 44 materialized contracts. This covers identity, capability, policy, budgets, lifecycle, audit, delivery wave, provenance, and summary fields.
- Per-tool functional input/output schema objects exist and compile for all 44 contracts. Success schemas use `SUCCEEDED`; failures use the shared stable-error schema.
- Schema presence is complete. Semantic review, compatibility fixtures, and runtime conformance remain limited to the fifteen implemented handlers, so this is not a 44-tool implementation claim.

## Current phase

Phase 1 — Broker and Edge foundation with initial L0/L1 inspection slices. Runtime/package selection, signed-policy activation/rollback, HMAC plus macOS UID/GID/PID-authenticated local IPC, authenticated MCP introspection, sanitized system/process inspection, descriptor-backed path metadata, bounded regular-file reads, directory listing, depth/entry-bounded trees, and metadata-only file discovery run in tests. Production key distribution, native-adapter packaging/runtime compatibility, remote issuer integration, operational policy tooling, audit reliability, packaging, configurable secret/remount controls, and enforceable I/O deadlines remain open.

## Decisions recorded

- Keep Edge, Broker, adapters, Job Manager, Audit Store, and Privileged Helper responsibilities explicit.
- Treat the Broker as the sole final host authorization point.
- Keep L0-L5 as planning labels rather than inherited permission levels.
- Distinguish planned, implemented, and enabled tool states.
- Require durable audit intent before mutations and privileged actions.
- Bind filesystem authority to the resolved/opened target, not only a path string check.
- Treat repository task scripts as untrusted child code.
- Add idempotency, status lookup, and unknown-outcome reconciliation for mutations.
- Define revocation and kill-switch effects for queued and active work.
- Defer generic shell, GUI action, and privileged execution until their boundary evidence passes.

## Pending decisions

- Remote OAuth issuer and tunnel/provider deployment choice.
- Native peer-adapter packaging, Node socket-descriptor compatibility, Edge process-ID lifecycle, cross-process/keychain distribution, storage-level erasure limits, session concurrency, and canonicalization compatibility.
- Child-process sandbox technology on the target macOS version.
- Signer rotation/revocation, operator reload command, general schema-version framework, and rollback runbook.
- Audit backend, integrity, retention, and read-only outage behavior.
- Production filesystem allow roots, operator-configurable secret classifications, Unicode/case rules, and removable-volume identities.
- macOS packaging, signing, launch, update, and rollback strategy.
- Runtime compatibility fixtures and host conformance for unimplemented tools.
- KB-MCP writeback review for the resolved contract and progress changes.

## Blockers

There is no blocker to continued local implementation. Production enablement is blocked by protected Keychain/cross-process secret distribution, native peer-adapter packaging/compatibility, real OAuth issuer and remote transport integration, audit crash/disk/backup behavior, operational policy tooling, packaging, and clean-revision evidence. `node:sqlite` is prototype-only pending ADR-0005 evidence. Named task execution remains blocked by sandbox and credential-isolation proof. Controlled writes, GUI actions, public access, and the privileged helper remain closed behind their documented gates.

## Verification performed

- Confirmed accepted documentation baseline `2e389b8` and implementation baseline `8bc038a`; the exact-revision evidence record is refreshed after the governed process, hash, directory-listing, directory-tree, file-discovery, and recent-file slices.
- Confirmed all 44 catalog tools have one valid JSON materialization, a unique tool name, a unique KB item ID, preserved source text, and a catalog link.
- Confirmed the runtime catalog reports all 44 tools separately; fifteen have local handlers and the production default enables none.
- Confirmed all 44 contracts have one taxonomy-valid `audit_class` and one structured `postcondition_verification`; all remain `planned`.
- Confirmed canonical contracts contain `tool_delivery_wave` and no top-level legacy `phase` field; roadmap lifecycle phases remain separate.
- Validated all 44 contract envelopes and compiled all 44 functional input/output schemas; checked unique tool and provenance IDs, bounded fields, forbidden authority-field absence, and output/verification compatibility.
- Ran 131 automated tests covering the identity, IPC, Edge, policy, filesystem metadata/content/hash/list/tree/find/recent/write adapters, system/process-summary adapters, native process inventory, worker, secret, audit, contract, Request/Approval/Job Ledgers, authenticated approval issuance, protected issuer-key lifecycle, named task profile boundary, and disabled process supervisor, including bounded recent-file windows/results/visited entries/depth, bounded search roots/results/visited entries/depth, independent multi-root authorization, protected-entry filtering, bounded process output and numeric owner redaction, bounded directory pagination/tree depth and protected-entry filtering, exact write-approval binding, durable write-job idempotency/status/restart recovery, descriptor-backed create/replace, expected hash and create-only preconditions, atomic rename/readback, descriptor-backed SHA-256/SHA-512 hashing without content return, hash target-change rejection, symlink/intermediate escape rejection, issuer/key authentication, preview binding, issuance replay denial, attended/unattended profile gating, durable approval-key revocation, revoke-before-retire deletion, versioned key metadata atomic write/reload and digest readback, persisted monotonic activation, exact restart restore, activation audit, rollback rejection, fixed executable/cwd/environment selection, anchored argument allowlists, symlink/duplicate/revoked config rejection, expiry/revocation/exhaustion, competing consumption, pre-dispatch invalidation, atomic future-job admission, idempotent reuse, conflict rollback, fault-injected admission rollback and restart readback, atomic replay admission, revisioned request lifecycle, fail-closed restart reconciliation, owner isolation, cancellation, explicit environment/argument/cwd validation, bounded output, process-group timeout/cancellation, descendant cleanup, capacity accounting, and schema conformance.
- Recorded initial real-Mac sandbox evidence in `SANDBOX_RESEARCH.md` and `evidence/2026-09-12-sandbox-research.json`; the result is explicitly partial and does not unblock `mac_task_run`.
- Recorded bounded host evidence in `evidence/2026-09-12-local-broker-foundation.md`.

The passing tests prove only the local foundation, bounded filesystem workers/search, and initial persistent Request/Approval/Job Ledgers on the recorded clean revision. They do not satisfy a release gate or prove protected Keychain-backed secret storage, installed cross-process code identity, a human approval UI/channel, production unattended profiles, remote deployment, removable-volume remount identity, process-tree ownership/termination, credential isolation, sandbox, GUI, helper, packaging, or whole-service rollback.

## Next steps

1. Close native peer-adapter packaging/runtime compatibility and cross-process/keychain distribution under `MOP-081`.
2. Integrate a real OAuth issuer and test MCP metadata, expiry, revocation, scope reduction, rate limits, and Broker outage without exposing the Broker publicly.
3. Add policy-signer rotation/revocation and an operator-only reload/rollback runbook.
4. Connect `admitApprovedJob` to a sandboxed named-task handler only after MOP-086 isolation evidence passes, then connect running-job cancellation to verified process-tree ownership.
5. Keep task execution, writes, GUI, public deployment, and helper capabilities disabled until their gates pass.

## Related documents

See `README.md`, `TASK.md`, `VERIFICATION.md`, and `docs/adr/README.md`.
