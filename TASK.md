# Mac-Operator-MCP Task Ledger

Status: Active
Version: 0.1
Last verified: 2026-09-14

Real process-kill-switch addendum: an opt-in Darwin integration flips the
durable `process` switch during a running task, verifies process-group drain,
and keeps the Job `unknown` after `CANCELLED`. Evidence:
`evidence/2026-09-14-real-broker-task-kill-switch.md`.

Real active-revocation addendum: an opt-in Darwin integration revokes a
session during a running `/bin/sleep` task, verifies process-group drain, and
keeps the Broker Job `unknown` after returning `CANCELLED`. Evidence:
`evidence/2026-09-14-real-broker-task-revocation.md`.

Real Broker task-path addendum: an opt-in Darwin integration now proves the
signed `mac_task_run` request can traverse Broker admission, single-use
approval, Job linkage, the experimental `SandboxExecTaskRunner`, and verified
readback. The default policy remains disabled; production execution is still
blocked by MOP-086. Evidence:
`evidence/2026-09-14-real-broker-task-path.md`.

Status values: `DONE`, `IN_PROGRESS`, `PLANNED`, `BLOCKED`. Completion requires repository evidence. Current implementation, test, and working-tree state is owned by `PROGRESS.md`; this ledger records task status and acceptance evidence. `BLOCKED` is reserved for an evidenced unmet prerequisite, not merely future-phase placement. Every blocked task records `blocked_by`, `unblock_condition`, and `expected_evidence`.

Privileged-helper source-composition addendum: commit `1405b99` adds an
independent-source composition boundary for launchd, native process, plist,
runtime, and signature readback. It rejects service identity, state, type,
PID, argv, plist-path, and process-identity substitution before readiness.
Real root installation remains open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper executor addendum: commit `56ab0ca` forces the host-only
lifecycle executor to accept raw readback sources and compose the final
readback internally, preventing a preassembled-readback bypass. Root-owned
installation remains open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper host-adapter addendum: commit `a3d7765` wires bounded
`launchctl print`, native PID/start-time capture, descriptor plist reading, and
strict `codesign` verify/details parsing into the observer factory. Runtime
metadata remains helper-owned input; no root service is installed. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper observer addendum: commit `30b69df` re-reads launchd,
PID/start-time, and plist identities before composition and rejects replacement
during collection. The observer fixture covers success and PID-swap failure;
real root installation remains open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper plist addendum: commit `d3efae1` requires the exact
root-domain plist path, rendered byte count, SHA-256, and descriptor
device/inode identity in helper readback; descriptor-backed reads reject
target swaps and tampering. Root-owned installation and real helper readback
remain open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper identity addendum: commit `cc103a7` requires a positive
launchd PID and matching native PID/start-time identity in every helper
readback; missing, null, mismatched, or non-positive values fail closed. This
remains a contract-only hardening change; root-owned installation and real
helper readback remain open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper readback addendum: commit `8fd5814` carries the exact native
helper `ProgramArguments` vector into the root-domain LaunchDaemon readback and
rejects missing, reordered, or substituted arguments. This is a contract-only
hardening change; root-owned installation and real helper readback remain open.
Evidence: `evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Installer readback addendum: commit `6da24f6` requires a positive launchd PID
and matching native PID/start-time identity in every post-bootstrap Broker
readback. The host composition layer must obtain that identity from the native
observer; installed LaunchAgent/bootstrap and final real-service evidence remain
open. Evidence: `evidence/2026-09-13-installed-readback-identity.md`.

Verified launchd readback addendum: commit `4cb4e1a` adds
`composeMacOsInstallReadback`, binding the bounded launchd service identity,
running state, LaunchAgent type, PID, program, and plist path to the native
process identity before Broker/signature validation. It remains a non-installing
host composition boundary; real LaunchAgent bootstrap and final service evidence
remain open. Evidence: `evidence/2026-09-13-installed-readback-identity.md`.

Final plist readback addendum: commit `70ca1e9` requires descriptor-backed
plist identity and SHA-256 content matching the rendered plan, with canonical
`/var`/`/private/var` path handling and tamper/truncation rejection. Real
LaunchAgent bootstrap and installed-service evidence remain open. Evidence:
`evidence/2026-09-13-installed-readback-identity.md`.

Exact-arguments readback addendum: commit `9d90138` parses bounded launchd
arguments and requires the exact planned Node binary plus Broker entrypoint;
missing or substituted arguments fail closed. Generic system-service readback
remains compatible when launchd omits arguments. Real LaunchAgent bootstrap and
installed-service evidence remain open. Evidence:
`evidence/2026-09-13-installed-readback-identity.md`.

Live launchd readback addendum: a reversible physical-macOS smoke bootstrapped
and booted out a unique temporary user LaunchAgent running only `/bin/sleep`.
The production readback adapter parsed the live service and exposed a real
macOS transient `state = xpcproxy`; that value is now normalized to
`launching` without claiming `running`. The separate service inspector applies
the same conservative mapping to `loaded`. Strict Edge/helper readiness still
requires `running` plus native PID/start-time identity. Focused launchd tests
pass 7/7 and the full real-sandbox suite passes 420/420. This does not close
signed production artifacts, installed Broker/Edge handshake, or real-package
upgrade/rollback/uninstall evidence. Evidence:
`evidence/2026-09-14-live-launchd-readback.md`.

The Edge identity capture path now retries only the observed `xpcproxy`
bootstrap state within a five-second global deadline. A second reversible live
LaunchAgent smoke captured a positive PID/start-time identity through that
path, then booted the service out and confirmed absence; stopped/malformed
states remain terminal failures. This strengthens startup readback but does
not claim an installed Broker/Edge service.

The Broker instance-lock boundary additionally has a real non-cooperating
process test: a child holds the owner-only lock, the parent is denied with
`ALREADY_ACTIVE`, and reclamation succeeds only after native PID/start-time
observation proves the child stale. Focused lock tests pass 5/5. This does not
claim launchd singleton enforcement or remount durability. Evidence:
`evidence/2026-09-14-service-instance-lock-process.md`.

Current-host sandbox addendum: `MOPS_REAL_SANDBOX=1 npm test` passed 430/430
with one explicit non-sandbox skip on the Darwin arm64 host. Environment and
protected-surface denial, single-process fork/setsid and external-network
denial, selected loopback allowlisting, and active process-group cancellation
all ran successfully. This strengthens MOP-086 evidence but leaves its
deprecated-`sandbox-exec` production decision, post-snapshot descendants,
remounts, credential contents, and `mac_task_run` enablement open. Evidence:
`evidence/2026-09-14-real-sandbox-regression.md`.

Current runner-binding addendum: `TaskRunner` now declares the exact host
sandbox mechanism alongside `TaskIsolationProof`. Broker admission and task
dispatch reject missing or mismatched declarations before consuming approval or
launching a child process; `mac_task_run` remains disabled.

Install-plan readback hardening is committed locally. The host-only install
plan now has a physical-Mac package smoke that calls the
real executor with only independent launchd, native PID/start-time, plist,
Broker-status, and signature sources. It waits through transient `launching`,
double-reads mutable identities, starts a temporary zero-capability Broker
under a user LaunchAgent, and completes exact uninstall with final absence.
The package uses ad-hoc signing and the host observer now supports a distinct,
HMAC-authenticated Broker status socket with native peer credentials and
durable replay rejection. The recorded package smoke still used its historical
owner-only fixture; Developer ID, production artifact provenance,
upgrade/rollback, remote Edge, and helper installation remain open. Evidence:
`evidence/2026-09-14-live-install-plan.md` and
`evidence/2026-09-14-broker-status-ipc.md`.

The real Broker startup assembly now has a physical-host smoke: a temporary
user LaunchAgent supplied the native PID/start-time identity, signed policy and
Edge-key activations were restored from a temporary BrokerStore, and the
native Broker socket started with zero enabled capabilities and mode `0600`.
Close removed the socket and cleanup booted out the temporary service. This is
startup-assembly evidence, not installed-package, Edge request-exchange,
Developer ID, or privileged-helper evidence. Evidence:
`evidence/2026-09-14-live-broker-startup.md`.

Packaging-shape addendum: the repository now carries a reviewable Edge
LaunchAgent template beside the Broker template. The deployment notes bind
Edge launchd identity/readback before Broker startup and keep the Broker status
socket as a separate authenticated operator/readback channel. A static
template regression rejects shell, environment, user, and privileged fields;
this does not claim persistent installation or signing provenance.

## P0 — Foundation

- `MOP-001` — `DONE` — Git repository, npm workspace/package baseline, developer commands, dependency lockfile, ignore rules, and a least-privilege macOS CI definition exist. First remote CI execution remains verification evidence rather than bootstrap scope.
- `MOP-002` — `DONE` — Materialized and synchronized GOAL, DESIGN, SPEC, EPIC, ROADMAP, TASK, PROGRESS, and GOAL_PROMPT with repository-state, consistency, whitespace, task-ID, and prompt-length checks.
- `MOP-003` — `DONE` — Accepted TypeScript/Node 24+ for Edge/Broker/shared contracts; Swift remains available for native adapters/helper. Package direction and prototype evidence are recorded in ADR-0001.
- `MOP-004` — `IN_PROGRESS` — Versioned request/result/failure/principal/scope types, signed policy schemas, and a shared stable failure schema exist. A versioned `schemas/ledger-records.schema.json` now machine-validates bounded Request, Approval, Job, and Audit record envelopes, including typed privileged payloads and rejection of raw authority fields; persistence runtime validation remains the implementation authority. Host-only SQLite backup/restore/retention primitives now add owner-only atomic publication, audit-chain/SQLite integrity checks, fresh-target restore refusal, numeric timestamp retention, and symlink/ownership/mode/size/target-swap guards. Mutation-state invariants, encrypted/protected backup storage, disk-exhaustion behavior, general migration policy, and final ADR acceptance remain incomplete.
- `MOP-005` — `DONE` — Materialized the locked capability taxonomy, lifecycle, catalog, standard, and all 44 KB tool contracts with unique provenance, deterministic mandatory fields, and canonical delivery-wave naming. Upstream KB writeback is tracked separately in `KB_SYNC.md`.
- `MOP-006` — `DONE` — Created the initial threat model for remote client, Edge, IPC, Broker, adapters, child processes, GUI, helper, audit, policy, and secret stores, with verification targets.
- `MOP-007` — `IN_PROGRESS` — Strict typecheck, build, Node test, AJV contract validation, dependency audit, unit/integration/adversarial foundation tests, a dependency-free tracked-file style/lint check, and a least-privilege macOS CI workflow exist. First remote CI evidence remains pending.
- `MOP-008` — `IN_PROGRESS` — Established the initial evidence and verification matrix; machine enforcement and real evidence remain pending the test baseline.

## P0 — Architecture closure

- `MOP-080` — `IN_PROGRESS` — Freeze exact scope, principal, session, parameterized-target, wildcard, inheritance, and revocation semantics. Depends on ADR-0002 and ADR-0004 acceptance.
- `MOP-081` — `IN_PROGRESS` — Exact Edge/key identity, signed key metadata, protected/exclusive key provisioning, revoke-before-retire deletion, overlapping rotation, validity windows, key-specific revocation, request/response policy-key binding, replay persistence, forged-socket response rejection, macOS UID/GID/PID peer verification, optional native PID/start-time peer identity binding, legacy revocation migration, a BrokerStore-backed monotonic activation/restore guard, and a native public-`Socket({ fd })` IPC candidate are implemented and tested. Edge key metadata now has an owner-only versioned loader requiring an explicit `file` or `keychain` source, an expected secret-byte digest, protected config target readback, BrokerStore revocation preflight, and a BrokerStore-backed monotonic activation/restore manager with exact restart matching and audited activation; the owner-only Authority Control channel now has a dedicated `authority_key` source/loader with digest, validity, audited activation, exact restore, revocation, and host uninstall client assembly. The Edge request factory has matching protected-file and opt-in native peer-authenticated Keychain delivery factories using a fresh challenge, strict bounded messages, replay rejection, fixed service/account startup binding, response digest checks, and no environment-variable or MCP-argument fallback. The Edge IPC client checks the owner-only socket parent and revalidates socket device/inode identity after connect before sending request bytes. LaunchAgent startup now restores the exact active key config before launchd PID/start-time capture and native runtime construction, injecting the restored keyring through a Broker factory; unactivated, changed, or cross-Edge config fails before `launchctl` readback. Overlapping source-backed rotation remains startup/configuration-only without installed hot reload. The protected native adapter loader rejects non-canonical/symlinked, writable, foreign-owned, oversized, changed, or incomplete `.node` artifacts before use, binds Node's cached module to the first artifact's device/inode/size/digest, requires all 19 production native exports including non-interactive Keychain read/provisioning, checks compiled N-API compatibility with the active runtime, and is the only production consumer path for filesystem, process, network, and process-tree adapters. The macOS native build now fails closed if `/usr/bin/codesign --verify --strict` cannot validate the emitted adapter, but the observed artifact remains ad-hoc signed only. The production runtime now captures a running Edge PID from an exact per-user LaunchAgent readback, binds its native start time before listening, monitors the identity, closes the native listener on identity loss, and durably revokes the Edge; this is startup-assembly evidence only and is not installed Edge/launchd evidence. Developer ID code identity/provenance, notarization, Node/runtime version pinning beyond N-API compatibility, Edge PID lifecycle packaging, Keychain ACL review, live-item rotation/deletion, physical-erasure limits, session concurrency, cross-runtime canonicalization, and general corruption/migration handling remain open. Evidence: `evidence/2026-09-13-edge-key-source-rotation.md`, `evidence/2026-09-13-edge-keychain-delivery.md`, and `evidence/2026-09-13-authority-key-activation.md`.
- `MOP-082` — `IN_PROGRESS` — Broker-owned single-use approval records bind approver/requester, tool/contract, normalized target, arguments digest, policy version, approval class, attended mode and TTL. Exact consumption is atomic with request intent; substitution, expiry, revocation, exhaustion, competing use, missing approval, and pre-dispatch invalidation tests pass. A separately authenticated issuer prototype now binds issuer/key identity, signed payload, preview digest, issuance nonce, attended/unattended policy, and decision/completion provenance before persistence. Owner-only issuer-key file loading/provisioning and a separate durable `approval_key` revocation kind pass revoke-before-retire tests. A versioned owner-only metadata config atomically rotates and reloads non-secret key paths with revision/digest readback; BrokerStore activation history now rejects rollback and startup restore requires the exact persisted identity. Protected Keychain/cross-process storage, human approval UI/channel, unattended profile ownership, privileged approval, active-work semantics and ADR acceptance remain.
- `MOP-083` — `IN_PROGRESS` — SQLite Request records atomically bind nonce admission, request/payload identity, lifecycle, decisions, approval-backed mutation intent, completion, and restart-safe recovery to audit evidence. Single-use Approval records and Job records persist their bounded identities and state. `admitApprovedJob` atomically binds future-request approval/intent/idempotency/new-job creation with idempotent reuse and conflict rollback, while `admitApprovedJobAfterDecision` atomically binds the already-authorized task path's approval consumption, intent audit, and queued Job linkage with owner/target/payload/timestamp preconditions. Fault-injected rollback proves the post-decision path leaves no partial approval, intent, or Job; restart reconciliation fails an authorized-but-not-intented request closed without consuming approval. Generic authority switches and revocations now persist redacted intent/completion audit pairs in the same transaction as the authority change and queued-job cancellation, and the separate Authority Control IPC durably admits its request/nonce before applying only bounded switch/revocation operations. Job execution now persists owner/token/expiry/heartbeat leases and fences stale terminal commits. Host-only `backupTo`, `restoreBackup`, and `pruneBackups` measure source/destination capacity before writing, provide atomic owner-only snapshots, SQLite/audit-chain verification, fresh-target restore, numeric retention, and fail-closed symlink/ownership/mode/size/target-swap checks. Crash recovery removes stale hidden backup and WAL/SHM sidecar temporaries, simulated `ENOSPC` and insufficient-capacity preflight return retryable `AUDIT_UNAVAILABLE`, and a two-process writer test preserves the audit chain with a bounded SQLite busy timeout. Process-tree ownership, real kernel/disk exhaustion, encrypted backup storage, explicit single-owner service policy, general migrations, and ADR-0005 acceptance remain.
- `MOP-084` — `DONE` — Contract envelope and per-tool functional `input_schema`/`output_schema` objects are complete for all 44 tools. Envelope validation, functional schema compilation, semantic review, authority-surface review, and catalog parity pass. The mandatory audit taxonomy, structured postcondition field, and `tool_delivery_wave` migration are closed. This documentation/schema closure does not implement runtime behavior or close `MOP-004` or `MOP-080..083`.
- `MOP-085` — `IN_PROGRESS` — Maintain Requirement -> Threat -> Task -> Test -> Evidence -> Release Gate traceability. Depends on test IDs from `MOP-007` and contracts from `MOP-084`.
- `MOP-086` — `IN_PROGRESS` — Initial real-macOS sandbox probe is recorded in `SANDBOX_RESEARCH.md` and `evidence/2026-09-12-sandbox-research.json`. Commit `2e6cd57` adds a disabled-by-default `SandboxExecTaskRunner` and Broker-owned deny-default profile renderer: resolved profiles default to `processTreePolicy: single_process` without `process-fork`; `owned_group` profiles may render the explicit fork rule but the runner now refuses to enable them even with an external proof until a separate process-tree decision is accepted. `TaskIsolationProof` binds the explicit sandbox mechanism and selected process-tree policy and rejects proof reuse across variants. The opt-in host smoke reads/writes an allowed temporary root, denies `/private/etc/passwd`, a root-contained `.env`, an outside-file symlink, and existing `.ssh`, `.docker`, Chrome, Safari, Mail, Messages, and Keychains surfaces plus `/var/run/docker.sock` readability, without opening their contents; it filters controller/`HOME`/SSH-agent/AWS_PROFILE environment canaries, allows only a selected loopback `tcp` destination, denies an unlisted loopback port and external curl DNS/network access, rejects a Bash child-launch attempt, and maps active `/bin/sleep` cancellation to detached process-group termination. Source `01a26ba` adds a real-Mac Perl hostile-descendant fixture: `fork()`/`setsid()`/marker-write returns `fork-denied` under `single_process`, with no marker left behind; the focused sandbox suite passes 8/8 and the full `MOPS_REAL_SANDBOX=1` suite passes 387/387. The new shared environment policy rejects task-profile `PATH`, `NODE_OPTIONS`, dynamic-loader, interpreter-startup, temp-directory, and arbitrary Git/Docker configuration keys; fixed adapters retain only exact explicit non-secret keys. Filesystem/symlink, executable-allowlist, network-deny, fake credential-canary, and Broker launch file-descriptor behavior remain partial evidence; real credential/Docker/persistence isolation, owned-group or post-snapshot `setsid` ownership, descendants created after the last persisted snapshot, remount behavior, external allowlisted networking, and UDP behavior remain open. A disabled Broker `ProcessSupervisor` plus named `TaskProfileRegistry` prove explicit profile-owned executable/cwd/args/environment/stdio budgets, non-inherited descriptor canary behavior, bounded detached process-group drain/readback, shared live adapter ownership, exact PID/start-time recovery for a live root plus an observed detached descendant after BrokerStore reopen, and conservative `UNKNOWN` handling when an empty post-exit snapshot cannot prove absence; `SandboxExecTaskRunner.close()` and `Broker.close()` now forward that boundary. Broker admission additionally requires a versioned profile-matched `TaskIsolationProof` covering the explicit sandbox mechanism, sandbox, filesystem, network, credentials, process-tree, and selected process-tree policy guarantees; the fail-closed `mac_task_run` Job/approval handler remains unwired to a production runner. Still blocks `MOP-043`, `MOP-045`, and `mac_task_run` enablement.
- `MOP-087` — `IN_PROGRESS` — Complete README navigation and testing, configuration, deployment, operations, incident, rollback, and kill-switch runbooks. Verified commands depend on runtime and packaging work.
- `MOP-088` — `DONE` — Resolved the two repo representation conflicts, recorded decision/rationale/migration/evidence, and prepared `KB_SYNC.md` for owner-reviewed upstream writeback. This documentation-only task does not mutate KB-MCP.

Authority-control note: generic runtime switches and revocations now append redacted hash-linked `intent`/`completion` audit pairs in the same persistence transaction as the authority change and queued-job cancellation. A separate owner-only, native-peer/HMAC/replay-bound Authority Control IPC now admits only switch and revocation commands and carries its request ID into those audit pairs. Its operator key is selected by a protected, digest-bound, monotonic activation manager with a dedicated revocation kind and exact restart restore, and the uninstall coordinator constructs its client from that manager. This does not close active process-tree termination, installed startup, or operator recovery evidence.

IPC ownership addendum: source revision `44cae6a` now probes configured Unix
socket paths before stale cleanup, rejects active listeners without unlinking
them, binds generic close cleanup to device/inode identity with a temporary
symlink barrier, limits native cleanup to the recorded listener identity, and
preflights the Broker socket before startup Job recovery. Repository-level
tests pass; installed launchd singleton enforcement and physical crash/remount
readback remain open.

Startup serialization addendum: source revision `0c34c65` adds an owner-only
runtime-root instance lock with exact PID/start-time identity. It is acquired
before socket preflight, BrokerStore access, and restart reconciliation;
duplicate live owners are rejected and stale locks are reclaimed only after
proof of owner death or PID reuse. Normal and failed startup cleanup paths
release the lock after resource disposal. Launchd install/bootstrap and
non-cooperating-process lock evidence remain open.

## P1 — Local Broker vertical slice

- `MOP-010` — `IN_PROGRESS` — Broker core plus local `mac_health`, `mac_capabilities`, `mac_policy_explain`, `mac_system_summary`, `mac_process_list`, `mac_process_inspect`, `mac_network_status`, `mac_service_status`, `mac_log_tail`, exact-target `mac_git_status`/`mac_git_branch_list`/`mac_git_log`, `mac_stat_path`, bounded `mac_read_file`, descriptor-backed `mac_hash_file`, bounded descriptor-backed `mac_list_directory`, bounded `mac_directory_tree`, metadata-only `mac_find_files`, metadata-only `mac_recent_files`, bounded secret-filtered `mac_search_text`, bounded `mac_project_discover`, bounded `mac_project_summary`, and bounded `mac_storage_analysis` handlers exist and pass tests. A fail-closed `LocalBrokerRuntime` now orders Broker IPC before operator channels, rolls back partial startup, retains failed cleanup for explicit recovery, and `createMacOsNativeBrokerRuntime` binds that lifecycle to the native Broker channel. The launchd startup assembly now restores the protected Authority key and places its separate native-peer channel under the same lifecycle. Installed launchd lifecycle, operator startup, listener ABI pinning, and production enablement remain open.
- `MOP-011` — `IN_PROGRESS` — Mode-`0600` Unix IPC, macOS `getpeereid`/`LOCAL_PEERPID`, optional native PID/start-time identity binding, domain-separated request/response HMAC authentication, and a shared native accept path for Broker, policy-signer, and approval channels that hands descriptors through public `Socket({ fd })` pass prototype tests, including OS identity denial and rejection of a replacement socket using another key. Separate spawned Broker and Edge package-process fixtures now complete a signed request/response across native UDS under the captured Edge PID/start-time identity and verify the Broker response proof. A bounded read-only launchd readback adapter and real system-service smoke are also present. The fixed Broker service entrypoint restores exact persisted Policy/Edge-key activation before native listener construction and wipes loaded Edge keys on close. Production key lifecycle, native packaging/code identity, Edge PID lifecycle wiring, and installed transport selection remain open under ADR-0002.
- `MOP-012` — `IN_PROGRESS` — Timestamp/session expiry, canonical payload binding, atomic nonce/request admission, persistent replay denial, terminal request lookup, and restart replay/reconciliation tests exist. Corruption, canonicalization cross-runtime, retention, and accepted persistence design remain open.
- `MOP-013` — `IN_PROGRESS` — Ed25519-signed policy loading, Broker-owned principal grants, exact typed target rules, deny-over-allow, default deny, immutable request snapshots, durable activation/rollback, policy-version binding, filesystem-root authorization, and unimplemented-tool enable rejection pass tests. The signer lifecycle now has a versioned owner-only metadata file, per-key public-key digests, bounded overlap/validity windows, monotonic activation and restart restore, audited durable key revocation, and a separate owner-only UDS operator channel with HMAC authentication, OS peer verification, replay persistence, reload, rollback, and revoke commands; it is not exposed through the MCP Edge. Installed startup wiring, native caller/process identity packaging, Keychain distribution, and the complete filesystem policy matrix remain open.
- `MOP-014` — `IN_PROGRESS` — A non-executing `mac_policy_explain` handler reports allow/deny, normalized query target, required/missing scopes, reason codes, and policy version. Path queries are mapped to Broker-owned signed root identities before authorization; remaining target types depend on MOP-013.
- `MOP-015` — `IN_PROGRESS` — Broker-owned request states commit atomically with decision, mutation-intent, and completion audit records; recursive redaction, a SHA-256 event chain, startup tamper rejection, and transactional policy intent/completion are implemented as prototype behavior. Crash/outage injection, retention, access control, stronger integrity/anchoring, and ADR-0005 acceptance remain open.
- `MOP-016` — `IN_PROGRESS` — Persistent global/capability-family switches plus principal/session/Edge revocation checks exist. Filesystem workers poll active authority, request termination, revalidate before returning success, and audit active revocation as `CANCELLED`; mutation writes now keep the Job `UNKNOWN` when a mutations kill switch trips before completion persistence. Disabling global/mutations/process/network switches now transactionally cancels applicable queued Jobs, and principal/session revocation does the same with conservative cancellation for identities whose queued-job provenance is not yet persisted. A separate owner-only Authority Control IPC enforces native peer identity, HMAC authentication, durable replay denial, strict operation allowlists, and expected-state switch preconditions. The host-only uninstall path now binds to its authenticated client with response proof, socket identity revalidation, bounded transport, and switch/revocation readback. Active process-tree termination, restart behavior, protected key distribution, installed startup, and operator recovery controls remain open.
- `MOP-017` — `IN_PROGRESS` — Bounded filesystem workers implement concurrency admission, per-tool deadline, active cancellation polling, termination requests, output caps, and post-result authority revalidation. Fixtures cover a real multi-root filesystem worker request, fixed-capacity overlap rejection, cancellation capacity release only after worker exit, an abrupt worker crash after a committed write that preserves an `UNKNOWN` Job while releasing capacity only after the exit event, explicit executor shutdown that terminates active workers and rejects new work, and a real `Broker.handle` stale-completion attempt rejected after a second `BrokerStore` reopen reconciles the Job to `UNKNOWN`. Broker admission rechecks authority immediately before starting a queued Job, while the Job Ledger persists queued cancellation, idempotency, and execution owner/token/expiry/heartbeat leases. The disabled ProcessSupervisor now binds the macOS root PID and descendants to start-time identities, registers runs before the first ownership observation, signals verified descendants in addition to the detached process group, suppresses group signalling when the root identity is unavailable, and fails closed when the native observer is unavailable; it waits for group and tracked-descendant disappearance before reporting observed termination, holds capacity while unresolved work is reaped, rejects new work after close, drains the shared Broker-owned OS process authority plus active task-runner process groups during live Broker shutdown, and supports explicit restart recovery using persisted exact PID/start-time snapshots while retaining UNKNOWN Job state; an observed detached descendant is recovered after root exit without relying on group membership, and an empty post-exit snapshot remains UNKNOWN rather than claiming absence. Descendants created after the last snapshot, post-snapshot `setsid` escape resistance, unknown-outcome recovery, and restart cleanup remain.
- `MOP-018` — `IN_PROGRESS` — Descriptor-backed bounded regular-file metadata, content-read, full-file `mac_hash_file`, bounded `mac_list_directory`, and depth/entry-bounded `mac_directory_tree` slices have canonical target binding, independent root policy, final-symlink/special-file denial, single-link enforcement where content is opened, local-volume restriction, plan-captured root volume identity, native `f_fsid`/filesystem-type checks, canonical secret checks before I/O, post-operation identity stability, strict encoding/digest handling, protected-entry filtering, and audit identity. Physical/removable remount evidence, configurable secret corpus, syscall timeout/cancellation, packaging, and release evidence remain.
- `MOP-019` — `IN_PROGRESS` — Bounded local success and adversarial metadata/content-read cases pass on the real Mac; a dedicated read-only host probe now records bounded system/network/process facts and `/System/Library` metadata/list/tree readback without active probes, content reads, credential access, or mutation. Clean-revision, installed-service, full filesystem/secret, and production policy evidence remain. Evidence: `evidence/2026-09-13-l0-l1-host-readback.md`.

## P2 — Remote Edge

- `MOP-020` — `IN_PROGRESS` — MCP SDK v2 initialize/modern protocol handling, Broker-filtered tool discovery, `mac_health` routing, stable Broker failure mapping, strict HTTPS Edge configuration, bounded connection budgets, and a real local HTTPS boundary probe are implemented and tested. A fixed packaged Edge service entrypoint now loads a strict owner-only, root-bound startup document, assembles the protected TLS/key/contract/JWT/IPC boundary, requires listener host/port readback, and wipes in-memory key material on close. A real RS256-authenticated MCP client now completes pinned `2026-07-28` discovery and reaches `mac_health` through the signed, peer-checked local Broker UDS; bearer material is absent from Broker audit rows. Pagination/notification behavior, separate packaged processes, remote deployment, and production key distribution remain. Evidence: `evidence/2026-09-13-governed-edge-service-entrypoint.md`.
- `MOP-021` — `IN_PROGRESS` — The MCP Edge validates signed JWT access tokens with pinned issuer/resource/audience, explicit asymmetric algorithms, bounded local/remote JWKS retrieval, controlled unknown-`kid` refresh cooldown, short token age, required identity claims, internal issuer-ID projection, known-scope filtering, and a fail-closed revocation callback. Startup also requires the configured OAuth issuer to match metadata and rejects non-HTTPS authorization/token endpoints. Local HTTPS tests verify bearer challenge/route ordering, metadata mismatch denial, official-client discovery, and in-process JWKS key rotation using a signed JWT; external issuer issuance/discovery, issuer-to-internal-ID operational mapping, live rotation/propagation latency, and remote client interoperability remain open; the local fixed-window rate limiter is tracked under MOP-023.
- `MOP-021` security addendum — Protected TLS certificate and private-key loading is implemented with owner-only regular-file checks, `O_NOFOLLOW`, canonical paths, bounded sizes, and device/inode stability readback. The fixed Edge startup loader additionally rejects weak/symlinked config, root escapes, and non-canonical target parents before constructing HTTPS. Remote issuer deployment, certificate rotation, Keychain storage, and installed Edge startup remain open.
- `MOP-022` — `IN_PROGRESS` — `EdgeRequestFactory` constructs canonical signed Broker requests with contract/protocol versions, policy audience/version, principal projection, timestamp, nonce, and key identity; `BrokerIpcClient` verifies the response proof against the exact request/result. The service-owned factory now exposes explicit disposal that wipes its HMAC key on shutdown. Cross-runtime canonicalization, protected production key distribution, and rotation/compatibility evidence remain.
- `MOP-023` — `IN_PROGRESS` — Implemented a bounded in-memory fixed-window Edge limiter after Bearer verification, keyed by verifier-provided client/principal identity, with fixed request/window/key budgets and `Retry-After` responses; Broker-filtered discovery is bounded. Shared multi-instance limits, durable counters, and real-client load evidence remain.
- `MOP-024` — `IN_PROGRESS` — Broker session/principal/Edge/key revocation and request/session expiry pass local tests; the JWT verifier accepts a host-owned revocation callback keyed by issuer/subject/session/jti. External issuer revocation, refresh/session lifecycle, propagation latency, and active-work behavior remain open.
- `MOP-025` — `PLANNED` — Select authenticated HTTPS/tunnel deployment and verify a real client end to end.

## P3 — L0/L1 inspection

- `MOP-030` — `IN_PROGRESS` — Implemented bounded `mac_system_summary` with sanitized host facts and optional load, local-interface-only `mac_network_status` with inferred connectivity, plus descriptor-verified, metadata-only `mac_storage_analysis` with capacity facts, ranked consumers, and fixed traversal budgets. The real Mac host probe now verifies system facts and interface state with listener enumeration/active probing disabled; listener ABI pinning, physical real-volume remount behavior, and release evidence remain.
- `MOP-031` — `IN_PROGRESS` — Implemented bounded native `mac_process_list` and `mac_process_inspect` with independent `mac.process.read` scope, process target authorization, numeric owner redaction, executable identity, CPU/memory bounds, parent/child PID bounds, sort/limit/PID validation, and no argv/environment exposure. The real Mac host probe verifies bounded inventory and current-process readback; network listener remains intentionally unavailable, while service status, allowlisted log inspection, exact-target Git status/branch/log/diff inspection, and the independent `mac.app.read` app inventory boundary are implemented through fixed adapters.
- `MOP-032` — `IN_PROGRESS` — Descriptor-backed `mac_stat_path`, bounded `mac_list_directory`, bounded `mac_directory_tree`, and metadata-only `mac_recent_files` are implemented with signed roots, canonical readback, plan/native volume-identity binding, same-volume containment, deny-zone revalidation, protected-entry filtering, fixed traversal/result limits, Broker-bound time windows, and audit identity. A real `/System/Library` metadata/list/tree probe now verifies canonical host readback with content reads disabled; physical remount and broader release evidence remain.
- `MOP-033` — `IN_PROGRESS` — Implemented bounded metadata-only `mac_find_files` and bounded secret-filtered `mac_search_text` over explicitly authorized roots with independent `mac.files.search` scope, per-root target authorization, descriptor-backed traversal, protected-entry/secret-content filtering, fixed entry/depth/result/text-byte budgets, worker cancellation, and strict result validation. `mac_log_tail` now preserves and redacts a supervisor-confirmed bounded output prefix on `OUTPUT_LIMIT`, reports explicit truncation, and fails closed on unresolved process outcomes. Packaging and release evidence remain.
- `MOP-034` — `IN_PROGRESS` — The bounded safe-file-read, full-file hash, descriptor-backed directory-list, depth/entry-bounded directory-tree, metadata-only file-discovery, and bounded content-search handlers are implemented. Binary policy expansion, secret controls, and broader read behavior remain.
- `MOP-035` — `IN_PROGRESS` — Implemented bounded metadata-only `mac_project_discover` and `mac_project_summary` with allowlisted marker types, safe manifest/language inference, bounded traversal/tree output, protected-entry filtering, dependency-directory pruning, per-root/root authorization, worker cancellation, strict result validation, and explicit VCS branch/dirty omission warnings. Packaging and release evidence remain.
- `MOP-036` — `IN_PROGRESS` — Traversal, root/target symlink, deny-inside-allow alias, root `/`, metadata/hash/content-read/list/tree target-change, content-read intermediate-symlink target-swap, protected directory-entry filtering, bounded depth/entry truncation, multiply-linked inode denial, post-authorization mutation, concurrent create-only target/symlink-swap, Unix-domain-socket generic-tool, FIFO/non-blocking pseudo-device, observed character/block-device, bounded pressure-budget, and real multi-root worker-capacity tests pass. Lexical case-alias rejection, NFKC-normalized Unicode search identity, and plan/native volume-identity guards are covered by adversarial fixtures. Physical remount identity, cross-volume normalization policy, broader device/pseudo-filesystem coverage, production-scale resource exhaustion, and kernel-blocked I/O recovery remain.
- `MOP-037` — `IN_PROGRESS` — Broker-mandatory F0/F1 path rules cover representative SSH, GPG, cloud, Docker, Kubernetes, Keychain, Mail, Messages, Safari, Chrome, Photos, dot-env, GitHub CLI, browser, and containerized Apple data paths; returned byte ranges are denied on representative private-key/token/credential signatures without audit leakage. Evidence redaction now covers protected paths with spaces, `/private/var/root`, Bearer/Basic credentials, and JWT-shaped values. Configurable classification, split-range signatures, false-positive corpus, and broader no-secret-output regressions remain. Evidence: `evidence/2026-09-13-secret-zone-redaction.md`.

## P4 — L2 developer operations

- `MOP-040` — `IN_PROGRESS` — Implemented governed Git status, diff, log, and branch metadata through exact project-root authorization, fixed `/usr/bin/git` commands, repository integration rejection, literal path/revision validation, bounded outputs, secret redaction, identity readback, and schema/conformance tests. Git log now preserves complete records from a supervisor-confirmed bounded prefix while rejecting unverified termination. A disabled-by-default controlled Git write prototype now adds explicit-path staging and local commit through Broker-owned Jobs, approval binding, fixed no-hook/no-network commands, staged-diff/HEAD/index/status readback, and fail-closed unknown-outcome handling. Network operations remain excluded; real-Mac repository evidence and write-gate closure remain open.
- `MOP-041` — `IN_PROGRESS` — Implemented bounded `mac_package_inspect` with independent `mac.package.read` scope, exact project-root authorization, descriptor-backed manifest/lock identity checks, npm/pnpm/yarn/pip/uv/poetry/Brewfile parsing, protected-content denial, cancellation/timeout checks, and no package-manager script execution. Outdated registry reads remain disabled until an allowlisted registry profile and network-scope binding are released.
- `MOP-042` — `IN_PROGRESS` — Implemented fixed local-only Docker status, object inspection, and bounded container logs through a Broker-owned adapter with exact `mac.docker.read` targets, a canonical Docker Desktop executable allowlist, fixed arguments, bounded parsing, environment/mount/log redaction, cancellation, and no raw socket proxy. A real Mac daemon readback observed local Docker version `29.1.3` without listing containers/images; object/log compatibility, storage readback, and independent raw-socket negative tests remain.
- `MOP-043` — `BLOCKED` — Implemented the named-profile validation boundary and Broker-owned `mac_task_run` admission/Job lifecycle; an opt-in Darwin integration now proves signed-request admission, single-use approval, Job linkage, experimental sandbox dispatch, and verified readback, but production execution remains disabled. `blocked_by: MOP-086`; `unblock_condition: per-tool functional schemas remain complete and sandbox/credential-isolation evidence passes`; `expected_evidence: hostile task-profile PoC, resource-bound tests, and L2 release-gate evidence (VT-SBX-01, VT-SBX-02)`.
- `MOP-044` — `IN_PROGRESS` — Owner-bound `mac_job_status` and `mac_job_cancel` handlers, bounded output, durable cancellation intent, queued cancellation, terminal idempotency, lease-fenced terminal transitions, and restart reconciliation are implemented and schema-tested. Opt-in Darwin integrations now verify both session revocation and the durable `process` kill switch during real running tasks; each drains the process group and leaves the Job `unknown` after `CANCELLED`. Broader restart/crash and production process-tree evidence remains gated by MOP-086.
- `MOP-045` — `BLOCKED` — Prove child processes cannot access Edge/Broker/controller credentials or exceed filesystem/network policy. The handler accepts only a Broker-owned runner and records unknown outcomes when runner evidence or active authority is not trusted; no production child-process runner is enabled. `blocked_by: MOP-086`; `unblock_condition: real-Mac hostile sandbox PoC passes or task capability is restricted/removed`; `expected_evidence: credential canary, filesystem, network, process, Docker, and persistence isolation evidence (VT-SBX-01, VT-SBX-02)`.
- `MOP-046` — `IN_PROGRESS` — Implemented a disabled `mac_write_file_atomic` Broker/native prototype with independent write-root policy, exact approval binding, secret-content denial, descriptor identity checks, atomic same-directory rename, expected hash/create-only preconditions, explicit idempotency key, Broker Job Ledger linkage/status lookup, restart-to-`UNKNOWN` recovery, readback verification, and focused tests. Write jobs now persist only a bounded non-secret descriptor, including the exact generated temporary filename, and `mac_job_status` probes `matches`/`mismatch`/`unavailable` postconditions without inferring success. An explicit host-startup recovery hook now selects only restart-reconciled unknown write Jobs and cleans one recorded temporary artifact with descriptor-relative identity checks, audited intent/completion, and no prefix scan; legacy descriptors without a temporary name remain untouched. Real `WorkerFilesystemExecutor` pre-commit, post-rename, and test-only post-commit worker-crash failures now prove Broker preserves the Job as `UNKNOWN`; a Broker completion-failure simulation, deterministic fault-test-only `ENOSPC` cleanup before temporary write/`fsync` and after rename before parent `fsync`, a test-only fault-instrumented native `SIGKILL` boundary at selected syscalls, and final authority revalidation when the mutations kill switch trips confirm a committed atomic target cannot be published as an unauthorized success and remains inspectable as `UNKNOWN`. A 500-iteration hostile fixture now exercises concurrent create and symlink replacement; `RENAME_EXCL`/identity checks prevent replacement of the attacker target, while outside content remains unchanged. `mac_apply_patch` now adds a separate disabled-by-default textual patch path with independent `mac.files.write` + `mac.project.write` scopes, approval/Job/audit binding, expected-base hashing, bounded relative targets, secret denial, identity-bound atomic writes, rollback, and structured readback; focused Broker and filesystem tests pass. Release remains gated by physical remount/durability, Broker-process restart fencing, prior-worker/process ownership proof, broader partial-mutation coverage, and final readback evidence (`MOP-013, MOP-015, MOP-017, MOP-082, MOP-083`; VT-FS-01, VT-FS-02, VT-APR-01, VT-AUD-01, VT-REL-01).
- `MOP-047` — `IN_PROGRESS` — Implemented a disabled-by-default controlled Git staging/local-commit prototype. Broker admission binds the exact project target, arguments, approval, mutation intent, idempotency key, and generic Job lease; staging accepts only bounded explicit literal paths after canonical/symlink/secret checks, and commit binds an optional staged-diff hash precondition. Fixed `/usr/bin/git` commands disable hooks, fsmonitor, optional locks, signing, and network integrations; no push/reset/remote command surface exists. Staged diff hash, HEAD/parent, index-empty, working-tree, target identity, redaction, and unknown-outcome readbacks are enforced by tests, including a real temporary repository run. Release remains gated by MOP-046 write-gate closure, broader crash/concurrency/remount/actor-attribution coverage, and final readback (VT-GIT-01, VT-REL-01, VT-AUD-01, VT-DOS-01).

## P5 — L3/L4 applications and GUI

- `MOP-050` — `IN_PROGRESS` — Implemented the read-only `mac_app_list` inventory slice, disabled-by-default `mac_app_open` launch and `mac_app_focus` focus slices, the first read-only `mac_ui_observe` Accessibility snapshot boundary, and a disabled-by-default snapshot-bound `mac_ui_action` slice. Inventory/launch/focus use stable `bundle:<bundle_id>` identities; launch and focus require exact target authorization, `trusted_gui` approval, Broker Job leases, fixed `/usr/bin/open -b` or Broker-owned JXA, bounded timeout/output, and launch/focus readback. UI observation requires an independent `mac.ui.observe` scope, `window:bundle:<bundle_id>` target rule, GUI kill-switch coverage, fixed Broker-owned JXA, empty environment, bounded node output, secure-label masking, and opaque window/element references. UI actions require `mac.ui.control`, exact parent app-window authority, a 30-second owner/session-bound snapshot, GUI approval, exact role/label/index matching, and before/after Accessibility reobservation. Document/URL launch, structured automation, typing, and broader GUI actions remain planned or disabled.
- `MOP-051` — `PLANNED` — Implement structured AppleScript/JXA/Shortcuts adapters without raw script input.
- `MOP-052` — `IN_PROGRESS` — Implemented bounded read-only Accessibility-tree observation with permission-denied fail-closed behavior, secure-node masking, redacted labels, and opaque window/element identity derivation. The observation now feeds an owner/session-bound 30-second snapshot registry, and action adapters reobserve exact window/index/role/label identity before completion. Permission-granted real-app evidence remains open.
- `MOP-053` — `IN_PROGRESS` — Implemented disabled-by-default `mac_ui_action` for the fixed allowlist `press`, `select`, `increment`, `decrement`, `show_menu`, and `focus`. It requires a fresh owned snapshot, exact parent app-window authority, `trusted_gui` approval, a Broker Job ID, fixed Broker-owned JXA, stale/sensitive/secure-target denial, and verified post-action reobservation. Credential typing and broader GUI mutation remain blocked by `MOP-054`; real permission-granted, focus-race, and adversarial app evidence remain open.
- `MOP-054` — `IN_PROGRESS` — Added a conservative sensitive UI deny policy for SecurityAgent, Keychain Access, System Settings, loginwindow, security/privacy/password/credential/sign-in window hints and returned titles; secure Accessibility nodes remain masked and labels are redacted. Clipboard, cross-app data, broader credential-surface classification, and permission-granted adversarial evidence remain open.
- `MOP-055` — `PLANNED` — Verify macOS permission-denied, revoked-permission, stale-target, and real-app workflows.

## P6 — L5 privileged helper

- `MOP-060` — `IN_PROGRESS` — Added the proposed separately authenticated helper protocol: owner-only peer-authenticated IPC, HMAC command/response binding, durable request/nonce replay rejection, fixed `service_control`/`package_install`/`power` operation names, Broker argument digests, approval/intent identity, bounded redacted evidence, and fail-closed postcondition validation. Added a Broker-owned factory that signs only matching explicit-approval, intent-linked running Jobs and rechecks target, payload, policy, principal/session, kill switches, and revocation before signing. A dedicated protected `helper_key` manager now binds explicit file/Keychain source, digest, validity, monotonic activation, exact restore, revocation, and disposal before constructing the factory or helper server; both helper HMAC owners defensively wipe key copies and recheck active key authority. Already-constructed factory/server paths now fence helper-key expiry and activation replacement without restart. An independent helper runtime now restores the exact activation, requires native peer identity, rejects Broker/control socket reuse, and owns serialized start/close rollback. A separate root-domain package plan now fixes native-only launchd argv, signature identity, socket separation, Broker peer binding, disabled capabilities, and rollback/readback invariants. Helper startup can derive the caller from the exact Broker LaunchAgent readback and bind native PID/start-time identity; a real macOS cross-process test rejects a spawned caller spoof before request parsing. No helper operation is enabled; signed artifact provenance, real root-domain host evidence, and independent review remain open under ADR-0009 and VT-PRIV-01.
- `MOP-061` — `BLOCKED` — Added a non-executing root-domain helper package plan with native-only argv, exact code-signature identity, root-owned plist actions, protected helper-root/key/socket paths, Broker peer UID/GID binding, and exact upgrade/rollback/uninstall commands plus readback rejection for enabled capabilities. Helper startup now derives the Broker caller from the exact per-user `gui/<uid>/com.mac-operator.broker` LaunchAgent readback and binds PID/start-time identity before constructing the helper. A real macOS temporary bundle smoke test executes the fixed ad-hoc `codesign` verification command and reads back the exact helper identifier; the package also has a double-`lstat` root-owned preflight and a host-only, explicitly confirmed descriptor-relative plist apply/upgrade/rollback/uninstall primitive with identity-bound restoration. A real cross-process native IPC test now proves the bound Broker caller is accepted while a second spawned caller is dropped before parsing, and plist apply verifies the real current process UID before any filesystem access. A host-only dry-run execution contract and gated executor now bind exact service-revision preconditions, fixed command/file order, final readback, and operation-specific recovery steps; non-root callers fail before command or readback access. These do not prove Developer ID provenance, successful root-owned execution, or real root-domain readback. `blocked_by: MOP-003, MOP-081, ADR-0007`; `unblock_condition: runtime, IPC identity, package/signing, launch ownership, and credential-cleanup decisions are accepted`; `expected_evidence: Developer ID signature and provenance, install/upgrade/rollback, helper mismatch, uninstall, caller identity, caller-spoof, and real root-domain readback tests (VT-PRIV-01, VT-OPS-01)`.
- `MOP-062` — `BLOCKED` — Implement approved service control with preconditions and postconditions. `blocked_by: MOP-060, MOP-061`; `unblock_condition: authenticated helper protocol and service allowlist are released`; `expected_evidence: allowlist, precondition, service-state readback, audit, rollback, and bypass tests (VT-PRIV-01)`.
- `MOP-063` — `BLOCKED` — Implement approved package installation with exact identity/version policy. `blocked_by: MOP-060, MOP-061`; `unblock_condition: authenticated helper, package source policy, and version allowlist are released`; `expected_evidence: package identity/version, source, approval, installed-version, rollback, and bypass tests (VT-PRIV-01)`.
- `MOP-064` — `BLOCKED` — Implement reboot/shutdown with explicit policy and verified audit intent. `blocked_by: MOP-060, MOP-061, MOP-082, MOP-083`; `unblock_condition: helper auth, privileged approval, durable audit intent, and handoff semantics are released`; `expected_evidence: accepted/scheduled handoff, policy denial, audit-intent, cancellation/reconciliation, and recovery tests (VT-PRIV-01, VT-AUD-01)`.

## P7 — Hardening and release

- `MOP-070` — `PLANNED` — Fuzz schemas and test traversal, replay, revocation, prompt injection, resource exhaustion, and policy downgrade.
- `MOP-071` — `PLANNED` — Verify crash, restart, partial mutation, audit outage, credential rotation, and kill-switch recovery.
- `MOP-072` — `IN_PROGRESS` — Added source-level launchd plist rendering, reviewed Edge/Broker LaunchAgent templates, signal-aware Broker/Edge service lifecycles, bounded startup readback, fixed packaged Broker and HTTPS Edge entrypoints with owner-only root-bound startup configuration, component-specific `buildMacOsEdgeInstallPlan`/`buildMacOsInstallPlan` boundaries and Edge/Broker readback composition, host-only install-plan executors requiring exact operation confirmation and existing-service preconditions, fixed bounded `codesign`/`launchctl` argv, exact previous-revision preconditions, rollback/uninstall actions, post-bootstrap identity validation, double-`lstat` owner/mode/symlink/device/inode checks, and temporary-root-tested descriptor-relative atomic plist install/upgrade/rollback/uninstall. Read-only launchd metadata parsing and an opt-in Darwin smoke of separate real Edge/Broker LaunchAgents now verify exact arguments, Edge TLS readiness, native/status socket ownership, HMAC Broker readback, PID identity, empty capabilities, and post-bootout absence. The Edge entrypoint has local listener readback and remote JWKS configuration, while the uninstall coordinator binds to the real owner-only Authority Control client with authenticated readback and exact Edge revocation. A real macOS temporary ad-hoc artifact smoke test executes the plan's fixed signature verification command. Developer ID signing/notarization, production artifact identity, unattended installer authorization, remote OAuth/JWKS, Keychain ACLs, production upgrade/rollback, observability, retention, and final operator runbooks remain.
- `MOP-073` — `PLANNED` — Perform independent security and architecture review; resolve all reproducible P0/P1 findings.
- `MOP-074` — `PLANNED` — Produce exact-revision release candidate and real-client/real-Mac evidence.

### Privileged helper status addendum (`2240870`, hardened in `86a99ca`)

`MOP-060`/`MOP-061` now include a helper-owned read-only status IPC slice. It
uses a separate HMAC domain, native peer authorization, durable replay
admission, fixed status/readback schemas, socket identity fencing, and active
helper-key authority checks. The status source is explicit and is not exposed
as an MCP tool; no privileged operation or root-domain service is enabled.
Verification: 398 tests (395 passed, 3 opt-in sandbox tests skipped),
typecheck, contract verification, audit, and diff checks pass. Evidence:
`evidence/2026-09-13-privileged-helper-status-ipc.md`.

`MOP-086` host-evidence addendum: source revision `a8d9007` passed the full
`MOPS_REAL_SANDBOX=1 npm test` run at 398/398 and the focused sandbox suite at
9/9 on the Mac mini host. This strengthens, but does not close, the sandbox
gate; real credential/Docker/persistence isolation, remount identity,
owned-group/post-snapshot process ownership, UDP, external allowlisted
networking, and production packaging remain open.

`MOP-061` signature addendum: source revision `46a3167` requires the exact
helper identifier, Developer ID TeamIdentifier, and CDHash in the root-domain
package plan and final codesign readback. Missing fields fail closed before
filesystem or launchd actions. Developer ID signing/notarization, installation,
live readback, and independent review remain blocked. Evidence:
`evidence/2026-09-13-helper-signature-gate.md`.

`MOP-061` observer addendum: source revision `3b24604` wires the authenticated
helper socket/key status client into the package observer and rejects a missing
runtime source. The integration test completes a real local signed status
exchange through the production-shaped observer. Root installation and live
launchd evidence remain blocked. Evidence:
`evidence/2026-09-13-helper-observer-ipc-integration.md`.

Source revision `a1bd63c` additionally verifies that an already-created
key-manager server rejects status reads immediately after helper-key revocation;
the latest default suite is 400 tests with 397 passed and 3 sandbox tests
skipped.

Source revision `6d6087d` adds the bounded Broker-side client for already-signed
helper commands. It authenticates complete responses and maps transport loss
to retryable `UNKNOWN_OUTCOME`; no privileged adapter or root service is
enabled. Evidence: `evidence/2026-09-13-helper-command-client.md`.

The helper Job executor slice adds a disabled-by-default Broker Job executor above the
client. It renews the Job lease, enforces command-to-Job identity binding,
rechecks authority before/after dispatch, redacts validated helper evidence,
and persists conservative `UNKNOWN_OUTCOME` for unresolved execution. The
executor is not wired to an MCP tool, and helper installation/root launchd
remain blocked. Evidence: `evidence/2026-09-13-helper-job-executor.md`.

The Broker owns the seam through an optional `privilegedHelperExecutor`
dependency and `executePrivilegedHelperJob()`; the default constructor injects
the disabled implementation and performs no privileged dispatch.

The helper command boundary also persists a strict typed payload descriptor and
includes it in the signed envelope. Only Broker-owned service, package, and
power descriptors can cross the helper boundary; raw shell text, executable
paths, environments, credentials, and arbitrary maps remain unrepresentable.
Target, operation, secret-policy, and canonical digest checks run at Job
creation and command validation. This is still disabled and does not unblock
the privileged capability rows.

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
