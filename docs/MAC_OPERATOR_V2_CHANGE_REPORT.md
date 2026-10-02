# Mac Operator V2 change report

Updated: 2026-10-02. Final acceptance is recorded in
[production evidence](../evidence/2026-10-02-v2-production-gateway.md).
Implementation branch: `codex/v2-production-executor`; destination: local `main`.
No remote push, PR publication or YAP production merge is part of this change.

Requested V2 delivery: **DONE, 100% (11/11 Definition-of-Done gates)**.
Runtime implementation commit: `6e332f1d3adeaaccdb100a03cf0a990b3fef96ad`.
The final protected release readback records its complete source revision and
native artifact digest; documentation and operator verification do not change
the runtime implementation. The live endpoint is `https://mac.yapweijun1996.com/mcp`.

| Completion gate | Result |
| --- | --- |
| Codex operates an authorized project | PASS, actual YAP and public OAuth workflows |
| Codex writes only in an isolated worktree | PASS, exact source path and primary fingerprint equality |
| Tests/build use managed jobs | PASS, named task, test and site build |
| Secrets and unauthorized paths inaccessible | PASS, native, policy, controller and physical checks |
| Coding grant has no unrestricted sudo/shell | PASS, no host tools, unprivileged guest, no terminal scope |
| Git push remains gated | PASS, default denial and no publishing route |
| Audit evidence exists | PASS, durable ownership, source import, Git and execution audit |
| Policy tests pass | PASS |
| Security tests pass | PASS, actual isolation plus failure/recovery regressions |
| E2E development workflow passes | PASS, public read/write/test/build/commit/review |
| Existing R1 behavior compatible | PASS, 26 real reads and unchanged old grant scopes |

## Architecture before and after

| Before | After |
| --- | --- |
| Edge OAuth → authenticated Local Broker policy/approval | Same boundary; separate V2 coding grant and delegated development issuer |
| Safe files/Git, managed jobs; task runner disabled in personal policy | Same components; registered task/test/build commands in one disposable container per owned worktree |
| Worktree/gateway contracts existed but no accepted executor/provider | Pinned Docker Engine/image plus constrained native Codex app-server controller |
| Schema 19 persistent requests, approvals, jobs and audit | Schema 20 adds immutable container ownership before start, verified cleanup and conservative restart recovery |
| Independently authorized O1 host terminal | Existing O1 grants retain their scopes; fresh coding consent excludes terminal authority |

Codex inference runs in a private controller directory. Its model-visible host
filesystem permissions deny `/`; built-in shell, patch, MCP, skills, subagents,
browser, plugins and hooks are disabled. Its exact supplied tools operate on
logical `/workspace` inside the task container. This intentionally differs
from launching an ordinary Codex CLI in a host worktree: inference credentials
stay with the trusted authentication manager, outside task code and snapshots.

The agent container has no host mounts, socket, credentials or task network.
A bounded, filtered source snapshot is copied in. Only validated source changes
from `workspace-write` are imported through canonical native atomic writes into
the owned worktree. Validation jobs retain artifacts inside their container.

## Tools and contracts

The existing 57 versioned contracts remain compatible. The accepted personal
runtime enables ten V2 tools plus the existing `mac_task_run`:

- Worktree create/list/remove and branch create through a new worktree.
- Codex read-only preflight and asynchronous run with explicit execution profile.
- Purpose-specific test/build, review preparation and bounded execution audit.
- Named task profiles with manifest identity, fixed guest argv, required runtime
  and durable idempotency; no caller-supplied shell command.

`mac_policy_explain` plans future operations without executing them.
Existing explicit-path Git stage/local commit work on managed worktrees.
`mac_git_push` is reserved and always denied; force push, remote mutation,
package install and PR publishing have no development approval route.

Preflight reports installed version, safe authentication readiness, supported
models, owned-worktree validity, Git state and available registered commands.
It never returns authentication values. Async receipts return a `job_id`;
status/cancel and bounded log retrieval retain the existing job contracts.
Test/build receipts include redacted fixed argv; terminal status includes
execution duration, exit status and bounded stdout/stderr evidence.

The Engine transport repeats only read queries and registration of an unstarted
exec descriptor after `EPIPE`/`ECONNRESET`, at most twice within the original
deadline. Every attempt verifies the native peer and socket again. It never
replays exec-start, task code, lifecycle mutations or host imports. Unique-ID
lost-response tests prove the abandoned descriptor starts zero times and the
returned descriptor starts once.

## Security controls

| Tier | Ordinary V2 authority |
| --- | --- |
| READ | Exact scope/target checks; bounded safe reads, preflight, review and audit |
| SAFE_WRITE | Authorized source/worktree, canonical native path gate, stable retry identity, intent/readback audit |
| AGENT_RUN | Owned isolated worktree, explicit profile/network none, bounded runtime/output, durable container identity and managed jobs |
| HIGH_RISK | Denied; ordinary coding consent/issuer cannot authorize push, install, service mutation or privilege escalation |

Controlled storage is private and excluded from ordinary filesystem roots.
Secret zones, `.env` values, Git metadata, symlink escapes and traversal are
blocked before snapshot/tool access/import. Known secret signatures are checked
on source input, dynamic tool content and bounded output. All output deltas and
allowed paths are validated before the first source write.

Containers have a read-only root filesystem, nonroot UID65532, no capabilities,
no-new-privileges, default seccomp, private PID/IPC/cgroup namespaces and bounded
memory/CPU/PIDs. UID65533 PID1 owns an independent deadline; the task UID cannot
stop it. Readonly/test-only source is root-owned and non-writable. Export fences
new execution, terminates task descendants and pins each file before reading.

Container ownership is durable before start. Success requires exact teardown
and absence readback. Cancellation/revocation cannot become success. A crash
retains UNKNOWN ownership; restart performs exact cleanup without replaying
execution or inventing success. Renewable job leases remain valid across long
bounded jobs and reject wrong tokens, clock rollback and forged intervals.

Git adapters override hooks/fsmonitor, pin configuration and disable all
transports and lazy fetch. A real partial-clone fixture reproduced implicit
remote-helper execution; governed Git now rejects it before host credentials
or networking can be invoked.

Audit records request/task/project/worktree/actor/scopes/decision/result,
duration, verified paths and local commit IDs. Partial imports retain their
verified-path evidence even if a later write or cleanup fails. Prompt/source
contents and credential values are not audit fields.

## Verification and rollout

The current production evidence owns exact test counts, physical security
checks, the real YAP synthetic workflow, source/runtime commit hashes, public
OAuth checks and deployment readback. Earlier October 1 records and the 55%
source-only rollout remain historical; they did not prove production execution.

The synthetic YAP task changes only one test file in a Broker-created worktree,
runs the existing isolation tests and site build through managed jobs, stages
that explicit path, commits locally and prepares review evidence. Primary HEAD,
index, test-source hash and status are compared before/after. Existing unrelated
YAP `.claude/settings.local.json` is preserved. No production YAP code is merged.

Deployment uses an immutable tested release, a full stopped-state backup,
explicit signed-policy/runtime migration and readback. Existing OAuth grants
are not expanded. Fresh coding consent provides 27 scopes and 48 tools without
terminal authority; reconnecting obtains those scopes. The installation retains
a separately authorized old O1 terminal boundary for existing owner grants.

## Known limitations and remaining risks

- Docker Desktop/guest kernel, pinned image, native adapter and Codex binary are
  trusted dependencies. Same-UID host compromise is outside the remote-agent
  boundary. Version/image changes require fresh acceptance.
- The approved YAP subset contains root scripts, shared source and the site;
  `portal`, `mcp-connector`, `sample`, `docs`, `output` and `tmp` are excluded.
  Other projects, languages, source scopes and build dependencies require
  separately reviewed registry/image configuration. Snapshot limits remain fixed.
- Only task network policy `none` is enabled. Trusted inference may contact its
  configured provider through the authentication manager; task tools cannot
  reach that manager or its credential storage.
- Claude is not provisioned. Source deletion, dirty force-removal, package
  installation, push and PR publishing are unsupported and fail closed.
- Validation artifacts are ephemeral; safe host artifact import is not added.
  Source import is atomic per file, not a multi-file transaction. A later failure
  can leave earlier audited source changes for review.
- Known-signature scanning cannot recognize every unknown credential format.
  Secrets must not be committed to approved source. Control/path separation
  prevents task access to host secret stores without relying on scanning alone.
- A create acknowledgement lost before durable ownership can leave an empty,
  unstarted container; no task code starts before acknowledgement. Exact-owned
  recovery never blindly deletes unproven containers.
- The migration updates database and protected files in steps. Interrupted
  migration requires the full stopped-state backup; the old release cannot read
  schema 20. Formal Developer ID/notarization and the old staging helper/VM
  release gates remain separate from this personal V2 deployment.
- Docker may close a transport connection. Only non-executing preparation has
  bounded recovery; ambiguous execution still stops the exact owned container
  and fails closed. The Docker-internal cause of the observed registration
  `EPIPE` is not established. Historical failed jobs remain recorded as failures.

The [design/threat model](MAC_OPERATOR_V2_DESIGN.md) and
[operator runbook](MAC_OPERATOR_V2_RUNBOOK.md) document current boundaries,
provisioning, configuration migration, recovery and rollback.

## Final source checks and changed files

Standard regression: 1595 total, **1577 PASS / 18 SKIP / 0 FAIL**.
Final-image physical enforcement passed every check in six actual 17-check runs,
including the deployed runtime, with zero skips. Final release readback is
recorded separately in protected deployment evidence.
Public acceptance passed two full coding workflows: 27 scopes, 48 tools, 26
legacy reads each, five managed jobs, local commit/review and primary unchanged.
The read grant separately passed 29 tools/26 reads with no coding scope expansion.
57 strict contracts, native/TypeScript build, style, docs, verification matrix,
process-boundary audit, canonical JSON 5/5 and dependency audit all pass.
Independent source review has no unresolved substantiated P0/P1.

This production-runtime change modifies the following 61 focused files:

- `PROGRESS.md`
- `README.md`
- `docs/MAC_OPERATOR_V2_CHANGE_REPORT.md`
- `docs/MAC_OPERATOR_V2_DESIGN.md`
- `docs/MAC_OPERATOR_V2_RUNBOOK.md`
- `evidence/2026-10-02-v2-production-gateway.md`
- `packages/auth/src/contracts.ts`
- `packages/auth/src/index.ts`
- `packages/auth/src/personal-approval-browser-controller.test.ts`
- `packages/auth/src/personal-development-approval.test.ts`
- `packages/auth/src/personal-development-approval.ts`
- `packages/auth/src/personal-development-runtime.test.ts`
- `packages/auth/src/personal-development-runtime.ts`
- `packages/auth/src/personal-development-upgrade.ts`
- `packages/auth/src/personal-service.ts`
- `packages/auth/src/personal-terminal-approval.ts`
- `packages/auth/src/v2-policy.test.ts`
- `packages/auth/src/v2-policy.ts`
- `packages/broker/native/filesystem_acl.h`
- `packages/broker/native/peer_credentials.cc`
- `packages/broker/src/approval-authority.ts`
- `packages/broker/src/approval-ipc-client.ts`
- `packages/broker/src/broker.ts`
- `packages/broker/src/codex-controller.test.ts`
- `packages/broker/src/codex-controller.ts`
- `packages/broker/src/container-broker.test.ts`
- `packages/broker/src/container-engine.test.ts`
- `packages/broker/src/container-engine.ts`
- `packages/broker/src/container-job-metadata.ts`
- `packages/broker/src/container-physical-validation.ts`
- `packages/broker/src/container-physical.test.ts`
- `packages/broker/src/container-snapshot.test.ts`
- `packages/broker/src/container-snapshot.ts`
- `packages/broker/src/container-task-profile.test.ts`
- `packages/broker/src/container-task-profile.ts`
- `packages/broker/src/container-task-runner.test.ts`
- `packages/broker/src/container-task-runner.ts`
- `packages/broker/src/development-approval-boundary.ts`
- `packages/broker/src/development-gateway.ts`
- `packages/broker/src/git-hooks-isolation.test.ts`
- `packages/broker/src/git-inspector.test.ts`
- `packages/broker/src/git-inspector.ts`
- `packages/broker/src/index.ts`
- `packages/broker/src/ledger-export.test.ts`
- `packages/broker/src/ledger-export.ts`
- `packages/broker/src/persistence-container.test.ts`
- `packages/broker/src/persistence-lease-renewal.test.ts`
- `packages/broker/src/persistence.test.ts`
- `packages/broker/src/persistence.ts`
- `packages/broker/src/process-environment.ts`
- `packages/broker/src/task-profile.ts`
- `packages/broker/src/task-runner.ts`
- `runtime/container/Dockerfile`
- `runtime/container/run-site-build.cjs`
- `schemas/ledger-records.schema.json`
- `scripts/check-process-boundaries.mjs`
- `scripts/probe-v2-yap-container.mjs`
- `scripts/verify-personal-connection.mjs`
- `tool-contracts/mac_build_run.json`
- `tool-contracts/mac_job_status.json`
- `tool-contracts/mac_test_run.json`
