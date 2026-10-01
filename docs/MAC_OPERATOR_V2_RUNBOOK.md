# Mac Operator V2 Operator Runbook

## Status and authority

V2 is additive to the existing R1/G1 deployment. The
[design and threat model](MAC_OPERATOR_V2_DESIGN.md) describes its boundaries;
[the V2 validation record](../evidence/2026-10-01-v2-gateway-validation.md) owns this change's source verification; [PROGRESS.md](../PROGRESS.md) retains deployment evidence.
The wire and contract versions remain `0.1`.

All 11 V2 tools default to disabled. `mac_git_push` always denies execution,
even when its scope and policy entry are present. There is no shipped production
coding-agent adapter, no automatic service migration, and no claimed production
Codex or YAP-MCP coding E2E. Source tests and mock providers do not establish an
accepted macOS execution boundary.

A separately deployed O1 owner-terminal mode is now live; see the
[rollout distinction](MAC_OPERATOR_V2_CHANGE_REPORT.md). Its CLI/shell checks do
not qualify as V2 isolation evidence. Do not use that terminal authority to
bypass V2 job/worktree/profile admission or bundle it into coding approval.

The host operator owns provisioning, signed policy changes, OAuth grants and
operation approvals. Tool arguments cannot create profiles, select an arbitrary
executable, grant credentials, or upgrade a staging runner to production.

## Host-owned provisioning

1. Preserve the current signed policy, deployment revision, job/audit store and
   R1/G1 grants. Record the original project's canonical path, HEAD, index digest
   and status. Use a staging deployment first; do not replace the running service
   simply to enable a tool name.
2. Provision two separate, non-nested absolute canonical directories for
   `ManagedWorktrees(stateRoot, worktreeRoot)`. Both must already exist, belong to
   the Broker's effective user and have owner-only permissions such as `0700`.
   They must be outside every primary project used by the gateway and must not
   be symlinks. Keep provenance state unavailable to project scripts, agents and
   ordinary file tools. The gateway rejects ordinary filesystem roots that cover
   provenance or the all-task tree root. Worktrees are created beneath the controlled tree root;
   callers cannot choose arbitrary destination paths.
3. Construct `DevelopmentGateway` in reviewed host startup code. Supply its
   `worktrees` object and, when needed, fixed `commands` entries with canonical
   `projectRoot`, task `type`, and named `profile`. Do not load these entries from
   an untrusted project manifest or MCP request. The optional `codexExecutable`
   is a metadata-only hint; preflight does not execute it or open auth/config.
4. Register reviewed commands in `TaskProfileRegistry`: fixed executable and
   arguments, pinned executable/content identity, allowed cwd roots, filesystem
   roots, minimal credential-free environment, declared network/process policy,
   runtime/output bounds and postcondition strategy. Only then map a `test` or
   `build` entry to the matching profile in the gateway. Project manifests can
   inform operator review; they never authorize execution. If more than one
   approved profile matches, the caller must name the registered profile.
5. Pass `developmentGateway` and any `taskProfileRegistry` through the host-owned
   `createBrokerServiceFromStartupConfig` / `runBrokerServiceMain` options. These
   are source integration seams, not new MCP fields or public command-line
   flags. Startup rejects task-profile configuration without a configured
   isolated task runner. Existing runner startup options and release gates still
   apply; the default is `FailClosedTaskRunner`.
6. Keep AGENT_RUN tools disabled until the chosen runner has accepted physical
   host evidence, `available: true`, `publicEnablement: "production"`, a matching
   isolation mechanism and owned process-tree proof. Evidence must cover hostile
   descendants, secrets, filesystem escape, cancellation and restart. Do not set
   production metadata merely to bypass a gate.

A future `CodingAgentProvider` must be provisioned by trusted host code and
resolve to a governed `ResolvedTaskProfile`. It must report enforced `readonly`,
`workspace-write` or `test-only` profiles, deny host Git control, and declare its
supported network policy. The gateway requires exact worktree cwd and
`credentialPolicy: "none"`; it rejects direct sudo/su executables and mismatched
network profiles. These admission checks complement the accepted outer runner;
readiness assertions and prompt text alone do not prove containment.

Do not mount `~/.codex`, `~/.claude`, `.ssh`, Keychain, browser profiles, MCP state
or user credential stores into a task. Do not put API keys into prompts,
profile arguments, environment or audit records. Credential-free inference
provisioning remains a separate dependency. Current registered network
allowlists accept precise loopback destinations; installing a CLI or observing
its local login is insufficient to enable coding.

## Policy migration and grants

Review a new signed policy revision; retain existing R1/G1 grants unchanged.
Enable only the selected V2 entries after their host dependencies exist. New
scope grants must appear both in the authenticated principal authority and in
Broker target rules. V2 project targets are exact canonical original project
paths. Worktree inventory binds the original project, principal and task;
linked `.git` metadata alone never grants project authority.

| Tool | Tier | Required scopes |
| --- | --- | --- |
| `mac_git_worktree_create` | SAFE_WRITE | `mac.project.write`, `mac.git.write` |
| `mac_git_worktree_list` | READ | `mac.project.read`, `mac.git.read` |
| `mac_git_worktree_remove` | SAFE_WRITE | `mac.project.write`, `mac.git.write` |
| `mac_git_branch_create` | SAFE_WRITE | `mac.project.write`, `mac.git.write` |
| `mac_codex_preflight` | READ | `mac.project.read`, `mac.agent.read` |
| `mac_codex_run` | AGENT_RUN | `mac.project.read`, `mac.project.write`, `mac.agent.run` |
| `mac_test_run`, `mac_build_run` | AGENT_RUN | `mac.project.read`, `mac.project.write`, `mac.task.run` |
| `mac_pr_prepare` | READ | `mac.project.read`, `mac.git.read`, `mac.job.read` |
| `mac_execution_audit` | READ | `mac.project.read`, `mac.audit.read` |
| `mac_git_push` | HIGH_RISK | `mac.project.write`, `mac.git.push`; execution still denied |

Existing `mac_job_status` and `mac_job_cancel` require `mac.job.read` and
`mac.job.cancel` respectively, together with the existing owned-job target
rules. Existing filesystem tools keep their own root/path scopes and secret
restrictions. If direct source read/patch access is needed in a new worktree,
provision only the intended filesystem roots and path rules; do not grant
blanket access to provenance state or all task checkouts. Existing Git
status/diff/stage/commit tools can resolve a managed checkout back to its exact
original project, but retain their existing scopes and approvals.

Use `mac_policy_explain` with `proposed_tool`, exact proposed target and
`proposed_arguments` to inspect a future operation. Explain may validate
metadata and policy but must never create a worktree, resolve an execution
profile, start a process/job or consume an operation approval. An ALLOW is a
policy preview, not execution or postcondition evidence.

SAFE_WRITE requires existing `trusted_write` approval; AGENT_RUN requires
`trusted_profile`. Use the existing authenticated owner approval workflow,
bound to tool, canonical target, payload digest, policy version, principal and
expiry. A supplied boolean or a scope alone is not approval. Coding approval
cannot authorize push, install, service control or destructive cleanup.

## Approved development workflow

1. Discover and summarize the authorized project using the existing tools.
   Inspect Git status. Use a resolved existing base ref and a fresh `task_id`.
2. Preview and approve `mac_git_worktree_create` (or
   `mac_git_branch_create`, which creates the worktree rather than switching the
   primary checkout). Request a valid `codex/` branch and stable
   `idempotency_key`. A duplicate with the same owner and arguments reuses the
   active worktree; reusing the key for different arguments returns CONFLICT.
3. Preserve the returned canonical worktree path. Preflight reports installation
   metadata, adapter readiness, approved commands, Git status and reason codes
   without returning credentials. Missing production isolation, agent adapter,
   credential-free authentication or agent authority yields DENY/not-ready.
4. After a separately accepted adapter exists, submit `mac_codex_run` with the
   owned worktree/task, explicit execution/network profile, bounded
   `max_runtime` (1 to 600000 ms) and retry key. Relative `allowed_paths` cannot
   escape the checkout or include `.git`. Do not embed credentials in tasks.
5. Run `mac_test_run` / `mac_build_run` only against the owned task worktree and
   an unambiguous registered profile. These tools do not invent commands or
   install missing dependencies. They return a managed-job receipt, not an
   immediate test/build verdict.
6. Retrieve bounded job status/evidence, inspect the Git diff, stage explicit
   files and commit through the existing approved Git tools. A local commit
   changes shared branch/object metadata but must not alter the primary
   checkout's HEAD, index or working files. A task branch shared with the primary
   or another checkout is denied. Git mutation waits for active worktree jobs.
7. Use `mac_pr_prepare` for changed paths, bounded commit metadata, recorded
   validation evidence, and suggested title/description. It does not publish a
   PR. Inspect `mac_execution_audit` with a limit of 1 to 100 (default 50) for
   redacted, owner/project-filtered audit events. The MCP audit view is bounded;
   the protected Broker ledger remains authoritative.

For the requested YAP-MCP E2E, use only an authorized synthetic task in an
isolated checkout. Record primary HEAD, index and status before/after and keep
production source unchanged. Do not claim this E2E passed until the actual
coding adapter, validation jobs, local Git review/commit and primary-checkout
comparison have completed. Push remains denied.

## Jobs, cancellation and restart

V2 agent/test/build submissions use the existing Broker job ledger and return
`job_id`, state, task and worktree. A SUCCEEDED submission with verification
`accepted` proves admission only. Observe terminal state and postcondition
verification before calling a task successful. Use `mac_job_status` with a
small `tail_bytes` for bounded sanitized output, exit/result class and evidence;
there is no automatic bulk log return. `mac_job_cancel` requests termination
through owned job control. Check status afterward; cancellation uncertainty must
not be reported as proven process termination.

Keep the same retry key and exact payload for a delivery retry. Owner, payload,
tool, target and policy bindings prevent a different action from inheriting an
existing job. A changed task, profile or policy needs a newly reviewed request;
an uncertain job must be reconciled before execution is retried.

On restart, the existing ledger conservatively cancels interrupted queued
admissions and marks interrupted running work UNKNOWN. It never automatically
replays coding or validation tasks. Existing host recovery may inspect or drain
an exactly owned process/guest where supported; it must not promote unknown
outcomes to success without evidence. Queued, running and unknown jobs block
worktree deletion, including relevant jobs owned by another principal.

## Inventory reconciliation and removal

The protected `worktrees.json` inventory records `pending`, `active`, `removing`
and `removed` provenance. MCP list returns only verified active records. A
failed creation can leave a pending record and artifacts; an interrupted removal
can leave removing state. These are operator reconciliation conditions, not
permission to repeat creation under a new key or delete directories manually.

1. Disable the affected V2 mutations and execution, inspect jobs/audit, and
   quiesce the Broker before examining protected inventory. Preserve the
   inventory, relevant audit/job records and task files before corrective work.
2. Match original project, owner, task, branch, base commit, canonical worktree,
   directory identities and both directions of Git metadata pointers. Compare
   the primary checkout evidence. Determine whether creation/removal occurred
   and whether a process still owns the checkout. Missing or contradictory
   identity evidence must remain unresolved.
3. A lock owned by a live or unknown process must not be deleted. Startup can
   retire a stale lock only after native PID/start-time evidence proves its
   former owner is dead. Malformed locks require operator investigation.
4. There is no MCP reconciliation or force-delete tool. Do not hand-edit records
   to assert success, remove lock files blindly, run `git worktree prune`, or
   force-remove a checkout as a retry shortcut. Keep the affected task disabled
   until a reviewed host repair with exact identity/read-back evidence exists.

Normal `mac_git_worktree_remove` requires a Broker-owned active checkout, exact
owner/project/task, explicit write approval and retry key, no active/unresolved
job, and clean status including ignored files. Dirty deletion is unavailable;
no request boolean overrides it. The primary repository is never a valid target.
Removal verifies checkout/metadata absence and unchanged primary state. It keeps
a removal tombstone; an exact completed retry succeeds only while the removed
paths remain absent. Branch history is not automatically deleted.

## Rollback and acceptance

Disable V2 enablement first, cancel/drain jobs where evidence permits, and
preserve dirty/unknown task checkouts plus provenance and audit. Restore the
reviewed prior service/policy revision while retaining valid job-state history.
Do not erase V2 state or reclaim worktrees as part of rollback. Recheck R1/G1
health, grants, read behavior and GUI behavior according to the existing
[operations](../OPERATIONS.md) and [rollback](../ROLLBACK.md) procedures.

Before production execution enablement, require contract/policy/security tests,
physical isolation/credential/network evidence, managed-job timeout/cancel and
restart evidence, and an actual isolated development E2E. Record PASS/FAIL and
source revision in [PROGRESS.md](../PROGRESS.md). Current missing production
coding provisioning and any unavailable project grant remain explicit
acceptance dependencies, never implicit waivers.
