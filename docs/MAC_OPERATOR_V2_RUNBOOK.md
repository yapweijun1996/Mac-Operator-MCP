# Mac Operator V2 Operator Runbook

## Status and authority

V2 is additive to the existing R1/G1 deployment. The
[design and threat model](MAC_OPERATOR_V2_DESIGN.md) describes its boundaries;
[the V2 validation record](../evidence/2026-10-01-v2-gateway-validation.md) owns this change's source verification; [PROGRESS.md](../PROGRESS.md) retains deployment evidence.
The wire and contract versions remain `0.1`.

All 11 V2 contracts remain disabled by default; the accepted personal V2
profile enables ten of them and the existing named `mac_task_run` interface.
`mac_git_push` always denies execution, including with a supplied scope.
The production adapter is `ContainerTaskRunner`; its pinned Linux runtime and
constrained `CodexController` are distinct from the earlier staging runners.
Real acceptance is recorded in the [current change report](MAC_OPERATOR_V2_CHANGE_REPORT.md).

Ordinary V2 OAuth consent excludes `mac.terminal.exec`. The installation retains
previously authorized O1 grants and their separate terminal approval issuer.
Neither a new coding grant nor its development issuer grants host-shell authority.

The host operator owns provisioning, signed policy changes, OAuth grants and
operation approvals. Tool arguments cannot create profiles, select an arbitrary
executable, grant credentials, or upgrade a staging runner to production.

## Host-owned provisioning

1. Pin Docker Desktop Engine identity, canonical owner socket and native peer
   identity. Pin an immutable image ID built from the reviewed Dockerfile in
   `runtime/container`; tasks cannot select a daemon/image, install packages or
   mount host directories. Provision dependencies once as an operator outside MCP.
2. Provision separate canonical owner-only `stateRoot` and `worktreeRoot`.
   Keep control state beneath protected MCP storage. Worktree source storage
   must be outside credential zones and every original repository, for example
   a separate `DevelopmentWorktrees` directory. Never put source worktrees under
   `.codex` or `MacOperator` credential storage. All ordinary filesystem roots,
   including broad metadata roots, must explicitly deny both private roots.
3. Create a private runtime JSON matching `personal-development-runtime.ts`:
   exact authorized projects, Engine/image/controller hashes and version,
   approved manifest hashes and script values, fixed guest argv, timeout/output
   caps, and `snapshotExcludedPaths`. The current YAP registry approves
   `test:isolation` and `site/package.json` build. The build image contains Linux
   dependencies installed with lifecycle scripts disabled; task network is none.
4. Review source exclusions before admission. The YAP configuration omits
   the entire `portal`, `mcp-connector`, `sample`, `docs`, `output` and
   `tmp` trees. The approved source subset contains root scripts, shared
   source and the site build; it excludes production portal data and uploads. Those paths
   cannot be read/written by dynamic tools or recreated during source import.
   Add a new source scope only after operator review and fresh relevant evidence;
   do not raise snapshot budgets or copy production data to make a task pass.
5. Run actual isolation and YAP probes in private, non-listening acceptance
   state. Preserve bounded evidence in an owner-only file. The loader requires
   all sixteen named acceptance checks, exact image/Engine/provider identity and
   an unchanged evidence digest. Unit doubles are not physical acceptance.
6. Stop the existing service and take a full consistent private state backup,
   including SQLite, audit anchor, signed policy, approval/OAuth state and launch
   configuration. Preserve dirty task files and original repository evidence.
7. Run the explicit offline upgrade from the verified immutable release:
   `node packages/auth/dist/personal-service.js development <state-root> <source-revision> <private-runtime-config> --enable`.
   It validates the runtime before signed authority changes, adds the narrowly
   constrained `personal-development-1` issuer and signs exact project/profile
   rules. It does not initialize the installation or expand existing OAuth grants.
8. Start the new release, verify public OAuth, fresh coding discovery, old
   read/O1 scope projections, accepted task jobs, policy explain and push denial.
   Save supervisor configuration only after readback. Reconnect ChatGPT to obtain
   the new coding scopes; a preexisting connection intentionally keeps its old grant.

Use `MOPS_VERIFY_DEVELOPMENT=1` with `scripts/verify-personal-connection.mjs`
for the explicitly synthetic YAP public acceptance workflow. It edits one test
only in a new owned worktree, runs named task/test/build jobs, commits locally,
prepares review evidence, verifies primary fingerprints and removes the clean
worktree. It never publishes or merges YAP changes. The verifier uses two-second
job polling to respect the unchanged Edge rate limit; avoid simultaneous bulk
verification clients. Protected evidence is stored outside Git without tokens.

Engine connection recovery is limited to read queries and registration of
unstarted exec descriptors after a fixed `EPIPE`/`ECONNRESET`. There are at most
two retries inside the original deadline, with peer/socket verification on every
attempt. No task code, exec-start, lifecycle mutation or source import retries.
If execution or cleanup is ambiguous, preserve the failed/UNKNOWN evidence and
use exact-owned recovery; never replay the task to manufacture a success.

The controller binary is pinned to Codex `0.153.4`; its installed permission
profile and feature gates were physically checked. Upgrading the CLI requires
fresh review and acceptance. Trusted inference uses the existing authentication
manager; no credential bytes enter task tools, snapshots, environment or logs.
Built-in shell, patch, MCP, subagent, skill, browser, plugin and hook capabilities
are disabled. The logical coding cwd is `/workspace`; the inference controller
has a private cwd and no model-visible host filesystem authority.

## Container recovery and rollback

A container handle is durable before start. UID65533 PID1 enforces an independent
deadline; task UID65532 cannot stop it. A task is successful only after exact
container deletion and absence readback. Export first fences all new execution,
terminates same-UID descendants, verifies quiescence, then hashes bounded regular
files. Native import rechecks authority and persists per-path intent/readback.

Restart converts interrupted jobs to UNKNOWN and retains exact Engine, image,
container, owner, nonce and descriptor identity. Recovery may delete only that
verified container and settle failed/cancelled; it never replays or reports
success. If identity or Engine availability is uncertain, keep UNKNOWN and the
worktree locked. Status/cancel/log retrieval use the existing job tools.

The migration spans database activation and several private config renames; it
is not an atomic cross-file transaction. An interrupted migration requires the
full stopped backup. Schema 20 is not readable by the earlier release: stop and
drain the new service, preserve new worktrees/audit as a separate snapshot,
restore the complete old private state and old launch configuration, then verify
health and unchanged grants. Restoring only an old policy or Edge config is
insufficient. Never erase task checkouts or falsely clear UNKNOWN ownership.

Docker Desktop and the pinned controller are availability dependencies. Changed
binary, image, Engine, peer or evidence identities fail startup closed. Investigate
and revalidate before enabling them again; never choose another runtime implicitly.

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
   PR. Inspect `mac_execution_audit` for redacted, owner/project-filtered audit
   events, newest first: `limit` is 1 to 100 (default 50). When older events
   remain, the result has `truncated: true` and a `next_cursor`; pass it as
   `cursor` for the next page (a malformed cursor is `PRECONDITION_FAILED`). A
   page that exactly fills the limit with nothing older reports `truncated:
   false`. Events carry `duration_ms` and, for completed container runs,
   `phase_ms`. The MCP audit view is bounded; the protected Broker ledger
   remains authoritative.

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
not be reported as proven process termination. Cancelling a job that has already
finished, failed, been cancelled or is unknown returns `CONFLICT` before any approval is
requested; only queued and running jobs can be cancelled. A failed job's
`outcome_class` (`TIMEOUT`, `OUTPUT_LIMIT`, `VERIFICATION_FAILED`, `EXECUTION_FAILED`)
is read best-effort from its request; the job state stays `failed`.

Keep the same retry key and exact payload for a delivery retry. A job cancelled
because its access token expired is replayed under the same key; a re-run needs a new key. Owner, payload,
tool, target and policy bindings prevent a different action from inheriting an
existing job. A changed task, profile or policy needs a newly reviewed request;
an uncertain job must be reconciled before execution is retried.

On restart, the existing ledger conservatively cancels interrupted queued
admissions and marks interrupted running work UNKNOWN. It never automatically
replays coding or validation tasks. Existing host recovery may inspect or drain
an exactly owned process/guest where supported; it must not promote unknown
outcomes to success without evidence. Queued, running and unknown jobs block
worktree deletion, including relevant jobs owned by another principal.

`mac_git_stage` and `mac_git_commit` jobs that fail before the Git process is spawned end
`failed` and release the worktree. A failure after the spawn stays UNKNOWN and pins the
worktree until the owner reconciles it; there is no MCP reconciliation tool and records
must not be hand-edited.

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
paths remain absent. Branch history is deleted conservatively: after the worktree is removed the Broker runs
`git branch -d` on the managed task branch, so a branch with unmerged commits is kept and
reported with `branch_deleted: false`. The owner deletes such a branch from the owner
terminal with `git branch -d <name>` once merged (never `git worktree prune`). A removal
retry with the completing key only re-attempts that cleanup. A refused removal lists
status counts (never file names): commit changes with `mac_git_stage` and `mac_git_commit`,
because ignored files cannot be removed by any tool. A task id can be created again after
removal with a new idempotency key. Cancelling blocking queued or running jobs needs an
explicit owner approval; unknown jobs stay until the owner reconciles the ledger.

### Gateway development clone

The registered development project (for example `DevelopmentProjects/Mac-Operator-MCP`)
is a separate clone with its own object store and is never updated automatically. The
scope difference from the owner project (`Documents/GitHub/...`) is intentional: only
registered development projects receive the V2 project, agent, audit and task scopes.
Update the clone with fast-forward only, after confirming `git status --short` is empty,
no managed worktree or job is active, and that `package.json` and the profile scripts
still hash to the registered `manifestSha256`:

    git -C <clone> fetch <source-repo> main
    git -C <clone> merge --ff-only FETCH_HEAD

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
source revision in [PROGRESS.md](../PROGRESS.md). An unavailable dependency or unverified project grant remains an explicit
acceptance dependency, never an implicit waiver.

## Personal O1 source-only upgrade

After explicit owner deployment authorization, the combined O1/V2 source can
replace the personal release while all V2 authority stays disabled. Keep the
exact O1 signed policy, OAuth and approval configuration, protected state root,
TLS and loopback status channel. Do not inject DevelopmentGateway into the
broad O1 roots; V2 enablement needs a separate narrow profile.

1. Verify the combined source, matching native artifacts and all 57 contracts.
2. Create a fresh protected immutable release; never overwrite the prior one.
3. Stop the supervisor, confirm no queued/running jobs or live listeners, and
   preserve a complete consistent protected state backup and prior launch args.
4. Atomically update only `packageRoot`, `contractsDirectory` and `sourceRevision`
   in the unsigned `personal/edge-service.json`, keeping the same state root.
   Do not run `init`/`provision`; the O1 upgrade command intentionally returns
   early for an already-O1 installation and cannot rebind this source.
5. Run snapshot preflight, start the new release through the existing PM2
   supervisor, and verify public OAuth, exact 38 tools/24 scopes, legacy read
   grants, revocation, and all V2/task gates. Save PM2 only after acceptance.
6. If readback fails, stop the new supervisor, restore the prior Edge config and
   prior release launch arguments. Restore the consistent full backup if any
   incompatible ledger change occurred. Keep the previous release and backup.

The upgraded native write adapter requires canonical authorization version 1;
copy its newly built native binary together with the matching JavaScript.
Older binaries fail source writes closed. O1 terminal smoke evidence continues
to belong to the separate owner authority, not to V2 isolation acceptance.
