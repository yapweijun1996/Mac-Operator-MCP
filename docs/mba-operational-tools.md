# MBA operational tool enablement

## Explicit owner opt-in

O1 and V2 retain their existing default tool and scope sets. An operator can add
`mac_docker_status`, `mac_docker_inspect`, and `mac_docker_logs` through the
protected `dockerReadAccess` configuration. This grants Docker reads only; it
cannot create containers, select another daemon, or expose Docker credentials.
The offline migration requires an existing root O1 or V2 installation:

```sh
node packages/auth/dist/personal-service.js docker-read <state-root> <source-revision> --enable
```

Stop the service and take a consistent private state backup first. The migration
verifies and signs a new exact policy revision, preserves unrelated targets,
filesystem roots, kill switches and GUI grants, and is idempotent. Existing OAuth
grants keep their original scopes. A fresh connection and owner consent are
required to obtain `mac.docker.read`; refreshing an old token cannot add it.
The independent `/terminal/` connection does not inherit Docker consent.

## Development runtime on a different Mac

Follow the [V2 operator runbook](MAC_OPERATOR_V2_RUNBOOK.md) before enabling the
development profile. Runtime evidence must bind this Mac's actual Engine ID,
immutable image ID, pinned Codex executable and provider version. Evidence from
another Mac is insufficient. Physical validation accepts an explicit
`MOPS_CONTAINER_ENGINE_ID` alongside `MOPS_CONTAINER_IMAGE_ID`; both are checked
against the real Engine. Worker processes do not inherit parent execution flags.

A full macOS build cannot be substituted by a Linux task. Before registering a
repository build, verify the actual approved command against that repository's
filtered snapshot and container resource budget. The initial MBA probe of this
MCP repository failed because source scanning omitted files and TypeScript hit
the default heap limit. That probe is not evidence of a successful project build.
Do not relax secret filtering or claim complete V2 acceptance from synthetic
build fixtures alone. Host-native builds remain available through the separately
authorized owner terminal.

Codex file tools accept workspace-relative paths. The workspace root listing uses
an empty string, and `public.txt` addresses a file; absolute host paths and
`/workspace/public.txt` remain denied. Real read-only and workspace-write
acceptance must verify imported changes and the unchanged primary repository.

## Availability is more than signed policy

With Docker opt-in, O1 enables 42 tool implementations and V2 enables 53. Ordinary
V2 coding OAuth still excludes the two owner-terminal tools. Use the independent
owner-terminal connection when enabling that profile; never silently expand old
OAuth grants. GUI readiness continues to use the installed application's
LaunchServices identity and its existing TCC permissions. Runtime provisioning
must not rebuild or reinstall that application.

`mac_git_push` is implemented as a bounded, non-force push (see [Git push](git-push.md)). Privileged operations and service control likewise
require their own configured, authenticated executors and operation targets.
Changing enablement flags cannot implement those tools or validate their
postconditions. Their absence must remain visible in capability diagnostics.


## MBA V2 named validation profiles

`build:catalog` builds deterministic public metadata for the repository's actual
tool contracts and verifies the output hash. `test:catalog` checks artifact
integrity, invalid contract rejection, deterministic identity and safe output
publication. These are platform-independent commands for the registered clean
development repository; they run in an owned container with network denied.
The build profile writes its artifact in the disposable container's `/tmp`, so
validation cannot import generated files into a coding worktree.

`mac_test_run` and `mac_build_run` take `max_runtime` in **milliseconds**. The approved
maximum is set per profile (currently 120000 ms for the catalog profiles) and is reported
in the rejection message when exceeded. The deadline covers Engine checks, container start,
workspace staging and the command; a deadline failure reports the phase that was running.
Where the time goes has not been measured on the MBA: earlier notes that staging dominates
were an assumption. Container runs now record per-phase timing (see "Phase timing" below).

These named profiles do not claim a full TypeScript or macOS native build.
The initial full TypeScript container probe remains failed; secret-content
filtering and the existing resource limits remain enforced. Full host-native
verification uses the independently authorized owner terminal connection.
The coding connection at `/mcp` exposes the 51 coding/GUI/read tools, and the
independent `/terminal/mcp` connection provides owner terminal authority. The
shared signed policy enables 53 implementations; neither connection silently
inherits the other connection's additional scopes.

## Development worktree workflow and its limits

Behaviour observed in MBA probes that the tool schemas alone do not show.

### Branches and references

- **Branch names** for `mac_git_worktree_create` and `mac_git_branch_create` must start with `codex/`
  (for example `codex/my-task`). The input description states the segment rules: letters, digits, `. _ -` and `/`
  only, at most 127 characters, no empty, dotted or `.lock` segments, no `..`, no `//`, no trailing `/`.
  Create checks `refs/heads/<branch>` first: an existing branch gives `CONFLICT` "Branch X already exists; choose
  another branch_name" and uses no inventory slot.
- **`base_ref`** (create tools and `mac_pr_prepare`) is a branch, tag or commit name of letters, digits, `. _ - /`.
  The schema rejects `@` and `~`; revision expressions such as `HEAD~1` or `main@{1}` are not accepted.
  The schema still cannot express "no `..`"; the runtime rejects it with `PRECONDITION_FAILED`.

### Working in a worktree

- **Ordinary file tools cannot read or write inside a managed worktree.** The signed policy denies
  `DevelopmentWorktrees/MBA-MCP` to every ordinary root, so `mac_read_file`, `mac_list_directory`,
  `mac_directory_tree`, `mac_stat_path`, `mac_hash_file`, `mac_find_files`, `mac_search_text`,
  `mac_write_file_atomic` and `mac_apply_patch` are denied there (`POLICY_DENIED`). For a worktree you own, the
  message now names the cause: "Path is inside a managed worktree: ..." and `mac_policy_explain` returns the reason
  codes `POLICY_DENIED` and `MANAGED_WORKTREE_PATH`. Secret-shaped paths, `.git` metadata, other principals'
  worktrees and removed worktrees keep the generic denial. Lifting the restriction needs code changes
  (`v2FilesystemRoots` / `assertV2Policy` in `packages/auth/src/v2-policy.ts`, `assertProtectedStorage`), a per-task
  path authorization and a new signed policy revision, not only a policy edit.
- **Change code with `mac_codex_run`; review it with Git tools.** `mac_git_status` shows what changed,
  `mac_git_stage` followed by `mac_git_diff` (staged) shows the content, and `mac_pr_prepare` summarises paths,
  commits and test evidence. A coding import cannot delete files. `mac_apply_patch` with `project_root` set to the
  original project edits the primary checkout, not the worktree.
- **`mac_test_run` / `mac_build_run`** validate the worktree as it is; on an unmodified worktree they test unmodified code.

### Removing a worktree

- **Commit, then remove.** `mac_git_worktree_remove` requires a clean status including ignored files. Otherwise it
  returns `POLICY_DENIED` with counts only (staged, unstaged, untracked, ignored; file names are never shown).
  Commit tracked and untracked changes with `mac_git_stage` and `mac_git_commit`; the task branch is then kept.
  Ignored files cannot be removed by any tool. Over-limit Git output gives the same `POLICY_DENIED`.
- **Unfinished jobs block removal.** Queued, running and unknown jobs on the project pin it, including other
  principals' jobs. The message names up to three of your own jobs and only counts the rest. Queued or running jobs
  can be cancelled with `mac_job_cancel`, which needs an explicit owner approval (the delegated coding approver does
  not approve it); unknown jobs cannot be cancelled and stay until the owner reconciles the ledger.
- **After removal** the worktree path for a task is deterministic, so the same task id can be created again with a
  new `idempotency_key`, and that worktree is removed with a new removal key. A key that already removed an earlier
  worktree gets `CONFLICT` ("IDEMPOTENCY_KEY_IN_USE: ... Use a new idempotency_key") and never touches the newer
  checkout. Repeating a create whose worktree was later removed is now `CONFLICT` (it was `UNKNOWN_OUTCOME`).
  Pending or removing records stay `UNKNOWN_OUTCOME` and need operator reconciliation; `mac_git_worktree_list`
  adds a warning for each. The 256-record inventory cap counts removed records for ever.
- **The task branch is deleted with `git branch -d`** after the worktree is gone. A branch with commits not merged
  into the primary checkout's HEAD is kept: the result has `branch_deleted: false` and a warning. Merge it, or
  delete it from the owner terminal with `git branch -d <branch>` once merged. Do not use `git branch -D` for
  unmerged work unless the owner has decided to discard it. Retrying a completed removal with the same key
  re-attempts only the branch cleanup and needs its own owner approval.

### Jobs

- **Container jobs show no live output.** `mac_job_status` returns empty `stdout`/`stderr` while a test, build or
  task job is `running`; output appears when the job finishes. There is no phase or progress field there.
- **`mac_job_cancel` on a finished job is `CONFLICT`**, returned before any approval is requested: "has already
  finished (state: completed|failed|cancelled). Read its result with mac_job_status", or for `unknown` "its outcome
  is unresolved ... cannot change it". Only queued and running jobs can be cancelled. Client automation that
  treated an approved cancel of a finished job as success must treat `CONFLICT` as "already finished".
- **`mac_job_status` `outcome_class`** (optional): for a `failed` job whose request recorded `TIMEOUT`,
  `OUTPUT_LIMIT`, `VERIFICATION_FAILED` or `EXECUTION_FAILED`. Best effort: absent while the request is still
  completing, after the request was reconciled to unknown, and when request history was pruned. A timeout is still
  job state `failed`.
- **A task cannot outlive its access token.** Access tokens last five minutes and a task's authority ends when the
  token expires. The accept receipt warns "The access token authorizing this task expires in Ns but the task may
  run up to Ms; a task still running at expiry is cancelled, and a re-run needs a NEW idempotency_key". A job
  cancelled for that reason reports that the token expired (or that the Broker was shutting down, or that
  authority was revoked or the policy changed), each with the new-key advice. Start long tasks right after a token refresh.
- **Idempotent replay.** Repeating a task key returns the recorded job with `ok: true` and runs nothing; the
  receipt's first warning reads "IDEMPOTENT_REUSE: <job id> is <state>; nothing was run again. Use a new
  idempotency_key to run it again." This applies to cancelled and failed jobs too.

### Idempotency keys

Keys are per account, permanent and never freed; the contract descriptions say so. Repeating the identical request
from the same OAuth login never runs it again, but what comes back depends on the recorded job: task tools return it
with `ok: true` in any state (see above); `mac_write_file_atomic` replays only a completed write and answers a queued
job with `CONFLICT`, a running or unknown one with `UNKNOWN_OUTCOME`, a cancelled one with `CANCELLED` and a failed
one with `EXECUTION_FAILED`; `mac_terminal_exec` replays a completed or failed result (`reused: true`) and answers
the other states with `UNKNOWN_OUTCOME`, `CANCELLED` or `CONFLICT`; a repeated `mac_terminal_session` start is
`CONFLICT` in every state. Any different request needs a new key. Namespaces are
shared across tools: write, terminal exec and terminal session share the raw key; `mac_test_run`, `mac_build_run`,
`mac_codex_run` and `mac_task_run` share one task-key space. A held key now gives `CONFLICT` starting
"IDEMPOTENCY_KEY_IN_USE: this idempotency_key already belongs to job <id> (<tool>, <state>, created <time>)", plus
the first differing binding (tool, arguments, target, policy version, OAuth login, Edge connection) and what to do.
Archived jobs keep their keys; inspect them with `mac_job_status`. A replay of a write or terminal request from
another OAuth login is still detected only after the approval is consumed.

### Audit

- **`mac_execution_audit` paging.** `limit` defaults to 50 (max 100). When older events remain, `truncated` is
  true and `next_cursor` is returned; pass it as `cursor` for the next page (opaque; a malformed cursor is
  `PRECONDITION_FAILED`). An exact-limit page reports `truncated: false`. Internal `internal_*` ledger rows are
  not shown in the project view.
- **Failure rows** for requests with a worktree or task now carry project, worktree, task id and job id, so a
  failed git or task run appears in `mac_execution_audit(project_root)`. Rows written before deployment stay invisible there.
- **`mac_pr_prepare` test evidence** is task-scoped (principal, worktree, task id), keeps the newest 32 outcomes in
  chronological order, and no longer drops a finished run when other project activity fills the audit window.
- **Phase timing.** Container task runs record `phase_ms` on the audit event, whether they completed, timed out, were
  cancelled (for example at token expiry) or failed: `prepare`, `start`,
  `snapshot`, `stage`, `command` (also the coding controller run), `export`, `import` and `cleanup`, whole
  milliseconds; phases never entered are absent. A run cut off mid-phase includes that phase with the time it had run
  (a timeout in the export phase shows `prepare` to `command` and `export`), plus `cleanup` when the container was
  removed. A container deadline also appends `phases (ms): ... (in progress)` to the job's `stderr`. Limits:
  `mac_job_status` does not show it; host process runners report none; the event's `duration_ms` is measured separately, so phases need not add up to it.
  Compare `stage` with `command` on a real MBA run before concluding anything about staging overhead.

### Git jobs

`mac_git_stage` and `mac_git_commit` jobs that fail before the Git process is spawned now end `failed` and no longer
pin the worktree. A failure after the spawn stays `unknown` and pins the worktree until the owner reconciles it:
staging a missing untracked file in an existing directory, a staged-secret denial after `git add`, a non-zero
`git commit` exit (for example no `user.name`) and "Git commit did not advance HEAD". An empty index now reports
"Nothing is staged to commit; stage the intended paths with mac_git_stage first" (the single-use approval is still consumed).
