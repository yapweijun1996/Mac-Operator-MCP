# Mac Operator V2 change report

Updated: 2026-10-02. V2 acceptance: PARTIAL. Source regression and personal
deployment: PASS.
Overall completion: **55%**, based on 6 of 11 Definition of Done gates verified;
5 require a real production coding/runtime workflow. This is an acceptance
estimate, not a claim that 55% of engineering effort remains.

Current branch: `main` (local merge; no push). Integration source commit:
`2c37194d9bd822e78ad088f61d79a5f91061e152`.
Original implementation branch: `codex/safe-development-gateway-v2`.
Baseline commit: `0be86f5`. Implementation commit:
`d43d4f5fc423d3ecd73d9357515def61b3d496b1`. A later documentation-only commit
records the independent O1 rollout below. No push or PR.

## Architecture before and after

| Before | After |
| --- | --- |
| Authenticated Edge → Local Broker scopes/policy/approval | Same authority boundary; additive project-scoped gateway admission |
| Filesystem workers and fixed safe Git on primary repositories | Same adapters, plus inventory-verified linked worktree Git support |
| Named task profiles; default fail-closed runner; async flag rejected | Same registry/isolation/job system; opt-in async and bounded retries; test/build aliases |
| Durable SQLite jobs/audit with conservative restart | Same ledger, with agent/test/build ownership/recovery and bounded execution-audit view |
| No accepted local Codex runtime | Trusted provisioning interface/preflight; execution still denied without accepted adapter/runtime |

The V2 interfaces add no unrestricted shell, sudo, credential mount, automatic
push or PR publishing. The original October 1 implementation did not migrate
the service. The separately authorized October 2 source rollout is recorded below.

## Independent live O1 deployment (later on 2026-10-01)

The owner-terminal work was implemented and deployed independently from this
V2 checkout. Its rollout evidence is
`evidence/2026-10-01-owner-terminal-control.md` on
`codex/owner-terminal-control` (runtime source
`fa215d61ba553c306127a0f0a676dffd39bd6cc3`, evidence commit
`463388cfd4b2fb210fb1d9321dc26ee5a1e79780`). It records release
`personal-20261001-o1a`, state `MacOperator-o1-20261001a`, 38 runtime tools and
24 scopes. This is source-backed handoff evidence; this V2 task did not perform
that rollout or merge its code.

A subsequent live `mac_capabilities` read confirmed a 46-contract catalog,
`mac_terminal_exec` implemented but `scope_not_granted` for this caller,
`mac_task_run` still `disabled_by_policy`, and no V2 Codex/worktree entries.
At that time the live mode was independent O1, while the V2 implementation
remained undeployed. Earlier G1 observations in the audit are
historical baseline evidence, not a statement that live deployment stayed G1.

O1 intentionally executes arbitrary owner-account commands, with owner-file
and network authority. Its own evidence explicitly excludes isolated-task
acceptance and warns that output redaction cannot guarantee secret protection.
Successful shell/CLI, timeout or cancellation checks are not evidence of V2
worktree, secret, readonly or descendant containment. O1 must not serve as a
fallback for V2 agent/test/build admission, and ordinary V2 coding approval
must not confer owner-terminal authority. V2 completion remains PARTIAL/55%.

## Verified source integration (2026-10-02)

The owner subsequently authorized testing, committing, merging to local main
and live deployment. The integration combines this V2 source with the existing
O1 branch to preserve the already deployed owner-terminal capability. The
October 1 separate-branch observations above remain historical evidence.
The personal rollout retains the exact O1 signed policy, 24 scopes and 38
runtime tools; no DevelopmentGateway is provisioned and all 11 V2 tools plus
`mac_task_run` stay disabled. Deployment does not advance V2 isolation/E2E
acceptance or confer new authority on existing OAuth grants.

Integration validation: **1330 tests, 1313 PASS, 17 SKIP, 0 FAIL** using the
standard `npm test`; native/TypeScript build and 57 strict tool contracts pass.
Style, documentation, verification matrix, process boundaries and native
canonical JSON checks pass. `npm audit` reports zero vulnerabilities after the
compatible `fast-uri` patch from 3.1.7 to 3.1.8.

Independent review found a P1 canonical-write alias bypass. It was reproduced
before fixing: a source directory alias to `.git` could rewrite metadata.
Native writes now require synchronous canonical-path authorization from a
pinned parent descriptor before temporary creation and again before commit;
callbacks deny Git metadata, secret zones and configured denied paths. Paths
are rechecked after callbacks; rejected writes leave no temporary remnants.
A native capability-version gate rejects writes through an older binary that
would ignore the new callback. Independent review accepted the fix, with
55 related regression tests passing and no unresolved P0/P1 findings.

O1 clone fixtures were changed from shared object stores to independent clones
so they respect the V2 metadata boundary. Duplicate test imports were removed.
The [personal rollout record](../evidence/2026-10-02-v2-o1-personal-rollout.md)
confirms live cutover to `personal-20261002-v2a` at integration commit `2c37194`.
The signed policy is byte-identical to the offline backup. Only unsigned source
binding fields changed. Public OAuth checks passed exact 38-tool owner and
27-tool read-only discovery, 26 reads for each grant, denied out-of-project
writes, terminal idempotency, timeout, durable cancellation and revocation.
`mac_health` is healthy; `mac_capabilities` reports all 57 contracts and disabled
V2/task tools. The tested native binary hash matches the release record. PM2
configuration is saved. No push or PR publication occurred.

This completes the authorized source deployment and local main merge. V2
production coding acceptance remains PARTIAL/55%; the O1 checks above cannot
substitute for it.

## Tools

Added 11 contracts and Broker policies:

- `mac_git_worktree_create`, `mac_git_worktree_list`, `mac_git_worktree_remove`
- `mac_git_branch_create` (creates a worktree; never switches the primary)
- `mac_codex_preflight`, `mac_codex_run`
- `mac_test_run`, `mac_build_run`
- `mac_git_push` (always denied), `mac_pr_prepare`, `mac_execution_audit`

Modified `mac_task_run` for strict async/task/retry/runtime fields while keeping
synchronous named-profile behavior. It accepts no arbitrary command or shell
string. Modified `mac_policy_explain` for bounded proposed arguments and a
non-executing future-action plan. Existing Git operations map an owned managed
checkout back to the exact original-project grant and retain explicit approvals.

Test/build selection uses an approved host command registry. It does not
execute arbitrary manifest scripts or guess a missing test command. A manifest
may inform operator registration; it is not authorization. Claude execution,
package installation and publishing are not added.

## Security and operational controls

- Protected separate state/worktree roots, exclusive inventory lock, native
  inode-conditional lock deletion, atomic fsynced provenance and conservative
  pending/removing records. Ordinary file roots cannot expose provenance or
  every task checkout at once.
- Owner/project/task-bound worktrees, stable retry fingerprints, canonical
  identities, no overwrite, no primary checkout switch and no force removal.
  Dirty and ignored files prevent removal; uncertain jobs pin storage.
- Fixed safe Git environment/arguments, blocked metadata indirection, symlink
  and alternate object stores, configuration content identity, reciprocal
  pointers, approved task HEAD and exclusive checkout branch ownership.
- Ordinary file writes/patches cannot modify `.git`. Same-worktree jobs block
  competing execution and premature Git mutation; distinct worktrees remain
  independent. Primary HEAD/index/content/status invariance has real fixtures.
- Four permission tiers with explicit scopes/targets/operation approvals. New
  tools default disabled; push fails closed even with a grant. Coding approval
  cannot authorize higher-risk actions.
- Production runner and owned-process proof remain mandatory. Profiles are
  snapshotted/frozen and narrowed to the exact worktree; runtime is bounded,
  credentials remain `none`, network must be explicit, direct privilege
  escalation executables are rejected.
- Expanded Codex/Claude/Firefox/MCP secret zones and `.env` variants. Raw `.env`
  content/hash is denied; existing metadata can expose existence safely.
  There is no new environment-value export or credential reader.
- Existing tamper-evident request/intent/completion ledger records actual
  scopes, project/task/worktree, duration, bounded changed paths and commit IDs
  where observed. Prompts and file/credential contents are not audit evidence.
  Async receipt proves admission; terminal status is separately inspectable.
- Existing restart UNKNOWN/quarantine, leases, cancellation and shutdown drain
  are reused; interrupted coding/validation tasks are never blindly replayed.

## Validation

Final suite: **1322 tests, 1305 PASS, 17 SKIP, 0 FAIL**. Native build and
TypeScript passed. Style, documentation, verification-matrix and process-boundary
checks passed. Two existing GUI test launchers were bounded and registered after
the boundary check found missing controls; GUI product code was preserved. All **56** tool contracts passed verification. V2 signed
Broker results were also validated against strict output schemas. Real Git
worktrees, stage/commit, audit/review and primary invariance passed. The physical
single-process Seatbelt probe passed allowed/denied file access, fork denial and
bounded output/time.

An initial default-concurrency run exposed an existing timing-sensitive UI
assertion. The unchanged file passed alone and complete concurrency-4 reruns
passed. See the [validation record](../evidence/2026-10-01-v2-gateway-validation.md)
for exact limits, commands, 25 required cases and mock-versus-physical evidence.

## Definition of Done accounting

| Gate | Status |
| --- | --- |
| Codex safely operates an authorized project | PENDING: accepted adapter/runtime/inference route |
| Codex writes only inside isolated worktree | PENDING: admission verified; real agent enforcement not exercised |
| Tests/builds run through production managed jobs | PENDING: lifecycle fixture verified; production executor absent |
| V2/R1 scoped APIs preserve secret and unauthorized path denials | PASS: native/file authorization regressions; O1 owner authority is a separate boundary |
| Unrestricted sudo/shell unavailable through V2 tool contracts | PASS: separate existing O1 authority is preserved; V2 never uses it as a fallback |
| Git push gated | PASS: implementation always denies |
| Audit evidence exists | PASS |
| Policy tests pass | PASS |
| Complete agent security acceptance tests pass | PENDING: real descendant/network/readonly agent evidence |
| YAP-MCP development E2E passes | PENDING: project identity and execution dependencies |
| Existing R1 behavior remains compatible | PASS: full regression and original contracts preserved |

## Limitations and remaining risks

1. No production `CodingAgentProvider` ships. Existing local runners have
   staging limitations; App Sandbox descendant escape is a known acceptance
   failure. VM/root-helper alternatives require installed/accepted host resources.
   CLI installation/login, mock proofs or prompts cannot replace these controls.
2. Credential-free model inference and the provisioned model catalog are absent.
   No user credential storage was read or mounted. Preflight reports unknown or
   not-ready rather than manufacturing authentication/model evidence.
3. Authorized discovery did not identify the exact YAP-MCP Git repository, and
   the results were bounded/truncated. Memory confirms Mac mini as host but no
   path. No YAP production source was modified. The requested live E2E is not
   passed by the synthetic Git fixture.
4. Operator startup integration, signed policy and OAuth provisioning are
   documented source seams, not an automatic migration or installed V2 profile.
   Direct file access to one new checkout needs exact filesystem roots/rules.
5. Pending/removing inventory needs reviewed host reconciliation. There is no
   MCP force-delete, dirty-removal override, push implementation or PR publisher.
   Inventory is capped at 256 records; Git metadata inspection at 50000 entries.
   Coding/validation retry identity also binds the original session and Edge;
   after authority rotation, inspect the owned job before a newly approved run.
   Worktree retries reuse provenance but still require an operation approval at
   the Broker; they are not an approval bypass. Complex object alternates,
   metadata symlinks and worktree configuration are
   conservatively rejected. Shared Git metadata means trusted host operators
   must avoid concurrent manual checkout/ref changes during managed operations.
6. Readonly/test-only and secret protections in an eventual coding runtime must
   be enforced by accepted outer isolation. Fixture readiness declarations prove
   admission behavior only. Secret scanners cover known signatures and zones;
   an eventual adapter must validate its project snapshot and output boundary.
   `allowed_paths` and `validation_plan` are validated and passed to the trusted
   adapter; per-file write restriction/plan enforcement still needs runtime evidence.
7. PR preparation and audit views are intentionally bounded. They are review
   evidence, not exhaustive ancestry or per-system-call filesystem tracing.
   Failed/unknown tasks require additional Git/status inspection before review.
8. Independent source-integration review accepted the confirmed fixes and
   independently reran 55 related tests. This is not a production coding
   isolation certification.

The recommended next step is to supply an accepted production execution and
credential-free inference boundary, then configure one staging project and run
its actual synthetic E2E. Keep current V2 execution disabled until that passes.

## Changed files

The original V2 implementation changed 51 files. The combined integration
changed 84 files relative to baseline `0be86f5`; the later rollout record is a
documentation-only commit. Unrelated existing progress/evidence edits remain
outside the task commits. The integration delta is available with
`git diff --stat 0be86f5 2c37194`.

- `PROGRESS.md`
- `README.md`
- `TOOL_CATALOG.md`
- `docs/MAC_OPERATOR_V2_CHANGE_REPORT.md`
- `docs/MAC_OPERATOR_V2_DESIGN.md`
- `docs/MAC_OPERATOR_V2_RUNBOOK.md`
- `evidence/2026-10-01-v2-gateway-validation.md`
- `packages/broker/src/broker-async-task.test.ts`
- `packages/broker/src/broker.test.ts`
- `packages/broker/src/broker.ts`
- `packages/broker/src/default-policy.ts`
- `packages/broker/src/development-gateway.test.ts`
- `packages/broker/src/development-gateway.ts`
- `packages/broker/src/development-policy.ts`
- `packages/broker/src/filesystem-inspector.test.ts`
- `packages/broker/src/filesystem-inspector.ts`
- `packages/broker/src/filesystem-patch.ts`
- `packages/broker/src/git-inspector.ts`
- `packages/broker/src/index.ts`
- `packages/broker/src/managed-worktrees.test.ts`
- `packages/broker/src/managed-worktrees.ts`
- `packages/broker/src/persistence.ts`
- `packages/broker/src/policy.test.ts`
- `packages/broker/src/sandbox-profile.ts`
- `packages/broker/src/secret-policy.test.ts`
- `packages/broker/src/secret-policy.ts`
- `packages/broker/src/service-startup.ts`
- `packages/broker/src/task-profile.test.ts`
- `packages/broker/src/task-profile.ts`
- `packages/contracts/src/catalog.ts`
- `packages/contracts/src/types.ts`
- `packages/contracts/src/verify-contracts.ts`
- `packages/edge/src/oauth-grant-status.ts`
- `schemas/policy-document.schema.json`
- `scripts/check-process-boundaries.mjs`
- `scripts/gui-hit-testing.test.mjs`
- `scripts/gui-transport.test.mjs`
- `tool-contracts/README.md`
- `tool-contracts/mac_build_run.json`
- `tool-contracts/mac_codex_preflight.json`
- `tool-contracts/mac_codex_run.json`
- `tool-contracts/mac_execution_audit.json`
- `tool-contracts/mac_git_branch_create.json`
- `tool-contracts/mac_git_push.json`
- `tool-contracts/mac_git_worktree_create.json`
- `tool-contracts/mac_git_worktree_list.json`
- `tool-contracts/mac_git_worktree_remove.json`
- `tool-contracts/mac_policy_explain.json`
- `tool-contracts/mac_pr_prepare.json`
- `tool-contracts/mac_task_run.json`
- `tool-contracts/mac_test_run.json`
