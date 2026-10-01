# Mac Operator V2 change report

Date: 2026-10-01. Status: PARTIAL. Source regression: PASS.
Overall completion: **55%**, based on 6 of 11 Definition of Done gates verified;
5 require a real production coding/runtime workflow. This is an acceptance
estimate, not a claim that 55% of engineering effort remains.

Branch: `codex/safe-development-gateway-v2`.
Baseline commit: `0be86f5`. The resulting focused local commit is recorded in the
final delivery response; this report is part of that commit. No push or PR.

## Architecture before and after

| Before | After |
| --- | --- |
| Authenticated Edge → Local Broker scopes/policy/approval | Same authority boundary; additive project-scoped gateway admission |
| Filesystem workers and fixed safe Git on primary repositories | Same adapters, plus inventory-verified linked worktree Git support |
| Named task profiles; default fail-closed runner; async flag rejected | Same registry/isolation/job system; opt-in async and bounded retries; test/build aliases |
| Durable SQLite jobs/audit with conservative restart | Same ledger, with agent/test/build ownership/recovery and bounded execution-audit view |
| No accepted local Codex runtime | Trusted provisioning interface/preflight; execution still denied without accepted adapter/runtime |

No unrestricted shell, sudo, credential mount, automatic push or PR publishing
was added. No live deployment was migrated as part of this V2 work.

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
| Current secrets and unauthorized path boundaries remain inaccessible | PASS: current fail-closed execution and native/file authorization regressions |
| Unrestricted sudo/shell unavailable through this gateway | PASS |
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
8. Independent review produced confirmed fixes, but its final follow-up was
   unavailable. This delivery is not an independent security certification.

The recommended next step is to supply an accepted production execution and
credential-free inference boundary, then configure one staging project and run
its actual synthetic E2E. Keep current V2 execution disabled until that passes.

## Changed files

This focused delivery contains 51 files. Only the V2 progress entry in `PROGRESS.md` is staged; unrelated existing progress/evidence edits are preserved outside the task commit.

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
