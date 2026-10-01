# V2 gateway validation — 2026-10-01

Status: PARTIAL. Source regression PASS; production Codex/YAP-MCP E2E NOT RUN.
Host: macOS arm64 Mac mini; Node 25.5.0, Codex CLI 0.153.4.
Baseline: `0be86f5`; branch: `codex/safe-development-gateway-v2`.
No live service, signed policy, OAuth grant or production project was changed by
this V2 implementation. No push or PR publication occurred.

This is historical October 1 evidence. The subsequent integration and live
source deployment are recorded in the [October 2 rollout record](2026-10-02-v2-o1-personal-rollout.md).
The newer 1330-test suite passed 1313, skipped 17 and failed zero. Real V2
coding isolation and YAP-MCP E2E remain unverified.

## Verification results

| Check | Result | Evidence limits |
| --- | --- | --- |
| Native build via `npm test` | PASS | Existing native targets and TypeScript built |
| Final TypeScript `npm run typecheck` | PASS | Static contracts, not runtime isolation |
| Full tests, concurrency 4 | 1322 total; 1305 PASS; 17 SKIP; 0 FAIL | Opt-in real task/Keychain/Docker/GUI probes remain skipped |
| Contract verification | 56 unique contracts PASS | 45 original plus 11 new; original wire version retained |
| V2 signed Broker integration | 9 tests PASS within full suite | Real Git/filesystem; fixture agent/runner for jobs |
| Managed worktrees | 12 tests PASS within full suite | Real Git, ownership, metadata, primary invariance, native lock deletion |
| Async task lifecycle | 11 tests PASS within full suite | Runner doubles; real SQLite admission, retries/recovery/audit |
| Physical Seatbelt probe | PASS | Allowed/denied reads/writes, fork denied, detached marker absent, bounded output/time |
| Style/docs/matrix/process-boundary checks | PASS | Explicit reviewed entrypoints; no shell fallback |
| Real production coding runtime | NOT RUN | No accepted credential-free coding adapter/production runner |
| YAP-MCP development E2E | NOT RUN | Exact repository not identified by authorized discovery; runtime prerequisite absent |

Reproduce full source verification after the native build with:

```sh
npm run typecheck
node --test --test-concurrency=4 --test-timeout=120000 packages/*/dist/**/*.test.js scripts/*.test.mjs
node packages/contracts/dist/verify-contracts.js
npm run probe:sandbox
```

The first default-concurrency `npm test` run had 1303 passes, 17 skips and one
existing UI retry-deadline assertion failure (two observations rather than one).
The unchanged UI file then passed 25/25 alone; bounded-concurrency complete
reruns passed. That assertion uses a real 40ms deadline and timer wakeups, so
its exact observation count is scheduling-sensitive. UI product behavior was
not changed; this transient failure is retained as a known test limitation.

The process-boundary check initially rejected two pre-existing GUI test scripts.
Review confirmed fixed fixture compilation/execution but missing explicit
cwd/environment/shell/timeout/output controls. The test harnesses now use fixed
`/usr/bin/clang`, minimal environment, explicit `shell:false`, bounded compiler
output/time, and transport-child lifetime/stderr bounds. They are registered with
mandatory boundary requirements; the gate was not bypassed. Both tests and the
boundary check pass. GUI product code remains unchanged.

The standalone physical probe uses temporary synthetic protected files and
cleans them up. It proves single-process Seatbelt containment only. It does not
prove multi-process Codex, guest boot/authentication, live API readiness,
production network isolation or a deployed managed task service.

## Real Git development workflow evidence

`development-gateway.test.ts` submits authenticated Broker requests with exact
original-project grants and owner approvals. It creates a controlled worktree,
reads status, edits a synthetic file in that checkout, stages only `source.txt`,
commits locally and prepares review/audit. It compares the primary repository's
HEAD, binary index bytes, working-file bytes and porcelain status before/after;
all remain unchanged. Test fixtures are removed afterward. This is real Git
integration evidence; the synthetic edit is made by the fixture, not by Codex.

Named test/build aliases return bounded asynchronous job receipts and reuse one
job/approval for an exact retry. Fixture runs cover terminal success, failure,
timeout, cancellation, shutdown, restart UNKNOWN/quarantine and different
worktree concurrency. No raw stdout is returned automatically with admission.

Independent review identified metadata indirection, reference-directory
symlinks, task HEAD redirection and shared primary/task branch ownership risks.
The implementation rejects these states before granting managed Git authority;
regression fixtures cover them. A later independent-review continuation was
unavailable; final source review and regressions were performed by the primary
engineer. This is not a complete independent security certification.

## Required acceptance cases

PASS below means the named source/native boundary was tested, not that a live
coding agent has exercised that boundary.

| # | Required case | Result and scope |
| --- | --- | --- |
| 1 | Authorized project read | PASS: existing read regressions and managed Git status with original-project grant |
| 2 | Unauthorized project denied | PASS: valid ungranted Git repository rejected by Broker |
| 3 | Secret path denied | PASS: expanded secret corpus, filesystem and coding path admission |
| 4 | Symlink escape denied | PASS: native filesystem and managed Git/storage regressions |
| 5 | Traversal denied | PASS: V2 canonical project/path admission and filesystem regressions |
| 6 | Worktree creation | PASS: real Git under protected controlled storage |
| 7 | Duplicate create idempotent | PASS: inventory reuses one checkout; conflicts denied; Broker write approval remains required |
| 8 | Codex readonly | PARTIAL: fixture admission PASS; real enforced readonly NOT RUN |
| 9 | Codex workspace-write | PARTIAL: owned-worktree admission PASS; real coding execution NOT RUN |
| 10 | Codex cannot escape | PARTIAL: path/cwd admission PASS; actual agent hostile runtime NOT RUN |
| 11 | Codex cannot read .ssh | PARTIAL: secret/path denial PASS; actual agent runtime NOT RUN |
| 12 | Codex cannot use sudo | PARTIAL: privileged executable registry denial PASS; descendant runtime NOT RUN |
| 13 | Test runner success | PASS: managed-job fixture and existing runner tests; production alias NOT RUN |
| 14 | Test runner failure | PASS: failure/exit evidence persisted and bounded |
| 15 | Timeout | PASS: job terminal timeout and physical probe bounds |
| 16 | Cancellation | PASS: job control/verified terminal fixtures; accepted production agent stop NOT RUN |
| 17 | Malformed command | PASS: arbitrary script field, unknown profile and malformed args denied |
| 18 | Stage explicit paths | PASS: empty paths denied; literal explicit file staged |
| 19 | Local commit | PASS: real Git commit with staged digest and readback |
| 20 | Push denied | PASS: denied even with scope/policy entry; no publishing action |
| 21 | Audit entry | PASS: owner/project filtering, actual scopes, task/worktree and commit evidence |
| 22 | Policy explain no execution | PASS: no provider resolution, runner call, job or worktree mutation |
| 23 | Primary unchanged | PASS: real Git HEAD/index/content/status comparisons on synthetic repository |
| 24 | Concurrent isolation | PASS: separate checkouts/jobs; one-worktree competing admission denied |
| 25 | Restart/recovery | PASS: durable job states, no replay, inventory reload and native stale-lock handling |

## Remaining live dependencies

1. Accepted production process/guest runtime with hostile descendant, filesystem,
   secrets, network, readonly/write, cancellation and restart evidence. Do not
   promote a staging runner or rely on cwd/CLI flags as the boundary.
2. Reviewed coding adapter and credential-free inference route. Installed Codex
   and local account login do not supply an approved credential mount or model
   catalog. Preflight reports unknown/not-ready when these are absent.
3. Exact YAP-MCP Git path and project grants. Authorized project discovery did
   not return it; results were traversal-bounded/truncated. KB recall confirms
   Mac mini execution location but supplies no canonical repository path.
4. Staged signed-policy and OAuth migration, followed by the actual synthetic
   YAP-MCP workflow and primary comparison. Ordinary coding approval never
   authorizes push, package installation or service/system mutation.

## Later independent O1 state

After V2 source delivery, another authorized task deployed its independent O1
release. Its committed rollout record was read in the separate owner-terminal
worktree. A fresh live capability read confirmed 46 registered contracts, the
owner-terminal contract with `scope_not_granted` for this caller, the task-run
contract with `disabled_by_policy`, and no V2 Codex/worktree contracts. No owner
terminal execution was performed during this follow-up. The O1 rollout did not
change the V2 source test counts or complete its production/YAP acceptance.
The [change report](../docs/MAC_OPERATOR_V2_CHANGE_REPORT.md) records its source
commits and the distinction between owner authority and isolated execution.
