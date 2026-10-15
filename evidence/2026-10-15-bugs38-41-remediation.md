# BUG-38 through BUG-41 Remediation — 2026-10-15

Status: **DONE locally — all four authorized repairs implemented and regression-verified.**

Base revision: `a7d599934d3def5105b24871cf5229d75fecea24`, branch `main`.
The worktree already contained the preceding review's Markdown changes. Those
records were preserved and updated by status rather than discarded. Source,
tests and documentation are uncommitted. No push, deployment, production-state
change or live service acceptance is included.

## Scope and decisions

| Finding | Root correction | Preserved behavior |
| --- | --- | --- |
| BUG-38 | Independently attempt status and command close on every runtime path; preserve single errors, aggregate multiple errors, report failed state and allow cleanup retry. | Command server remains the owner of active-request cancellation, authority polling and key disposal; no new privilege or endpoint. |
| BUG-39 | Handle incomplete EOF/close and enforce one absolute response deadline; guard late connection validation after settlement. | Existing signed response validation, replay checks, byte cap and protected socket checks. |
| BUG-40 | Hold a private SQLite transaction throughout runner acquisition, recovery and release; atomically link a complete PID into its legacy directory. | Live/uninspectable legacy PID exclusion, bounded empty-lock grace, explicit failure on malformed or changed evidence, no service-policy mutation. |
| BUG-41 | Completed removal replay reads branch existence and never repeats branch deletion. | Existing owner/authority/project identity and replacement-worktree checks; first removal still uses non-force `git branch -d`. |

BUG-41 deliberately avoids new fields or an inventory version change. A record
completed before branch cleanup failed has no reliable ownership over any later
same-name ref. Readback is safe for old, restarted and archived records, whereas
reissuing deletion cannot distinguish a recreated branch. A remaining branch
therefore requires separate owner cleanup. On replay, `branch_deleted` describes
current absence; it does not assert a new deletion. The result schema is unchanged
and its description and operational documentation now make this explicit.

BUG-40 uses `node:sqlite`, already required by the auto-deploy script. The new
helper owns only `auto-deploy/lock.sqlite` and the runner's legacy PID directory,
not a Broker/Auth ledger. Holding `BEGIN IMMEDIATE` prevents concurrent new
runners from racing during stale cleanup. Kernel ownership ends on process exit,
including SIGKILL. The database file must remain at the same identity while in
use; the helper checks its regular-file identity, ownership and 0600 mode.

Existing published live legacy owners are respected. Fresh empty directories
receive a 30-second publication grace; stale empty directories are removed with
`rmdir`, so a concurrently published PID prevents removal. New PID bytes are
written/flushed privately and linked atomically, avoiding partial publication.
A crash after the link but before temporary cleanup can leave a second hard link;
recovery safely removes only the canonical dead PID and retains the scratch file.
Unknown directory contents and malformed legacy PID files require investigation.
Repeated or stale release cannot remove a successor's directory.

There is no state-format migration. Keep the helper with `run.mjs`. Quiesce the
runner before switching versions; preserve a live kernel-lock file. See the
[operational constraints](../docs/auto-deploy.md#lock-recovery). No automatic
rollback or release switch was executed as part of these source changes.

## Regression evidence

Tests were first added against the failing implementation:

- Root-helper, Edge status and worktree focused run: 54 tests, 39 passed and
  15 failed with the original cleanup/EOF/recreated-branch conditions.
- Lock helper initially retained the old runner algorithm with an injectable
  directory path: 14 tests, eight passed and six failed on unpublished locks,
  stale release, malformed PID and replacement ownership conditions.

No assertion was weakened to make these cases pass. The final implementation
adds **26 regression cases** and extends archive replay checks:

| Area | New cases and important assertions |
| --- | --- |
| Root-helper runtime | 12 cases: four lifecycle phases times status/command/both close failures; both cleanup attempts, error preservation, failed state and successful retry. |
| Edge status IPC | Four cases: empty EOF, partial EOF, reset and continuously dripping partial data. Each must settle with the correct transport/deadline error before a separate watchdog. |
| Worktree replay | One new real-Git case covers recreated branches before/after restart; the existing 256-record/archive test additionally verifies recreated branch preservation across archived replay/restart. |
| Auto-deploy lock | Nine cases cover fresh/stale unpublished directories, contention and stale release, live/dead legacy PID, malformed/unexpected evidence, replacement identity, real child SIGKILL, interrupted hard-link cleanup and redirected guard. |

The SIGKILL test launches only a disposable Node process with an explicit cwd,
minimal environment, `shell: false`, five-second timeout and 8 KiB output bound.
It acquires the actual helper lock, kills itself and leaves evidence that the
parent successfully reclaims. The process-boundary audit registers this test
entry and checks its bounds rather than exempting it from inspection.

## Final verification

| Check | Result |
| --- | --- |
| Build, including native stages | PASS |
| Native fault-test build | PASS |
| TypeScript typecheck | PASS |
| Current-source suite, 242 compiled/script test files | PASS: **2,272 total; 2,253 passed, zero failed/cancelled, 19 skipped** |
| Root-helper/Edge/worktree focused suites | PASS: 54 tests; final full run also includes enhanced archive assertions |
| Auto-deploy/preflight/recovery suites | PASS: 83 tests |
| Final auto-deploy lock assertions | PASS: 17 tests in the auto-deploy test file |
| Style, documentation, verification matrix and process-boundary checks | PASS |
| Contract/catalog/ledger schema validation | PASS: 58 contracts |
| Final diff, new-file whitespace, local links and finding status counts | PASS |

Runtime was Node.js `v25.5.0` on macOS. The full run mapped only tracked
`packages/*/src/*.test.ts` and `scripts/*.test.mjs` to current test artifacts,
required every mapped file to exist, and invoked
`node --test --test-timeout=120000` on those 242 files. The two obsolete ignored
compiled test files previously identified in the review were preserved and
excluded because they have no tracked source. The ordinary `npm test` glob was
not rerun; its earlier three stale-artifact failures are not claimed resolved.

Scratch logs are temporary convenience copies, not required permanent artifacts:

- `/private/tmp/mac-operator-bugs38-41-red.log`
- `/private/tmp/mac-operator-bug40-red.log`
- `/private/tmp/mac-operator-bugs38-41-focused.log`
- `/private/tmp/mac-operator-bug40-deploy-tests.log`
- `/private/tmp/mac-operator-bug40-final-focused.log`
- `/private/tmp/mac-operator-bugs38-41-full-tests.log`

The permanent regression source and retained baseline trigger descriptions in
the [bug report](../CODEBASE_BUG_REVIEW.md) make the repairs reviewable without
those logs. No production root-helper, actual auto-deploy cutover or live
identity-provider/GUI/Docker/VM workflow was exercised. Node 24 and the 19
opt-in/platform/integration skips remain unverified. Source correctness does
not establish that the running deployment contains these fixes.

## Knowledge reuse and next work

The preceding review's KB-MCP Skill content, local architecture-change guide,
existing runtime tests, worktree provenance/archive behavior and SQLite runtime
informed the implementation. Fresh KB recall returned `503 UPSTREAM_UNAVAILABLE`
and the engineering reuse endpoint returned an internal error. The authorized
work continued against the verified local evidence; no remote context was
invented and no unavailable reuse gate was described as passing.

BUG-38 through BUG-41 are fixed locally. BUG-42 through BUG-53 remain open;
the recommended next group is executable transfer, terminal stop and UTF-8
paging (BUG-42 through BUG-44). Deployment and remaining fixes are separate work.
