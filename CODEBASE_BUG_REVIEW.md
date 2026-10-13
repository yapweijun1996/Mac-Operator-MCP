# Codebase Bug Review

Review date: 2026-10-13 (Asia/Kuala_Lumpur)
Reviewed revision: `09dd85b99b7ffc0246a14f85959a7b49473d7abc` (`main`)
Remediation date: 2026-10-13
Status: **DONE — all nine new findings FIXED locally and regression-verified.**

This report records **37 findings, all FIXED in the current working tree**:
28 historical repairs are in the reviewed revision, and BUG-29 through BUG-37
are nine additional P2 repairs implemented after the user authorized option A.
The historical findings comprise 8 P1 and 20 P2 defects. This pass adds no
confirmed P0/P1 finding. Each new defect was reproduced against the baseline
before repair; the retained trigger descriptions below document that behavior.

Repair-revision regression (`a7f2450`): **2,226 passed, 0 failed, 0 cancelled, 19 skipped;
2,245 total**, across 242 test files. The change adds 32 regression cases.
The previously missing BUG-15 through BUG-28 history is also restored below.
FIXED refers to verified local source behavior. No production configuration,
migration, deployment or push is included in this remediation.

Repairs are committed as `a7f2450`. Subsequent actual pre-deployment acceptance
found two existing production configuration/provenance blockers and a missing
approved task image. The exact original image was later restored from an older
archive. Follow-up at 15:41 UTC found another workflow had installed `17bbdfd`:
the service and authenticated MCP health/capabilities/terminal smoke pass. The
original authorization/runtime/inventory bindings are preserved, but the two
earlier findings remain unresolved and the installed supervisor has lost its
explicit bounded-restart configuration. These operational findings and the
verified backup are recorded in the
[pre-deployment evidence](evidence/2026-10-13-predeployment-acceptance.md).

P1 denotes a security boundary failure, serious availability failure, or unsafe
state recovery. P2 denotes a narrower functional, integrity, or verification
defect. This is a broad review with focused deep checks, not an exhaustive proof
that every file or unexecuted platform path has no other bugs. The list contains
all supported findings from the reviewed paths; hypotheses are not counted.

## Findings repaired in this change

| ID | Priority | Original defect | Status | Original reproduction |
| --- | --- | --- | --- | --- |
| BUG-29 | P2 | OAuth polling revokes a valid read session when an older scope expires during status lookup | FIXED | Injected clock crossing the older token's expiry |
| BUG-30 | P2 | Git commit accepts a staged-content precondition while committing different content | FIXED | Actual Git with an index change between validation and commit |
| BUG-31 | P2 | Deleting every patch line leaves an unwanted newline | FIXED | Actual native file write and byte readback |
| BUG-32 | P2 | Git diff silently omits quoted filenames from changed paths | FIXED | Actual Git diff of `caf\u00e9.txt` |
| BUG-33 | P2 | Git diff reports complete output after dropping its 5,001st changed path | FIXED | Actual parser with 5,001 short diff headers |
| BUG-34 | P2 | Patch policy explanation allows a project whose filesystem root denies writes | FIXED | Signed requests through the actual Broker |
| BUG-35 | P2 | Removed worktrees permanently consume the 256-record creation quota | FIXED | Valid inventory with 256 removed records and no active checkout |
| BUG-36 | P2 | A removed worktree's missing original project prevents inventory startup | FIXED | Valid removed record after its historical project is unavailable |
| BUG-37 | P2 | Docker semantic result caps do not propagate the truncation flag | FIXED | 501 CLI containers and 1,001 Engine mount records |

## Repair implementation and verification

| Finding | Implemented behavior | Regression evidence |
| --- | --- | --- |
| BUG-29 | Re-evaluate live scope expiry after the status lookup. A newly accepted scope is checked on the next poll; refreshing a different scope cannot hide genuine terminal revocation. Explicit inactive status still revokes the session. | [OAuth monitor tests](packages/edge/src/oauth-grant-status.test.ts): expiry during lookup, inactive status, concurrent broader token and concurrent read-only refresh. |
| BUG-30 | Hold the shared index lock, validate and commit a private index snapshot against a pinned parent, then compare the actual committed diff and shared index before success. A noncooperating concurrent index replacement is preserved and produces an unresolved result; it cannot enter the approved commit. | [Git tests](packages/broker/src/git-inspector.test.ts): real index replacement during snapshot/commit, exact committed bytes, preserved concurrent content, existing lock, stale digest, cancellation and revoked authority. [Hook isolation](packages/broker/src/git-hooks-isolation.test.ts) and [signed V2 workflow](packages/broker/src/development-gateway.test.ts) pass. |
| BUG-31 | Emit zero bytes when a patch removes every line, while retaining deliberate blank lines. | [Patch tests](packages/broker/src/filesystem-patch.test.ts): terminated/unterminated source, intentional blank line and multiple deletion hunks with native readback. |
| BUG-32 | Decode Git's C-quoted UTF-8 header bytes. Header-shaped hunk content cannot introduce fake changed paths; unsupported path shapes report incompleteness. | [Git tests](packages/broker/src/git-inspector.test.ts): actual ASCII, spaces, UTF-8, quotes, nested separator-like names, additions/deletions, mode-only headers and unsafe control characters. |
| BUG-33 | Carry the changed-path cap into the top-level truncation result. | [Git tests](packages/broker/src/git-inspector.test.ts): exactly 5,000 and 5,001 distinct paths, including repeated headers. |
| BUG-34 | Patch explanations reuse execution's filesystem write planning, including explanations without proposed arguments. | [Signed Broker tests](packages/broker/src/broker.test.ts): writable/metadata-only roots, with/without arguments, execution denial and no diagnostic mutation. |
| BUG-35 | At the hot inventory limit, archive completed provenance and retry indexes before releasing slots. Active/pending/removing records remain bounded, and old create/removal keys remain enforceable after restart. | [Worktree tests](packages/broker/src/managed-worktrees.test.ts): 256 removed records, new creation, stale retries against a replacement checkout, restart, interrupted publication and corrupt archive refusal. |
| BUG-36 | Validate removed records' historical syntax without requiring a live old repository. Live records and actual branch cleanup retain project identity checks. | [Worktree tests](packages/broker/src/managed-worktrees.test.ts): missing removed versus active projects, archived restart and missing-project retry refusal; existing replacement-project/revoked-authority fences pass. |
| BUG-37 | Return parser completeness for Docker containers, images, ports and mounts, and combine it with transport truncation. Exact limits remain complete. | [Docker tests](packages/broker/src/docker-inspector.test.ts): CLI 500/501 containers and images, Engine 1,000/1,001 mounts, 128/129 bound/unbound ports, plus existing IPv4/IPv6 deduplication. |

The Git snapshot owns its temporary-file lifecycle in
[git-index-snapshot.ts](packages/broker/src/git-index-snapshot.ts). The process
supervisor checks that `GIT_INDEX_FILE` names a live Broker-created snapshot
for the same project and `/usr/bin/git`, both at admission and before spawn.
General task profiles still reject this execution-control variable. Shared
index snapshots are bounded to 4 MiB. Normal failures clean up exact owned
files; uncertain process termination retains the files/lock for reconciliation
and retires the in-memory capability. A created commit is never reset as
an automatic response to verification failure.

Worktree migration is lazy, triggered by creation at the 256-record limit.
Immutable completed records and exact-key indexes are synced before publication
of the versioned `0.2` manifest. Startup and retry lookups remain bounded without
scanning all historical records. Archives preserve retry evidence indefinitely
on disk, so disk history still grows with completed work. Older binaries reject
the new manifest. Back up the full protected state before deployment; rollback
after migration requires a consistent backup and reconciliation of subsequent
work. Migration, failure and rollback procedures are documented in the
[V2 runbook](docs/MAC_OPERATOR_V2_RUNBOOK.md#inventory-reconciliation-and-removal)
and [operational guide](docs/mba-operational-tools.md#git-jobs).

| Final check | Result |
| --- | --- |
| Build, including all native stages; native fault-test build | PASS |
| TypeScript typecheck | PASS |
| Current tracked-source suite, 242 compiled/script test files | PASS: **2,226 passed, 0 failed, 0 cancelled, 19 skipped; 2,245 total** |
| Style, docs, verification matrix and process-boundary checks | PASS |
| Contracts and versioned ledger schema | PASS: 58 contracts |
| Report links/status consistency, new module style and final diff whitespace | PASS |

The full suite was run outside the restricted sandbox with automatic approval,
using temporary state and local test listeners. An earlier sandbox-only process
run emitted macOS Python `confstr()` warnings that disturbed output budgets and
descendant tests; all corresponding tests pass in the final host run. No check
was weakened to dismiss those failures. Final logs are under
`/private/tmp/mac-operator-repair-*.log`; the full result is
`/private/tmp/mac-operator-repair-final-tests.log`. Node was `v25.5.0`; Node 24,
the 19 opt-in/platform/integration skips, live GUI/OAuth/Docker, production
migration and rollout were not separately exercised. Source verification does
not assert a deployment. No new dependency was added.

## Original triggers for BUG-29 through BUG-37

The descriptions and line locations below preserve the reviewed baseline.
The implementation and acceptance evidence above own the repaired behavior.

### BUG-29: Token expiry during polling causes false session revocation

**Location at review:** [oauth-grant-status.ts](packages/edge/src/oauth-grant-status.ts),
`OAuthGrantRevocationMonitor.poll()`, lines 158-181; Broker propagation is wired
in [service-startup.ts](packages/edge/src/service-startup.ts).

**Trigger and observed result:** Track an older token carrying read and terminal
scopes until second 101 and a newer read-only token until second 200. Start the
status read at second 100, then complete it at second 102 with
`{ active: true, scopes: ["mac.control.read"] }`. The actual monitor calls
`onRevoked` once, still carrying the expired terminal scope. The newer read
token remains within its lifetime. This uses the monitor's supported injected
clock and a synthetic reader; no issuer or Broker was revoked by the fixture.

**Cause and impact:** Expired scope entries are pruned before the asynchronous
lookup, but the resulting decision uses the captured context without another
expiry check. A legitimate scope reduction can be turned into durable
revocation of the entire session, interrupting valid later requests/jobs.

**Original repair recommendation:** After lookup, resolve the latest tracked session and
compare only scopes with an unexpired accepted token at decision time. Preserve
explicit inactive-grant revocation and revocation of a genuinely live removed
scope. Test expiry during lookup, concurrent token tracking, and inactive status.

### BUG-30: Staged digest does not bind the content Git actually commits

**Location at review:** [git-inspector.ts](packages/broker/src/git-inspector.ts),
`GitWriteInspectorImpl.commit()`, lines 394-451, and `readStagedSnapshot()`.

**Trigger and observed result:** Stage `single.txt` containing `approved\n` with
the actual stage implementation and retain its returned digest. Call commit
with that digest. A controlled supervisor fixture executes real Git commands,
but changes the file to `replacement\n` and stages it immediately before the
commit command. Commit returns success, `precondition.matched: true`, and the
approved digest. Independent `git show HEAD:single.txt` returns `replacement\n`.
No user's repository or remote was modified.

**Cause and impact:** The digest is checked against an earlier index snapshot.
Neither the mutating command nor the resulting commit tree is bound back to
that snapshot. Concurrent local index updates can therefore produce a commit
with content different from the approved precondition while the result claims
that the precondition matched. This requires a local concurrent index writer;
it does not establish remote unauthorized Git access.

**Original repair recommendation:** Commit from an immutable validated index/tree using a
reviewed index ownership/locking strategy, and compare the resulting tree to
the approved snapshot before reporting verification. A check after commit must
report uncertainty rather than silently reset a commit already created. Test
index changes during snapshot collection and between collection and spawn.

### BUG-31: Deleting all patch lines produces a one-byte file

**Location at review:** [filesystem-patch.ts](packages/broker/src/filesystem-patch.ts),
`applyUpdate()`, lines 278-297.

**Trigger and observed result:** Start with `one\n`, then apply:

```text
*** Begin Patch
*** Update File: single.txt
@@
-one
*** End Patch
```

The native write succeeds and the result is `applied`, but the resulting file
contains `\n` (one byte) instead of being empty (zero bytes).

**Cause and impact:** The function restores the original final newline even
when the hunk removes every source line, changing the requested file content.

**Original repair recommendation:** Emit zero bytes when no lines remain; preserve existing
newline behavior for nonempty output. Test both final-newline variants, deleting
all lines versus retaining an intentional blank line, and multi-hunk deletion.

### BUG-32: Quoted Git filenames vanish from changed_paths

**Location at review:** [git-inspector.ts](packages/broker/src/git-inspector.ts),
`extractGitDiffPaths()`, lines 844-876, and the fixed diff arguments at 307-339.

**Trigger and observed result:** Modify the ordinary filename represented in
JavaScript as `"caf\u00e9.txt"`. The actual diff inspector runs real Git. The
returned diff contains the changed content, but `changedPaths` is empty,
`truncated` is false, and there are no warnings.

**Cause and impact:** Git's default filename quoting emits quoted header paths.
The parser recognizes only unquoted `a/` and `b/` prefixes. A valid UTF-8
filename is therefore omitted from the reported change inventory. Quoted
double-quote filenames have the same parser limitation.

**Original repair recommendation:** Obtain paths from a separate bounded NUL-delimited Git
path readback, or correctly decode Git's quoted path format. Preserve protected
path redaction. Test ASCII, spaces, UTF-8, double quotes, additions and deletions.

### BUG-33: Git changed-path truncation is not reflected in truncated

**Location at review:** [git-inspector.ts](packages/broker/src/git-inspector.ts),
`parseGitDiffResult()` at 827-828 and `extractGitDiffPaths()` at 844-876.

**Trigger and observed result:** Supply 5,001 distinct, short valid diff headers
within the 1 MiB byte budget. The actual parser returns only 5,000 paths and a
path-limit warning, but `truncated: false`.

**Cause and impact:** The extractor keeps its truncation state locally and
returns only an array. The result flag accounts for byte/process limits, not
omitted paths, so consumers relying on the flag can treat a partial inventory
as complete. The warning prevents this from being wholly silent.

**Original repair recommendation:** Return completeness alongside extracted paths and
propagate it to the result. Test exactly 5,000 and 5,001 unique paths, repeated
headers, and independent byte truncation.

### BUG-34: Policy explanation bypasses patch filesystem-write checks

**Location at review:** [broker.ts](packages/broker/src/broker.ts),
`mac_policy_explain`, lines 2786-2852; actual patch planning at 4995-5014.

**Trigger and observed result:** Configure a canonical Git project with the
project write target rules and required principal scopes, enable the patch
tool, but set its filesystem root to `write: false`. A signed
`mac_policy_explain` request for `mac_apply_patch` and that project returns
`decision: allow`. An actual signed patch request returns `POLICY_DENIED`:
`Filesystem root does not grant write for this path`.

**Cause and impact:** Without `proposed_arguments`, project-target explanation
validates only the Git root and target rules. It omits the filesystem write
authorization used by patch planning. This is misleading diagnostics, not a
write authorization bypass; actual execution correctly denies the operation.

**Original repair recommendation:** Reuse the same pure target/capability resolution for
explanation and execution. Avoid consuming approvals or creating jobs while
explaining. Test writable/metadata-only roots, denied subpaths, managed worktree
mapping, and explanation both with and without proposed arguments.

### BUG-35: Worktree history exhausts creation capacity after cleanup

**Location at review:** [managed-worktrees.ts](packages/broker/src/managed-worktrees.ts),
constructor at 99-101, create at 199, and removal at 276-277.

**Trigger and observed result:** Open a schema-valid protected inventory
containing 256 removed records with absent checkout paths. Listing returns no
active worktrees. A new authorized create with fresh task/key fails with
`CONFLICT: Managed worktree inventory is full` before any Git mutation.

**Cause and impact:** Every successful removal retains a permanent tombstone;
both creation and startup bound the total record count. There is no supported
retirement/archive path, so ordinary create/remove use eventually prevents all
new development tasks despite successful cleanup. This lifetime-cap limitation
was already mentioned in the historical progress notes and remains unresolved.

**Original repair recommendation:** Introduce a bounded, audited tombstone retention/archive
policy that preserves promised retry behavior. Do not simply drop old keys or
raise the limit indefinitely. Test repeated create/remove cycles and retained
retry keys after compaction.

### BUG-36: Removed worktrees depend on a live historical project at startup

**Location at review:** [managed-worktrees.ts](packages/broker/src/managed-worktrees.ts),
constructor at 99-101 and `validateRecord()` at 486-495.

**Trigger and observed result:** Keep one otherwise valid `state: "removed"`
record, then make its former project root unavailable. Opening the actual
inventory throws `TARGET_NOT_FOUND: Git project root was not found`; the
worktree and state roots remain valid and there is no active checkout.

**Cause and impact:** Startup applies `validateCreate()` to every historical
record, requiring the original repository to exist even for completed removals.
A removed/decommissioned project can prevent the gateway from starting for
other available projects. The source record was synthetic; no real project
directory was deleted or moved by this task.

**Original repair recommendation:** Validate historical record syntax separately from live
repository identity. Require live identity for active operations and completed
removal branch retries, preserving BUG-28's fence. Test missing projects for
removed versus active/pending records and retry against a replacement project.

### BUG-37: Docker semantic caps return truncated=false

**Location at review:** [docker-inspector.ts](packages/broker/src/docker-inspector.ts),
CLI `status()` at 292-304, `parseContainerLines()`/`parseImageLines()` at 517-546,
`parseInspection()` at 571-587, and `parseMounts()` at 701-712.

**Trigger and observed result:** With a synthetic successful CLI response
containing 501 short container records, status returns 500 records, a cap
warning and `truncated: false`. Through the actual Engine inspector with a
synthetic exact-ID response containing 1,001 mounts, inspect returns 1,000
mounts, a cap warning and `truncated: false`. No Docker daemon was contacted.

**Cause and impact:** Semantic record caps are represented only as warnings;
the result flag reflects transport truncation. A bounded, incomplete container
or mount inventory is incorrectly marked complete. The mount path affects the
Engine inspector used by the personal runtime; the first trigger concerns the
separate CLI adapter. Images/ports use the same incomplete propagation pattern.

**Original repair recommendation:** Return structured completeness from the parsers and
aggregate all semantic caps into the result flag. Test exact limits and one
over each limit independently of transport/output limits.

## Pre-repair review verification and coverage

| Check | Result at the reviewed revision |
| --- | --- |
| `npm run build`, including its native stages | PASS |
| Native peer fault-test build | PASS |
| `npm run typecheck` | PASS |
| Current tracked-source suite: 242 compiled/script test files | PASS: **2,194 passed, 0 failed, 0 cancelled, 19 skipped; 2,213 total** |
| `npm run lint` | PASS, including final documentation |
| `npm run verify:docs` | PASS: 48 README links and 8 required runbooks |
| `npm run verify:matrix` | PASS |
| `npm run verify:process-boundaries` | PASS: zero unreviewed entries |
| Contracts verifier | PASS: 58 contracts and the ledger schema |
| New finding fixtures | PASS: 10 trigger checks covering 9 root causes; Docker has two fixtures |
| Report local links, unique IDs/statuses, `git diff --check` | PASS |

The full test run was derived from `git ls-files`: current
`packages/*/src/**/*.test.ts` files were mapped to compiled `.test.js` files,
plus tracked top-level `scripts/*.test.mjs`. This excludes ignored obsolete
compiled tests without deleting them. Native stages were rebuilt first. Node
was `v25.5.0` on this macOS host; the documented Node 24 production/CI baseline
was not separately tested. At that baseline, existing tests passed while the trigger fixtures reproduced
the defects. The final regression results above include their repairs.

The review covered Auth store/provider/login and GUI delegation, Edge bearer
verification/status polling/MCP/IPC, Broker planning and mutation results,
filesystem patch/traversal, Git/worktree lifecycle, terminal redaction/session
dispatch, container snapshot/Engine boundaries, archive retention, and deployment
and verification scripts. Automated tests cover additional modules. Source
inventory and targeted deep reading were used; no claim is made that all 568
tracked package source/native/script files received line-by-line inspection.

The fixture runner and non-sensitive fixture output were retained locally at
`/private/tmp/mac-operator-review-reproductions.mjs` and
`/private/tmp/mac-operator-review-reproductions.json`. Disposable fixture state
was removed in `finally`; these paths are optional session evidence, not durable
dependencies of this report. Their expected buggy outputs are historical evidence; permanent regression
tests now cover the corrected behavior. Full test/build logs
remain in `/private/tmp/mac-operator-review-*.log`.

Local listeners needed by the full test suite ran with automatic approval
outside the listener-restricted sandbox. The initial read-only listener probe
returned `EPERM`; this environment restriction is not a product finding.
Compiler module caches were redirected to writable temporary paths.

The 19 opt-in/platform/integration skips, live OAuth/GUI interactions, production
Docker execution, privileged installation, signing/notarization and service
cutover remain unverified here. No external dependency advisory query was made.
KB memory was recalled as context and checked against current source and Git;
no new security findings were sent to KB. Production deployment claims from
other historical documents were not independently revalidated.

## Documented risks and excluded hypotheses

- Auth's global login/request limiter can temporarily block unrelated owner
  requests after anonymous failed attempts. This is explicitly documented in
  [OAuth login design](docs/oauth-login-design.md), and the existing login-limit
  test asserts it. It is an accepted perimeter-dependent availability trade-off,
  not a newly counted implementation defect. Perimeter effectiveness was not
  tested; scope the protection carefully if its design is reconsidered.
- Git failures after a mutation may remain `unknown`; safe recovery requires
  independent readback. Unknown alone does not prove failure, and this report
  does not recommend weakening conservative reconciliation.
- Refresh-token compaction deliberately retains a bounded set of consumed
  hashes; older replay no longer has the same detection evidence. Treat this
  as a security/design follow-up rather than silently claiming unlimited replay
  detection. Compacted old tokens are still invalid; no refresh bypass was found.
- Opt-in task/signing/host permission gates and sandbox listener failures are
  unavailable verification evidence, not product bugs merely because a gate
  refuses execution.

## Historical follow-up findings BUG-15 through BUG-28

All rows below are **FIXED in the reviewed source**. These were previously
documented at `5c3f021` in the local history but missing from the report on main.
The current-source suite includes their regression files. The table records
source fixes and does not adopt unverified historical deployment claims.

| ID | Priority | Original defect | Status | Fix commit | Verified behavior / regression source |
| --- | --- | --- | --- | --- | --- |
| BUG-15 | P1 | Ledger rotation deletes Jobs referenced by retained Requests, preventing restart | FIXED | `ae1b1a1` | Referenced Jobs stay out of rotation; [ledger rotation tests](packages/broker/src/ledger-rotation.test.ts). |
| BUG-16 | P1 | Bodyless OAuth status responses throw outside the Promise boundary | FIXED | `43a763b` | Null bodies and invalid statuses settle safely; [loopback tests](packages/edge/src/oauth-status-loopback.test.ts). |
| BUG-17 | P1 | Network channels queue unbounded frames before checking the request budget | FIXED | `e2ca1d4` | Admission reserves request and retained-byte budgets; [proxy tests](packages/broker/src/network-proxy.test.ts). |
| BUG-18 | P1 | An Engine-level 404 falsely proves exact container cleanup | FIXED | `bfe08ce` | Only exact container inspection on the pinned Engine proves absence; [runner tests](packages/broker/src/container-task-runner.test.ts). |
| BUG-19 | P2 | Post-create inspection failure loses a confirmed container handle | FIXED | `bfe08ce` | Ownership is handed off before fallible inspection; [Engine tests](packages/broker/src/container-engine.test.ts). |
| BUG-20 | P2 | Container preparation ignores task cancellation and deadline | FIXED | `bfe08ce` | Preparation carries the task signal and remaining budget; [runner tests](packages/broker/src/container-task-runner.test.ts). |
| BUG-21 | P2 | Network channel closure leaves its active target connection running | FIXED | `e2ca1d4` | Channel abort cancels and drains the exchange; [proxy tests](packages/broker/src/network-proxy.test.ts). |
| BUG-22 | P2 | Codex dispatches dynamic tools after turn completion | FIXED | `7a2d7e0` | Terminal turns reject later tool calls before dispatch; [controller tests](packages/broker/src/codex-controller.test.ts). |
| BUG-23 | P2 | A NO_PUSH marker appearing during preflight is ignored at mutation | FIXED | `4e59359` | Marker is checked again immediately before spawn; [push tests](packages/broker/src/git-push.test.ts). |
| BUG-24 | P2 | JWT and downstream identity validators disagree | FIXED | `c8efd64` | Shared Broker identity validation rejects unsupported claims; [identity tests](packages/edge/src/identity.test.ts). |
| BUG-25 | P2 | Distinct colon-containing OAuth sessions collide in monitoring | FIXED | `aa2e94a` | A JSON tuple keeps session identities separate; [monitor tests](packages/edge/src/oauth-grant-status.test.ts). |
| BUG-26 | P2 | Retention misses its own interrupted quarantine files | FIXED | `938ce57` | Both quarantine name forms block false retries; [retention tests](packages/broker/src/archive-retention.test.ts). |
| BUG-27 | P2 | Successor audit anchors skip authentication of an existing anchor | FIXED | `e5302ef` | Existing MAC is verified before publication; [anchor tests](packages/broker/src/audit-anchor.test.ts). |
| BUG-28 | P2 | Completed-removal retries may delete branches in a replacement repository | FIXED | `09dd85b` | Retry rechecks live authority and recorded project identity; [worktree tests](packages/broker/src/managed-worktrees.test.ts). |

## Historical original review and repairs, 2026-10-11

The original BUG-01 through BUG-14 review used baseline
`79f02b5acf71a7fb742717a42d231134bea43d2e`; their repairs are recorded in
`5c3f0213dff64907c802b56d31babd230675ea37` and merged into the reviewed main.
The retained descriptions and verification below are historical evidence.
Statements about then-local changes, approvals, exclusions and deployment apply
to that earlier session, not to this review's current source or live service.

### Original findings index (BUG-01 through BUG-14)

| ID | Priority | Defect | Status | Original evidence |
| --- | --- | --- | --- | --- |
| BUG-01 | P1 | PTY output redaction can be bypassed through small reads | FIXED | Local reproduction; independent caller review |
| BUG-02 | P1 | An OAuth status outage permanently revokes healthy Broker sessions | FIXED | Local verifier reproduction; production wiring traced |
| BUG-03 | P1 | Auto-deploy exceptions after stopping the service do not restore it | FIXED | Exact-function fault injection |
| BUG-04 | P1 | Manual rollback can replace intact state with an incomplete backup | FIXED | Exact rollback reproduction in temporary directories |
| BUG-05 | P2 | PTY reads can return an empty page without advancing the cursor | FIXED | Local reproduction |
| BUG-06 | P2 | AuthStore accepts record counts that prevent the next startup | FIXED | Local schema-valid database reproduction |
| BUG-07 | P2 | Client eviction deletes clients used by pending OAuth transactions | FIXED | Local database reproduction; HTTP caller traced |
| BUG-08 | P2 | Text search silently omits matches beyond its per-file limit | FIXED | Local native-filesystem reproduction |
| BUG-09 | P2 | Storage max_depth stops unrelated sibling and root traversal | FIXED | Local native-filesystem reproduction |
| BUG-10 | P2 | Request ledger export drops the authenticated Edge key identity | FIXED | Encrypted archive reproduction; normalization traced |
| BUG-11 | P2 | Job ledger export rejects valid long Edge key identities | FIXED | Live-store/export reproduction |
| BUG-12 | P2 | Browser navigation verification aborts its retry loop on transient discovery failure | FIXED | Native control flow and Broker error mapping traced |
| BUG-13 | P2 | Process-boundary verification cannot pass on the current tracked scripts | FIXED | Verification command reproduction |
| BUG-14 | P2 | Manual release deployment reports success without checking the final restart | FIXED | Exact final-stage mock reproduction |

### Original remediation and regression coverage

The defect descriptions below preserve the original behavior and line locations
at the baseline source revision. This section describes the repaired behavior.
These repairs were local and uncommitted during the original session; they are now in the reviewed revision.

| Findings | Implemented behavior | Regression evidence |
| --- | --- | --- |
| BUG-01, BUG-05 | Sanitize output before the ring and define stable sanitized-byte cursors. Retain incomplete signatures across process chunks; suppress private-key bodies and oversized unfinished records. Reject tiny UTF-8 page budgets and invalid character cursors instead of returning stalled pages. | [Stream tests](packages/broker/src/terminal-output-redactor.test.ts), [session tests](packages/broker/src/owner-terminal-session.test.ts); one-byte pages, every split position, arbitrary cursors, split UTF-8, prompts, protected paths, encoded credentials, PEM/oversized states and ring overflow. |
| BUG-02 | Status transport/validation exceptions reject the current JWT without invoking durable revocation. Explicit inactive status and confirmed scope loss still propagate revocation. | [JWT tests](packages/edge/src/jwt-verifier.test.ts), [Auth tests](packages/auth/src/auth.test.ts); outage, 503, malformed response, same-token recovery, inactive and narrowed scopes. |
| BUG-03, BUG-04, BUG-14 | Exception-safe cutover recovers the prior release; only completed snapshots may restore state. Recovery requires a confirmed stop, stages restoration before moving live state and preserves the old location if publication fails. Final restart health accepts its expected counter of 1 and rejects further automatic restarts. | [Deployment recovery tests](scripts/deployment-recovery.test.mjs); actual shell recovery/health logic with disposable state and mocked PM2, including healthy success and copy/config/start/health/save/stop/settle/rename/log failures. |
| BUG-06 | New insertions enforce the same 8,000-total bound used by startup, alongside the existing 1,000-per-kind bound. Updates at capacity remain valid. | [Capacity test](packages/auth/src/store-capacity.test.ts); schema-valid full store, rejected additional insert, update, reopen and reuse after deletion. |
| BUG-07 | Client eviction protects grants and unexpired authorization transactions/codes. | [Eviction tests](packages/auth/src/store-eviction.test.ts), [Auth HTTP regression](packages/auth/src/auth.test.ts); pending consent completes after registration at client capacity, live code retention and expired-flow eviction. |
| BUG-08 | Detect an actual omitted 101st match and report truncation without stopping later files. Exactly 100 matches remain complete. | [Filesystem tests](packages/broker/src/filesystem-inspector.test.ts); multiple lines, multiple matches on one line and later-file visibility. |
| BUG-09 | Separate partial-depth reporting from global traversal termination. Depth limits preserve eligible siblings and other roots. | [Filesystem tests](packages/broker/src/filesystem-inspector.test.ts); depth 0/1/2, sibling files and multiple roots. |
| BUG-10, BUG-11 | Preserve populated, null and absent Request Edge key identities in encrypted archives. Validate Job Edge/key components with the authoritative validators and enforce their ownership binding. | [Archive tests](packages/broker/src/ledger-export.test.ts); decrypted snapshot/digest readback, legacy omission, 257-character identities, invalid components and mismatched owner rejection. |
| BUG-12 | Retry only transient AX enumeration/window correlation failures, within the existing 30-attempt limit and original window authority. Permission, identity and sensitive-target failures remain immediate. | [Native window tests](scripts/gui-window-resolution.test.mjs); transient recovery, bounded exhaustion, failed postcondition and immediate authority denials. |
| BUG-13 | Register reviewed script boundaries, add explicit shell/cwd/environment/time/output limits, and run the process-boundary gate in CI. | `npm run verify:process-boundaries`; zero unreviewed entries, plus native script and GUI probe regressions. |

Independent review of terminal and native navigation changes ran **5,656
synthetic adversarial cases** across 88 known-signature/path/encoded samples,
plus manager UTF-8/ring/finalization stress and eight native fixtures. It caught
and verified fixes for prematurely released AWS labels, path-context loss,
dashed separator/public-certificate blocking and oversized PEM classification.
Independent deployment review caught and verified corrections to PM2 restart
counter handling and confirmed-stop recovery. No unresolved confirmed finding
remains in these reviewed paths.

Compatibility and operational limits:

- Terminal cursors now count sanitized bytes. In-memory sessions do not survive
  a Broker restart, so there is no durable cursor migration. Incomplete output
  fragments may wait for a boundary; unfinished records over 64 KiB are omitted
  with a marker. Redaction still recognizes known signatures. Details:
  [owner-terminal contract](docs/owner-terminal.md).
- Existing databases already exceeding 8,000 Auth records still fail closed.
  This patch prevents new over-capacity state; it does not delete user records
  or perform a production data repair.
- Archive format/schema are unchanged. Missing legacy Request key fields remain
  missing; no synthetic identity is added.
- Keep `deployment-state.zsh` and `deployment-service.zsh` beside the manual
  deployment scripts. No live service was stopped or restarted by this task.
  Operational behavior is recorded in [auto-deploy](docs/auto-deploy.md).

### BUG-01: PTY output redaction can be bypassed through small reads

**Location:** [owner-terminal-session.ts](packages/broker/src/owner-terminal-session.ts),
lines 325-336; public read bounds in
[owner-terminal-session-request.ts](packages/broker/src/owner-terminal-session-request.ts);
output forwarding in
[owner-terminal-session-dispatch.ts](packages/broker/src/owner-terminal-session-dispatch.ts).

**Trigger and actual behavior:** The session stores raw output, slices it using
the caller's cursor and `max_bytes`, and then redacts only that slice. A client
can read an otherwise recognizable credential in one-byte pages. No page
contains a complete secret signature, so concatenating the returned pages
recovers the original credential. The public parser permits `max_bytes: 1`.
The dispatch and MCP result paths do not apply redaction across pages.

**Verified reproduction:** An injected supervisor emitted a synthetic value
consisting of `ghp_` followed by 32 `A` characters. A full read redacted it;
successive one-byte reads reconstructed it exactly. No real credential was used.

**Impact:** Authorized owner-terminal clients can receive secret output despite
the explicit redaction guarantee. This finding concerns output confidentiality;
owner-account command execution is already an explicitly authorized feature.

**Recommended fix:** Redact the stream before exposing paginated bytes. Preserve
enough state to recognize signatures split across process chunks and reads, and
define cursors over a stable sanitized stream. Add cases for one-byte pages,
arbitrary cursors, and signatures split across successive output chunks.

### BUG-02: An OAuth status outage permanently revokes healthy sessions

**Location:** [oauth-grant-status.ts](packages/edge/src/oauth-grant-status.ts),
lines 52-58; [jwt-verifier.ts](packages/edge/src/jwt-verifier.ts), lines 94-96;
[service-startup.ts](packages/edge/src/service-startup.ts), lines 423-425 and
439-442; [broker.ts](packages/broker/src/broker.ts), lines 1914-1915.

**Trigger and actual behavior:** A timeout, failed status fetch, non-success
response, or malformed response becomes `true` from the revocation check.
The JWT verifier treats that result as confirmed revocation and invokes
`onRevoked`. Production wiring propagates this to durable Broker session
revocation. Restoring the issuer status endpoint does not undo that revocation.
The background monitor already distinguishes transport failures from explicit
revocation; the per-request path does not.

**Verified reproduction:** A valid ES256 JWT was checked with a status fetch that
failed once and then returned `active: true` with the original scopes. The first
check invoked the revocation callback. The later JWT verification succeeded,
but the recorded session-revocation state remained set. The Broker persistence
path was traced separately in source.

**Impact:** A temporary issuer outage can permanently disable otherwise healthy
connections and cancel their active work. Reconnecting with a new grant/session
may be necessary after the issuer has recovered.

**Recommended fix:** Reject the current request when status cannot be established,
without emitting a durable revocation event. Only explicit inactive status or
confirmed scope removal should invoke `onRevoked`. Test outage, recovery, and
genuine revocation through the same propagation path.

### BUG-03: Auto-deploy exceptions leave the service stopped

**Location:** [auto-deploy/run.mjs](scripts/auto-deploy/run.mjs), lines 164-179,
199, and 295-298.

**Trigger and actual behavior:** After `pm2 stop`, directory creation, state
copying, configuration parsing, and configuration publication execute without
a recovery guard. An exception skips both `startService` and the rollback
branch. The outer catch only sends a notification and sets the exit code.
Subsequent polls skip an offline service, so they cannot repair the outage.

**Verified reproduction:** The exact `cutover` function was evaluated with
side-effect-free dependencies. Injecting `ENOSPC` from `copyTree` recorded only
the service `stop` operation; no restart or restore operation ran.

**Impact:** A backup or configuration I/O failure during an otherwise authorized
release can leave the production service unavailable until manual recovery.

**Recommended fix:** Track the stopped, backup-complete, and config-published
stages explicitly. Guard every step after a confirmed stop with recovery that
restarts the previous release using intact state when backup preparation fails.
Also check the stop result before copying state. Test failures at each stage.

### BUG-04: Manual rollback trusts an incomplete state backup

**Location:** [deploy-release.zsh](scripts/deploy-release.zsh), lines 52-53 and
85. The same pattern exists in
[deploy-git-push-release.zsh](scripts/deploy-git-push-release.zsh), lines 56-57;
[deploy-codex-controller.zsh](scripts/deploy-codex-controller.zsh), lines 61-62;
[deploy-development-project-add.zsh](scripts/deploy-development-project-add.zsh),
lines 61-62; [deploy-v2-access-widening.zsh](scripts/deploy-v2-access-widening.zsh),
lines 73-74; and
[enable-terminal-connection.zsh](scripts/enable-terminal-connection.zsh), line 44.

**Trigger and actual behavior:** `cp -Rp` can create the backup directory and then
fail partway through. The error trap treats directory existence as proof that
the backup completed. It moves the intact active state aside and copies the
partial backup into its place. The previous release then starts against missing
or incomplete protected state.

**Verified reproduction:** The exact release rollback function ran in disposable
directories with a mocked service manager. The active state contained an
original marker and the backup contained only a partial-copy marker. Rollback
removed the original marker from active state and published the partial marker;
the original survived only in the `.failed-*` directory. No live service ran.

**Impact:** A failed backup can turn recoverable deployment preparation into
an outage and replacement of active authorization/database state with incomplete
data. The original directory is retained, but automatic recovery uses the wrong
copy.

**Recommended fix:** Copy into a staging backup, verify completion, and publish
it atomically before enabling state restore. If preparation fails before any
state mutation, restart against the original state. Share the corrected backup
contract across the affected deployment scripts.

### BUG-05: A small PTY read can stall on UTF-8 output

**Location:** [owner-terminal-session.ts](packages/broker/src/owner-terminal-session.ts),
lines 328-336.

**Trigger and actual behavior:** If the next character needs more bytes than
`max_bytes`, the UTF-8 boundary adjustment reduces the selected length to zero.
The response contains empty data, `truncated: true`, and the same `next_cursor`.
A client following that cursor repeats the empty page indefinitely.

**Verified reproduction:** Reading a three-byte CJK character with a one-byte
limit returned zero data and an unchanged cursor. Both limits are accepted by
the public request parser.

**Impact:** Valid reads can fail to make progress; polling clients can loop or
time out even though output is available.

**Recommended fix:** Guarantee progress or return a clear error requiring a
larger byte budget. Define and test how cursors interact with complete UTF-8
characters, including two-, three-, and four-byte code points.

### BUG-06: AuthStore can write a database it cannot reopen

**Location:** [store.ts](packages/auth/src/store.ts), lines 61-62 and 107-114;
record kinds in [contracts.ts](packages/auth/src/contracts.ts), lines 90-103.

**Trigger and actual behavior:** Writes enforce a 1,000-record limit separately
for each kind. Startup rejects more than 8,000 total records. There are nine
non-account record kinds, so legal writes can exceed the startup limit without
any individual kind reaching an invalid count.

**Verified reproduction:** `AuthStore.put` accepted 9,000 schema-valid records,
1,000 in each non-account kind. Closing and reopening the same database threw
`Auth state unavailable`. Expiring record types used future expirations.

**Impact:** Successful runtime state growth can prevent Auth startup after a
routine restart. This is a capacity-contract mismatch, not database corruption.

**Recommended fix:** Use one consistent capacity contract for writes and
startup. Reject an insertion before crossing the supported global limit, or
expand the validated startup bound to cover the supported per-kind capacities.
Test reopening at and around the chosen boundary.

### BUG-07: Client eviction breaks pending OAuth authorization

**Location:** [store.ts](packages/auth/src/store.ts), lines 147-152;
[app.ts](packages/auth/src/app.ts), lines 116-120 and 133-140.

**Trigger and actual behavior:** When anonymous registration fills the client
table, eviction protects only clients referenced by `grant` records. A client
used by an unexpired authorization transaction has no grant yet and can be
deleted while its login/consent session remains active. The browser handler
then rejects that session with `Invalid authorization client`.

**Verified reproduction:** A database with 1,000 clients included an oldest
client referenced by an unexpired transaction and authenticated session.
`evictUnusedClients(100)` deleted that client while retaining both references.

**Impact:** New registrations can invalidate another in-progress login or consent
flow at capacity. The user must begin authorization again.

**Recommended fix:** Exclude clients referenced by live authorization
transactions and other required live records, as well as grants. Add an eviction
test that completes an already-started consent flow after a new registration.

### BUG-08: Text search hides its per-file truncation

**Location:** [filesystem-inspector.ts](packages/broker/src/filesystem-inspector.ts),
lines 675-697.

**Trigger and actual behavior:** Searching stops after 100 matches in one file.
Only global traversal limits and the byte budget influence the returned
`truncated` flag. If the global `max_results` is larger, the per-file cutoff is
not reported.

**Verified reproduction:** A regular file with 150 matching lines, searched with
`maxResults = 1000`, returned 100 matches and `truncated: false`.

**Impact:** Consumers can mistake an incomplete search for a complete one,
missing relevant references during diagnosis or code review.

**Recommended fix:** Track per-file omissions and propagate them into the
result's truncation state. Test per-file and global limits independently.

### BUG-09: Storage depth truncation stops unrelated traversal

**Location:** [filesystem-inspector.ts](packages/broker/src/filesystem-inspector.ts),
lines 933-936 and 984-997.

**Trigger and actual behavior:** Encountering a directory at `max_depth` sets
the global `truncated` flag. Both traversal loops use that flag as a stop
condition, abandoning queued sibling directories and additional roots that
are still within the requested depth.

**Verified reproduction:** With sibling trees `a/nested` and `z/large.bin`, a
depth-one scan stopped after encountering the nested directory under `a` and
did not scan the queued `z` directory. The omitted file was within the allowed
depth. Results report truncation, but do not cover all eligible siblings.

**Impact:** Storage rankings depend on traversal order and can omit large
consumers unrelated to the branch that reached the depth limit.

**Recommended fix:** Separate the partial-result indicator from the stop flag
for global time/entry budgets. Skip descent at the depth boundary while
continuing eligible siblings and roots. Test this with multiple roots too.

### BUG-10: Request ledger export drops Edge key provenance

**Location:** [ledger-export.ts](packages/broker/src/ledger-export.ts), lines
198-220; its validator accepts `edgeKeyId` at lines 310-317.

**Trigger and actual behavior:** A live Request can contain its authenticated
`edgeKeyId`. Export validates that field but constructs a replacement record
without it. The encrypted archive and its digest describe the reduced record,
so archive integrity checks succeed despite the omitted provenance.

**Verified reproduction:** A terminal Request recorded with
`edgeKeyId = edge-1:key-1` was exported. The decrypted Request omitted the field,
and its snapshot digest differed from the canonical original live snapshot.
This does not mean the archive's own encrypted readback failed.

**Impact:** Export loses which authentication key authorized a historical
Request. Rotation can then remove the live record, leaving only incomplete
key-level forensic evidence.

**Recommended fix:** Preserve the optional field through normalization and
archive validation. Test an encrypted round trip against the complete live
record, including null, absent, and populated key identities.

### BUG-11: Job export rejects valid composite Edge key identities

**Location:** [ledger-export.ts](packages/broker/src/ledger-export.ts), lines
344-346; the authoritative live validator is `validEdgeKeyIdentity` in
[persistence.ts](packages/broker/src/persistence.ts).

**Trigger and actual behavior:** The live store accepts a composite identity
`edgeId:keyId`, with each component up to 128 characters. The export validator
limits the whole composite to 128 characters. Consequently, some valid
terminal Jobs cannot be exported.

**Verified reproduction:** The live store accepted and completed a Job with a
201-character composite identity. Ledger export rejected it with
`AUDIT_UNAVAILABLE` / `Ledger export Job record is malformed`.

**Impact:** Valid key naming can break history export and the rotation path
that depends on verified export, allowing retained history to accumulate.

**Recommended fix:** Reuse the authoritative component/prefix validation for
archives. Test component lengths at their supported limits and preserve rejection
of malformed or mismatched Edge/key identities.

### BUG-12: Browser navigation abandons stabilization on the first resolver error

**Location:** [gui_vision.m](packages/broker/native/gui_vision.m), lines 507-525;
error presentation in [ui-inspector.ts](packages/broker/src/ui-inspector.ts).

**Trigger and actual behavior:** After navigation has already been dispatched,
the native code enters a 30-attempt verification loop. If `resolveGuiWindow`
fails during the first transient AX enumeration or AX/CG correlation gap, the
function returns immediately instead of waiting for later attempts. The
TypeScript layer explains the resulting unverified navigation, but does not
restore the missing stabilization behavior.

**Evidence:** The immediate return at line 511 precedes the bounded wait at
line 523. Input dispatch occurs before this branch. Current failure mappings
confirm that transient enumeration/correlation failures surface as
`VERIFICATION_FAILED`. This path was established from source; no live browser
or Accessibility permission was changed during this review.

**Impact:** Successfully dispatched browser navigation can fail its verification
prematurely, making ordinary loading transitions unreliable.

**Recommended fix:** Retry only explicitly classified transient discovery
failures within the existing deadline and original window identity. Continue
to reject security, stale identity, and authorization failures immediately.
Test a transient resolver failure followed by successful readback.

### BUG-13: The process-boundary guard has stale script registration

**Location:** [check-process-boundaries.mjs](scripts/check-process-boundaries.mjs),
lines 13-32 and 90-99.

**Verified reproduction:** `npm run verify:process-boundaries` exits 1 and reports
these current tracked child-process entry points as unreviewed:

- `scripts/auto-deploy/preflight.mjs`
- `scripts/auto-deploy/run.mjs`
- `scripts/gui-desktop-app.test.mjs`
- `scripts/gui-focus-regression.test.mjs`
- `scripts/gui-window-resolution.test.mjs`
- `scripts/probe-gui-ax-metadata.mjs`
- `scripts/probe-gui-observation-reliability.mjs`

**Actual behavior and impact:** The allowlist has not followed the added entry
points, so this dedicated verification command is unusable on current source.
A read-only in-memory continuation past registration also exposed the missing
explicit `shell: false` marker in `auto-deploy/preflight.mjs`. Node's spawn
default is already false; that marker finding is a guard-contract mismatch,
not evidence of command injection. The current GitHub workflow does not run
this dedicated guard, so its failure is not a claim that CI itself was observed
failing.

**Recommended fix:** Review each entry point's arguments, working directory,
environment, output/time limits, and termination behavior before registering
it. Satisfy the existing guard contract without weakening it, and include this
guard in the appropriate verification workflow.

### BUG-14: The final deployment restart is not checked for health

**Location:** [deploy-release.zsh](scripts/deploy-release.zsh), lines 100-106.
The same final-restart/config-only sequence appears in
[deploy-codex-controller.zsh](scripts/deploy-codex-controller.zsh), lines 119-124;
[deploy-git-push-release.zsh](scripts/deploy-git-push-release.zsh), lines 107-112;
[deploy-development-project-add.zsh](scripts/deploy-development-project-add.zsh),
lines 113-118; and
[deploy-v2-access-widening.zsh](scripts/deploy-v2-access-widening.zsh), lines 128-133.

**Trigger and actual behavior:** The first release start receives a health check.
The required second restart only waits five seconds, verifies configuration
invariants, saves PM2 state, disables the error trap, and prints `OK`. PM2
accepting the restart command does not establish that the restarted application
stayed running or that its endpoint became available.

**Verified reproduction:** The exact final stage of `deploy-release.zsh` ran
with a mocked PM2 command that accepted restart but set service state to
`crashed`. Configuration checks passed. The stage exited zero and printed `OK`
while the simulated service remained crashed. No live service was restarted.

**Impact:** The final restart can break service availability without triggering
rollback, while the operator receives a successful deployment result.

**Recommended fix:** Check fresh PM2 state and the expected endpoint after the
second restart, before saving state or clearing the rollback trap. Test a first
healthy start followed by a failing second start.

### Original review verification and limitations

The review traced critical Auth/OAuth and Edge/MCP paths, Broker request and
ledger behavior, filesystem traversal, process/helper boundaries, V2 runtime,
container/controller/worktree integration, PTY and GUI paths, and deployment/
verification scripts. This was broad source review with focused deep checks;
it was not line-by-line proof of every file or real execution of every adapter.

| Check | Result |
| --- | --- |
| Build, including the native stages invoked by `npm test` | PASS |
| `npm run typecheck` | PASS |
| `npm run lint` | PASS after documentation changes |
| `npm run verify:docs` | PASS after documentation changes: 48 README links and 8 required runbooks |
| `npm run verify:matrix` | PASS |
| `node packages/contracts/dist/verify-contracts.js` | PASS: 58 tool contracts and ledger schema |
| Test run derived from 237 current tracked test files | PASS: 2,059 passed, 0 failed, 19 skipped; 2,078 total |
| `npm run verify:process-boundaries` | FAIL: BUG-13 |
| Targeted PTY, AuthStore, deployment, filesystem, and ledger checks | Confirmed findings described above |
| External dependency advisory query | NOT RUN: automatic approval review rejected the request |

The first sandboxed test attempt was unsuitable for IPC verification: a direct
loopback listener probe returned `EPERM`, and some native fixture compilation
was restricted. Those failures were not classified as product bugs. Tests were
then run outside that sandbox with approval.

The ordinary unrestricted `npm test` glob reported 2,060 passes, 3 failures,
and 19 skips. All three failures came from obsolete ignored build files
`packages/broker/dist/native-peer-ipc-server.test.js` and
`packages/broker/dist/owner-terminal-session-contract.test.js`, which have no
current source counterpart. No build artifacts were deleted. Running only
compiled tests corresponding to current tracked source, plus tracked top-level
script tests, produced the clean result above. Obsolete-artifact failures are
not included in the defect count.

The 19 skipped tests remain outside this verification claim. No production
Docker task, real browser interaction, privileged installation, signing/
notarization workflow, or live service cutover was performed. Native navigation and deployment failures now have targeted synthetic/native
regressions; real browser navigation and live service cutover remain outside
this local verification claim.

The dependency query was rejected because `npm audit` would send dependency
names and versions to npm registry. No dependency advisory result is claimed;
that optional check requires explicit authorization for the external payload.

Relevant prior KB memory was read as context and checked against current source.
An attempted end-of-review memory preview was rejected by automatic approval
review because it would send the repository/security-finding summary to KB-MCP.
No new review memory was saved; the local report is the retained deliverable.

### Remediation verification

All 14 original triggers have regression coverage, and the relevant checks pass.
The earlier review results above are historical. Final local results:

| Check | Result |
| --- | --- |
| Current-source full test run: 240 compiled/script test files, including all new tests | PASS: **2,140 passed, 0 failed, 19 skipped; 2,159 total** |
| TypeScript and all native stages in `npm run build` | PASS |
| Native peer fault build | PASS |
| `npm run typecheck` | PASS |
| `npm run lint`, plus direct style checks for new untracked artifacts | PASS |
| `npm run verify:docs` and report-link checks | PASS: 48 README links, 8 runbooks; all report links resolve |
| `npm run verify:matrix` | PASS |
| `npm run verify:process-boundaries` | PASS: zero unreviewed production/script entries; enabled in CI |
| Contracts verifier | PASS: 58 tool contracts and versioned ledger schema |
| Native canonical JSON probe | PASS: 5/5 vectors |
| Independent terminal/native and deployment review | PASS; confirmed review findings corrected and revalidated |
| `git diff --check`, report status/ID/count consistency | PASS |

The final full run includes **81 more passing cases** than the review baseline.
It enumerates tests from current `packages/*/src/**/*.test.ts` sources and
`scripts/*.test.mjs`, including the three new test files. It excludes the two
obsolete ignored compiled test files described above; their artifacts were not
deleted or changed. A direct `npm test` glob can still include those stale local
artifacts. A clean checkout has no such orphan test files.

Tests requiring temporary local listeners ran with approval outside the
listener-restricted sandbox. The canonical probe initially could not write its
default compiler module cache; rerunning with `CLANG_MODULE_CACHE_PATH` and
`SWIFT_MODULE_CACHE_PATH` pointing to a writable temporary directory passed.
No verification check was weakened.

The 19 opt-in/platform/integration skips, real browser navigation, production
service cutover, Docker acceptance, privileged installation, and signing/release
acceptance remain outside this task. No production state changed, and no commit
or push was created. The Markdown report and operational docs are the durable
local deliverables.

External npm advisory queries and outbound KB reuse/writeback remain excluded.
Automatic approval review rejected the disclosure of dependency metadata and
internal security/deployment context to their respective external destinations.
No workaround or new KB write was performed; current local code, tests and the
retained prior context supplied the implementation evidence.
