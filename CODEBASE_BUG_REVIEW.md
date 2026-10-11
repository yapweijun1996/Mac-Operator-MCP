# Codebase Bug Review

Review date: 2026-10-11 (Asia/Kuala_Lumpur)
Source revision: `79f02b5acf71a7fb742717a42d231134bea43d2e` (`main`)
Remediation date: 2026-10-11
Status: **DONE — all 14 findings FIXED locally and regression-verified.**

This review identified **14 supported defects: 4 P1 and 10 P2**. The user selected
option B to repair all 14 findings. Implementation and regression tests are now
in the local working tree. No production configuration, service deployment,
commit, or push was changed.
The report contains all confirmed findings from this review, not a guarantee
that the repository has no other bugs.

P1 means a security boundary failure, serious loss of availability, or unsafe
state recovery. P2 means a functional, data integrity, or verification defect
with a narrower trigger. Findings are grouped by root cause rather than counting
each affected script as a separate bug.

## Findings index

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

## Remediation and regression coverage

The defect descriptions below preserve the original behavior and line locations
at the baseline source revision. This section describes the repaired behavior.
All changes remain local and uncommitted.

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

## BUG-01: PTY output redaction can be bypassed through small reads

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

## BUG-02: An OAuth status outage permanently revokes healthy sessions

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

## BUG-03: Auto-deploy exceptions leave the service stopped

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

## BUG-04: Manual rollback trusts an incomplete state backup

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

## BUG-05: A small PTY read can stall on UTF-8 output

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

## BUG-06: AuthStore can write a database it cannot reopen

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

## BUG-07: Client eviction breaks pending OAuth authorization

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

## BUG-08: Text search hides its per-file truncation

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

## BUG-09: Storage depth truncation stops unrelated traversal

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

## BUG-10: Request ledger export drops Edge key provenance

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

## BUG-11: Job export rejects valid composite Edge key identities

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

## BUG-12: Browser navigation abandons stabilization on the first resolver error

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

## BUG-13: The process-boundary guard has stale script registration

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

## BUG-14: The final deployment restart is not checked for health

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

## Original review verification and limitations

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

## Remediation verification

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
