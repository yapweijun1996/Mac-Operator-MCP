# Codebase Bug Review

## Current review — 2026-10-15

Status: **DONE — BUG-38 through BUG-53 FIXED; all 53 recorded findings resolved locally.**

Reviewed revision: `a7d599934d3def5105b24871cf5229d75fecea24` (`main`).
The review started with a clean working tree. The subsequently authorized
BUG-38 through BUG-53 repairs change source, tests, contract documentation and
Markdown. The cumulative repairs are committed on `codex/fix-review-bugs-38-53`
and integrated into local `main`. No remote push, deployment or live-service
change is included. Earlier batch evidence retains its point-in-time status.

The report now contains **53 findings: zero OPEN and 53 FIXED locally**.
The review identified 16 individually supported P2 defects, BUG-38 through
BUG-53; all sixteen are now repaired. No new P0/P1 was confirmed.
The 37 historical fixes retain their original evidence below; they
were not all independently reproduced again in this pass. Existing operational
PREDEPLOY findings remain in their deployment evidence and were not rechecked
against the live service.

The current source-backed suite passes: **2,394 total; 2,375 passed, zero failed,
19 skipped; 248 files**, including 15 new cases in the final batch, with four concurrent test files
and unchanged timeouts/assertions. Build/native fault build, typecheck, style,
docs, matrix, process-boundary and 58-contract checks pass.
Current verification is recorded in the
[BUG-51–53 repair evidence](evidence/2026-10-15-bugs51-53-remediation.md).
The preceding source-backed revisions remain documented in
[BUG-49–50 evidence](evidence/2026-10-15-bugs49-50-remediation.md),
[BUG-47–48 evidence](evidence/2026-10-15-bugs47-48-remediation.md),
[BUG-45–46 evidence](evidence/2026-10-15-bugs45-46-remediation.md) and
[BUG-42–44 evidence](evidence/2026-10-15-bugs42-44-remediation.md).
The earlier ordinary `npm test` run discovered two obsolete ignored compiled
test files and three failures; those artifacts are preserved. The source-backed
run includes every current source test, including newly added files, and excludes
only artifacts without source. Original baseline details remain in
[review evidence](evidence/2026-10-15-codebase-review.md); prior fixes remain in
[BUG-38–41 evidence](evidence/2026-10-15-bugs38-41-remediation.md).
All sixteen newly reviewed defects now have targeted regression coverage.

This is a broad review with focused source tracing and disposable reproductions,
not proof that every possible bug has been found. The table contains every
supported new finding from this pass. Coverage, fixtures, exact verification
results, and unexecuted paths are recorded in the evidence document.

### Current finding status

| ID | Priority | Status | Defect | Evidence |
| --- | --- | --- | --- | --- |
| BUG-38 | P2 | FIXED locally | A status-channel close error skips root-helper command-channel cleanup | Runtime failure fixtures; 12 new lifecycle regression cases |
| BUG-39 | P2 | FIXED locally | Edge status read hangs after an incomplete response reaches EOF | Actual local-socket EOF/reset/drip regressions |
| BUG-40 | P2 | FIXED locally | A crash before PID publication leaves an unrecoverable auto-deploy lock | Actual filesystem/SQLite checks and child SIGKILL recovery |
| BUG-41 | P2 | FIXED locally | Completed worktree removal retries delete a newly recreated same-name branch | Actual Git replay, restart and archive regressions |
| BUG-42 | P2 | FIXED locally | Container snapshots and staging discard executable permissions | Actual native snapshot and isolated staging-script fixture |
| BUG-43 | P2 | FIXED locally | Terminal stop returns an error when unread output begins with a multibyte character | Actual terminal manager and dispatch |
| BUG-44 | P2 | FIXED locally | Host and guest file pagination reject valid UTF-8 at a byte boundary | Actual host worker and isolated guest-script fixture |
| BUG-45 | P2 | FIXED locally | Revoked permanent GUI grants exhaust the lifetime per-kind capacity | Actual Auth/Broker stores and GUI approvals |
| BUG-46 | P2 | FIXED locally | Schema-valid long owner IDs silently disable default browser access | Actual configuration parser and GUI authorization |
| BUG-47 | P2 | FIXED locally | Installed-app capacity hides running apps without reporting truncation | Actual inventory script and parser with simulated ObjC |
| BUG-48 | P2 | FIXED locally | Standard Utilities applications are absent from inventory and cannot be opened | Actual inventory/controller with simulated app metadata |
| BUG-49 | P2 | FIXED locally | Python dependency parsing silently drops inline array entries | Actual package inspector with temporary manifests |
| BUG-50 | P2 | FIXED locally | Named Xcode project/workspace bundles are not recognized as Swift projects | Actual native filesystem discovery |
| BUG-51 | P2 | FIXED locally | Paginated directory discovery emits duplicate project/type records | Actual native filesystem discovery over 502 files |
| BUG-52 | P2 | FIXED locally | Project discovery hides its depth-limit omissions | Actual native traversal with a project at depth 17 |
| BUG-53 | P2 | FIXED locally | Text-search policy explanation allows a root that denies content reads | Actual signed Broker explanation and execution requests |

### BUG-38 through BUG-41 implementation and acceptance

| Finding | Implemented behavior | Regression coverage |
| --- | --- | --- |
| BUG-38 | All owned server cleanup is attempted; errors are retained/aggregated and failed cleanup stays retryable with visible failed state. | Running, stopped, failed-startup and unavailable paths; status, command and both-close failures; successful cleanup retry. |
| BUG-39 | EOF/close rejects an incomplete frame; a single absolute deadline also bounds peers sending partial data. Late connection readback cannot write after settlement. | Empty EOF, partial EOF, reset and drip; existing authenticated success/replay/denial tests remain green. |
| BUG-40 | A separate owner-only SQLite transaction serializes the entire runner and recovery. Aged empty directories recover safely; complete PID publication is atomic and release checks ownership. | Fresh/aged unpublished locks, live/dead legacy owners, contention, stale release, changed identity, malformed/unexpected evidence, real child SIGKILL, crash-left PID hard link and redirected guard. |
| BUG-41 | A completed removal retry only reads branch existence; retained or recreated branches require separate owner cleanup. Existing authority and project/replacement-worktree checks remain in force. | Actual branch recreation, normal/restarted/archived replay, retained unmerged branches, revoked authority and replaced projects. |

The lock helper is [lock.mjs](scripts/auto-deploy/lock.mjs). It uses Node's
existing SQLite runtime and never opens a Broker ledger. Keep its persistent
`lock.sqlite` identity in place; the kernel releases the transaction after a
crash. The PID directory remains for old-runner compatibility, with a 30-second
unpublished-lock grace period. Malformed/unknown evidence fails closed.
See [lock operations](docs/auto-deploy.md#lock-recovery) for release/rollback
constraints. Worktree replay uses the existing record format; no migration is
needed. `branch_deleted` on replay describes current absence, not a newly
executed delete. A branch left by an earlier failed cleanup is now deliberately
left for the owner rather than being deleted by a historical key.

The original trigger descriptions and line references below describe the
pre-repair review revision. This table and the repair evidence own current
behavior. BUG-51 through BUG-53 are repaired in the acceptance section below.

### BUG-38: A status close error leaves the root-helper command server open

**Location:** [root-helper-snapshot-runtime.ts](packages/broker/src/root-helper-snapshot-runtime.ts),
lines 154-158 and 169-178; command cleanup is owned by
[root-helper-snapshot-transport.ts](packages/broker/src/root-helper-snapshot-transport.ts),
`RootHelperSnapshotServer.close()`.

**Trigger and evidence:** Start the actual runtime with the existing injectable
server interfaces. Make status-server close throw `IPC socket ownership changed
before close`. Runtime close rejects and reports `state: failed`, but the
command-server close is never called and the fixture remains listening. Startup
failure followed by the same cleanup error has the same result. An independent
repeat confirmed the shutdown case. Socket-identity and filesystem failures in
the real IPC close path can produce this exception.

**Impact:** Failure of the diagnostic endpoint skips command-listener shutdown,
active-request cleanup, authority-poller shutdown, and key disposal. This is a
conditional lifecycle defect in the optional root-helper runtime, not evidence
that the deployed service enables it or that authentication is bypassed.

**Correction and verification:** Attempt every owned cleanup independently and
aggregate errors. Test normal shutdown and failed startup with each close
operation failing; command cleanup must always run, and unavailable cleanup
must remain visible rather than being reported as a successful stop.

### BUG-39: A truncated Edge status response can wait forever

**Location:** [edge-status-ipc.ts](packages/edge/src/edge-status-ipc.ts),
`exchangeStatusSocket()`, lines 417-450, especially 429-438.

**Trigger and evidence:** A protected temporary Unix-socket peer sends partial
JSON without its terminating newline and closes normally. The actual status
client is configured with a 100 ms timeout; its Promise is still unsettled
after 502 ms. No external endpoint is involved.

**Cause and impact:** The client handles data, errors, connection and inactivity
timeout, but not end/close. Once the connection closes, its socket timeout no
longer bounds the unfinished Promise. Installation or deployment status
readback can hang instead of returning a bounded failure.

**Correction and verification:** Reject EOF/close before a complete frame and
enforce an absolute deadline. Clean up all handlers and timers on settlement.
Test empty EOF, partial EOF, a stalled/dripping response, and normal completion.

### BUG-40: An incompletely published auto-deploy lock never recovers

**Location:** [run.mjs](scripts/auto-deploy/run.mjs), `acquireLock()`, lines 58-68.

**Trigger and evidence:** Stop a process after lock-directory creation but
before its PID file is written. Running the actual extracted lock function
twice against that disposable empty directory returns `ENOENT` both times.

**Cause and impact:** The existing-directory path unconditionally reads the
PID file. Lock acquisition occurs outside the run's cleanup `finally`, so every
later automatic run fails and leaves the same lock behind. No live deployment
was interrupted in this test.

**Correction and verification:** Define recovery for missing/invalid owner
publication with a bounded grace period and directory-identity checks. Preserve
live-owner exclusion. Test interruption before/after PID publication, concurrent
acquisition, a dead owner, and a healthy owner.

### BUG-41: Removal replay deletes a newly recreated branch

**Location:** [managed-worktrees.ts](packages/broker/src/managed-worktrees.ts),
completed-removal retry at lines 262-268 and branch cleanup at 346-358.

**Trigger and evidence:** Remove a managed worktree and successfully delete its
`codex/retry` branch. Recreate that branch in the same original repository at a
merged commit, then repeat the completed removal's key. Actual Git readback
shows the recreated branch exists before retry and is absent afterward.

**Cause and impact:** Replay reissues `git branch -d` using only the old name.
Project-identity checks correctly preserve BUG-28's replacement-repository
guard, but cannot distinguish the new ref inside the original repository.
This deletes a later branch reference; the reproduction does not establish
deletion of unmerged commits or a force-delete bypass.

**Correction and verification:** Persist successful branch cleanup and replay
that outcome without deleting again. Any pending cleanup must bind the original
branch identity. Test same-name recreation after successful removal, pending
cleanup, restart/archive replay, and existing project-identity guards.

### BUG-42–44 repair outcome — 2026-10-15

BUG-42 now carries a validated executable marker from identity-checked host
metadata through the tar checksum and staging chunks. Files normalize to
`0700`/`0600`, or `0555`/`0444` in read-only workspaces. Execution is granted
only after staged size/hash verification. Guest edits retain existing owner
execution. Host imports retain only the existing host inode's owner execution
through the atomic native writer; guest mode cannot grant execution to a new
or previously nonexecutable host file. Special bits are stripped. The native
preservation capability must be version 1; older addons fail closed.

BUG-43 now obtains stop state from `describe()` after authoritative completion,
without decoding or consuming output. Existing read cursors, redaction, bounded
reads and final-state persistence remain in force.

BUG-44 shares a strict UTF-8 page decoder between host and guest. A valid partial
last character is deferred to the next page. Invalid encoding, incomplete EOF,
unaligned offsets and pages too small for one character still fail explicitly.
Host `bytes_returned` and `next_offset` are additive optional result fields;
`sha256` covers the actual returned original bytes, including any BOM. Guest
`nextOffset` advances by the same actual byte count. Host base64/metadata behavior
is preserved. See the [repair evidence](evidence/2026-10-15-bugs42-44-remediation.md)
for tests, compatibility and unexecuted physical acceptance.

### BUG-42: Container transfer removes executable permissions

**Location:** [container-snapshot.ts](packages/broker/src/container-snapshot.ts),
line 118; [container-engine.ts](packages/broker/src/container-engine.ts),
lines 408-409, 933 and 941.

**Trigger and evidence:** Snapshot an ordinary tracked `0755 run.sh`. The actual
native snapshot archive records `0600`, and its file model has no mode field.
Execute the actual staging script in an isolated filesystem fixture: begin,
chunk and seal all return `STAGED`, but the staged file is `0600` and executing
it fails with `EACCES`. Read-only sealing instead assigns `0444`.

**Impact:** An approved manifest command such as an npm test that invokes
`./run.sh` fails after transfer despite the source script being executable.
Approved scripts are supported by the task-profile contract and
[V2 runbook](docs/MAC_OPERATOR_V2_RUNBOOK.md); this does not imply every
currently registered validation uses such a script.

**Correction and verification:** Carry a restricted executable bit through the
snapshot, digest/transport and staging contracts while stripping special
permissions. Preserve read-only enforcement. Test an approved script invocation
in writable and read-only profiles and verify that nonexecutables stay so.

### BUG-43: Successful terminal stop can return a UTF-8 read error

**Location:** [owner-terminal-session-dispatch.ts](packages/broker/src/owner-terminal-session-dispatch.ts),
lines 147-157.

**Trigger and evidence:** An actual terminal-manager session has unread output
beginning with U+4F60 followed by a newline. Stop it through the actual dispatch
function. The session is finished, but dispatch returns `PRECONDITION_FAILED`:
`Terminal read size cannot fit the next UTF-8 character`.

**Cause and impact:** Stop obtains final state by reading one byte of output.
The existing UTF-8 read guard correctly refuses a page smaller than the first
character, converting a completed stop into an apparent failure.

**Correction and verification:** Obtain terminal state without consuming an
output page, or use a character-safe state read. Test ASCII, a multibyte first
character, drained output, and repeat stop; preserve output redaction and
bounded ordinary reads.

### BUG-44: Byte-limited UTF-8 file pages reject valid text

**Location:** [filesystem-worker.ts](packages/broker/src/filesystem-worker.ts),
lines 24-30; guest read in
[container-task-runner.ts](packages/broker/src/container-task-runner.ts),
lines 474-476.

**Trigger and evidence:** Read a valid file containing 65,535 ASCII bytes,
U+4F60, then `abc` through the actual host worker's default 65,536-byte UTF-8
page. It returns `PRECONDITION_FAILED` / `Filesystem content is not valid UTF-8`;
a 65,538-byte page succeeds. The actual guest script likewise fails on 16,383
ASCII bytes followed by the same character at its default 16 KiB page, returning
`ISOLATED_FILE_OPERATION_DENIED`. Guest execution used a filesystem fixture,
not a live container.

**Cause and impact:** Both readers apply a byte slice before fatal UTF-8
decoding. A page ending inside a character makes a valid text file appear
invalid or denied. This can prevent ordinary source inspection by clients and
the coding controller. Base64 host reads are a workaround, not corrected UTF-8
paging.

**Correction and verification:** Define character-safe byte-page boundaries,
accurate continuation offsets and the behavior of too-small/unaligned ranges.
Keep strict validation for genuinely invalid text and scan every returned byte
for secrets. Test default boundaries, 2/3/4-byte characters, continuation,
genuinely invalid UTF-8, EOF and raw/base64 range behavior.

### BUG-45–46 repair outcome — 2026-10-15

BUG-45 now compacts revoked browser/desktop records transactionally into bounded
`gui_consent_tombstone` records. Ordinary consent evidence is retained until the
maximum Broker preview lifetime after grant creation, then removed; expired
previews cannot be reused or renewed. Default-browser revocations have no expiry.
Both persistent consent entry points check durable evidence across browser and
desktop kinds. Only active grants restore into the GUI consent cache.

The existing 8,000-record total and 1,000-record per-kind bounds are unchanged.
The new marker kind shares those limits. If its 1,000 slots are full, the original
revoked grant is retained rather than forgetting a revocation. Expired ordinary
history can still be reclaimed. Finite capacity remains a deliberate fail-closed
limit; indefinite default-policy history is never silently evicted.

BUG-46 creates `default-browser-v2:` plus a SHA-256 digest of the JSON identity
tuple `(principal, browser, policy)`. The marker is always 83 characters. Reads
also check legacy concatenated markers in grants and tombstones, preserving old
active grants and same-policy revocations. Supported long owner IDs now work;
owner/app/policy, explicit approval and desktop isolation rules remain unchanged.

No SQL table/version migration is required, but the record vocabulary expands.
An older binary rejects compacted state as an unknown record kind. Keep matching
Auth source and state, and preserve all revocations during rollback. Details and
regression results: [repair evidence](evidence/2026-10-15-bugs45-46-remediation.md).

### BUG-45: Revoked GUI grants permanently consume capacity

**Location:** [store.ts](packages/auth/src/store.ts), lines 114-117 and 186-188;
[gui-session-approval.ts](packages/auth/src/gui-session-approval.ts), lines
175-182; permanent grant records in [contracts.ts](packages/auth/src/contracts.ts).

**Trigger and evidence:** Populate actual protected temporary Auth state with
1,000 schema-valid revoked browser grants and run `prune()`. With zero active
grants, a new authorized persistent grant fails with `Auth capacity exceeded`.
The same reproduction with 1,000 revoked desktop grants also fails.

**Cause and impact:** Revocation retains the records without an expiry, pruning
removes only expired rows, and insertion caps the entire kind at 1,000. Ordinary
consent/revocation history eventually disables new permanent GUI grants.

**Correction and verification:** Reclaim hot capacity using bounded historical
records/tombstones while preserving revocation and old-consent replay guards.
Test revoke/prune/reopen at capacity and ensure stale/default-browser consent
cannot be resurrected by compaction.

### BUG-46: Valid long owner IDs silently disable default browser access

**Location:** [gui-session-approval.ts](packages/auth/src/gui-session-approval.ts),
lines 150-151; accepted configuration IDs in
[contracts.ts](packages/auth/src/contracts.ts), lines 41 and 64.

**Trigger and evidence:** Parse a G1 owner configuration with
`defaultBrowserAccess: true` and an 80-character principal ID. The actual schema
accepts it. Identical GUI authorization succeeds for the short-ID control but
returns false and creates no grant for the long ID: its concatenated default
marker is 130 characters.

**Cause and impact:** The marker concatenates principal, application and policy
identities, then silently returns when their combined length exceeds 128.
Individually supported IDs therefore produce a nonfunctional supported setting.

**Correction and verification:** Derive a bounded digest from an unambiguous
identity tuple, with compatibility for existing grants/revocations. Test maximum
valid IDs, distinct tuples and legacy revoked defaults; do not widen consent.

### BUG-47–48 repair outcome — 2026-10-15

BUG-47 now reserves the 500-result budget for running apps before installed-only
identities. Running-only requests skip installed discovery entirely; duplicate
IDs merge metadata without consuming more capacity. The shipped adapter returns
an internal `{apps, truncated}` envelope, validated by the parser and propagated
through the existing public warnings/truncation fields. Capacity, depth, entry,
directory and metadata failures report incomplete results. A complete exact-cap
inventory is not incorrectly marked truncated. If app-open cannot find a target
in incomplete inventory, it returns `OUTPUT_LIMIT` without launching, rather
than asserting that the app does not exist.

BUG-48 adds fixed system, shared and per-user Utilities roots and breadth-first
ordinary-directory discovery: at most four nested directory levels, 128 scheduled
directories and 10,000 inspected entries. Symlinks and paths resolving through
symlinks are skipped. App bundles and other package interiors are not traversed;
hidden entries are outside discovery scope. Every app is identified by bundle ID,
not a returned filesystem path. Root and app metadata cannot expand GUI consent.

Regression fixtures run the actual shipped JXA and the actual app controller
with simulated Foundation/AppKit/process effects. A separate read-only macOS run
also found Activity Monitor in standard Utilities. No actual application was
launched, service changed or GUI consent broadened. Public result schemas and
persistent formats are unchanged; matching adapter/parser source ships together.
Full coverage and limits: [repair evidence](evidence/2026-10-15-bugs47-48-remediation.md).

### BUG-47: App inventory capacity hides running applications

**Location:** [app-inspector.ts](packages/broker/src/app-inspector.ts), lines
59, 74-81 and 188.

**Trigger and evidence:** Execute the actual inventory JXA script with simulated
ObjC metadata for 501 installed apps and one additional running app, then use
the actual parser. The all-app query returns 500 apps with `truncated: false`
and no warnings. The running-only query returns zero apps with the same false
completeness claim.

**Cause and impact:** Installed entries fill the 500-slot map before running
apps are merged. The script silently discards later entries, and the parser
knows only transport truncation. Inventory loses active apps; dependent app
control can also mistake an omitted app for an unknown target.

**Correction and verification:** Apply requested filtering/priority before the
cap and propagate semantic completeness. Test 500/501 installed entries, extra
running apps, duplicates and running-only requests without invoking real apps.

### BUG-48: Standard Utilities applications cannot be discovered or opened

**Location:** [app-inspector.ts](packages/broker/src/app-inspector.ts), lines
24 and 55-59; inventory-dependent open in
[app-control.ts](packages/broker/src/app-control.ts), lines 75-79.

**Trigger and evidence:** Represent an unstarted Activity Monitor bundle under
`/System/Applications/Utilities`. The actual inventory script and controller
with simulated ObjC/process dependencies return an empty inventory and
`TARGET_NOT_FOUND`; the launch adapter is never called. A read-only system-file
check confirms this is Activity Monitor's standard location and bundle ID on
the reviewed host. No application was launched.

**Cause and impact:** The fixed roots are scanned only for direct `.app`
children. Utilities is a directory, so its installed applications are absent
unless already running. Other nested Applications folders have the same
limitation. Installed-app discovery and authorized opening are therefore
incomplete even well below the inventory cap.

**Correction and verification:** Include standard Utilities roots and define
bounded, symlink-safe nested bundle discovery. Test an unstarted Utilities app,
a direct app, ordinary nested folders, duplicate IDs and symlinks.

### BUG-49–50 repair outcome — 2026-10-15

BUG-49 now reads the complete supported `[project].dependencies` string array,
including inline/multiline layouts, multiple items per line, comments, trailing
commas, single/double quotes and supported basic-string escapes. Quoted markers
and URL fragments inside strings are preserved. Empty arrays are valid;
unsupported/malformed arrays return a fixed warning and contribute no partial
array results. Poetry sections and pip/uv/poetry selection retain existing
behavior. This is a bounded metadata extractor, not a complete TOML validator;
multiline string literals and `\U` escapes remain explicitly unsupported in
this field. Existing secret, symlink, 512 KiB manifest, 5,000 dependency,
cancellation and sanitization guards remain in force. No dependency was added.

BUG-50 now recognizes nonempty named directory basenames ending in `.xcodeproj`
or `.xcworkspace`, alongside exact `Package.swift` markers. Symlinks, file
lookalikes, bare suffix names and unrelated endings cannot create those bundle
markers. Indicators retain the bounded suffix labels `.xcodeproj` and
`.xcworkspace`, so even long bundle filenames satisfy the existing result schema.
The automatic walk treats discovered Xcode bundles as opaque markers, preventing
internal workspaces from being reported as additional source projects.

Native metadata-only fixtures and signed Broker coverage verify discovery without
content-read authority. No Xcode, Python interpreter or package manager is run.
This is the BUG-49–50 acceptance scope. Pagination, depth reporting and policy
diagnostics are subsequently repaired below. Earlier verification:
[repair evidence](evidence/2026-10-15-bugs49-50-remediation.md).

### BUG-49: Python inline dependency arrays are silently omitted

**Location:** [package-inspector.ts](packages/broker/src/package-inspector.ts),
`parsePythonManifest()`, lines 266-276.

**Trigger and evidence:** Inspect a temporary `pyproject.toml` with
`[project]` and `dependencies = ["requests>=2.31", "flask>=3"]`. The actual
package inspector returns `dependencies: []`, `warnings: []`, and
`truncated: false`. Moving the two strings onto separate lines returns both;
keeping only the first string on the opening line loses that first dependency.

**Cause and impact:** The parser skips the array's opening line and extracts
only one quoted dependency from each later line. Equivalent valid manifest
formatting changes the reported dependency inventory without any warning.

**Correction and verification:** Parse the supported TOML array syntax across
opening/closing lines and multiple entries, or explicitly report unsupported
syntax. Test equivalent inline/multiline arrays, extras, comments and multiple
strings per line, retaining existing secret and size guards.

### BUG-50: Named Xcode bundles are not recognized as Swift projects

**Location:** [filesystem-inspector.ts](packages/broker/src/filesystem-inspector.ts),
Swift markers at line 313 and marker matching at 739-744.

**Trigger and evidence:** Create a disposable directory containing only
`Example.xcodeproj/`. Actual native discovery with `types: ["swift"]` returns
`projects: []`, `truncated: false`.

**Cause and impact:** `.xcodeproj` and `.xcworkspace` are tested as literal
complete filenames rather than suffixes. Normal named Xcode bundles are never
recognized through these advertised Swift indicators unless a separate
`Package.swift` happens to exist.

**Correction and verification:** Match named project/workspace directory
suffixes while preserving exact manifest markers and symlink exclusions.
Test both named bundle forms, `Package.swift`, unrelated suffixes and symlinks.

### BUG-51 through BUG-53 implementation and acceptance

BUG-51 aggregates only recognized marker labels across every directory page,
then emits one canonical-root/type record with ordered, distinct indicators.
Overlapping roots remain deduplicated. Exact result caps stay complete unless
another distinct record or traversal omission is found.

BUG-52 separates incomplete traversal from budget exhaustion. Eligible children
omitted below depth 16 mark the result truncated without stopping later pages
or queued siblings. Skipped folders, links and opaque Xcode bundles do not
create depth omissions. Global directory/entry/result bounds remain enforced.

BUG-53 shares the filesystem capability mapping across explanation, path/search
planning and capability projection. Search requires content-read authority;
metadata-only roots produce the same denial as execution. Detailed search
explanations bind the public target to the first requested normalized path and
authorize every additional root. Existing write/patch guards remain covered.
No proposed tool executes during explanation.

Fifteen new cases cover native pagination/depth behavior, simulated global
budgets and signed Broker authorization. Original failing fixtures reproduced
all three defects before repair. Scope and final verification:
[BUG-51–53 evidence](evidence/2026-10-15-bugs51-53-remediation.md).

### BUG-51: A project is emitted again on each marker-bearing directory page

**Location:** [filesystem-inspector.ts](packages/broker/src/filesystem-inspector.ts),
lines 739-751, inside the paginated directory loop.

**Trigger and evidence:** Create `requirements.txt`, 500 ordered `sNNNN.txt`
files, and `setup.py` in one directory. Actual native discovery emits two
Python projects for that same root, one with each indicator, and reports
`truncated: false`.

**Cause and impact:** Marker aggregation is page-local and project results are
appended without a `(root, type)` identity. Pagination duplicates logical
projects, splits their indicators and can consume result slots that should
have been available for other projects.

**Correction and verification:** Aggregate indicators per directory/type
across pages and apply the result cap to distinct logical results. Test markers
on pages one/two, multiple types, overlapping input roots and exact result caps.

### BUG-52: Project discovery omits deeper projects without truncation

**Location:** [filesystem-inspector.ts](packages/broker/src/filesystem-inspector.ts),
line 761 and final result at 773; `MAX_PROJECT_DEPTH` is 16.

**Trigger and evidence:** Place a `package.json` beneath 17 nested directories
and discover from the outer root. Actual native discovery returns no projects
with `truncated: false`. Narrowing the root by one directory finds that same
Node project.

**Cause and impact:** Descending is skipped at the depth boundary without
recording incomplete traversal. Clients cannot distinguish an empty tree from
an unvisited subtree, unlike the existing entry/directory budget handling.

**Correction and verification:** Preserve the fixed depth budget but propagate
that eligible subdirectories were omitted. Continue other accessible roots.
Test exact depth, depth plus one, skipped special folders and sibling roots.

### BUG-53: Text-search explanation uses weaker filesystem authority

**Location:** [broker.ts](packages/broker/src/broker.ts), policy explanation at
line 2816 versus text-search planning at lines 4912-4917.

**Trigger and evidence:** Configure an otherwise authorized root with
`metadata: true`, `contentRead: false` and both required principal/target scopes.
Send actual signed requests to a temporary Broker. A `mac_policy_explain`
request for `mac_search_text` without `proposed_arguments` returns `allow` and
`AUTHORIZED`; actual search returns `POLICY_DENIED` because the root does not
grant `content_read`.

**Cause and impact:** The explanation's tool-to-capability mapping defaults
text search to metadata, while execution requires content reads. This is
misleading diagnostics, not a content authorization bypass. BUG-34's patch
write explanation fix remains intact.

**Correction and verification:** Share the authoritative filesystem capability
mapping with execution, retaining side-effect-free explanations. Test metadata
and content roots, with/without proposed arguments and the actual corresponding
read decision.

### Review method and repair order

KB-MCP recall and Skill Registry reads supplied
`engineering:scmc-review` v1.0.0 and
`project:code-docs-source-of-truth-sync` v1.0.1. Current source and reproduced
behavior take precedence over recalled historical repair states.

Original-review SCMC scope was the lifecycle, inventory, transfer and diagnostic paths:
Simple **PASS** (no speculative replacement required), Clear **WARN** (silent
omissions), Modular **PASS** (repairs fit existing owners), Consistent **FAIL**
(Medium: page-local project identity, divergent content-authority mapping, and
lost file-mode semantics produced inconsistent observable behavior). BUG-38–44
now correct the repaired lifecycle and transfer paths. BUG-45–53 also repair
the confirmed inventory, discovery and diagnostic defects. Correctness and security
guards must be preserved. These ratings do not replace bug priorities or
establish a whole-system architecture verdict.

BUG-38 through BUG-53 now have local fixes and regression evidence. This closes
all supported findings from this review; it does not establish exhaustive
whole-system defect freedom.

## Historical review and remediation — 2026-10-13

Review date: 2026-10-13 (Asia/Kuala_Lumpur)
Reviewed revision: `09dd85b99b7ffc0246a14f85959a7b49473d7abc` (`main`)
Remediation date: 2026-10-13
Status: **DONE — all nine new findings FIXED locally and regression-verified.**

This historical review records **37 findings, all FIXED in repair revision `a7f2450`**:
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
