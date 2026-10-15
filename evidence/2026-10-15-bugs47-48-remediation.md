# BUG-47 through BUG-48 remediation — 2026-10-15

Status: **DONE locally**. Base:
`a7d599934d3def5105b24871cf5229d75fecea24` (`main`), preserving all preceding
uncommitted BUG-38–46 repairs. No commit, push, deployment, service restart,
production configuration write or actual app launch occurred.
The report contains **53 findings: 48 fixed locally and five open**
(BUG-49 through BUG-53).

## Root causes and changes

| Bug | Cause | Correction |
| --- | --- | --- |
| BUG-47 | Installed entries filled the 500-slot map before running apps were merged, and the script reported no completeness information. | Collect running apps first; skip installed discovery for either running-only filter; merge duplicate identities; report semantic truncation in a strict internal envelope and propagate public warnings/truncation. |
| BUG-48 | Only direct `.app` children of installation roots were inspected; Utilities and ordinary nested app folders were absent. | Add fixed shared/system/user Utilities roots and bounded breadth-first directory discovery, excluding links and bundle/package interiors. |

AppInventoryInspector still owns a fixed Broker-generated JXA program. The only
script specialization is a boolean computed after input-filter validation;
callers cannot supply JavaScript, discovery paths, commands or launch flags.
Process execution still uses `/usr/bin/osascript`, cwd `/`, an empty environment,
a ten-second maximum, the fixed 256 KiB output bound and cancellation.

The inventory remains limited to 500 distinct valid bundle identities. Running
apps reserve slots before installed-only apps; if running apps alone exceed the
limit, their result is explicitly partial. Duplicate metadata can still enrich
an existing identity at capacity, preserving running state and discovered version.
A complete result of exactly 500 apps is not marked truncated merely for being
full. Both `running_only: true` and `include_installed: false` skip installation
scanning entirely, rather than filtering a previously exhausted installation map.

The shipped JXA returns `{ apps, truncated }`; the parser rejects malformed,
extra-field or over-cap envelopes and retains strict per-app validation,
sanitization and output sorting. Legacy arrays remain accepted for existing
internal adapter fixtures; they have no new completeness evidence. The production
script always emits the envelope. Semantic incompleteness is ORed with existing
transport truncation, and a bounded generic warning explains that discovery is
partial without exposing paths. Existing Broker result fields propagate it;
no public result schema or persistent format migration is needed.

App-open still requires a concrete inventory identity and uses only
`/usr/bin/open -b <bundle-id>`, followed by running-state readback. When an absent
target comes from incomplete inventory, it returns `OUTPUT_LIMIT` before any
launch rather than the definitive `TARGET_NOT_FOUND`. Complete-scope absence
still returns `TARGET_NOT_FOUND`. GUI grants, app target authority, document/URL
denials, explicit approvals, cancellation and final-state verification remain
unchanged. This does not authorize opening arbitrary filesystem paths.

## Discovery boundaries

The fixed roots cover `/Applications`, `/System/Applications`,
`/System/Library/CoreServices` and the owner's `~/Applications`, with explicit
Utilities roots for shared, system and per-user Applications. Initial roots are
scheduled before ordinary nested folders, and duplicates are visited once.

Discovery has fixed bounds of four nested ordinary-directory levels per root,
128 scheduled directories across roots, and 10,000 inspected entries. Depth,
directory, entry and app-count omissions set `truncated`. Directory/listing,
running-inventory and bundle-metadata exceptions also flag incomplete results.
Absent optional roots are ignored. Hidden entries and policy-excluded package
interiors do not expand discovery scope.

Directory attributes reject symbolic links; resolving a root/child path through
symlinks also excludes it. The walk does not enter an `.app` bundle or another
AppKit-recognized package. This is bounded metadata discovery, not descriptor-
pinned execution authority: the controller launches by an independently
approved bundle identity, never the inspected bundle path. No stronger promise
about hostile concurrent namespace replacement is inferred from these checks.

## Regression evidence

The initial actual-script fixture run against the original implementation had
**10 tests: one passed and nine failed**. Failures reproduced lost running apps,
false completeness, missing version merging, undiscovered Utilities/nested apps,
and followed symlink metadata. Tests were not weakened to make the repair pass.

This revision adds **24 cases**:

| Area | New cases | Important assertions |
| --- | --- | --- |
| Actual JXA with Foundation/AppKit seams | 16 | 499/500/501 installed entries plus a distinct running app; all running-filter combinations skip installed scanning; 501 running apps; duplicate IDs and version at exact capacity; Utilities/nested controller opening; symlinks, ancestor links and package/app boundaries; exact/over entry limits; exact/over depth; directory budget with Utilities reservation; missing roots versus unavailable directory/bundle metadata. |
| Inventory parser and actual host metadata | 7 | Strict completeness envelopes, semantic/transport flag combination, malformed/extra/over-cap framing, and a real read-only Utilities inventory. |
| App controller | 1 | Missing target in partial inventory returns `OUTPUT_LIMIT` with zero launch attempts. |

The existing signed Broker inventory test additionally verifies public
`warnings`/`truncated` propagation. Existing control tests retain fixed launch
arguments, running readback, target normalization, unsupported-target rejection,
deadline and focus validation. The focused inventory/controller suites pass
**36 tests, zero failures/skips** on this host.

The fixture executes the exact script passed by AppInventoryInspectorImpl in a
VM with mocked Foundation/AppKit metadata and captures actual controller calls.
Its launch adapter only changes simulated running state. It never opens a real
application. The initial script seam checks were followed by a real macOS
read-only inventory: it returned 264 metadata identities, found
`com.apple.ActivityMonitor`, and explicitly reported partial discovery. This is
a dated observation, not a stable app count or a complete host inventory claim.
The final focused suite also verified the actual standard Utilities app when
present. Neither read requires or establishes GUI mutation approval.

## Verification workflow and limits

An initial default-concurrency full run hit three existing ten-second Git-clone
fixture timeouts in Broker Git status/log and contract conformance. These were
`spawnSync /usr/bin/git ETIMEDOUT`, not assertions in the changed inventory paths.
A follow-up was mistakenly started before that run finished and reused its
scratch log; the follow-up exited zero, but the mixed log is unsuitable as final
summary evidence. Both runs were allowed to finish before the final validation.

The corrected final workflow runs one source-backed suite with
`--test-concurrency=4`, the original `--test-timeout=120000`, and a dedicated
scratch log. No production Git behavior, test assertion or timeout was relaxed.
This bounds test load and reruns the original failure paths. Resource contention
is consistent with the initial timeouts; the exact host-load cause was not
profiled. Only the final isolated run supplies the completion results below.

| Check | Result |
| --- | --- |
| Build, including native stages | PASS |
| Native fault-test addon build | PASS |
| Final TypeScript typecheck | PASS |
| Focused inventory/controller suites | PASS: 36 tests, zero failures/skips |
| Current-source full suite: 246 compiled/script files | **2,348 total; 2,329 passed; zero failed/cancelled; 19 skipped** |
| Style/docs/matrix/process-boundary checks | PASS |
| Contract/catalog/ledger validation | PASS: 58 unique contracts |
| Final diff/new-file whitespace, links and counts | PASS |

Runtime: Node.js `v25.5.0` on macOS. The source-backed suite includes every current
`packages/*/src/**/*.test.ts` and root `scripts/*.test.mjs`, including untracked
new sources; it verifies mapped compiled artifacts exist. It includes 246 test
files and 24 new cases beyond the preceding 2,324-test revision. The two previously
identified obsolete ignored compiled tests without source remain excluded and
preserved. Their three historical ordinary-`npm test` failures are not claimed
resolved.

The final isolated suite passed the original Git status/log and contract
conformance failure paths. Its dedicated log ended with the counts above and
a zero process exit; the mixed scratch log was not used as completion evidence.

Node 24, physical app launch/focus, live OAuth/GUI authorization and the existing
19 opt-in/platform/integration skips are not newly verified. The read-only host
check establishes metadata visibility only. No deployment or desktop-state
acceptance is inferred from simulated app opening. Public contract field shapes,
GUI authority and persisted formats remain unchanged. Ship the new adapter and
parser source together; no live release switch or rollback was performed.

KB-MCP project recall supplied dated project references but no directly reusable
inventory repair. Current source, the actual shipped script, disposable metadata
fixtures and read-only host behavior own the conclusions. Previously retrieved
SCMC/code-documentation sync skills and the local planning/architecture guides
informed scope and compatibility checks.

The new dated outcome and reusable discovery/completeness boundaries were saved
as agent-inference memory
`ef9a01bc-87c8-48a7-ab32-dd65ab6eebff:aff5652a-3ef2-49c1-8cd0-c3e8ae3e6fbf`;
KB-MCP confirmed the write. Future reuse still requires current-source verification.
