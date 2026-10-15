# BUG-51 through BUG-53 remediation — 2026-10-15

Status: **DONE locally**, including the authorized local commit and main integration.
Base: `a7d599934d3def5105b24871cf5229d75fecea24` (`main`). This batch preserves
the preceding authorized BUG-38–50 repairs and adds the final three corrections.
The user additionally authorized committing the cumulative work and merging it
into local `main`. No remote push or live deployment is part of acceptance.

## Corrections

| Bug | Verified cause | Implemented correction |
| --- | --- | --- |
| BUG-51 | Each marker-bearing directory page emitted a separate project/type result. | Aggregate only known marker labels for each directory across pages, then emit one canonical-root/type result with catalog-ordered distinct indicators. Apply the result cap to distinct records. |
| BUG-52 | Eligible children omitted at depth 16 did not affect completeness; setting the old shared flag would also stop other work. | Separate incomplete traversal from global exhaustion. Depth/path omissions mark truncation and continue later pages/siblings. Existing entry/directory/result limits still stop work. |
| BUG-53 | Explanation treated text search as metadata while actual planning required content reads. | Share the capability mapping with path/search execution and capability projection, preserving write/patch checks. Detailed search explanations compare the public path against the first planned search root and authorize additional roots. |

## Reproduction and regression evidence

Before production edits, targeted new tests failed for all three original
triggers: split Python indicators at an exact one-result cap; a project at depth
17 returning false completeness; and a signed search explanation allowing a
metadata-only root. The content-enabled control passed. After repair, all three
triggers and the additional cases below pass.

Fifteen new test cases:

- Eleven discovery tests: native page-one/page-two aggregation; distinct types,
  overlapping/duplicate roots and real result overflow; Swift bundle aggregation
  and opaque interiors; exact depth 16 and depth 17; a marker on a later page
  after a depth omission plus a pending sibling; ignored folders, symlinks and
  Xcode bundles at the boundary; explicit deeper roots; synthetic exact/over-limit
  50,000-entry cases and the 10,000-directory budget.
- Four signed Broker tests: metadata-only and content-readable roots both with
  and without proposed arguments, actual corresponding search decisions,
  mismatched first-root targets, and denial of a second root lacking content
  capability or its target grant. Explanation only plans the request; it never
  invokes search execution.

The discovery pagination/depth fixtures use the actual native filesystem
adapter in disposable directories. Only large global-budget enumeration is
simulated. Discovery remains metadata-only, retains existing marker labels and
does not read manifests. The signed Broker tests run against a disposable ledger.
Existing metadata-stat, secret/denied-zone explanation and BUG-34 write/patch
regressions remain in the affected Broker suite.

Focused suites: **146 total; 140 passed; zero failed; 6 existing skips** across
Broker, filesystem executor, Swift discovery and discovery pagination suites.

## Verification and limits

| Check | Result |
| --- | --- |
| Full current-source suite, 248 package/script files | PASS: **2,394 total; 2,375 passed; zero failed; 19 existing skips** |
| Full TypeScript/native build | PASS |
| Native peer fault build | PASS |
| Typecheck | PASS |
| Style, documentation and local Markdown links | PASS |
| Verification matrix | PASS: 29 targets, 25 threats, 31 tasks, 19 evidence references |
| Process boundaries | PASS: zero unreviewed entries |
| Tool contracts and ledger schema | PASS: 58 contracts |
| Final diff whitespace and finding-count consistency | PASS |

The 19 skipped checks remain outside acceptance. The final full run completed
in approximately 90 seconds. No failing test was suppressed or assertion changed.
The full runner enumerates every current source-backed package test and
top-level script test, including new files. It uses four concurrent files and
the original 120-second timeout, without weakening assertions. Two obsolete
ignored compiled test artifacts with no current source remain preserved and
excluded, as documented in the earlier review evidence.

Local verification does not cover the existing opt-in/platform/integration skips,
Node 24 runtime acceptance, production Docker tasks, privileged installation,
signing/release acceptance or live service cutover. No dependency, schema,
persistence migration, network operation or production state change is introduced
by BUG-51–53. The pre-existing search execution security checks remain enforced.

KB recall was checked against current source. Prior review Skills and current
local evidence supplied the workflow; historical memory did not override code.

## Local Git integration

The cumulative authorized BUG-38–53 source, tests, contracts, runbooks and evidence
are included in the commit created on `codex/fix-review-bugs-38-53` and
fast-forwarded into local `main` after acceptance. The commit message is
`Fix code review bugs 38 through 53 with regression coverage`. No push occurred. Earlier batch evidence describes the state at that
batch's completion, including its then-uncommitted status; it is historical.
