# BUG-49 through BUG-50 remediation — 2026-10-15

Status: **DONE locally**. Base: `a7d599934d3def5105b24871cf5229d75fecea24`
(`main`), preserving preceding uncommitted BUG-38–48 work. No commit, push,
deployment, service restart, package installation or Xcode execution occurred.
The report contains **53 findings: 50 fixed locally and three open**
(BUG-51 through BUG-53).

## Root causes and corrections

| Bug | Cause | Correction |
| --- | --- | --- |
| BUG-49 | The Python line parser skipped the opening array line and accepted only one dependency string per following line. | Scan the complete supported string array across line boundaries, separating string content from comments/delimiters, then reuse existing dependency validation and limits. |
| BUG-50 | Xcode suffix markers were compared with complete filenames instead of matching named bundle directories. | Recognize nonempty named `.xcodeproj`/`.xcworkspace` directory suffixes, preserve exact Swift manifest markers and emit existing bounded suffix labels. |

## Python parsing scope

The new private reader handles `[project].dependencies` arrays, including bare or
quoted `dependencies` keys, single/double-quoted single-line strings, inline or
multiline array layout, multiple entries per line, comments outside strings,
trailing commas and common basic-string escapes including `\uXXXX`. Environment
marker quotes and URL fragments inside dependency strings are not mistaken for
TOML delimiters/comments. CRLF and empty arrays work. pip, uv and poetry manager
selection all use the corrected project-array path. Following Poetry dependency
sections remain independent and keep the existing `python` exclusion.

This is deliberately a bounded metadata reader, not a complete TOML/PEP-508
validator or resolver. Triple/multiline string literals and `\UXXXXXXXX` escapes
remain unsupported in this field; malformed separators, incomplete arrays and
non-string members also produce a fixed warning. A syntax-rejected array adds
no partial entries. Malformed individual requirement strings are separately
omitted with a warning. Version/marker text follows the existing representation;
extras are excluded from the package-name field rather than introducing a new
schema. Unrelated TOML features are not newly interpreted or globally validated.

The implementation reuses dependency sanitization, deduplication and truncation.
Manifest reads still enforce canonical roots, no-follow descriptors, regular
files, identity readback, UTF-8 validation, secret scanning and the 512 KiB cap.
Output remains capped at 5,000 dependencies. Cancellation/time checks occur
while scanning array values and long strings/comments. No parser dependency,
Python process, package manager, shell or network operation was added.

## Swift/Xcode discovery scope

Native directory metadata identifies a Swift source root when it contains
`Package.swift` or a named directory ending in `.xcodeproj` / `.xcworkspace`.
Symlinks, file lookalikes, bare suffix names and unrelated endings cannot create
those bundle markers. Case-sensitive suffix matching follows the existing marker
convention. Existing exact manifest and non-Swift marker behavior is preserved.

The result uses the existing indicator labels `.xcodeproj` and `.xcworkspace`,
not the full filename. This preserves the public indicator length bound even
for long valid filesystem basenames. The automatic walk does not descend into
a discovered Xcode bundle: internal `project.xcworkspace` or marker-looking files
cannot manufacture additional source projects. Explicitly selected roots retain
ordinary authorized metadata inspection behavior.

The shared small bundle-marker helper owns both suffix identification and the
walk exclusion. No file content is read and no new root authority is granted.
Tests give discovery metadata permission with `contentRead: false`. The existing
public result shape, limits, process boundaries and persisted formats are
unchanged; no migration is required. The original page-local aggregation and
depth-completeness logic remain outside scope as BUG-51 and BUG-52, and policy
explanation mismatch remains BUG-53.

## Regression evidence

The first failing run against the original code contained **29 tests: nine
passed and 20 failed**. Failures reproduced all six supported array layouts,
manager paths, quoted requirements, missing unsupported-syntax warnings, named
Xcode bundle discovery and the bare-suffix false positive. After repair, these
checks passed without weakening the assertions.

The revision adds **31 regression cases**:

| Area | New cases | Coverage |
| --- | --- | --- |
| Actual package inspector | 22 | Six equivalent array layouts; pip/uv/poetry; extras, quoted markers, escaped quotes and URL fragments; six malformed/unsupported forms; empty/CRLF/Unicode escape handling and later Poetry sections; output cap/deduplication; in-array cancellation; oversized and secret manifests; no-follow manifest links. |
| Actual native filesystem discovery | 9 | Each named bundle kind and opaque interiors; merged exact/suffix Swift labels and long names; four nonmatching names; file/symlink lookalikes; automatic types with nested bundles and exact Swift manifests. |

The existing signed Broker discovery test additionally creates a named Xcode
bundle, requests Swift alongside existing project types, checks the bounded
indicator and preserves its metadata-only/secret-output assertions.

Focused package/Xcode suites pass **36 tests with zero failures/skips**. All
new manifests and project structures live in disposable temporary directories.
The 5,001-unique-dependency fixture verifies that one duplicate does not consume
a slot and that output truncates at 5,000. Synthetic secret content is denied
before parsing; cancellation is checked inside a populated array. No project
setup code, Python resolver or Xcode project is executed by these checks.

## Final verification

| Check | Result |
| --- | --- |
| Build, including native stages | PASS |
| Native fault-test addon build | PASS |
| TypeScript typecheck | PASS |
| Current-source suite: 247 compiled/script files | **2,379 total; 2,360 passed; zero failed/cancelled; 19 skipped** |
| Focused package/Xcode suites | PASS: **36 tests**, zero skipped |
| Style/docs/matrix/process-boundary checks | PASS |
| Contract/catalog/ledger validation | PASS: **58 unique contracts** |
| Final diff, new-file whitespace, links and finding counts | PASS |

Runtime: Node.js `v25.5.0` on macOS. A single full run enumerated current
`packages/*/src/**/*.test.ts` and root `scripts/*.test.mjs`, including untracked
new sources, verified their compiled artifacts exist, and invoked
`node --test --test-timeout=120000 --test-concurrency=4` across those 247 files.
The run exited zero. Thirty-one new cases explain the increase from 2,348 to
2,379 tests. It preserved and excluded only the two previously identified
obsolete ignored compiled tests with no source; their three historical ordinary
`npm test` failures are not claimed resolved. No test assertion or timeout was
relaxed for the repair.

Node 24, full Python dependency resolution, Xcode opening/building, deployment
and the 19 existing opt-in/platform/integration skips remain unverified. These
are metadata behavior repairs; local inspection tests do not imply executable
project acceptance. Public schemas, dependencies and persistence formats are
unchanged. No live release switch or rollback was performed.

KB-MCP project recall returned historical context without a directly reusable
parser/discovery repair. Current source, existing guards and regression evidence
own these conclusions. Previously retrieved SCMC/code-documentation sync skills
and the local planning/knowledge-reuse guides informed the scoped changes.

The new dated result and reusable parser/discovery boundaries were saved as
agent-inference memory
`ef9a01bc-87c8-48a7-ab32-dd65ab6eebff:31e2ce5a-f53b-455c-83e5-800ecc09c3b9`;
KB-MCP confirmed the write. Future reuse requires current-source verification.
