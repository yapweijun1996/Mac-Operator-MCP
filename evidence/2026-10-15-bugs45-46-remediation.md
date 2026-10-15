# BUG-45 through BUG-46 remediation — 2026-10-15

Status: **DONE locally**. Base: `a7d599934d3def5105b24871cf5229d75fecea24`
(`main`), preserving the preceding uncommitted BUG-38–44 repairs. No commit,
push, deployment, service restart, production Auth write or live GUI operation
occurred. The report contains **53 findings: 46 fixed locally and seven open**
(BUG-47 through BUG-53).

## Root causes and corrections

| Bug | Cause | Correction |
| --- | --- | --- |
| BUG-45 | Revoked browser/desktop grants had no expiry and occupied the same 1,000-record kind capacity as live authority forever. | Transactionally compact revoked rows into a separately bounded `gui_consent_tombstone` kind, retain replay evidence while needed, and restore only active grants into the GUI cache. |
| BUG-46 | Concatenated default markers exceeded 128 characters even for supported owner IDs; creation silently stopped. | Use `default-browser-v2:` plus SHA-256 of a JSON `(principal, app, policy)` tuple. The marker is always 83 characters. Check both old and new markers before automatic creation. |

Both persistent consent entry points now check durable consent use across browser
and desktop grant kinds. A compacted consent cannot be reused after restart,
converted to desktop authority or downgraded to temporary consent to bypass use
tracking. An existing active matching grant remains idempotently reusable.
Default creation remains owner-only and Chrome/Safari-only; explicit approval,
sensitive controls, session/principal revocation, policy binding and desktop
opt-in rules remain unchanged.

## Ownership, retention and compatibility

AuthStore owns durable records and atomic compaction. GuiSessionApprovals owns
browser/default consent identities and active in-memory delegation. The Broker
continues to own preview validation and the maximum preview lifetime;
AuthStore imports the existing `GUI_SESSION_PREVIEW_TTL_MS` rather than creating
a second lifetime constant. There is no new package dependency.

Replay through the GUI consent entry points requires a live Broker preview.
For grants issued through those entry points, grant creation is at or after
preview creation and the preview lifetime is at most ten minutes. Retaining
consent evidence until grant creation plus that maximum is conservative.
Stopped-service setup grants have no matching Broker consent preview and cannot
be replayed through those entry points without a new owner-reviewed preview. `BrokerStore.createApprovalPreview()` returns an
existing preview without extending expiry; ledger rotation leaves request
replay tombstones. Once the retained lifetime passes, a missing GUI marker does
not make an expired/archived preview usable. Active permanent grants are never
expired by this retention rule.

Default-browser markers have no preview, so their revocations never expire.
The tombstone schema rejects an expiry for both `default-browser:` and
`default-browser-v2:` identities. Legacy active records remain usable without
creating a duplicate, and legacy revoked records/tombstones still block the
same default. New policy identities remain separately eligible, preserving the
existing setting's semantics. New digest tuples are unambiguous even where
legacy colon concatenation could collide; legacy denials remain conservative.

The existing limits remain **8,000 total records, 1,000 per kind, 16 active GUI
sessions and 4,096 in-memory consent mappings**. Tombstones count toward the
total and have their own 1,000-record kind limit. Expired ordinary markers are
pruned. If marker capacity is full, compaction leaves additional revoked rows
in their original kind; it never evicts still-relevant evidence. Finite default
policy history can therefore still reach a genuine bounded-capacity limit;
that is a deliberate fail-closed boundary, not automatic revocation removal.
The tests cover new consent after 1,000 revoked ordinary grants in each kind,
new default-policy access after 1,000 revoked legacy defaults, and three cycles
of ordinary-history reclamation.

Compaction deletes the original row and writes its marker in one SQLite
transaction. Replacing one row with another does not exceed the global cap.
A failed marker insert rolls the original deletion back. Existing inactive
cache entries grant no authority because every operation checks the durable
original record; removing it cannot revive a grant. Marker keys are validated
against their consent-ID SHA-256 during write, lookup and startup. Malformed
stored markers fail closed with value-free errors.

The `records` table and `user_version=1` are unchanged, but the record vocabulary
has expanded. Earlier Auth binaries explicitly reject unknown record kinds and
cannot open state once tombstones exist. This is a source-level compatibility
finding, not a fresh old-binary deployment test. Before upgrading, take a
consistent stopped-service backup. Keep compatible Auth code/state together.
Do not delete tombstones or restore stale state after later revocations to make
an older binary start. Downgrade needs a reviewed revocation-preserving
conversion, or continued compatible code. No live migration or downgrade was
performed. See [operations](../docs/gui-computer-use.md#gui-consent-history-and-capacity).

## Regression evidence

The initial test run against the original implementation had **28 tests:
24 passed, four failed**. The two capacity cases failed with `Auth capacity
exceeded`; the 80/128-character owner cases returned false. The legacy revoked
default control already passed and remains covered after compaction.

The first implementation run exposed a test fixture error: an Auth-schema-valid
plain policy ID did not satisfy the independent Broker `policy-...` contract.
The fixture was corrected to a maximum valid 127-character Broker policy ID;
production policy validation was not widened. The consent-capacity fixture uses
the same fixed clock for Auth pruning and Broker previews, avoiding synthetic
clock disagreement. No security assertion was weakened.

The revision adds **18 regression cases**:

| Area | New cases | Coverage |
| --- | --- | --- |
| GUI manager/authorization | 10 | 80/128-character owners with maximum valid Broker policies; stable reuse and revoked restart; 1,000 revoked rows for each kind; legacy active/revoked defaults; distinct tuples with colliding legacy concatenation; cross-kind replay denial; a full legacy default history followed by a new policy. |
| AuthStore compaction | 8 | Active/retired browser and desktop preservation; live-marker expiry and restart; expired history reclamation; indefinite legacy/new defaults; full-marker fallback; injected transactional insert failure; marker identity corruption; three 1,000-record reclamation cycles; schema denial of expiring default revocations. |

The focused suites also retain existing tests for revocation during approval
issuance, global reset, owner/session/policy restrictions, sensitive operations,
finite temporary grants, capacity bounds, corrupt storage and restart behavior.
All Auth/Broker databases used for new tests are disposable private fixtures.

## Final verification

| Check | Result |
| --- | --- |
| Build, including native stages | PASS |
| Native fault-test addon build | PASS |
| TypeScript typecheck | PASS |
| Current-source suite: 245 compiled/script files | **2,324 total; 2,305 passed; zero failed/cancelled; 19 skipped** |
| Focused GUI/store/capacity/diagnostics suites | PASS: **45 tests**, zero skipped |
| Style, docs, matrix, process boundaries | PASS |
| Contract/catalog/ledger validation | PASS: **58 unique contracts** |
| Final diff, new-file whitespace, links and finding counts | PASS |

Runtime: Node.js `v25.5.0` on macOS. The source-backed run includes every current
`packages/*/src/**/*.test.ts` and root `scripts/*.test.mjs`, including untracked
new sources, verifies mapped compiled artifacts exist, and invokes
`node --test --test-timeout=120000` on those 245 files. Eighteen new cases explain
the increase from 2,306 to 2,324 tests. The two previously identified obsolete
ignored compiled tests with no source remain excluded and preserved; their three
historical ordinary-`npm test` failures are not claimed resolved.

Node 24, live OAuth/GUI consent/revocation, production database migration,
downgrade and the 19 existing opt-in/platform/integration skips were not newly
verified. No runtime permission or deployment conclusion is inferred from the
local unit/regression evidence. Prior repairs remain documented in
[BUG-38–41 evidence](2026-10-15-bugs38-41-remediation.md) and
[BUG-42–44 evidence](2026-10-15-bugs42-44-remediation.md).

KB-MCP recall found the historical default-browser authorization decision and
its original same-policy-revocation boundary. Current source and tests verified
that boundary before adapting marker storage. Previously read SCMC and
code/documentation-sync skills and the local architecture-change review guide
informed this scoped change; memory was not treated as runtime truth.

The new dated outcome and reusable retention/compatibility rules were saved as
agent-inference memory
`82ebf7fd-6f91-4d7b-baba-9f006fb34362:8cdd9c49-c9d3-47d1-83de-ebeba3052566`;
KB-MCP confirmed the write. Revalidate current source before future reuse.
