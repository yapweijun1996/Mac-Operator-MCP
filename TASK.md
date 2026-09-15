# Mac-Operator-MCP Task Ledger

Status: Active
Version: 0.1
Last verified: 2026-09-15

Service-lock quarantine addendum: commit `d3ca767` atomically moves exact
owner-lock identities to private same-directory quarantine names, rechecks
device/inode/type, and only then removes them. Replacement locks fail closed;
focused service-lock tests pass 5/5. Orphan quarantine recovery and installed
service readback remain open. Evidence:
`evidence/2026-09-15-service-lock-quarantine.md`.

IPC socket quarantine addendum: commit `6e246bf` moves stale and owned Unix
sockets to private same-directory quarantine names before identity recheck and
unlink, so a replacement pathname is not deleted after the initial check.
Focused Broker IPC tests pass 10/10; orphan quarantine recovery and installed
service readback remain open. Evidence:
`evidence/2026-09-15-ipc-socket-quarantine.md`.

TLS material lifetime addendum: commit `96adc2d` returns the validated TLS
file buffer without an unnecessary duplicate and wipes a partially loaded
certificate when private-key loading fails. Focused Edge TLS/service-startup
tests pass 8/8; production TLS packaging, shutdown readback, and full HTTPS
Edge evidence remain open. Evidence:
`evidence/2026-09-15-tls-material-lifetime.md`.

Edge key handoff lifetime addendum: commit `5695db0` clears the protected-file
loader buffer after request-factory copy. Focused Edge key/request-factory
tests pass 5/5; full HTTPS Edge and production key-storage evidence remain
open. Evidence: `evidence/2026-09-15-edge-key-handoff-lifetime.md`.

Request-authentication key lifetime addendum: commit `fec6e5b` clears transient
Edge HMAC key copies in Broker authentication and response signing `finally`
paths. Focused IPC tests pass 18/18. Production key storage and full Broker
regression remain open. Evidence:
`evidence/2026-09-15-request-authentication-key-lifetime.md`.

Authentication-key memory lifecycle addendum: commit `42766c9` clears partial
loads and superseded raw Edge/approval snapshots, with explicit manager
disposal and startup cleanup after Broker handoff. Focused keyring tests pass
10/10. Production delivery, signing, and shutdown evidence remain open.
Evidence: `evidence/2026-09-15-authentication-key-memory-lifecycle.md`.

Backup-cleanup target-fence addendum: commit `f25c900` removes Broker backup
and temporary files through identity-checked same-directory quarantine with
non-overwriting restoration on failure. Build, lint, typecheck, diff checks,
and a physical prune probe pass. Fresh persistence regression and orphan
quarantine recovery remain open. Evidence:
`evidence/2026-09-15-backup-cleanup-target-fence.md`.

Filesystem unlink target-swap addendum: commit `a6971fc` atomically quarantines
the selected pathname before verifying and deleting its exact inode, and uses
non-overwriting restoration on mismatch. Focused filesystem tests and the
physical temp-root probe pass. Orphan-quarantine recovery and production
packaging remain open. Evidence:
`evidence/2026-09-15-filesystem-unlink-quarantine.md`.

Credential-retirement fence addendum: commit `737ab3a` validates the exact
revoked key identity before and after quarantine rename, restores only with a
non-overwriting hard link when retirement fails, and clears loaded key bytes on
all paths. The physical Keychain-enabled credential suite passes 11/11.
Production Keychain distribution, installed helper recovery, and final release
gates remain open. Evidence:
`evidence/2026-09-15-credential-retirement-fence.md`.

Privileged policy-state addendum: source revision `7926c99` gives all 44
catalog tools explicit default-policy lifecycle records. The three L5 helper
tools carry independent scopes, privileged family, target types, budgets, and
explicit approval policy while remaining unimplemented and disabled; package
targets are now first-class policy targets. Focused policy and
contract-conformance checks pass 10/10. Root-domain signing, installation,
and privileged enablement remain open. Evidence:
`evidence/2026-09-15-privileged-policy-state.md`.

Physical secret-boundary regression addendum: source revision `356ebd4`
passes 598/598 non-overlapping built tests with zero skips and zero failures
under all three physical gates. Real sandbox, temporary Keychain ACL, and
Edge/Broker LaunchAgent bootstrap/bootout checks ran; process ownership tests
now await bounded startup snapshots and verify shutdown cancellation. The old
Broker/Persistence process was left undisturbed. Production signing, VM,
remote issuer, helper installation, and task enablement remain open. Evidence:
`evidence/2026-09-15-real-secret-boundary-regression.md`.

Latest secret-boundary regression addendum: source revision `f921714` passes
598 non-overlapping built tests (592 pass, 6 explicit opt-in skips, 0 fail)
after shared local-process and virtualization guest secret checks. The old
Broker/Persistence process was left undisturbed; production signing,
installation, isolation, and helper gates remain open. Evidence:
`evidence/2026-09-15-secret-boundary-full-regression.md`.

Process environment secret-value addendum: source revision `98b36ac` extends
the shared ProcessSupervisor, TaskProfile, and virtualization guest boundary
to reject known token, credential, and authorization signatures in explicitly
allowlisted environment values before child dispatch; guest task arguments also
reject protected credential options. The focused suites pass 51/51 with
typecheck, lint, and diff checks passing. This is defense-in-depth only;
production credential/process isolation and `mac_task_run` enablement remain
gated by MOP-045/MOP-086.
Evidence: `evidence/2026-09-15-process-environment-secret-values.md`.

Latest regression addendum: the non-overlapping built suite passes 595 total
(589 pass, 6 skipped, 0 fail), including audit-target, credential-field, and
secret-shaped-string redaction coverage; the existing Broker/persistence process was left
undisturbed. Evidence: `evidence/2026-09-15-latest-local-regression.md`.

Persistence integrity rerun addendum: source revision `8077a6d` passes 33/33
focused replay, Approval, authority, configuration, Request, Job,
Request-to-Job, and complete schema-layout invariant tests with no skips or
failures. The existing Broker/persistence process was left undisturbed;
physical crash/remount durability, production Keychain, installed recovery,
external rollback, and independent P0/P1 review remain open. Evidence:
`evidence/2026-09-15-ledger-integrity-rerun.md`.

Physical Darwin full-regression addendum: after rebuilding source revision
`cd62bbc`, the serial non-overlapping package set passes 595/595 with zero
skips and zero failures under all three explicit physical gates. The old
Broker/persistence process was left undisturbed. Persistent production
installation, Developer ID provenance, real isolation, VM isolation, remote
issuer/deployment, and independent P0/P1 review remain open. Evidence:
`evidence/2026-09-15-real-full-regression-rerun.md`.

Test-timeout boundary addendum: source revision `7d99b98` adds a fixed
120-second timeout to each root `npm test` case so verification cannot hang
indefinitely. Lint, typecheck, and the 11-test contracts smoke pass; this
does not alter Broker task budgets or satisfy production crash/isolation,
installed-service, remote, or independent-review gates. Evidence:
`evidence/2026-09-15-test-timeout-boundary.md`.

Release-gate rerun addendum: source revision `7e0cc43` passes 44-contract
verification, 5/5 native canonical vectors, `npm audit --audit-level=high`
with zero vulnerabilities, lint across 611 tracked files, typecheck, and
diff checks. The old Broker/persistence process was left undisturbed; full
suite and production/release gates remain open. Evidence:
`evidence/2026-09-15-release-gate-rerun.md`.

Audit-outage availability decision addendum: BrokerStore now fails closed for
all MCP admissions, including read-only tools, after keyed audit-tail
publication failure; a focused test proves no Request row is created until a
restart with verified tail. The host recovery/readback path remains separate.
Evidence: `evidence/2026-09-15-audit-readonly-fail-closed.md`.

Physical Darwin sandbox addendum: correctly exporting `MOPS_REAL_SANDBOX=1`
to the test processes yields 595 total (593 pass, 2 skipped, 0 fail) on
Darwin arm64/macOS 26.2. Real sandbox, protected-surface, fork/`setsid`,
TCP/UDP allowlist, and active cancellation checks passed; real Keychain ACL
and temporary install gates remain skipped. Evidence:
`evidence/2026-09-15-real-sandbox-regression.md`.

Physical Keychain/install addendum: exporting all physical gates yields
595/595 with 0 skips and 0 failures. Temporary Keychain ACL retirement and
per-user Edge/Broker LaunchAgent bootstrap, authenticated readback, bootout,
and post-test label absence passed. Persistent production installation,
Developer ID provenance, and helper deployment remain open. Evidence:
`evidence/2026-09-15-real-install-keychain-regression.md`.

Audit-evidence redaction addendum: the persistence and privileged-helper
response boundaries now redact common credential and key field aliases and
secret-shaped strings before canonicalization or response publication; focused
alias/content/helper tests pass. This is defense-in-depth only and leaves the
broader secret-corpus, physical isolation, and release gates open. Evidence:
`evidence/2026-09-15-audit-evidence-redaction.md`.

Failure-audit target addendum: commit `3ed2e02` records the normalized target
for post-authorization failure completion rows and keeps pre-authorization
denials bounded as `unresolved`. Focused source assertions and an independent
built harness pass; the long-running Broker/persistence suites were left
undisturbed. Evidence: `evidence/2026-09-15-failure-audit-target.md`.

Schema-startup error and coverage addendum: source revision `183ecd4` gives
malformed persistence migrations a stable `AUDIT_UNAVAILABLE` class and tests
unknown-column rejection across all 29 Broker persistence tables (2/2 schema
tests; 593 total package regression, 587 passed, 6 skipped, 0 failed).
Production crash recovery, signing/Keychain, installed lifecycle, isolation,
disk exhaustion, and independent review remain open. Evidence:
`evidence/2026-09-15-core-schema-layout.md`.

Schema-migration readback addendum: legacy Request and Job database layouts
open successfully under the current BrokerStore, retain historical records,
and pass the complete post-migration schema-layout check at source revision
`a26e6d8`. The temporary host check does not claim production backup restore,
crash recovery, disk exhaustion, or release upgrade/rollback acceptance.
Evidence: `evidence/2026-09-15-schema-migration-readback.md`.

Filesystem-worker result boundary addendum: source revisions `5657267` and
`86a6792` harden every filesystem worker result as plain data with exact
operation-specific fields, dense bounded arrays, and validated nested
records. Storage volume results now explicitly project away the internal
`rootPath` field before crossing the worker boundary, so internal planning
authority cannot be exposed as public result data. Focused filesystem and
contract-conformance tests pass 3/3; the non-overlapping package regression
passes 521 total (515 pass, 6 skipped, 0 fail). This closes local filesystem
result-shape integrity only; native provenance, remount, sandbox, credential,
VM, persistence, and capability enablement evidence remain open.
Evidence: `evidence/2026-09-15-filesystem-worker-result-boundary.md`.

Read-only adapter result-boundary addendum: commits `a9d1b2a` and `e1ae276`
close unstable result-shape paths for network, app inventory, and
Accessibility adapters. Native network records now require plain exact
fields and dense bounded address/listener arrays. JSON app and UI results now
reject unknown fields, non-data records, sparse node arrays, and unstable
nested node shapes before identity or sensitive-content handling. Focused
app/UI/network tests pass 15/15; the non-overlapping package regression passes
523 total (517 pass, 6 skipped, 0 fail). This closes local read-only adapter
result-shape integrity only; native provenance, permission-granted GUI
evidence, sandbox, credential, VM, persistence, and capability enablement
evidence remain open.
Evidence: `evidence/2026-09-15-readonly-adapter-result-boundaries.md`.

Virtualization VM result-boundary addendum: source revision `c22fc98` makes
native guest lifecycle start/stop/status readbacks plain records with the
exact `bootId`, `guestIdentity`, and `state` fields. Accessor, inherited,
symbolic, and unknown result fields fail closed before guest identity or boot
identity comparison. Focused native VM lifecycle tests pass 9/9; the
non-overlapping package regression passes 524 total (518 pass, 6 skipped,
0 fail). This closes local VM readback shape integrity only; native
attestation production, VM isolation, credential/persistence isolation, and
`mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-virtualization-vm-result-boundary.md`.

Persisted Job readback addendum: source revisions `2cc1db7`, `937ffcd`, and
`5f4980d`
make completed app-open, app-focus, UI-action, filesystem-write, and
filesystem-patch Job results exact plain-data records before reuse or
postcondition publication. Nested targets, preconditions, reobservations,
and patch files reject unknown fields; malformed stored data remains
`UNKNOWN_OUTCOME`. Focused persisted-result tests pass 2/2; the
non-overlapping package regression passes 527 total (521 pass, 6 skipped,
0 fail). This closes local stored-result integrity only; SQLite corruption,
crash ownership, disk exhaustion, service recovery, and final release gates
remain open.
Evidence: `evidence/2026-09-15-persisted-job-readbacks.md`.

Process worker executor addendum: source revision `8a9a89c` makes the
WorkerProcessExecutor reuse the strict native process inventory/detail
parsers, including exact fields, plain records, dense bounded collections,
and fresh projection. A sparse inventory or extra/accessor field now fails
closed before the process result reaches Broker handlers. Focused process
executor/inspector tests pass 6/6; the non-overlapping package regression
passes 528 total (522 pass, 6 skipped, 0 fail). Native provenance, process
ownership, kernel limits, and production task enablement evidence remain
open.
Evidence: `evidence/2026-09-15-process-worker-executor-boundary.md`.

Filesystem native-result addendum: source revision `645f57b` makes native
filesystem stat/read/hash/list/write/unlink/storage records exact plain data;
directory entries and buffers are copied, and sparse/accessor/unknown fields
fail closed before path or postcondition checks. Focused filesystem tests
pass 37/37; the non-overlapping package regression passes 530 total (524
pass, 6 skipped, 0 fail). Physical remount, kernel I/O, native provenance,
and production resource evidence remain open.
Evidence: `evidence/2026-09-15-filesystem-native-result-boundary.md`.

Audit-anchor readback addendum: source revision `e54a862` requires the
Broker-owned audit sidecar and native lock-recovery result to be plain records
with exact fields before MAC, tail, or unlink readback checks. Unknown or
accessor authority fields fail closed. Focused audit-anchor tests pass 8/8;
the non-overlapping package regression passes 530 total (524 pass, 6 skipped,
0 fail). SQLite corruption, key provenance, disk exhaustion, and installed
service recovery evidence remain open.
Evidence: `evidence/2026-09-15-audit-anchor-result-boundary.md`.

Docker result-boundary addendum: source revision `50fd2fb` makes Docker CLI
container and image records require plain data, known fields, and unambiguous
identities before projection. Inspection identity aliases now fail closed on
conflict, nested state/config/network/port/mount data is consumed only from
plain bounded shapes, and Docker log parsing caps line count and individual
line bytes before redaction. Focused Docker tests pass 9/9; the
non-overlapping package regression passes 533 total (527 pass, 6 skipped,
0 fail). This closes Docker CLI result-shape and output-budget integrity
only; daemon compatibility, storage readback, isolation, raw-socket negative
coverage, packaging, and capability enablement remain open.
Evidence: `evidence/2026-09-15-docker-result-boundary.md`.

Install-readback boundary addendum: source revision `61e7357` routes macOS
install-plan service, component, existing-service, and signature observations
through the shared plain-data record guard. Inherited, accessor, symbolic, and
non-record readbacks now fail closed before service identity or capability
validation. Focused install-plan tests pass 22/22. This closes local readback
representation integrity only; Developer ID provenance, persistent installed
service lifecycle, production upgrade/rollback, helper execution, and final
capability enablement remain open.
Evidence: `evidence/2026-09-15-install-readback-boundary.md`.

Edge IPC response-boundary addendum: source revision `adddedd` makes the Edge
accept only a plain exact response envelope and a stable Broker success/failure
shape. Unknown envelope/result fields, invalid error classes, oversized
warnings/duration, and accessor-shaped observations fail closed before MCP
publication. Focused Edge IPC tests pass 4/4; Broker correctness, remote
OAuth/JWKS deployment, production key lifecycle, installed provenance, and
capability enablement remain open.
Evidence: `evidence/2026-09-15-edge-ipc-response-boundary.md`.

Persisted process-ownership addendum: source revision `7ad478c` makes native
recovery accept only exact plain root identities, dense bounded descendant
arrays, and the single Broker-owned no-fork proof marker. Inherited/accessor/
unknown persisted fields fail before signalling or observer use. Focused
process-supervisor tests pass 33/33; post-snapshot descendant escapes,
kernel-level termination, credential isolation, production task enablement,
and installed recovery evidence remain open.
Evidence: `evidence/2026-09-15-process-ownership-readback.md`.

Audit-evidence boundary addendum: source revision `fbb197b` restricts audit
evidence projection and recursive redaction to plain records and dense data
arrays. Accessor, inherited, symbolic, and other non-data values are replaced
with a fixed marker before canonical hashing or persistence. Focused audit
evidence tests pass 2/2; SQLite corruption, disk exhaustion, external anchor,
production Keychain, installed recovery, and release acceptance remain open.
Evidence: `evidence/2026-09-15-audit-evidence-boundary.md`.

Process-worker result boundary addendum: source revision `a01b62e` hardens
native process metadata and worker-result parsers. Inventory/detail records
now require plain data and exact fields; owners are bounded uid identities,
child PID arrays are dense and strictly increasing, and worker envelopes
reject unknown fields before consumers can treat a result as successful. The
focused process-inspector/worker suite passes 14/14; the non-overlapping
package regression passes 520 total (514 pass, 6 skipped, 0 fail). This
closes local result-shape integrity only; native identity provenance,
sandbox, credential, VM, persistence, and capability enablement evidence
remain open.
Evidence: `evidence/2026-09-15-process-worker-result-boundary.md`.

Task-profile request snapshot addendum: source revision `04f77eb` snapshots
the validated TaskProfileRegistry request before asynchronous cwd, root, and
executable readback. Profile selection, argument matching, environment and
process construction now use the snapshot, preventing caller mutation during
filesystem awaits from substituting task arguments or targets. The focused
task-profile suite passes 6/6; the non-overlapping package regression passes
518 total (512 pass, 6 skipped, 0 fail). This closes one local task-request
TOCTOU window only; sandbox, credential isolation, VM, persistence, and
`mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-task-profile-request-snapshot.md`.

Guest-request snapshot addendum: source revision `31dc880` snapshots the
authenticated guest task request, including its nested guest identity, before
the registry's asynchronous executable/cwd readback. Ledger keys, adapter
input, budgets, cancellation, response binding, and terminal recovery now use
the snapshot, so caller mutation during target checks cannot change the
admitted task or published result. The focused guest executor suite passes
11/11; the non-overlapping package regression passes 517 total (511 pass,
6 skipped, 0 fail). This closes one local guest-request TOCTOU window only;
native attestation production, VM isolation, credentials, persistence, and
`mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-guest-request-snapshot.md`.

Guest-profile boundary addendum: source revision `5f67e18` hardens the
startup-owned Virtualization guest profile registry and task request parser.
Profiles and requests must be plain records with known fields; executable,
cwd, filesystem-root, argument, network, and environment collections reject
symbolic, inherited, accessor, sparse, and oversized shapes before digest
resolution or target readback. The focused guest executor suite passes 10/10;
the non-overlapping package regression passes 516 total (510 pass, 6 skipped,
0 fail). This closes guest manifest representation integrity only; native
attestation production, VM isolation, credentials, persistence, and
`mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-guest-profile-boundary.md`.

Process-request snapshot addendum: source revision `aa8040e` snapshots the
validated ProcessSupervisor request before the first asynchronous executable
or cwd identity check. The spawn path, capacity keys, environment, callbacks,
and every later stability/revocation check now use that snapshot, so caller
mutation during filesystem awaits cannot substitute a target, argument, or
environment after authorization. The focused process-supervisor,
task-profile, and task-runner suite passes 50/50; the non-overlapping package
regression passes 515 total (509 pass, 6 skipped, 0 fail). Build, typecheck,
lint, and diff checks are required before release. This closes one local
request TOCTOU window only; child sandbox, credential isolation, VM,
persistence, and `mac_task_run` enablement evidence remains open.
Evidence: `evidence/2026-09-15-process-request-snapshot.md`.

Process-request boundary addendum: source revision `78dd404` makes
ProcessSupervisor validate requests as plain data records with an exact
allowlist before any child-process admission. Executable and cwd paths must
be canonical absolute paths; argument arrays are dense bounded string arrays;
environment records reject inherited/accessor authority; limits are safe
bounded integers; and control callbacks must be callable. Unknown fields,
prototype/accessor/symbol/sparse shapes, malformed environments, and invalid
callbacks fail closed before spawning. The focused process-supervisor,
task-profile, and task-runner suite passes 49/49; the non-overlapping package
regression passes 514 total (508 pass, 6 skipped, 0 fail). Build, typecheck,
lint, and diff checks are required before release. This closes local process
request representation integrity only; child sandbox, credential isolation,
VM, persistence, and `mac_task_run` enablement evidence remains open.
Evidence: `evidence/2026-09-15-process-request-boundary.md`.

Task-profile authority-shape addendum: source revision `956e95f` makes named
TaskProfile documents and task-run requests accept only plain data records with
known fields. Path, argument, and network arrays must be dense bounded string
arrays; environment data rejects accessors and inherited fields; resolved
arguments are copied before execution. The focused task-profile/task-runner
suite passes 18/18; the non-overlapping package regression passes 513 total
(507 pass, 6 skipped, 0 fail). Build, typecheck, lint, and diff checks pass.
This closes local task-profile representation integrity only; sandbox,
credential, VM, and `mac_task_run` enablement evidence remains open.
Evidence: `evidence/2026-09-15-task-profile-authority-shape.md`.

Task-runner result-boundary addendum: source revision `0c486c9` applies the
plain-data boundary to host isolation proofs and runner results. Both records
reject inherited/accessor/symbolic fields and unknown keys; result verification
records allow only their declared optional summary, while UTF-8 output and
duration remain bounded before Broker persistence or audit. The focused
task-runner/guest-attestation suite passes 19/19; the non-overlapping package
regression passes 512 total (506 pass, 6 skipped, 0 fail). Build, typecheck,
lint, and diff checks pass. This closes local result-shape integrity only;
production sandbox, credential isolation, VM, and `mac_task_run` gates remain
open.
Evidence: `evidence/2026-09-15-task-runner-result-boundary.md`.

Filesystem mutation rename-race addendum: source revision `e83bf1e` adds a
physical-host atomic-write race harness alongside the read harness. It
repeatedly renames an authorized child directory, replaces it with an outside
symlink, and restores it while bounded writes execute. Successful write
readbacks remain under the canonical authorized root, and the outside file is
unchanged. The focused filesystem suite passes 34/34; the non-overlapping
package regression passes 511 total (505 pass, 6 skipped, 0 fail). Build,
typecheck, lint, and diff checks pass. Physical remount, broader volume, and
production resource-exhaustion evidence remain open.
Evidence: `evidence/2026-09-15-filesystem-mutation-rename-race.md`.

Filesystem directory-rename race addendum: source revision `7fe59fd` adds a
physical-host runtime race test that repeatedly renames an authorized child
directory, replaces it with an outside symlink, and restores it while a
descriptor-relative content read is in flight. Successful reads contain only
the authorized bytes and remain under the canonical authorized root; escape
observations fail closed. The focused filesystem suite passes 33/33; the
non-overlapping package regression passes 510 total (504 pass, 6 skipped,
0 fail). Build, typecheck, lint, and diff checks pass. This adds runtime
directory create/rename evidence but does not close physical remount, broader
volume, or production resource-exhaustion evidence.
Evidence: `evidence/2026-09-15-filesystem-directory-rename-race.md`.

Filesystem root-descriptor addendum: source revision `6fb5372` changes native
metadata/list/read/hash and atomic write/unlink paths to derive traversal-free
relative targets and open them through the already-pinned root descriptor.
Canonical parent aliases are preserved for final-symlink policy, while
`.`/`..`/empty components and lexical escapes fail closed. Filesystem focused
tests pass 32/32; the non-overlapping package regression passes 509 total
(503 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff checks pass.
This closes the absolute-open root rename window but does not close physical
remount, broader volume, or production resource-exhaustion evidence.
Evidence: `evidence/2026-09-15-filesystem-root-descriptor-binding.md`.

System-published guest-image addendum: source revisions `e00554c`, `f74e485`,
and `a08d2a5` add an
explicit image publication mode. Enabled native Virtualization.framework
creation now requires a root-owned, non-symlink image and canonical ancestor
chain with no group/other write bits; the native path also rejects a root
Broker. Broker-owned fixtures remain available for
protocol/test seams but are rejected before native loading. The native C++
preflight repeats this publication check because attachment uses a pathname
after descriptor hashing. Focused image/native suites pass 12/12; the
non-overlapping package regression passes 508 total (502 pass, 6 skipped,
0 fail); build, typecheck, lint, and diff checks pass. This narrows the
unprivileged target-swap window but does not close root rotation, VM boot,
guest isolation, attestation production, or `mac_task_run` enablement.
Evidence: `evidence/2026-09-15-system-published-guest-image.md`.

Nested authenticated-data addendum: source revision `54fe71a` validates
plain-data shapes for helper payloads/results/verification/evidence, Broker
and Helper status readbacks, and nested authority/status failures. Accessors,
hidden, symbolic, and prototype-provided fields fail closed before
canonicalization, redaction, or postcondition checks. Focused authority,
status, and helper suites pass 17/17; the non-overlapping package regression
passes 506 total (500 pass, 6 skipped, 0 fail); build, typecheck, lint, and
diff checks pass. This closes local nested parser integrity only; production
peer, packaging, VM, credential, helper, and enablement gates remain open.
Evidence: `evidence/2026-09-15-nested-authenticated-data.md`.

Guest attestation data-shape addendum: source revision `d276615` requires the
signed guest attestation envelope, payload, and nested identity to be plain
data records before canonical digest and Ed25519 verification. Inherited,
accessor, hidden, and symbolic fields fail closed as `POLICY_DENIED`. The
focused attestation suite passes 6/6; the non-overlapping package regression
passes 505 total (499 pass, 6 skipped, 0 fail); build, typecheck, lint, and
diff checks pass. This protects local provenance parsing only and does not
close native attestation production, private-key distribution, VM isolation,
or task-runner enablement.
Evidence: `evidence/2026-09-15-guest-attestation-data-shapes.md`.

Operator IPC data-shape addendum: source revision `8ed6e298` applies the
shared plain-data-record guard to policy-signer command and approval issuance
parsers, including nested approval payloads. Inherited, accessor, symbolic,
and hidden fields fail closed before signature/digest verification or
persistence. Focused policy-signer and approval suites pass 14/14; the
non-overlapping package regression passes 504 total (498 pass, 6 skipped,
0 fail); build, typecheck, lint, and diff checks pass. This local parser
hardening does not close production key distribution, packaging, VM,
credential, helper, or capability enablement gates.
Evidence: `evidence/2026-09-15-operator-ipc-data-shapes.md`.

Real sandbox readback addendum: source revision `a8b4660` records a fresh
physical-Mac run of the opt-in sandbox suite with 16/16 tests passing and no
skips. It strengthens host evidence for deny-default filesystem/environment,
TCP/UDP loopback, fork/setsid, and cancellation behavior, but does not close
MOP-086/MOP-045 or enable `mac_task_run` because deprecated sandbox-exec,
credential-content, remount, crash/restart, Docker, and production packaging
evidence remain incomplete.
Evidence: `evidence/2026-09-15-real-sandbox-16-tests.md`.

Authenticated IPC data-shape addendum: source revision `27e102b` makes the
Authority Control, Broker Status, Privileged Helper, and guest transport
parsers accept only plain data records at their authenticated boundaries.
Focused IPC tests pass 32/32; the non-overlapping package regression passes
502 total (496 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff
checks pass. This local hardening does not close OS peer identity, production
packaging, VM, credential, helper, or enablement gates.
Evidence: `evidence/2026-09-15-authenticated-ipc-data-shapes.md`.

Signed request data-shape addendum: source revision `14d3cc0` validates the
complete request as a bounded JSON-shaped tree of ordinary or null-prototype
data records and dense arrays. Hidden/accessor/inherited fields, cycles, and
unsupported nested values cannot escape the canonical signed payload boundary.
Security-fuzz tests pass 8/8; the non-overlapping package regression passes
498 total (492 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff
checks pass. This remains local parser hardening and does not close production
transport, VM, credential, helper, or enablement gates.
Evidence: `evidence/2026-09-15-request-data-shape.md`.

Request object authority-boundary addendum: source revision `8a8f335` limits
the Broker request envelope, arguments, and principal to ordinary or
null-prototype records, preventing inherited fields from escaping the signed
payload boundary. Security-fuzz tests pass 8/8; the non-overlapping package
regression passes 498 total (492 pass, 6 skipped, 0 fail); build, typecheck,
lint, and diff checks pass. This is local parser hardening only and does not
close production transport, VM, credential, helper, or enablement gates.
Evidence: `evidence/2026-09-15-request-object-authority-boundary.md`.

Policy prototype authority-boundary addendum: source revision `b164da0`
restricts runtime policy records to ordinary or null-prototype objects, so
inherited fields cannot become Broker authority. Policy tests pass 4/4, the
security-fuzz policy corpus passes 7/7, and the non-overlapping package
regression passes 497 total (491 pass, 6 skipped, 0 fail); build, typecheck,
lint, and diff checks pass. This is a local validation boundary only and does
not establish production signing, Keychain, VM, helper, or enablement gates.
Evidence: `evidence/2026-09-15-policy-prototype-authority-boundary.md`.

Guest executor close-recovery addendum: source revision `3245482` always drains
active guest work after cancellation, preserves the first adapter cleanup
failure, and permits explicit cleanup retry without reopening execution. The
focused guest executor suite passes 10/10 and the non-overlapping package
regression passes 496 total (490 pass, 6 skipped, 0 fail); build, typecheck,
lint, and diff checks pass. VM boot/isolation, attestation production,
credential isolation, and production task enablement remain open. Evidence:
`evidence/2026-09-15-guest-executor-close-recovery.md`.

Broker shutdown recovery addendum: source revision `505d28a` leaves the Broker
permanently fenced against new work while allowing an explicit retry after a
resource close failure. The Broker close regression passes, the
non-overlapping package regression passes 495 total (489 pass, 6 skipped, 0
fail), and build, typecheck, lint, and diff checks pass. This does not prove
installed launchd recovery or any VM, credential, helper, or production
capability gate. Evidence: `evidence/2026-09-15-broker-close-recovery.md`.

Virtualization guest attestation key-validity addendum: source revision
`5aa7d2e` binds `issuedAtMs` and `expiresAtMs` to the configured signing-key
validity window. The focused attestation suite passes 5/5 and the
non-overlapping package regression passes 495 total (489 pass, 6 skipped, 0
fail); build, typecheck, lint, and diff checks pass. This does not establish a
native attestation producer, protected private-key distribution, VM boot or
guest isolation, or production task-runner enablement. Evidence:
`evidence/2026-09-15-virtualization-guest-attestation-key-validity.md`.

Virtualization guest runtime close-recovery addendum: source revisions
`d68176b` and `28007cf` leave the runtime retryable after a failed shutdown and
mark it closed only after every shutdown step succeeds. While an explicit
close retry is pending, new start/stop operations are fenced and lifecycle
status recovery remains available. The focused startup suite passes 3/3 and
the non-overlapping package regression passes 494 total (488 pass, 6 skipped,
0 fail); build, typecheck, lint, and diff checks pass. This does not close the
VM boot, guest isolation, credential/process isolation, signing, or production
task-runner gates. Evidence:
`evidence/2026-09-15-virtualization-guest-runtime-close-recovery.md`.

Darwin descriptor-exec boundary addendum: the physical host probe records no
public `fexecve`/`execveat` declaration or executable-fd `posix_spawn` API, and
direct `/dev/fd/N` execution fails with permission denied (status 126). No
pathname shim is accepted as fexec evidence. Descriptor/fexec or an immutable
Broker-owned snapshot with code-signing proof remains required for `VT-FS-02`;
the existing ProcessSupervisor path revalidation is compensating control only.
Evidence: `evidence/2026-09-15-darwin-descriptor-exec-boundary.md`.

Process argv false-positive addendum: source revision `7231964` applies
sensitive option-name checks only to explicit Unix options and keeps concrete
token/credential signature checks on every argument. Real-Darwin sandbox tests
pass 16/16 after the canary regression was fixed; focused process/secret tests
pass 35/35 and the non-overlapping package regression passes 494 total (488
pass, 6 skipped, 0 fail). Build, typecheck, lint, and diff checks pass. This
does not close opaque secret classification or production credential/process
isolation. Evidence: `evidence/2026-09-15-secret-argv-script-boundary.md`.

Capability-list integrity addendum: source revision `399a17c` makes Edge
capability parsing fail closed on duplicate or unregistered tool names and
malformed name/version fields. The non-overlapping package regression passes
494 total (488 pass, 6 skipped, 0 fail); Edge tests, contract validation,
build, typecheck, lint, and diff checks pass. Capability enablement is
unchanged and production host/VM/credential/privileged evidence remains open.
Evidence: `evidence/2026-09-15-capability-list-integrity.md`.

Capability lifecycle-state addendum: source revision `e22f025` exposes the
Broker-owned `planned`, `implemented`, and `enabled` fields in every
`mac_capabilities` item, requires them in the versioned contract, and makes
the Edge reject an enabled item unless all three authority states are true.
Focused Broker/Edge tests and the non-overlapping package regression pass 493
total (487 pass, 6 skipped, 0 fail); contract validation, build, typecheck,
lint, and diff checks pass. This does not change enablement and leaves production host,
VM, credential-isolation, and privileged-helper evidence gates open. Evidence:
`evidence/2026-09-15-capability-lifecycle-states.md`.

Worker startup-failure addendum: `BoundedWorkerExecutor` catches synchronous
worker-factory failures and returns the stable `EXECUTION_FAILED` class while
leaving capacity unchanged. Worker-executor tests pass 8/8; the non-overlapping
package regression passes 492 total (486 pass, 6 skipped, 0 fail); build,
typecheck, lint, and diff checks pass. This is a bounded error-normalization fix; worker
sandboxing, credential/process isolation, and production task enablement
remain governed by the existing MOP-045/MOP-086 gates. Evidence:
`evidence/2026-09-15-worker-startup-failure-boundary.md`.

Edge JWKS response-status addendum: source revision `fc04641` rejects any
non-2xx remote JWKS response before body handling or key parsing. JWT tests
pass 8/8, all Edge tests pass 41/41, and the non-overlapping physical-Darwin
regression passes 491 total (485 pass, 6 skipped, 0 fail). Build, typecheck,
lint, and diff checks pass. This closes response-status interpretation only;
external issuer and deployment evidence remain open. Evidence:
`evidence/2026-09-15-edge-jwks-status-boundary.md`.

Edge JWKS redirect-boundary addendum: source revision `c97140a` rejects
redirected remote responses and any non-empty final URL that differs from the
startup-configured JWKS endpoint. JWT tests pass 7/7, all Edge tests pass
40/40, and the non-overlapping physical-Darwin regression passes 490/490 with
0 skipped tests. Build, typecheck, lint, and diff checks pass. This closes
endpoint-identity handling only; external issuer and deployment evidence
remain open. Evidence:
`evidence/2026-09-15-edge-jwks-redirect-boundary.md`.

Process-argument secret-boundary addendum: source revision `17d10e2` rejects
credential-bearing option names and known token signatures in fixed profile
arguments, combined task arguments, and the final `ProcessSupervisor` spawn
boundary. Secret-policy tests pass 5/5, task-profile tests pass 4/4,
process-supervisor tests pass 30/30, and the non-overlapping physical-Darwin
regression passes 489/489 with 0 skipped tests. Build, typecheck, lint,
contract, canonical-JSON, audit, and diff checks pass. Arbitrary opaque
strings, sandbox isolation, and Broker-managed credential workflows remain
separate boundaries. Evidence:
`evidence/2026-09-15-process-argument-secret-boundary.md`.

Edge remote-JWKS response addendum: source revision `3cca22c` wraps every
remote JWKS fetch with an Edge-owned 256 KiB streaming body cap and strict JSON
MIME check before `jose` parses key material; invalid or oversized responses
fail closed as invalid tokens. JWT tests pass 6/6, all Edge tests pass 39/39,
and the non-overlapping physical-Darwin regression passes 488/488 with 0
skipped tests. Build, typecheck, lint, contract, canonical-JSON, audit, and
diff checks pass. External issuer deployment, certificate-chain proof,
rotation/revocation propagation, and remote production hosting remain open.
Evidence: `evidence/2026-09-15-edge-jwks-response-boundary.md`.

Virtualization lifecycle timeout-fence addendum: source revision `ea85237`
retains a timed-out or cancelled native VM operation until its promise settles;
later status or transition calls fail closed with retryable `UNKNOWN_OUTCOME`
instead of overlapping an unknown mutation. Lifecycle tests pass 7/7; the
focused guest/transport/lifecycle/startup/native/task-runner suite passes
86/86; and the non-overlapping physical-Darwin regression passes 486/486 with
0 skipped tests. Build, typecheck, lint, and diff checks pass. VM boot,
guest isolation, descriptor/fexec, remount resistance, production isolation,
and `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-lifecycle-timeout-fence.md`.

Process-supervisor early-capture addendum: source revision `efb9d5c` installs
bounded stdout/stderr and exit/close capture immediately after child spawn,
before asynchronous path and ownership checks, preventing short-lived child
events from being lost. Process-supervisor tests pass 30/30; the physical-
Darwin regression over non-overlapping test files passes 485/485 with 0
skipped tests. Build, typecheck, lint, and diff checks pass. Descriptor/fexec,
remount, production isolation, and `mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-process-supervisor-early-capture.md`.

Guest-executor close-drain addendum: source revision `9f772fe` tracks active
adapter promises and makes executor close abort, invoke the adapter close hook,
and await all active executions before returning. Guest executor tests pass
8/8; the combined guest/transport/lifecycle/startup/native focused suite passes
53/53 with 0 skipped tests. Build, typecheck, lint, and diff checks pass. VM
boot, guest isolation, and production `mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-virtualization-guest-close-drain.md`.

Guest-executor admission-concurrency addendum: source revision `eb9aa47`
reserves a slot before asynchronous manifest readback and enforces
`active + inFlight <= maxConcurrent`, preventing concurrent admissions from
oversubscribing guest process capacity. Guest executor tests pass 8/8; the
combined guest/transport/lifecycle/startup/native focused suite passes 53/53
with 0 skipped tests. Build, typecheck, lint, and diff checks pass. VM boot,
guest isolation, and production `mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-virtualization-guest-concurrency.md`.

Guest-bootstrap timeout-cancellation addendum: source revision `9148013`
propagates connection deadline and transport failure into the per-connection
guest executor before stream close, so timed-out work cannot continue after
rejection. Bootstrap tests pass 6/6; the combined guest/transport/lifecycle/
startup/native focused suite passes 52/52 with 0 skipped tests. Build,
typecheck, lint, and diff checks pass. VM boot, guest isolation, and
production `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-bootstrap-timeout.md`.

Task-profile startup-wiring addendum: the explicit host startup seam now
requires a validated `TaskProfileRegistry` whenever an isolated task runner
is configured, injects it into the Broker, and rejects malformed or runnerless
registry configuration. The default packaged assembly keeps an empty registry
and fail-closed task runner. A gated physical-Darwin smoke now executes one
fixed profile through startup, native UDS, approval, sandbox, and Job readback;
an approved read of the protected Broker database is denied with
`VERIFICATION_FAILED` and a failed Job. Production profile enablement remains
evidence-gated. Evidence:
`evidence/2026-09-15-task-profile-startup-wiring.md`.

Task-profile regex-safety addendum: source revision `c42c7a8` bounds
host-owned argument patterns to a short anchored fragment without grouping,
alternation, or backreferences before compiling JavaScript `RegExp`; nested,
unbounded-range, and oversized inputs fail closed, closing a profile-
configuration denial-of-service surface. Task-profile tests pass 4/4. This
does not close descriptor/fexec, remount, production sandbox, or task
enablement evidence.
Evidence: `evidence/2026-09-15-task-profile-regex-safety.md`.

Sandbox startup-wiring addendum: source revision `2e605ea` adds an explicit
host-only `sandboxTaskRunner` startup seam. It automatically protects the
validated package, data, and runtime roots, rejects simultaneous sandbox and
virtualization runner configuration, and injects the selected runner into the
Broker without accepting MCP or ambient-environment authority. Service-startup
tests pass 5/5 and sandbox tests pass 16/16. The packaged default still uses
the fail-closed runner; production evidence and `mac_task_run` enablement
remain blocked. Evidence:
`evidence/2026-09-15-sandbox-startup-wiring.md`.

Sandbox UDP addendum: source revision `02fec55` adds a physical-Darwin
loopback UDP regression. A Broker-rendered `udp://localhost:port` allowlist
delivers a datagram only to the listed port; an unlisted loopback port fails
without delivery. The sandbox suite passes 16/16 and the complete serial
physical-Darwin suite passes 607/607 with 0 skipped tests. External networking,
DNS policy, and production task-runner enablement remain open. Evidence:
`evidence/2026-09-15-sandbox-udp.md`.

Sandbox protected-root addendum: source revision `5fb0f3a` adds a bounded,
Broker-owned list of canonical protected filesystem roots to the Seatbelt
renderer and `SandboxExecTaskRunner`. Read/write deny rules are emitted after
task allow rules, so a persistence-shaped root remains inaccessible even when
it overlaps an allowed task root. A real-Darwin regression verifies denial of
`broker-persistence/ledger.sqlite` while ordinary task writes still succeed;
the complete serial physical-Darwin suite passes 606/606 with 0 skipped tests.
This is now available through an explicit host startup seam, while the
packaged default remains fail-closed; mount-namespace and remount resistance,
and full credential/Docker isolation remain open.
Evidence: `evidence/2026-09-15-sandbox-protected-roots.md`.

Executable-content identity addendum: source revision `a0e62e2` extends the
Broker-owned executable identity snapshot from device/inode/mode and ordinary
metadata to a bounded SHA-256 content digest read through an `O_NOFOLLOW`
descriptor. ProcessSupervisor rechecks the digest after spawn and awaited
startup ownership capture; SandboxExecTaskRunner repeats the check on final
readback. Directory identities remain device/inode/mode-only so legitimate
task writes do not look like cwd replacement. Physical-Darwin regressions
rewrite an executable in place at the same path/inode and verify digest
readback; the complete serial physical-Darwin suite passes 606/606 with 0
skipped tests. Descriptor/fexec atomicity, post-read mutation windows, and
remount resistance remain open. Evidence:
`evidence/2026-09-15-process-executable-content-identity.md`.

Sandbox-root identity addendum: source revision `f562bc2` binds every
Broker-owned task filesystem root to a device/inode/mode snapshot, with
startup and post-execution rechecks alongside the existing volume identity
guard. A physical-Darwin regression replaces a non-cwd allowed root and
rejects the synthetic success; the complete suite passes 604/604 with
0 skipped tests. This closes root-path swap detection only; atomic descriptor
execution and in-syscall remount resistance remain open. Evidence:
`evidence/2026-09-15-sandbox-root-identity.md`.

Sandbox-task path addendum: source revision `2599502` extends process identity
binding into `SandboxExecTaskRunner`, covering the profile's actual executable
and cwd in addition to the outer `sandbox-exec` process. Device/inode/mode
readback runs before dispatch, through awaited startup ownership capture, and
after execution; a real Darwin regression rejects an executable replaced
after authorization. The complete physical-Darwin suite passes 603/603 with
0 skipped tests. This is startup swap detection only; descriptor/fexec
atomicity remains open. Evidence:
`evidence/2026-09-15-sandbox-task-path-identity.md`.

Process-path identity addendum: source revision `5efe002` binds process
execution to canonical executable/cwd device, inode, and mode readback before
spawn, after spawn, and after startup ownership capture. The physical-Darwin
target-swap regression rejects a replaced executable and verifies cleanup;
the complete physical-Darwin regression passes 602/602 with 0 skipped tests.
This closes the implemented startup swap-detection boundary only; an atomic
kernel descriptor/fexec proof remains a later hardening item. Evidence:
`evidence/2026-09-15-process-path-identity.md`.

Policy-helper gate addendum: source revision `21559e7` routes principal
projection, target authorization, family kill-switch checks, and capability
discovery through the complete Broker policy validator before use. Security
fuzz policy mutations now exercise full policy shapes; the complete physical-
Darwin regression passes 601/601 with 0 skipped tests. This closes the
helper-entry policy gate only; broader release evidence remains open. Evidence:
`evidence/2026-09-15-policy-helper-gate.md`.

Runtime-policy semantic-validation addendum: source revision `83a733e`
extends the Broker final-authority gate to policy metadata, trusted-key
windows, principal grants, target rules, filesystem roots, kill switches, and
target references. It rejects unknown fields, malformed identities, scope
projection outside a grant, duplicate IDs, wildcard/path escapes, and invalid
root deny paths before authorization. The complete physical-Darwin regression
passes 601/601 with 0 skipped tests. This closes only the in-memory policy
semantic boundary; broader release gates remain open. Evidence:
`evidence/2026-09-15-runtime-policy-semantics.md`.

Runtime-policy snapshot addendum: source revision `0be82c4` deep-copies
BrokerPolicy authority at plain Broker construction and PolicyManager
activation/restore/rollback/current readback. Retained caller references to
target rules, principal grants, kill switches, filesystem roots, or ToolPolicy
entries cannot mutate active authorization after the trust-boundary handoff.
Focused Broker/policy selection passes 82 tests (76 passed, 6 explicit
platform skips); the complete physical-Darwin regression passes 601/601 with
0 skipped tests. This closes the mutable-policy-reference boundary only;
broader release gates remain open. Evidence:
`evidence/2026-09-15-policy-authority-snapshot.md`.

Runtime-policy validation addendum: source revision `ee994a8` makes the
Broker final authority fail closed when its in-memory policy or any ToolPolicy
entry is malformed. Validation is repeated at PolicyManager transitions and
authorization, so post-construction Map mutation cannot expand capability
advertising or execution. It covers contract version, known tool identity,
independent scopes and capability families, target/approval types, bounded
budgets, and implemented/enabled consistency. Policy and PolicyManager tests
pass 17/17; the complete physical-Darwin regression passes 600/600 with
0 skipped tests. This closes the runtime policy-shape boundary only; broader
release gates and host evidence remain open. Evidence:
`evidence/2026-09-15-runtime-policy-validation.md`.

Strict UTF-8 boundary addendum: source revision `1ce5bee` makes implemented
JSON protocol and protected configuration readers use fatal UTF-8 decoding.
Malformed bytes fail closed before JSON parsing or replay admission, including
Broker IPC, owner channels, helper, Keychain, guest, persistence, audit, and
Edge contract/configuration paths. Focused boundary tests pass 78/78, the
native canonical JSON probe passes 5/5 vectors, and the complete physical-
Darwin regression passes 587/587 with 0 skipped tests. This closes malformed
encoding handling only; full numeric canonicalization compatibility,
duplicate-key handling, and release acceptance remain open. Evidence:
`evidence/2026-09-15-strict-utf8-boundary.md`.

Strict JSON parser addendum: source revision `ecc3a98` adds bounded recursive
validation before `JSON.parse` at implemented trust boundaries. Duplicate
object keys (including escaped equivalents), unpaired UTF-16 surrogates,
malformed grammar, and trailing data now fail closed without replay admission
or mutation. Focused trust-boundary tests pass 49/49, the native canonical
JSON probe passes 5/5 vectors, and the complete physical-Darwin regression
passes 588/588 with 0 skipped tests. This closes duplicate-key and lone-
surrogate parser divergence; broader numeric canonicalization, runtime fuzzing,
and release acceptance remain open. Evidence:
`evidence/2026-09-15-strict-json-parser.md`.

Runtime strict-JSON addendum: source revision `0bcb354` routes implemented
child-adapter, Authority Control IPC, stored-result, Job metadata, audit, and
encrypted-backup evidence readers through `parseJsonStrict` before validation
or canonical hashing. Static schema loading and parser internals remain
separate trusted implementation inputs. Targeted runtime-reader tests pass
79/79; the complete physical-Darwin regression passes 592/592 with 0 skipped
tests. This closes runtime parser divergence at these readers only; broader
numeric canonicalization, fuzzing, and release acceptance remain open.
Evidence: `evidence/2026-09-15-runtime-strict-json-boundaries.md`.

Cross-runtime number addendum: source revision `c31f82a` compares each strict
JSON number token's lexical canonical form with Node's ECMAScript
`JSON.stringify` output. Precision-changing, underflowing, overflowing, and
oversized-exponent values fail closed before authentication or persistence.
Focused canonical JSON tests pass 5/5 and the complete physical-Darwin suite
passes 593/593 with 0 skipped tests. This closes the implemented numeric input
boundary; broader independent native vector coverage and release acceptance
remain open. Evidence:
`evidence/2026-09-15-cross-runtime-json-number-canonicalization.md`.

Capability-family capacity addendum: source revisions `db129b3`, `0b7d3b9`, `d7c4689`, and `8ad120b` persist the
Broker-resolved capability families on each request and enforces independent
durable active-request quotas for read, write, process, network, GUI,
destructive, and privileged work inside the SQLite admission transaction.
Cross-handle tests prove that one saturated family does not block another;
unknown legacy markers are counted against every requested family and
malformed markers return `AUDIT_UNAVAILABLE` before replay persistence, even
for a family-less request. Focused Broker/persistence tests pass 123/123 with
6 explicit skips; the complete physical-Darwin suite passes 597/597 with 0
skipped tests, and RequestRecord/ledger-schema readback exposes the resolved
family list, including fail-closed malformed readback. This closes
the durable family-capacity boundary only; adapter-specific semantic quotas,
kernel/disk/depth limits, and release acceptance remain open. Evidence:
`evidence/2026-09-15-capability-family-capacity.md`.

Durable request-capacity addendum: source revision `31e89f0` adds a durable
global and principal/session admission gate inside the SQLite write
transaction. Default caps are global 64 and per principal/session 8, with
hard maxima 256/64. Saturation fails with retryable `CONFLICT` before nonce or
request persistence; terminal and restart reconciliation release capacity.
Cross-handle tests prove this boundary. Full physical-Darwin regression passes
589/589 with 0 skipped tests. This closes only durable request admission
capacity; process/adapter-specific quotas, disk/depth budgets, and release
acceptance remain open. Evidence:
`evidence/2026-09-15-durable-request-capacity.md`.

Process-quota addendum: source revision `a135396` adds a Broker-owned
per-executable admission gate to the shared ProcessSupervisor. Active and
pending starts for one canonical executable share a default cap of 4, while
the Broker-wide pool remains bounded at 16. Focused ProcessSupervisor tests
pass 26/26; the complete physical-Darwin regression passes 592/592 with 0
skipped tests. This closes the shared per-executable process quota only;
adapter-specific semantic quotas, disk/depth budgets, and release acceptance
remain open. Evidence: `evidence/2026-09-15-process-quota-isolation.md`.

Broker session-concurrency addendum: source revisions `d185f12` and `9d92f0d` add bounded
request-age/clock-skew constructor validation and an in-process active-request
cap per authenticated principal/session (default 8, maximum 64). A saturated
session receives retryable `CONFLICT` before request persistence or audit, and
capacity is released on success or failure. Broker focused tests pass 78/78;
the native canonical JSON probe passes 5/5 vectors; the complete
physical-Darwin regression passes 585/585 with 0 skipped tests.
This closes only the local Broker budget boundary; cross-process quotas,
installed service packaging, and release acceptance remain open. Evidence:
`evidence/2026-09-15-broker-session-concurrency.md`.

Approval TTL-gate addendum: source revision `0ab3fc9` rejects a signed Approval
whose TTL has already elapsed before Approval or audit persistence. Approval
Authority/IPC tests pass 10/10 and the complete physical-Darwin regression
passes 583/583 with 0 skipped tests. This closes only source-level Approval
expiry admission; human approval UI, protected production issuer-key storage,
and unattended profile ownership remain open. Evidence:
`evidence/2026-09-15-approval-ttl-gate.md`.

Task isolation proof addendum: source revision `7a101d9` adds a required
`persistence: "isolated"` field to the Broker-owned `TaskIsolationProof` and
rejects missing or non-isolated claims before runner availability. Proof and
guest-startup fixtures pass, and the complete physical-Darwin regression
passes 582/582 with 0 skipped tests. This strengthens the contract only;
real persistence/credential/VM isolation evidence and `mac_task_run`
enablement remain blocked. Evidence:
`evidence/2026-09-15-task-persistence-proof.md`.

Approval issuance expiry-gate addendum: source revision `8552210` rejects a
current-expired signed Approval issuance nonce before persistence or audit.
Approval Authority/IPC tests pass 9/9 and the complete physical-Darwin
regression passes 582/582 with 0 skipped tests. This closes only the
source-level current-clock nonce boundary; human approval UI, protected
production issuer-key storage, and unattended profile ownership remain open.
Evidence: `evidence/2026-09-15-approval-expiry-gate.md`.

IPC expiry-gate addendum: source revision `6947608` rejects current-expired
Privileged Helper command/status requests before replay, authorization,
dispatch, or readback, and rejects current-expired Policy Signer nonces before
manager mutation. Focused Helper tests pass 9/9 and Policy Signer tests pass
2/2; the complete physical-Darwin regression passes 581/581 with 0 skipped
tests. This closes only source-level current-clock expiry admission; installed
helper provenance, production key distribution, and real privileged execution
remain open. Evidence: `evidence/2026-09-15-ipc-expiry-gates.md`.

Broker Status IPC error-proof addendum: source revision `ad3adc9` binds
structurally valid status requests to authenticated `AUTH_EXPIRED` and
`REPLAY_DENIED` failure responses before freshness/auth checks. Unknown fields
remain on the invalid-request fallback, and the candidate never reaches replay
admission or status execution. The focused Broker Status IPC test passes 1/1;
the complete physical-Darwin regression passes 581/581 with 0 skipped tests.
Evidence: `evidence/2026-09-15-broker-status-error-proof.md`.

Authority Control CLI and IPC error-proof addendum: source revisions
`447e4aa`, `f359360`, `5962efc`, and `032bf8f` add a
source-level `mac-operator-authority` entrypoint that exposes only bounded
switch readback, expected-state switch
changes, and identity revocation. It requires canonical protected paths,
restores the persisted active key through `AuthorityControlKeyManager`, uses
explicit mutation confirmation, and verifies mutations by authenticated
readback; guest-attestation key revocation is included. Focused tests pass
4/4, including a protected-file/authenticated-IPC round trip. Authority
Control IPC tests pass 3/3, including stable authenticated `AUTH_EXPIRED`
readback without admission, audit, or mutation side effects; the complete
physical-Darwin regression passes 581/581 with 0 skipped tests. Installed
launchd ownership, active process-tree termination, and
production operator-key distribution remain open. Evidence:
`evidence/2026-09-15-authority-control-cli.md`.

Privileged helper command-factory disposal addendum: the Broker-owned helper
command factory now owns a one-way disposal boundary, wipes its copied HMAC
key once, and fails closed with `CANCELLED` on every later command issuance;
repeated disposal is harmless. Focused privileged-helper tests pass 9/9 and
the complete physical-Darwin regression passes 576/576 with 0 skipped tests.
This closes factory key lifetime only; production operator-key distribution,
root helper installation, real privileged execution, and deployed kill-switch
readback remain open. Evidence:
`evidence/2026-09-15-privileged-helper-factory-disposal.md`.

Virtualization guest active-I/O drain addendum: the Native VM lifecycle now
tracks Broker-owned Virtio exchanges and closes them before stop/close. Late
connection callbacks observe the atomic closed state and close immediately;
tracked Objective-C references are released only after set removal. Native
build and focused VM-native tests pass 7/7; the complete physical-Darwin
regression passes 576/576 with 0 skipped tests. This strengthens active-work
shutdown but does not prove VM boot, guest isolation, attestation, or
`mac_task_run` enablement. Evidence:
`evidence/2026-09-15-virtualization-native-connection-drain.md`.

Virtualization guest native-handle fencing addendum: the Native
Virtualization.framework lifecycle no longer resurrects a closed handle when
retained async work completes. Its validity marker is atomic, and the serial
queue remains available until finalization so delayed callbacks fail closed
instead of dispatching through a null queue. Native build and focused
VM-native tests pass 7/7; the complete physical-Darwin regression passes
576/576 with 0 skipped tests. VM boot, guest isolation, production
attestation, and `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-native-handle-fencing.md`.

Local IPC shutdown-drain addendum: all Node owner-only/local UDS servers now
own an accepted-socket set and destroy those sockets before waiting for server
close, preventing idle peers from extending shutdown to the read timeout.
Cross-channel IPC tests pass 29/29 and the complete physical-Darwin regression
passes 575/575 with 0 skipped tests. Evidence:
`evidence/2026-09-15-local-ipc-shutdown-drain.md`.

Broker IPC framing addendum: the authenticated Broker socket rejects
non-whitespace trailing data before JSON parsing or request admission; the
same signed request retries successfully, so no replay or audit state is
consumed by the rejected frame. Focused Broker IPC tests pass 6/6 and the
complete physical-Darwin regression passes 574/574 with 0 skipped tests.
Evidence: `evidence/2026-09-15-local-ipc-framing-hardening.md`.

Approval IPC framing addendum: the owner-only approval channel enforces one
authenticated newline-delimited frame and rejects non-whitespace trailing data
before replay admission, approval persistence, or audit. A clean retry of the
same signed issuance succeeds after the rejection. Focused approval tests pass
8/8 and the complete physical-Darwin regression passes 574/574 with 0 skipped
tests. Evidence: `evidence/2026-09-15-local-ipc-framing-hardening.md`.

Approval issuer key lifecycle addendum: the Broker-owned approval authority
now wipes its defensive issuer HMAC-key copies on idempotent disposal and
fails closed on all later issuance or key addition. Approval authority and
owner-only IPC tests pass 8/8; build and diff checks pass. Evidence:
`evidence/2026-09-15-approval-key-lifecycle.md`.

Authority-control key lifecycle addendum: the Authority Control client owns a
copied HMAC key, wipes it on explicit disposal, and fails closed on all later
requests. Authority Control and Privileged Helper server cleanup now wipes
copied keys even if socket detachment raises. Focused Authority Control tests
pass 2/2, Privileged Helper IPC tests pass 9/9, and the complete
physical-Darwin regression passes 573/573 with 0 skipped tests. Evidence:
`evidence/2026-09-15-authority-control-key-lifecycle.md`.

Local IPC framing hardening addendum: Privileged Helper, Policy Signer, and
Broker Status channels now enforce one authenticated frame and reject
non-whitespace trailing data before replay or side effects; clients reject
trailing response frames, and the Policy Signer wipes its copied HMAC key on
close. The complete physical-Darwin regression passes
573/573 with 0 skipped tests. Evidence:
`evidence/2026-09-15-local-ipc-framing-hardening.md`.

Capability kill-switch readback addendum: capability discovery now reflects
both persisted runtime and signed-policy family kill-switches. Enabled
process capabilities become `disabled_by_kill_switch` when the process family
is disabled, and the regression covers both authority sources. The complete
physical-Darwin regression passes 572/572 with 0 skipped tests. Evidence:
`evidence/2026-09-15-capability-kill-switch-readback.md`.

Authority-control framing addendum: the owner-only IPC rejects non-whitespace
trailing bytes after its one newline-delimited command and performs no replay
admission, authority mutation, or audit for that frame. Focused IPC tests pass
2/2; the full physical-Darwin regression passes 571/571 with 0 skipped tests.
Evidence: `evidence/2026-09-15-authority-control-framing.md`.

Authority-control restart readback addendum: the owner-only IPC now has a
cross-restart regression that reads back persisted switch and revocation state
through a fresh authenticated client and confirms replay denial remains in
force. Focused IPC tests pass 2/2; the full physical-Darwin regression passes
571/571 with 0 skipped tests. Installed operator identity, active process
termination, and safe re-enable procedures remain open. Evidence:
`evidence/2026-09-15-authority-control-restart-readback.md`.

Guest transport shutdown hardening addendum: the host transport client tracks
active exchanges, aborts them on close, and rejects post-close sends or signed
success publication. Focused transport tests pass 15/15; the full
physical-Darwin regression passes 571/571 with 0 skipped tests. Evidence:
`evidence/2026-09-15-virtualization-guest-transport-close.md`.

Guest-agent shutdown hardening addendum: the guest protocol service now tracks
each admitted request with a Broker-owned abort controller, propagates caller
cancellation, aborts active work on close, and refuses to sign a success after
shutdown. Focused guest-agent tests pass 4/4; the full physical-Darwin
regression passes 571/571 with 0 skipped tests. This is protocol shutdown
evidence only; VM boot, guest isolation, and `mac_task_run` enablement remain
open. Evidence: `evidence/2026-09-15-virtualization-guest-agent.md`.

Guest bootstrap addendum: `VirtualizationGuestBootstrap` adds a disabled-by-
default, transport-independent guest protocol loop. It accepts a native
startup-owned connection source, admits exactly one bounded length-prefixed
frame, delegates to the authenticated guest agent, writes one bounded response,
rejects trailing data, and closes streams and key material deterministically.
Focused bootstrap tests pass 5/5; the full physical-Darwin regression passes
560/560 with 0 skipped tests. AF_VSOCK acceptance, bootable image, isolation,
attestation production, and `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-bootstrap.md`.

Virtio listener addendum: the native lifecycle artifact now provides a
startup-owned fixed-port `VZVirtioSocketListener` with bounded queued accepts,
finite asynchronous chunk I/O, connection-handle lifetime fencing, and
deterministic listener/VM draining. The TypeScript wrapper exposes the
transport-independent bootstrap source and cleans up a late connection after
accept cancellation. Focused VM/listener tests pass 6/6; the full
physical-Darwin regression passes 562/562 with 0 skipped tests. Guest-side
AF_VSOCK serving, bootable image, guest profile execution/isolation, attestation
production, and `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-vsock-listener.md`.

Guest profile executor addendum: a startup-owned Guest manifest registry now
recomputes profile/task digests, denies shell executables and unsafe
environment entries, rechecks canonical targets, and passes only fixed
manifest material to a bounded process adapter. Terminal outcomes are kept in
a bounded status ledger with stable redacted summaries; active work is
cancelled before executor close can publish success; the concrete process
adapter remains evidence-gated. The host Broker redacts runner verification
summaries before publishing task success. Focused guest-executor tests pass 7/7; the
full physical-Darwin regression passes 569/569 with 0 skipped tests. Guest
isolation evidence, bootable image deployment, and `mac_task_run` enablement
remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-executor.md`.

Startup composition addendum: an optional startup-only factory now wires the
native guest VM, serialized lifecycle, fixed virtio channel, optional
guest-initiated listener source, HMAC transport, durable replay guard, and
virtualization task runner into Broker service
startup. It validates the immutable image before construction, starts an
enabled guest before restart recovery, and drains it before store close. The
default path remains disabled and fail closed. Focused startup tests pass 3/3;
the full physical-Darwin regression passes 555/555 with 0 skipped tests. This
does not close the bootable-image, guest-serving, isolation, attestation, or
`mac_task_run` release gates. Evidence:
`evidence/2026-09-15-virtualization-guest-startup.md`.

Virtio connector addendum: commit `b8551d6` connects the native VM handle to a
bounded `VZVirtioSocketDevice` frame exchange and the existing authenticated
guest transport client. Connect/write/read deadlines, port and frame caps,
single-frame response parsing, trailing-data rejection, SIGPIPE protection,
callback-race cleanup, and generic native errors are implemented and tested.
Focused lifecycle/native/channel tests pass 10/10; the full physical-Darwin
regression passes 552/552 with 0 skipped tests. The host rejects the synthetic
VM configuration before creation, so guest serving, VM boot/isolation,
attestation production, and `mac_task_run` enablement remain blocked. Evidence:
`evidence/2026-09-15-virtualization-guest-virtio-connector.md`.

Native virtualization lifecycle addendum: commit `40f0461` connects the
Broker lifecycle state machine to a protected Objective-C++ N-API artifact.
It revalidates the startup-owned image, builds a read-only Virtualization
framework configuration without host network or directory sharing, exposes
asynchronous handle-only start/stop/status/close operations, and binds every
transition to an adapter-owned boot ID. The TypeScript adapter rechecks image
identity before every call and maps malformed or uncertain native outcomes
fail-closed. Focused lifecycle/adapter tests pass 9/9; full physical-Darwin
regression passes 551/551 with 0 skipped tests. The host rejected the
synthetic VM configuration before boot, so entitlement, bootable image, guest
serving/isolation, attestation production, and `mac_task_run` enablement remain
blocked. Evidence:
`evidence/2026-09-15-virtualization-guest-native-lifecycle.md`.

Virtualization lifecycle addendum: commit `042517a` adds the disabled,
Broker-owned VM lifecycle state machine. It serializes start/stop/status and
close, enforces caller cancellation and bounded deadlines, binds every result
to the immutable guest identity and boot ID, and leaves failed or ambiguous
operations in `unknown` until fresh status recovery. Focused tests pass 5/5;
the full physical-Darwin regression passes 547/547 with 0 skipped tests. This
does not boot a VM or close the guest isolation, virtio serving, attestation
production, or `mac_task_run` release gates. Evidence:
`evidence/2026-09-15-virtualization-guest-lifecycle.md`.

Guest-agent protocol addendum: commit `c8a856e` adds a bounded
`VirtualizationGuestAgent` service for the future native guest channel. It
performs HMAC/freshness/profile/guest-identity verification and replay admission
before guest execution, binds signed task and status responses to their
admitted requests, enforces frame budgets, and keeps host paths, commands, and
credentials out of the executor surface. Focused tests pass 3/3 and the full
physical-Darwin regression passes 542/542 with 0 skipped tests. This advances
the guest protocol boundary only; VM lifecycle, bootable image deployment,
guest isolation, native serving integration, and `mac_task_run` enablement
remain blocked. Evidence:
`evidence/2026-09-15-virtualization-guest-agent.md`.

Native Virtualization guest-preflight addendum: commit `7de8385` adds a
protected, artifact-validated `virtualization_guest.node` N-API seam. Its
startup-only image readback binds canonical owner-only device/inode/size/SHA-256
identity, creates a read-only Virtualization.framework disk attachment, and
confirms no host network or directory-sharing devices are configured. Focused
tests pass 2/2 and the full physical-Darwin regression passes 539/539 with 0
skipped tests. This advances MOP-086/MOP-010 native boundary evidence only;
the artifact does not boot a VM or provide guest execution, attestation
production, isolation proof, or `mac_task_run` enablement. Evidence:
`evidence/2026-09-15-native-virtualization-guest-preflight.md`.

Canonical JSON wire-profile addendum: commits `7860a00`, `a26a188`, `1aa0eea`,
and `ae2e9eb` export
the versioned `jcs-utf8-v1` profile, exact UTF-8 byte helper, and a bounded
read-only native Swift standard-library probe. Five fixed digest vectors pass
2/2 focused TypeScript tests, 5/5 Swift readback, and the 537/537 full Darwin
regression with 0 skipped tests; the protected C++ N-API artifact also passes
the five digest readbacks and its 1 MiB cap check. This advances `MOP-012`
serialization compatibility but does not
close production Swift/C++ adapter integration, corruption, retention, VM
isolation, or accepted persistence design.

Guest-attestation keyring addendum: commits `73148a6`, `db83881`, and `c56aa0a` add a startup-only
Broker manager for protected Ed25519 public-key configuration. Owner-only
canonical files are opened with `O_NOFOLLOW`, device/inode and digest bound,
size limited, and rejected on duplicate paths, weak modes, replacement, or
non-Ed25519 content. The schema-version-8 migration persists an independent
 revisioned activation/rollback history and `guest_attestation_key` revocation
kind; verifier construction checks revocation dynamically. Focused
persistence/keyring tests pass 50/50 and full physical-Darwin regression passes
533/533. Guest private signing keys remain outside the host; native producer,
Keychain distribution, VM boot/isolation, and capability enablement remain
blocked. The policy, policy-signer, and guest verification loaders also reject
private-key material before constructing trusted public keys. Packaged startup
restores an optional dataRoot-bound trust set before listeners or recovery.
Evidence:
`evidence/2026-09-15-virtualization-guest-attestation-keyring.md`.

Authority-lifecycle addendum: commit `d0c96be` adds a deterministic
BrokerStore state-machine regression with 16 seeds and 72 authority/job
actions per seed. It covers independent kill switches, principal/session and
upstream revocation, expected-state conflicts, queued/running cancellation,
terminal completion, and restart reconciliation while checking cross-principal
isolation, monotonic revisions, and terminal-state immutability. The focused
persistence suite passes 46/46 and the full physical-Darwin regression passes
527/527. Evidence:
`evidence/2026-09-15-authority-state-machine.md`.

Signed guest-provenance addendum: commit `84da3e0` extracts the Virtualization
guest attestation contract and adds a versioned Ed25519 envelope covering key,
algorithm, freshness, payload digest, and complete claims. Startup-trusted key
validity/revocation and bounded lifetime are enforced; a configured
`VirtualizationTaskRunner` verifier rechecks provenance before dispatch and
restart status lookup. Focused attestation/runner tests pass 15/15 and the
full physical-Darwin regression passes 527/527. Native attestation production,
Keychain key distribution, VM boot, guest isolation, and production enablement
remain blocked. Evidence:
`evidence/2026-09-15-virtualization-guest-attestation.md`.

Guest-image binding addendum: commits `846eca5` and `81faff0` add a protected
startup-owned image preflight and make its digest/runtime/device/inode/size
identity a required `VirtualizationTaskRunner` gate. The Broker rechecks the
image before dispatch and restart recovery; content replacement is denied
before executor invocation. Focused runner/image tests pass 15/15 and the
full physical-Darwin regression passes 527/527. Native signed-attestation
production, VM boot, isolation, and production enablement remain blocked.

Virtualization channel addendum: commits `521eecc` and `4592cad` add a
disabled-by-default Broker-side Unix-socket channel for the future native
guest adapter. It verifies owner-only socket target/device/inode identity,
native UID/GID/PID peer credentials with optional PID/start-time binding, and
parses exactly one bounded frame only after peer authorization. Physical
Darwin focused channel tests pass 4/4 and the full regression passes 527/527.
This is transport evidence only; native guest serving, VM boot, guest
isolation, and `mac_task_run` enablement remain blocked by MOP-086/MOP-045.

Strict-exit addendum: the governed sandbox task path sets a Broker-owned
`requireCleanExitProof` flag. `ProcessSupervisor` performs a final native
descendant snapshot after child close and keeps the result `UNKNOWN_OUTCOME`
on observer uncertainty, truncation, PID replacement, or unresolved
descendants. Focused process-supervisor/sandbox tests pass 29/32 with three
explicit Darwin-boundary skips; full real sandbox/Keychain regression passes
475/476 with one explicit skip. This does not prove kernel-held process or
remount isolation, post-snapshot detached-descendant prevention, credential
contents, or task enablement. Evidence:
`evidence/2026-09-14-post-snapshot-exit-proof.md`.

Keyed-audit addendum: `BrokerStore` can bind its audit tail to an explicit
owner-only 0600 sidecar with a memory-only HMAC key; a dedicated Keychain
source factory binds that key to the Broker executable ACL. The Broker
publishes only after SQLite commit and fails closed on missing, stale, forged,
or key-mismatched readback.
Focused persistence tests pass 43/43. This does not claim an external
immutable log, production Keychain anchor provisioning, cross-process sidecar
locking, or packaged enablement. Evidence:
`evidence/2026-09-14-keyed-audit-anchor.md`.

Process-identity exit-window addendum: short-lived children now retain the
bounded native PID/start-time retry after close, without synthetic identity or
unowned registration. Evidence:
`evidence/2026-09-14-process-identity-exit-window.md`.

Virtualization.framework candidate addendum: the current Darwin SDK exposes
the framework surface and the native probe links it without booting a VM while
reporting host support and rejecting a guest-less configuration; a
disabled `VirtualizationTaskRunner` seam now
requires externally reviewed guest image digest/runtime evidence plus a
matching native-adapter identity at dispatch. Identity mismatch, absent guest
evidence, unavailable adapter, and adapter failure all fail closed or remain
`UNKNOWN_OUTCOME`; this does not enable `mac_task_run`.
Evidence: `evidence/2026-09-14-virtualization-framework-sdk.md`.

Startup-authority addendum: the Supervisor rechecks close/cancellation state
after ownership sampling and before active-run registration, draining a child
and returning `CANCELLED` when authority is lost in that window. Evidence:
`evidence/2026-09-14-process-supervisor-startup-authority.md`.

Process-identity startup addendum: native PID/start-time capture retries for a
bounded 100ms after spawn, including a child that exits while the process table
settles, and never synthesizes an identity. Evidence:
`evidence/2026-09-14-process-identity-startup-retry.md`.

Task-crash mapping addendum: an observed child signal is retained as
`UNKNOWN_OUTCOME` at the task boundary so writes-local work cannot be reported
successful without post-crash attribution; a real Broker integration confirms
the Request and Job remain unresolved. Evidence:
`evidence/2026-09-14-task-crash-unknown.md`.

Process-crash addendum: an observed child termination signal is now classified
as `EXECUTION_FAILED` even when `exitCode` is null, preventing false-success
task readback. Evidence:
`evidence/2026-09-14-process-supervisor-crash-attribution.md`.

Real Broker network addendum: an opt-in Darwin integration verifies a signed
task can reach only its profile-owned loopback TCP destination and return
verified readback. Evidence:
`evidence/2026-09-14-real-broker-task-network.md`.

Task-volume identity addendum: the experimental runner double-reads and
rechecks native volume identity for every authorized task root, failing closed
on a changed root or volume before publishing a result. Evidence:
`evidence/2026-09-14-task-volume-identity.md`.

Process-supervisor startup-abort addendum: startup ownership persistence
failure now force-terminates the detached process group and waits for bounded
native root/descendant drain before returning; an unproven drain is reported as
retryable `UNKNOWN_OUTCOME`. Evidence:
`evidence/2026-09-14-process-supervisor-startup-abort.md`.

Task credential-policy addendum: versioned TaskProfiles explicitly declare
`credentialPolicy: none`; registry, sandbox renderer, and isolation-proof
admission reject unsupported credential-bearing values. Evidence:
`evidence/2026-09-14-task-credential-policy.md`.

Real process-kill-switch addendum: an opt-in Darwin integration flips the
durable `process` switch during a running task, verifies process-group drain,
and keeps the Job `unknown` after `CANCELLED`. Evidence:
`evidence/2026-09-14-real-broker-task-kill-switch.md`.

Real active-revocation addendum: an opt-in Darwin integration revokes a
session during a running `/bin/sleep` task, verifies process-group drain, and
keeps the Broker Job `unknown` after returning `CANCELLED`. Evidence:
`evidence/2026-09-14-real-broker-task-revocation.md`.

Real Edge-revocation addendum: an opt-in Darwin integration revokes the
authenticated Edge identity during a running `/bin/sleep` task, verifies
process-group drain, and keeps the Broker Job `unknown` after returning
`CANCELLED`. Evidence:
`evidence/2026-09-14-real-broker-task-edge-revocation.md`.

Real Broker task-path addendum: an opt-in Darwin integration now proves the
signed `mac_task_run` request can traverse Broker admission, single-use
approval, Job linkage, the experimental `SandboxExecTaskRunner`, and verified
readback. The default policy remains disabled; production execution is still
blocked by MOP-086. Evidence:
`evidence/2026-09-14-real-broker-task-path.md`.

Keychain ACL addendum: the native credential boundary now uses the file-based
Keychain model required by launchd daemons. Provisioning binds a canonical
protected Broker executable through `SecAccess` ACL, readback checks the exact
trusted-application identity before secret access, and digest-bound retirement
uses the exact item reference. The protected loader now requires 21 native
exports, including ACL inspection and retirement. Real host evidence covers
wrong-executable denial and cleanup; production signing/provenance and
installed rotation remain open. Evidence:
`evidence/2026-09-14-keychain-acl.md`.

Production-signature addendum: Broker and Edge install plans now default to a
strict Developer ID identity gate requiring the exact component identifier,
TeamIdentifier, and CDHash; explicit ad-hoc development plans cannot enable
capabilities. Focused install-plan tests pass 21/21. Developer ID artifact,
notarization, and persistent launchd evidence remain open. Evidence:
`evidence/2026-09-14-production-signature-gate.md`.

Task credential-proof addendum: `TaskIsolationProof` now requires a
mechanism-bound credential-isolation value for sandbox-exec or virtualization;
generic `credentials: isolated` claims are insufficient. Mechanism mismatch is
rejected before child dispatch. Focused runner/sandbox tests pass 18/21 with
three explicit Darwin skips. Production credential-store isolation remains
open. Evidence:
`evidence/2026-09-14-task-credential-isolation-proof.md`.

Persistence operations addendum: `PERSISTENCE_CUTOVER.md` records the forward
migration, encrypted-backup restore, authority freeze, UNKNOWN-job handling,
rollback, and final readback procedure. It is host/operator documentation and
does not imply an installed service cutover.

Status values: `DONE`, `IN_PROGRESS`, `PLANNED`, `BLOCKED`. Completion requires repository evidence. Current implementation, test, and working-tree state is owned by `PROGRESS.md`; this ledger records task status and acceptance evidence. `BLOCKED` is reserved for an evidenced unmet prerequisite, not merely future-phase placement. Every blocked task records `blocked_by`, `unblock_condition`, and `expected_evidence`.

Privileged-helper source-composition addendum: commit `1405b99` adds an
independent-source composition boundary for launchd, native process, plist,
runtime, and signature readback. It rejects service identity, state, type,
PID, argv, plist-path, and process-identity substitution before readiness.
Real root installation remains open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper executor addendum: commit `56ab0ca` forces the host-only
lifecycle executor to accept raw readback sources and compose the final
readback internally, preventing a preassembled-readback bypass. Root-owned
installation remains open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper host-adapter addendum: commit `a3d7765` wires bounded
`launchctl print`, native PID/start-time capture, descriptor plist reading, and
strict `codesign` verify/details parsing into the observer factory. Runtime
metadata remains helper-owned input; no root service is installed. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper observer addendum: commit `30b69df` re-reads launchd,
PID/start-time, and plist identities before composition and rejects replacement
during collection. The observer fixture covers success and PID-swap failure;
real root installation remains open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper plist addendum: commit `d3efae1` requires the exact
root-domain plist path, rendered byte count, SHA-256, and descriptor
device/inode identity in helper readback; descriptor-backed reads reject
target swaps and tampering. Root-owned installation and real helper readback
remain open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper identity addendum: commit `cc103a7` requires a positive
launchd PID and matching native PID/start-time identity in every helper
readback; missing, null, mismatched, or non-positive values fail closed. This
remains a contract-only hardening change; root-owned installation and real
helper readback remain open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper readback addendum: commit `8fd5814` carries the exact native
helper `ProgramArguments` vector into the root-domain LaunchDaemon readback and
rejects missing, reordered, or substituted arguments. This is a contract-only
hardening change; root-owned installation and real helper readback remain open.
Evidence: `evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Installer readback addendum: commit `6da24f6` requires a positive launchd PID
and matching native PID/start-time identity in every post-bootstrap Broker
readback. The host composition layer must obtain that identity from the native
observer; installed LaunchAgent/bootstrap and final real-service evidence remain
open. Evidence: `evidence/2026-09-13-installed-readback-identity.md`.

Verified launchd readback addendum: commit `4cb4e1a` adds
`composeMacOsInstallReadback`, binding the bounded launchd service identity,
running state, LaunchAgent type, PID, program, and plist path to the native
process identity before Broker/signature validation. It remains a non-installing
host composition boundary; real LaunchAgent bootstrap and final service evidence
remain open. Evidence: `evidence/2026-09-13-installed-readback-identity.md`.

Final plist readback addendum: commit `70ca1e9` requires descriptor-backed
plist identity and SHA-256 content matching the rendered plan, with canonical
`/var`/`/private/var` path handling and tamper/truncation rejection. Real
LaunchAgent bootstrap and installed-service evidence remain open. Evidence:
`evidence/2026-09-13-installed-readback-identity.md`.

Exact-arguments readback addendum: commit `9d90138` parses bounded launchd
arguments and requires the exact planned Node binary plus Broker entrypoint;
missing or substituted arguments fail closed. Generic system-service readback
remains compatible when launchd omits arguments. Real LaunchAgent bootstrap and
installed-service evidence remain open. Evidence:
`evidence/2026-09-13-installed-readback-identity.md`.

Live launchd readback addendum: a reversible physical-macOS smoke bootstrapped
and booted out a unique temporary user LaunchAgent running only `/bin/sleep`.
The production readback adapter parsed the live service and exposed a real
macOS transient `state = xpcproxy`; that value is now normalized to
`launching` without claiming `running`. The separate service inspector applies
the same conservative mapping to `loaded`. Strict Edge/helper readiness still
requires `running` plus native PID/start-time identity. Focused launchd tests
pass 7/7 and the full real-sandbox suite passes 420/420. This does not close
signed production artifacts, installed Broker/Edge handshake, or real-package
upgrade/rollback/uninstall evidence. Evidence:
`evidence/2026-09-14-live-launchd-readback.md`.

The Edge identity capture path now retries only the observed `xpcproxy`
bootstrap state within a five-second global deadline. A second reversible live
LaunchAgent smoke captured a positive PID/start-time identity through that
path, then booted the service out and confirmed absence; stopped/malformed
states remain terminal failures. This strengthens startup readback but does
not claim an installed Broker/Edge service.

The Broker instance-lock boundary additionally has a real non-cooperating
process test: a child holds the owner-only lock, the parent is denied with
`ALREADY_ACTIVE`, and reclamation succeeds only after native PID/start-time
observation proves the child stale. Focused lock tests pass 5/5. This does not
claim launchd singleton enforcement or remount durability. Evidence:
`evidence/2026-09-14-service-instance-lock-process.md`.

Current-host sandbox addendum: `MOPS_REAL_SANDBOX=1 npm test` passed 430/430
with one explicit non-sandbox skip on the Darwin arm64 host. Environment and
protected-surface denial, single-process fork/setsid and external-network
denial, selected loopback allowlisting, and active process-group cancellation
all ran successfully. This strengthens MOP-086 evidence but leaves its
deprecated-`sandbox-exec` production decision, post-snapshot descendants,
remounts, credential contents, and `mac_task_run` enablement open. Evidence:
`evidence/2026-09-14-real-sandbox-regression.md`.

Current runner-binding addendum: `TaskRunner` now declares the exact host
sandbox mechanism alongside `TaskIsolationProof`. Broker admission and task
dispatch reject missing or mismatched declarations before consuming approval or
launching a child process; `mac_task_run` remains disabled.

Install-plan readback hardening is committed locally. The host-only install
plan now has a physical-Mac package smoke that calls the
real executor with only independent launchd, native PID/start-time, plist,
Broker-status, and signature sources. It waits through transient `launching`,
double-reads mutable identities, starts a temporary zero-capability Broker
under a user LaunchAgent, and completes exact uninstall with final absence.
The package uses ad-hoc signing and the host observer now supports a distinct,
HMAC-authenticated Broker status socket with native peer credentials and
durable replay rejection. The recorded package smoke still used its historical
owner-only fixture; Developer ID, production artifact provenance,
upgrade/rollback, remote Edge, and helper installation remain open. Evidence:
`evidence/2026-09-14-live-install-plan.md` and
`evidence/2026-09-14-broker-status-ipc.md`.

The real Broker startup assembly now has a physical-host smoke: a temporary
user LaunchAgent supplied the native PID/start-time identity, signed policy and
Edge-key activations were restored from a temporary BrokerStore, and the
native Broker socket started with zero enabled capabilities and mode `0600`.
Close removed the socket and cleanup booted out the temporary service. This is
startup-assembly evidence, not installed-package, Edge request-exchange,
Developer ID, or privileged-helper evidence. Evidence:
`evidence/2026-09-14-live-broker-startup.md`.

Packaging-shape addendum: the repository now carries a reviewable Edge
LaunchAgent template beside the Broker template. The deployment notes bind
Edge launchd identity/readback before Broker startup and keep the Broker status
socket as a separate authenticated operator/readback channel. A static
template regression rejects shell, environment, user, and privileged fields;
this does not claim persistent installation or signing provenance.

## P0 — Foundation

- `MOP-001` — `DONE` — Git repository, npm workspace/package baseline, developer commands, dependency lockfile, ignore rules, and a least-privilege macOS CI definition exist. First remote CI execution remains verification evidence rather than bootstrap scope.
- `MOP-002` — `DONE` — Materialized and synchronized GOAL, DESIGN, SPEC, EPIC, ROADMAP, TASK, PROGRESS, and GOAL_PROMPT with repository-state, consistency, whitespace, task-ID, and prompt-length checks.
- `MOP-003` — `DONE` — Accepted TypeScript/Node 24+ for Edge/Broker/shared contracts; Swift remains available for native adapters/helper. Package direction and prototype evidence are recorded in ADR-0001.
- `MOP-004` — `IN_PROGRESS` — Versioned request/result/failure/principal/scope types, signed policy schemas, and a shared stable failure schema exist. A versioned `schemas/ledger-records.schema.json` now machine-validates bounded Request, Approval, Job, and Audit record envelopes, including typed privileged payloads and rejection of raw authority fields; persistence runtime validation remains the implementation authority. Host-only SQLite backup/restore/retention primitives now add owner-only atomic encrypted publication, AES-256-GCM authentication, audit-chain/SQLite integrity checks, fresh-target restore refusal, numeric timestamp retention, and symlink/ownership/mode/size/target-swap guards; missing or mismatched Broker-owned key sources and legacy plaintext backup names fail closed. BrokerStore now records and enforces monotonic SQLite schema version `11`, applies a versioned forward-only migration registry transactionally, preserves legacy data, rejects future markers and inconsistent registry identities, verifies the complete post-migration column set for every persistence table, and defines rollback as restore-from-encrypted-backup only. Schema version 6 adds the durable virtualization-guest replay ledger; schema version 7 adds bounded guest request metadata used for restart status reconciliation and clears it after verified terminal readback; schema version 8 adds independently persisted guest-attestation key configuration and its dedicated revocation kind; schema version 9 adds durable request capability-family markers; schema version 10 adds nullable Job Edge provenance; schema version 11 adds nullable Edge-key provenance with conservative legacy migration behavior. Packaged Broker startup additionally claims a persisted singleton runtime fence so stale writers fail closed after service takeover. The macOS Keychain source now has a real physical ACL readback and digest-bound retirement path; Job state/result/timestamp/lease/cancellation invariants now fail closed on readback, and a durable cancellation revision fences late success. Disk-exhaustion behavior, production code-signing/Keychain identity, and final ADR acceptance remain incomplete.
- MOP-004 schema clarification: source revisions `db129b3`, `e0b9db8`, and
  `8dbbd67` add schema versions `9`, `10`, and `11` for durable request
  capability-family markers, nullable Job Edge provenance, and nullable
  Edge-key provenance. Version `8` remains the guest-attestation key
  configuration migration; the current BrokerStore runtime and migration
  registry are at version `11`.
- `MOP-005` — `DONE` — Materialized the locked capability taxonomy, lifecycle, catalog, standard, and all 44 KB tool contracts with unique provenance, deterministic mandatory fields, and canonical delivery-wave naming. Upstream KB writeback is tracked separately in `KB_SYNC.md`.
- `MOP-006` — `DONE` — Created the initial threat model for remote client, Edge, IPC, Broker, adapters, child processes, GUI, helper, audit, policy, and secret stores, with verification targets.
- `MOP-007` — `IN_PROGRESS` — Strict typecheck, build, Node test, AJV contract validation, dependency audit, unit/integration/adversarial foundation tests, a dependency-free tracked-file style/lint check, and a least-privilege macOS CI workflow exist. First remote CI evidence remains pending.
- MOP-007 local-gate addendum: source revision `48d5b12` passes the native
  canonical-JSON check (5/5 vectors) and `npm audit --audit-level=high` reports
  zero vulnerabilities. This is local evidence only; first remote CI execution
  remains pending.
- `MOP-008` — `IN_PROGRESS` — Established the initial evidence and verification matrix; machine enforcement and real evidence remain pending the test baseline.

## P0 — Architecture closure

- `MOP-080` — `IN_PROGRESS` — Freeze exact scope, principal, session, parameterized-target, wildcard, inheritance, and revocation semantics. Depends on ADR-0002 and ADR-0004 acceptance.
- `MOP-081` — `IN_PROGRESS` — Exact Edge/key identity, signed key metadata, protected/exclusive key provisioning, revoke-before-retire deletion, overlapping rotation, validity windows, key-specific revocation, request/response policy-key binding, replay persistence, forged-socket response rejection, macOS UID/GID/PID peer verification, optional native PID/start-time peer identity binding, legacy revocation migration, a BrokerStore-backed monotonic activation/restore guard, and a native public-`Socket({ fd })` IPC candidate are implemented and tested. Edge key metadata now has an owner-only versioned loader requiring an explicit `file` or `keychain` source, an expected secret-byte digest, protected config target readback, BrokerStore revocation preflight, and a BrokerStore-backed monotonic activation/restore manager with exact restart matching and audited activation; the owner-only Authority Control channel now has a dedicated `authority_key` source/loader with digest, validity, audited activation, exact restore, revocation, and host uninstall client assembly. The Edge request factory has matching protected-file and opt-in native peer-authenticated Keychain delivery factories using a fresh challenge, strict bounded messages, replay rejection, fixed service/account startup binding, response digest checks, and no environment-variable or MCP-argument fallback. The Edge IPC client checks the owner-only socket parent and revalidates socket device/inode identity after connect before sending request bytes. LaunchAgent startup now restores the exact active key config before launchd PID/start-time capture and native runtime construction, injecting the restored keyring through a Broker factory; unactivated, changed, or cross-Edge config fails before `launchctl` readback. Overlapping source-backed rotation remains startup/configuration-only without installed hot reload. Broker-owned Jobs now persist the admitting Edge identity, and Edge revocation precisely cancels matching queued Jobs while legacy/null provenance remains conservative. The protected native adapter loader rejects non-canonical/symlinked, writable, foreign-owned, oversized, changed, or incomplete `.node` artifacts before use, binds Node's cached module to the first artifact's device/inode/size/digest, requires all 19 production native exports including non-interactive Keychain read/provisioning, checks compiled N-API compatibility with the active runtime, and is the only production consumer path for filesystem, process, network, and process-tree adapters. The macOS native build now fails closed if `/usr/bin/codesign --verify --strict` cannot validate the emitted adapter, but the observed artifact remains ad-hoc signed only. The Broker now validates request-age/clock-skew constructor limits and bounds active work per principal/session (default 8, maximum 64), rejecting saturated sessions before durable admission; focused Broker and physical-Darwin regressions pass. Developer ID code identity/provenance, notarization, Node/runtime version pinning beyond N-API compatibility, Edge PID lifecycle packaging, Keychain ACL review, live-item rotation/deletion, physical-erasure limits, cross-process/global quotas, broader numeric canonicalization, and general corruption/migration handling remain open. Evidence: `evidence/2026-09-13-edge-key-source-rotation.md`, `evidence/2026-09-13-edge-keychain-delivery.md`, `evidence/2026-09-13-authority-key-activation.md`, `evidence/2026-09-15-broker-session-concurrency.md`, `evidence/2026-09-15-strict-json-parser.md`, and `evidence/2026-09-15-job-edge-provenance.md`.
- Durable request-capacity clarification: source revision `31e89f0` now closes
  the shared BrokerStore global and principal/session admission boundary that
  was previously described as open in the MOP-081 summary. Remaining quota
  work is process/adapter-specific enforcement, disk/depth budgets, and
  production service evidence.
- Durable capability-family clarification: source revision `db129b3` extends
  the request ledger to schema version `9` and closes the cross-handle durable
  family-capacity boundary for read, write, process, network, GUI, destructive,
  and privileged work. Remaining quota work is adapter-specific semantic
  enforcement plus kernel/disk/depth limits and production service evidence.
- Idempotency authorization clarification: source revision `d715512` binds
  durable Job reuse to the original policy version as well as principal, tool,
  target, and payload digest. A retry under a different policy revision is
  rejected with `CONFLICT` before reusing the old Job; crash-window,
  concurrency, and installed-service mutation evidence remain open.
- Runtime contract-integrity clarification: source revision `2dedae0` makes
  Edge reject group/other-writable contract directories/files and verifies
  device/inode/mode stability while loading. This hardens the untrusted
  package boundary; Developer ID/package provenance and installed-service
  evidence remain open.
- Job provenance clarification: source revisions `8dbbd67`, `08c8100`, and
  `b31cf4c` add schema version
  `11` and persists the authenticated Edge-key identity alongside Edge
  provenance for Broker-created Jobs. Edge-key revocation now isolates matching
  queued Jobs; legacy/null or malformed provenance remains conservative or
  fails closed. Restarted guest recovery rechecks persisted Edge authority
  before status lookup, including Edge-key revocation.
- `MOP-082` — `IN_PROGRESS` — Broker-owned single-use approval records bind approver/requester, tool/contract, normalized target, arguments digest, policy version, approval class, attended mode and TTL. Exact consumption is atomic with request intent; substitution, expiry, revocation, exhaustion, competing use, missing approval, and pre-dispatch invalidation tests pass. A separately authenticated issuer prototype now binds issuer/key identity, signed payload, preview digest, issuance nonce, attended/unattended policy, and decision/completion provenance before persistence. Owner-only issuer-key file loading/provisioning and a separate durable `approval_key` revocation kind pass revoke-before-retire tests. A versioned owner-only metadata config atomically rotates and reloads non-secret key paths with revision/digest readback; BrokerStore activation history now rejects rollback and startup restore requires the exact persisted identity. Protected Keychain/cross-process storage, human approval UI/channel, unattended profile ownership, privileged approval, active-work semantics and ADR acceptance remain.
- `MOP-083` — `IN_PROGRESS` — SQLite Request records atomically bind nonce admission, request/payload identity, lifecycle, decisions, approval-backed mutation intent, completion, and restart-safe recovery to audit evidence. Broker startup now validates every persisted Request, Approval, Revocation, Kill-switch, and Job row before policy evaluation or reconciliation, rejecting malformed authority identities and lifecycle state as `AUDIT_UNAVAILABLE`; persisted Request Approval/Job references are cross-checked for existence and owner/session/tool/target/policy/Edge consistency. Request-to-Job linkage validates the same bindings transactionally before writing. Single-use Approval records and Job records persist their bounded identities, including the admitting Edge provenance for Broker-created Jobs. `admitApprovedJob` atomically binds future-request approval/intent/idempotency/new-job creation with idempotent reuse and conflict rollback, while `admitApprovedJobAfterDecision` atomically binds the already-authorized task path's approval consumption, intent audit, and queued Job linkage with owner/Edge/target/payload/timestamp preconditions. Fault-injected rollback proves the post-decision path leaves no partial approval, intent, or Job; restart reconciliation fails an authorized-but-not-intented request closed without consuming approval. Generic authority switches and revocations now persist redacted intent/completion audit pairs in the same transaction as the authority change and queued-job cancellation, and the separate Authority Control IPC durably admits the request/nonce before applying only bounded switch/revocation operations. Edge revocation cancels only matching queued Jobs while legacy/null provenance fails closed conservatively. Job execution now persists owner/token/expiry/heartbeat leases and fences stale terminal commits. Virtualization guest task admission now persists a bounded signed-request descriptor after replay admission; startup recovery performs a fresh authority-checked status lookup, rechecks persisted Job Edge revocation, and only promotes a restart-unknown Job after verified terminal readback, otherwise retaining `UNKNOWN`. Host-only `backupTo`, `restoreBackup`, and `pruneBackups` measure source/destination capacity before writing, provide atomic owner-only encrypted `.sqlite.enc` snapshots, AES-256-GCM authentication, SQLite/audit-chain verification, fresh-target restore, numeric retention, and fail-closed symlink/ownership/mode/size/target-swap/key-source checks. Crash recovery removes stale hidden backup and WAL/SHM sidecar temporaries, simulated `ENOSPC` and insufficient-capacity preflight return retryable `AUDIT_UNAVAILABLE`, and a two-process writer test preserves the audit chain with a bounded SQLite busy timeout. Process-tree ownership, real kernel/disk exhaustion, explicit single-owner service policy, and ADR-0005 acceptance remain.
- `MOP-084` — `DONE` — Contract envelope and per-tool functional `input_schema`/`output_schema` objects are complete for all 44 tools. Envelope validation, functional schema compilation, semantic review, authority-surface review, and catalog parity pass. The mandatory audit taxonomy, structured postcondition field, and `tool_delivery_wave` migration are closed. This documentation/schema closure does not implement runtime behavior or close `MOP-004` or `MOP-080..083`.
- `MOP-085` — `IN_PROGRESS` — Maintain Requirement -> Threat -> Task -> Test -> Evidence -> Release Gate traceability. Depends on test IDs from `MOP-007` and contracts from `MOP-084`.
- `MOP-086` — `IN_PROGRESS` — Initial real-macOS sandbox probe is recorded in `SANDBOX_RESEARCH.md` and `evidence/2026-09-12-sandbox-research.json`. Commit `2e6cd57` adds a disabled-by-default `SandboxExecTaskRunner` and Broker-owned deny-default profile renderer: resolved profiles default to `processTreePolicy: single_process` without `process-fork`; `owned_group` profiles may render the explicit fork rule but the runner now refuses to enable them even with an external proof until a separate process-tree decision is accepted. `TaskIsolationProof` binds the explicit sandbox mechanism and selected process-tree policy and rejects proof reuse across variants. The opt-in host smoke reads/writes an allowed temporary root, denies `/private/etc/passwd`, a root-contained `.env`, an outside-file symlink, and existing `.ssh`, `.docker`, Chrome, Safari, Mail, Messages, and Keychains surfaces plus `/var/run/docker.sock` readability, without opening their contents; it filters controller/`HOME`/SSH-agent/AWS_PROFILE environment canaries, allows only a selected loopback `tcp` destination, denies an unlisted loopback port and external curl DNS/network access, rejects a Bash child-launch attempt, and maps active `/bin/sleep` cancellation to detached process-group termination. Source `01a26ba` adds a real-Mac Perl hostile-descendant fixture: `fork()`/`setsid()`/marker-write returns `fork-denied` under `single_process`, with no marker left behind; focused sandbox checks now include volume-identity target-swap coverage and pass 10/10, while the full `MOPS_REAL_SANDBOX=1` suite passes 446/447 with one explicit skip. The new shared environment policy rejects task-profile `PATH`, `NODE_OPTIONS`, dynamic-loader, interpreter-startup, temp-directory, and arbitrary Git/Docker configuration keys; fixed adapters retain only exact explicit non-secret keys. The experimental runner now captures and rechecks native root volume identity around each task, refusing to publish a result after a root/volume change; this is a readback guard, not a kernel-held mount namespace. Filesystem/symlink, executable-allowlist, network-deny, fake credential-canary, and Broker launch file-descriptor behavior remain partial evidence; real credential/Docker/persistence isolation, owned-group or post-snapshot `setsid` ownership, descendants created after the last persisted snapshot, in-syscall remount resistance, external allowlisted networking, and UDP behavior remain open. A disabled Broker `ProcessSupervisor` plus named `TaskProfileRegistry` prove explicit profile-owned executable/cwd/args/environment/stdio budgets, non-inherited descriptor canary behavior, bounded detached process-group drain/readback, shared live adapter ownership, exact PID/start-time recovery for a live root plus an observed detached descendant after BrokerStore reopen, and conservative `UNKNOWN` handling when an empty post-exit snapshot cannot prove absence; `SandboxExecTaskRunner.close()` and `Broker.close()` now forward that boundary. Broker admission additionally requires a versioned profile-matched `TaskIsolationProof` covering the explicit sandbox mechanism, sandbox, filesystem, network, credentials, process-tree, and selected process-tree policy guarantees; the fail-closed `mac_task_run` Job/approval handler remains unwired to a production runner. Still blocks `MOP-043`, `MOP-045`, and `mac_task_run` enablement.
- `MOP-087` — `IN_PROGRESS` — Complete README navigation and testing, configuration, deployment, operations, incident, rollback, and kill-switch runbooks. Verified commands depend on runtime and packaging work.
- MOP-087 navigation clarification: `npm run verify:docs` now rejects README
  local-link escapes or unavailable targets and requires the eight named
  runbooks. The physical host check passes for 29 README local links and all
  8 runbooks; draft content still depends on production signing, installed
  launchd ownership, remote deployment, and operator approval evidence.
  Evidence: `evidence/2026-09-15-documentation-link-check.md`.
- MOP-083 persistence publication clarification: source revision `8e57790`
  replaces backup/restore `rename` publication with same-directory hard-link
  publication that fails closed with `CONFLICT` if a destination already
  exists. Source temporary identity is revalidated at publication, and file
  identity checks include device, inode, owner, mode, size, and modification
  time. The no-replace restore regression and a physical-host probe preserve
  an existing destination; build, lint, typecheck, and diff checks pass.
  Evidence: `evidence/2026-09-15-persistence-backup-publication.md`.
- MOP-071 process-recovery clarification: source revision `436917d` treats
  `PROCESS_RECOVERY_UNKNOWN` as retryable observer uncertainty. A later Broker
  startup retries the exact persisted PID/start-time/process-group identity
  without replaying task execution or promoting the Job; definitive drained,
  absent, and identity-mismatch outcomes remain terminal. Physical-host probe
  and regression coverage verify unknown-then-drained recovery. Evidence:
  `evidence/2026-09-15-process-recovery-retry.md`.
- MOP-071 write-recovery clarification: source revision `2fadf8a` retries a
  prior `TEMPORARY_CLEANUP_SKIPPED` observation using only the persisted root,
  target, and exact temporary name. Root, symlink, and device/inode checks gate
  unlinking; no write is replayed or promoted. Physical-host probe and
  regression coverage verify skip-then-safe-removal recovery. Evidence:
  `evidence/2026-09-15-write-recovery-retry.md`.
- `MOP-088` — `DONE` — Resolved the two repo representation conflicts, recorded decision/rationale/migration/evidence, and prepared `KB_SYNC.md` for owner-reviewed upstream writeback. This documentation-only task does not mutate KB-MCP.

Authority-control note: generic runtime switches and revocations now append redacted hash-linked `intent`/`completion` audit pairs in the same persistence transaction as the authority change and queued-job cancellation. A separate owner-only, native-peer/HMAC/replay-bound Authority Control IPC now admits only switch and revocation commands and carries its request ID into those audit pairs. Its operator key is selected by a protected, digest-bound, monotonic activation manager with a dedicated revocation kind and exact restart restore, and the uninstall coordinator constructs its client from that manager. This does not close active process-tree termination, installed startup, or operator recovery evidence.

IPC ownership addendum: source revision `44cae6a` now probes configured Unix
socket paths before stale cleanup, rejects active listeners without unlinking
them, binds generic close cleanup to device/inode identity with a temporary
symlink barrier, limits native cleanup to the recorded listener identity, and
preflights the Broker socket before startup Job recovery. Repository-level
tests pass; installed launchd singleton enforcement and physical crash/remount
readback remain open.

Startup serialization addendum: source revision `0c34c65` adds an owner-only
runtime-root instance lock with exact PID/start-time identity. It is acquired
before socket preflight, BrokerStore access, and restart reconciliation;
duplicate live owners are rejected and stale locks are reclaimed only after
proof of owner death or PID reuse. Normal and failed startup cleanup paths
release the lock after resource disposal. Launchd install/bootstrap and
non-cooperating-process lock evidence remain open.

## P1 — Local Broker vertical slice

- `MOP-010` — `IN_PROGRESS` — Broker core plus local `mac_health`, `mac_capabilities`, `mac_policy_explain`, `mac_system_summary`, `mac_process_list`, `mac_process_inspect`, `mac_network_status`, `mac_service_status`, `mac_log_tail`, exact-target `mac_git_status`/`mac_git_branch_list`/`mac_git_log`, `mac_stat_path`, bounded `mac_read_file`, descriptor-backed `mac_hash_file`, bounded descriptor-backed `mac_list_directory`, bounded `mac_directory_tree`, metadata-only `mac_find_files`, metadata-only `mac_recent_files`, bounded secret-filtered `mac_search_text`, bounded `mac_project_discover`, bounded `mac_project_summary`, and bounded `mac_storage_analysis` handlers exist and pass tests. A fail-closed `LocalBrokerRuntime` now orders Broker IPC before operator channels, rolls back partial startup, retains failed cleanup for explicit recovery, and `createMacOsNativeBrokerRuntime` binds that lifecycle to the native Broker channel. The launchd startup assembly now restores the protected Authority key and places its separate native-peer channel under the same lifecycle. Installed launchd lifecycle, operator startup, listener ABI pinning, and production enablement remain open.
- `MOP-011` — `IN_PROGRESS` — Mode-`0600` Unix IPC, macOS `getpeereid`/`LOCAL_PEERPID`, optional native PID/start-time identity binding, domain-separated request/response HMAC authentication, and a shared native accept path for Broker, policy-signer, and approval channels that hands descriptors through public `Socket({ fd })` pass prototype tests, including OS identity denial and rejection of a replacement socket using another key. The Edge IPC client now rejects non-plain or unknown-field response envelopes and malformed Broker success/failure results before MCP publication. Separate spawned Broker and Edge package-process fixtures now complete a signed request/response across native UDS under the captured Edge PID/start-time identity and verify the Broker response proof. A bounded read-only launchd readback adapter and real system-service smoke are also present. The fixed Broker service entrypoint restores exact persisted Policy/Edge-key activation before native listener construction and wipes loaded Edge keys on close. Production key lifecycle, native packaging/code identity, Edge PID lifecycle wiring, and installed transport selection remain open under ADR-0002. Evidence: `evidence/2026-09-15-edge-ipc-response-boundary.md`.
- `MOP-012` — `IN_PROGRESS` — Timestamp/session expiry, canonical payload binding, atomic nonce/request admission, persistent replay denial, terminal request lookup, and restart replay/reconciliation tests exist. Broker startup now validates every persisted replay ledger (request, approval, operator, helper, status, and virtualization guest) and fails closed on malformed identities or timestamp ordering; focused corruption tests pass. Broader canonicalization cross-runtime, retention, accepted persistence design, and production recovery evidence remain open.
- MOP-012 clarification: the atomic admission boundary now includes durable
  global and principal/session active-request limits; corruption, broader
  numeric canonicalization, retention, and the accepted persistence design
  remain open.
- `MOP-013` — `IN_PROGRESS` — Ed25519-signed policy loading, Broker-owned principal grants, exact typed target rules, deny-over-allow, default deny, immutable request snapshots, durable activation/rollback, policy-version binding, filesystem-root authorization, and unimplemented-tool enable rejection pass tests. The signer lifecycle now has a versioned owner-only metadata file, per-key public-key digests, bounded overlap/validity windows, monotonic activation and restart restore, audited durable key revocation, and a separate owner-only UDS operator channel with HMAC authentication, OS peer verification, replay persistence, reload, rollback, and revoke commands; it is not exposed through the MCP Edge. Installed startup wiring, native caller/process identity packaging, Keychain distribution, and the complete filesystem policy matrix remain open.
- `MOP-014` — `IN_PROGRESS` — A non-executing `mac_policy_explain` handler reports allow/deny, normalized query target, required/missing scopes, reason codes, and policy version. Path queries are mapped to Broker-owned signed root identities before authorization; remaining target types depend on MOP-013.
- `MOP-015` — `IN_PROGRESS` — Broker-owned request states commit atomically with decision, mutation-intent, and completion audit records; recursive redaction, a SHA-256 event chain, startup tamper rejection, and transactional policy intent/completion are implemented as prototype behavior. Audit evidence projection and redaction now reject non-data records and arrays before canonical hashing. The packaged Broker startup now requires a keyed 0600 audit-tail sidecar and loads its HMAC source through the executable-bound Keychain factory, failing closed on missing or forged readback; the sidecar read/publication path now has an owner-only atomic sibling lock with target-identity recheck on release. Crash/outage injection, retention, access control, production Keychain provisioning/rotation, stale-lock operator recovery, external rollback detection, and ADR-0005 acceptance remain open. Evidence: `evidence/2026-09-15-audit-evidence-boundary.md`.
- `MOP-016` — `IN_PROGRESS` — Persistent global/capability-family switches plus principal/session/Edge revocation checks exist. Filesystem workers poll active authority, request termination, revalidate before returning success, and audit active revocation as `CANCELLED`; mutation writes now keep the Job `UNKNOWN` when a mutations kill switch trips before completion persistence. Disabling global/mutations/process/network switches now transactionally cancels applicable queued Jobs, and principal/session revocation does the same using persisted Job ownership. Upstream identities without persisted Job provenance remain conservative. Edge revocation uses persisted Job provenance to isolate matching queued Jobs and conservatively cancels legacy/null-provenance rows. A separate owner-only Authority Control IPC enforces native peer identity, HMAC authentication, durable replay denial, strict operation allowlists, and expected-state switch preconditions. The host-only uninstall path now binds to its authenticated client with response proof, socket identity revalidation, bounded transport, and switch/revocation readback. A deterministic 16-seed authority/job state-machine regression checks queued/running/terminal/restart invariants and cross-principal isolation. Active process-tree termination, restart behavior, protected key distribution, installed startup, and operator recovery controls remain open.
- `MOP-017` — `IN_PROGRESS` — Bounded filesystem workers implement concurrency admission, per-tool deadline, active cancellation polling, termination requests, output caps, and post-result authority revalidation. Fixtures cover a real multi-root filesystem worker request, fixed-capacity overlap rejection, cancellation capacity release only after worker exit, an abrupt worker crash after a committed write that preserves an `UNKNOWN` Job while releasing capacity only after the exit event, explicit executor shutdown that terminates active workers and rejects new work, and a real `Broker.handle` stale-completion attempt rejected after a second `BrokerStore` reopen reconciles the Job to `UNKNOWN`. Packaged Broker startup now enables a persisted singleton runtime fence; after a second instance claims the next generation, stale writers fail closed with `CONFLICT` inside their SQLite transaction. Broker admission rechecks authority immediately before starting a queued Job, while the Job Ledger persists queued cancellation, idempotency, and execution owner/token/expiry/heartbeat leases. The disabled ProcessSupervisor now binds the macOS root PID and descendants to start-time identities, counts pending starts against shared capacity, waits for pending startup cleanup during close, requires the native root process-group ID to match the detached PID, rechecks that group identity before treating the root as alive, signals verified descendants in addition to the detached process group, suppresses group signalling when the root identity is unavailable, and fails closed when the native observer is unavailable; it waits for group and tracked-descendant disappearance before reporting observed termination, holds capacity while unresolved work is reaped, rejects new work after close, drains the shared Broker-owned OS process authority plus active task-runner process groups during live Broker shutdown, and supports explicit restart recovery using persisted exact PID/start-time snapshots while retaining UNKNOWN Job state; an observed detached descendant is recovered after root exit without relying on group membership, and an empty post-exit snapshot remains UNKNOWN rather than claiming absence. Persisted process ownership recovery now rejects non-plain identity/snapshot/descendant records before native signalling. The validated `sandbox-exec` single-process path now persists a Broker-owned no-fork proof and may report `PROCESS_ABSENT` after a dead root only when no descendants were recorded and the original group is gone; generic descendant trees, post-snapshot `setsid` escape resistance, unknown-outcome recovery, and old-process OS ownership remain. Evidence: `evidence/2026-09-15-process-ownership-readback.md`.
- Process-quota clarification: `ProcessSupervisor` now counts active and
  pending starts per canonical executable in addition to the Broker-wide pool;
  a saturated executable fails with retryable `CONFLICT` while another
  executable may still use available global capacity. Adapter-specific
  semantic quotas and kernel-level resource limits remain separate work.
- Authority-provenance clarification: source revision `8dbbd67` extends queued
  Job revocation isolation to authenticated Edge-key identities. Matching Edge
  or Edge-key revocations cancel only their queued Jobs; legacy/null and
  malformed provenance is handled conservatively or fails closed.
- `MOP-018` — `IN_PROGRESS` — Descriptor-backed bounded regular-file metadata, content-read, full-file `mac_hash_file`, bounded `mac_list_directory`, and depth/entry-bounded `mac_directory_tree` slices have canonical target binding, independent root policy, final-symlink/special-file denial, single-link enforcement where content is opened, local-volume restriction, plan-captured root volume identity, native `f_fsid`/filesystem-type checks, canonical secret checks before I/O, post-operation identity stability, strict encoding/digest handling, protected-entry filtering, and audit identity. Physical/removable remount evidence, configurable secret corpus, syscall timeout/cancellation, packaging, and release evidence remain.
- `MOP-019` — `IN_PROGRESS` — Bounded local success and adversarial metadata/content-read cases pass on the real Mac; a dedicated read-only host probe now records bounded system/network/process facts and `/System/Library` metadata/list/tree readback without active probes, content reads, credential access, or mutation. Clean-revision, installed-service, full filesystem/secret, and production policy evidence remain. Evidence: `evidence/2026-09-13-l0-l1-host-readback.md`.

## P2 — Remote Edge

- `MOP-020` — `IN_PROGRESS` — MCP SDK v2 initialize/modern protocol handling, Broker-filtered tool discovery, `mac_health` routing, stable Broker failure mapping, strict HTTPS Edge configuration, bounded connection budgets, and a real local HTTPS boundary probe are implemented and tested. A fixed packaged Edge service entrypoint now loads a strict owner-only, root-bound startup document, assembles the protected TLS/key/contract/JWT/IPC boundary, requires listener host/port readback, and wipes in-memory key material on close. A real RS256-authenticated MCP client now completes pinned `2026-07-28` discovery and reaches `mac_health` through the signed, peer-checked local Broker UDS; bearer material is absent from Broker audit rows. Pagination/notification behavior, separate packaged processes, remote deployment, and production key distribution remain. Evidence: `evidence/2026-09-13-governed-edge-service-entrypoint.md`.
- `MOP-021` — `IN_PROGRESS` — The MCP Edge validates signed JWT access tokens with pinned issuer/resource/audience, explicit asymmetric algorithms, bounded local/remote JWKS retrieval, controlled unknown-`kid` refresh cooldown, short token age, required identity claims, internal issuer-ID projection, known-scope filtering, and a fail-closed revocation callback. Startup also requires the configured OAuth issuer to match metadata and rejects non-HTTPS authorization/token endpoints. Local HTTPS tests verify bearer challenge/route ordering, metadata mismatch denial, official-client discovery, and in-process JWKS key rotation using a signed JWT; external issuer issuance/discovery, issuer-to-internal-ID operational mapping, live rotation/propagation latency, and remote client interoperability remain open; the local fixed-window rate limiter is tracked under MOP-023.
- `MOP-021` security addendum — Protected TLS certificate and private-key loading is implemented with owner-only regular-file checks, `O_NOFOLLOW`, canonical paths, bounded sizes, and device/inode stability readback. The fixed Edge startup loader additionally rejects weak/symlinked config, root escapes, and non-canonical target parents before constructing HTTPS. Remote issuer deployment, certificate rotation, Keychain storage, and installed Edge startup remain open.
- `MOP-022` — `IN_PROGRESS` — `EdgeRequestFactory` constructs canonical signed Broker requests with contract/protocol versions, policy audience/version, principal projection, timestamp, nonce, and key identity; `BrokerIpcClient` verifies the response proof against the exact request/result. The service-owned factory now exposes explicit disposal that wipes its HMAC key on shutdown. Cross-runtime canonicalization, protected production key distribution, and rotation/compatibility evidence remain.
- `MOP-023` — `IN_PROGRESS` — Implemented a bounded in-memory fixed-window Edge limiter after Bearer verification, keyed by verifier-provided client/principal identity, with fixed request/window/key budgets and `Retry-After` responses; Broker-filtered discovery is bounded. Shared multi-instance limits, durable counters, and real-client load evidence remain.
- `MOP-024` — `IN_PROGRESS` — Broker session/principal/Edge/key revocation and request/session expiry pass local tests; the JWT verifier accepts a host-owned revocation callback keyed by issuer/subject/session/jti. External issuer revocation, refresh/session lifecycle, propagation latency, and active-work behavior remain open.
- `MOP-025` — `PLANNED` — Select authenticated HTTPS/tunnel deployment and verify a real client end to end.

## P3 — L0/L1 inspection

- `MOP-030` — `IN_PROGRESS` — Implemented bounded `mac_system_summary` with sanitized host facts and optional load, local-interface-only `mac_network_status` with inferred connectivity, plus descriptor-verified, metadata-only `mac_storage_analysis` with capacity facts, ranked consumers, and fixed traversal budgets. The real Mac host probe now verifies system facts and interface state with listener enumeration/active probing disabled; listener ABI pinning, physical real-volume remount behavior, and release evidence remain.
- `MOP-031` — `IN_PROGRESS` — Implemented bounded native `mac_process_list` and `mac_process_inspect` with independent `mac.process.read` scope, process target authorization, numeric owner redaction, executable identity, CPU/memory bounds, parent/child PID bounds, sort/limit/PID validation, and no argv/environment exposure. The real Mac host probe verifies bounded inventory and current-process readback; network listener remains intentionally unavailable, while service status, allowlisted log inspection, exact-target Git status/branch/log/diff inspection, and the independent `mac.app.read` app inventory boundary are implemented through fixed adapters.
- `MOP-032` — `IN_PROGRESS` — Descriptor-backed `mac_stat_path`, bounded `mac_list_directory`, bounded `mac_directory_tree`, and metadata-only `mac_recent_files` are implemented with signed roots, canonical readback, plan/native volume-identity binding, same-volume containment, deny-zone revalidation, protected-entry filtering, fixed traversal/result limits, Broker-bound time windows, and audit identity. A real `/System/Library` metadata/list/tree probe now verifies canonical host readback with content reads disabled; physical remount and broader release evidence remain.
- `MOP-033` — `IN_PROGRESS` — Implemented bounded metadata-only `mac_find_files` and bounded secret-filtered `mac_search_text` over explicitly authorized roots with independent `mac.files.search` scope, per-root target authorization, descriptor-backed traversal, protected-entry/secret-content filtering, fixed entry/depth/result/text-byte budgets, worker cancellation, and strict result validation. `mac_log_tail` now preserves and redacts a supervisor-confirmed bounded output prefix on `OUTPUT_LIMIT`, reports explicit truncation, and fails closed on unresolved process outcomes. Packaging and release evidence remain.
- `MOP-034` — `IN_PROGRESS` — The bounded safe-file-read, full-file hash, descriptor-backed directory-list, depth/entry-bounded directory-tree, metadata-only file-discovery, and bounded content-search handlers are implemented. Binary policy expansion, secret controls, and broader read behavior remain.
- `MOP-035` — `IN_PROGRESS` — Implemented bounded metadata-only `mac_project_discover` and `mac_project_summary` with allowlisted marker types, safe manifest/language inference, bounded traversal/tree output, protected-entry filtering, dependency-directory pruning, per-root/root authorization, worker cancellation, strict result validation, and explicit VCS branch/dirty omission warnings. Packaging and release evidence remain.
- `MOP-036` — `IN_PROGRESS` — Traversal, root/target symlink, deny-inside-allow alias, root `/`, metadata/hash/content-read/list/tree target-change, content-read intermediate-symlink target-swap, protected directory-entry filtering, bounded depth/entry truncation, multiply-linked inode denial, post-authorization mutation, concurrent create-only target/symlink-swap, Unix-domain-socket generic-tool, FIFO/non-blocking pseudo-device, observed character/block-device, bounded pressure-budget, and real multi-root worker-capacity tests pass. Lexical case-alias rejection, NFKC-normalized Unicode search identity, and plan/native volume-identity guards are covered by adversarial fixtures. Physical remount identity, cross-volume normalization policy, broader device/pseudo-filesystem coverage, production-scale resource exhaustion, and kernel-blocked I/O recovery remain.
- `MOP-037` — `IN_PROGRESS` — Broker-mandatory F0/F1 path rules cover representative SSH, GPG, cloud, Docker, Kubernetes, Keychain, Mail, Messages, Safari, Chrome, Photos, dot-env, GitHub CLI, browser, and containerized Apple data paths; returned byte ranges are denied on representative private-key/token/credential signatures without audit leakage. Evidence redaction now covers protected paths with spaces, `/private/var/root`, Bearer/Basic credentials, and JWT-shaped values. Configurable classification, split-range signatures, false-positive corpus, and broader no-secret-output regressions remain. Evidence: `evidence/2026-09-13-secret-zone-redaction.md`.

## P4 — L2 developer operations

- `MOP-040` — `IN_PROGRESS` — Implemented governed Git status, diff, log, and branch metadata through exact project-root authorization, fixed `/usr/bin/git` commands, repository integration rejection, literal path/revision validation, bounded outputs, secret redaction, identity readback, and schema/conformance tests. Git log now preserves complete records from a supervisor-confirmed bounded prefix while rejecting unverified termination. A disabled-by-default controlled Git write prototype now adds explicit-path staging and local commit through Broker-owned Jobs, approval binding, fixed no-hook/no-network commands, staged-diff/HEAD/index/status readback, and fail-closed unknown-outcome handling. A real opt-in Broker task integration now exercises a profile-owned loopback TCP allowlist through the sandbox runner; external destinations and broader network release evidence remain open. Network operations remain excluded; real-Mac repository evidence and write-gate closure remain open.
- `MOP-041` — `IN_PROGRESS` — Implemented bounded `mac_package_inspect` with independent `mac.package.read` scope, exact project-root authorization, descriptor-backed manifest/lock identity checks, npm/pnpm/yarn/pip/uv/poetry/Brewfile parsing, protected-content denial, cancellation/timeout checks, and no package-manager script execution. Outdated registry reads remain disabled until an allowlisted registry profile and network-scope binding are released.
- `MOP-042` — `IN_PROGRESS` — Implemented fixed local-only Docker status, object inspection, and bounded container logs through a Broker-owned adapter with exact `mac.docker.read` targets, a canonical Docker Desktop executable allowlist, fixed arguments, bounded parsing, environment/mount/log redaction, cancellation, and no raw socket proxy. Container/image CLI records now require plain known-field data with unambiguous IDs; inspection aliases fail closed, nested metadata stays bounded, and logs cap line count and line bytes before redaction. A real Mac daemon readback observed local Docker version `29.1.3` without listing containers/images; daemon-version/object compatibility, storage readback, and independent raw-socket negative tests remain. Evidence: `evidence/2026-09-15-docker-result-boundary.md`.
- `MOP-043` — `BLOCKED` — Implemented the named-profile validation boundary and Broker-owned `mac_task_run` admission/Job lifecycle; versioned profiles now explicitly declare `credentialPolicy: none`, and an opt-in Darwin integration proves signed-request admission, single-use approval, Job linkage, experimental sandbox dispatch, and verified readback, but production execution remains disabled. `blocked_by: MOP-086`; `unblock_condition: per-tool functional schemas remain complete and sandbox/credential-isolation evidence passes`; `expected_evidence: hostile task-profile PoC, resource-bound tests, and L2 release-gate evidence (VT-SBX-01, VT-SBX-02)`.
- `MOP-044` — `IN_PROGRESS` — Owner-bound `mac_job_status` and `mac_job_cancel` handlers, bounded output, durable cancellation intent, queued cancellation, terminal idempotency, lease-fenced terminal transitions, and restart reconciliation are implemented and schema-tested. Opt-in Darwin integrations now verify session revocation, Edge revocation, and the durable `process` kill switch during real running tasks; each drains the process group and leaves the Job `unknown` after `CANCELLED`. Broader restart/crash and production process-tree evidence remains gated by MOP-086.
- `MOP-045` — `BLOCKED` — Prove child processes cannot access Edge/Broker/controller credentials or exceed filesystem/network policy. The handler accepts only a Broker-owned runner and records unknown outcomes when runner evidence or active authority is not trusted; no production child-process runner is enabled. `blocked_by: MOP-086`; `unblock_condition: real-Mac hostile sandbox PoC passes or task capability is restricted/removed`; `expected_evidence: credential canary, filesystem, network, process, Docker, and persistence isolation evidence (VT-SBX-01, VT-SBX-02)`.
- `MOP-046` — `IN_PROGRESS` — Implemented a disabled `mac_write_file_atomic` Broker/native prototype with independent write-root policy, exact approval binding, secret-content denial, descriptor identity checks, atomic same-directory rename, expected hash/create-only preconditions, explicit idempotency key, Broker Job Ledger linkage/status lookup, restart-to-`UNKNOWN` recovery, readback verification, and focused tests. Write jobs now persist only a bounded non-secret descriptor, including the exact generated temporary filename, and `mac_job_status` probes `matches`/`mismatch`/`unavailable` postconditions without inferring success. An explicit host-startup recovery hook now selects only restart-reconciled unknown write Jobs and cleans one recorded temporary artifact with descriptor-relative identity checks, audited intent/completion, and no prefix scan; legacy descriptors without a temporary name remain untouched. Real `WorkerFilesystemExecutor` pre-commit, post-rename, and test-only post-commit worker-crash failures now prove Broker preserves the Job as `UNKNOWN`; a Broker completion-failure simulation, deterministic fault-test-only `ENOSPC` cleanup before temporary write/`fsync` and after rename before parent `fsync`, a test-only fault-instrumented native `SIGKILL` boundary at selected syscalls, and final authority revalidation when the mutations kill switch trips confirm a committed atomic target cannot be published as an unauthorized success and remains inspectable as `UNKNOWN`. A 500-iteration hostile fixture now exercises concurrent create and symlink replacement; `RENAME_EXCL`/identity checks prevent replacement of the attacker target, while outside content remains unchanged. `mac_apply_patch` now adds a separate disabled-by-default textual patch path with independent `mac.files.write` + `mac.project.write` scopes, approval/Job/audit binding, expected-base hashing, bounded relative targets, secret denial, identity-bound atomic writes, rollback, and structured readback; focused Broker and filesystem tests pass. Release remains gated by physical remount/durability, prior-worker/process ownership proof, broader partial-mutation coverage, and final readback evidence (`MOP-013, MOP-015, MOP-017, MOP-082, MOP-083`; VT-FS-01, VT-FS-02, VT-APR-01, VT-AUD-01, VT-REL-01).
- `MOP-047` — `IN_PROGRESS` — Implemented a disabled-by-default controlled Git staging/local-commit prototype. Broker admission binds the exact project target, arguments, approval, mutation intent, idempotency key, and generic Job lease; staging accepts only bounded explicit literal paths after canonical/symlink/secret checks, and commit binds an optional staged-diff hash precondition. Fixed `/usr/bin/git` commands disable hooks, fsmonitor, optional locks, signing, and network integrations; no push/reset/remote command surface exists. Staged diff hash, HEAD/parent, index-empty, working-tree, target identity, redaction, and unknown-outcome readbacks are enforced by tests, including a real temporary repository run. Release remains gated by MOP-046 write-gate closure, broader crash/concurrency/remount/actor-attribution coverage, and final readback (VT-GIT-01, VT-REL-01, VT-AUD-01, VT-DOS-01).

## P5 — L3/L4 applications and GUI

- `MOP-050` — `IN_PROGRESS` — Implemented the read-only `mac_app_list` inventory slice, disabled-by-default `mac_app_open` launch and `mac_app_focus` focus slices, the first read-only `mac_ui_observe` Accessibility snapshot boundary, and disabled-by-default snapshot-bound `mac_ui_action`/`mac_ui_type` slices. Inventory/launch/focus use stable `bundle:<bundle_id>` identities; launch and focus require exact target authorization, `trusted_gui` approval, Broker Job leases, fixed `/usr/bin/open -b` or Broker-owned JXA, bounded timeout/output, and launch/focus readback. UI observation requires an independent `mac.ui.observe` scope, `window:bundle:<bundle_id>` target rule, GUI kill-switch coverage, fixed Broker-owned JXA, empty environment, bounded node output, secure-label masking, and opaque window/element references. UI actions and typing require `mac.ui.control`, exact parent app-window authority, a 30-second owner/session-bound snapshot, GUI approval, exact role/label/index matching, and before/after Accessibility reobservation. Document/URL launch, structured automation, and broader GUI actions remain planned or disabled.
- `MOP-051` — `PLANNED` — Implement structured AppleScript/JXA/Shortcuts adapters without raw script input.
- `MOP-052` — `IN_PROGRESS` — Implemented bounded read-only Accessibility-tree observation with permission-denied fail-closed behavior, secure-node masking, redacted labels, and opaque window/element identity derivation. The observation now feeds an owner/session-bound 30-second snapshot registry, and action adapters reobserve exact window/index/role/label identity before completion. Permission-granted real-app evidence remains open.
- `MOP-053` — `IN_PROGRESS` — Implemented disabled-by-default `mac_ui_action` for the fixed allowlist `press`, `select`, `increment`, `decrement`, `show_menu`, and `focus`, plus disabled-by-default `mac_ui_type` for bounded text and nine allowlisted keys. Both require a fresh owned snapshot, exact parent app-window authority, `trusted_gui` approval, a Broker Job ID, fixed Broker-owned JXA, stale/sensitive/secure-target denial, and verified before/after Accessibility reobservation. UI text travels through bounded stdin rather than argv and is never written to Job output; secret-like input is rejected before execution. Real permission-granted, focus-race, and adversarial app evidence remain open.
- `MOP-054` — `IN_PROGRESS` — Added a conservative sensitive UI deny policy for SecurityAgent, Keychain Access, System Settings, loginwindow, security/privacy/password/credential/sign-in window hints and returned titles; secure Accessibility nodes remain masked and labels are redacted. Clipboard, cross-app data, broader credential-surface classification, and permission-granted adversarial evidence remain open.
- `MOP-055` — `PLANNED` — Verify macOS permission-denied, revoked-permission, stale-target, and real-app workflows.

## P6 — L5 privileged helper

- `MOP-060` — `IN_PROGRESS` — Added the proposed separately authenticated helper protocol: owner-only peer-authenticated IPC, HMAC command/response binding, durable request/nonce replay rejection, fixed `service_control`/`package_install`/`power` operation names, Broker argument digests, approval/intent identity, bounded redacted evidence, and fail-closed postcondition validation. Added a Broker-owned factory that signs only matching explicit-approval, intent-linked running Jobs and rechecks target, payload, policy, principal/session, kill switches, and revocation before signing. A dedicated protected `helper_key` manager now binds explicit file/Keychain source, digest, validity, monotonic activation, exact restore, revocation, and disposal before constructing the factory or helper server; both helper HMAC owners defensively wipe key copies and recheck active key authority. Already-constructed factory/server paths now fence helper-key expiry and activation replacement without restart. An independent helper runtime now restores the exact activation, requires native peer identity, rejects Broker/control socket reuse, and owns serialized start/close rollback. A separate root-domain package plan now fixes native-only launchd argv, signature identity, socket separation, Broker peer binding, disabled capabilities, and rollback/readback invariants. Helper startup can derive the caller from the exact Broker LaunchAgent readback and bind native PID/start-time identity; a real macOS cross-process test rejects a spawned caller spoof before request parsing. No helper operation is enabled; signed artifact provenance, real root-domain host evidence, and independent review remain open under ADR-0009 and VT-PRIV-01.
- MOP-060 cancellation/lease clarification: source revision `6fab84d` closes the
  pre-dispatch cancellation race, rechecks the Job after command signing before
  helper IPC, retains `UNKNOWN_OUTCOME` when cancellation occurs after a
  command may have crossed the boundary, and renews long helper leases at a
  bounded interval. Focused executor/dispatch tests pass 12/12 and the latest
  physical non-overlapping regression passes 606/606. Default helper policy and
  executor remain disabled. Evidence:
  `evidence/2026-09-15-privileged-cancellation-lease-regression.md`.
- MOP-060 authority-gate clarification: source revision `91806ae` adds a
  Broker-backed helper callback that reconstructs Request/Approval/Job
  authority and rejects disabled switches, Edge/key/principal/session
  revocation, cancelled or non-running Jobs, expired approvals, and command
  identity substitution. The combined helper/executor/dispatch suite passes
  26/26 and the latest physical non-overlapping regression passes 607/607.
  Evidence: `evidence/2026-09-15-privileged-authority-gate.md`.
- MOP-060 authority-polling clarification: source revision `2c3e01d` (building
  on `b9d038a`, `d717525`, `2660bdf`, `becea16`, and `1eea5cb`) adds an
  independent helper-to-Broker Unix socket with mandatory peer authentication
  on both directions, direction-separated HMAC domains, durable replay
  admission, and the Broker-backed Request/Approval/Job authority callback.
  The helper polls before dispatch, during execution, and before success;
  post-dispatch authority loss is retryable `UNKNOWN_OUTCOME`. Runtime startup
  rejects enabled adapters without this poller and enforces root-helper/
  non-root-Broker peer roles. Focused helper/authority tests
  pass 18/18, runtime/keyring tests pass 7/7, native startup assembly tests
  pass 8/8, and the latest physical non-overlapping regression passes 613/613.
  Evidence: `evidence/2026-09-15-privileged-authority-polling-ipc.md`.
- MOP-060 root-helper key-material clarification: source revision `e786002`
  adds `createPrivilegedHelperRuntimeFromKeyMaterial`, which does not accept
  or open `BrokerStore`. It loads protected local key material, checks its
  validity window, and requires the separately authenticated Broker authority
  poller whenever an adapter is enabled. The existing BrokerStore-backed
  activation factory remains a Broker-side compatibility path. Focused
  helper/runtime/keyring/authority tests pass 11/11 and the latest physical
  non-overlapping regression passes 614/614. Evidence:
  `evidence/2026-09-15-privileged-helper-key-material.md`.
- MOP-061 authority-socket clarification: source revision `ee2c934` binds the
  root-domain package plan and helper status readback to the Broker-owned
  `helperAuthoritySocketPath`. It rejects socket reuse and authority endpoints
  placed inside the root-owned helper package, and requires exact runtime
  readback of the three socket identities. Focused helper/package/status tests
  pass 31/31 and the latest physical non-overlapping regression passes
  614/614. Evidence:
  `evidence/2026-09-15-privileged-helper-package-authority-socket.md`.
- MOP-061 authority-socket ACL clarification: source revision `fe9d681` adds
  independent readback of the Broker-owned authority Unix socket. It requires
  the expected Broker UID/GID, owner-only permissions, socket type, and stable
  device/inode/mode/ownership across two reads; the endpoint remains outside
  the root-owned helper filesystem set. Focused package tests pass 14/14 and
  the latest physical non-overlapping regression passes 615/615. Evidence:
  `evidence/2026-09-15-privileged-helper-authority-socket-acl.md`.
- MOP-060 root-helper poller construction clarification: source revision
  `a79d813` removes injectable authority-poller selection from the
  no-`BrokerStore` root-helper factory. Enabled adapters must use a fixed
  authority socket and native Broker peer policy to construct the authenticated
  client; missing authority configuration fails closed. Focused runtime tests
  pass 5/5 and the latest physical non-overlapping regression passes 615/615.
  Evidence: `evidence/2026-09-15-privileged-helper-poller-construction.md`.
- MOP-060 runtime disposal clarification: source revision `2ce0945` (with
  failed-cleanup coverage in test revision `ccb248b`) makes authority-poller
  disposal idempotent across startup failure, failed cleanup, close-before-
  start, and ordinary close. A runtime whose separately authenticated poller
  has been disposed cannot restart with wiped key material. Focused runtime
  tests pass 6/6 and the latest physical
  non-overlapping regression passes 616/616; the existing Broker/Persistence
  process remained undisturbed. Evidence:
  `evidence/2026-09-15-privileged-helper-runtime-disposal.md`.
- MOP-060 root-helper Keychain ACL clarification: source revisions `4bc0308`,
  `666a978`, and `711f3e4` keep the BrokerStore-backed key loader bound to the
  Broker executable and require the no-`BrokerStore` root-helper loader to
  receive an explicit canonical helper executable path for Keychain-backed
  keys. The loader verifies non-secret ACL/protection metadata before loading
  key bytes, and missing or non-canonical binding fails with a stable error
  before Keychain access. Focused helper keyring/runtime tests pass 10/10;
  focused credential tests pass 14/14 with one explicit physical Keychain
  skip; the latest physical non-overlapping regression passes 617/617 and the
  existing Broker/Persistence process remained undisturbed.
  Evidence: `evidence/2026-09-15-root-helper-keychain-acl-binding.md`.
- MOP-060/061 signing-readiness clarification: source revisions `7f725bf` and
  `0c21edb` bind Keychain trusted executable ACL checks to the current owner
  and include UID/mode in the native before/after identity fence. A physical
  host probe on 2026-09-15 found zero available Developer ID signing
  identities; the rebuilt native adapter is strict ad-hoc/linker-signed with
  no TeamIdentifier. This is recorded as a release blocker rather than a
  policy relaxation. Evidence:
  `evidence/2026-09-15-keychain-trusted-executable-ownership.md` and
  `evidence/2026-09-15-production-signing-readiness.md`.
- `MOP-061` — `BLOCKED` — Added a non-executing root-domain helper package plan with native-only argv, exact code-signature identity, root-owned plist actions, protected helper-root/key/socket paths, Broker peer UID/GID binding, and exact upgrade/rollback/uninstall commands plus readback rejection for enabled capabilities. Helper startup now derives the Broker caller from the exact per-user `gui/<uid>/com.mac-operator.broker` LaunchAgent readback and binds PID/start-time identity before constructing the helper. A real macOS temporary bundle smoke test executes the fixed ad-hoc `codesign` verification command and reads back the exact helper identifier; the package also has a double-`lstat` root-owned preflight and a host-only, explicitly confirmed descriptor-relative plist apply/upgrade/rollback/uninstall primitive with identity-bound restoration. A real cross-process native IPC test now proves the bound Broker caller is accepted while a second spawned caller is dropped before parsing, and plist apply verifies the real current process UID before any filesystem access. A host-only dry-run execution contract and gated executor now bind exact service-revision preconditions, fixed command/file order, final readback, and operation-specific recovery steps; non-root callers fail before command or readback access. These do not prove Developer ID provenance, successful root-owned execution, or real root-domain readback. `blocked_by: MOP-003, MOP-081, ADR-0007`; `unblock_condition: runtime, IPC identity, package/signing, launch ownership, and credential-cleanup decisions are accepted`; `expected_evidence: Developer ID signature and provenance, install/upgrade/rollback, helper mismatch, uninstall, caller identity, caller-spoof, and real root-domain readback tests (VT-PRIV-01, VT-OPS-01)`.
- `MOP-062` — `BLOCKED` — Implement approved service control with preconditions and postconditions. `blocked_by: MOP-060, MOP-061`; `unblock_condition: authenticated helper protocol and service allowlist are released`; `expected_evidence: allowlist, precondition, service-state readback, audit, rollback, and bypass tests (VT-PRIV-01)`.
- `MOP-063` — `BLOCKED` — Implement approved package installation with exact identity/version policy. `blocked_by: MOP-060, MOP-061`; `unblock_condition: authenticated helper, package source policy, and version allowlist are released`; `expected_evidence: package identity/version, source, approval, installed-version, rollback, and bypass tests (VT-PRIV-01)`.
- `MOP-064` — `BLOCKED` — Implement reboot/shutdown with explicit policy and verified audit intent. `blocked_by: MOP-060, MOP-061, MOP-082, MOP-083`; `unblock_condition: helper auth, privileged approval, durable audit intent, and handoff semantics are released`; `expected_evidence: accepted/scheduled handoff, policy denial, audit-intent, cancellation/reconciliation, and recovery tests (VT-PRIV-01, VT-AUD-01)`.

## P7 — Hardening and release

- `MOP-070` — `IN_PROGRESS` — Added deterministic bounded security-fuzz regression coverage in `packages/broker/src/security-fuzz.test.ts` for request/guest authentication mutations, replay IDs/nonces, strict extra-field and authority-shaped inputs, traversal/protected-zone paths, secret and prompt-injection-shaped content, output/resource budgets, canonical JSON rejection, deny-overrides-allow, and projected-scope expansion attempts. Commit `d0c96be` adds a 16-seed authority/job state-machine campaign covering independent switches, revocation, cancellation, terminal immutability, revision monotonicity, and restart reconciliation; the full physical-Darwin suite passes 527/527. Broader schema/property fuzzing, long-running campaigns, policy-downgrade exploration, kernel/resource-exhaustion evidence, and independent review remain open.
- `MOP-071` — `IN_PROGRESS` — Verify crash, restart, partial mutation, audit outage, credential rotation, and kill-switch recovery. Audit-anchor outage, stopped-service exact lock recovery, persisted Broker runtime fencing, core schema-shape checks, and startup-wide Request/Approval/Revocation/Kill-switch/Job ledger validation now have focused persistence/Darwin evidence; malformed persisted identities, lifecycle state, authority linkage, lease ownership, secret-shaped/oversized Job output, unknown core columns, and mixed local-process/guest recovery metadata are rejected before reconciliation or policy evaluation. Physical crashed-process/old-worker ownership, credential rotation, partial-mutation durability, and installed operator recovery remain open. Evidence: `evidence/2026-09-15-request-ledger-startup-integrity.md`, `evidence/2026-09-15-authority-ledger-startup-integrity.md`, `evidence/2026-09-15-job-ledger-startup-integrity.md`, `evidence/2026-09-15-job-output-integrity.md`, and `evidence/2026-09-15-core-schema-layout.md`.
- `MOP-072` — `IN_PROGRESS` — Added source-level launchd plist rendering, reviewed Edge/Broker LaunchAgent templates, signal-aware Broker/Edge service lifecycles, bounded startup readback, fixed packaged Broker and HTTPS Edge entrypoints with owner-only root-bound startup configuration, component-specific `buildMacOsEdgeInstallPlan`/`buildMacOsInstallPlan` boundaries and Edge/Broker readback composition, host-only install-plan executors requiring exact operation confirmation and existing-service preconditions, fixed bounded `codesign`/`launchctl` argv, exact previous-revision preconditions, rollback/uninstall actions, post-bootstrap identity validation, double-`lstat` owner/mode/symlink/device/inode checks, and temporary-root-tested descriptor-relative atomic plist install/upgrade/rollback/uninstall. Install-plan readback now rejects inherited/accessor/symbolic observations before identity or capability checks. Read-only launchd metadata parsing and an opt-in Darwin smoke of separate real Edge/Broker LaunchAgents now verify exact arguments, Edge TLS readiness, native/status socket ownership, HMAC Broker readback, PID identity, empty capabilities, and post-bootout absence. The Edge entrypoint has local listener readback and remote JWKS configuration, while the uninstall coordinator binds to the real owner-only Authority Control client with authenticated readback and exact Edge revocation. A real macOS temporary ad-hoc artifact smoke test executes the plan's fixed signature verification command. Developer ID signing/notarization, production artifact identity, unattended installer authorization, remote OAuth/JWKS, Keychain ACLs, production upgrade/rollback, observability, retention, and final operator runbooks remain. Evidence: `evidence/2026-09-15-install-readback-boundary.md`.
- `MOP-073` — `PLANNED` — Perform independent security and architecture review; resolve all reproducible P0/P1 findings.
- `MOP-074` — `PLANNED` — Produce exact-revision release candidate and real-client/real-Mac evidence.

### Privileged helper status addendum (`2240870`, hardened in `86a99ca`)

`MOP-060`/`MOP-061` now include a helper-owned read-only status IPC slice. It
uses a separate HMAC domain, native peer authorization, durable replay
admission, fixed status/readback schemas, socket identity fencing, and active
helper-key authority checks. The status source is explicit and is not exposed
as an MCP tool; no privileged operation or root-domain service is enabled.
Verification: 398 tests (395 passed, 3 opt-in sandbox tests skipped),
typecheck, contract verification, audit, and diff checks pass. Evidence:
`evidence/2026-09-13-privileged-helper-status-ipc.md`.

`MOP-086` host-evidence addendum: source revision `a8d9007` passed the full
`MOPS_REAL_SANDBOX=1 npm test` run at 398/398 and the focused sandbox suite at
9/9 on the Mac mini host. This strengthens, but does not close, the sandbox
gate; real credential/Docker/persistence isolation, remount identity,
owned-group/post-snapshot process ownership, UDP, external allowlisted
networking, and production packaging remain open.

Latest MOP-086 exit-proof addendum: governed tasks now request a final native
descendant snapshot after child close and retain `UNKNOWN_OUTCOME` when the
observer is unavailable, truncated, replaced, or non-empty. The current full
real sandbox/Keychain regression is 475/476 with one explicit skip. This is an
observation guard only; post-snapshot detached descendants, remount identity,
credential-store isolation, and production task enablement remain open.

Latest Virtualization seam addendum: the disabled `VirtualizationTaskRunner`
now requires a digest-bound native guest attestation tied to the immutable
guest identity, resolved sandbox profile, external evidence reference,
guest-private filesystem, profile-bound network, unavailable host credentials,
and guest-owned process tree/policy. Commit `84da3e0` additionally defines a
versioned Ed25519 envelope with startup-trusted key validity/revocation and
freshness checks; a configured runner revalidates the signed claims before
dispatch and recovery. SDK presence, guest-less configuration validation, and
this structural/signature check still do not prove VM boot, entitlement,
credential isolation, or production enablement. Evidence:
`evidence/2026-09-15-virtualization-guest-attestation.md`.

Latest exit-event addendum: strict task proof now begins at child `exit`,
records process-group survival before stream `close`, and performs a second
native descendant sample after one bounded poll interval. A Darwin
fork-and-detach fixture that keeps the output pipe open remains
`UNKNOWN_OUTCOME`; focused process-supervisor tests pass 20/20 and the full
real sandbox/Keychain regression passes 477/478 with one explicit skip. This
closes the close-event reparenting race but not post-window descendants,
remount resistance, credential isolation, or production task enablement.
Evidence:
`evidence/2026-09-14-exit-observation-window.md`.

Latest restart-recovery addendum: when a persisted task root has exited and
its previously observed descendants are gone, the Broker no longer reports
`PROCESS_ABSENT`. A persisted snapshot is not a complete post-exit census, so
descendants created after the last observation could have escaped into another
process group; recovery now remains `UNKNOWN_OUTCOME` with no termination
claim. The Darwin regression and full real sandbox/Keychain run pass 21/21
focused process-supervisor tests and 478/479 tests with one explicit install
skip. Evidence:
`evidence/2026-09-14-restart-descendant-absence.md`.

Latest audit-outage addendum: a held owner-only audit-anchor lock now proves
the post-commit publication failure boundary. The audit append returns
retryable `AUDIT_UNAVAILABLE` after SQLite has committed, the same BrokerStore
freezes further writes, the sidecar remains at its previous tail, and the next
BrokerStore startup rejects the mismatch. The focused persistence suite passes
41/41. Evidence:
`evidence/2026-09-14-audit-anchor-publication-outage.md`.

Latest packaged-startup addendum: the compiled Broker service entrypoint now
requires the owner-controlled audit-anchor path and fixed Keychain
service/account/key-id configuration, loads the HMAC source through the
executable-bound ACL, and verifies the sidecar before readiness. The
service-startup suite passes 3/3. The real temporary LaunchAgent smoke with
`MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1` passes 1/1 and cleans up the exact
temporary Keychain item and both labels. Production Developer ID provisioning,
persistent installation, cross-process locking, and external rollback-
resistant anchoring remain open. Evidence:
`evidence/2026-09-14-packaged-audit-anchor-startup.md`.

Latest audit-lock addendum: `AuditAnchorManager` now holds an owner-only
atomic sibling lock across sidecar read, validation, publication, and
directory `fsync`, then rechecks device/inode identity before release. A
pre-existing lock is never auto-reclaimed and fails closed for authenticated
operator recovery. The focused audit-anchor plus persistence suite passes
44/44. This closes the local sidecar race but leaves stale-lock recovery,
external immutable anchoring, production Keychain rotation, and Developer ID
installation open. Evidence:
`evidence/2026-09-14-audit-anchor-lock.md`.

Audit-lock recovery addendum: `recoverAuditAnchorLock` is now a host-only
stopped-service boundary. It requires the exact owner-only lock device/inode
from operator readback and uses the existing Darwin native descriptor-relative
`unlinkat` + parent `fsync` path with removal readback; startup never applies
age/PID-based cleanup. Focused recovery tests pass 3/3. This remains a
recovery primitive rather than external immutable anchoring or installed
operator authentication. Evidence:
`evidence/2026-09-14-audit-anchor-lock-recovery.md`.

Latest controller-secret-zone addendum: Broker-owned sandbox profiles now
deny `.codex` and `.openai` controller-state directories alongside SSH, cloud,
Docker, browser, Mail, Messages, and Keychain zones. The real
`MOPS_REAL_SANDBOX=1` sandbox/task-runner readback passes 21/21 and confirms
those surfaces are denied without opening contents. This strengthens the
credential-surface boundary but does not prove real credential-content
isolation or production `sandbox-exec` enablement. Evidence:
`evidence/2026-09-14-sandbox-controller-secret-zones.md`.

`MOP-061` signature addendum: source revision `46a3167` requires the exact
helper identifier, Developer ID TeamIdentifier, and CDHash in the root-domain
package plan and final codesign readback. Missing fields fail closed before
filesystem or launchd actions. Developer ID signing/notarization, installation,
live readback, and independent review remain blocked. Evidence:
`evidence/2026-09-13-helper-signature-gate.md`.

`MOP-061` observer addendum: source revision `3b24604` wires the authenticated
helper socket/key status client into the package observer and rejects a missing
runtime source. The integration test completes a real local signed status
exchange through the production-shaped observer. Root installation and live
launchd evidence remain blocked. Evidence:
`evidence/2026-09-13-helper-observer-ipc-integration.md`.

Helper/install-plan boundary addendum: source revision `3d9e326` passes the
focused 47-test package/runtime/install-plan suite on the physical macOS host.
The suite covers fixed package plans, signature/readback binding, socket and
native peer identity, exact revision preconditions, host confirmation,
non-root rejection, and recovery ordering. It does not prove Developer ID
provenance, protected production Keychain material, or root-domain lifecycle;
those gates remain blocked.

Approval persistence boundary addendum: source revision `28b26db` validates
persisted Approval rows before they influence intent admission, consumption,
status readback, or revocation. Single-use counters, timestamp/expiry order,
consumption and revocation pairing, bounded identity/target/digest fields, and
revision values fail closed as `AUDIT_UNAVAILABLE`; focused approval authority
and corruption tests pass 14/14. The non-overlapping package regression reports
563 tests total (557 passed, 6 explicitly skipped, 0 failed). Protected
production Keychain/cross-process storage, human approval UI, unattended
ownership, and ADR acceptance remain open.

Authority-row boundary addendum: source revision `e11127e` validates persisted
revocation and kill-switch rows before policy, Job cancellation, or capability
evaluation. Malformed query identities fail with `PRECONDITION_FAILED` and
corrupted rows fail closed as `AUDIT_UNAVAILABLE`; focused Authority Control
IPC, Policy, and corruption tests pass 15/15. Production Keychain
distribution, installed operator recovery, external rollback detection, and
ADR acceptance remain open.

Replay-row boundary addendum: source revision `100133e` scans all seven
Broker-owned replay ledgers after migration and rejects malformed identities,
nonce formats, timestamp ordering, or guest-ledger over-capacity as
`AUDIT_UNAVAILABLE` before runtime or admission decisions. Focused replay,
Approval, Authority Control, and Policy tests pass 12/12 in the replay-focused
slice; the non-overlapping package regression passes 572 total (566 passed, 6
explicitly skipped, 0 failed). Broader canonicalization, retention, protected
Keychain, installed recovery, and ADR acceptance remain open. Evidence:
`evidence/2026-09-15-replay-row-invariants.md`.

Configuration-row boundary addendum: source revision `7a34191` validates every
Policy/configuration history row and active singleton after migration, binds
active identities to matching history, and repeats those checks in identity
getters. Malformed revisions, digests, timestamps, Policy metadata, or
active/history mismatches fail closed as `AUDIT_UNAVAILABLE`; focused
configuration plus Policy/policy-signer tests pass 26/26 and the
non-overlapping package regression passes 579 total (573 passed, 6 explicitly
skipped, 0 failed). Production Keychain distribution, installed recovery,
external rollback detection, and ADR acceptance remain open. Evidence:
`evidence/2026-09-15-configuration-row-invariants.md`.

Restart-reconciliation clock addendum: source revision `5148a8b` rejects a
recovery timestamp earlier than a persisted Request received/updated time or
Job created/start/heartbeat time before any state transition. Focused Request,
Job, and runtime tests pass 9/9; the non-overlapping package regression passes
582 total (576 passed, 6 explicitly skipped, 0 failed). Crash ownership,
real clock/rollback behavior, production Keychain, installed recovery, and
ADR acceptance remain open. Evidence:
`evidence/2026-09-15-reconciliation-clock-order.md`.

The non-overlapping package regression after the authority-row change reports
565 tests total (559 passed, 6 explicitly skipped, 0 failed). The existing
`broker.test.js` and `persistence.test.js` processes were excluded because
they were already running, so this is bounded local evidence rather than a
fresh full-suite run. Evidence:
`evidence/2026-09-15-authority-row-invariants.md`.

Source revision `a1bd63c` additionally verifies that an already-created
key-manager server rejects status reads immediately after helper-key revocation;
the latest default suite is 400 tests with 397 passed and 3 sandbox tests
skipped.

Source revision `6d6087d` adds the bounded Broker-side client for already-signed
helper commands. It authenticates complete responses and maps transport loss
to retryable `UNKNOWN_OUTCOME`; no privileged adapter or root service is
enabled. Evidence: `evidence/2026-09-13-helper-command-client.md`.

The helper Job executor slice adds a disabled-by-default Broker Job executor above the
client. It renews the Job lease, enforces command-to-Job identity binding,
rechecks authority before/after dispatch, redacts validated helper evidence,
and persists conservative `UNKNOWN_OUTCOME` for unresolved execution. The
executor is not wired to an MCP tool, and helper installation/root launchd
remain blocked. Evidence: `evidence/2026-09-13-helper-job-executor.md`.

The Broker owns the seam through an optional `privilegedHelperExecutor`
dependency and `executePrivilegedHelperJob()`; the default constructor injects
the disabled implementation and performs no privileged dispatch.

The helper command boundary also persists a strict typed payload descriptor and
includes it in the signed envelope. Only Broker-owned service, package, and
power descriptors can cross the helper boundary; raw shell text, executable
paths, environments, credentials, and arbitrary maps remain unrepresentable.
Target, operation, secret-policy, and canonical digest checks run at Job
creation and command validation. This is still disabled and does not unblock
the privileged capability rows.

`MOP-017` process-tree identity addendum: ProcessSupervisor now treats a
changed start-time for an already tracked descendant PID as a target-swap
failure, stops descendant signalling, and preserves unresolved work as
`UNKNOWN`. The deterministic regression is covered; OS PID-reuse timing and
post-snapshot descendant escapes remain open. Evidence:
`evidence/2026-09-14-process-pid-reuse.md`.

## Immediate next steps

1. Close `MOP-080` through `MOP-083` before implementing authority-sensitive handlers.
2. Establish test IDs and automated matrix checks through `MOP-007` and `MOP-085`.
3. Execute `MOP-086` before implementing or enabling `mac_task_run`.
4. Decide `MOP-003` and create the runtime/package baseline.
5. Review the `KB_SYNC.md` writeback manifest before any upstream KB mutation.
6. Implement the local Broker vertical slice before selecting production remote transport.

The Virtualization guest bridge now has a disabled protocol-only seam in
`virtualization-guest-transport.ts`. It is implemented/tested as an
HMAC-authenticated, request/response-bound contract with bounded output and a
BrokerStore-backed replay guard that survives restart. It remains `PLANNED`
for production enablement until a native VM adapter, host/guest credential and
filesystem/network evidence, cancellation/readback proof, and signing are
available. Evidence: `evidence/2026-09-14-virtualization-guest-transport.md`.

Latest guest recovery addendum: commit `c2a7888` adds a separate
HMAC-authenticated status lookup bound to the original task request and a
Broker-owned authority callback. It provides a tested recovery protocol but
now persists the admitted request identity in schema version `7` and
reconciles restart-unknown guest Jobs only through a fresh, authority-checked
status lookup. Only a signed, verified terminal result can close the Job;
unavailable or uncertain status leaves it `UNKNOWN`. This still does not serve
status from a native guest, boot a VM, or enable `mac_task_run`; the capability
remains `PLANNED` for production.

## Definition of Done

A task is `DONE` only when implementation, focused verification, affected regression and security checks, real-Mac evidence where relevant, documentation updates, and final repository readback are complete. Code existence alone is insufficient.

## Related documents

See `EPIC.md`, `ROADMAP.md`, `PROGRESS.md`, `VERIFICATION.md`, and `docs/adr/README.md`.

Privileged-helper status request boundary addendum: commit `026a83f` now
requires plain-data status envelopes before classification, candidate recovery,
`Object.keys`, or field access. Accessor and inherited status fields fail closed
with stable `PRECONDITION_FAILED` behavior. Focused status-boundary tests pass
1/1 and the non-overlapping package regression passes 537 total (531 passed,
6 skipped). This is representation evidence only; Developer ID, root-domain,
production Keychain, real privileged adapter, crash-recovery, and helper
enablement gates remain open. Evidence:
`evidence/2026-09-15-helper-status-boundary.md`.

Helper status readback addendum: commit `e9d67e6` applies the same plain-data
check before readback key enumeration and helper-owned state access. Focused
status request/readback tests pass 2/2; the non-overlapping package regression
passes 538 total (532 passed, 6 skipped, 0 failed). This remains
representation evidence only and does not close helper provenance, root-domain
installation, production Keychain, real privileged adapters, crash recovery,
or enablement. Evidence:
`evidence/2026-09-15-helper-status-boundary.md`.

Broker status request boundary addendum: commit `240ee88` applies the shared
plain-data check before unsigned request key enumeration and field access.
Accessor and inherited request fields fail closed; the focused parser test
passes 1/1 and the non-overlapping package regression passes 538 total (532
passed, 6 skipped). This representation evidence does not close production
deployment, Keychain, remote transport, privileged operations, or capability
enablement. Evidence: `evidence/2026-09-15-broker-status-boundary.md`.

Status-array boundary addendum: commit `987cadc` requires dense bounded
capability arrays in Broker and privileged-helper status readbacks, rejecting
extra enumerable/accessor properties and sparse or symbolic shapes. Focused
status readback tests pass 2/2; the non-overlapping package regression passes
538 total (532 passed, 6 skipped). This remains representation evidence only;
production deployment, Keychain, remote transport, privileged operations, and
capability enablement remain open. Evidence:
`evidence/2026-09-15-status-array-boundary.md`.

Startup-config boundary addendum: commit `345b329` applies the shared
plain-data check before Broker startup configuration key enumeration, path
normalization, or authority checks. Accessor and inherited fixtures are
rejected; the focused startup-config test passes 1/1 and the non-overlapping
package regression passes 538 total (532 passed, 6 skipped). Developer ID,
installed lifecycle, Keychain, remote deployment, helper, and release gates
remain open. Evidence:
`evidence/2026-09-15-startup-config-boundary.md`.

Schema migration readback addendum: commit `7ce59c1` now reads back the exact
schema marker and ordered migration registry inside the migration transaction
before startup recovery. Marker, registry, and tampering tests pass 3/3; the
non-overlapping package regression passes 538 total (532 passed, 6 skipped).
Physical disk recovery, production backups, Keychain deployment, installed
recovery, and release acceptance remain open. Evidence:
`evidence/2026-09-15-schema-migration-readback.md`.

Runtime policy array-boundary addendum: commit `d1f96f2` requires dense bounded
plain arrays for principal scopes, target rules, filesystem roots, deny paths,
tool scopes, and capability families before authorization or discovery.
Focused hostile-array tests pass 2/2; the non-overlapping package regression
passes 539 total (533 passed, 6 skipped). ADR-0004, production signer/Keychain,
installed reload, and capability gates remain open. Evidence:
`evidence/2026-09-15-policy-array-boundary.md`.

Broker family-limit boundary addendum: commit `0a97e3f` requires a plain
data-only `maxActiveRequestsByFamily` object before default-limit merging;
inherited and accessor overrides fail closed. Focused constructor tests pass
2/2; the non-overlapping package regression passes 539 total (533 passed, 6
skipped, 0 failed). Process-wide/adapter quotas, kernel/disk limits,
production packaging, and capability gates remain open. Evidence:
`evidence/2026-09-15-broker-family-limit-boundary.md`.

Durable admission-limit boundary addendum: commit `999435d` applies the
plain-data check inside `BrokerStore.admitRequest` before reading global,
session, or capability-family limits. Focused persistence validation passes
1/1; the non-overlapping package regression remains 539 total (533 passed, 6
skipped, 0 failed). Kernel/process quotas, disk exhaustion, production
service evidence, and capability gates remain open. Evidence:
`evidence/2026-09-15-admission-limit-boundary.md`.

Active approval revalidation addendum: commit `b4cac00` rechecks consumed
mutation approvals during pre-dispatch, active control callbacks, and final
readback. Revocation or expiry cancels active work and prevents success
publication, leaving a started Job `unknown`. Focused Broker verification
passes 1/1; the non-overlapping package regression remains 539 total (533
passed, 6 skipped, 0 failed). Human approval UI/channel, protected Keychain,
unattended ownership, production evidence, and capability gates remain open.
Evidence: `evidence/2026-09-15-active-approval-revalidation.md`.

Edge configuration-shape addendum: commit `04fcffc` requires plain startup
records and dense bounded Host/Origin arrays before URL/path validation or
listener setup. Focused Edge tests pass 2/2; the non-overlapping package
regression passes 540 total (534 passed, 6 skipped, 0 failed). TLS/key
lifecycle, remote deployment, launchd installation, and capability gates
remain open. Evidence: `evidence/2026-09-15-edge-config-shape-boundary.md`.

Contract-registry boundary addendum: commit `fa0dc50` rejects non-data records
and unknown top-level contract fields before MCP construction. Focused registry
tests pass 2/2; the non-overlapping package regression passes 541 total (535
passed, 6 skipped, 0 failed). Handler completeness, signing provenance,
remote deployment, and capability gates remain open. Evidence:
`evidence/2026-09-15-contract-registry-boundary.md`.

MCP capability-readback addendum: commits `0b8c7e2` and `3f65dc8` enforce
plain response data, dense bounded capability arrays, governed fields, and
optional Broker `scopes`/`reason` metadata before tool registration. Focused
Edge tests pass 2/2; the non-overlapping package regression passes 542 total
(536 passed, 6 skipped, 0 failed). Broker handler completeness, remote
deployment, and capability gates remain open. Evidence:
`evidence/2026-09-15-mcp-capability-boundary.md`.

Principal-projection boundary addendum: commit `ce198e1` rejects non-data
identity metadata and accessor/sparse/symbolic scope arrays before governed
principal creation. Focused projection tests pass 3/3; the non-overlapping
package regression passes 543 total (537 passed, 6 skipped, 0 failed). OAuth
provider correctness, key rotation, remote deployment, and capability gates
remain open. Evidence:
`evidence/2026-09-15-principal-projection-boundary.md`.

Direct policy-input boundary addendum: commit `88d9179` validates dense known
scope arrays and canonical plain target records inside exported authorization
helpers before matching or grant lookup. Focused policy tests pass 2/2; the
non-overlapping package regression passes 544 total (538 passed, 6 skipped, 0
failed). Production signer/Keychain, installed reload, and capability gates
remain open. Evidence: `evidence/2026-09-15-policy-input-boundary.md`.

Scope-list boundary addendum: commit `cb704af` validates principal scope
arrays at request parsing and direct tool authorization. Duplicate, unknown,
sparse, and oversized lists fail with `AUTH_INVALID` before policy lookup;
focused policy/security-fuzz verification passes 15/15; the non-overlapping
package regression passes 545 total (539 passed, 6 skipped, 0 failed).
Production token issuance, cross-process identity packaging, and capability
gates remain open.
Evidence: `evidence/2026-09-15-scope-boundary.md`.

Target-grant boundary addendum: commit `d785eb0` requires an enabled principal
grant and in-grant scopes inside `authorizeTarget` before target-rule matching.
Disabled grants fail with `POLICY_DENIED`; out-of-grant scopes fail with
`SCOPE_DENIED`. Focused policy/security-fuzz verification passes 16/16; the
non-overlapping package regression passes 546 total (540 passed, 6 skipped, 0
failed). Production policy distribution and capability gates remain open.
Evidence: `evidence/2026-09-15-target-grant-boundary.md`.

Kill-switch isolation addendum: commit `6bf29d4` narrows the `mutations`
queued-Job reconciliation to an explicit mutation tool allowlist, preserving
read-only queued work while retaining the global all-capability stop. Build and
a temporary BrokerStore smoke pass; the non-overlapping package regression
remains 546 total (540 passed, 6 skipped, 0 failed). Process ownership,
physical resource limits, and production service evidence remain open.
Evidence: `evidence/2026-09-15-kill-switch-scope-isolation.md`.

Fail-closed kill-switch addendum: commit `fe6a187` preserves only a bounded
known-read-only tool set when `mutations` is disabled; unknown or future tools
are cancelled until explicitly classified. Build and a temporary BrokerStore
smoke pass; the non-overlapping package regression remains 546 total (540
passed, 6 skipped, 0 failed). Process ownership, physical resource limits, and
production service evidence remain open. Evidence:
`evidence/2026-09-15-kill-switch-fail-closed.md`.

BrokerStore Request state invariants are now enforced at the persistence
readback boundary (source revision `f607f41`). Stored request states must agree
with their result class, mutation approval and Job linkage, and lifecycle
timestamps must be monotonic; malformed rows fail closed as
`AUDIT_UNAVAILABLE`. Focused request corruption tests pass 3/3 and the
non-overlapping package regression passes 558 total (552 passed, 6 skipped, 0
failed). Disk exhaustion, production identity, and final ADR acceptance remain
open. Evidence: `evidence/2026-09-15-request-state-invariants.md`.

Audit-event readback invariants are now enforced at the persistence boundary
(source revision `ed22f71`). Audit sequence ordering, bounded identity/text
fields, event/decision enums, timestamp, hash shape, and strict evidence JSON
are validated before audit verification or caller readback. Focused audit-row
corruption tests pass 1/1 and the non-overlapping package regression passes 559
total (553 passed, 6 skipped, 0 failed). Evidence:
`evidence/2026-09-15-audit-row-invariants.md`.

Audit events are now validated before persistence as well as on readback
(source revision `3cc9c80`): malformed identity/text, event, decision,
timestamp, or evidence budgets fail closed before an SQLite row is written.
Focused audit write/read tests pass 2/2; the non-overlapping package
regression passes 560 total (554 passed, 6 skipped, 0 failed). Evidence:
`evidence/2026-09-15-audit-row-invariants.md`.

MOP-086 current-host readback was rerun at source revision `633f538`: the
physical Mac mini sandbox profile suite passes 16/16 with no skips. This is
fresh host evidence only; deprecated `sandbox-exec`, credential-content,
remount, crash/restart, Docker/persistence, process-tree, packaging, and
independent review gates remain open. Evidence:
`evidence/2026-09-15-real-sandbox-16-tests.md`.

The current physical-host `mac_app_list` readback passes 4/4 at source revision
`c4bf986`, including the real running-app inventory case and fixed-command,
bounded-result, redaction, and malformed-result checks. This remains read-only
host evidence; GUI mutation, Accessibility permission, packaging, and final
readback gates remain open. Evidence:
`evidence/2026-09-15-app-inventory-host-readback.md`.

The current physical-host Accessibility probe for Finder fails closed with
stable `POLICY_DENIED` when Accessibility permission is absent, without
returning UI content. Permission-granted observation, focus races, GUI
mutation, packaging, and final readback remain open. Evidence:
`evidence/2026-09-15-ui-permission-denial-host-readback.md`.

The current production dependency audit reports zero high-severity-or-greater
npm advisories with `npm audit --omit=dev --audit-level=high`. This is
point-in-time dependency evidence only and does not close native signing,
runtime isolation, or release review gates. Evidence:
`evidence/2026-09-15-dependency-audit.md`.

The L5 privileged-helper boundary suite passes 38/38, covering independent
peer/HMAC authentication, replay rejection, fixed operation allowlists, typed
payloads, helper-owned status, trailing frames, denied peers, Job binding, and
active revocation. No root command or real privileged mutation was executed;
production signing, installation, Keychain, approval UI, and enablement remain
gated. Evidence: `evidence/2026-09-15-helper-boundary-38-tests.md`.
