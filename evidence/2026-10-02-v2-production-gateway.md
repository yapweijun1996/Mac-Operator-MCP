# V2 production development gateway — 2026-10-02

Requested V2 acceptance: **DONE, 100%, 11/11 completion gates PASS**.
Source, physical enforcement, actual YAP and public end-to-end workflows passed.
Runtime implementation `6e332f1d3adeaaccdb100a03cf0a990b3fef96ad` is merged to local
main. Protected final deployment evidence records the exact immutable release,
source revision, native artifact, service restart and saved supervisor state.

The owner authorized the complete implementation, testing, local commit/main
merge and live deployment without additional implementation questions. No push
or PR publication is authorized by ordinary coding approval.

## Runtime identity and physical evidence

- Image: `sha256:540f2d2753dc5674d05ec0cb7963a1fbb75b77f1fdeaa63c48a3825660aa01c4`.
- Engine: `f8fbb9ed-402f-4ff7-b672-fc10a3401347`; Docker Desktop 29.1.3,
  Linux ARM64/cgroup v2; image Node v24.21.0.
- Codex: 0.153.4; executable SHA-256
  `b973d440acac501fd2594a43e7ca9ce41e0a65b9dfb28d0d7a7837c99e1261e3`.
- Physical security validation passed 17/17 in a final single run and two
  simultaneous independent runs. It used the actual Engine and SQLite,
  including a child Broker SIGKILL and independent PID1 deadline.
- Actual Codex read/write and strict argument-correction canaries passed.
  Private evidence is retained outside Git without authentication values.

## Required test mapping

| Requirement | Evidence |
| --- | --- |
| 1 Authorized read | Existing native/Broker regression; actual YAP discovery/summary |
| 2 Unauthorized project denied | Gateway/Broker policy and exact registry tests |
| 3 Secret path denied | Snapshot/tool/native tests; actual filtered secret fixture |
| 4 Symlink escape denied | Native/snapshot tests; actual input filtering and no host mounts |
| 5 Traversal denied | Strict snapshot/tar/tool schema and path tests |
| 6 Worktree creation | Actual YAP and Git hook-isolation fixture |
| 7 Duplicate worktree idempotency | Actual same YAP create request |
| 8 Codex readonly | Actual native Codex/YAP job; no source change |
| 9 Codex workspace-write | Actual native Codex/YAP synthetic test edit |
| 10 Codex cannot escape | No model-visible host tools; exact allowed paths; physical no mounts |
| 11 Codex cannot read `.ssh` | Secret-zone/tool denial; `.ssh` excluded; host filesystem deny |
| 12 Codex cannot use sudo | No host shell; actual nonroot/zero caps/no privilege escalation |
| 13 Test success | Actual registered YAP test and named task jobs |
| 14 Test failure | Actual physical command exit failure; lifecycle regressions |
| 15 Timeout | Actual detached descendants, independent PID1 deadline and exact cleanup |
| 16 Cancel | Actual durable cancellation/cleanup; Broker cancel/revocation races |
| 17 Malformed command rejected | Actual admission rejection; fixed registry/schema tests |
| 18 Stage explicit paths | Git/Broker path requirement; actual YAP single-file stage |
| 19 Commit | Actual YAP local commit; configured-hook fixture |
| 20 Push denied | Policy/Gateway tests; public policy explain |
| 21 Audit | Durable pre-start ownership and per-path import audits; actual YAP query |
| 22 Explain never executes | Policy-planner regression and public inventory before/after |
| 23 Primary unchanged | Actual YAP HEAD/index/source/status equality |
| 24 Concurrent isolation | Two physical task identities; parallel complete physical runs |
| 25 Restart recovery | Actual Broker SIGKILL → UNKNOWN retained → deadline → exact cleanup/no replay |

The final evidence below distinguishes unit doubles, actual local fixtures,
physical enforcement, inference and public deployment; skips never count as passes.

## Actual YAP workflow

Project: `cloudflare-tunnel-server-001` on this Mac mini. Primary HEAD:
`4815f2d703477df4fccb96ab95ed4c1c1ff03577`.
Task: `v2-yap-e2e-20261002-final`; branch:
`codex/mac-operator-v2-e2e-20261002-final`.
Synthetic local commit: `e24ffbb64b9efd5895a03fef37dcdb46d140483b`.
The real private Broker completed 21 successful tool calls in 164104 ms,
including duplicate create, preflight, readonly/writer inference, diff, tests,
named task, build, explicit stage, local commit, review and bounded audit.

Codex added one synthetic credential-filter test to
`scripts/test-isolation.test.js`; no production helper or manifest changed.
Tests use the existing `test:isolation` manifest script. Build validates the
existing `site/package.json` `tsc -b && vite build` command through the reviewed
fixed guest launcher. Pinned Linux dependencies stay immutable; only Vite's
cache directory is task-local. No package installation runs inside task authority.

Primary index SHA-256 before/after:
`90098c45d2991e3be8beb4eda3576bedc69cd6ea71ec658393ae624263447248`.
Primary test source SHA-256 before/after:
`a3a9c27040f07fc2e592f466e1c4893dbb09a75337118c08c2fc699384f96777`.
Status before/after: only preexisting `?? .claude/settings.local.json`.
Primary HEAD was unchanged. The synthetic branch remains local; no push/merge.

Final private physical evidence hashes (single, parallel A, parallel B):

- `dc03bc05842ada3b2b18116ad5778517953ad31c6b4c0111f3527be838829008`
- `8d4db7a80976ace4d160ebd1ca8636b8de02ec89f69f15628e68f68b872b3ba0`
- `0d9a77efafe0475e8b07b058b56faaeb941046472916e86af7c6a61cebf6c0d8`

The combined sixteen-check acceptance file has SHA-256
`960c1ecb43803a0fce3fc5fd4c6691227e9a0886ef3cac3a11209b64c8b36ad3`.
It maps genuine physical and YAP results, not unit readiness declarations.
Private acceptance copies are retained under `MacOperator/v2-provisioning/accepted-v2`
with mode 0400/0700. Production config requires its exact digest and runtime IDs.

## Failures found and corrected during acceptance

- Docker archive APIs could not safely stage/export tmpfs under readonly rootfs;
  fixed bounded staging and quiescent export retained the original isolation rules.
- Renewable leases were incorrectly measured from initial acquisition and failed
  after long staging. The verified lease is now bounded from latest heartbeat;
  real SQLite renewal/reopen/cancel/clock-rollback cases pass.
- Host filesystem denial confused the inference model about separately authorized
  gateway writes. Trusted instructions now bind the profile and actual tool names;
  no host permissions or schemas were broadened. Rejected schema arguments cannot
  invoke handlers; bounded correction can submit a new valid operation.
- Vite's default cache could not write through an immutable dependency symlink.
  A new digest-pinned image creates task-local cache parents and retains immutable
  package targets. Its actual build and all physical checks pass.
- A partial-clone fixture reproduced lazy remote-helper execution. All governed
  Git disables lazy fetch/transports and hooks. Actual hostile helper fixtures pass.
- Named tasks now reject unresolved same-worktree jobs as well as coding/validation
  jobs; original-project audit attribution is preserved. UNKNOWN encrypted archive
  round-trip retains identity and cannot report recovery as success.
- Public staging exposed a Docker connection `EPIPE` while registering an
  unstarted exec. Exact fixed errno/operation diagnostics do not expose backend
  messages. Bounded recovery repeats only reads/unstarted registration within
  the same deadline; unique-ID tests prove no task replay. Exec-start, lifecycle
  mutations, status errors, malformed responses and identity failures never retry.
- Parallel operator probes exceeded the existing 100-request/60-second Edge
  limit. The verifier now polls managed jobs every two seconds. Production rate
  limits and task execution permissions were not relaxed.

## Public deployment acceptance

Fresh public OAuth coding consent exposes exactly 27 scopes/48 tools and excludes
`mac.terminal.exec`. Existing read grants expose 29 tools (27 legacy plus two
safe read additions); 26 real legacy read calls and revocation passed.

Two full public coding workflows passed on the accepted runtime. They created
fresh worktrees, reused duplicate creation/task identities, ran actual Codex
readonly and workspace-write jobs, executed registered test/build commands,
reviewed the one-file diff, staged explicitly, committed locally and prepared
review evidence. Primary HEAD/index/source/status were identical before/after;
push was denied. Clean worktrees were removed, retaining their local branches:

- `codex/public-v2-99348726de927826`: `9d61b177e02f02d1fac21285fa8281e3162bbc06`.
- `codex/public-v2-fcefea6fd37d3f98`: `5d991c2257d1cd419c7ebe0dc9a7c6f1743a15a3`.

Six failed operator canaries were removed only after exact provenance and clean
Git readback. Private synthetic worktrees were removed through Broker approval
and audit; the one known failed synthetic edit was archived and restored first.
Other user worktrees and the primary's preexisting `.claude` file were preserved.

Additional physical evidence SHA-256:

- Diagnostic runtime: `421d6a47c897d513ce7c7c8c90d537e01b5753448c0559c868b2f97fb1adfdff`.
- Bounded recovery: `01c48a3d3472112f454c937b198d28da3f35d6d73a15354bce2714f1b3b55b94`.
- Deployed runtime: `fa19c416df7c1a3b9a5af4c9fe3e36954fcd572ebcef746b36ff381829c1f2f1`.
- First public workflow: `518d866de9aa25acf1621432eabf4e7181dc09b3c5d86cd42186a0845ecef7cb`.
- Exact public cleanup: `657db067f0b80ca86ae2f208799c936c26edbc40584b163f2b857a3459118131`.

Failed historical jobs remain failed/unknown as observed; they were not rewritten
as successes. New evidence uses new task/request identities. Independent source
review found no unresolved substantiated P0/P1. Migration is fsynced per file but
not atomic across database/files; a full stopped backup is mandatory.

## Final source verification

Standard `npm test`: **1595 total, 1577 PASS, 18 SKIP, 0 FAIL**.
Native builds and TypeScript passed. The 18 skips are explicit opt-in host
checks; the container check was separately exercised against the final image
six times, including the deployed runtime, with zero skips. No skip is counted
as a pass. A final-release physical readback is retained separately.
Strict contracts: 57 unique schemas and the schema-20 ledger record verified.
Style: 1197 tracked inputs. Docs: 40 README links/8 runbooks. Verification
matrix: 29 targets/25 threats/31 tasks/19 evidence references. Process-boundary
audit: five reviewed production boundaries and zero unreviewed entries.
Native canonical JSON: 5/5. Production dependency audit: zero vulnerabilities.
Independent acceptance review: no unresolved substantiated P0/P1.
