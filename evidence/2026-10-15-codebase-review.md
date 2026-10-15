# Codebase Review Evidence — 2026-10-15

Status: **Historical review baseline — review/documentation completed with 16 new P2 defects OPEN.**

Subsequent authorized remediation fixes BUG-38 through BUG-41 locally;
12 findings remain open. Current results and limits belong to the
[repair evidence](2026-10-15-bugs38-41-remediation.md).

## Identity and scope

- Date: 2026-10-15, Asia/Kuala_Lumpur.
- Source: `a7d599934d3def5105b24871cf5229d75fecea24`, branch `main`.
- Starting worktree: clean. Final intended changes: Markdown only.
- Runtime used for checks: Node.js `v25.5.0`, macOS. Node 24 was not separately tested.
- Deliverable: [current findings and retained history](../CODEBASE_BUG_REVIEW.md).
- No source repair, commit, push, policy/state migration or deployment was performed.

The review used one primary reviewer and three independent read-only reviewers.
Experiments used disposable repositories, files, stores, sockets, and dependency
fixtures; they did not use real OAuth accounts or mutate a production service.
The primary reviewer separately reproduced BUG-38's shutdown failure in addition
to the originating reviewer's startup/shutdown checks.

## Knowledge and Skill evidence

KB-MCP project recall returned historical repair/deployment memories. Several
carried newer-evidence or unverified warnings; they were treated as leads and
checked against this source revision, not copied as current open bugs.

Skill Registry search/get supplied:

| Skill | Version | Registry reference | Applied requirement |
| --- | --- | --- | --- |
| `engineering:scmc-review` | 1.0.0 | `270d896a-12b0-40b4-856f-f6274d872c95:f9e45147-7c67-424b-86a7-4d9bbeb131c7` | Concrete consequences, root causes, bounded recommendations and preserved invariants |
| `project:code-docs-source-of-truth-sync` | 1.0.1 | `270d896a-12b0-40b4-856f-f6274d872c95:69041ed0-2609-45bf-9b7a-57a4e1f0801c` | Current source/test truth, explicit scope/status and preserved historical evidence |

The SCMC get response included a bounded wrapper with metadata truncation. Its
complete `content` string was available in the returned preview and was read;
the documentation-sync skill returned its complete content directly.

Memory decision: the end-of-review duplicate/context lookup returned
`503 UPSTREAM_UNAVAILABLE` on repeated reads. No memory write was attempted
without that check. The early recall and Skill reads succeeded; the repository
documents retain the completed review independently of KB availability.

## Verification results

| Check | Observed result |
| --- | --- |
| `npm test` build and native fault-test build, host run | PASS |
| `npm run typecheck` | PASS |
| `npm run lint` | PASS for the existing 1,293 tracked files |
| `npm run verify:docs` | PASS: 48 README links and eight required runbooks |
| `npm run verify:matrix` | PASS: 29 targets, 25 threats, 31 tasks, 19 evidence references |
| `npm run verify:process-boundaries` | PASS: no unreviewed entries |
| `node packages/contracts/dist/verify-contracts.js` | PASS: 58 contracts, catalog links and ledger schema |
| Current tracked-source test files | PASS: 2,246 tests; 2,227 passed, zero failed/cancelled, 19 skipped; 242 files |
| Ordinary `npm test` glob, host run | FAIL: 2,250 tests; 2,228 passed, three failed, 19 skipped |
| Final Markdown verification | PASS: whitespace, local link targets and all 16 finding table/detail IDs agree |

The first restricted-sandbox test attempt failed on denied local listeners,
compiler temporary-file creation and process/environment effects. A normal
host run was then approved automatically and executed; those environment
failures were not counted as product defects.

The three remaining failures in the ordinary host command come exclusively
from two ignored compiled files with no corresponding current source:

- `packages/broker/dist/native-peer-ipc-server.test.js`: one stale parent-GID assertion.
- `packages/broker/dist/owner-terminal-session-contract.test.js`: two stale terminal-schema assertions.

No compiled file was deleted or assertion weakened. To distinguish stale local
artifacts from current code, the second host run enumerated tracked
`packages/*/src/*.test.ts` and `scripts/*.test.mjs` using `git ls-files -z`, mapped
each source test to its compiled `/dist/` counterpart, required every mapped
file to exist, and invoked `node --test --test-timeout=120000` with exactly
those 242 files. The clean result applies to that current-source set; it does
not claim the ordinary glob command passed in this checkout. The earlier
review already disclosed obsolete compiled tests; this is retained as a
verification-environment limitation rather than a newly discovered runtime bug.

Scratch logs, not permanent evidence dependencies:

- `/private/tmp/mac-operator-review-20261015-tests.log`: restricted attempt.
- `/private/tmp/mac-operator-review-20261015-host-tests.log`: broad host command.
- `/private/tmp/mac-operator-review-20261015-current-tests.log`: tracked-source run.

## Reproduction matrix

These are trigger experiments against unchanged source. Their expected failure
outcomes establish findings, not passing regression tests for future repairs.

| Finding | Executed boundary | Observed trigger result |
| --- | --- | --- |
| BUG-38 | Actual root-helper runtime, injected server lifecycle | Status close throws; runtime failed; command close uncalled and fixture listening |
| BUG-39 | Actual Edge status client, protected temporary Unix socket | Partial EOF; configured 100 ms; still pending after 502 ms |
| BUG-40 | Actual auto-deploy lock function, temporary directory | Missing PID returns `ENOENT` on two successive attempts |
| BUG-41 | Actual Git and managed-worktree implementation | Successful removal, recreated same-name merged branch, replay removes new ref |
| BUG-42 | Actual native snapshot; actual staging program in VM fixture | Source `0755`, archive/staged `0600`, direct invocation `EACCES` |
| BUG-43 | Actual terminal manager and dispatch | Multibyte output; stop finishes process but returns `PRECONDITION_FAILED` |
| BUG-44 | Actual host worker; actual guest program in VM fixture | Default byte boundary splits valid character; host/guest reject; aligned control succeeds |
| BUG-45 | Actual Auth/Broker stores and GUI approval implementation | 1,000 revoked browser or desktop grants, zero active; insertion fails after prune |
| BUG-46 | Actual configuration schema and authorization | Both IDs accepted; short control grants access, 80-character ID silently fails |
| BUG-47 | Actual inventory script/parser, simulated ObjC | 501 installed + unique running app; 500 total / zero running-only, truncation false |
| BUG-48 | Actual inventory/controller, simulated ObjC; read-only system metadata check | Standard Utilities bundle absent; open returns `TARGET_NOT_FOUND`, no launch attempted |
| BUG-49 | Actual package inspector, temporary `pyproject.toml` | Inline two-dependency array returns zero, no warnings; multiline control returns two |
| BUG-50 | Actual native filesystem inspector | `Example.xcodeproj/` returns no Swift project, truncation false |
| BUG-51 | Actual native filesystem inspector | Two Python markers on separate directory pages return duplicate root/type |
| BUG-52 | Actual native filesystem inspector | Depth-17 project omitted with truncation false; narrowed-root control finds it |
| BUG-53 | Actual signed requests to temporary Broker | Explanation allows metadata-only text-search root; execution denies content read |

The retained scratch fixtures are `/private/tmp/mac-review-broker-repros.mjs`,
`/private/tmp/mac-review-guest-repros.mjs`,
`/private/tmp/mac-operator-auth-edge-review-20261015.mjs`, and
`/private/tmp/mac-operator-review-native-deploy-20261015.mjs`, with matching
JSON/log output alongside them. They are temporary convenience artifacts;
the report's source locations, trigger descriptions and matrix above retain
the durable finding evidence if the temporary directory is cleared.

Guest-script fixtures execute the actual embedded source with VM filesystem
adapters mapping Linux `/workspace`, `/proc/self/fd` and UID behavior to a
temporary directory. They establish parsing, staging and mode behavior; they
do not establish actual Docker confinement or deployed container acceptance.
App-inventory fixtures execute the actual JXA program with simulated ObjC
metadata and the real result parser/controller. They do not establish live
GUI state or exercise actual app launches.

## Coverage and limits

| Review area | Work performed | Material limitation |
| --- | --- | --- |
| Auth, OAuth, Edge HTTP/MCP/JWT/IPC and contracts | Main-path source tracing, GUI grant and IPC reproductions, existing suite | No real identity provider, account flow or authenticated external endpoint |
| Broker admission, policy, persistence and filesystem | Focused authority/lifecycle/export/parser tracing; signed diagnostic and native filesystem reproductions | Large Broker/store files were reviewed selectively, not every branch |
| Git/worktrees, container transfer/tasks, Codex and terminal | Focused source tracing; real temporary Git/snapshot/terminal checks; guest fixtures | No live Docker/Engine, inference, remote push or production worktree |
| Native GUI, application inventory and deployment | Focused native/source and lifecycle review; script/ObjC/deploy-lock fixtures | No real GUI manipulation, permission changes, launchd/root installation or release cutover |
| Root-helper, privileged and virtualization paths | Focused lifecycle and failure-path inspection; runtime fixtures | Large native files were inspected selectively; no real root/VM lifecycle, signing or notarization acceptance |

The 19 opt-in/platform/integration skips remain unverified. Existing production
configuration/provenance findings and PM2 behavior were not rechecked. No npm
advisory lookup, remote scan or live service health claim is included.
Unsubstantiated hypotheses were excluded; no confirmed P0/P1 remained unresolved
within the reviewed findings. Further review may discover additional defects.

## Handoff

At this review handoff, all 16 new findings were open in unchanged source. The
recommended first implementation phase was lifecycle cleanup,
bounded status reads and removal replay first; retain independent authorization,
consent, secret filtering, read-only profiles and exact resource ownership.
Add regression cases for each trigger during the repair phase, then repeat the
affected suites and any necessary physical acceptance before deployment.
