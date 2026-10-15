# BUG-42 through BUG-44 remediation — 2026-10-15

Status: **DONE locally**. Base: `a7d599934d3def5105b24871cf5229d75fecea24`
(`main`), preserving the preceding uncommitted BUG-38–41 fixes. No commit,
push, deployment, service restart or live configuration change occurred.
The report contains **53 findings: 44 fixed locally and nine open**
(BUG-45 through BUG-53).

## Changes and boundary decisions

| Bug | Root cause | Correction |
| --- | --- | --- |
| BUG-42 | Snapshot/tar/staging and atomic replacements discarded execution permission. | Capture owner execution from identity-checked host metadata; carry a validated boolean through tar/staging; normalize writable files to 0700/0600 and readonly files to 0555/0444. Set execution only after size/hash verification. Preserve execution during guest edits and host import. |
| BUG-43 | Stop read one byte of output to obtain final state, invoking the normal UTF-8 size guard. | Read final state/exit code from the manager's committed outcome, without reading output. Persistence still completes before finished becomes visible. |
| BUG-44 | Fatal UTF-8 decoding treated a valid character cut by the page limit as invalid text. | Use a shared dependency-free strict decoder in the host worker and embedded guest program. Defer only a valid incomplete trailing character, and advance by actual returned bytes. |

Execution permission has one authority on each side of the import boundary.
The container receives only a restricted owner-execution marker, never arbitrary
modes. Host import ignores the guest marker and preserves execution only from
an existing regular host inode. Newly created and previously nonexecutable host
files remain nonexecutable; setuid/setgid/sticky and group/other permissions
are not copied. Ordinary host write APIs retain their existing behavior.

The optional native writer argument is used only by snapshot import. The new
`nativeSourceExecutablePreservationVersion: 1` capability is required before
using it, so older addons fail closed. The native writer applies the normalized
mode on the private temporary descriptor before fsync and rename, using the
existing identity/path/authorization checks. No post-rename host chmod or public
permission-changing tool was introduced. Source and native artifacts must be
rebuilt, accepted and rolled back together. No persistent-format migration or
new dependency is required.

UTF-8 decoding still rejects invalid bytes, incomplete EOF, offsets inside a
character and a cap too small for the next complete character. A nonempty page
never returns an unchanged continuation cursor. Existing BOM decoding behavior
is preserved, but returned-byte counts and hashes include its original bytes.
Host secret scanning covers the original captured window before any shortening;
guest tool-result secret screening remains unchanged. Base64 ranges and metadata
semantics remain unchanged.

`mac_read_file` adds optional output-schema fields `bytes_returned` and
`next_offset`; the implementation emits both. Continue using `next_offset`
until null. Metadata has zero bytes and null continuation. `sha256` covers the
actual returned original bytes, not the requested cap or deferred character.
Guest reads retain their existing `nextOffset` shape with corrected values.
Existing clients may ignore the additive fields; strict schema consumers must
use the updated contract. No existing required field was removed or renamed.

## Regression evidence

The first failing run against the original snapshot/stop implementation had
46 tests: **41 passed and five failed** (two snapshot mode cases, three
multibyte stop cases). After the initial transfer fix, the shipped guest edit
program still failed the executable-mode assertion; that replacement path was
then corrected as part of BUG-42. Original host/guest default-cap failures are
also preserved in the [review evidence](2026-10-15-codebase-review.md).

The final revision adds **34 regression cases**:

| Area | New cases | Coverage |
| --- | --- | --- |
| Native snapshot/import | 4 | Writable/readonly tar mode round trips; executable replacement; guest cannot grant host execution; special-bit stripping; older-native denial before mutation. |
| Shipped guest programs | 7 | Actual fixed staging/read/edit programs in descriptor-path fixtures; writable/readonly modes; execution of staged scripts; malformed markers/hash failure before execution; default UTF-8 caps, continuation, too-small/unaligned ranges, malformed bytes and incomplete EOF. |
| Terminal manager/dispatch | 6 | Empty, ASCII and 2/3/4-byte unread output; repeat stop; stop while completion is pending; committed cancellation state; drained output remains readable. Existing redaction/read/finalization tests still pass. |
| Host filesystem worker | 3 | Actual native/worker default-cap reads for 2/3/4-byte characters; complete reconstruction and exact hashes/counts; malformed data, incomplete EOF, too-small/unaligned ranges and base64 preservation. |
| Shared UTF-8 decoder | 14 | Every partial prefix of 2/3/4-byte characters, invalid lead/continuation/overlong/surrogate/out-of-range encodings, BOM, empty EOF and exact boundaries. |

The existing signed Broker range test additionally verifies public byte-count
and continuation fields. The existing Engine transport assertions cover the
updated readonly sealer. No live container is used by these fixtures. The guest
fixture substitutes Linux descriptor paths and guest UID only, executing the
actual shipped JavaScript. Its execution check runs only a disposable fixed
shell script with explicit cwd, empty environment, no shell wrapping, a five
second timeout and an 8 KiB output cap.

A first host-worker test attempt hit the executor's intended capacity gate
because a completed result precedes worker exit. The harness now waits for
capacity release before its next read, matching the established test pattern;
no production capacity behavior was changed or assertion weakened.

## Final verification

| Check | Result |
| --- | --- |
| Build, including native stages | PASS |
| Native fault-test addon build | PASS |
| TypeScript typecheck | PASS |
| Current-source suite: 244 compiled/script test files | **2,306 total; 2,287 passed; zero failed/cancelled; 19 skipped** |
| Final native snapshot/import and shipped guest-program suites | PASS: 36 tests |
| Final host-worker suite | PASS: 7 tests |
| Style, documentation, matrix and process-boundary checks | PASS |
| Contract/catalog/ledger validation | PASS: 58 unique contracts |
| Final diff/whitespace and current finding counts | PASS |

Runtime: Node.js `v25.5.0` on macOS. The suite enumerated every current
`packages/*/src/**/*.test.ts` and root `scripts/*.test.mjs`, including untracked
new tests, required corresponding compiled artifacts to exist, and ran
`node --test --test-timeout=120000` on those 244 files. It excludes only the two
previously identified obsolete ignored compiled tests with no current source;
their three historical `npm test` failures are not claimed resolved and the
artifacts were preserved. Relative to the preceding source-backed suite,
34 new cases explain the increase from 2,272 to 2,306 tests.

No fresh Node 24 run, live Docker/image/profile acceptance, real Linux readonly
permission enforcement, privileged deployment or production service check was
performed. The 19 existing opt-in/platform/integration skips remain unverified.
The disposable scripts prove execution and mode behavior on the host fixture;
they do not establish physical container isolation. Follow the existing
[V2 acceptance workflow](../docs/MAC_OPERATOR_V2_RUNBOOK.md) before deploying.

KB-MCP project recall and previously retrieved SCMC/code-documentation sync
skills informed the investigation; current source and regression results own
these conclusions. The optional reuse-context preflight connector rejected
its caller payload shape; it did not provide additional verified reuse evidence.
No remote implementation was reused based on that failed request.

A targeted end-of-task recall found no matching duplicate. The dated local result
and reusable permission/pagination boundaries were saved as an agent-inference
memory (`ef9a01bc-87c8-48a7-ab32-dd65ab6eebff:59648711-a413-412f-a335-534d8caf9906`);
KB-MCP confirmed the write. Future use still requires current-source verification.
