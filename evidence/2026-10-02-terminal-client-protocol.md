# Native owner terminal protocol acceptance

Status: PASS. Scope: the owner's selected independent O1 connection, authenticated
native Codex execution, focused commits, local main merge and live deployment.
No remote push was performed. This supplements the existing V2 acceptance; it
does not grant owner-shell authority to the default V2 resource.

## Problem and architecture

The saved Codex registration was authenticated, but its `2025-06-18` initialize
request was rejected by the modern-only SDK handler. Earlier public probes
pinned `2026-07-28` and therefore missed the native consumer. The existing owner
terminal implementation subsequently added stateless SDK compatibility and
request cancellation guards in `8066356`; its callback/consent setup and verified
native execution are retained from `5032f64` and `17d8288`.

Focused implementation `d30a8ce` restricts compatibility to the exact independent
terminal issuer/resource and 24 O1 scopes. It accepts only `2025-06-18` legacy
traffic, requires its protocol header after initialization, rejects batches,
unknown/conflicting versions and malformed modern claims, and preserves valid
request IDs in errors. Modern requests remain SDK-validated. The same governed
factory, bearer verifier, scope projection, Broker policy, managed jobs and
revocation checks serve both eras. No dependency or persisted schema changed.

The primary endpoint cannot opt into legacy compatibility. HTTP/tool abort
signals remain combined, including already-aborted requests before/after async
capability discovery. A separate stateless cancellation notification cannot
reference another POST; close the active request or cancel its observed job.

| Resource | OAuth scopes | Tools | Protocol boundary |
| --- | ---: | ---: | --- |
| `/mcp` | 27 V2 | 48 | `2026-07-28`; owner terminal absent; push denied |
| `/terminal/mcp` | 24 O1 | 43 | `2025-06-18` and modern; explicit owner terminal consent |

O1 runs as the existing macOS owner within OS permissions. It is separately
authorized HIGH_RISK access, with no claim of V2 worktree isolation or admin/TCC
privilege. Normal coding approval does not grant O1 authority. Issuer/audience
separation, minimum scopes, body/rate/Host/Origin limits and durable audit/job
authorization remain in place. No credential was extracted or forwarded.

## Verification

| Check | Result |
| --- | --- |
| Focused HTTPS/factory tests, including cancellation windows | 24 PASS |
| Implementation full build/regression | 1,598 PASS; 18 existing opt-in SKIP; 0 FAIL |
| Combined deployed GUI + Edge source regression | 1,600 PASS; 18 existing opt-in SKIP; 0 FAIL |
| Typecheck, style, documentation, process-boundary review | PASS |
| Independent read-only review | PASS; two P2 findings fixed and retested |
| Saved native OAuth manager | `oAuth`, `connected`, 43 tools |
| Native `mac_health` | healthy |
| Native `printf O1_CONNECTION_OK`, cwd `/tmp`, timeout 5 seconds | exit 0; exact output; completed durable job |
| Native execution request | `818888aa-09c0-402c-88e0-c5ddce45e086` |
| Public modern V2 OAuth | 48 tools, 26 reads; terminal absent; next request rejected after revocation |
| Public modern O1 OAuth | 43 tools, 26 reads; 31-second shell, CLI, network, temporary write/read, idempotency and job status PASS |
| Terminal timeout and active grant revocation | PASS; cancelled job and cleared process ownership verified |
| Supervisor / active jobs | online; 0 automatic/unstable restarts; 0 active jobs |

The native check used the documented Codex app-server status/direct-tool APIs
with its saved OAuth manager and no AI turn. Its successful command and job
readback prove actual execution, rather than relying on a model's final answer.
The app's foreground UI was unavailable to automation; no UI workaround was used.

An initial assembled-release test attempt failed because Git fixtures clone
their checkout, while release directories intentionally omit `.git`; packaged
GUI tests were also older than its implementation. The corrected combined run
used an isolated Git checkout with the exact GUI source snapshot, refreshed
tests, and byte verification of every deployed production JavaScript module.
A first V2 probe defaulted to the protected release directory and correctly
received POLICY_DENIED. Repeating it against the authorized primary project
passed. These failed harness attempts are retained in protected evidence.

## Source, rollout and preservation

Branch: `codex/terminal-client-protocol`. Code commit: `d30a8ce`. Integrated Edge
source: `a4da27d6a65e57fe1f03278f9d099651ca1cb338`, merged into local main. Later
documentation commits do not change runtime code.

Live release:
`/Users/yapweijun/Library/Application Support/MacOperator/releases/personal-20261002-terminal-protocol-c`.
Another authorized GUI rollout occurred during verification. The new release
preserves that immutable `personal-20261002-gui-a` release and its native GUI
artifacts, with only the independently tested Edge module overlaid. Its complete
combined production JavaScript matches the final 1,600-pass regression. Runtime
composition and every artifact hash are recorded in the protected manifest;
the GUI source changes remain owned by the separate GUI task.

Full stopped-state rollback backup:
`/Users/yapweijun/Library/Application Support/MacOperator/backups/gui-a-before-20261002-protocol-c`.
It contains 328 byte-verified state files, launch/rollback configurations,
runtime manifest and public verification logs. All 22 protected key/policy/runtime
authority files and the owner account remained unchanged. Existing saved OAuth
was reused successfully after restart. Only unsigned Edge package/contract paths
and its source revision changed. There was no migration or tunnel change.

The primary repository's unrelated PROGRESS and GUI changes were preserved;
only conflicting PROGRESS/auth-test paths were temporarily scoped-stashed for
the fast-forward and restored with identical added/removed content. The unrelated
direct-task evidence file retained its original SHA-256. Temporary validation
source copies were removed from this task's checkout after verification.

Changed implementation files: `packages/edge/src/https-edge.ts`,
`packages/edge/src/https-edge.test.ts`, `packages/edge/src/service-startup.ts`,
`docs/MAC_OPERATOR_V2_DESIGN.md`, and `docs/owner-terminal-connection.md`.
README, the existing change report and this acceptance record document the result.
MCP tool schemas and existing R1/V2 contracts are unchanged.

## Limits

The 18 skipped tests require explicitly enabled physical-host prerequisites;
they are not counted as passes. GUI TCC acceptance belongs to the concurrent GUI
task and is not claimed here. Fourteen pre-existing UNKNOWN job outcomes were
retained rather than reclassified or replayed; the two with process metadata had
no surviving recorded PID or process-group members at deployment. This does not
establish their historical outcomes. New verification jobs settled normally.

The SDK, native Codex OAuth manager, macOS owner permissions and separately
approved O1 policy remain trusted boundaries. A new native Codex session loads
the connection; the current chat's previously loaded tool list is not rewritten.
Completion for the selected connection/deployment scope: 100%.
