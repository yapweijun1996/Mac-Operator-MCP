# Socket Security Fix Report — container engine restart revalidation

Branch `fix/container-engine-socket-revalidation` (base `main` @ `040c491`) in the worktree
`/Users/yapweijun/.mac-operator-worktrees/engine-socket-revalidation`.
**Committed locally on this branch; not pushed, merged or deployed.** The live Broker runs the old code (no revalidation).
It was restarted by the owner at 13:55:33 SGT (pid 78535), which re-pinned the current OrbStack socket and daemon, so Docker
should work again until the engine restarts the next time. Only deploying this branch removes that dependency (see section 7).

Cause and evidence: `ROOT_CAUSE_REPORT.md`. Host transcript: `evidence/2026-10-09-container-engine-restart-revalidation.md`.

## 1. What changed

| File | Change |
|---|---|
| `packages/broker/src/container-engine.ts` | New opt-in `revalidation` option and `revalidate()`. The three pins (socket device/inode, peer policy with daemon PID + start time, peer verifier) are now replaceable, but only by a successful revalidation. `assertSocket()` is split into `inspectSocketStructure()` (every static invariant) plus the identity comparison. Requests carry the pins they were admitted under (`EnginePins`). The constructor pins the identity from the same `lstat` that passed the checks (previously a second `lstat` ran after the checks). |
| `packages/broker/src/container-engine-peer.ts` (new) | `captureContainerEnginePeer()`: one connect, native kernel peer credentials, daemon PID, start time and executable path. Shared by startup pinning and revalidation so they cannot diverge. |
| `packages/broker/src/index.ts` | Exports the new module. |
| `packages/auth/src/personal-development-runtime.ts` | Startup uses the shared probe and enables revalidation with the approved `engineId` from `development-runtime.json` and the daemon executable seen at startup. Decisions are logged as JSON lines. If the executable cannot be read, revalidation stays off (fail closed, the previous behaviour). |
| `packages/broker/src/container-engine-revalidation.test.ts` (new) | 16 tests (15 injected + 1 real-process). |
| `OPERATIONS.md`, `evidence/2026-10-09-…md`, `ROOT_CAUSE_REPORT.md`, this file | Documentation. |

No policy, scope, target rule, contract, schema or audit-store change. `mac_policy_explain` and `mac_stat_path` are unchanged on purpose (section 5).

## 2. How a restart is handled now

Trigger: a request finds that the socket path names a different object than the pinned one (device/inode differ). Without the
opt-in option, or for any other failure, behaviour is exactly as before.

One shared attempt runs; every other request waits for its outcome:

1. Cooldown (default 2 s) after a refusal. A cooldown refusal does not extend the cooldown.
2. Refuse while any task is `staging`, `exporting` or executing.
3. The new socket must pass every first-start check: real socket, not a symlink, canonical path, owner = Broker user, no group/other write, owner-only parent chain, no extended ACL on the socket or its directory.
4. The kernel peer on the socket must be the Broker user and the pinned group, and run the **same executable path** that was pinned at startup. The socket is re-checked afterwards and must be the same inode (TOCTOU / replacement during the read).
5. Only then is `GET /info` sent, through the **candidate** pins (connect-time check of inode, uid, gid, PID and start time). The ID must equal the operator-approved `engineId`, and the usual Linux/ARM64/seccomp/cgroup checks apply.
6. The candidate pins replace the old ones. Every tracked task container is fenced (`blocked`: no more staging, exec or export; stop/remove only, through the existing per-container identity checks).

Any refusal leaves the old pins untouched, so the engine keeps failing closed. Each decision is reported once:
`{"event":"container_engine_revalidation","outcome":"accepted|refused","reason":"…","previous":{inode,pid},"current":{inode,pid},"fencedWorkspaces":n}`
with reasons `ENGINE_RESTART_REVALIDATED`, `ENGINE_TASK_ACTIVE`, `ENGINE_SOCKET_UNSAFE`, `ENGINE_SOCKET_REPLACED`, `ENGINE_PEER_UNVERIFIED`, `ENGINE_PEER_OWNER_MISMATCH`, `ENGINE_EXECUTABLE_CHANGED`, `ENGINE_IDENTITY_CHANGED`, `ENGINE_UNAVAILABLE`, `ENGINE_REVALIDATION_COOLDOWN`. No path, PID of another user or secret is logged.

## 3. Requirement check

| Requirement | Result |
|---|---|
| Fail closed | Default off; every refusal keeps old pins; no fallback path. |
| Strict ownership and permission validation | Same function as startup, run before the daemon is contacted. |
| Canonical path and symlink protection | Same `inspectSocketStructure()`; symlink test below. |
| TOCTOU / replacement | Candidate pins checked on connect; inode compared before/after the peer read; test swaps the socket mid-read. |
| Reject unauthorized paths and owners | The path is the configured one only; file owner and peer uid/gid are checked. |
| Legitimate recreation handled by explicit revalidation | `revalidate()` as above. |
| Docker target authorization matches policy | Unchanged. `policy-8` already allows `docker_runtime/local`; audit 11173 shows `AUTHORIZED`. |
| No broad filesystem roots, no disabled checks, no `chmod 777`, no privilege, no credentials | None added. |

## 4. Test results

Environment: `yaps-Mac-mini.local`, macOS 26.2 arm64, Node 25.5.0, worktree built with `npm run build`.

**Real host (read-only, real OrbStack socket and daemon)** — `host-verify.mjs`, output in the evidence file:
- A: stale pin without revalidation → `Container Engine socket path or ownership changed or is unsafe` (the reported message).
- B: stale pin with revalidation → accepted; then Docker status (daemon 29.4.0), approved-image check and a second call with no new revalidation.
- C1/C2: wrong approved engine ID → `ENGINE_IDENTITY_CHANGED`; wrong approved executable → `ENGINE_EXECUTABLE_CHANGED`. Both denied.

**Real host (real processes)** — test "real host: a restarted daemon process is revalidated, an impostor executable is not": production engine, native peer adapter, stand-in daemon killed and restarted (accepted), then replaced by a byte-identical copy of `node` at another path (denied, zero requests received).

**Injected-peer tests** (mock probe and verifier; they exercise the engine's decisions, not the kernel):

| Acceptance item | Test | Result |
|---|---|---|
| Engine restart safely revalidated | "an engine restart is revalidated once…" | pass |
| Socket symlink attack denied | "unsafe permissions, a symlink or an unsafe parent" | pass |
| Socket replacement attack denied | "different executable", "swapped again while … identified", "another engine identity" | pass |
| Wrong owner denied | "peer is another user or group" (peer uid and gid); file-owner check shares `inspectSocketStructure()` with startup, whose existing tests still pass | pass |
| Unsafe permissions denied | mode 0666 socket, 0777 parent | pass |
| Unauthorized target / path denied | revalidation only ever uses the configured socket path; constructor tests unchanged | pass |
| No request reaches an unverified daemon | every denial test asserts `requests.length === 0` | pass |
| Task safety | "an active task blocks revalidation…", "concurrent requests share one revalidation" | pass |
| Opt-in only, config validated, probe seam unavailable in production | "without opt-in…", "configuration is validated…" | pass |

**Mutation check:** removing each guard (executable continuity, approved engine ID, post-read inode check, task fence, uid/gid check, candidate-pin verification, workspace fencing) makes at least one test fail; the code was restored and re-verified identical.

**Regression:** see section 8 for the final full-suite numbers. Existing `container-engine.test.ts` (including "rejects symlink socket, writable parents and replaced socket inode"), `docker-inspector`, `container-task-runner`, `container-task-profile`, `container-broker`, `persistence-container`, `container-snapshot`, `peer-credentials`, `policy` and `filesystem-inspector` suites pass unchanged. `npm run lint`, `verify:docs`, `verify:matrix` pass.

## 5. Findings deliberately not changed

- **`mac_policy_explain` cannot name a Docker target** (`tool-contracts/mac_policy_explain.json` `target.kind` enum). Widening it is an additive but public contract change that `TOOL_CONTRACT_STANDARD.md` requires to go through a reviewed transition, and it affects the "explain must not be an oracle" rule. Not needed for Docker to work. Check authorization in the audit rows instead.
- **`mac_stat_path` on a Unix socket node** is denied because `open(2)` on a socket fails (`EOPNOTSUPP`) and the catch-all message says "escaped … root". Loosening the opener would widen the filesystem boundary for no Docker benefit. A clearer error text would be a safe follow-up.

## 6. Remaining risks

1. **Executable-path continuity is not code-signature identity.** A same-user process that runs from the exact pinned path (for example by overwriting the helper inside a user-writable app bundle) and answers `/info` with the approved engine ID would be accepted. Same-user compromise already defeats the startup pin; this does not make it worse, but it is the weakest link. Recommended follow-up: pin the daemon's Team ID/designated requirement in the native adapter.
2. If OrbStack or Docker Desktop updates change the helper's path, revalidation refuses (fail closed) and the Broker needs a restart.
3. A restart while a task is staging/executing/exporting is refused; those tasks fail and are fenced, and the next request after they settle revalidates.
4. Pre-restart task containers are fenced, not auto-removed. No janitor was added.
5. Startup still fails when the engine is down at service start (OPERATIONS.md follow-up about making Docker optional).
6. The cooldown is process-wide, so a stream of requests during a flapping engine returns the cooldown denial instead of probing again (by design).

## 7. Verification status

| Item | Status |
|---|---|
| Broker Health | **Healthy** (live `mac_health`, v0.1.0) — unchanged by this work |
| `mac_docker_status` succeeds with the authorized engine | **UNVERIFIED on the live Broker.** Needs deploy or service restart. Verified through the same engine code path against the real OrbStack socket (section 4). |
| `mac_codex_preflight` succeeds | Already succeeded during the incident (audit 11145/11146, 11156/11157) because it does not touch the engine. Not re-run. |
| `mac_codex_run` executes a bounded read-only task | **UNVERIFIED.** Needs the deployed Broker and the owner's Codex login. Only its engine gate (`validateRuntime`: `info()` + approved image) was verified on the host. |
| Real OrbStack restart through the deployed Broker | **UNVERIFIED** (would stop the owner's containers). Covered by the real-process restart test and the stale-pin run on the real daemon. |
| Audit decisions and reason codes | Audit rows already show `AUTHORIZED` then `POLICY_DENIED`. New decisions are logged as `container_engine_revalidation` JSON lines in the pm2 out log; the audit store and reason-code contract were not changed. |

Owner actions:
- Done by the owner at 13:55:33 SGT: `pm2 restart mac-operator-personal`. Afterwards `mac_health` is healthy, port 3443 listens, no startup error, and the new process started after the socket was created (11:00:29), so it pinned the current identity. As of the last audit read (sequence 11309, 13:55:46) no Docker or Codex tool had been called yet, so the three calls below are still to be confirmed from the audit rows: `mac_docker_status`, `mac_codex_preflight`, `mac_codex_run` (read-only task).
- To fix permanently: review this branch, then deploy through the normal release path.

## 8. Final regression run

Full suite on the final code, run in the worktree with `npm test` (build plus all `packages/*/dist/**/*.test.js` and `scripts/*.test.mjs`):

```
tests 2078 · pass 2059 · fail 0 · cancelled 0 · skipped 19 · todo 0        exit 0
```

The first full run (before the pin-handling refactor) was 2076 / 2057 / 0 / 19; the two extra tests are the ones added afterwards. The 19 skips are existing environment-gated tests (for example real Docker Desktop, privileged helper); none were skipped by this change. `npm run lint`, `npm run verify:docs` and `npm run verify:matrix` pass.

Untouched and still running on the live host while this work was done: pm2 `mac-operator-personal` pid 23034 (started 08:05:38), OrbStack pid 48396, policy `policy-8`, `development-runtime.json`, `broker.sqlite` (read only through a copy).
