# Pre-deployment acceptance and backup — 2026-10-13

Status: **PARTIAL.** Local repairs are committed and the complete stopped-state
backup is verified. The candidate rollout is **NO-GO** because two existing
production configuration/provenance issues remain. The original service is
stopped; its prepared recovery requires explicit owner approval after automatic
approval review rejected the production image/evidence switch.

## Source and installed state

- Repair commit: `a7f24509eeb668c63334e1b154fc6b1b1300474b` on local `main`.
  BUG-29 through BUG-37, 32 regression cases and their documentation are included.
  No push or repair rollout occurred.
- Installed source remains `09dd85b99b7ffc0246a14f85959a7b49473d7abc`, release
  `~/Library/Application Support/MacOperator/releases/personal-20261011-09dd85b`.
- Actual protected state is `~/Library/Application Support/MacOperator-g1-20260925a`.
  Its development inventory is inside `personal/development`, with a legacy array
  containing four records: three active and one removed. No `0.2` migration occurred.
- Before backup, PM2 was online with zero restarts and zero queued/running Jobs.
  The existing MCP connection, Broker health and production LaunchServices GUI
  installation/identity/Accessibility/Screen Recording checks passed.
- The installed Auth profile is V2. Independent owner-terminal OAuth is disabled;
  unauthenticated `/mcp` returned 401 and `/terminal/mcp` returned the expected 404.

## Verified backup

Backup root:
`~/Library/Application Support/MacOperator/backups/predeploy-2026-10-13T030851-465Z-a7f2450`.

The service was stopped and the existing protected-state helper copied the whole
state into `state.partial`, publishing `state` only after the copy succeeded.
Before/after tree comparisons verified all regular-file bytes, ownership, modes
and symlink targets against the unchanged stopped source. The snapshot contains
**554 files / 101,882,778 bytes**. The backup root is mode 0700. Sensitive state
and the detailed file manifest remain local; their contents are not in this repo.

The owner-private `manifest.json` SHA-256 is
`81018cc8ac70d5a51b8f41648bd4355978f0bd982fc759712b4f165460c8494c`.
`rollback-launch.json` records the original release's non-secret launch binding.
The complete inventory is included. External active checkout directories remain
in their original locations; this snapshot does not copy their working files.

An additional mode-0600 `recovery-image.tar` contains the exact prepared image
manifest. Size: **121,511,424 bytes**. SHA-256:
`0a858ecd6f8a5c67afe0757e487727db7c197dddbb3f265bd6f5e66a026f113a`.
Archive readability and exact manifest presence passed. A destructive image-load
or full state-restore rehearsal was not performed.

## Restart failure and prepared recovery

Stopping the service exposed a missing restart dependency. The configured
OrbStack Engine identity still matches, but its approved image
`sha256:90e9d231f56d358dd792b928da7a1da4ce1349306e91dacaa83d9a73defa5b25`
is absent. Actual Engine inspection returns 404. The former Docker Engine socket
and an exact-image local archive were unavailable. The original source therefore
fails closed on startup. The failed PM2 retry loop was stopped.

The execution order was insufficient: database/OAuth/GUI checks passed before
quiescing, but the full Engine/image restart prerequisites were checked afterward.
For future backups, verify those dependencies while the service is still online.

A replacement was prepared from the retained digest-pinned Node base, locked
dependencies and public build helper. Its first actual build failed with `EACCES`
because private context-file modes were copied into the image. The private build
recipe now sets copied public package/helper files to 0644 explicitly; host
permissions, secret filtering and container restrictions are preserved.
Fresh acceptance was repeated for the corrected final image:

`sha256:de58d8259f429819ba390e1303e5e36e7073743617ae28f0dddef8b7bbf41334`.

| Recovery evidence | Result |
| --- | --- |
| Actual container isolation, secrets, network, non-root execution, deadlines, cancellation and crash/restart recovery | 17/17 PASS |
| Actual Codex read-only and workspace-write integration | PASS |
| Actual registered site build, approved staged-content commit and review/audit flow | PASS |
| Primary project HEAD, index, status and original source | Unchanged |
| Required runtime evidence names mapped to fresh physical/coding checks | 16/16 PASS |
| Original installed source opens private backup Auth/Broker stores, restores signed policy and matches V2 contracts | PASS |
| Original installed source accepts replacement Engine/image/Codex prerequisites | PASS |

Physical registered-test success/failure evidence uses actual fixture commands.
It does **not** claim that the installed `yap.test-isolation` profile passes; that
separate failure is recorded below. Host Node is v25.5.0; the final image uses
v24.21.0. The full host suite was not rerun under Node 24.

Recovery files are private under
`~/Library/Application Support/MacOperator/prepared/recovery-predeploy-20261013-a7f2450`:
`physical-b.json`, `coding-b/e2e.json`, `acceptance.json` and
`recovery-runtime.json`. The proposed runtime configuration changes only
`imageId`, `evidencePath` and `evidenceSha256`. The source/release, signed policy,
OAuth configuration and inventory remain the original bindings.

Automatic approval review rejected applying that configuration and restarting:
the user authorized backup/pre-deployment acceptance, not an explicit production
configuration switch, and two acceptance issues remain. No live recovery binding
was applied. The owner has been asked to approve this exact recovery action.

## Rollout blockers

| ID | Verified issue | Required next step |
| --- | --- | --- |
| PREDEPLOY-01 | The installed `yap.test-isolation` command targets `scripts/test-isolation.test.js`. That tracked file is present in the checkout but excluded from the actual sanitized snapshot. Both installed and candidate secret-content guards deny it. The actual registered Job exits 1 with `TEST_ISOLATION_RUN_FAILED`. | Review the fixture content/profile and produce a legitimate runnable test input without relaxing secret protection; rerun the actual registered command. |
| PREDEPLOY-02 | One historical active `Mac-AI-Terminal-Hub` worktree's stored primary Git configuration digest differs from the current repository. Repository directory identities still match; the other two active records' configuration digests match. Inventory verification refuses the stale record with `Primary project identity changed`. | Review the configuration change and the recorded checkout/branch provenance before operator reconciliation. Preserve the checkout and existing guard; do not rewrite identity merely to make the check pass. |

The missing approved image is a separate availability dependency. Prepared
recovery can restore the original release after authorization, while these two
issues continue to prevent accepting the new rollout. General isolation evidence
does not override either installed-profile or provenance failure.

## Verification boundaries and next executable action

The committed source retains the verified result: **2,226 PASS, 0 FAIL, 19 SKIP**
across 242 test files, plus native builds and project checks. Fresh live acceptance
adds the results above; it does not erase the full suite's skipped paths.
No repair deployment, push, signed-policy migration or live worktree compaction
occurred. Existing and acceptance worktrees are retained for review.

After explicit recovery approval, apply the reviewed three-field runtime binding
and restart the original release. Require stable PM2 process identity/restart
count, unauthenticated `/mcp` 401, actual MCP health/capabilities and unchanged
policy/OAuth/inventory readback. Record recovery before addressing the two rollout
blockers. A later rollout needs a new consistent backup of the then-current state.

For rollback, restoring the original snapshot alone still references the missing
image. Retain the accepted replacement image, matching recovery configuration and
evidence together with the state backup. Always verify the loaded image identity
and reconcile subsequent Jobs/worktrees before restoring older state.

## Recovery update

Later on 2026-10-13 the original service was recovered without applying the
prepared replacement image or any production configuration change. The earlier
sections of this record describe the state at backup time and are kept as written.

### Root cause

PM2 showed `mac-operator-personal` in a restart loop (307 restarts when
investigation began). `main()` in `personal-service.ts` discards the startup
error on purpose, so the log held only the generic fail-closed line. A bounded
diagnostic (a preload that records errors reaching `Promise.prototype.catch`,
45 s limit, long tokens masked, run outside PM2) captured
`BrokerError: Container Engine operation failed with status 404`, raised by
`inspectImage` in `container-engine.ts` and called from
`personal-development-runtime.ts`. The first attempts reported
`ALREADY_ACTIVE` because PM2's own attempt held the service lock; retrying until
the lock was free produced the real error.

The configured image `sha256:90e9d231f56d358dd792b928da7a1da4ce1349306e91dacaa83d9a73defa5b25`
was absent from the OrbStack Engine. Everything else the startup checks matched:
Engine ID, Codex executable hash and version, runtime evidence hash and file
modes. The signed policy does not reference the image or evidence, so no
re-signing was involved. Why the image left the Engine is not established.

### Repair

`backups/before-personal-20261005-5fbc317/recovery-image.tar` (SHA-256
`76982c163bc342aef15f99341223b88412e7c2ef23b8c5c4def2a65f18fc3115`) holds the
pinned image: its OCI index names manifest digest `sha256:90e9d231...` and tag
`recovery-20261005`. `docker load -i` restored that tag and `docker image inspect`
returned the identical ID. A throwaway container from it ran as uid 65533 with no
network, a read-only root, no capabilities, no host mounts and no Docker socket.
PM2 restarted the service on its own within its normal retry cycle. The
`predeploy-recovery` images and `recovery-runtime.json` prepared earlier stay
unused.

### Verification

| Check | Result |
| --- | --- |
| PM2 `online`, restart count stable across a 60 s window and a controlled restart | PASS |
| Edge `127.0.0.1:3443` and Auth `127.0.0.1:3444` listening | PASS |
| Public unauthenticated `/mcp` | PASS, 401 with challenge |
| Public OAuth protected-resource and authorization-server metadata | PASS, 200 |
| Authenticated internal `/mcp` `server/discover` | PASS, 200 |
| Other PM2 services (35) | PASS, unchanged |
| Authenticated `mac_health` | NOT VERIFIED |
| Authenticated `mac_terminal_exec` | NOT VERIFIED |

No MCP client session was available, so the two authenticated tool calls were not
made. A loopback request without the public `Host` header returns 403 by design.
The two rollout blockers above, PREDEPLOY-01 and PREDEPLOY-02, were not touched.

### PM2 restart policy

The loop reached hundreds of restarts because PM2 counts a restart against
`max_restarts` only when the process died before `min_uptime` (default 1 s), and
the fail-closed start lives longer. `pm2 start` has no `--min-uptime` flag in PM2
6.0.14, so the policy needs an ecosystem file. It was checked in an isolated PM2
home first: the old flags restarted without bound, while `min_uptime` plus
`max_restarts` stopped the process and left it at `waiting restart`.

The running service now has `max_restarts: 60`, `restart_delay: 5000`,
`min_uptime: 30000` (about eight minutes of retries), applied in place with the
service id and environment unchanged, and saved. Only that service's dump entry
differs from the previous dump. The limit is not 3 because the host `pm2-health`
monitor does not cover this service and a reboot can need minutes for the Engine.
After the limit PM2 leaves the service stopped; recover it with
`pm2 restart mac-operator-personal` once the cause is fixed.

Rollback: `backups/pm2-restart-policy-before-20261013T174853` holds the previous
dump and a `rollback.ecosystem.json` with the old values (owner-only).

### Related findings

`Mac-AI-Terminal-Hub` release gates, checked read-only: no `_terminalhub` account
exists, the Cloudflare Access application and policy could not be checked without
an Access API credential, the installed ttyd (Homebrew 1.7.7_14, ad-hoc signed)
is not hash-pinned in that repository, and there is no production release
verifier. No `terminal.yapweijun1996.com` DNS record or tunnel route exists, so
nothing is exposed. The Hub is not ready for a separate deployment.
