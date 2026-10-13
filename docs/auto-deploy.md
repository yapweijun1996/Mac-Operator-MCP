# Personal auto-deploy

Status: implemented for the owner-managed personal deployment on one Mac. It is
not a signed-release installer and never changes signed policy.

A launchd user agent (`com.yapweijun.mac-operator-autodeploy`) polls GitHub every
five minutes and deploys new `origin/main` commits to the PM2 service
`mac-operator-personal`. It only pulls, so no inbound port is opened. Anyone who
can push to `main` can therefore run code with the owner's authority on this
Mac; keep push access to `main` limited to the owner.

## What one run does

1. Stop if `~/Library/Application Support/MacOperator/auto-deploy/PAUSE` exists or
   another run holds the lock.
2. Fetch `origin/main` into a dedicated checkout (`auto-deploy/checkout`), never
   the owner's working copy.
3. Compare the live `sourceRevision` (from `personal/edge-service.json`) with the
   fetched tip:
   - same or newer than `origin/main`: nothing to do (no downgrade);
   - not in `origin/main` history, or diverged: notify once and wait for a manual
     decision;
   - behind but only docs, tests or tooling changed: notify once, no restart;
   - behind with runtime changes: continue.
4. `npm ci` and `npm test`. A failing test file is rerun alone; only a file that
   also fails alone blocks the deploy. A blocked revision is not retried until a
   newer commit arrives.
5. Create an immutable release `releases/personal-YYYYMMDD-<short>`.
6. Defer to the next poll while any Job is queued or running.
7. Stop the service, copy the complete protected state to
   `backups/auto-<timestamp>-<short>/state.partial`, publish it as `state` only
   after copying succeeds, rebind only `packageRoot`,
   `contractsDirectory` and `sourceRevision`, start the new release and require
   an online process with zero restarts plus `401` from `/mcp` (and
   `/terminal/mcp` when enabled).
8. A failed cutover, including a thrown copy, configuration or startup error,
   attempts to restart the previous release. Before live state changes, the
   intact state stays in place. After changes, recovery requires a confirmed
   service stop and a completed backup; it stages the restore copy before moving
   live state. Failed recovery preserves the available state and reports an
   explicit failure. Healthy: `pm2 save`, prune old auto releases and
   backups (the newest five are kept, plus the live and previous releases;
   hand-named releases are never pruned), notify.

`MOP_AUTODEPLOY_TEST_UNHEALTHY_ONCE=1` is a test-only switch that fails the first
health check so the rollback path can be rehearsed; leave it unset in normal use.

The agent never runs the policy upgrade commands. A release that needs a new
signed tool (for example `V2 tool set mismatch` at startup) is rolled back and
needs the documented manual `personal-service.js <mode> ... --enable` upgrade.
It also never touches the installed GUI app, OAuth grants or keys.

Before manual quiescence or a backup, independently verify the installed release's
restart prerequisites: exact approved Engine/image availability, Codex readiness,
signed-policy/runtime bindings and managed worktree provenance. The current
automatic startup preflight opens a private Broker database copy; it does not
prove that every external runtime dependency is still available. A service can
remain online after its pinned image disappears and then fail closed on restart.
Keep an exact-image private archive with the consistent state backup. Missing
images require validated, explicitly authorized recovery; a state restore alone
cannot recreate them. See the [October 13 acceptance record](../evidence/2026-10-13-predeployment-acceptance.md).

## Commands

```sh
node scripts/auto-deploy/run.mjs install      # write the LaunchAgent and load it
node scripts/auto-deploy/run.mjs status       # agent, live revision, last outcomes
node scripts/auto-deploy/run.mjs once --dry-run  # decide only, change nothing
node scripts/auto-deploy/run.mjs pause        # skip deployments until resume
node scripts/auto-deploy/run.mjs resume
node scripts/auto-deploy/run.mjs uninstall
```

The installed agent runs the script from its own checkout, so the agent updates
itself when a push changes it. Logs: `auto-deploy/logs/events.jsonl`, one test
log per revision and the launchd stdout/stderr files. Notifications use macOS
Notification Center.

## Manual rollback

Use the `backups/auto-*` directory recorded in the deployment log: stop the service,
restore its `state` directory over the protected state root, restore the previous
`packageRoot` in `personal/edge-service.json` if needed and start that release,
as in [personal deployment](personal-deployment.md).

The manual `.zsh` cutover scripts source `deployment-state.zsh` and
`deployment-service.zsh` from their own directory; keep those helpers with the
scripts. An incomplete `state.partial` directory is never a rollback source.
Release scripts check health after both starts: zero restarts after the initial
start and exactly one after the explicit final restart. An additional automatic
restart fails the deployment before it is saved or reported as successful.
