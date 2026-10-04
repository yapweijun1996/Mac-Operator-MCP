# MBA usability deployment — 2026-10-04

Source revision: 342d5057930c2bc9370ac439fe25f0281eb805e3 (local `main`, not pushed).
Active immutable release: `v2-usability-20261004-342d505`. Previous release `v2-gui-session-20261003-a7783e1` is retained.

## What changed

The release is the previous release plus eight files compiled from the tested checkout
(byte-compared; hashes in the release's `USABILITY-HOTFIX.json`): `broker.js`,
`filesystem-inspector.{js,d.ts}`, `gui-window.js`, `log-inspector.js`,
`process-inspector.{js,d.ts}` and `tool-contracts/mac_capabilities.json`. Native binaries
and the signed GUI app are unchanged (not rebuilt, not reinstalled). Behaviour changes are
listed in the October 4 `PROGRESS.md` entry.

## Procedure

No queued/running jobs before restart (completed 73 / failed 6 / unknown 24; identical after).
`mba-mcp` was stopped, only unsigned Edge `packageRoot`, `contractsDirectory` and
`sourceRevision` in `personal/edge-service.json` were changed (original saved as
`edge-service.json.before-usability-20261004`, mode 0600), then PM2 was recreated from
`mba-mcp.usability.ecosystem.json` and saved. Policy, keys, OAuth state and the database were
not touched; no whole-state backup was made because none of them was modified.

## Evidence

PM2 `mba-mcp` online, restart count 0, Auth and Edge children running from the new release.
Edge/Auth status heartbeats return 200. Public checks: `/mcp` 401 unauthenticated, both
`.well-known` documents 200, `/register` with the Claude callback 201 (the Claude redirect
URIs were added to `allowedRedirectUris` earlier today; backup `auth-config.json.bak-pre-claude-redirect`).

Limitation: an authenticated MCP call to MBA was not made from this session. The `mac_*` tools
available here connect to a different, older instance (16 GB / 245 GB host, not this 32 GB
MacBook Air), so they cannot show MBA's new behaviour. Confirm from an MBA connector:
`mac_capabilities` should now include `authorized_roots`, and `mac_process_inspect` on PID 1
should return POLICY_DENIED.

## Rollback

Run the previous release: stop PM2 `mba-mcp`, restore `edge-service.json.before-usability-20261004`
into `personal/edge-service.json`, then `pm2 delete mba-mcp`,
`pm2 start mba-mcp.pre-usability.ecosystem.json`, `pm2 save`. Do not restore full state.
