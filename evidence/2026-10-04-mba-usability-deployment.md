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
(`/oauth/status` log lines are Edge grant lookups for authenticated MCP requests, not a timer, and the
first check cited the pre-restart log file.) Public checks: `/mcp` 401 unauthenticated, both
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

## Second deployment — release `v2-usability2-20261004-a7bb6b1`

Source revision a7bb6b192a7d67aa755d845d9ddc854a5bbe9c95. Previous release `v2-usability-20261004-342d505`
retained. Same procedure: copy of the running release plus nine compiled/contract files (hashes in
`USABILITY-HOTFIX-2.json`), no queued/running jobs (73/6/24 before and after), only the three unsigned
Edge fields changed (original saved as `edge-service.json.before-usability2-20261004`), PM2 recreated from
`mba-mcp.usability2.ecosystem.json` and saved. Rollback: restore that file, `pm2 delete mba-mcp`,
`pm2 start mba-mcp.pre-usability2.ecosystem.json`, `pm2 save`. PM2 now writes `~/.pm2/logs/mba-mcp-out.log`
(the older `-0` files belong to the first process).

Evidence: PM2 online, restart count 0; `/mcp` 401 unauthenticated, protected-resource metadata 200,
`/register` with the Claude callback 201. During the first release authenticated clients made 49
`tools/call`, 26 `server/discover` and 6 `tools/list` requests (all 200, protocol 2026-07-28), so MBA served
real MCP traffic on the new code. No authenticated request has arrived since the second restart, so the new
fixes themselves are not yet observed through MCP.

## Open finding: Claude initialize is rejected

In the same window 11 authenticated `POST /mcp initialize` requests with `protocolVersion: "2025-11-25"`
(Cloudflare IAD) returned 400, each followed by a `GET /mcp` 405. The primary endpoint is modern-only by
design (`legacy: "reject"`; only the owner-terminal endpoint accepts legacy 2025-06-18). Not changed by
either deployment; whether this client is the Claude connector is not proven.

## Third deployment — release `v2-usability3-20261004-1e4f7b7`

Source revision 1e4f7b7 (reviewed by six adversarial lenses before commit). Previous release
`v2-usability2-20261004-a7bb6b1` retained. Copy of the running release plus 25 files (13 compiled files
including `packages/contracts/dist/errors.js` for `BrokerError.reasonCode`, and 12 tool contracts; hashes in
`USABILITY-HOTFIX-3.json`). No queued/running jobs (completed 73 / failed 7 / unknown 24 before and after).
Only the three unsigned Edge fields changed (original: `edge-service.json.before-usability3-20261004`).
PM2 recreated from `mba-mcp.usability3.ecosystem.json` and saved. Rollback: restore that file,
`pm2 delete mba-mcp`, `pm2 start mba-mcp.pre-usability3.ecosystem.json`, `pm2 save`.

Evidence: PM2 online, restart 0, Auth and Edge children on the new release, `/mcp` 401, both
`.well-known` documents 200, `/register` with the Claude callback 201, no new errors in the PM2 error log.
No authenticated MCP call has been made since the restart, so the fixes are not yet observed end to end.
Verify from an MBA connector: `mac_capabilities` lists `authorized_log_sources`/`authorized_projects`,
`mac_log_tail` with `system/com.apple.logd` names the bad argument, `mac_policy_explain` returns
`OUTSIDE_AUTHORIZED_ROOTS`/`ROOT_CAPABILITY_NOT_GRANTED`, and `mac_storage_analysis` without roots returns.
Owner action recommended: add `Library/CloudStorage` to the signed policy's deny_relative_paths.
