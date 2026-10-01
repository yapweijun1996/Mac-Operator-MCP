# Combined V2/O1 personal source rollout — 2026-10-02

Source deployment and local main merge: DONE/PASS.
Safe development gateway acceptance: PARTIAL, 55% (6 of 11 gates).
Verification completed at 2026-10-01 20:18 UTC / 2026-10-02 04:18 UTC+08.
The owner explicitly authorized testing, committing, merging to main and live
deployment. No push or PR publication was requested or performed.

## Source and architecture

- Branch: local `main`; integration branch: `codex/v2-live-integration`.
- Runtime source commit: `2c37194d9bd822e78ad088f61d79a5f91061e152`.
- Integration parents: V2 `46047ec` and existing O1 `463388c`.
- Before: independent O1 source with 46 contracts and 38 enabled owner tools.
- After: combined O1/V2 source with 57 contracts; the same 38 enabled owner
  tools, 24 OAuth scopes and signed policy. Existing grants retain their scopes.
- All 11 V2 tools and `mac_task_run` remain disabled by policy. No
  DevelopmentGateway, coding adapter, task registry or execution authority was
  injected into the broad O1 profile. `mac_git_push` remains disabled/denied.

The project-scoped V2 interfaces and independently authorized O1 terminal keep
separate admission paths. O1 deliberately runs commands as the owner; it is
not a V2 isolation boundary. Successful Codex CLI version inspection does not
prove a real Codex development task, secret denial or descendant containment.

## Verification

| Check | Result |
| --- | --- |
| Standard `npm test`, native and TypeScript builds | PASS: 1330 total, 1313 passed, 17 skipped, zero failed |
| Strict tool contracts | PASS: 57 unique contracts |
| Typecheck, style, docs, matrix, process boundaries, native canonical JSON | PASS |
| Dependency audit | PASS: zero vulnerabilities; compatible `fast-uri` 3.1.8 patch |
| Independent review | PASS: 55 related regressions; confirmed P1 fixed; no unresolved P0/P1 |
| Release native binary | PASS: hash matches tested integration binary and release record |
| Public OAuth discovery, owner login/consent/S256 | PASS |
| Full owner grant tool discovery and reads | PASS: exactly 38 tools; 26 real reads |
| Old read-scope grant tool discovery and reads | PASS: exactly 27 tools; 26 real reads; no terminal authority |
| Out-of-project source write | PASS: policy denied; no file created |
| Existing O1 terminal canary | PASS: 31-second execution, local CLI/network/file access, idempotent replay, Job readback |
| Terminal timeout | PASS: 150 ms bound; delayed marker absent |
| Active grant revocation | PASS: CANCELLED, durable cancelled Job, process ownership cleared, delayed marker absent |
| Subsequent request after grant revocation | PASS: HTTP 401 |
| Connected MCP health | PASS: healthy; Broker version 0.1.0 |
| Connected MCP capabilities | PASS: 57 contracts; V2/task execution disabled |
| Signed policy preservation | PASS: byte-identical SHA-256 before/after |
| Unsigned source configuration delta | PASS: only packageRoot, contractsDirectory, sourceRevision |
| PM2 saved configuration | PASS: selected release matches live source; dump mode 0600 |
| Job ledger after probes | PASS: no queued/running jobs; historical unknown records retained |
| Live execution audit | PASS: terminal intent/success/timeout/cancel and denied source-write events persisted |
| Production V2 Codex/task/build execution | NOT RUN: accepted executor/inference boundary absent |
| YAP-MCP isolated development E2E | NOT RUN: repository/runtime prerequisites unresolved |

The 17 skips are explicit opt-in host/production probes; they do not count as
passes. Source tests and runner doubles cannot establish production isolation.
The required V2 security/E2E gates remain listed in the
[change report](../docs/MAC_OPERATOR_V2_CHANGE_REPORT.md).

Independent review reproduced a canonical source-write bypass through aliases
to Git metadata. The fix authorizes descriptor-pinned canonical destinations
before temporary creation and again before atomic commit, rejects asynchronous
or missing authorizers, rechecks paths after callbacks and cleans failed
temporary files. Older native binaries fail writes closed through capability
version gating. Git metadata/secret alias, parent-retargeting and cleanup tests
pass. This protects the scoped write API; a future coding runtime still needs
accepted outer isolation.

## Live bindings and protected rollback

Public MCP URL: `https://mac.yapweijun1996.com/mcp`.
Supervisor: PM2 `mac-operator-personal`; online, zero restarts at readback.
Node interpreter: `/opt/homebrew/bin/node`.

All paths below are relative to `/Users/yapweijun/Library/Application Support/`:

- Current release: `MacOperator/releases/personal-20261002-v2a`.
- Previous release: `MacOperator/releases/personal-20261001-o1a`.
- Unchanged state: `MacOperator-o1-20261001a`.
- Complete offline backup: `MacOperator/backups/o1-before-20261002-v2a` (0700).

The stopped service had no active jobs before its full protected state was
copied. The backup contains the signed policy, databases, audit, authentication
and TLS material, original unsigned Edge configuration and both supervisor
configurations. Secrets stay inside protected storage and were never printed
or committed. The new immutable source snapshot excludes project `.env` and
test artifacts. Its native binary SHA-256 is
`2b44dd901bf97c387c33e2af6ed00303b4659e11017811aff0e2d02758576552`.
The unchanged signed policy SHA-256 is
`67e1b4cac754f882991c3f74a783a4d9a284b732fb0aa667a9ab6325348e1832`.

Public verifier logs are bounded, credential-free diagnostics in the protected
backup directory: `public-owner-verification.log` and
`public-read-verification.log`. Temporary verifier grants are revoked and
clients/canary directories are removed. Existing unknown terminal jobs remain
unknown; this rollout did not replay them or convert them to success.

For source rollback, first inspect owned jobs and stop this one PM2 service.
Copy `edge-service.before.json` from the protected backup to
`MacOperator-o1-20261001a/personal/edge-service.json`, preserving mode 0600.
Delete the stopped `mac-operator-personal` definition, then start the backup's
`rollback.config.cjs` with `--only mac-operator-personal`. Verify health,
exact tools/scopes and job/audit readback before `pm2 save`.
Keep the current state and ledgers for a source rollback; restore an entire
database backup only after separately reviewing newer jobs/grants/audit.
Never run `init`/`provision` against the existing state or use a global PM2
resurrection to roll back unrelated services.

## Remaining work

The live source upgrade is verified. Actual V2 coding remains disabled because
the accepted production isolation, credential-free inference and exact YAP-MCP
workflow are not available. Ordinary coding approval cannot grant O1 authority.
No production YAP source was modified, and no remote push occurred.

The integration changes 84 files against baseline `0be86f5`; this rollout
record and affected status/runbook documents are committed separately. The
primary checkout's pre-existing progress note and untracked task-enablement
evidence are preserved outside these commits.
