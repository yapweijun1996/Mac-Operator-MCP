# Owner-level full access for AI agents (design proposal)

Status: item 1 (background PTY sessions) is implemented on a local branch as the single tool `mac_terminal_session`; see `docs/owner-terminal.md`. Items 2-5 remain proposals. Nothing is deployed or enabled in a live policy.
Scope: personal Mac (MacBook Air) running this repository. Owner-level only; no root, no sudo.

## Goal

Let an authorized AI agent do anything the owner account can do from a terminal, without
per-command human approval, while keeping the existing OAuth/policy/audit/kill-switch boundary.

## Current limits (evidence)

| Limit | Where | Value |
| --- | --- | --- |
| Synchronous, no PTY, no stdin after start | `packages/broker/src/owner-terminal.ts` | command piped to `/bin/zsh -f -s` |
| Max timeout | `owner-terminal.ts:36`, `tool-contracts/mac_terminal_exec.json` | 120 s |
| Output cap | `owner-terminal.ts:64` | 128 KiB total |
| Descendants outside process group are untracked | `docs/owner-terminal.md` | by design |
| `mac_git_push` denied | `tool-contracts/mac_git_push.json` | reserved |
| Grants split by profile (G1 / O1 / V2) | `docs/owner-terminal.md` | reconnect needed per new scope |
| GUI limited to allowlisted apps, no secure fields | `docs/gui-computer-use.md` | Chrome/Safari |

## Proposed changes (in priority order)

1. **Background sessions** (`mac_terminal_session_start/read/write/stop`): Job-backed PTY
   sessions with owner-selected idle and absolute lifetimes, cursor-based output reads
   (ring buffer, per-read cap), stdin writes, and kill. Reuses the existing durable Job,
   process-identity recording, revocation cancellation and redaction paths.
2. **Raised limits for `mac_terminal_exec`**: a signed-policy-configurable timeout
   (default unchanged, owner may raise to 1 h) and output spooled to a protected file with
   a bounded tail returned inline.
3. **Git push under explicit grant**: a separate `mac.git.push` scope, never force,
   exact remote+branch bound into the single-use approval digest.
4. **GUI allowlist as owner-signed policy data** instead of a fixed list; secure fields
   stay denied.
5. **One consent for all owner scopes** (an `o2` profile) so a single reconnect grants
   the full set.

## Explicitly out of scope

- sudo/root and `mac_priv_*` (needs Developer ID + installed root helper; conflicts with `GOAL.md` non-goals).
- Disabling audit, redaction, kill switches or revocation.

## Risks

- A PTY session is a long-lived owner shell; revocation must cancel it (add a test).
- Redaction is signature-based; spooled output must stay in a 0600 file under the state dir.
- Each new tool needs a contract in `tool-contracts/`, policy entry in `default-policy.ts`,
  tests, and updates to `PROGRESS.md`.

## Verification plan

Unit tests per tool; extend `owner-terminal.test.ts` for session lifecycle, revocation,
restart recovery and idempotency; run `npm test`, typecheck, lint and contract verification;
live check through the public OAuth verifier on a disposable grant.
