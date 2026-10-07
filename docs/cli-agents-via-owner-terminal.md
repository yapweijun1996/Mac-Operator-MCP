# Running coding-agent CLIs through the owner terminal (O1)

Status: verified on the Mac mini on 2026-10-06 against the default `/mcp` endpoint after the G1 to O1 upgrade.

The default endpoint carries `mac_terminal_exec` and `mac_terminal_session` (see [Personal owner terminal (O1)](owner-terminal.md)). Any CLI installed for the owner account can be run through them. These are the verified invocations.

## Verified invocations

| CLI | Command | Notes |
|---|---|---|
| `codex` | `codex exec --skip-git-repo-check 'PROMPT'` | Needs codex-cli 0.160.1 or newer for the default `gpt-6.1-sol` model. 0.153.4 failed with HTTP 400 (`model is not supported when using Codex with a ChatGPT account`). |
| `pi` | `pi -p 'PROMPT'` | Non-interactive print mode. |
| `claude` | `CLAUDE_CODE_OAUTH_TOKEN=$(cat ~/.claude-oauth-token) claude -p 'PROMPT' --max-turns 1` | See the credential note below. |

Use a new `idempotency_key` for every call. A reused key returns the recorded result with `"reused": true` instead of running the command again.

## Why `claude` needs a token file

Claude Code stores its login only in the macOS login keychain (`Claude Code-credentials`); there is no credentials file under `~/.claude`. The Broker runs commands as a child of the PM2 daemon, and that process tree cannot read the keychain, so `claude auth status` reports `loggedIn: false` there even though the owner's own terminal is logged in. `codex` and `pi` keep their login in files and are not affected.

Workaround: run `claude setup-token` in the owner's own terminal, save the result to `~/.claude-oauth-token` with mode `0600`, and pass it as shown above. The O1 environment is only `HOME` and a fixed `PATH`, and command text containing a known literal credential is rejected, so the token must be read from the file inside the command. The token file is a long-lived secret readable by anything that can run O1 commands: keep it out of Git and out of shared backups.

## Limits

- One-shot `mac_terminal_exec`: 30 s default, 120 s maximum, 128 KiB of output. Model calls near the limit can time out.
- `mac_terminal_session`: at most 600 s, 120 s idle, two at once. Every `write` needs its own approval. The first `read` must pass `cursor: 0`; later reads use the returned `next_cursor`. `write` does not return a cursor.
- O1 runs with the owner's macOS permissions and no isolation. It is not root and does not bypass macOS privacy controls.

## Verification checklist

1. `mac_capabilities` shows both terminal tools with `enabled: true`. `scope_not_granted` means the OAuth grant predates the upgrade: remove the connector and add it again, or run `revoke-all` as described in [OAuth login operations](oauth-login-operations.md).
2. `which claude codex pi` and the three `--version` commands succeed.
3. Each CLI returns an exact reply to a one-line prompt (`CLAUDE_OK`, `CODEX_OK`, `PI_OK`).
