# Personal owner terminal (O1)

O1 is an explicit owner authorization profile for controlling a personal Mac through terminal and local CLIs. It adds `mac_terminal_exec` and `mac.terminal.exec` to G1. Existing profiles never acquire this scope automatically. The separate isolated `mac_task_run` tool retains its named-profile and isolation requirements.

## Execution contract

```json
{
  "command": "pwd; git --version; node --version",
  "cwd": "/Users/owner/project",
  "idempotency_key": "inspect-project-001",
  "timeout_ms": 30000
}
```

The Broker starts the immutable system `/bin/zsh -f -s` as the non-root owner, records process identity before delivering command input, and changes to the canonical requested directory. Commands support shell syntax, pipes, subprocesses and network access. The explicit environment includes the owner's HOME and a fixed Homebrew/system PATH; Broker credentials and ambient environment variables are not inherited. Local CLIs may use the owner's existing authentication files.

Command text is bounded to 32 KiB, delivered over stdin, and omitted from argv and audit records. Known literal credentials are rejected; bounded stdout and stderr are scanned and redacted before persistence. This is signature-based redaction, not a guarantee that arbitrary owner commands cannot disclose sensitive files. The owner shell has access to any state the owner account can access, including local application credentials and service configuration.

Each command has a durable Job and an exact single-use delegated approval bound to owner, tool, payload digest, policy revision and target `host:owner-terminal`. The delegated terminal issuer has its own key; the browser issuer remains attended. The two issuers use the existing versioned keyring and authenticated local approval channel. No browser approval dialog is required for each O1 command after the explicit local owner opt-in and OAuth consent.

Commands have a default 30-second timeout and a 120-second maximum. Output is limited to 128 KiB total and retained at no more than 64 KiB per stream. A nonzero program exit produces a recorded failed command with its exit code; observing the exit does not prove application-specific success. A matching owner/idempotency key reuses the persisted result. Changed payloads conflict, and running or unresolved Jobs are never executed again automatically.

Authority revocation, job cancellation, shutdown and timeout terminate observed process groups and tracked descendants. Arbitrary owner programs can daemonize or intentionally persist outside observed process ownership; this mode makes no complete containment or rollback claim. Restart recovery uses recorded PID/start-time identities and never converts an unresolved Job into success. The MCP call is synchronous and noninteractive; password prompts and interactive terminal sessions require a separate PTY feature.

## Interactive sessions (`mac_terminal_session`)

`mac_terminal_session` adds a PTY-backed interactive shell to O1. It reuses the `mac.terminal.exec` scope, the `host:owner-terminal` target, the delegated terminal issuer and the same owner-account authority as `mac_terminal_exec`; it adds no scope. The tool is disabled in the default policy, and an already-signed live O1 or V2 policy does not list it. **No upgrade path exists yet:** `owner-terminal` returns without change for an existing O1 state, and a service running this code against a policy that lacks the tool fails its startup capability check. A policy re-signing step must be added before this can be deployed; until then do not run this build against live state.

Actions (one tool, exact per-action arguments):

- `start` — `cwd`, `idempotency_key`, optional `rows`, `cols`, `lifetime_ms` (default 300 s, max 600 s), `idle_timeout_ms` (default 120 s). Creates a durable Job, persists the shell's process identity, returns `session_id` and `job_id`, and keeps the start request open until the session ends. At most two sessions run at once.
- `write` — `session_id`, `data` (at most 4 KiB, no NUL, known literal credentials rejected). Control characters such as Ctrl-C (`\u0003`) are allowed. Every write is its own request with its own single-use delegated approval bound to the payload digest; a start approval never covers later input.
- `read` — `session_id`, `cursor`, optional `max_bytes` (at most 32 KiB), `wait_ms` (at most 5 s). Returns redacted output, `next_cursor`, and `dropped_bytes` when the 256 KiB ring buffer overwrote unread output.
- `stop` — hangs up the shell and waits for the session to end; if the shell ignores the hangup the Job is cancelled and the process tree drained. `mac_job_cancel` on the session Job does the same.

Limits and behaviour: sessions are in memory and bound to the starting principal; another principal receives not-found. Revocation, Job cancellation, idle timeout, the absolute lifetime and Broker shutdown terminate the observed process tree. A Broker restart never resumes a session. The Job uses the generic terminal-Job process-identity recovery (the tool is covered by those queries), but no session-specific restart test exists yet. The session lifetime is also capped by the OAuth token: the start approval and the request authority end at the principal's expiry, which cancels the session. Output redaction is signature-based and applied per read, so a secret split across two reads may not be recognised. Output is never persisted. The PTY is created by `/usr/bin/python3`, a root-owned system executable, so no native Node dependency is added. The same disclaimers as one-shot O1 apply: no isolation, no rollback, daemonized descendants can escape observation.

## Permissions and disablement

O1 runs with the owner's existing macOS permissions. Administrator authentication, Accessibility, Automation, Screen Recording, Full Disk Access and other macOS controls remain OS-owned. Commands can launch applications, manipulate owner files, invoke CLIs and use networks or persistence allowed to that account. Structured-tool path restrictions and destructive/privileged kill switches do not constrain shell command contents. Revoke `mac.terminal.exec`, disable `mac_terminal_exec`, revoke the OAuth grant, or use the global/mutation/process/network kill switches to remove this execution authority.

## Installation and upgrade

For a fresh personal installation, pass `--grant-profile o1` to the existing Auth `init` command, then provision the personal service normally. O1 startup verifies the exact owner policy and delegated issuer boundary.

For an existing G1 installation:

1. Stop the personal supervisor and preserve a complete protected copy of its state and previous release. Do not copy live SQLite state during writes.
2. Use the verified O1 release against a protected offline copy of the state:

   ```sh
   node packages/auth/dist/personal-service.js owner-terminal /absolute/protected/state SOURCE_REVISION --enable
   ```

3. This preserves owner identity, TLS material, registered OAuth clients and browser grants; it increments signed policy and approval-key revisions, rebases fixed socket/key/TLS paths to the selected state directory, migrates retained browser consent to the new policy revision, and adds the terminal issuer.
4. Start the new release against the upgraded state and reconnect the MCP client to consent to the new scope. Existing grants retain their original scopes.

The offline upgrade changes several files and database activation identities; an interrupted upgrade fails startup validation. Preserve the original state until readback succeeds. Roll back by stopping the new supervisor and selecting the complete previous release/state pair, rather than decreasing a policy revision in the upgraded database.

## Verification

`owner-terminal.test.ts` exercises real shell/CLI execution, pipelines, file writes, environment isolation, refusal before command delivery when ownership audit fails, nonzero exits, timeout termination, denied scope/delegation, durable audits, idempotent replay, exact capability discovery and durable session-revocation cancellation. Personal service tests verify G1/O1 policy provisioning, issuer separation, offline G1 upgrade and browser-grant retention. The public verifier supports `--owner-terminal` for an OAuth-backed terminal smoke test and ordinary read regression checks. Its active-revocation check requires both a `CANCELLED` response and a persisted cancelled Job with cleared process ownership. The October 1 live rollout passed; see [verification evidence](../evidence/2026-10-01-owner-terminal-control.md).
