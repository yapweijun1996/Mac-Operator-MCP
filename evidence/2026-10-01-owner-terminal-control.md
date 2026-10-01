# Personal owner terminal verification — 2026-10-01

Status: PASS for the requested owner-account terminal/CLI capability. This is
personal O1 execution, not isolated-task or formal production release acceptance.

## Source and rollout

- Branch: `codex/owner-terminal-control`, based on `0be86f548aab5b178064279e95ff309972abfd18`.
- Runtime source: `fa215d61ba553c306127a0f0a676dffd39bd6cc3`.
- Worktree: `/Users/yapweijun/.codex/worktrees/owner-terminal-control/Mac-Operator-MCP`.
- Release: `/Users/yapweijun/Library/Application Support/MacOperator/releases/personal-20261001-o1a`.
- Protected state: `/Users/yapweijun/Library/Application Support/MacOperator-o1-20261001a`.
- Endpoint: `https://mac.yapweijun1996.com/mcp`.
- Supervisor: PM2 `mac-operator-personal`, online after two intentional fix restarts.
- Profile: O1, signed policy revision 2, 24 scopes, 38 runtime tools.

The previous G1 release `personal-20260925-g1a` and complete protected state
`MacOperator-g1-20260925a` were preserved. The offline upgrade retained OAuth
clients, owner identity, TLS and browser grants, rebased fixed state paths and
kept the ChatGPT/Claude callback allowlist. Protected `rollback-launch.json`
contains prior supervisor arguments without environment variables or credentials.
Rollback selects that complete previous pair after stopping O1.

The independent owner worktree/release avoids overwriting the concurrent V2
work in the primary checkout. These commits have not been merged into that
checkout or pushed.

## Local verification

- Native build and TypeScript build passed; final TypeScript check passed.
- Full suite: 1,291 total, 1,274 passed, 17 explicitly skipped, 0 failed.
- Style, documentation links, 46 contract schemas and final diff checks passed.
- Final owner-terminal focused tests: 3 passed, 0 failed.
- Independent read-only review accepted the implementation; all reported
  serious findings were fixed and independently rerun.

Regression coverage includes delayed command delivery until process ownership
is recorded, environment isolation, pipelines, file writes, nonzero exits,
scope and approval denial, output limits, timeout, explicit cancellation,
session revocation, Job readback, idempotent reuse and refusal to rerun archived
idempotency keys. G1/O1 provisioning tests cover a different-root offline copy,
issuer separation, browser-grant migration and the unchanged original G1 copy.

## Public OAuth and runtime verification

The final verifier completed using real public HTTPS owner login, explicit
consent, S256 exchange and a temporary registered client. It never printed or
persisted credentials or bearer tokens. Its temporary client/grant and file
canaries were cleaned up.

1. OAuth metadata advertised exactly 24 O1 scopes; unauthenticated MCP returned 401.
2. The consented token carried exactly 24 requested scopes and matching issuer,
   audience, owner and session identities.
3. MCP listed exactly 38 tools, including `mac_terminal_exec`; 26 real read calls passed.
4. A 31-second shell command completed with exit 0. Git, Node and Codex CLI
   versions were observed. A successful HTTPS request was required before
   emitting the network marker; stderr was empty.
5. The command wrote/read a counter. A matching idempotency replay reused the
   result and left the counter at one execution. Owner Job readback was completed.
6. A 150 ms timeout returned `TIMEOUT`; the command's later marker was absent.
7. Revoking the OAuth grant stopped a running command and returned `CANCELLED`.
   Direct read-only SQLite verification showed state `cancelled`, a durable
   cancellation marker and empty process ownership. The late marker was absent.
8. The next MCP request with the revoked token returned 401.
9. A separate old-read-scope grant listed exactly 27 tools, omitted terminal
   authority, passed 26 reads and rejected the next request after revocation.
10. Snapshot preflight passed against the new protected root and loopback CA.

Final readback found zero queued/running terminal Jobs. Signed policy explicitly
enables terminal authority and leaves `mac_task_run` disabled. PM2 configuration
was saved for the selected O1 release/state pair.

## Issues found and corrected

- Approval validity now covers the requested command budget plus bounded
  completion time, capped at the OAuth grant expiry.
- Job tombstones are checked before approval consumption and new admission.
- Parsed IPC requests use a bounded processing deadline instead of retaining
  the 15-second framing timeout throughout a long command.
- Offline copied-state upgrades rebase only validated fixed state paths.
- Capability discovery authorizes the same exact `host:owner-terminal` target
  used by command execution.
- Observed authority cancellation creates the existing durable cancellation
  marker before terminal persistence, preserving the Store's cancellation fence.

Two early revocation-test Jobs retain conservative `unknown` records from before
the last fix; they were not replayed or changed into success. Their recorded
root and descendant PIDs were absent during final readback. Startup recovery
continues to report its conservative unknown outcome because owner execution
cannot prove complete post-exit containment. The final strengthened public
revocation probe recorded cancellation correctly.

## Practical limits

The tool runs arbitrary commands as the non-root macOS owner. It supports
shell syntax, owner files, local CLIs and network access. It is synchronous and
noninteractive, with a 30-second default/120-second maximum and bounded output.
Administrator authentication and macOS privacy permissions remain controlled
by the OS. Owner programs can create side effects or daemonize; observed
process cancellation does not establish complete isolation or automatic rollback.
Signature-based output redaction cannot guarantee that arbitrary shell commands
will not disclose owner-accessible sensitive data. Existing grants require fresh
consent to acquire the new scope.
