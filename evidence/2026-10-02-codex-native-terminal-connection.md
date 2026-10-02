# Codex native owner terminal connection

Status: PASS, October 2, 2026. The owner authorized adding and authenticating the
independent terminal connection. Implementation commits are `5032f64` (native
OAuth callbacks) and `8066356` (native MCP protocol and cancellation).

## Installed client and service

The user Codex configuration now contains `mac-terminal` pointing to
`https://mac.yapweijun1996.com/terminal/mcp`. Native CLI OAuth registration,
owner login/consent, S256 exchange and callback delivery completed successfully.
Codex itself saved its credentials; no credential store was read or exported.
Both Homebrew Codex 0.153.4 and bundled Codex 0.159.2 report OAuth authentication.

The callback is exactly `http://127.0.0.1:61989/callback`, with a listener pinned
to the same loopback port. HTTP redirect records accept only canonical IPv4
loopback with an explicit unprivileged port, no credentials/query/fragment, and
an exact protected-config allowlist match. All issuer/resource bindings remain
HTTPS. Existing HTTPS callbacks remain available.

The native client timeout is 150 seconds, covering the server's 120-second
command limit. Only `mac_terminal_exec` has client `approval_mode = "approve"`,
under the owner's explicit authorization. Global approvals, other servers and
Broker policy remain unchanged. Terminal commands run as the macOS owner;
root privileges and macOS TCC remain separate boundaries.

## Findings and fixes

Native registration initially failed because HTTPS-only redirect records could
not represent Codex's loopback callback. Dedicated redirect validation fixes
that without allowing HTTP issuers/resources or redirect wildcards.

An explicit `oauth_resource` client override duplicated the resource already
discovered by Codex 0.153.4. Removing the redundant override fixed authorization
HTTP 400 while retaining strict single-resource validation.

Codex 0.153.4 sends MCP 2025-06-18. Only the independent terminal resource now
permits the official SDK stateless legacy handler; default V2 remains
modern-only. Both protocol paths use the same authenticated governed factory.
Modern malformed headers/envelopes cannot downgrade into legacy handling.

Independent review reproduced an SDK race: a request cancelled before its abort
listener was installed could still deliver a tool. The factory checks captured
HTTP cancellation before and after assembly, and execution combines HTTP/tool
signals and rejects pre-cancelled delivery. Tests cover cancellation before
assembly, during capability lookup, just after assembly with a cache hit, and
normal delivery. Independent validation also confirmed cancellation of running
gateway work. No serious review finding remains open.

The first native tool smoke encountered Codex's write-tool confirmation rule
under `approval_policy = "never"`. The authorized per-tool client override
resolved it; tool annotations and global policy were preserved.

## Verification

| Check | Result |
| --- | --- |
| TypeScript, style, documentation links, process-boundary audit, final diff | PASS |
| All Auth tests | 109 passed, zero failures |
| All Edge tests | 81 passed, zero failures |
| Independent bounded review tests | 14 passed; pre-abort and running cancellation verified |
| Native OAuth | PASS; exact loopback callback, S256 and terminal scope |
| Missing bearer, wrong resource, insufficient scope | Rejected before tool delivery |
| Root legacy requests and malformed modern requests | Rejected; no protocol downgrade |
| Native AI terminal invocation | PASS; `id -un`, `pwd`, `git --version`, `node --version`, exit 0 |
| Observed output | Owner `yapweijun`, selected primary cwd, Git 2.50.1, Node v25.5.0 |
| Job readback | Completed successfully, 91 ms execution duration |
| Native timeout | `/bin/sleep 3` with 150 ms returned TIMEOUT; durable failed Job, 181 ms execution |
| Process cleanup | Both observed Jobs have cleared process metadata; no active Broker Jobs |
| Existing V2 public OAuth | 48 tools, 26 actual reads, revocation rejects the next request |
| Protected authority | 22 key/policy/config authority files unchanged, owner account unchanged, five active grants preserved |
| Supervisor | Correct immutable release, online, zero automatic restarts, PM2 state saved |

The native AI proof used only the named MCP server and observed its actual tool
responses. Local shell tools were disabled for the smoke. No project files were
changed by the validation commands. Primary-checkout edits from other work were
preserved. No source merge, push or PR creation was requested.

## Release and recovery

Current release:
`/Users/yapweijun/Library/Application Support/MacOperator/releases/personal-20261002-terminal-codex-b`.
Current source revision: `806635607dc552a5fa8bf4322334b74f453d1896`.
826 runtime artifacts match the tested build; dependency workspace links resolve
inside the release. Source archives exclude `.env` and Git metadata.

The complete stopped-state backup immediately before this release is
`MacOperator/backups/codex-before-20261002-native-b/state`, with private
`deploy.config.cjs`, `rollback.config.cjs` and a Codex configuration backup.
It restores the prior native-OAuth release `personal-20261002-terminal-codex-a`
at `5032f64`; that release authenticates native clients but rejects MCP 2025.

The earlier backup `MacOperator/backups/terminal-before-20261002-codex-a/state`
preserves the service before HTTP callback records. Restoring a release older
than `5032f64` requires its complete matching Auth state, since it rejects native
HTTP redirect records. Stop the supervisor before recovery, preserve newer
state separately, restore the selected matching state/release, and verify both
resources before saving PM2. Tunnel routes and TLS pinning were unchanged here.

Private OAuth/client validation logs remain in those owner-only backup folders.
This evidence contains no passwords, tokens, OAuth codes or raw credential data.
