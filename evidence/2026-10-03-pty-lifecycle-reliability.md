# PTY lifecycle reliability

Date: 2026-10-03 (Asia/Singapore). Host: macOS arm64, unprivileged owner.
Runtime: Node 24.21.0. Claude Code: 2.1.287. Broker package: 0.1.0.

## Root cause and attribution

The shared Node/native Broker IPC handler lacked a Socket `error` listener. A real loopback connection reset delivered `read ECONNRESET` (errno -54), causing the pre-change Broker-handler child process to exit with code 1 before its survival marker. A disconnect can therefore fail unrelated tools by terminating the Broker, independently of any terminal control sequence. The isolated regression uses the same `handleBrokerSocket` as the native UDS transport.

The original outage coincides with an explicit PM2 service stop/restart. Local PM2 records show `mba-mcp` stopping at 2026-10-02 23:47:57, exiting code 0 via SIGINT at 23:47:59, then repeated code-1 startup failures until 23:52:02. Host timezone is Asia/Singapore (+08), matching the ticket's 15:47:59Z termination time; the historical daemon timezone itself was not recorded. Service stderr contains only the fixed message `Personal service failed closed; check protected configuration and service prerequisites.` No ECONNRESET/EPIPE/unhandled-error marker was found in those service logs. Who requested the stop and which startup prerequisite failed remain unknown.

A read-only query of the exact original Job confirmed `state=unknown`, `result_class=unknown`, `finished_at=2026-10-02T15:47:59.043Z`, `exit_code=null`, `cancel_requested=0`, `cancel_reason=null`, and retained process metadata. This is not the normal `BROKER_RESTART` reconciliation signature, which writes a durable cancellation marker and restart reason. With the already successful start, the supported inference is an unresolved PTY finalization during the coordinated service stop. The precise process-observation/cleanup failure cannot be recovered from those fields. The service's SIGINT handler awaits Broker close and job persistence before closing the store.

The unmodified build's isolated real Claude `/private/tmp` trust screen, parallel health/terminal exec, Ctrl-C and stop probe succeeded (`completed`, exit 0). Claude itself has not been established as the cause of either the PM2 stop or a global Broker failure. The independently reproduced connection-reset crash above is a separate confirmed reliability defect.

Other concrete defects were found: Node writable backpressure was reported as rejected input; supervisor startup stdin errors killed only the relay; the manager deleted sessions on supervisor rejection; finished publication/expiry preceded authoritative finalization; persistence errors were swallowed; and close/proof async rejection paths were unguarded.

## Implementation

- `ipc-server.ts`: socket errors and response write exceptions destroy only the offending connection.
- `process-supervisor.ts`: stdin errors are observed before startup awaits; accepted queued writes return true; end is idempotent; stdin/output-consumer failures drain their process tree before returning a local failure; async exit-proof/close failures are caught. Startup stdin binding failure uses verified tree cleanup. A root exiting between native liveness and identity reads is resolved by one identity recheck plus an ESRCH-only signal-0 probe; observation failure or PID replacement remains unknown. This race is proven by deterministic tests, but is not proven to be the historical incident's exact observation failure.
- `owner-terminal-session.ts`: opaque nonblocking PTY input relay handles partial writes, EINTR/EAGAIN and terminal EOF; shutdown HUPs the attached terminal groups, escalates only the unreaped direct child, then relies on native PID/start-time checks for surviving descendants. Bounded relay diagnostics expose only errno. No Claude special case is used.
- `owner-terminal-session.ts`: lifecycle is starting -> running -> stopping/finalizing -> committed terminal outcome -> retained -> expired. Startup rejection and exit-before-ready settle the start promise. Finalization precedes finished publication/retention. Failed persistence retains the session and surfaces structured errors, including on shutdown.
- `owner-terminal-session-dispatch.ts`: proven orphan cleanup is failed rather than unknown; durable cancellation wins an exit race and the committed state is returned to the manager; pre-execution failures receive failed jobs. Genuine uncertainty has an explicit diagnostic and preserved process ownership.
- Changed tests: `ipc-server.test.ts`, `process-supervisor.test.ts`, `owner-terminal-session.test.ts`, and new `owner-terminal-session-reliability.test.ts`. `docs/owner-terminal.md` and this evidence record document the behavior and limits.

## Verification

Commands use `PATH=/opt/homebrew/opt/node@24/bin:$PATH`. Full supervisor checks run outside the filesystem sandbox because sandboxed system Python emits a macOS `confstr()` warning that contaminates pre-existing tiny-output fixtures; no checks were weakened.

| Check | Result |
| --- | --- |
| Pre-change IPC connection reset in isolated subprocess | Exit 1, unhandled `read ECONNRESET`, no survival marker |
| Post-change IPC reset before and during pending request | Exit 0; later health and actual `/bin/echo PARALLEL_OK` succeed |
| IPC regression suite | 15/15 pass |
| Process supervisor regression suite | 58/58 pass, including six exit-race proof tests and unchanged PID replacement/ownership uncertainty checks |
| Existing terminal-session suite | Pass with new finalization/startup/cancellation tests |
| stdin wait and raw alternate-screen/mouse/bracketed-paste fixture | Read/write/stop and concurrent health/exec pass |
| SIGKILL foreground and PTY relay | Explicit final jobs, tracked descendants absent, unrelated calls succeed |
| read/write/repeated-stop races and expiry | Structured results/errors; final public job state committed before expiry |
| Durable cancel vs process-exit race | Public job status and retained session read/stop agree `cancelled` |
| Broker shutdown with active raw TUI | Final Job committed as cancelled/failed, observed tree absent, repeated close succeeds |
| 50 sequential raw-TUI start/stop cycles | Final integrated run: 22,491 ms; 0 unknown jobs, 0 surviving observed children, 0 retained registry entries after expiry |
| Real Claude trust screen | 6 consecutive outside-sandbox runs plus final integrated-build recheck pass; `/private/tmp`, `No, exit`, `completed/0`, health/exec succeed, observed tree absent |
| Workspace trust flag | `/private/tmp` trust flag unchanged after each real Claude run |
| Full repository suite | 1,697 tests: 1,678 pass, 0 fail, 19 skipped; 62,278 ms |
| Typecheck / style / documentation links | Pass |
| Verification matrix / diff whitespace | Pass |

Stress cycles exercise a foreground TUI and its `sleep` child, raw input and alternate-screen control bytes. Each cycle polls public `mac_job_status`, checks process disappearance, and makes independent health/exec calls. Retention is shortened to one second by Broker-owned test configuration; production retains 60 seconds. The fixture verifies expiry for every session.

Real Claude checks are opt-in to avoid launching user-installed software during normal CI:

```sh
MOPS_REAL_CLAUDE_PTY=1 node --test --test-timeout=120000 \
  --test-name-pattern='real Claude trust screen' \
  packages/broker/dist/owner-terminal-session-reliability.test.js
```

During implementation, an intermediate relay version produced intermittent `failed/1` after trust refusal. A later final-build check returned `failed/0`: instrumentation proved that the relay exited 0 while a tracked CLI descendant was still alive, requiring identity-bound orphan cleanup (`unknown`, `terminationObserved=true` at the supervisor boundary). This is a concrete failure rather than success and is correctly reported as failed. There was no stdin error or Broker outage. The real trust test now waits for an actual shell `CLAUDE_EXITED` marker after `No, exit`, then stops the shell; the strict `completed/0` assertion remains. Six consecutive outside-sandbox runs passed. No original global Claude outage was reproduced by the isolated CLI probes.

## Remaining limits

- No deployed Broker/Edge was upgraded or restarted. Signed service release adoption and production reproduction remain separate from this checkout's verification.
- Abrupt Broker/OS termination, native observer failure, PID replacement, or unavailable durable storage cannot honestly establish a successful process outcome. Genuine uncertainty remains `unknown` with diagnostics/ownership rather than being converted to success; restart recovery remains unchanged. Consequently the ticket's absolute requirement that every PTY always becomes one of four concrete states is not claimed for those conditions.
- Cleanup proves disappearance of observed PID/start-time identities. Owner-terminal mode still cannot contain deliberate daemonization or descendants that escape between observations.
- The 50-cycle test proves the in-process signed Broker path plus isolated IPC reset behavior; it is not 50 production OAuth/Edge transport cycles. It does not establish the historical trigger or indefinitely exclude every possible transport failure.

The implementation resolves reproduced connection-crash and PTY lifecycle defects, with the remaining acceptance boundaries stated above.
