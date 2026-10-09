# Container Engine restart revalidation — host evidence (2026-10-09)

Branch `fix/container-engine-socket-revalidation` (base `040c491`). Host: `yaps-Mac-mini.local`, macOS 26.2 arm64, Node 25.5.0,
OrbStack Docker engine 29.4.0. Nothing was deployed, restarted or changed on the live Broker or on OrbStack.

## 1. Why the live Broker rejected the engine

| Fact | Value | Source |
|---|---|---|
| Broker process start | 2026-10-09 08:05:38 SGT, pid 23034 | `ps`, `personal/run/service.lock` |
| OrbStack restart | 11:00:28 SGT, daemon pid 48396 | `ps -o lstart` |
| Socket birth / mtime | 11:00:29 SGT, inode 382583756 | `stat -f %SB` |
| First failing audit rows | 12:23:38 `mac_codex_run` (11158), 12:35:23 `mac_docker_status` (11173/11174) | copy of `broker.sqlite` |
| Last successes | 2026-10-08 22:09:50 `mac_docker_status` (10346), 21:22:32 `mac_codex_run` (10266) | same |

The socket and daemon were created about three hours after the Broker pinned them, so both pins were necessarily stale.
A fresh, unmodified engine built against the same socket passed every strict check (socket type, owner 501, mode 0755, no ACL,
canonical path, parents, peer uid/gid, approved engine ID `a235e0b0-…`), so the change was legitimate.

## 2. Real-host verification of the fix (read-only)

`host-verify.mjs` builds the engine from this branch against the live socket. OrbStack is not restarted (that would stop the
owner's containers); staleness is reproduced by overwriting the engine's in-memory pins with a wrong inode and a dead daemon
identity. Real in this run: the socket, structural and ACL checks, kernel peer credentials, the daemon PID and executable, and
the Engine API.

```
{"step":"pin-at-startup","pid":48396,"startTimeMicros":1791514828732756,"executable":"/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper"}
{"step":"A-control-stale-no-revalidation","result":"denied","message":"Container Engine socket path or ownership changed or is unsafe"}
{"step":"B-revalidated","engineIdMatchesApproved":true,"serverVersion":"29.4.0","event":{"outcome":"accepted","reason":"ENGINE_RESTART_REVALIDATED","fencedWorkspaces":0,"current":{"inode":382583756,"pid":48396},"engineId":"a235e0b0-1868-4917-9802-6b826785b2c6","previous":{"inode":382583757,"pid":99999}}}
{"step":"B-docker-status","daemon":{"available":true,"version":"29.4.0","context":"local"},"containerCount":8}
{"step":"B-codex-validateRuntime","imageMatchesApproved":true,"os":"linux","architecture":"arm64"}
{"step":"B-second-call-no-new-revalidation","acceptedEvents":1}
{"step":"C1-wrong-approved-engine-id","result":"denied","message":"Container Engine identity changed","reason":"ENGINE_IDENTITY_CHANGED"}
{"step":"C2-wrong-approved-executable","result":"denied","message":"Container Engine daemon executable differs from the approved one","reason":"ENGINE_EXECUTABLE_CHANGED"}
```

Reading: A reproduces the reported message with revalidation off; B shows an accepted revalidation (`previous` is the injected
stale pin, `current` is the live socket and daemon), then Docker status, the Codex-style runtime check (approved image) and a
second call that does not revalidate again; C1/C2 deny a wrong approved engine ID and a wrong approved executable.

## 3. Real-process restart test

`packages/broker/src/container-engine-revalidation.test.ts`, test "real host: a restarted daemon process is revalidated, an
impostor executable is not". A stand-in daemon is a child `node` process on a Unix socket. The production engine, the native
peer adapter and the real pid/start-time/executable lookups are used (no test seam). The daemon is killed and restarted (new
pid, new inode: accepted, one `ENGINE_RESTART_REVALIDATED` event), then replaced by a byte-identical copy of `node` at another
path (denied with `ENGINE_EXECUTABLE_CHANGED`, zero requests received).

## 4. Not verified here

- A genuine OrbStack restart through the deployed Broker (needs a deploy and an engine restart; both out of scope).
- `mac_codex_run` end to end (needs the deployed Broker and the owner's Codex login).
- Code-signature (Team ID) identity of the engine daemon: continuity is by executable path only.
