# Root Cause Report — Docker / Codex blocked after OrbStack restart

Date: 2026-10-09 (SGT) · Host: `yaps-Mac-mini.local` (macOS 26.2, arm64) · Repo base: `main` @ `040c491`
Live release inspected: `personal-20261009-040c491` (pm2 `mac-operator-personal`, pid 23034, data root `MacOperator-g1-20260925a`)
Method: read-only inspection only. No production file, process, policy or socket was changed.

Evidence labels: **[HOST]** observed on the real Mac mini · **[AUDIT]** read from a copy of `broker.sqlite` · **[CODE]** read from source · **[INFER]** deduced, not directly observed.

## 1. Verdict

| Symptom | Real cause | Security violation? |
|---|---|---|
| `mac_docker_status` / `mac_codex_run` → `Container Engine socket path or ownership changed or is unsafe` | The Broker pins the Docker socket **inode + device** and the engine **daemon PID + start time** once, at process start, and has no way to re-pin. OrbStack was restarted at 11:00:28 and recreated both. | **No.** A fresh engine built from unmodified code against the current socket passes every strict check [HOST]. It is a legitimate engine restart rejected by a pin that can never be refreshed. |
| `mac_policy_explain` → `deny / TARGET_NOT_AUTHORIZED`, `missing_scopes: []` | `mac_policy_explain`'s public input schema cannot express a `docker_runtime` / `docker_object` target. Any target a caller can send mismatches the policy rule kind. | **No.** It is a contract gap in the explain tool. Real execution of the same tool was authorized by `policy-8` (audit 11173). |
| `mac_stat_path` → `Filesystem target escaped its authorized root or volume` | `statPathWithinRoot` opens the target with `open(2)`; a Unix socket cannot be opened (`EOPNOTSUPP`). A catch-all relabels every native failure as "escaped root". | **No.** Expected limitation, misleading text. Independent of the Docker failure. |

The three failures are **independent**. Only the first blocks Docker and Codex.

## 2. Finding F1 (primary) — pinned socket identity cannot survive an engine restart

### 2.1 Mechanism [CODE]
`packages/broker/src/container-engine.ts`
- `:93` `socketIdentity` is `readonly`; set once at `:126` from `lstatSync()` in the constructor.
- `:100`, `:116` `peerPolicy` (incl. `allowedProcessIdentity` = daemon PID + start time) is `readonly`; `:121-122` the peer verifier is built from it once.
- `:466` every `exchange()` calls `assertSocket()`; `:484-489` the connect-time check repeats it and verifies the peer PID.
- `:537-556` `assertSocket()` rejects when `socket.dev/ino` differs from the constructor snapshot. The single `catch` at `:556` throws the reported message for **any** reason (not a socket, symlink, wrong owner, loose mode, bad parent, ACL, or inode changed), so the message cannot tell a restart from an attack.

`packages/auth/src/personal-development-runtime.ts`
- `:66-76` the engine peer is captured and `DockerContainerEngine` is constructed **once** at service start; the object is shared by `mac_docker_status` (`:112`), `validateRuntime` (`:93`, used by `mac_codex_run` planning at `container-task-profile.ts:121`) and the task runner.
- Nothing recreates or refreshes it. Only a Broker restart re-pins.

### 2.2 Timeline [HOST][AUDIT]
| Time (SGT, 2026-10-09) | Event |
|---|---|
| 08:05:38 | Broker (pid 23034) started; pins socket + daemon identity as they were then (`service.lock` startTimeMicros 1791504338152718). |
| 11:00:28 | OrbStack restarted: new daemon pid 48396. |
| 11:00:29 | `~/.orbstack/run/docker.sock` **born** (birth = mtime = 11:00:29), inode `382583756`. |
| 12:23:38 | `mac_codex_run` — audit 11158: `decision=deny POLICY_DENIED target=unresolved` (fails while planning, before any target exists). |
| 12:35:23 | `mac_docker_status` — audit 11173 `allow/AUTHORIZED docker_runtime:local`, then 11174 `completion = POLICY_DENIED`. |

Last successes: `mac_docker_status` 2026-10-08 22:09:50 (audit 10346), `mac_codex_run` 2026-10-08 21:22:32 (audit 10266) — both under the same `policy-8`.

The socket and its owning daemon were created ~3 h **after** the Broker pinned its snapshot, so both pins are necessarily stale [INFER, but forced by the timestamps]. The old inode and PID were not persisted, so they cannot be read back.

### 2.3 The new socket is legitimate [HOST]
A fresh `DockerContainerEngine` built with **unmodified** code (same steps as `personal-development-runtime.ts:66-77`) against the live socket succeeded:
```
socket: isSocket=true uid=501 mode=755 realpath==path aclOnSocket=false ino=382583756
peer:   uid=501 gid=20 pid=48396 (OrbStack Helper, started 11:00:28)
info:   engineIdMatchesApproved=true  server 29.4.0  aarch64  cgroup v2
```
So: canonical path, no symlink, owner, mode, parents, ACLs, peer uid/gid and the approved `engineId` (`a235e0b0-…`, pinned in `development-runtime.json`) all pass. The docker CLI context `orbstack` points at the same path. `/var/run/docker.sock` is a root-owned symlink to it (not used by the Broker, whose config pins the real path).

Conclusion for question 8: **a legitimate socket change is being incorrectly rejected; no genuine violation was found.**

### 2.4 Engine identification (questions 1–3)
- Active engine: **OrbStack** (docker context `orbstack` is current; Docker Desktop socket `~/.docker/run/docker.sock` does not exist). `desktop-linux` context is stale.
- Socket: `/Users/yapweijun/.orbstack/run/docker.sock` — real socket, `uid=501 gid=20 mode=0755`, no ACL, not a symlink, dev `16777231` ino `382583756`, listener = OrbStack Helper pid 48396.
- Config: `development-runtime.json` pins that path, `engineId a235e0b0-1868-4917-9802-6b826785b2c6`, `imageId sha256:90e9d231…`.

## 3. Finding F2 — `TARGET_NOT_AUTHORIZED` from `mac_policy_explain` (questions 6, 9)

- `policy-8` is correct. The signed policy (`revision 8`) grants the owner principal `mac.docker.read` and has two allow rules: `docker_runtime/local` and `docker_object/all` [HOST: `policy.json`]. `mac_docker_status` plans exactly `{kind:"docker_runtime", reference:"local"}` (`broker.ts:5148-5156`), and the execution decision was **AUTHORIZED** (audit 11173). Docker target authorization already matches the intended policy.
- `mac_policy_explain` forces the caller to name the target (`broker.ts:2796`, default `host:broker`). The Broker accepts `docker_runtime` (`broker.ts:6942-6945`), but the public contract `tool-contracts/mac_policy_explain.json` (`target.kind` enum, line 45) lists only `host, path, project, process, job, app, app_window, ui_element, service, package, power`. `docker_runtime`, `docker_object`, `task_profile`, `app_set`, `log_source` are missing. With any listed kind, `authorizeTarget()` finds no rule of that kind and raises `TARGET_NOT_AUTHORIZED` (`policy.ts:386-400`); `missing_scopes` is `[]` because the caller does hold the scope.
- With `proposed_arguments`, `broker.ts:2807` additionally requires `planned.target == target`, so the correct docker target is unreachable through the public schema either way.
- Reproduction limit: this Claude session's principal does **not** hold `mac.docker.read` (`mac_policy_explain` for `mac_docker_status` with a `host` target returned `SCOPE_DENIED`, `mac_docker_status` is not exposed). The reported output is therefore explained from code, and is covered by a new unit test rather than a live replay.

## 4. Finding F3 — `mac_stat_path` "escaped its authorized root or volume" (question 9)

- Audit 11177/11178: authorized on root `system-metadata`, then `completion = POLICY_DENIED`.
- Live probes through the Broker [HOST]: stat of `/var/run/docker.sock` and of `/Users/yapweijun/.orbstack/run/docker.sock` (`follow_symlink=false`) are denied; stat of the directory `/Users/yapweijun/.orbstack/run` and of a regular file succeed.
- `peer_credentials.cc:1733-1747` opens the target with `openat(..., O_RDONLY|O_NONBLOCK|O_NOFOLLOW)`. On macOS that fails for a socket node: Python probe of the same flags on the OrbStack socket → `EOPNOTSUPP` [HOST]. `filesystem-inspector.ts:1138-1143` wraps every native error into "escaped its authorized root or volume".
- Not a root-escape and not a symlink-protection event. It means `mac_stat_path` cannot report on socket nodes. Left unchanged: loosening the opener would widen the filesystem boundary for no Docker benefit. Recommendation only (see fix report).

## 5. What I could not verify
- The exact pre-restart inode / daemon PID (never persisted).
- The per-request error text (audit stores only the result class, not the message).
- A live replay of the user's `mac_policy_explain` call (principal lacks the docker scope).
- Post-fix behaviour **inside the running Broker** — deploying is forbidden in this task. Post-fix checks run against the real socket from the isolated build instead (see fix report).

## 6. Related prior art
`OPERATIONS.md:117-136` records the 2026-10-06 incident where Docker being absent at startup failed the whole service, and lists "make Docker an optional dependency" as an open follow-up. Same family: the engine identity is evaluated once and never refreshed.
