# Experimental sandbox profile runner evidence

Date: 2026-09-13
Source commit: `1e3eb86` (`test: expand sandbox secret surface checks`), building on `08a2913`, `3e4b065`, and `2e6cd57`
Working tree: clean before evidence commands
Host: Mac mini `Mac16,10`, Apple M4, 16 GB, arm64
OS: macOS `26.2`, build `25C56`
Runtime: Node `v25.5.0`
Scope: disabled-by-default `SandboxExecTaskRunner`, synthetic temporary fixture only; no real credentials or production task profile

## Boundary exercised

`renderTaskSandboxProfile` constructs a Broker-owned deny-default Seatbelt
profile from a resolved named `TaskProfile`. The default `processTreePolicy`
is `single_process`, so the profile does not grant `process-fork`; an explicit
`owned_group` profile is the only path that adds that rule and still requires
separate evidence. The renderer accepts only canonical
non-broad filesystem roots, the Broker-resolved executable, an in-root cwd, and
`networkPolicy: "none"` or a loopback-only allowlist; caller-supplied SBPL and
non-loopback network destinations are not accepted. Global credential/system zones and representative project secret
names are explicitly denied after the allowed-root rules. The runner invokes
only `/usr/bin/sandbox-exec` through `ProcessSupervisor`, with an explicit cwd,
profile-owned executable/arguments, profile environment, timeout, output cap,
and cancellation callback.

`TaskIsolationProof` includes the selected `processTreePolicy`; Broker
admission rejects a proof whose process policy differs from the resolved task
profile.

## Automated checks

- `npm test`: 291 tests, 289 passed, 2 default opt-in real-host tests skipped.
- `MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js`:
  6 passed, 0 failed, 0 skipped.
- Renderer tests reject `/`, `/System`, `/Users`, `/private`, cwd escapes, and
  network allowlists; runner tests verify the supervisor receives only
  Broker-rendered sandbox arguments and remains unavailable without explicit
  host evidence and opt-in. The real runner also maps active cancellation to
  detached process-group termination, and proof validation rejects a
  single-process/owned-group policy mismatch. Renderer tests accept only
  loopback `tcp`/`udp` destinations.

## Real-host smoke results

The opt-in fixture ran `/bin/bash` with an explicitly empty environment and a
temporary allowed root. The child reported the parent controller, `HOME`, SSH
agent, and AWS profile canaries as unset; it could read an allowed fixture,
could not read `/private/etc/passwd`, a root-contained `.env`, or a symlink to
the protected file, and created/read back a file inside the allowed root. An
loopback allowlist fixture reached its selected HTTP server and returned its
bounded response; the same profile denied a second loopback port. An
independent `/usr/bin/curl` probe to `http://example.com` returned a
non-success result with empty stdout (DNS resolution was denied, exit 6). A
script attempt to launch `/bin/sleep` as a child was rejected with a fork
permission error and only its pre-attempt output; a separate direct
`/bin/sleep` fixture was cancelled through the runner and returned `CANCELLED`
after process-group termination. The same real-host probe found the current
user's `.ssh`, `.docker`, Chrome, Safari, Mail, Messages, and Keychains
directories, plus `/var/run/docker.sock`, unavailable to the task; it checked
only existence/readability and did not read credential or daemon content.

| Dimension | Result | Evidence | Residual risk |
|---|---|---|---|
| Broker-owned profile construction | `ENFORCED` for tested inputs | Deny-default deterministic renderer; arbitrary SBPL is never accepted; broad roots/cwd escapes/network declarations fail closed. | Renderer is a narrow Seatbelt subset; complete macOS policy semantics and future profile changes still need review. |
| Allowed-root read/write | `PARTIAL` | Allowed fixture read and create/readback inside a temporary root succeeded; a root-contained `.env` and symlink to `/private/etc/passwd` were denied. | Remount identity, hardlinks, mount escapes, and concurrent target swaps are not covered by this runner smoke. |
| Protected system/secret paths | `PARTIAL` | `/private/etc/passwd`, a root-contained `.env`, a protected-file symlink, and the current user's existing `.ssh`, `.docker`, Chrome, Safari, Mail, Messages, and Keychains directories were denied; global and project secret deny rules are rendered. | Real credential contents, cloud, package, Git, and signing stores were not opened. |
| Environment isolation | `PARTIAL` | Explicit empty environment hid controller, `HOME`, SSH-agent, and AWS-profile canaries. | This is ProcessSupervisor/profile evidence, not proof that every future profile or launcher has no secret inputs. |
| Network allow/deny | `PARTIAL` | A loopback allowlist reached its selected `localhost:port`; an unlisted loopback port was denied, and an external curl DNS/network probe returned exit 6 with no stdout. | External allowlisted destinations, DNS pinning, non-DNS addresses, UDP behavior, and broader egress controls remain untested. |
| Process-tree ownership | `PARTIAL` | The default profile omits `process-fork`; a child-launch attempt was denied, a built-in-only Bash fixture completed without descendants, and a real `/bin/sleep` fixture was cancelled through the runner with detached process-group termination. The runner now refuses `owned_group` even when an external proof is supplied. | `setsid`, timeout/crash/restart cleanup, and a real task Job lease remain untested. |
| Credential/Docker/persistence/privilege isolation | `PARTIAL` | The real smoke confirmed existing `.ssh`, `.docker`, browser, Mail, Messages, Keychains, and `/var/run/docker.sock` surfaces were not readable, without opening their contents. | Credential contents, Docker protocol behavior, launchd, persistence, and privilege isolation remain unproven; `mac_task_run` remains disabled. |

## Decision

This evidence moves the implementation boundary forward but is insufficient to
select deprecated `sandbox-exec` as the production task boundary. The runner
requires a profile-matched `TaskIsolationProof`, explicit opt-in, and an
external host-evidence gate; the default `FailClosedTaskRunner` and Broker
capability state remain unchanged. MOP-086, MOP-043, and MOP-045 stay blocked
pending hostile credential/process/persistence/cleanup evidence or a stronger
isolation design.

The focused real-Mac smoke was rerun from `1e3eb86` with
`MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js`:
7/7 tests passed, including the owned-group refusal guard and the existing
environment, filesystem, network, child-launch, and active-cancellation
fixtures. The host evidence remains partial and does not select deprecated
`sandbox-exec` for production.

## Fresh current-revision readback

The same opt-in command was rerun from source revision `e10f380` after the
authenticated Keychain-delivery change, with a clean worktree before the
verification command. Result: 7 passed, 0 failed, 0 skipped. No Keychain item,
LaunchAgent, real credential contents, Docker protocol, persistence mechanism,
or privileged action was touched. This refreshes the evidence to the current
source revision but does not change the `PARTIAL` decision or unblock
`mac_task_run`.
