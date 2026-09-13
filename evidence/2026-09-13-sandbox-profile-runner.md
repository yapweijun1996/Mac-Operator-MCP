# Experimental sandbox profile runner evidence

Date: 2026-09-13  
Source commit: `684058c` (`feat: add experimental macOS sandbox task runner`)  
Working tree: clean before evidence commands  
Host: Mac mini `Mac16,10`, Apple M4, 16 GB, arm64  
OS: macOS `26.2`, build `25C56`  
Runtime: Node `v25.5.0`  
Scope: disabled-by-default `SandboxExecTaskRunner`, synthetic temporary fixture only; no real credentials or production task profile

## Boundary exercised

`renderTaskSandboxProfile` constructs a Broker-owned deny-default Seatbelt
profile from a resolved named `TaskProfile`. The renderer accepts only canonical
non-broad filesystem roots, the Broker-resolved executable, an in-root cwd, and
`networkPolicy: "none"`; caller-supplied SBPL and network allowlists are not
accepted. Global credential/system zones and representative project secret
names are explicitly denied after the allowed-root rules. The runner invokes
only `/usr/bin/sandbox-exec` through `ProcessSupervisor`, with an explicit cwd,
profile-owned executable/arguments, profile environment, timeout, output cap,
and cancellation callback.

## Automated checks

- `npm test`: 290 tests, 289 passed, 1 default opt-in real-host test skipped.
- `MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js`:
  5 passed, 0 failed, 0 skipped.
- Renderer tests reject `/`, `/System`, `/Users`, `/private`, cwd escapes, and
  network allowlists; runner tests verify the supervisor receives only
  Broker-rendered sandbox arguments and remains unavailable without explicit
  host evidence and opt-in.

## Real-host smoke results

The opt-in fixture ran `/bin/bash` with an explicitly empty environment and a
temporary allowed root. The child reported the parent controller-canary
variable as unset, could read an allowed fixture, could not read
`/private/etc/passwd`, and created/read back a file inside the allowed root.
An independent `/usr/bin/curl` probe to `http://example.com` returned a
non-success result with empty stdout (DNS resolution was denied, exit 6).

| Dimension | Result | Evidence | Residual risk |
|---|---|---|---|
| Broker-owned profile construction | `ENFORCED` for tested inputs | Deny-default deterministic renderer; arbitrary SBPL is never accepted; broad roots/cwd escapes/network declarations fail closed. | Renderer is a narrow Seatbelt subset; complete macOS policy semantics and future profile changes still need review. |
| Allowed-root read/write | `PARTIAL` | Allowed fixture read and create/readback inside a temporary root succeeded. | Remount identity, hardlinks, mount escapes, and concurrent target swaps are not covered by this runner smoke. |
| Protected system/secret paths | `PARTIAL` | `/private/etc/passwd` read failed; global and project secret deny rules are rendered. | Real Keychain, SSH, browser, cloud, package, Git, and signing stores were not opened. |
| Environment isolation | `PARTIAL` | Explicit empty environment prevented the synthetic parent canary from appearing. | This is ProcessSupervisor/profile evidence, not proof that every future profile or launcher has no secret inputs. |
| Network deny | `PARTIAL` | Curl DNS/network probe returned exit 6 and no stdout. | Network allowlists are intentionally unsupported; non-DNS addresses and broader egress controls remain untested. |
| Process-tree ownership | `UNKNOWN` | ProcessSupervisor has controlled process-group tests, but this smoke did not exercise descendants, `setsid`, timeout, crash, or restart cleanup. | A real task Job lease and hostile descendant harness remain required. |
| Credential/Docker/persistence/privilege isolation | `UNKNOWN` | No real credential, Docker socket, launchd, privilege, or persistence surface was accessed. | `mac_task_run` remains disabled. |

## Decision

This evidence moves the implementation boundary forward but is insufficient to
select deprecated `sandbox-exec` as the production task boundary. The runner
requires a profile-matched `TaskIsolationProof`, explicit opt-in, and an
external host-evidence gate; the default `FailClosedTaskRunner` and Broker
capability state remain unchanged. MOP-086, MOP-043, and MOP-045 stay blocked
pending hostile credential/process/persistence/cleanup evidence or a stronger
isolation design.
