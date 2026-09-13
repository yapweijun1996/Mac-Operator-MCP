# Child-Process Sandbox Research Contract

Status: Partial real-Mac evidence; blocks `mac_task_run`
Task: MOP-086

## Research question

What isolation can the supported physical Mac enforce for project-controlled commands while keeping Broker and controller credentials, denied filesystem targets, denied networks, host processes, Docker authority, and persistence mechanisms outside child reach?

## Target matrix

Record exact Mac hardware, macOS version/build, runtime, user identity, OS permissions, candidate isolation mechanism, and known platform deprecations for every experiment.

## Required experiments

- Read allowed fixture and write only to an explicit scratch root.
- Deny Keychain, SSH, browser, cloud, package, Git credential, Broker, and Edge secret canaries.
- Verify inherited environment and file descriptors contain no controller credentials.
- Deny traversal, symlink/mount escape, and alternate path spelling.
- Deny configured network destinations and prove permitted network profiles separately.
- Prevent arbitrary Docker socket, launchd persistence, privilege escalation, and process detachment.
- Own and terminate the full process tree on cancellation or timeout.
- Test native binaries, shell scripts, Node, Python, package scripts, Git hooks, and spawned grandchildren.
- Test restart, crash, and cleanup of artifacts and processes.

## Evaluation criteria

For each dimension, report `ENFORCED`, `PARTIAL`, `UNAVAILABLE`, or `UNKNOWN`, with commands, expected behavior, observed behavior, artifact hashes, and limitations. A successful happy path is insufficient.

## Decision outputs

Choose the supported sandbox, restrict `mac_task_run` profiles to proven guarantees, move execution into a stronger isolation boundary, or remove the capability. Document residual risk in ADR-0006 and update the tool contract before enablement.

## 2026-09-12 host evidence

The first hostile boundary probe ran on a Mac mini `Mac16,10` (Apple M4, 16 GB), macOS `26.2` build `25C56`, arm64, Node `v25.5.0`. The complete redacted result is [`evidence/2026-09-12-sandbox-research.json`](evidence/2026-09-12-sandbox-research.json), SHA-256 `3dac37728965894e313dcfa2332ef2dfb3ece3a2e75d407bbe1865f86633f077`. The candidate was `/usr/bin/sandbox-exec`; the platform marks it deprecated, so this is evidence about current behavior, not a production selection.

| Dimension | Result | Evidence | Residual risk |
|---|---|---|---|
| Explicit filesystem root | `ENFORCED` | A deny-default profile allowed a canonical scratch root and allowed fixture; outside read/write and an allowed-root symlink to an outside file were denied. | Profile construction, canonical path mapping, mounts, hardlinks, and create-target races need a dedicated harness. |
| Process executable allowlist | `ENFORCED` | A profile allowing only `/bin/bash` denied `/usr/bin/true` and `/bin/launchctl`. | No process-tree lease, descendant ownership, or cancellation proof exists. |
| Process-tree ownership | `UNAVAILABLE` | A sandboxed Bash parent started `/bin/sleep`; terminating the parent left the child alive until the harness explicitly killed it. The disabled Broker `ProcessSupervisor` now proves process-group cancellation and descendant cleanup in controlled tests, but is not connected to a task handler. | A real profile/task integration and lease recovery path remain open. |
| Network allow/deny | `PARTIAL` | `/usr/bin/curl` under the deny-default profile returned exit 6 with zero output for `https://example.com`; a loopback allowlist reached its selected local server and denied a second loopback port. | External allowlisted destinations, DNS pinning, UDP behavior, and broader non-DNS address tests remain open. |
| Environment isolation | `UNAVAILABLE` (historical sandbox-only probe) | A parent-set `MOP_CONTROLLER_SECRET` was printed by the child. | The Broker executor must construct a minimal environment; sandbox policy does not solve this. |
| File descriptor isolation | `PARTIAL` | The `sandbox-exec` wrapper did not expose the test descriptor. Separately, the Broker `ProcessSupervisor` now launches with explicit `stdio` and a temporary parent file-descriptor canary test confirms that a non-stdio canary is not visible in the child (`process-supervisor.test.ts`, source SHA-256 `b3a748e10a5616541f56e0b7b7b6658d86b1304e0ddd7d08cf8e135d581f08d2`). | This proves the current Broker launch boundary on the tested host, not every future executor or OS sandbox profile; a production task runner still needs an explicit isolation proof and a descriptor audit at the sandbox boundary. |
| Credential canaries | `PARTIAL` | Fake SSH, cloud, Docker, and Keychain canary files outside the allowed root were denied. | No real credential surface was opened; package-manager, Git, signing, and Keychain API canaries remain open. |
| Docker/persistence/privilege isolation | `UNKNOWN` | Docker authority, launchd persistence, privilege escalation, native binaries, scripts, and grandchildren were not yet exercised. | `mac_task_run` remains disabled. |

This evidence is insufficient to select `sandbox-exec` as the production task boundary. It does not unblock `MOP-043` or `MOP-045`; the next research slice must test hostile credentials, process-tree ownership, cleanup after timeout/crash, and external allowlisted networking or move execution to a stronger boundary. The Broker-side canary closes only one previously unknown launch invariant: `ProcessSupervisor` does not inherit arbitrary parent descriptors. It must not be interpreted as credential isolation or as proof that `sandbox-exec` itself enforces descriptor policy.

The Broker task admission boundary now also requires a versioned `TaskIsolationProof` before any runner marked available can consume approval or create a task Job. The proof must name the explicit sandbox mechanism and profile, then attest to enforced filesystem/network boundaries, isolated credentials, and owned process-tree cleanup. Binding the mechanism prevents evidence for deprecated `sandbox-exec` from being reused by a future App Sandbox or Virtualization runner. This is a fail-closed contract gate; the current default runner remains unavailable, and the test-only attestation is not production evidence.

The `TaskRunner` boundary now declares the host mechanism alongside its proof.
Broker admission and dispatch reject a runner whose declaration is absent or
does not match the proof, before approval consumption or child-process launch.

## 2026-09-13 experimental runner evidence

Source commit `1e3eb86` adds real-host secret-surface denial evidence on top of
the `3e4b065` runner guard and `2e6cd57` profile boundary. The experimental
runner uses `renderTaskSandboxProfile` and an opt-in
`SandboxExecTaskRunner`. The renderer emits only a Broker-owned deny-default
Seatbelt subset, allows a resolved executable and explicit filesystem roots,
denies global and representative project secret zones, and supports only
loopback `tcp`/`udp` network allowlists. Resolved profiles default to `processTreePolicy:
"single_process"`, which omits `process-fork`; only an explicit
`owned_group` profile adds that rule and it remains separately unevidenced. The
runner now refuses to become available for `owned_group`, even with an
external proof, until a separate process-tree ownership decision is accepted.
The runner invokes `/usr/bin/sandbox-exec` through the bounded
`ProcessSupervisor` with an explicit environment, cwd, timeout, output cap, and
cancellation callback. It remains unavailable unless macOS, explicit opt-in,
an external host-evidence gate, and a matching `TaskIsolationProof` are all
present.

The exact host smoke record is [`evidence/2026-09-13-sandbox-profile-runner.md`](evidence/2026-09-13-sandbox-profile-runner.md).
On the Mac mini M4/macOS 26.2 host, the synthetic child could read/write the
allowed temporary root, could not read `/private/etc/passwd`, did not inherit a
parent controller/`HOME`/SSH-agent/AWS-profile canaries, and could not resolve
an HTTP destination through curl (exit 6, empty stdout). A child-launch
attempt from Bash was denied because the default profile omits `process-fork`,
and a real `/bin/sleep` cancellation mapped through detached process-group
termination. This is `PARTIAL` evidence:
real credential surfaces, descendants/`setsid`, crash/restart cleanup,
external allowlisted networking, DNS pinning, UDP behavior, Docker, persistence,
privilege, and remount behavior remain unproven. The same host probe checked
only readability of the current user's `.ssh`, `.docker`, Chrome, Safari, Mail,
Messages, and Keychains directories and `/var/run/docker.sock`; all were denied
without reading contents. The focused
real-Mac smoke passes 7/7 tests with `MOPS_REAL_SANDBOX=1`. `sandbox-exec` is
deprecated, so this does not select it for
production or unblock `mac_task_run`.

The versioned `TaskIsolationProof` binds both the selected sandbox mechanism
and `processTreePolicy`, so evidence for deprecated `sandbox-exec`,
`single_process`, or another profile cannot be silently reused by a different
runner or an `owned_group` profile. The runner's availability gate
independently refuses `owned_group`; this is a fail-closed enablement safeguard,
not proof that the owned-group variant is safe.

## 2026-09-13 current-revision readback

After source revision `e10f380`, the same `MOPS_REAL_SANDBOX=1 node --test
packages/broker/dist/sandbox-profile.test.js` command passed 7/7 with no
skips. This is a fresh readback of the existing temporary-fixture evidence;
it does not add real credential-content, crash/restart, remount, Docker,
persistence, privilege, or production task-runner proof.

## 2026-09-13 Broker environment hardening

Source commit `e9d8570` adds a shared Broker environment-key policy. Task
profiles reject command-resolution, interpreter-startup, dynamic-loader,
temporary-directory, and arbitrary Git/Docker configuration variables; the
lower-level Supervisor permits only the exact non-secret keys used by fixed
Broker-owned adapters. A real child still receives an explicit environment and
does not inherit controller, `HOME`, SSH-agent, or AWS-profile values. This
changes the Broker launch boundary from the historical sandbox-only
`UNAVAILABLE` result to `PARTIAL` for environment construction, but it does
not prove real credential-content isolation or make deprecated `sandbox-exec`
a production selection. `mac_task_run` remains disabled.
