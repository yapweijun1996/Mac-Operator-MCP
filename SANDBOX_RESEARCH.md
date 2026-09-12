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
| Network deny | `PARTIAL` | `/usr/bin/curl` under the deny-default profile returned exit 6 with zero output for `https://example.com`; the built-in `no-network` profile also returned no DNS result. | An allowlisted network profile and non-DNS address tests remain open. |
| Environment isolation | `UNAVAILABLE` | A parent-set `MOP_CONTROLLER_SECRET` was printed by the child. | The Broker executor must construct a minimal environment; sandbox policy does not solve this. |
| File descriptor isolation | `UNKNOWN` | The `sandbox-exec` wrapper did not expose the test descriptor. | This does not prove every executor launch path closes inherited descriptors. |
| Credential canaries | `PARTIAL` | Fake SSH, cloud, Docker, and Keychain canary files outside the allowed root were denied. | No real credential surface was opened; package-manager, Git, signing, and Keychain API canaries remain open. |
| Docker/persistence/privilege isolation | `UNKNOWN` | Docker authority, launchd persistence, privilege escalation, native binaries, scripts, and grandchildren were not yet exercised. | `mac_task_run` remains disabled. |

This evidence is insufficient to select `sandbox-exec` as the production task boundary. It does not unblock `MOP-043` or `MOP-045`; the next research slice must test hostile credentials, process-tree ownership, cleanup after timeout/crash, and a real network policy or move execution to a stronger boundary.
