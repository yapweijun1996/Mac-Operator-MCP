# ADR-0006: Child-Process Sandbox

Status: Proposed
Date: 2026-09-12
Tasks: MOP-086, MOP-043, MOP-045

## Context

`mac_task_run` executes project-controlled code. A named profile limits entry arguments but does not make the repository script trustworthy. The project must prove what macOS can enforce for filesystem, network, environment, process, credential, and persistence isolation.

## Decision rule

No sandbox technology is selected by documentation alone. Complete `SANDBOX_RESEARCH.md`, run real-Mac adversarial PoCs, and record unsupported guarantees. If credential isolation cannot be proven, restrict or remove the affected task capability.

The decision remains open pending that research and evidence; this ADR is not accepted and does not authorize `mac_task_run`.

Initial host evidence is recorded in `SANDBOX_RESEARCH.md` and [`evidence/2026-09-12-sandbox-research.json`](../../evidence/2026-09-12-sandbox-research.json). It demonstrates partial filesystem, symlink, executable-allowlist, and network-deny behavior from deprecated `sandbox-exec`, but also demonstrates inherited environment visibility and that sandbox-only parent termination leaves a child alive. A separate disabled `ProcessSupervisor` prototype proves explicit process-group cleanup in controlled tests, but does not select a production sandbox or authorize `mac_task_run`.

## Candidate areas

Evaluate macOS sandbox profiles and current platform support, dedicated users, containers or lightweight VMs, process wrappers, endpoint/security controls, filesystem ACLs, Keychain access groups, network filtering, and combinations. Do not treat environment filtering alone as credential isolation.

## Acceptance evidence

A hostile fixture must fail to read controller and user credentials, escape allowed roots, reach denied network targets, detach unowned processes, access Docker/root-equivalent interfaces, persist launch items, or survive cancellation. Results must identify exact macOS/hardware/runtime versions.
