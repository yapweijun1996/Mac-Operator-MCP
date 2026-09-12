# Mac-Operator-MCP Goal

Status: Planning
Version: 0.1
Last verified: 2026-09-12

## Mission

Build a governed MCP service and local macOS broker that let ChatGPT and other authorized AI clients inspect and operate a physical Mac mini. The system must provide useful machine-level capabilities while keeping credentials, authorization, privileged execution, and recovery under deterministic host control.

## Implementation interpretation

This document defines durable product intent. `PROGRESS.md` is the source of truth for current Git state, implementation status, verification, blockers, and next work. A documented capability remains a target until repository evidence marks it implemented and enabled.

## Intended outcome

An authorized user can ask an AI client to inspect system health, locate and diagnose projects, read approved files, inspect Git and Docker state, run approved development tasks, control selected applications, and eventually invoke a small set of privileged operations. The AI selects an action; the Mac host authenticates the request, authorizes the exact target, performs bounded execution, verifies the result, and records redacted evidence.

## Governing principles

1. High capability with bounded authority.
2. The Local Broker is the final authorization authority.
3. Authentication, read, write, process, network, GUI, destructive, and privileged permissions are independent.
4. Unknown identities, tools, scopes, targets, or policy states fail closed.
5. Secret existence may be observable; secret contents are denied by default.
6. Structured adapters are preferred over generic command execution.
7. Every execution has an explicit target, budget, result, and audit trail.
8. Revocation and kill switches affect queued and active work according to a documented contract.
9. A planned or discoverable tool is not executable authority.
10. Documentation records current repository truth and distinguishes decisions from proposals.

## Capability model

- L0 Observe: system, storage, process, service, network, and approved log inspection.
- L1 Files: approved directory, file, search, hash, and project discovery operations.
- L2 Developer: Git, build/test profiles, package inspection, Docker inspection, jobs, and controlled local writes.
- L3 Apps: inventory, open, focus, and structured application automation.
- L4 GUI: Accessibility-tree observation and target-bound UI actions.
- L5 System: separately authenticated, allowlisted privileged operations.

Levels group capabilities for planning. They do not inherit access to secrets, broader paths, networks, applications, or root authority.

## MVP success

The first release proves authenticated Edge-to-Broker communication and a narrow L0/L1 vertical slice on a real Mac. It must reject forged, replayed, expired, unauthorized, secret-targeting, and path-escaping requests; enforce output and time limits; create redacted audit records; expose health and policy explanations; and remove execution authority when the Broker is locked or credentials are revoked.

## Non-goals

- Unrestricted shell or terminal access.
- A model-facing or persistent root process.
- Raw Keychain, SSH key, browser credential, token, signing-key, or password-store access.
- Arbitrary Docker socket, AppleScript/JXA source, launchd persistence, or screen-coordinate control.
- Silent scope expansion or bypass of macOS privacy controls.
- Automatic Git push, force reset, destructive disk operations, or security-setting bypass.

## Success measures

- All released tools have versioned contracts, policy tests, implementation evidence, and deployment state.
- No released request path relies only on client-supplied authority claims.
- Secret-boundary, path-race, replay, revocation, and process-isolation tests pass.
- Every mutation has preconditions, idempotency or recovery semantics, and postcondition verification.
- Production release has no unresolved P0 or P1 findings in the affected authority boundary.

## Related documents

See `DESIGN.md`, `SPEC.md`, `SECURITY.md`, `FILESYSTEM_POLICY.md`, and `PROGRESS.md`.
