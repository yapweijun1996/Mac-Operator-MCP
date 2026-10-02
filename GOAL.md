# Mac-Operator-MCP Goal

Status: Owner-directed revision; full owner control is the product target, not yet an implemented capability
Version: 0.2
Last verified: 2026-10-02

## Mission

Build a service and local macOS broker that let the owner's AI agents operate the owner's own Mac with the owner's full authority, at any time and from anywhere. The owner is the only principal. An AI agent connected through an owner-authorized grant can run terminal sessions and coding agents, build and test, use any application and the browser, and read and change any file the owner account can reach. The Mac host authenticates the owner, executes, verifies results where it can, and records evidence.

## Owner direction (2026-10-02)

The owner has decided that bounded, split-permission operation is the wrong default for this personal deployment. The earlier model (separate scopes per connection, a separate terminal endpoint, a browser-only GUI allowlist, per-action attended approval and one-shot commands) is superseded as the product target by the owner full-control profile in [Owner full control](docs/owner-full-control.md).

This is a statement of intent. Repository code and exact-revision evidence still decide what is implemented; see `PROGRESS.md`. Until the profile is implemented and verified, the governed profiles (R1, G1, O1, V2) remain what is deployed.

## Implementation interpretation

This document defines durable product intent. `PROGRESS.md` is the source of truth for current Git state, implementation status, verification, blockers, and next work. A documented capability remains a target until repository evidence marks it implemented and enabled.

## Intended outcome

The owner can ask an AI client, from a phone or any other device, to do anything they could do at the Mac: run commands and long-lived interactive terminal sessions (including coding-agent CLIs such as Claude Code, Codex and pi), build and test projects, operate any installed application and the browser, manage files, inspect and change system state, and recover the machine, all through one connection and one consent.

## Governing principles

1. Full capability for the owner. The profile grants the owner account's whole authority through a single owner grant.
2. Authenticate the owner, not the action. Unknown identities, tokens, clients, and policy states fail closed. Once the owner's grant is valid, individual actions are not blocked by tool-level boundaries.
3. One consent, one connection. Terminal, files, coding tasks, applications, and GUI come with the same owner grant instead of separate endpoints and re-consent.
4. The owner can always take control back. Revocation, a kill switch, and an audit trail are required. They control who is connected and let the owner stop it; they do not restrict what the owner has granted.
5. Operating-system permissions stay with the operating system. Accessibility, Screen Recording, Automation, Full Disk Access and administrator authentication are granted by the owner in macOS; the service does not try to bypass them.
6. Every execution has an explicit target, deadline, result, and audit record. Long-lived sessions have an owner-visible identity and can be cancelled.
7. Evidence over claims. A planned or discoverable tool is not executable authority, and documentation distinguishes decisions from proposals and implemented capability.
8. Availability matters. The agent must be able to reach the Mac at any time, so the host is configured to stay awake and the connection is monitored.

## Capability model

- L0 Observe: system, storage, process, service, network, and approved log inspection.
- L1 Files: approved directory, file, search, hash, and project discovery operations.
- L2 Developer: Git, build/test profiles, package inspection, Docker inspection, jobs, and controlled local writes.
- L3 Apps: inventory, open, focus, and application automation for any installed application.
- L4 GUI: Accessibility-tree observation, screenshots, and UI actions in any application.
- L5 System: privileged operations through the privileged helper, plus owner terminal sessions.
- L6 Sessions: long-lived interactive terminal (PTY) sessions for coding-agent CLIs.

Levels group capabilities for planning. Under the owner full-control profile all levels are granted together by the single owner grant; under the governed profiles they remain independent.

## MVP success

The first release of the owner full-control profile proves that one owner consent over the existing authenticated HTTPS/OAuth connection exposes terminal, build/test, coding, application and GUI tools together, that an interactive terminal session can run a coding-agent CLI end to end, and that revocation and the kill switch stop the agent. It must still reject forged, replayed, expired and unauthenticated requests, and create audit records.

## Non-goals

- Access by anyone other than the authenticated owner. This is a single-owner profile.
- A persistent root process reachable by the model. Root-level work goes through the privileged helper; the owner may revisit this decision explicitly.
- Bypassing macOS privacy controls or administrator authentication.
- Multi-tenant isolation between projects or users.

Items that earlier versions listed as non-goals (unrestricted shell or terminal access, access to the owner's credentials and Keychain-backed tools, AppleScript/JXA, launchd persistence, screen-coordinate control, Git push, destructive disk operations) are now in scope for the owner full-control profile. The governed profiles keep their own limits.

## Success measures

- All released tools have versioned contracts, policy tests, implementation evidence, and deployment state.
- No released request path relies only on client-supplied authority claims.
- Replay, forged-token, revocation, and kill-switch tests pass.
- The owner can stay connected to an awake Mac and drive an interactive coding-agent session from another device.
- Mutations are recorded; where practical they have idempotency or recovery semantics and result verification.
- Production release has no unresolved P0 or P1 findings in owner authentication, revocation and the kill switch.

## Related documents

See `docs/owner-full-control.md`, `DESIGN.md`, `SPEC.md`, `SECURITY.md`, `FILESYSTEM_POLICY.md`, and `PROGRESS.md`.
