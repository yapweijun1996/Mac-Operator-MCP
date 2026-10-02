# Owner full control (OFC)

Status: Owner-directed product target. Not implemented. Nothing in this document is enabled by the current release.
Decision date: 2026-10-02
Decided by: the repository owner

## Decision

This is a single-owner deployment. The owner wants their AI agents to control their own Mac with the owner's full authority, from any device, at any time. The governed profiles (R1, G1, O1, V2) were built for bounded authority and impose separate connections, scopes, app allowlists, per-action approval and one-shot commands. For this deployment those limits are the wrong default. The owner full-control profile (OFC) replaces them as the target; the governed profiles stay available and unchanged until OFC is implemented and verified.

## What OFC grants

One owner grant, given with one OAuth consent on one connection, covers all of:

- Terminal: one-shot commands and long-lived interactive (PTY) sessions with the owner's HOME, PATH and CLI authentication state, so coding-agent CLIs (Claude Code, Codex, pi and similar) can be started and driven across many turns.
- Developer tasks: build, test, Git (including push, when the owner's own credentials allow it), package managers, Docker, and coding-agent jobs.
- Files: read, write and search anything the owner account can access, including credentials stored in the owner's files.
- Applications and GUI: open, focus, observe, click, type and capture screenshots in any installed application, not only Chrome and Safari.
- System: inspect and change settings and services reachable by the owner account; privileged operations through the privileged helper.

## What OFC keeps

These are controls on who is connected and on stopping the agent. They are not limits on what the granted agent may do.

1. Owner authentication: HTTPS/OAuth with PKCE, a signed access token, an exact redirect allowlist, and fail-closed handling of unknown identities.
2. Revocation: revoking the grant ends active sessions and queued work.
3. Kill switch: one command or control that disables the OFC profile and terminates its sessions.
4. Audit: each command, session and GUI action is recorded with time, target and result. Credentials the agent types or prints may appear in recorded output; the audit store is protected like the other owner-only state.
5. macOS permissions: Accessibility, Screen Recording, Automation, Full Disk Access and administrator authentication are granted by the owner in System Settings. OFC does not bypass them.

## Explicit decisions the owner can revisit

- No persistent root process reachable by the model. Root-level work goes through the privileged helper.
- No multi-user or multi-tenant use. A second principal needs a new decision.
- The profile is a deliberate expansion of authority. Anyone who obtains a valid owner token or the owner's credentials controls the whole Mac. The owner accepts this for the personal deployment and is responsible for protecting the login, the tunnel and the signing keys.

## Required to make this real

Each item needs implementation, tests and evidence before the profile can be called implemented. The first item is the largest.

1. Interactive PTY sessions: create, write input, read output with offsets, resize, signal, close; survive client disconnects; owner-visible list and cancel.
2. Single connection: expose the terminal, task and GUI tools on the default `/mcp` resource from one consent, instead of a separate `/terminal/mcp` resource.
3. Application scope: replace the Chrome/Safari allowlist with any installed bundle identifier under the OFC grant.
4. Approval model: replace per-action attended approval with the single owner grant plus the session or persistent grant model already used for browser access.
5. Policy: an OFC signed-policy profile that grants the whole tool set to the owner principal, with default deny for every other principal.
6. Availability: documented host settings (power, sleep, auto-login, tunnel supervision) so the Mac stays reachable.
7. Verification: real-Mac evidence for a coding-agent CLI session, revocation, and the kill switch.

## Relationship to other documents

- `GOAL.md` records the product intent this profile serves.
- `SECURITY.md` records the trust boundary of governed profiles and of OFC.
- `docs/owner-terminal.md` and `docs/owner-terminal-connection.md` describe O1, the current terminal profile, which stays as deployed until OFC replaces it.
- `PROGRESS.md` is the source of truth for what is implemented.
