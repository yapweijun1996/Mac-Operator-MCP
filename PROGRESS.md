# Mac-Operator-MCP Progress

Status: Phase 0 in progress
Version: 0.1
Last verified: 2026-09-12

## Current situation

The repository is initialized on `main` and tracks `origin/main`. HEAD is initial commit `8f8d6b5`; before this documentation update, the only tracked project file was `.gitattributes`. There is no application source, package manifest, dependency lockfile, build configuration, test suite, CI, deployment configuration, generated artifact, or running service evidenced by this repository.

## Completed work

- Created the Git repository and initial commit.
- Established LF text normalization through `.gitattributes`.
- Created the initial KB planning set for goal, design, specification, security, Epics, roadmap, tasks, progress, tool contracts, and the 44-tool catalog.
- Selected the high-level topology: Remote MCP Edge to authenticated local IPC to Mac Local Broker to adapters, with separate audit and privileged boundaries.
- Selected the governing security direction: Broker final authority, default deny, secret deny zones, bounded execution, redacted audit, kill switches, and no unrestricted shell or root interface.
- Completed an architecture deep dive identifying identity-chain, path-race, child-process isolation, active revocation, mutation recovery, GUI target, and tool-lifecycle requirements.
- Materialized, reviewed, verified, and committed the repository documentation baseline through `MOP-002`.

## Implementation status

- Runtime implementation: 0%.
- Released tools: 0 of 44 planned.
- Implemented tools: 0 of 44 planned.
- Enabled tools: 0 of 44 planned.
- Automated tests: 0.
- Real-Mac execution evidence: none.
- Remote MCP deployment: none.
- Privileged helper: none.

Percentages beyond these objective counts are intentionally omitted because the delivery scope and estimates are not yet baselined.

## Current phase

Phase 0 — Foundation and contracts. `MOP-001` is partially complete because the repository exists but lacks an engineering baseline. `MOP-002` is complete. The next implementation decision is `MOP-003`, runtime and package structure.

## Decisions recorded

- Keep Edge, Broker, adapters, Job Manager, Audit Store, and Privileged Helper responsibilities explicit.
- Treat the Broker as the sole final host authorization point.
- Keep L0-L5 as planning labels rather than inherited permission levels.
- Distinguish planned, implemented, and enabled tool states.
- Require durable audit intent before mutations and privileged actions.
- Bind filesystem authority to the resolved/opened target, not only a path string check.
- Treat repository task scripts as untrusted child code.
- Add idempotency, status lookup, and unknown-outcome reconciliation for mutations.
- Define revocation and kill-switch effects for queued and active work.
- Defer generic shell, GUI action, and privileged execution until their boundary evidence passes.

## Pending decisions

- Implementation language/runtime and repository package structure.
- Remote authentication and tunnel provider.
- Edge-to-Broker IPC authentication and replay mechanism.
- Child-process sandbox technology on the target macOS version.
- Policy format and update workflow.
- Audit backend, integrity, retention, and read-only outage behavior.
- Initial filesystem allow roots, deny roots, and secret classifications.
- macOS packaging, signing, launch, update, and rollback strategy.

## Blockers

There is no blocker to completing Phase 0 documentation and baseline engineering work. Named task execution is blocked by the missing sandbox decision and credential-isolation proof. Controlled writes are blocked by missing policy, audit, idempotency, and postcondition primitives. GUI actions are blocked by missing sensitive-target and freshness design verification. Privileged-helper work is blocked by the absence of lower-level identity and authorization evidence and packaging/signing decisions.

## Verification performed

- Confirmed clean `main` before documentation edits.
- Confirmed HEAD `8f8d6b5` and its initial-commit timestamp.
- Confirmed the pre-update tracked tree contained only `.gitattributes`.
- Confirmed no existing source or documentation files were overwritten.

No runtime tests can be run because no runtime exists yet. Documentation consistency and file checks are required after this update.

## Next steps

1. Confirm TypeScript/Node or select another runtime.
2. Create package structure, developer commands, and CI.
3. Implement shared contracts and threat-model tests.
4. Deliver the local Broker and safe file-read vertical slice.
5. Select remote deployment only after the local authority boundary passes.
