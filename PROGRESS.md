# Mac-Operator-MCP Progress

Status: Phase 0 in progress
Version: 0.1
Last verified: 2026-09-12

## Current situation

The repository is initialized on `main` and tracks `origin/main`. Verified HEAD is `e019b01`, which contains `.gitattributes` and eight root planning documents; the current working tree contains the uncommitted documentation-only remediation described below. There is no application source, package manifest, dependency lockfile, build configuration, test suite, CI, deployment configuration, generated artifact, or running service evidenced by this repository.

## Completed work

- Created the Git repository and initial commit.
- Established LF text normalization through `.gitattributes`.
- Created the initial KB planning set for goal, design, specification, security, Epics, roadmap, tasks, progress, tool contracts, and the 44-tool catalog.
- Selected the high-level topology: Remote MCP Edge to authenticated local IPC to Mac Local Broker to adapters, with separate audit and privileged boundaries.
- Selected the governing security direction: Broker final authority, default deny, secret deny zones, bounded execution, redacted audit, kill switches, and no unrestricted shell or root interface.
- Completed an architecture deep dive identifying identity-chain, path-race, child-process isolation, active revocation, mutation recovery, GUI target, and tool-lifecycle requirements.
- Materialized, reviewed, verified, and committed the repository documentation baseline through `MOP-002`.
- Started documentation-only remediation against the newer KB SSOT: repaired stale dynamic-state ownership; materialized locked Security, Filesystem Policy, Tool Contract Standard, and Tool Catalog documents; added threat, scope, persistence, verification, ADR, sandbox-research, navigation, testing, configuration, deployment, operations, incident, rollback, and kill-switch documents.
- Resolved the two representation conflicts: every contract now has deterministic `audit_class` and structured `postcondition_verification`, and the legacy contract `phase` field is now canonical `tool_delivery_wave`.
- Prepared the KB writeback manifest without changing KB-MCP; orchestration review is still required before upstream synchronization.

## Implementation status

- Runtime implementation: 0%.
- Released tools: 0 of 44 planned.
- Implemented tools: 0 of 44 planned.
- Enabled tools: 0 of 44 planned.
- Automated tests: 0.
- Real-Mac execution evidence: none.
- Remote MCP deployment: none.
- Privileged helper: none.
- Machine-readable tool contracts: 44 of 44 materialized with unique KB provenance; all remain planned, not implemented or enabled.

Percentages beyond these objective counts are intentionally omitted because the delivery scope and estimates are not yet baselined.

## Contract schema status

- Contract envelope schema: complete and validated for all 44 materialized contracts. This covers identity, capability, policy, budgets, lifecycle, audit, delivery wave, provenance, and summary fields.
- Per-tool functional input/output schemas: incomplete for 44 of 44 contracts. The current records retain `input_summary` and `output_summary`; they do not yet define implementation-ready `input_schema` and `output_schema` objects.
- Therefore, envelope schema validation is a documentation PASS, while functional API contract closure remains `MOP-084` `IN_PROGRESS`.

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
- Remaining input/output JSON Schema detail and validation automation for the 44 contracts.
- KB-MCP writeback review for the resolved contract and progress changes.

## Blockers

There is no blocker to the completed contract-field and naming remediation. Remaining Phase 0 work is still open: runtime/package selection, scope and identity/IPC semantics, approval and persistence closure, input/output schema detail, and automated verification. Named task execution is blocked by sandbox research and credential-isolation proof. Controlled writes are blocked by scope, approval, policy, audit, idempotency, persistence, and postcondition runtime primitives. GUI actions are blocked by sensitive-target and freshness verification. Privileged-helper work is blocked by lower-level identity/authorization evidence and packaging/signing decisions.

## Verification performed

- Confirmed clean `main` before documentation edits.
- Confirmed baseline HEAD `e019b01` and clean working tree before this remediation.
- Confirmed `e019b01` contains the eight root planning documents plus `.gitattributes`.
- Confirmed no application source, tests, or deployable runtime exist.
- Confirmed all 44 catalog tools have one valid JSON materialization, a unique tool name, a unique KB item ID, preserved source text, and a catalog link.
- Confirmed all 44 contracts remain `planned`; none is represented as implemented or enabled.
- Confirmed all 44 contracts have one taxonomy-valid `audit_class` and one structured `postcondition_verification`; all remain `planned`.
- Confirmed canonical contracts contain `tool_delivery_wave` and no top-level legacy `phase` field; roadmap lifecycle phases remain separate.
- Validated the contract envelope for all 44 contracts against `tool-contracts/tool-contract.schema.json`; separately checked UUID shape, Markdown links, trailing whitespace, task-definition uniqueness, stale-state removal, excluded-interface absence, catalog parity, and the 1999-character `GOAL_PROMPT.md` limit. Functional input/output schema validation remains pending.

No runtime tests can be run because no runtime exists yet. Documentation consistency and machine-readable contract checks passed; they prove document integrity only.

## Next steps

1. Complete input/output schema detail and automated contract validation under `MOP-084`.
2. Review `KB_SYNC.md` and synchronize the resolved contract/progress changes upstream only after owner approval.
3. Accept or revise the proposed scope, identity/IPC, approval, persistence, runtime, remote-auth, policy/config, audit, sandbox, and packaging ADRs.
4. Create package structure, developer commands, and CI only after runtime selection.
5. Execute sandbox PoC before enabling task execution.

## Related documents

See `README.md`, `TASK.md`, `VERIFICATION.md`, and `docs/adr/README.md`.
