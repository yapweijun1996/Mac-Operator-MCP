# SSOT Conflict Register

Status: Closed representation conflicts; runtime and architecture decisions remain tracked in task/ADR documents
Last reviewed: 2026-09-12

No conflict was found with the locked topology, Broker authority, security invariants, F0-F5 filesystem model, excluded interfaces, or 44-tool membership. The two representation conflicts identified during KB materialization are resolved in the canonical repository representation. KB-MCP writeback remains pending orchestration review and is listed in `KB_SYNC.md`.

## C-001 — Mandatory tool fields absent from individual KB metadata

Status: `RESOLVED`

### Historical issue

`TOOL_CONTRACT_STANDARD v0.1` requires every tool to declare `postcondition_verification` and `audit_class`, while the 44 KB individual records did not contain separate structured values for those fields. The first repo materialization preserved both as `null`.

### Decision

Freeze a deterministic repository taxonomy and map every tool exactly once. `audit_class` uses the nine classes in `TOOL_CONTRACT_STANDARD.md`; `postcondition_verification` is a structured object with `required`, semantic `strategy`, and `failure_class: VERIFICATION_FAILED`. Values are derived from declared tool semantics and do not assert runtime implementation or passing evidence.

### Affected artifacts

`TOOL_CONTRACT_STANDARD.md`, `tool-contracts/tool-contract.schema.json`, all 44 files under `tool-contracts/`, `tool-contracts/README.md`, `TASK.md`, `VERIFICATION.md`, `KB_SYNC.md`.

### Migration impact

The 44 contracts no longer contain `null` for either mandatory field. Contract envelope closure is complete; `MOP-084` remains `IN_PROGRESS` for per-tool functional input/output schema closure and validation automation. No tool changed from `planned`, no authority changed, and no runtime implementation was added.

### Verification evidence

The documentation consistency check confirmed exactly 44 contracts, no null mandatory fields, schema-valid envelope objects, one audit class per tool, and semantic strategies for read, write, Git, GUI, execution, and privileged tools. Runtime postcondition behavior and functional input/output schemas remain unverified/incomplete and are still governed by the release gates.

## C-002 — Two incompatible meanings of phase

Status: `RESOLVED`

### Historical issue

The locked KB catalog and individual contracts used Phase 1-5 as tool delivery groups, while the repository program roadmap uses Phase 0-7 for project lifecycle. The shared name `phase` was semantically ambiguous.

### Decision

Use `tool_delivery_wave` for contract sequencing (`wave_1` through `wave_5`) and reserve roadmap phase terminology for project lifecycle (`Phase 0` through `Phase 7`). The canonical contract schema contains only `tool_delivery_wave`; `phase` is not retained as an equivalent field.

### Affected artifacts

`TOOL_CONTRACT_STANDARD.md`, `TOOL_CATALOG.md`, `tool-contracts/tool-contract.schema.json`, all 44 files under `tool-contracts/`, `tool-contracts/README.md`, `ROADMAP.md`, `EPIC.md`, `TASK.md`, `VERIFICATION.md`, `README.md`, `KB_SYNC.md`.

### Migration impact

The old contract field `phase: Phase N` maps directly to `tool_delivery_wave: wave_N`. Roadmap lifecycle phases are unchanged. The original KB wording remains only inside immutable `source.source_text` provenance; it is not a canonical contract field. A KB writeback is required to update the upstream item names/fields after review.

### Verification evidence

The consistency check confirmed no canonical contract contains a top-level `phase`, every contract has one valid `tool_delivery_wave`, catalog links remain one-to-one with the 44 contracts, and roadmap references now distinguish lifecycle phases from delivery waves.

## Resolution rule

A future conflict closes only when the authoritative meaning, affected records, migration impact, and verification evidence are recorded together. These two repo representation conflicts are closed for this remediation; upstream KB synchronization is intentionally deferred and must follow `KB_SYNC.md`.
