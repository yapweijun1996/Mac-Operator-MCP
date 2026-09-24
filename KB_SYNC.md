# KB-MCP Synchronization

Status: Documentation-only writeback manifest prepared; KB mutation intentionally deferred
KBID: `mac-operator-mcp`
KB UUID: `90f1df58-87f6-4f47-aa9a-2881c478f8a0`

## Authority rules

- Git and runtime evidence are authoritative for current implementation state.
- `PROGRESS.md` owns dynamic repository status.
- KB-MCP is the upstream SSOT for locked design artifacts until a reviewed synchronization rule changes that ownership.
- Conflicts are recorded in `CONFLICTS.md` and require owner review; neither side is silently overwritten.

## Materialized KB artifacts

| Repo artifact | KB item |
|---|---|
| `SECURITY.md` | `2ea82306-ed68-4ad2-b647-1a5937107320` |
| `FILESYSTEM_POLICY.md` | `fabad579-3f3d-4d08-a963-43b7b986b76b` |
| `TOOL_CONTRACT_STANDARD.md` | `757447f2-9ec8-4dd2-ae2c-21bce481e487` |
| `TOOL_CATALOG.md` | `65554efe-6a0a-404c-af6a-7670777944b4` |
| `tool-contracts/mac_*.json` | 45 unique KB items recorded in each file's `source` object |

## Readback checks

Materialization verifies 45 unique tool names, 45 unique KB item IDs, 45 catalog links, valid JSON, JSON Schema validity, required normalized fields, preserved source text, deterministic audit/postcondition fields, valid delivery waves, and planned lifecycle state. The legacy `phase` key is absent from canonical contracts. Source text remains immutable provenance and may retain historical KB wording.

## Repo-authoritative verified changes ready for writeback

This manifest records repo changes that are verified as documentation or contract state. No KB-MCP item is changed by this remediation. “Ready for writeback” means ready for owner review, not already approved for upstream mutation.

| KB item / concept | Repo authoritative change | Old value | New value | Reason | Writeback state |
|---|---|---|---|---|---|
| 45 `macop.tool` contracts — `audit_class` | Add one deterministic primary audit class to every JSON contract | `null` / absent in KB metadata | One of `observe`, `filesystem_read`, `developer_read`, `execution`, `filesystem_write`, `git_write`, `app_control`, `gui_control`, `privileged` | Mandatory standard field; supports retention, review, and release evidence without changing authority | Ready for owner review; update all 45 items after approval |
| 45 `macop.tool` contracts — `postcondition_verification` | Add a structured verification object to every JSON contract | `null` / absent in KB metadata | `{required, strategy, failure_class}` with semantic strategy and `VERIFICATION_FAILED` | Mandatory standard field; expresses verification intent without claiming runtime evidence | Ready for owner review; update all 45 items after approval |
| 45 `macop.tool` contracts — lifecycle naming | Rename canonical repo field and catalog terminology | `phase: Phase 1-5` | `tool_delivery_wave: wave_1-wave_5` | Separates capability delivery sequencing from roadmap lifecycle `Phase 0-7` | Ready for owner review; update upstream field after approval |
| 45 `macop.tool` contracts — functional API schemas | Add explicit bounded functional request and result schemas to every contract | Absent; only `input_summary`/`output_summary` | 45/45 functional `input_schema` and `output_schema` objects compile and pass semantic, authority-surface, and catalog-parity review; all tools remain `planned` | Makes the planned API surface machine-readable without expanding authority or claiming runtime compatibility | Ready for owner review; update all 45 items after approval |
| `FILESYSTEM_POLICY.md` | Materialize locked F0-F5 model and exact precedence | Not present in repo | F0-F5 with `HARD_DENY > SENSITIVE_OPT_IN > WRITE_ROOT > READ_ROOT > METADATA_DISCOVERY > DEFAULT_DENY` | Makes the existing KB filesystem authority model reviewable; no alternate authority model introduced | Verified materialization; no semantic promotion required |
| `TOOL_CATALOG.md` and 45 contract files | Materialize one-to-one catalog/contract membership with KB provenance | Not present in repo | 45 unique catalog links, names, KB item IDs, and `planned` lifecycle state | Establishes machine-readable contract inventory without implementation claims | Verified materialization; no implementation promotion permitted |
| `PROGRESS.md` — current repo state | Record verified Git and implementation state in the dynamic-state document | Older KB state said repo not established / `MOP-001` not executed | Accepted baseline HEAD `2e389b8`; working tree contains uncommitted implementation and evidence changes; 45 contracts planned | Git evidence is authoritative for current repository state | Ready for owner review as a dated progress snapshot |
| `MOP-080..088` — architecture-closure tasks | Update status and descriptions to reflect repo evidence | `MOP-084` pending functional schema closure; `MOP-088` blocked on conflicts | `MOP-084` done for functional input/output schema closure; `MOP-088` done for repo conflict resolution with KB writeback pending; other statuses remain evidence-based | Prevents stale task state and keeps implementation claims separate from documentation closure | Ready for owner review; do not infer runtime completion |
| `C-001` and `C-002` | Record resolution, rationale, affected artifacts, migration, and evidence | `OPEN` | `RESOLVED` in canonical repo representation | Removes contract field and lifecycle naming ambiguity while preserving history | Ready for owner review; upstream KB migration still required |
| Threat/Verification artifacts | Materialize `THREAT_MODEL.md`, `VERIFICATION.md`, and related traceability docs | Not materialized in repo | Documentation artifacts with runtime rows still `OPEN`/`BLOCKED` | Makes requirements and evidence paths reviewable without claiming proof | Ready for owner review as materialization only |

### Writeback constraints

- Preserve the KB item IDs and provenance recorded in each contract.
- Do not write `implementation_status: implemented`, enabled state, runtime evidence, or release status from documentation alone.
- Keep `source.source_text` as historical provenance; canonical consumers must use the structured repository fields.
- Apply the KB update only after owner review of `CONFLICTS.md`, the taxonomy, and the verification evidence.

## Repo-only drafts / proposed decisions not ready for KB promotion

- `docs/adr/0001-runtime.md` contains an out-of-scope accepted Edge/Broker baseline edit in the current working tree; `ADR-0002` through `ADR-0008` remain `Proposed`, including sandbox research in `ADR-0006`. MOP-084 does not depend on any ADR acceptance, and this manifest does not promote or write back the runtime decision.
- `SCOPE_MODEL.md`, `PERSISTENCE_MODEL.md`, `SANDBOX_RESEARCH.md`, `CONFIGURATION.md`, and operations documents contain open design work and research contracts. Do not promote their proposals as locked KB decisions.
- Runtime compatibility, sandbox proof, real-Mac evidence, deployment evidence, or release status is not ready for KB promotion. MOP-084's functional schemas are documentation-complete, but no runtime security or compatibility claim is implied.
- No runtime implementation, sandbox proof, real-Mac evidence, deployment evidence, or release status is ready for KB promotion.

## Future writeback

After owner review and a later Git commit, synchronize only the approved manifest rows back to KB-MCP with provenance that identifies the exact commit and changed documents. Do not write implementation completion, runtime verification, or release status unless the exact Git revision and evidence support it.
