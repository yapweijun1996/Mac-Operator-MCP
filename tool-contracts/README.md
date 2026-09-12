# Tool Contracts

This directory materializes the 44 planned KB-MCP tool contracts as one JSON document per tool. The files preserve the KB item ID and source text and normalize the structured metadata that already exists in KBID `mac-operator-mcp`.

`tool-contract.schema.json` validates the materialized contract envelope. It is not the final per-tool MCP input/output JSON Schema: all 44 contracts currently have `input_schema` and `output_schema` incomplete/absent. `audit_class` and `postcondition_verification` are mandatory, deterministic repository fields defined by `TOOL_CONTRACT_STANDARD.md`; their presence closes envelope completeness but does not claim runtime implementation or verification.

The former KB `phase` field is materialized as canonical `tool_delivery_wave` (`wave_1` through `wave_5`). The migration is documented in `CONFLICTS.md` and `KB_SYNC.md`.

All contracts have `implementation_status: "planned"`. Their presence does not make a tool implemented, enabled, or remotely callable.
