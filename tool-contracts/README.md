# Tool Contracts

This directory materializes the 45 planned KB-MCP tool contracts as one JSON document per tool. The files preserve the KB item ID and source text and normalize the structured metadata that already exists in KBID `mac-operator-mcp`.

`tool-contract.schema.json` validates the materialized contract envelope. All 45 contracts now also contain explicit functional `input_schema` and `output_schema` objects with bounded fields and strict input properties. These schemas define the planned API surface; they do not claim runtime implementation, compatibility testing, authorization enforcement, or host safety.

The canonical schema, build-time verifier, and Edge registry also enforce a closed approval-policy enum plus shared cross-field safety invariants for idempotence, mutation postconditions, privileged audit/approval, and rejection of trusted-read approval for mutations. Contract validation remains an integrity check; it does not make a planned tool implemented or enabled.

The former KB `phase` field is materialized as canonical `tool_delivery_wave` (`wave_1` through `wave_5`). The migration is documented in `CONFLICTS.md` and `KB_SYNC.md`.

All contracts have `implementation_status: "planned"`. Their presence does not make a tool implemented, enabled, or remotely callable.
