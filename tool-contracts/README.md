# Tool Contracts

This directory contains 56 JSON tool contracts: the original 45 KB-MCP contracts and 11 V2 Safe AI Development Gateway contracts. Original contracts preserve their KB item IDs and source text. V2 contracts are defined by `docs/MAC_OPERATOR_V2_DESIGN.md`; their fresh locally reserved UUIDs preserve the version 0.1 source envelope and do not assert that matching KB records exist.

`tool-contract.schema.json` validates the contract envelope. Every contract contains explicit functional `input_schema` and `output_schema` objects with bounded fields and strict properties. Presence in this directory declares an API surface, not runtime enablement, authorization enforcement, or verified host safety. Runtime availability comes from Broker adapter registration and policy.

The canonical schema, build-time verifier, and Edge registry enforce a closed approval-policy enum and shared safety invariants for idempotence, mutation postconditions, privileged audit/approval, and rejection of trusted-read approval for mutations. Contract validation remains an integrity check.

The V2 contracts add project-owned worktrees, coding-agent preflight and managed execution, approved test/build profiles, worktree-based branch creation, read-only PR preparation, and bounded audit retrieval. `mac_git_push` declares a separate high-risk boundary and remains denied until a supported explicit authorization workflow exists. It cannot inherit coding approval. Coding and validation jobs require provisioned execution boundaries; a contract never grants arbitrary shell, host filesystem, secrets, sudo, or network authority.

All contracts retain `schema_version: "0.1"` and `implementation_status: "planned"` for compatibility with the current materialized-contract format. V2 execution and write requests carry task-bound idempotency keys. Their success responses return small job references or bounded metadata; status, cancellation, and logs use existing managed-job tools.

The former KB `phase` field remains materialized as canonical `tool_delivery_wave` (`wave_1` through `wave_5`). The migration is documented in `CONFLICTS.md` and `KB_SYNC.md`.
