# ADR-0004: Policy and Configuration Format

Status: Proposed
Date: 2026-09-12
Tasks: MOP-013, MOP-080, MOP-084

## Locked semantics

Broker final authority, default deny, exact independent scopes, tool enable state, secret deny zones, and the F0-F5 filesystem model with precedence `HARD_DENY > SENSITIVE_OPT_IN > WRITE_ROOT > READ_ROOT > METADATA_DISCOVERY > DEFAULT_DENY` are fixed inputs to this ADR.

## Required decision

Select serialization, schema versioning, canonicalization, validation, source authentication, change authorization, secret references, environment overlays, atomic reload, rollback, migration, compatibility, and audit behavior. Define whether configuration is one signed bundle or separately versioned policy domains.

## Constraints

- Ordinary model-facing tools cannot alter authority configuration.
- Invalid or unknown configuration disables affected capabilities.
- A reload is all-or-nothing for one policy version.
- Decisions and evidence identify the exact policy version.
- Config stores references to secrets, never secret values.
- Host-specific roots, apps, services, volumes, and task profiles remain explicit data.

## Acceptance evidence

Schema-invalid, unknown field, conflicting rule, deny-inside-allow, downgrade, unauthorized edit, partial write, failed reload, rollback, and incompatible-version cases must be tested.
