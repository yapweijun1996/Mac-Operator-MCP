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

## Implemented candidate

The local Broker prototype uses a JSON Schema 2020-12 policy document inside an Ed25519-signed bundle. The offline/operator side owns the private signing key; the Broker receives only a pinned public key and key ID. The signature covers deterministic canonical JSON and a recorded SHA-256 payload digest.

The signed document owns exact principal grants, exact allow/deny target rules, trusted Edge IDs, tool enablement, and independent kill-switch states. It cannot change code-owned implementation state, contract scopes, budgets, schemas, or handlers. A policy cannot enable an unimplemented tool. Unknown fields, unknown scopes/tools, duplicate identities, target wildcards, digest mismatch, invalid signatures, future issue times, and non-increasing revisions fail closed.

Policy files and pinned public-key files must be regular, non-symlink, current-user-owned files that are not group/world writable. The loader checks the opened device/inode against the authorized path object. A verified policy is built completely before `PolicyManager` replaces one in-memory reference. Each request holds one immutable policy snapshot and binds its signed envelope to that exact policy version.

Policy activation identity is persisted with audit intent and completion in the same transaction. Restart restore requires the verified file's revision, digest, and key ID to match the active ledger. Explicit rollback requires the current revision, a bounded operator reason code, and an exact signed policy already present in history; it is also intent/completion audited.

The candidate passes schema, tamper, weak-permission, symlink, downgrade, unimplemented-enable, deny-over-allow, static kill-switch, transactional activation, restart-match, explicit rollback, and stale-request-policy tests. This ADR remains `Proposed`: crash injection, signer rotation/revocation, operator command/runbook, migration, and cross-runtime canonicalization evidence are still required before acceptance.
