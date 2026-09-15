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

The local Broker prototype uses a JSON Schema 2020-12 policy document inside an Ed25519-signed bundle. The offline/operator side owns the private signing key; the Broker receives only protected public-key files and key IDs. The signature covers deterministic canonical JSON and a recorded SHA-256 payload digest. Each versioned signer entry also binds a SHA-256 digest of its protected public-key file. The verifier accepts a bounded set of overlapping Ed25519 signer entries with validity windows and a Broker-owned revocation callback, so an old signer can be revoked without disabling its replacement. Reload, rollback, and revocation are available only through a separate owner-only UDS with a distinct HMAC key, OS peer verification, and durable replay admission; no MCP tool exposes them.

The signed document owns exact principal grants, exact allow/deny target rules, trusted Edge IDs, tool enablement, and independent kill-switch states. It cannot change code-owned implementation state, contract scopes, budgets, schemas, or handlers. A policy cannot enable an unimplemented tool. Unknown fields, unknown scopes/tools, duplicate identities, target wildcards, digest mismatch, invalid signatures, future issue times, and non-increasing revisions fail closed.

Policy files and pinned public-key files must be regular, non-symlink, current-user-owned files that are not group/world writable. The loader checks the opened device/inode against the authorized path object. A verified policy is built completely before `PolicyManager` replaces one in-memory reference. Each request holds one immutable policy snapshot and binds its signed envelope to that exact policy version.

Policy activation identity is persisted with audit intent and completion in the same transaction. Restart restore requires the verified file's revision, digest, and key ID to match the active ledger. Explicit rollback requires the current revision, a bounded operator reason code, and an exact signed policy already present in history; it is also intent/completion audited.

The candidate passes schema, tamper, weak-permission, symlink, per-key public-key digest, downgrade, unimplemented-enable, deny-over-allow, static kill-switch, transactional activation, restart-match, explicit rollback, stale-request-policy, protected multi-key loading, signer validity-window, unknown-key, durable activation/restore/reload, audited revocation, verified-history rollback, replay-bound HMAC operator-channel, peer-denial, and revocation migration tests. This ADR remains `Proposed`: installed startup wiring, native caller/process identity packaging, crash injection, general migration, Keychain distribution, and production cross-runtime adapter evidence are still required before acceptance.

Revision `a26a188` provides an independent bounded native Swift readback of
the canonical JSON vector set, including Unicode ordering and SHA-256 bytes.
It strengthens cross-runtime evidence for the serialization profile but does
not replace a production adapter or close the remaining acceptance items.

Revision `b164da0` hardens the runtime authority boundary by rejecting
prototype-bearing policy records at strict field-validation points. This
prevents inherited values from being interpreted as kill switches, key-window
limits, principal grants, or tool contracts. The change covers in-memory
policy-shape integrity only and does not change the signed policy schema or
close production signing, Keychain, migration, or installation evidence.

Revision `6fb5372` hardens the native filesystem policy boundary used by F0-F5:
metadata/list/read/hash and atomic write/unlink operations now derive bounded
relative targets and open through a pinned authorized-root descriptor. Final
symlink policy is preserved by canonicalizing only the target parent, while
traversal and empty components fail closed. This reduces root rename/target
replacement exposure but does not prove physical remount resistance or close
the remaining production resource and cross-volume evidence gates.

Revision `d1f96f2` extends runtime policy validation to require dense bounded
authority arrays for principal scopes, target rules, filesystem roots, deny
paths, tool scopes, and capability families. Sparse, symbolic, accessor, and
extra-property arrays fail closed before authorization or capability
advertisement. This is in-memory policy integrity evidence only; ADR-0004
remains Proposed pending production signer/Keychain distribution, migration,
installation, and cross-runtime evidence.

Commit `6bf29d4` makes queued-job reconciliation honor independent capability
families: the `mutations` switch cancels only an explicit mutation allowlist,
while read-only queued work remains queued and the `global` switch remains the
universal stop. This is local policy/persistence evidence and does not close
production installation or ADR acceptance.

Commit `fe6a187` strengthens the independent `mutations` switch with a
fail-closed classification: only known read-only queued Jobs are preserved;
unknown or future tools are cancelled until explicitly classified. This avoids
silently weakening a kill switch as the tool catalog evolves.

Commit `cb704af` applies the same bounded, dense, known,
and unique scope-list semantics to parsed request principals and direct
`authorizeTool` callers. This prevents a representation mismatch where an
unbounded or duplicate caller list could reach a separate authorization helper;
malformed lists fail with `AUTH_INVALID` before policy lookup. The change is
local parser/authority evidence and does not close production token issuance or
ADR acceptance.

Commit `d785eb0` closes a local target-authority consistency gap: direct target
authorization now rejects disabled principal grants and scopes outside the
enabled grant before matching allow/deny rules. This preserves default deny
under direct helper calls and policy reloads, but does not close production
policy distribution or ADR acceptance.

Commit `e0b9db8` adds schema version `10` Job Edge provenance. Broker-created
mutation Jobs persist the authenticated Edge that admitted them; idempotent
reuse is bound to that identity, and Edge revocation isolates matching queued
Jobs. Legacy/null provenance is intentionally cancelled conservatively, while
malformed persisted provenance fails closed. Commit `8dbbd67` extends the
same boundary with schema version `11` Edge-key provenance and precise
Edge-key revocation; `08c8100` makes the key identity shape and Edge binding
explicit at creation, readback, and revoke boundaries. These changes close a local authority-correlation gap but
do not close production policy distribution or ADR acceptance. Commit `b31cf4c`
also fences restarted guest status recovery on the persisted Edge-key
revocation state.

Commit `a2580e0` closes a related identity-validation drift: `EdgeKeyring.add`
now rejects malformed Edge/key identifiers before loading authority, while the
config loader, persisted Job provenance, and Edge revocation path reuse the
same bounded Edge identity predicate. This is a local fail-closed consistency
guard; it does not change the Proposed status or close production key
distribution and installation evidence.

Commit `6fdc725` aligns the bounded composite Edge-key identity length across
Job persistence and operator revocation. The maximum valid 128-character Edge
and key components now remain revocable as a 257-character subject instead of
being rejected by a stale 256-character guard. This is a compatibility and
fail-closed consistency fix; ADR-0004 remains Proposed.
