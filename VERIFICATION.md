# Verification Matrix

Status: Documentation matrix with contract checks; no implementation tests or runtime evidence exist
Version: 0.1

## Evidence contract

Each evidence record must identify source commit, dirty-state status, tool contract version, policy version, test command or manual procedure, target macOS/hardware profile, relevant component versions, timestamp, result, and artifact hashes. A later source revision cannot inherit earlier evidence without rerunning affected checks.

Status values are `OPEN`, `BLOCKED`, `PASS`, and `FAIL`. Documentation presence can close a documentation task but cannot produce `PASS` for runtime behavior.

## Requirement-to-release matrix

| Verification target | Requirement | Threat | Task | Test/evidence required | Gate | Status |
|---|---|---|---|---|---|---|
| VT-CON-01 | 44 canonical contract envelopes are schema-complete | T-019, T-020, T-021 | MOP-005, MOP-084, MOP-085 | Exactly 44 files; envelope JSON Schema validation; unique names and KB IDs; catalog parity; non-null audit class and postcondition object; valid delivery wave; required policy/budget fields; no excluded tools | Documentation | PASS |
| VT-CON-02 | Per-tool functional input/output schemas are implementation-ready | T-019, T-021 | MOP-004, MOP-084 | Every contract has bounded `input_schema` and `output_schema`, generated request/result validation, stable errors, and compatibility cases | Documentation | OPEN |
| VT-AUTH-01 | Broker final authority | T-001, T-003 | MOP-011, MOP-013 | Forged scope/principal integration tests | Local/Remote | OPEN |
| VT-AUTH-02 | Replay rejection | T-002 | MOP-012 | Duplicate nonce, stale timestamp, altered payload, restart tests | Local/Remote | OPEN |
| VT-AUTH-03 | Compromised Edge cannot expand target | T-003 | MOP-013 | Broker policy negative matrix | Local | OPEN |
| VT-FS-01 | F0-F5 and precedence | T-004 | MOP-018, MOP-036 | Traversal, symlink, mount, deny-inside-allow real-Mac tests | L0/L1 | OPEN |
| VT-FS-02 | Target identity survives race | T-005 | MOP-018, MOP-036 | Symlink swap and create-target race harness | L0/L1 | OPEN |
| VT-SEC-01 | No secret output | T-006 | MOP-037 | Result/error/audit secret corpus | L0/L1 | OPEN |
| VT-SEC-02 | F1 requires dedicated opt-in | T-007 | MOP-037 | Mail/browser/photo/private-data denial tests | L0/L1 | OPEN |
| VT-SBX-01 | Child cannot access controller secrets | T-008 | MOP-086, MOP-045 | macOS sandbox PoC and credential canary tests | L2 | BLOCKED |
| VT-SBX-02 | Child obeys network/process limits | T-009 | MOP-086, MOP-045 | Network egress and process escape tests | L2 | BLOCKED |
| VT-DKR-01 | No raw Docker authority | T-010 | MOP-042 | Adapter allowlist and raw-socket negative tests | L2 | OPEN |
| VT-APR-01 | Approval binding and consumption | T-011 | MOP-082 | Payload mutation, expiry, replay, cross-principal tests | Mutation | OPEN |
| VT-REL-01 | Mutation retry and reconciliation | T-012 | MOP-017, MOP-083 | Crash-window and duplicate-request tests | Mutation | OPEN |
| VT-REV-01 | Revocation/kill-switch lifecycle | T-013 | MOP-016 | New, queued, running, pre-mutation and restart cases | Local/Remote | OPEN |
| VT-AUD-01 | Durable intent before mutation | T-014 | MOP-015, MOP-083 | Audit outage and crash injection | Mutation | OPEN |
| VT-AUD-02 | Audit privacy/integrity | T-015 | MOP-015 | Tamper, access-control, redaction and retention tests | Release | OPEN |
| VT-UI-01 | Fresh target and focus | T-016 | MOP-052, MOP-053 | Stale ref, window change and focus-race tests | GUI | OPEN |
| VT-UI-02 | Sensitive UI denied | T-017 | MOP-054 | Password, credential and security-setting tests | GUI | OPEN |
| VT-PRIV-01 | Helper exposes no arbitrary root | T-018 | MOP-060, MOP-061 | Schema fuzz, caller spoof, operation bypass tests | L5 | BLOCKED |
| VT-POL-01 | Policy integrity/versioning | T-019 | MOP-080, MOP-084 | Invalid config, downgrade, atomic reload and rollback tests | Local | OPEN |
| VT-DOS-01 | Resource bounds | T-020 | MOP-017, MOP-070 | Rate, output, disk, depth, timeout and concurrency tests | Release | OPEN |
| VT-COMP-01 | Version negotiation fails safely | T-021 | MOP-081 | Edge/Broker/helper compatibility matrix | Local/Remote/L5 | OPEN |
| VT-OPS-01 | Disable/uninstall removes authority | T-022 | MOP-071, MOP-087 | Revocation, service removal and readback procedure | Release | OPEN |

## Release gates

- Documentation gate: locked decisions materialized; open decisions and conflicts explicit.
- Local authority gate: identity, IPC, policy, replay, audit, revocation, and failure behavior pass.
- L0/L1 gate: filesystem and secret tests pass on the supported Mac profile.
- L2 gate: sandbox and credential-isolation evidence pass before `mac_task_run` enablement.
- Write gate: approval, ledger, idempotency, audit intent, recovery, and postconditions pass.
- GUI gate: app/element identity, freshness, focus, privacy, and permission recovery pass.
- L5 gate: helper protocol, caller auth, allowlist, packaging/signing, rollback, and independent review pass.
- Release gate: exact revision has no unresolved P0/P1 or High/Critical threat in affected boundaries.

## Current evidence

The documentation-only evidence for `VT-CON-01` includes JSON validity/envelope schema validation, exactly 44 contracts, catalog/contract parity, field/taxonomy checks, cross-link checks, stale-state checks, trailing-whitespace checks, excluded-interface checks, and Git diff review. `VT-CON-02` remains `OPEN`: all 44 functional `input_schema` and `output_schema` objects are still incomplete. The `VT-CON-01` `PASS` proves contract-envelope integrity only; it does not prove complete tool APIs, runtime implementation, postcondition behavior, authorization enforcement, or host safety. Runtime rows remain `OPEN` or `BLOCKED` because no runtime exists.
