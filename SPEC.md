# Mac-Operator-MCP Specification

Status: Draft requirements baseline
Version: 0.1
Last verified: 2026-09-12

## Conformance language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` define requirements. A requirement is implemented only when code and relevant verification evidence exist in the repository.

## Product scope

The system will expose structured MCP tools for host and broker status, safe system inspection, approved filesystem and project access, bounded developer workflows, selected application control, and eventually allowlisted privileged actions. V0.1 release scope is the Edge/Broker foundation and a narrow L0/L1 read-only vertical slice.

## Implementation status

`PROGRESS.md` is authoritative for implementation and verification state. Requirements and contracts in this repository do not become executable authority merely by being documented.

## Common tool contract

Every tool MUST declare:

- Stable tool name and contract version.
- Capability level and safety class.
- Required scopes and normalized target type.
- Timeout and output limit.
- Filesystem and network policy.
- Secret handling policy.
- Approval or trusted-policy requirement when applicable.
- Idempotency and retry behavior.
- Postcondition verification.
- Audit class, tool delivery wave, implementation status, and enabled state.

Tool discovery MUST distinguish `planned`, `implemented`, and `enabled`. A planned contract MUST NOT be executable.

## Request envelope

The Edge-to-Broker request MUST contain a request ID, contract version, tool, validated arguments, immutable principal context, session reference, timestamp, nonce, policy audience and version, canonical payload digest, and authentication proof. Caller identity, scopes, policy overrides, credentials, and privileged command text MUST NOT be accepted from model-editable tool arguments.

## Result envelope

Tools MUST return a stable structure equivalent to:

```json
{
  "ok": true,
  "request_id": "request-id",
  "tool": "mac_health",
  "result_class": "SUCCEEDED",
  "data": {},
  "warnings": [],
  "truncated": false,
  "verification": {},
  "duration_ms": 0
}
```

The actual schema will be versioned before implementation. Results MUST NOT expose credentials, secret bytes, sensitive environment values, or raw authentication internals.

## Stable failure classes

Required classes are `AUTH_REQUIRED`, `AUTH_INVALID`, `AUTH_EXPIRED`, `REPLAY_DENIED`, `REVOKED`, `SCOPE_DENIED`, `SECRET_BOUNDARY_DENIED`, `PATH_DENIED`, `NETWORK_DENIED`, `PRIVILEGE_DENIED`, `POLICY_DENIED`, `TARGET_NOT_FOUND`, `PRECONDITION_FAILED`, `CONFLICT`, `TIMEOUT`, `OUTPUT_LIMIT`, `CANCELLED`, `EXECUTION_FAILED`, `VERIFICATION_FAILED`, `AUDIT_UNAVAILABLE`, `UNKNOWN_OUTCOME`, and `UNSUPPORTED_CAPABILITY`.

Failures MUST be machine-readable, bounded, and safe to audit. Internal errors MUST map to stable classes without leaking sensitive details.

## Authentication and authorization requirements

- The Edge MUST authenticate remote callers.
- The Broker MUST independently authenticate the Edge-to-Broker request.
- The Broker MUST be the final authorization authority.
- Authorization MUST bind principal, tool, normalized target, scopes, policy version, and execution constraints.
- Unknown or ambiguous authority state MUST fail closed.
- Requests MUST be timestamped, nonce-protected, payload-bound, and replay-resistant.
- Revocation MUST be checked at admission and immediately before mutation.
- Read, write, execution, network, GUI, destructive, and privileged scopes MUST remain independent.

## Policy requirements

- Deny rules MUST take precedence over allow rules.
- Policy MUST be deterministic for identical trusted inputs and policy version.
- `mac_policy_explain` MUST provide a dry-run decision without executing the action or exposing sensitive policy data.
- Authority-changing policy updates MUST be validated, versioned, audited, and atomic.
- A disabled capability or global kill switch MUST prevent new matching work.

## Filesystem requirements

- Paths MUST be canonicalized and checked against allow and deny roots.
- The implementation MUST resist traversal, alternate encoding, symlink, mount, and target-swap escapes applicable to macOS.
- Authorization MUST remain bound to the opened object where the platform permits.
- Reads MUST enforce type, size, duration, and output constraints.
- Writes MUST use explicit write scopes, target preconditions, recoverable or atomic methods where practical, and postcondition verification.
- Secret zones MUST deny content even when a broader allow root matches.
- Diagnostics and audits MUST NOT contain denied secret bytes.

## Process and job requirements

- Initial execution MUST use named task profiles.
- Every child MUST receive an explicit cwd, minimal environment, timeout, output cap, process-tree ownership, filesystem policy, and network policy.
- The design MUST prevent child access to Edge, Broker, connector, SSH, cloud, package-manager, and signing credentials unless a dedicated workflow explicitly permits one credential capability.
- Repository-defined scripts MUST be treated as untrusted executable code.
- Job status and cancellation MUST apply only to Broker-owned jobs.
- Timeout or cancellation MUST terminate the owned process tree and verify the resulting state.
- A generic command runner is outside V0.1 scope.

## Mutation requirements

- Mutations MUST carry idempotency identity and target preconditions.
- Reuse of an idempotency key with a different payload MUST fail.
- The system MUST record durable intent before mutating or privileged execution.
- Clients MUST be able to query uncertain outcomes.
- Success MUST require postcondition verification when a meaningful check exists.
- An unverified mutation MUST return `VERIFICATION_FAILED` or `UNKNOWN_OUTCOME`.

## Audit requirements

Audit MUST record principal reference, request ID, tool, normalized target reference, policy version, decision, timestamps, duration, result class, and bounded redacted evidence. Mutation intent and completion MUST be separate append-oriented events. Audit retention, access control, integrity mechanism, and storage backend are pending design decisions.

## Application and GUI requirements

- App control MUST be scoped by stable application identity and action family.
- UI observation and action MUST verify the current target, freshness, and focus.
- Sensitive dialogs, credentials, security settings, and unapproved targets MUST be denied.
- Native APIs and structured automation SHOULD precede Accessibility actions.
- Screen-coordinate actions are excluded from V0.1.
- Missing macOS permissions MUST return a bounded capability error and MUST NOT be bypassed.

## Privileged-helper requirements

- The helper MUST be separate from the model-facing Edge and unprivileged Broker.
- It MUST authenticate its local caller independently.
- It MUST expose only versioned, allowlisted operations with strict schemas.
- It MUST NOT accept shell text, environment injection, or arbitrary executable paths.
- Each operation MUST define preconditions, postconditions, rollback or recovery behavior, timeout, audit behavior, and emergency disable.

## Planned tool surface

The locked planning catalog contains 44 tools across Broker introspection, L0 observation, L1 files/projects, L2 developer operations and controlled writes, L3/L4 app and GUI actions, and L5 privileged operations. `TOOL_CATALOG.md`, `TOOL_CONTRACT_STANDARD.md`, and `tool-contracts/` are authoritative for that planned surface. `TASK.md` maps delivery work. Planned tools MUST NOT be reported as implemented or enabled.

## V0.1 vertical-slice acceptance

The first releasable slice MUST demonstrate:

1. A client reaches `mac_health`, `mac_capabilities`, `mac_policy_explain`, and one safe file-read workflow through the Edge and Broker.
2. Forged, expired, replayed, revoked, unauthorized, secret-targeting, traversal, symlink-escape, and target-swap cases fail closed.
3. Timeout and output limits work.
4. Audit intent, decision, result, and redaction are verified.
5. Broker lock and credential revocation remove authority according to the documented active-job contract.
6. Restart reconciliation does not report uncertain operations as successful.
7. Tests and real-Mac evidence are committed and traceable to the exact source revision.

## Release definition

A capability is released only when its contract, implementation, focused tests, affected regression checks, adversarial boundary tests, real-Mac evidence where applicable, documentation, deployment configuration, rollback path, and enabled state are verified. The affected authority boundary MUST have no unresolved P0 or P1 findings.

## Related documents

See `SECURITY.md`, `FILESYSTEM_POLICY.md`, `TOOL_CATALOG.md`, `tool-contracts/`, `THREAT_MODEL.md`, and `VERIFICATION.md`.
