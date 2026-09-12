# ADR-0008: Approval Model

Status: Proposed
Date: 2026-09-12
Task: MOP-082

## Principle

Policy allow is necessary but does not equal approval. Policy determines whether an operation may be considered. Approval records a trusted actor's consent for one bounded operation or an explicitly governed unattended profile.

## Proposed approval record

Bind `approval_id`, approver principal, requesting principal, tool and contract version, normalized target, canonical payload hash, policy version, issued-at, expiry, use limit, approval class, unattended flag, and revocation state. Mutation of any bound field invalidates the approval.

## Rules

- Default approvals are single-use and short-lived.
- Read-only trusted profiles may be policy-preapproved only when their contract declares it.
- Writes require a trusted write approval or a separately reviewed unattended profile.
- GUI approval binds app, window/element target class, action, and payload.
- Privileged actions require explicit privileged approval unless a narrowly defined emergency/maintenance policy is separately accepted.
- Approval cannot add a missing scope, bypass a deny rule, or override a disabled capability.
- Consumption and mutation admission require an atomic persistence decision.

## Open decisions

Approver authentication strength, TTLs by safety class, approval UI/channel, unattended profile ownership, batch approval, cancellation, human-readable preview, and recovery when approval consumption succeeds but execution does not.

## Acceptance evidence

Cross-principal reuse, replay, expiry, target substitution, payload mutation, policy-version change, use-limit exhaustion, revocation, concurrent consumption, and unattended-profile escape tests must fail safely.
