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

Approver authentication strength, protected issuer-key storage, TTLs by safety class, human approval UI/channel, unattended profile ownership, batch approval, cancellation, human-readable preview delivery, and recovery when approval consumption succeeds but execution does not.

## Acceptance evidence

Cross-principal reuse, replay, expiry, target substitution, payload mutation, policy-version change, use-limit exhaustion, revocation, concurrent consumption, and unattended-profile escape tests must fail safely.

## Prototype evidence

The Broker-owned SQLite prototype persists the proposed binding fields and accepts only single-use approvals. A separate `ApprovalAuthority` verifies an issuer/key identity, signed canonical payload, bounded preview digest, validity window, unattended-profile policy, and durable issuance nonce before atomically recording approval decision/completion provenance. `mac_job_cancel` now requires the fixed `trusted_write` approval class; the request cannot submit an approval ID or grant itself consent. Exact approval selection and consumption occur in the same transaction as request intent and audit evidence. Bounded tests cover issuer tampering, preview substitution, issuance replay, missing approval, principal/contract/target/payload/policy/attended-mode substitution, expiry, revocation, exhaustion, competing consumers, and revocation before dispatch.

This does not accept the ADR. The issuer channel is a disabled prototype with injected HMAC keys and a separate owner-only local IPC socket. Issuer-key files now use protected owner-only loading/provisioning and durable `approval_key` revocation before retirement. A versioned owner-only metadata config atomically rotates and reloads non-secret key paths with canonical revision/digest readback; BrokerStore activation history and audited intent/completion reject revision rollback and make startup restore exact. This remains an activation guard rather than Keychain-backed secret distribution or installed-service identity. Keychain storage, human UI/preview delivery, unattended-profile authority, batch approvals, privileged-helper integration, and active-work revocation semantics beyond the pre-dispatch gate remain open. Its versioned envelope is materialized in `schemas/approval-issuance.schema.json`.

Revision `ea50824` extends the approval issuer-key metadata reader with a
post-read descriptor identity check and byte wipe on change. This prevents an
in-place config mutation from being parsed during the protected read window;
it does not provide the missing human approval channel or production issuer
key distribution.

The disabled-by-default `mac_ui_type` implementation now uses the same
single-use `trusted_gui` approval binding as `mac_ui_action`. Its bounded text
payload is delivered over a Broker-owned stdin channel rather than argv and is
never persisted in Job output; exact snapshot ownership, parent-window
authorization, sensitive-target policy, and focused input postconditions remain
required. Real Accessibility permission and human approval-channel evidence
remain open, so this ADR stays Proposed.
