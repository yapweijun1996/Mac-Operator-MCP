# Scope Model

Status: Exact-scope and finite target-set authority implemented; physical resource identity remains open
Version: 0.1

## Purpose

Scopes are explicit grants consumed by Broker policy. They identify an action family; they do not bypass target, filesystem, network, approval, tool-enable, secret, or privileged policy.

## Existing scope vocabulary

The runtime vocabulary is the exact union used by the 45 contracts: `mac.control.read`, `mac.policy.explain`, `mac.system.read`, `mac.storage.read`, `mac.process.read`, `mac.log.read`, `mac.network.read`, `mac.service.read`, `mac.package.read`, `mac.files.read`, `mac.files.search`, `mac.files.hash`, `mac.files.write`, `mac.project.read`, `mac.project.write`, `mac.git.read`, `mac.git.write`, `mac.task.run`, `mac.job.read`, `mac.job.cancel`, `mac.docker.read`, `mac.app.read`, `mac.app.control`, `mac.ui.observe`, `mac.ui.control`, `mac.service.control`, `mac.priv.service`, `mac.priv.package`, and `mac.priv.power`. Automated verification rejects a contract scope absent from this runtime list.

## Proposed rules

1. Scope matching is exact by default.
2. No capability-level, dotted-prefix, parent-child, read-write, or privileged inheritance is implicit.
3. Wildcards are unsupported until a dedicated ADR defines syntax, expansion, review, and revocation behavior.
4. Tool contracts list every required scope. Multiple scopes use AND unless the contract explicitly defines an alternative set.
5. Target authority is evaluated separately. Possessing `mac.files.read` does not authorize every path.
6. Filesystem scope never overrides F0/F1 denial or F2-F5 classification.
7. Session scopes are an immutable subset of the principal grant and are bounded by issue time, expiry, audience, policy version, and a Broker-enforced maximum lifetime of 24 hours.
8. Revocation may target principal, session, scope grant, approval, tool, or capability switch.

## Principal model

A principal record needs a stable opaque ID, issuer, subject, status, grant set, issuance/version metadata, and revocation state. Human-readable names are display metadata, not authorization keys. The Broker accepts principal context only through authenticated Edge-to-Broker transport.

## Session model

A session binds principal ID, session ID, audience, issued-at, expiry, projected exact scopes, authentication strength, Edge identity, and policy compatibility. Broker admission also enforces durable request/session capacity and rejects a principal session whose declared lifetime exceeds 24 hours. A session cannot add scopes beyond its principal grant. Refresh behavior remains an issuer-side policy decision and must not extend a session beyond the Broker maximum.

## Parameterized authority

Target constraints belong in signed grants or Broker policy, not in model-editable scope strings. The signed policy document now supports an optional `target_constraint` with `mode: "finite_set"` and a bounded list of canonical references. The rule's `target.kind` supplies the type (for example, root ID, app bundle, service, task profile, or host), the anchor `target.reference` must be a member of the set, references must be unique and lexically sorted, and every member must pass the same kind-specific grammar. This is an explicit finite set, not a wildcard, prefix, or caller-supplied pattern.

The current Broker implements exact or finite-set `(principal, scope, target kind, target reference)` rules with deny-over-allow and default deny. Introspection handlers use the Broker-owned normalized target `host:broker`; model-editable arguments cannot replace their execution target. Filesystem path-root and volume identity checks, plus app/window identity checks for the implemented GUI boundaries, are enforced by Broker-owned planners and adapters. Policy-query input and signed policy references use the same kind-specific canonical grammar. Finite-set policy matching is now covered by schema, runtime, and authorization tests; physical target readback and broader resource identity proof remain open and must not be inferred from syntax or set membership alone.

## Revocation

The model must define precedence and propagation for principal, session, scope, approval, and capability-switch revocation. Broker checks revocation on admission and immediately before mutation. Job continuation after revocation depends on the declared interruptibility and kill-switch contract; it is never inferred from capability level.

## Open decisions

- Principal issuer and stable subject source.
- Session refresh behavior and whether shorter profile-specific lifetimes are required.
- Revocation storage, propagation latency, and restart persistence.
- Whether any wildcard form is ever necessary.
- Delegation and unattended-principal rules.

These decisions are tracked by the Identity/IPC and Approval ADRs and must close before remote mutation capabilities are enabled.
