# Mac-Operator-MCP Threat Model

Status: Initial threat-model baseline; mitigations are requirements, not implementation evidence
Version: 0.1
Last reviewed: 2026-09-14

> **Owner direction (2026-10-02):** the product target is now owner full control ([docs/owner-full-control.md](docs/owner-full-control.md)): one authenticated owner, one grant, the owner account's whole authority. This document's threats and mitigations describe the governed profiles that are deployed today. Where they conflict with that target, the owner direction in `GOAL.md` wins for future work, and `PROGRESS.md` still decides what is implemented.


## Scope

This model covers the remote MCP client, Remote MCP Edge, Edge-to-Broker IPC, Local Broker, policy/configuration, adapters, Broker-owned child processes, filesystem, Docker integration, applications and Accessibility, Audit Store, Privileged Helper, secrets, and operational recovery. It covers local and remote adversaries, compromised projects, accidental misuse, and partial system failure.

## Security objectives

- The host, not the model, decides authority.
- Credentials and secret content remain outside generic tool results and child-process reach.
- A granted capability cannot silently expand across targets, networks, applications, or privilege boundaries.
- Mutations have attributable intent, bounded execution, known or explicitly unknown outcome, and postcondition evidence.
- Revocation and kill switches remove authority according to a testable lifecycle contract.

## Assets

| ID | Asset | Required protection |
|---|---|---|
| A-01 | Broker and Edge credentials | Confidentiality, integrity, revocability |
| A-02 | Keychain, SSH, cloud, browser, package and signing secrets | Confidentiality; generic access denied |
| A-03 | User and project files | Confidentiality, integrity, recoverability |
| A-04 | Policy and capability configuration | Integrity, authenticity, rollback safety |
| A-05 | Principal, session and approval records | Integrity, freshness, attribution |
| A-06 | Request, nonce, idempotency and job state | Integrity, uniqueness, crash recovery |
| A-07 | Audit records | Integrity, privacy, bounded retention |
| A-08 | macOS applications and UI state | Target integrity, privacy, freshness |
| A-09 | Privileged system state | Integrity, least authority, recovery |
| A-10 | Availability of the physical Mac and Broker | Resource bounds and emergency disable |

## Actors

| ID | Actor | Trust position |
|---|---|---|
| ACT-01 | Authorized user | Trusted for explicit policy and approvals within assigned authority |
| ACT-02 | AI client/model | Untrusted for authorization claims and tool arguments |
| ACT-03 | Remote MCP client process | Authenticated identity; otherwise untrusted input source |
| ACT-04 | Remote attacker | No legitimate authority |
| ACT-05 | Malicious or compromised project | Untrusted executable content |
| ACT-06 | Local unprivileged process | Outside Broker trust boundary |
| ACT-07 | Compromised Edge | Authenticated local peer with no automatic host authority |
| ACT-08 | Operator/administrator | Trusted only through explicit operational workflows |
| ACT-09 | Privileged Helper | Trusted for its narrow allowlisted operation boundary |

## Entry points

- Public HTTPS MCP endpoint and authentication callbacks.
- MCP initialize, discovery, and tool invocation payloads.
- Edge-to-Broker IPC messages.
- Policy, config, approval, and revocation updates.
- Filesystem paths, search queries, project manifests, patches, and Git data.
- Task profiles, arguments, package managers, Git hooks, and project scripts.
- Docker object metadata and logs.
- Application identifiers, URLs, documents, Accessibility trees, and UI actions.
- Helper requests and package/service/power targets.
- Audit and job status/readback interfaces.

## Trust boundaries

| ID | Boundary | Required control |
|---|---|---|
| TB-01 | AI client to Edge | Remote authentication, schema limits, rate limits |
| TB-02 | Edge to Broker | Mutual/local authentication, payload binding, nonce and replay defense |
| TB-03 | Broker to adapter | Immutable authorized execution plan |
| TB-04 | Broker to child process | Filesystem/network/env/process/credential isolation |
| TB-05 | Broker to Audit Store | Authenticated append, redaction, failure policy |
| TB-06 | Broker to Privileged Helper | Independent caller authentication and operation allowlist |
| TB-07 | Adapter to macOS UI/app | App/element identity, freshness, focus and sensitive-target checks |
| TB-08 | Broker policy to OS permission | Broker deny remains authoritative even when macOS permits access |
| TB-09 | Broker to Virtualization guest channel | Domain-separated HMAC, durable nonce admission, guest identity/attestation binding, bounded frames, timeout/cancel, and unknown-outcome handling |

## Risk rating

Likelihood and impact are rated 1-5. Risk is `likelihood × impact`: Low 1-4, Medium 5-9, High 10-16, Critical 17-25. Release requires no unresolved Critical or High risk in the affected authority boundary. Accepted risk requires an ADR or signed review record with owner, reason, expiry, compensating controls, and revisit trigger.

## Threat register

| Threat | Path | Initial risk | Required mitigation | Verification target | Residual status |
|---|---|---:|---|---|---|
| T-001 Forged principal or scope | TB-01/TB-02 | 20 Critical | Transport auth; immutable principal; Broker reauthorization | VT-AUTH-01 | Open |
| T-002 Replay or stale request | TB-02 | 16 High | Timestamp, nonce, payload binding, durable replay policy | VT-AUTH-02 | Open |
| T-003 Compromised Edge expands authority | TB-02 | 20 Critical | Broker-owned policy; target normalization; independent deny | VT-AUTH-03 | Open |
| T-004 Path traversal or symlink/mount escape | TB-03/TB-08 | 20 Critical | F0-F5 precedence; canonical and handle-bound access | VT-FS-01 | Open |
| T-005 TOCTOU target replacement | TB-03 | 16 High | Parent/target revalidation; no-follow/descriptor operations; atomic descriptor execution or immutable snapshot | VT-FS-02 | Open |
| T-006 Secret disclosure in content, error or audit | TB-03/TB-05 | 20 Critical | F0 zones; pre-open deny; bounded redaction defense | VT-SEC-01 | Open |
| T-007 Sensitive personal-data sweep | TB-03 | 15 High | F1 opt-in and purpose-built adapters | VT-SEC-02 | Open |
| T-008 Malicious task steals controller credentials | TB-04 | 25 Critical | Proven child credential, env and filesystem isolation | VT-SBX-01 | Blocked by sandbox PoC |
| T-009 Child escapes network/process limits | TB-04 | 20 Critical | Enforceable sandbox and process-tree ownership | VT-SBX-02 | Blocked by sandbox PoC |
| T-010 Docker socket becomes root-equivalent proxy | TB-03 | 20 Critical | Structured adapter; no raw socket/tool passthrough | VT-DKR-01 | Open |
| T-011 Approval replay or parameter substitution | TB-01/TB-02 | 16 High | Bind approval to principal/tool/target/payload/TTL/use | VT-APR-01 | Open |
| T-012 Duplicate or uncertain mutation | TB-03/TB-05 | 16 High | Idempotency key, precondition, ledger, reconciliation | VT-REL-01 | Open |
| T-013 Kill switch leaves active work authorized | TB-03/TB-04 | 20 Critical | Admission/pre-mutation checks; queued cancel; active termination policy | VT-REV-01 | Open |
| T-014 Audit outage permits unattributed mutation | TB-05 | 16 High | Durable intent before mutation; fail closed | VT-AUD-01 | Open |
| T-015 Audit contains secrets or can be altered | TB-05 | 16 High | Redaction, access control, integrity and retention | VT-AUD-02 | Open |
| T-016 Stale or spoofed UI element | TB-07 | 15 High | Opaque fresh refs; app/window/focus revalidation | VT-UI-01 | Open |
| T-017 Credential/security UI manipulation | TB-07 | 20 Critical | Sensitive-target deny at observation and action | VT-UI-02 | Open |
| T-018 Arbitrary helper/root command | TB-06 | 25 Critical | Strict schemas, allowlist, caller auth, no command string | VT-PRIV-01 | Open |
| T-019 Policy downgrade or malicious config | TB-08 | 20 Critical | Signed/authenticated update, versioning, atomic apply, rollback controls | VT-POL-01 | Open |
| T-020 Resource exhaustion | All | 12 High | Rate, byte, depth, result, time, concurrency and disk budgets | VT-DOS-01 | Open |
| T-021 Version confusion between Edge/Broker/helper | TB-02/TB-06 | 16 High | Explicit negotiation and reject-incompatible behavior | VT-COMP-01 | Open |
| T-022 Incomplete uninstall or stale authority | Operations | 15 High | Credential revocation, service removal and readback runbook | VT-OPS-01 | Open |
| T-023 Guest identity or result substitution | TB-09 | 20 Critical | Domain-separated HMAC; durable nonce/request admission; request-digest, guest-identity, profile, and attestation binding; reject transport loss as unknown | VT-VZ-01 | Open |
| T-024 Guest boundary falsely claims isolation | TB-09/TB-04 | 25 Critical | Independently verified VM boot, image/runtime identity, guest filesystem/network/credential/process evidence, cancellation, and postcondition readback | VT-VZ-02 | Blocked pending native guest evidence |
| T-025 Release artifact substitution or false provenance | TB-03/TB-06 | 20 Critical | Owner-only manifest; bounded descriptor hashing; exact Developer ID identifier/Team ID/CDHash; fixed codesign and Gatekeeper assessment; immutable distribution and signing-key custody | VT-PKG-01 | Open |

## Attack-path priorities

1. Remote identity forgery or Edge compromise to Broker authorization.
2. Generic file or task tools to credential access.
3. Project-controlled code to host escape or controller credential theft.
4. Docker adapter to unrestricted daemon authority.
5. UI control to password/security surfaces.
6. Helper request to arbitrary root execution.
7. Crash or retry to duplicate or falsely successful mutations.
8. Policy, approval, audit, or version downgrade to silent authority expansion.

## Residual and accepted risk process

Every residual High or Critical risk blocks the affected release gate. Medium risks require an owner and planned mitigation or time-bounded acceptance. Accepted risks record scope, rationale, compensating controls, evidence, expiry, and approver. Documentation-only analysis cannot lower a risk rating; only testable implementation evidence can.

## Test mapping

`VERIFICATION.md` maps every `VT-*` target to requirements, tasks, tests, evidence, and release gates. Missing tests or evidence keep the target `OPEN` or `BLOCKED`.
