# Mac Control Center: MVP Technical Specification

Status: design deliverable; implementation and deployment have not started.
Date: 2026-10-07.

## 1. Product and acceptance boundary

Mac Control Center is a secure web-based control plane for Mac Mini, Mac-MCP,
and AI CLI agents. The first release provides an owner-only operations view and
bounded access revocation. Later releases add AI tasks and developer operations.

This specification defines Phase 1, not the entire product roadmap. Completion
means the acceptance criteria in section 12 pass against the deployed revision.
Screenshots, static fixtures, or an available tool contract alone do not prove
runtime readiness. No implementation completion percentage is assigned.

### Included in Phase 1

- Independent owner login, logout, session expiry, and login history.
- Overview with Broker health, independently observed component readiness,
  system facts, and explicit stale/unavailable states.
- Mac-MCP tool inventory with effective permission and runtime reason codes.
- Read-only status for configured services and bounded sanitized log retrieval.
- List and revoke the owner's OAuth connections and browser/desktop delegations.
- Control Center audit history and protected configuration validation.
- Responsive, keyboard-accessible interface with no unauthenticated telemetry.

### Deferred

AI task admission/queue/streaming, Claude/Pi execution, Git writes, Docker writes,
service start/stop/restart, process termination, kill-switch changes, web terminal,
file editing/upload/download, notification delivery, multi-user roles, permission
editing, local TOTP/passkeys, SMART, SSD temperature, and storage dependency alerts.
Existing operation approval pages remain available through their current flow;
Phase 1 does not add a pending-approval inbox or automatic approval.

## 2. Current implementation evidence

The following are source-level facts, not fresh live deployment checks:

| Existing source | Capability and reuse boundary |
| --- | --- |
| [Auth app](../packages/auth/src/app.ts) | Owner password verification, OAuth transactions, session rotation, CSRF, security headers, and GUI access management. OAuth sessions require a transaction and are consumed at consent; they are not admin sessions. |
| [Password verifier](../packages/auth/src/password.ts) | Native Argon2id hashing; reuse without storing a second password hash. |
| [Auth records](../packages/auth/src/contracts.ts) | One provisioned owner, OAuth grants, approval sessions, and persistent delegations. No admin identity/session model exists. |
| [Approval bridge](../packages/auth/src/approval-browser-bridge.ts) | Browser process receives bounded previews and delegation views over supervisor IPC, without issuer keys. |
| [Revocation forwarding](../packages/auth/src/personal-revocation.ts) | Durable Auth revocation notices propagate toward Edge/Broker; failures cannot be silently ignored. |
| [Broker gateway](../packages/edge/src/gateway.ts) | Authenticated, signed Broker requests using established principal context. Browser input cannot supply principal/scopes. |
| [Broker](../packages/broker/src/broker.ts) | `mac_health`, `mac_capabilities`, `mac_system_summary`, `mac_service_status`, and `mac_log_tail` exist and remain subject to policy. |
| [Authority IPC](../packages/broker/src/authority-control-ipc.ts) | Separate owner-authenticated switch/revocation channel; not a generic web administration API. |

`mac_health` currently describes Broker health, not overall Auth/Edge/Mac readiness.
`mac_system_summary` supplies CPU count, total memory, uptime, OS, architecture,
and optional load; it does not supply CPU utilization, used RAM, swap, or disk
temperature. The MVP must not invent these values. Richer metrics need separate
collector contracts and acceptance work.

`mac_capabilities` supplies planned/implemented/enabled state, required scopes,
reason codes, and authorized service/log references. Use this runtime view rather
than a fixed list or count. `mac_git_push` is governed by its own contract
([Git push](git-push.md)); this product design does not change it.

## 3. Architecture and responsibility

```text
Browser
  -> Cloudflare Access -> Cloudflare Tunnel
  -> Control Center HTTPS origin (new, loopback-bound service)
       -> Owner identity/session checks (Auth-owned local IPC)
       -> Read adapter and delegation management (supervisor-owned local IPC)
            -> established Auth revocation path / approval bridge
            -> established authenticated Edge-to-Broker request path
                 -> Broker policy, targets, audit, and execution
```

Use `packages/control-center` for a new TypeScript/Express workspace serving
HTML, CSS, browser JavaScript, and a same-origin JSON API. Follow existing npm
workspace conventions and Node 24 LTS tooling. No React, Redis, WebSocket, or
additional database server is required for Phase 1. Polling suffices.

Use a separate origin and a separate supervised child process. The existing Auth
app pins requests to its configured issuer host; do not relax that host check to
serve a second hostname. Preserve public MCP URLs, discovery, callbacks, scopes,
cookies, and existing OAuth clients.

### New local contracts to implement

These contracts do not exist yet and must be added with strict schemas and tests:

1. Auth-owned identity operations: login, resolve session, logout, reauthenticate,
   list owner connections, and revoke an owner connection.
2. Supervisor-owned read operations: overview, capabilities, approved service
   status, and approved log tail. No generic `execute(tool, args)` browser API.
3. Delegation operations: list and revoke through the existing approval bridge.

Use authenticated, owner-only local IPC and fixed operations, bounded messages,
timeouts, correlation IDs, and replay protection for mutations. Validate child
identity at the host boundary. The Control Center child receives no signing,
approval-issuer, authority-control, status, or Edge/Broker authentication keys.
It has no direct write access to BrokerStore or AuthStore.

Auth owns admin session authority. Each local operation resolves the session
server-side and obtains the configured owner identity; never accept a principal,
role, scope, target path, or tool name supplied by the browser as authority.
The supervisor derives read requests from the intersection of a dedicated
Control Center read allowlist and current Broker policy. Provision an explicit
control-center caller identity and read scope set through the existing protected
runtime configuration; do not synthesize scopes from a client request or borrow
an unrelated OAuth grant. Missing provisioning makes the affected panel unavailable.

A READ/EXECUTE/WRITE/ADMIN label is a UI classification only. It never replaces
existing scopes, target checks, approvals, or Broker's final authorization.
No executor or approval policy is widened by deploying the Control Center.

## 4. Authentication and security

- Reuse the existing owner username/password. Label the field `Username`, not
  `Email`, unless a later identity migration explicitly supports email.
- Admin sessions are independent of OAuth/approval cookies and transactions.
  Auth stores SHA-256 session fingerprints, expiry, auth epoch, and CSRF state.
- Use a 256-bit random opaque cookie named `__Host-mac-control-session`, with
  Secure, HttpOnly, SameSite=Strict, Path=/, and no Domain attribute.
- Rotate session and CSRF values after login and reauthentication. Idle expiry
  is 15 minutes; absolute expiry is 8 hours. Data polling does not extend idle
  expiry; a throttled authenticated user-interaction POST may extend it.
- Owner reset/reprovisioning increments the auth epoch and invalidates all admin
  sessions. Logout removes authority server-side. Expired sessions fail closed.
- Reauthentication grants a five-minute sensitive-action window. Revocation
  requires that window plus confirmation of the exact selected target.
- All POST requests require an exact same-origin check and an unpredictable
  session-bound CSRF token. Login uses a short-lived preauth cookie and token;
  rotate/discard both after use. No mutation is available through GET.
- No wildcard CORS; no browser bearer tokens in localStorage; no passwords in
  logs. Apply strict CSP, no-store, frame denial, and bounded request bodies.
- A failed-login policy must use validated source identity and bounded per-source
  buckets, plus an owner account bucket and password-verification concurrency
  bound. Proposed defaults: five failures/source/5 minutes and ten failures/owner/
  5 minutes, then a two-minute cooldown. Document residual single-account lockout
  risk; do not reuse the current global OAuth login counter for this service.
- Return generic login errors. Login history includes success/failure, timestamp,
  and trusted source address, never password, cookie, token, or raw request body.

Public deployment requires a configured Cloudflare Access owner allowlist and
its OTP/MFA policy plus local password login. Local TOTP and passkeys are deferred;
do not display a local 2FA setting as implemented. Validate the Access JWT using
the configured issuer, audience, expiry, and issuer JWKS; fail closed on invalid
or unverifiable assertions. Use a maintained verification library. Verify the
current official Access documentation before implementation/deployment.

Bind the origin to loopback, pin Host/Origin, and use TLS with explicit local
certificate verification from cloudflared. Trust forwarded client IP only from
the verified tunnel transport after valid Access identity checks; arbitrary
forwarded headers cannot affect authorization or bypass throttling. Direct
loopback access requires the same Access assertion in production. Development
without Access must be an explicit loopback-only profile that cannot be published.

## 5. Page behavior

Navigation: Overview, MCP Tools, Services, Logs, Access, Audit, Security.
Hide unimplemented navigation rather than showing working-looking controls.

| Page | Required behavior |
| --- | --- |
| Login | Username/password, generic errors, disabled repeated submit, session recovery. No Mac online indicator before authentication. |
| Overview | Broker, Edge, Auth and Control Center status separately; uptime, OS, CPU count, total RAM and load where allowed; last observation time. KB-MCP readiness is optional and unavailable until a configured probe exists. |
| MCP Tools | Search/filter; name, implementation state, effective enabled state, scopes, runtime reason, and last observation. No enable/disable toggle. |
| Services | Configured authorized targets, observed state, PID only when supplied; no lifecycle buttons. |
| Logs | Source dropdown from approved references, bounded tail, refresh, source/time metadata, visible truncation. No arbitrary paths or global host search. |
| Access | Owner OAuth connections and persistent/temporary GUI delegations, permissions, expiry where known, revoke confirmation and reauthentication. Never display access/refresh tokens. |
| Audit | Filterable Control Center events, pagination, target/result/correlation ID. Existing execution audit is a separate optional approved source, not silently merged with UI events. |
| Security | Current user, session expiry, bounded login history, logout; password reset remains the existing local operator flow. |

All pages support loading, empty, partial, denied, stale, and unavailable states.
Escape all data and render logs as text. Keyboard focus, labels, error messages,
and mobile layout are acceptance requirements. Confirmation identifies the target
and consequence; logging out does not revoke persistent GUI/OAuth access.

### Freshness and capability semantics

Overview polls every 15 seconds, services every 30 seconds, capabilities every
60 seconds, and logs only when explicitly refreshed. Coalesce concurrent reads
and pause hidden-tab polling. Mark data stale after twice its interval; mark
unavailable after 120 seconds without a successful observation. Keep the previous
value with its observation time; a failed sample is never converted to zero.
Polls never count as user activity for idle expiry.

Retain raw Broker reason codes. Presentation labels are Enabled, Disabled,
Restricted, Permission denied, Unavailable, or Not implemented. Unknown reason
codes show Disabled with the original code. A declared tool, a reachable process,
or successful OAuth login does not imply tool readiness. Do not combine different
observations into an unconditional `Mac Mini Online` claim.

## 6. API contracts (new; none are currently implemented)

Base path: `/api/v1`. JSON bodies use strict schemas; unknown fields are rejected.
IDs are opaque stable references. Lists use opaque cursors, default limit 50,
maximum 100. Timestamps use UTC ISO 8601; durations use seconds and sizes bytes.

| Method and route | Input | Result / authority |
| --- | --- | --- |
| GET `/auth/bootstrap` | None | Preauth cookie and login CSRF; no telemetry. |
| POST `/auth/login` | `username`, `password`, `csrf` | Rotated admin cookie, owner summary, CSRF and expiry. |
| GET `/auth/session` | Admin cookie | Owner, CSRF, idle/absolute expiry, reauth expiry. |
| POST `/auth/activity` | CSRF header | Extend idle expiry for explicit user activity, max once/minute. |
| POST `/auth/reauthenticate` | `password`; CSRF header | Rotate cookie/CSRF; set five-minute reauth window. |
| POST `/auth/logout` | CSRF header | Invalidate session, clear cookie. |
| GET `/overview` | None | Per-component observations and allowed system facts. |
| GET `/mcp/tools` | Optional `status`, `q`, cursor/limit | Effective capability inventory. |
| GET `/services` | Cursor/limit | Approved targets and bounded observed state. |
| GET `/logs/sources` | None | Approved source IDs and display labels. |
| GET `/logs/:sourceId` | `lines` 1..200 | Sanitized bounded tail, max 64 KiB, truncated flag. |
| GET `/access/connections` | Cursor/limit | Owner grants, client metadata, scopes, expiry, revoked state. |
| POST `/access/connections/:id/revoke` | `confirmationId`; CSRF and idempotency headers | Durable revoke and propagation/readback result; requires reauth. |
| GET `/access/delegations` | Cursor/limit | Owner browser/desktop delegation views. |
| POST `/access/delegations/:id/revoke` | `confirmationId`; CSRF and idempotency headers | Revoke and readback through existing bridge; requires reauth. |
| POST `/access/confirmations` | `targetType`, `targetId` | One-use confirmation ID bound to owner/session/action/target, 60-second expiry. |
| GET `/audit/events` | Optional category/result/time range, cursor/limit | Sanitized Control Center audit records. |
| GET `/security/logins` | Cursor/limit | Bounded owner login history. |

Example observation:

```json
{
  "requestId": "cc-request-123",
  "data": {
    "broker": {
      "status": "healthy",
      "observedAt": "2026-10-07T14:00:00Z",
      "source": "mac_health",
      "reasonCode": null
    },
    "cpuUtilization": {
      "status": "unavailable",
      "value": null,
      "reasonCode": "COLLECTOR_NOT_IMPLEMENTED"
    }
  }
}
```

Errors: `{requestId, error: {code, message, retryable}}`. Use 400 for invalid
input, 401 for missing/expired login, 403 for denied policy/CSRF, 404 for unknown
or unauthorized target, 409 for stale confirmation/idempotency conflict, 429 with
Retry-After for throttling, and 503 for dependency/audit failure. Return bounded
safe errors without raw host paths, stack traces, or credentials. Partial read
results return 200 with explicit per-section state, never fabricated success.

Revocation is irreversible for that grant and requires confirmation. Same-key
retries return the same recorded operation; different payloads under the same
key fail. Already-revoked owner targets return an idempotent result. Persist intent
before dispatch. Distinguish `revoked`, `propagation_pending`, and `failed`; do not
report completion after an IPC timeout. Auth/GUI state is authoritative. Reconcile
pending operations by readback after restart; never automatically regrant access.
Persist outcomes before acknowledging completion. If outcome persistence fails,
fail closed and show pending recovery even if the underlying revoke took effect.

## 7. Data ownership and persistence

Use existing Auth SQLite for new Auth-owned `admin_session`, `admin_preauth`,
`admin_confirmation`, and authentication-throttle state. Add strict versioned
schemas and migrations; do not put these sessions in the Control Center database.
Expiry cleanup and record caps must prevent normal polling/login activity from
exhausting AuthStore capacity. Admin session cap: 10/owner; new login evicts the
oldest session with audit. Password reset invalidates all admin state atomically.

Required Auth-owned fields (new versioned records, not existing schemas):

| Record | Required fields / invariants |
| --- | --- |
| `admin_auth_epoch` | Owner ID, monotonically increasing epoch; survives restart and reset. |
| `admin_session` | Fingerprint ID, owner ID, epoch, Access subject, created/last-interaction times, idle/absolute expiry, CSRF digest, reauth expiry; epoch and Access subject checked on every request. |
| `admin_preauth` | Cookie fingerprint, CSRF digest, Access subject, created/expiry times; five-minute expiry, one-use consumption, maximum 100 active records. |
| `admin_confirmation` | Fingerprint ID, owner/session binding, action, target type/ID, target revision or state digest, created/expiry times, consumed flag; maximum 100 active records. |
| `admin_throttle` | Hashed source/account bucket ID, window start, failure count, blocked-until, expiry; maximum 1,000 source buckets and bounded cleanup. Reject excess new sources rather than evicting active blocked buckets. |
| `admin_auth_events` | Stable event ID, owner ID when known, trusted source, action/result/reason, occurrence time, delivery state; bounded retention and durable delivery acknowledgment. |

Validate the Access subject against the configured owner mapping before password
verification; a local owner password does not authorize a different Access user.
Revoke confirmations are consumed atomically with recording the request in the
authoritative adapter. On repeated requests, resolve existing idempotency state
before rejecting a consumed confirmation. Recheck target identity/state at dispatch;
a changed target requires a fresh confirmation. Cap request and response messages
at 64 KiB, read calls at five seconds, and revocation calls at 15 seconds.

Use a separate owner-only `control.sqlite` for Control Center operational history:

| Table | Required fields / constraints |
| --- | --- |
| `schema_migrations` | version primary key, applied_at; sequential transactional migration. |
| `audit_events` | id, occurred_at, actor_id, session_fingerprint_prefix, category, action, target_type, target_id, result, reason_code, trusted_ip, request_id, operation_id; no raw payload. |
| `operations` | id, owner_id, session_binding, action, target_id, idempotency_key, payload_digest, state, created_at, updated_at, sanitized_result; unique(owner_id, idempotency_key). |

Index audit time/category/result and operation state/time. Use prepared SQL, foreign
keys, bounded strings, WAL, busy timeout, transactional writes, and restrictive
permissions (directory 0700, DB and sidecars 0600). No credentials or token values
are stored in this database. Configuration is an owner-only validated file;
Phase 1 has no browser settings editor. Do not duplicate users, OAuth grants,
Broker jobs, runtime permissions, tool definitions, or service authority here.

Login events must be durable in the Auth-owned authentication audit/outbox before
issuing a session. Deliver sanitized events to Control Center with stable event
IDs and deduplication; destination downtime must not silently lose login history.
The history endpoint queries the Auth-owned source when its projection is delayed.
Operational audit failure blocks mutations and new admin login; independent
authenticated read panels may continue with a visible audit-unavailable warning.

Default retention: 30 days or 100 MiB for Control Center audit, whichever is
reached first, with daily bounded pruning of completed history. Record pruning
and document this as local operational history, not tamper-proof compliance
evidence. Never prune pending operations for quota relief; stop accepting new
mutations when their bounded capacity is exhausted. Existing Broker audit remains
under its existing archival rules. Do not persist retrieved log contents or
continuous telemetry samples in Phase 1.

## 8. Configuration and deployment

Proposed protected configuration fields:

```text
version, enabled, origin, listenHost, listenPort, tlsCertificatePath,
tlsKeyPath, stateDirectory, accessIssuer, accessAudience, accessOwnerSubjects,
supervisorSocketPath, ownerPrincipalId, readCallerId, readScopes,
pollIntervals, readTimeoutMs, auditRetentionDays, auditMaxBytes
```

Paths are absolute and owner-protected; secrets are referenced through existing
protected-file/keychain delivery conventions. Validate configured identity and
scopes against runtime policy. Service/log targets come from current authorized
references, not arbitrary browser input. Set `enabled=false` by default.

Before public release: confirm hostname and Access identity with the owner,
generate a reviewable Tunnel/Access/LaunchAgent plan, validate TLS and loopback
isolation, back up Auth SQLite through its supported consistent backup path,
and run isolated migrations. Deployment requires the user's authorization;
this document does not authorize changing Cloudflare or starting services.

Roll out additively: contracts and migrations, disabled backend, local acceptance,
UI acceptance, then public owner canary. Rollback disables/unpublishes only the
Control Center and stops its child. Preserve databases for investigation; restore
an older Auth binary only if it accepts the additive schema, otherwise use the
tested backup restoration procedure. Existing OAuth and Broker services continue
through their existing entrypoints. Restart invalidates admin sessions by default.

## 9. Implementation sequence

1. Add contract schemas and protected configuration for Control Center IPC and
   dedicated read caller; test rejection of caller-forged identity/operation.
2. Add Auth-owned admin sessions, identity IPC, independent limiter, reset handling,
   and authentication audit delivery. Keep OAuth/approval behavior unchanged.
3. Add supervisor read adapter and bounded list/revoke adapters with identity
   resolution, audit intent, idempotency, timeout/restart reconciliation.
4. Add `packages/control-center` Express service, TLS/Access validation, API schemas,
   protected SQLite history, and child lifecycle integration behind `enabled=false`.
5. Add the seven pages using real API responses and explicit unavailable states.
6. Run contract/security/regression/UI checks and produce a public deployment plan.
7. After separately authorized deployment, perform the owner canary and attach
   exact-revision evidence. Only then mark Phase 1 complete.

## 10. Later phases

Phase 2 adds durable AI tasks using existing Broker jobs and supported agent
contracts first. Codex availability must pass preflight; Claude/Pi need explicit
adapters and evidence. Do not translate a browser prompt into unrestricted O1
shell execution. Pause is absent until the executor supports a verified pause
state. Queued/running/completed/failed/cancelled/timeout have durable definitions.

Phase 3 adds approved Git/Docker/service/process/storage operations, one contract
at a time. Git push is governed by the reviewed `mac_git_push` contract (see [Git push](git-push.md)).
Storage alerts require verified mount identity and explicit dependency mappings.

Phase 4 adds terminal/file management, richer approvals, notifications, and
orchestration. Authentication, authorization, audit, and confirmation already
exist in Phase 1; this phase expands them rather than introducing them late.

## 11. Risks and unresolved deployment inputs

- Hostname, Access owner identity/audience, origin port, and certificate delivery
  require actual deployment configuration; no placeholder is a working endpoint.
- Current global OAuth login throttling remains a separate existing availability
  risk. The new limiter must not extend that shared counter into admin login.
- The local owner can alter local history; immutable off-host audit is out of scope.
- Rich CPU/RAM/disk metrics and KB-MCP probes are absent from the reviewed read
  contract set. Show unavailable until separately implemented and verified.
- Runtime verification in the prior review crashed in Node 25.5.0 native callback
  handling. Run implementation acceptance under the documented Node 24 LTS
  environment; do not treat that crash as a passing login test.

## 12. Acceptance matrix

| ID | Required observable result |
| --- | --- |
| AUTH-01 | Anonymous browser sees login only; API returns 401 and no metrics, logs, targets, or connection metadata. |
| AUTH-02 | Valid owner login rotates cookie/CSRF; wrong password is generic; session fixation fails. |
| AUTH-03 | Idle/absolute expiry, logout, restart and password reset invalidate authority; polling never extends idle expiry. |
| AUTH-04 | Forged Origin/CSRF/Access JWT, wrong audience, forged forwarded IP, and direct-origin bypass fail. |
| AUTH-05 | Source/account throttling and concurrent hashing bounds work; source buckets cannot grow unbounded or share the OAuth global counter. |
| AUTH-06 | Missing Access verification material fails closed; local development mode cannot publish. |
| DATA-01 | Capability counts/states match the current Broker response; denied push and unimplemented metrics are truthful. |
| DATA-02 | Broker health cannot imply Edge/Auth/KB readiness; stale/timeouts preserve observation time and do not display zeros. |
| DATA-03 | Unknown service/log IDs and path traversal fail; oversized tails are bounded and sanitized; log HTML never executes. |
| ACL-01 | Browser-forged principal/scopes/tool/path and malformed IPC fail; read adapter cannot admit mutations or general shell execution. |
| ACL-02 | Another owner's or wrong-resource connection cannot be listed/revoked; browser and desktop grants remain distinct. |
| REV-01 | Revoke requires current reauth and exact one-use confirmation; replay/conflicting idempotency payload fails. |
| REV-02 | Durable revocation survives restart; propagation failure is pending/unavailable, never completed; subsequent established Edge/Broker authorization rejects the revoked grant. |
| REV-03 | Audit disk-full/IPC timeout/crash between dispatch and readback reconciles without fabricated success or regrant. |
| AUDIT-01 | Login and mutation intent/outcome are recorded once with target/result/correlation; secret scan finds no credentials/tokens. |
| DB-01 | Additive migration, backup restore, expiry cleanup, session caps, retention and pending-operation limits work under concurrent requests. |
| REG-01 | Existing OAuth discovery, login/consent, callbacks, refresh, approval pages and revocation regressions pass. |
| UI-01 | Desktop/mobile and keyboard checks pass; empty/denied/stale/partial states are readable; unimplemented actions are absent. |
| DEPLOY-01 | Origin is loopback-only, Access protects only the control hostname, existing MCP connections work, and disable/rollback is verified. |

Use targeted unit/integration tests for contracts, expiry, policy and recovery,
then browser checks for real login/navigation/revocation. Run repository lint,
typecheck and documentation checks plus affected Auth/Edge/Broker regressions.
Run full acceptance on an isolated fixture before any production revocation.
Public canary may revoke only a disposable owner-approved test connection.

Attach exact commit/runtime/config fingerprints, sanitized results, remaining
limitations, and rollback readback to the existing progress/evidence workflow.
The document itself can be complete while implementation remains unstarted.
