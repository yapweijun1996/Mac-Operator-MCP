# OAuth Direct Auth-to-Edge Revocation Push Evidence

Date: 2026-09-22

Status: implemented and focused-tested in the working tree; live personal R1
was not restarted or changed.

## Boundary

An issuer-side grant revocation now follows this bounded path:

```text
AuthStore durable grant revoke
  -> Auth child emits a strict non-secret grant notice
  -> owner supervisor accepts the notice only from the Auth child
  -> supervisor forwards the same bounded notice to the Edge child
  -> Edge converts it to a validated revocation context
  -> existing Edge-to-Broker HMAC revocation IPC
```

The notice contains only the grant/session identity, owner principal identity,
bounded known scopes, and grant expiry. It contains no access token, refresh
token, password, key material, or raw request payload. The supervisor does not
accept the notice from MCP or from an arbitrary process; it is handled only on
the fixed Auth child IPC listener and forwarded to the fixed Edge child.

## Failure and recovery behavior

- The Auth listener is dispatched only after the SQLite mutation commits.
- A failed Edge-to-Broker propagation remains in the Edge revocation monitor
  for bounded status-based retry; it cannot become an authority grant.
- The existing Broker event signature, replay ledger, session revocation, and
  queued/active-work cancellation remain the final authority boundary.
- Duplicate delivery is safe because Broker revocation admission is durable and
  the Edge monitor removes the retry entry only after propagation succeeds.
- The path is host-only and is not an MCP tool or an OAuth scope.

## Verification

- Auth grant-revocation callback: passed.
- Edge direct-push monitor and retry-removal behavior: passed.
- Combined focused Auth/Edge/parser run: `26` passed, `0` failed, `0` skipped.
- TypeScript build/typecheck passed.
- Live R1 PM2 service, OAuth grant, policy, and public tools list were not
  changed.

## Rollback

The feature is not assembled into a newly deployed snapshot by this probe.
Rollback is source-level removal of the direct child-message callback; the
existing owner-authenticated status polling and Edge-to-Broker revocation
channel remain the fallback boundary.
