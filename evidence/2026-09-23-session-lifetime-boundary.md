# Broker Session Lifetime Boundary

Date: 2026-09-23
Host: physical macOS host used by the repository test harness
Scope: authenticated Edge-to-Broker principal sessions

## Decision

The Broker now rejects a signed principal whose declared lifetime exceeds 24
hours. The check is inside the Broker authentication boundary, after request
authentication and before revocation, policy, or adapter dispatch can grant
work. The model's `expiresAtMs` remains authoritative for earlier expiry;
refreshing an OAuth grant cannot bypass this fixed Broker ceiling.

## Verification

The existing Broker session-expiry regression now covers expired sessions and
an overlong session, both returning `AUTH_EXPIRED`. The full regression remains
1,164 tests with 1,149 passed, 15 skipped, and 0 failed.

## Scope and limits

This closes only the maximum-lifetime invariant. It does not decide refresh
UX, issuer-side grant duration, revocation propagation latency, or production
remote issuer evidence. No host service, credential, permission, or persistent
authority state was changed.

## Recovery

The change is source-reversible, but removing the ceiling would reopen a
Broker-side long-lived principal authority path. Existing shorter sessions and
the current five-minute OAuth access-token lifetime remain compatible.
