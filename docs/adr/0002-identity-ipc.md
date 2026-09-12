# ADR-0002: Principal Identity and Edge-to-Broker IPC

Status: Proposed
Date: 2026-09-12
Tasks: MOP-011, MOP-012, MOP-081

## Context

The Edge authenticates remote callers, while the Broker owns final host authorization. IPC must preserve a trustworthy principal and prevent forgery, replay, payload substitution, downgrade, and unauthorized Edge replacement.

## Required decision

Define principal ID and issuer, session identity and concurrency, Edge identity, local transport, authentication primitive, key creation/storage/rotation/revocation, canonical payload encoding, signature or MAC, nonce domain and persistence, request-age limit, clock-skew policy, schema negotiation, incompatible-version behavior, and Edge replacement detection.

## Constraints

- Principal and scopes come from validated transport context, not tool arguments.
- The signed/authenticated envelope binds principal, session, Edge identity, tool, contract version, canonical payload digest, request ID, timestamp, nonce, and policy audience.
- Broker checks revocation on admission and immediately before mutation.
- Restart cannot silently reopen accepted nonce or idempotency windows.
- Multiple sessions do not imply shared approval or target authority.

## Candidate mechanisms

Protected Unix-domain socket with OS peer credentials plus application-layer request authentication; or loopback transport with mutually authenticated application credentials. The final choice depends on runtime and packaging evidence.

## Acceptance evidence

Forged peer, copied envelope, changed payload, expired timestamp, repeated nonce, revoked session, concurrent session, restart replay, version mismatch, and replaced-Edge tests must fail safely.
