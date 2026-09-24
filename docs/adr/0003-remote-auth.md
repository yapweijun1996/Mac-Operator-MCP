# ADR-0003: Remote Authentication and Transport

Status: Proposed
Date: 2026-09-12
Tasks: MOP-021, MOP-024, MOP-025

## Context

The public MCP endpoint needs authenticated HTTPS access, revocable principal projection, consent or scope handling, rate limits, and compatibility with intended AI clients. The Local Broker remains private.

## Options to evaluate

The proposed owner username/password login, consent, JWT issuance, and initial
three-tool connection are specified in [OAuth login design](../oauth-login-design.md).
The owner-authorized personal deployment is live as of 2026-09-21; see
[deployment evidence and limits](../personal-deployment.md). Formal release
acceptance remains Proposed.

- OAuth-based MCP authorization with short-lived access and revocation.
- A managed authenticated tunnel combined with application OAuth.
- Another standards-compatible HTTPS deployment that meets equivalent identity and revocation requirements.

## Decision criteria

Client compatibility, issuer and subject stability, PKCE/registration support where required, scope projection, revocation latency, key ownership, operational recovery, auditability, tunnel blast radius, and cost.

## Constraints

Transport reachability is not authorization. The Edge cannot project scopes it did not validate, and Broker policy remains authoritative. No tunnel directly exposes Broker IPC. Local integration tests must work without public deployment.

## Prototype evidence

The current Edge candidate uses the official MCP TypeScript SDK v2 and serves only the 2026-07-28 protocol through a fresh per-request server. It now includes a bounded JWT access-token verifier with pinned issuer/resource expectations, explicit asymmetric algorithms, local or remote JWKS sources with fetch/cache limits, bounded unknown-`kid` refresh cooldown, short token-age limits, required identity claims, internal issuer-ID projection, known-scope projection, and an optional fail-closed revocation callback. Startup rejects a metadata issuer or authorization/token endpoint that is not HTTPS or that does not match the configured issuer identity. The raw bearer token remains at the Edge and never enters the Broker principal. Host and Origin allowlists, a 1 MiB JSON limit, TLS 1.3 minimum, OAuth protected-resource metadata, caller-filtered Broker capability discovery, and Broker-authenticated responses are wired. Tests cover signed JWT acceptance, issuer/resource/signature/expiry/audience failures, remote-JWKS caching and rotated-key refresh, revocation, metadata mismatch, missing authentication context, unknown-scope filtering, token isolation, and per-principal tool visibility. The official MCP client completes pinned 2026-07-28 discovery and tool listing over the HTTPS Edge using a signed JWT.

The local owner OAuth candidate now implements username/password login, explicit
consent, code/S256 exchange, ES256 issuance, durable rotating refresh grants,
and per-request authenticated grant-state checks at the Edge. Its local tests
exercise the issuer-to-Edge-to-Broker identity path and three read-only tools.
The personal deployment now provides public HTTPS discovery, owner login,
consent, S256 exchange, three real Broker tool calls, and rejection after grant
revocation. Child-process failure recovery also passed. This is an
owner-managed unsigned snapshot, not formal signed-package acceptance. Actual
ChatGPT UI connection, live signing-key rotation, and cancellation of already
running Broker tasks on revocation remain unverified. Historical local
prototype evidence below does not establish these remaining properties.

The next personal snapshot keeps the public status URL as the issuer-bound
logical resource but performs each grant check over a fixed local HTTPS
channel. The local endpoint is restricted to `127.0.0.1`, the request uses
the issuer hostname for Host/SNI, the CA file is startup-bound under the Edge
data root, and the existing status key remains mandatory. The public status
path remains a compatibility fallback only for non-owner or older release
processes; the current owner startup contract rejects missing loopback fields.
Timeouts,
certificate failures, endpoint mismatches, and malformed status responses
continue to reject the token rather than permit access.

Revision `c82d04a` reruns the layered local path on a physical Darwin 25.2.0
arm64 host: the bounded L0/L1 probe, same-process HTTPS Edge, and separately
spawned Edge/native-Broker path pass 3/3 with replay and bearer-token audit
isolation checks. This strengthens local host evidence only; it does not change
the Proposed status or establish an external issuer, certificate provenance,
launchd installation, public exposure, or remote deployment.

Commit `3cca22c` adds an Edge-owned remote-JWKS response boundary before
`jose` parsing: the fetch body is streamed into a 256 KiB cap, invalid length
metadata is rejected, and only JSON JWKS MIME types are accepted. This reduces
parser and memory exposure but does not substitute for external issuer,
certificate-chain, rotation/revocation propagation, or deployment evidence.
Evidence: [`evidence/2026-09-15-edge-jwks-response-boundary.md`](../../evidence/2026-09-15-edge-jwks-response-boundary.md).

Commit `c97140a` extends that boundary to endpoint identity: redirected
responses and non-empty final URLs that differ from the startup-configured
JWKS URL are rejected before parsing. This prevents a followed redirect from
silently changing the key source, but it does not provide DNS/TLS pinning,
external issuer evidence, or public deployment acceptance. Evidence:
[`evidence/2026-09-15-edge-jwks-redirect-boundary.md`](../../evidence/2026-09-15-edge-jwks-redirect-boundary.md).

Commit `fc04641` extends the same boundary to HTTP response status: only 2xx
JWKS responses are read and parsed; non-success responses fail closed before
key material handling. This prevents JSON error responses from entering the
key parser, but does not provide external issuer, DNS/TLS, rotation/revocation,
or public deployment evidence. Evidence:
[`evidence/2026-09-15-edge-jwks-status-boundary.md`](../../evidence/2026-09-15-edge-jwks-status-boundary.md).

The packaged Edge now has a fixed `service-main.js` entrypoint and strict
owner-only `edge-service.json` startup document. It assembles the existing
HTTPS/JWT/contract/signed-IPC boundary only from canonical root-bound paths,
requires listener host/port readback, and wipes in-memory authentication/TLS
buffers on close. This improves local process-boundary evidence but does not
by itself establish deployment acceptance. The later personal deployment
provides the additional evidence and operational limits linked above.

## Acceptance evidence

Metadata discovery, authorization flow, valid connection, invalid token, expiry, revocation, scope reduction, rate limits, tunnel outage, and Broker-unavailable behavior must be verified without recording secrets.
