# ADR-0003: Remote Authentication and Transport

Status: Proposed
Date: 2026-09-12
Tasks: MOP-021, MOP-024, MOP-025

## Context

The public MCP endpoint needs authenticated HTTPS access, revocable principal projection, consent or scope handling, rate limits, and compatibility with intended AI clients. The Local Broker remains private.

## Options to evaluate

- OAuth-based MCP authorization with short-lived access and revocation.
- A managed authenticated tunnel combined with application OAuth.
- Another standards-compatible HTTPS deployment that meets equivalent identity and revocation requirements.

## Decision criteria

Client compatibility, issuer and subject stability, PKCE/registration support where required, scope projection, revocation latency, key ownership, operational recovery, auditability, tunnel blast radius, and cost.

## Constraints

Transport reachability is not authorization. The Edge cannot project scopes it did not validate, and Broker policy remains authoritative. No tunnel directly exposes Broker IPC. Local integration tests must work without public deployment.

## Prototype evidence

The current Edge candidate uses the official MCP TypeScript SDK v2 and serves only the 2026-07-28 protocol through a fresh per-request server. It now includes a bounded JWT access-token verifier with pinned issuer/resource expectations, explicit asymmetric algorithms, local or remote JWKS sources with fetch/cache limits, short token-age limits, required identity claims, internal issuer-ID projection, known-scope projection, and an optional fail-closed revocation callback. The raw bearer token remains at the Edge and never enters the Broker principal. Host and Origin allowlists, a 1 MiB JSON limit, TLS 1.3 minimum, OAuth protected-resource metadata, caller-filtered Broker capability discovery, and Broker-authenticated responses are wired. Tests cover signed JWT acceptance, issuer/resource/signature/expiry/audience failures, remote-JWKS caching, revocation, missing authentication context, unknown-scope filtering, token isolation, and per-principal tool visibility. The official MCP client completes pinned 2026-07-28 discovery and tool listing over the HTTPS Edge using a signed JWT.

No external/deployed OAuth issuer, authorization-code/token issuance flow, certificate-chain deployment, tunnel, public listener, or revocation propagation evidence exists. The local self-signed certificate and official-client probe are prototype evidence only. This ADR remains Proposed and the Edge must not be deployed publicly from this prototype evidence.

## Acceptance evidence

Metadata discovery, authorization flow, valid connection, invalid token, expiry, revocation, scope reduction, rate limits, tunnel outage, and Broker-unavailable behavior must be verified without recording secrets.
