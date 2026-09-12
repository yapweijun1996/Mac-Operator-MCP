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

## Acceptance evidence

Metadata discovery, authorization flow, valid connection, invalid token, expiry, revocation, scope reduction, rate limits, tunnel outage, and Broker-unavailable behavior must be verified without recording secrets.
