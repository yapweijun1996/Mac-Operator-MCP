# Configuration Contract

Status: Draft; serialization and storage remain open under ADR-0004

## Configuration domains

- Edge: remote issuer, audience, endpoint exposure, client/session rate limits, Broker address.
- Broker: component identity, capability switches, adapter registry, execution budgets, persistence, audit outage policy.
- Policy: exact scopes, target grants, F0-F5 filesystem data, app/service/package/volume allowlists, task profiles.
- Operations: log levels, retention, backups, health thresholds, update channel, emergency controls.

## Rules

Authority configuration is versioned, schema-validated, authenticated, atomically applied, audited, and rollback-aware. Unknown fields or incompatible versions fail the affected capability closed. Config contains secret references only; secret values belong in an approved host secret mechanism. Ordinary MCP tools cannot edit authority configuration.

## Pending decisions

File/database format, schema tooling, override precedence, environment handling, reload mechanism, signer/administrator identity, secret-reference provider, migration, and rollback format.
