# Configuration Contract

Status: Signed policy candidate implemented; operational configuration remains draft

## Configuration domains

- Edge: remote issuer, audience, endpoint exposure, client/session rate limits, Broker address.
- Broker: component identity, capability switches, adapter registry, execution budgets, persistence, audit outage policy.
- Policy: exact scopes, target grants, F0-F5 filesystem data, app/service/package/volume allowlists, task profiles.
- Operations: log levels, retention, backups, health thresholds, update channel, emergency controls.

## Rules

Authority configuration is versioned, schema-validated, authenticated, atomically applied, audited, and rollback-aware. Unknown fields or incompatible versions fail the affected capability closed. Config contains secret references only; secret values belong in an approved host secret mechanism. Ordinary MCP tools cannot edit authority configuration.

## Implemented policy candidate

`schemas/policy-document.schema.json` and `schemas/signed-policy-bundle.schema.json` define the current authority bundle. The Broker verifies Ed25519 signatures with a pinned, protected public-key file; the signing private key is not a Broker input. Policy revisions are monotonic, requests bind the active policy version, deny rules override allow rules, target matching is exact, and signed policy cannot mark code as implemented.

Activation identity and audit intent/completion commit in one Broker-owned transaction; the in-memory `PolicyManager` reference changes only after commit. Restart requires an exact verified identity match. Rollback can target only an exact signed historical policy and requires the current revision plus a structured operator reason code. No model-facing tool can load, replace, or roll back policy. Production operator wiring is not implemented.

Signed `filesystem_roots` bind a stable `root_id` to one lexically normalized absolute path, independent `metadata` and `content_read` enable flags, and normalized relative deny paths. Tool requests provide a path, but only the Broker selects the matching root ID and applies exact target authorization. Descriptor-backed adapters then revalidate canonical containment, same-volume identity, target type, and deny zones after opening the target. No root is configured or production-enabled by default.

Broker-mandatory secret path and content-signature rules are code-owned minimum denials; a signed policy cannot remove them. Policy `deny_relative_paths` can only add narrower exclusions. Content reads additionally require a local filesystem, a single-link regular-file inode, and unchanged descriptor identity and metadata after reading.

Local HMAC key files can be provisioned only with exclusive creation inside an owner-only non-symlink directory. Creation uses mode `0600` and synchronizes both file and directory. Retirement requires a persisted exact Edge-key revocation and expected SHA-256 digest, then moves the file to a unique same-directory quarantine name before unlinking. This is logical retirement, not a physical secure-erase guarantee on APFS or SSD media.

## Pending decisions

Crash-injection evidence, operator reload/rollback mechanism and runbook, signer rotation/revocation, secret-reference provider, production filesystem root/deny classification, a general versioned migration framework, and cross-runtime canonicalization evidence. The specific legacy revocation-table migration for `edge_key` support is implemented and tested.
