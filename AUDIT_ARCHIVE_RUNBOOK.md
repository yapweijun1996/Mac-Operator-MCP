# Audit Archive Export and Recovery Runbook

Status: Host-only operator procedure; no MCP route or model-facing tool
invokes this workflow.

This procedure exports a bounded, encrypted snapshot of the redacted Broker
audit ledger and verifies it without exposing event rows. It is separate from
SQLite backup/restore: an audit archive is evidence, not a database cutover
source.

## Preconditions

- The packaged `broker-service.json` is an owner-only `0600` file and passes
  the normal Broker startup-config validator.
- The config contains all three archive-key fields:
  `auditArchiveKeyService`, `auditArchiveKeyAccount`, and `auditArchiveKeyId`.
  They must identify a separate Broker-executable-ACL Keychain item and must
  not reuse the audit-anchor item.
- The fixed archive directory is `<dataRoot>/audit-exports`. It must remain
  an owner-only, non-symlink directory. The CLI creates this one directory
  with mode `0700` when absent; it never creates arbitrary paths.
- No key bytes, Keychain contents, archive plaintext, or database rows are
  placed in arguments, environment variables, logs, or MCP requests.

## Export

Stop the installed Broker through its service owner and verify that its
configured Broker socket is inactive. The command also acquires the exact
Broker instance lock, so a concurrent service start fails closed.

```sh
npm run audit:archive -- export \
  --config /absolute/path/to/broker-service.json \
  --confirm export
```

The command then opens the protected database with the configured audit-anchor
Keychain source, re-verifies the full local chain and keyed tail, and writes an
encrypted `audit-export-<timestamp>-<random>.json.enc` file. Publication is
exclusive and fsynced. The output is a bounded manifest containing path,
size, ciphertext digest, key ID, event count, and tail metadata; it never
contains decrypted events.

If the Broker socket is active, the instance lock is owned by a live process,
the database or parent is unsafe, either Keychain item is missing/mismatched,
or the audit tail cannot be verified, the operation stops before export.

## Inspect and preserve

Inspection is read-only and accepts only a direct child of the fixed archive
directory. It authenticates the archive and validates its exact versioned
shape, sequence continuity, previous-hash chain, redacted evidence JSON,
event hashes, ciphertext digest, and configured archive key identity:

```sh
npm run audit:archive -- inspect \
  --config /absolute/path/to/broker-service.json \
  --archive /absolute/path/to/data/audit-exports/audit-export-...json.enc \
  --confirm inspect
```

Preserve the returned manifest with the incident or cutover record. Do not
copy the archive into a shared or group-readable directory. External immutable
anchoring, if later approved, must copy only the encrypted artifact through a
separately reviewed destination adapter and must preserve the manifest digest;
the current CLI does not perform that transfer.

## Recovery and rollback

1. Keep new Broker admission disabled while investigating a failed export or
   failed integrity readback.
2. If the archive is valid but the live database is unavailable, use the
   separate authenticated SQLite backup/restore runbook. Restore into a fresh
   destination; never replace a live database or down-migrate in place.
3. Re-open the restored Broker with the current audit-anchor Keychain source.
   Startup must verify schema migrations, audit chain, keyed tail, runtime
   fence, and revocation/kill-switch state before any capability is enabled.
4. Re-run the archive inspection command against the preserved archive. A
   valid archive does not prove that the restored database is current; compare
   its sequence/tail manifest with the restored database readback.
5. If any archive, database, Keychain identity, owner/mode, or target identity
   check is ambiguous, preserve the artifacts and stop. Do not delete or
   overwrite them to make the service start.

The CLI is additive and has no archive deletion, pruning, compaction, or
database replacement operation. Rollback therefore means disabling the CLI
entrypoint and returning to the previous Broker release; existing audit-chain
readback, retention enforcement, and SQLite backup/restore remain unchanged.

## Verification evidence

The code boundary and negative paths are recorded in
`evidence/2026-09-23-audit-export-recovery.md`. A production acceptance record
must additionally prove the signed Broker release, Keychain ACL readback,
installed service identity, owner-only archive directory, a real export and
inspection, and a rehearsed fresh-destination recovery before this procedure
is considered production-complete.
