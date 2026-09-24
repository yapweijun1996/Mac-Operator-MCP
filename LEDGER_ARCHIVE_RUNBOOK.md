# Request and Job Ledger Archive Runbook

Status: Host-only, stopped-service recovery and bounded-rotation artifact; no
MCP route or model-facing tool invokes this workflow.

This procedure creates a bounded, owner-only encrypted snapshot of terminal
Request and Job history. `ledger-export` is additive. `ledger-rotate` first
creates the same encrypted snapshot, then uses the stopped-service runtime
fence to replace only sufficiently old known-terminal rows with compact,
integrity-checked tombstones. Active, queued, running, and `unknown` work is
never eligible for deletion.

## Preconditions

- The packaged `broker-service.json` is owner-only and passes the normal
  startup-config validator.
- The config contains a separate archive Keychain item through
  `auditArchiveKeyService`, `auditArchiveKeyAccount`, and `auditArchiveKeyId`.
  It must not reuse the audit-anchor item.
- The Broker socket is inactive and the exact Broker instance lock can be
  acquired. The operation never races a live Broker writer.
- The fixed `<dataRoot>/audit-exports` directory is owner-only and is not a
  symlink. No key bytes, archive plaintext, or database rows are placed in
  arguments, environment variables, logs, or MCP requests.

## Export

```sh
npm run audit:archive -- ledger-export \
  --config /absolute/path/to/broker-service.json \
  --confirm ledger-export
```

The command authenticates the configured archive key, validates persisted
Request and Job rows through the normal Broker invariants, selects only
terminal rows, and writes an encrypted
`ledger-export-<timestamp>-<random>.json.enc` artifact. Publication is
exclusive and fsynced. Before creating any temporary file, the command
performs a bounded free-space preflight for the plaintext payload plus fixed
headroom. An unavailable or insufficient capacity check returns retryable
`AUDIT_UNAVAILABLE` and leaves no archive temporary artifact. The returned
manifest contains only path, size, ciphertext digest, key ID, record counts,
and a snapshot digest.

## Rotate

Rotation is an explicit host-only operation. It requires exact retention
counts and a minimum age; the operation retains the newest terminal rows above
those counts and never removes active or unresolved work:

```sh
npm run audit:archive -- ledger-rotate \
  --config /absolute/path/to/broker-service.json \
  --retain-requests 10000 \
  --retain-jobs 10000 \
  --min-age-ms 86400000 \
  --confirm ledger-rotate
```

The encrypted archive is published before the SQLite transaction begins. The
transaction records a non-secret audit intent, writes Request/Job tombstones
bound to the archive digest, deletes only exact revision/state matches, and
records completion. A runtime-fence loss, archive/key failure, malformed
ledger state, insufficient archive capacity, tombstone capacity limit, or
changed row aborts the transaction. Capacity failure occurs before the
rotation transaction and preserves the live ledger unchanged.
Tombstones preserve terminal Job status, replay rejection, and idempotency
reuse rejection; raw stdout/stderr is not retained in tombstones.

Archive files are not automatically deleted by this command. Operators must
retain and protect them according to the approved storage policy. Use the
separate explicit archive-retention operation when deletion is approved.

## Archive artifact retention

This operation manages only exact encrypted `audit-export-*` and
`ledger-export-*` names in the protected archive directory. It never decrypts
or rewrites an artifact:

```sh
npm run audit:archive -- archive-prune \
  --config /absolute/path/to/broker-service.json \
  --retain-audit 7 \
  --retain-ledger 7 \
  --min-age-ms 86400000 \
  --confirm archive-prune
```

Files newer than `min-age-ms` are always retained. For older files, the newest
requested count is retained independently for audit and ledger archives. The
operation refuses symlinks, unsafe owner/mode/size, unfinished artifacts,
path/inode changes, malformed options, and unverified deletion. It is owner
only, stopped-service, instance-lock protected, and does not remove unknown
directory entries. Physical disk exhaustion, external immutable anchoring, and
production archive lifecycle remain separate release gates.

## Inspect

Inspection is read-only and accepts only a direct child of the fixed archive
directory:

```sh
npm run audit:archive -- ledger-inspect \
  --config /absolute/path/to/broker-service.json \
  --archive /absolute/path/to/data/audit-exports/ledger-export-...json.enc \
  --confirm ledger-inspect
```

Inspection authenticates the file, validates its exact versioned shape, record
identities, terminal states, bounds, and recomputed snapshot digest. Wrong
keys, ciphertext changes, symlink substitution, and target swaps fail closed.
Inspection returns manifest metadata only and never returns decrypted records.

## Retention boundary and rollback

Rotation is deliberately bounded and reversible at the live-ledger level: a
tombstone keeps the terminal identity and archive digest, while the encrypted
archive remains the recovery source for full historical records. Do not remove
tombstones or archive files manually, and never use this command to prune
active, queued, running, or unresolved work. The tombstone capacity is a hard
stop, not a permission to bypass the archive or retention policy.

Rollback is additive: disable the CLI caller and return to the previous Broker
release. Existing Request/Job state and audit-chain behavior remain unchanged;
preserve any generated encrypted artifact unless its disposal has a separately
approved owner-only procedure.

## Evidence

The local implementation and negative-path evidence is recorded in
`evidence/2026-09-23-ledger-export-recovery.md`. Production Keychain
provisioning, installed service readback, archive artifact retention,
physical disk exhaustion, external immutable anchoring, and final acceptance
remain open gates.
