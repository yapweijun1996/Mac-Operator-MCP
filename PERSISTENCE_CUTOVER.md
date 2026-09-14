# Persistence Migration and Rollback Runbook

Status: Draft operator procedure; no production cutover command is shipped

This runbook covers a Broker persistence revision change. It is intentionally
separate from model-facing tools and cannot be triggered by MCP arguments.
The current implementation supports forward schema migration only. A rollback
restores an authenticated encrypted backup into a fresh destination; it never
performs an automatic down-migration.

## Preconditions

An operator must record the exact source revision, target revision, contract
set, policy revision/key ID, Broker executable identity, Node/runtime identity,
SQLite schema marker, active kill-switch state, and backup key ID. The target
revision must pass the repository checks on the same supported runtime:

```text
npm ci
npm run lint
npm run typecheck
npm test
npm run verify:contracts
npm audit --omit=dev --audit-level=high
```

The operator must also have a protected, owner-only destination volume with
enough capacity for the SQLite snapshot, WAL/SHM sidecars, encrypted envelope,
verification copy, and bounded headroom. The backup key source must be the
Broker-owned configured file/Keychain source; key bytes must not appear in
commands, environment variables, logs, or MCP requests.

## Forward cutover

1. Disable admission for affected capabilities and record an audited operator
   intent. Revoke the Edge/session or capability authority if the change is
   security-related. New requests must fail closed; queued work is cancelled
   transactionally. Active work is drained or remains `UNKNOWN` until its
   postcondition and actor attribution are resolved.
2. Stop the Broker through the installed service owner, then verify the
   owner-only instance lock is released and no old process identity remains.
   Do not copy or replace a live SQLite file under an active Broker.
3. Call the host-only `BrokerStore.backupTo` boundary. Confirm the resulting
   `.sqlite.enc` manifest, key ID, file owner/mode, source identity, SQLite
   `quick_check`, audit-chain verification, and encrypted publication readback.
   Preserve the backup and its audit record before proceeding.
4. Restore the encrypted backup into a new, empty destination with
   `BrokerStore.restoreBackup`. The restore must authenticate/decrypt, reject
   source target swaps, verify SQLite and the audit chain, and refuse an
   existing destination. Keep the old destination untouched as the recovery
   reference.
5. Start the target Broker against the fresh destination. Its constructor must
   read `PRAGMA user_version`, validate every `schema_migrations` row, apply
   only the known monotonic migrations inside one transaction, and publish
   marker `4` only after all migration records commit. A future marker, gap,
   changed migration name, malformed row, audit-chain mismatch, or recovery
   error is a hard stop.
6. Before enabling any capability, perform final readback: exact source/schema
   and policy identities, signer/key revocation state, kill switches, audit
   head, request/job counts, instance lock, native IPC peer identity, and
   absence of queued work that was meant to be cancelled. Run the relevant
   focused and full test evidence again on the clean target revision.
7. Enable capabilities one scope at a time only after the readback is recorded.
   Keep the previous destination and authenticated backup until the observation
   window completes and the operator accepts the audit evidence.

## Failure and rollback

- Failure before the target Broker accepts work: keep admissions disabled and
  boot the previous known-good revision against its untouched destination.
- Failure after target startup but before final readback: stop the target,
  preserve its logs/audit database as evidence, and do not copy its database
  over the old destination. Restore the authenticated backup into another fresh
  destination and retry only after the cause is reviewed.
- A dispatched mutation with an unproven result is `UNKNOWN`, not success.
  Reconcile its postcondition and actor identity before replacing components;
  never infer success from a process exit or a matching digest alone.
- If the target database is corrupt, tampered, future-versioned, or has an
  invalid migration registry, refuse startup. Restore the last authenticated
  encrypted backup into a fresh destination and perform a separately reviewed
  cutover. There is no in-place down-migration or force-reset escape hatch.
- Do not restore revoked Edge, approval, signer, helper, or operator authority
  merely because it exists in an old backup. Reapply current revocations and
  reissue authority explicitly after readback.

## Post-rollback readback

Record the restored backup manifest/key ID, fresh destination identity, exact
schema marker and migration rows, audit-chain head, policy/signer revision,
revocations, kill switches, active/queued/unknown jobs, component code identity,
IPC peer identity, and capability enablement. Verify that no temporary restore
files, plaintext SQLite backup names, WAL/SHM sidecars, or secret-bearing logs
remain outside the protected Broker directory. A rollback is not complete until
this final readback and the operator audit completion are durable.

## Current implementation boundary

`BrokerStore.backupTo`, `restoreBackup`, `pruneBackups`, the schema-version gate,
and the transactional migration registry are implemented and test-covered.
The runbook's installed launchd stop/start, production artifact signing,
external anchoring, operator approval, and service cutover steps remain host
operations and are not automated by this repository.
