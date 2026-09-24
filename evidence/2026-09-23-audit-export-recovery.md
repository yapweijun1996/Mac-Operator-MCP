# Audit Export and Recovery Boundary

Date: 2026-09-23

Status: PASS for the local owner-only encrypted export and recovery boundary;
production deployment, external immutable anchoring, and final acceptance
remain open.

## Implemented boundary

- `BrokerStore.exportAuditArchive` performs the authenticated full-chain and
  keyed-tail readback before taking an audit snapshot.
- The archive format is versioned as `mac-operator-audit-export-v1` and uses
  AES-256-GCM with the existing protected Broker backup-key source contract.
- Exported rows retain the redacted audit shape only. The archive is bounded
  by event count and plaintext/ciphertext size, and the published file is
  owner-only mode `0600`.
- Publication uses `O_NOFOLLOW`, protected-parent validation, descriptor
  identity checks before and after the bounded read, exclusive no-overwrite
  hard-link publication, and file/directory `fsync`.
- Temporary files are cleaned only after identity checks. Archive inspection
  returns manifest metadata only and never returns decrypted event rows.
- Recovery validation checks the exact archive structure, authenticated key,
  sequence continuity, previous-hash chain, evidence JSON, and recomputed
  event hashes. Wrong keys, ciphertext tamper, symlink substitution, target
  swaps, and malformed payloads fail closed.
- The feature is export/inspection only. It does not delete, compact, rewrite,
  or weaken the append-only audit store.
- The host-only `mac-operator-audit` CLI accepts only the protected service
  config and a direct archive filename. Export requires a distinct configured
  archive Keychain item, acquires the Broker instance lock, rejects an active
  Broker socket, and derives the destination as `<dataRoot>/audit-exports`.
- Export performs a bounded free-space preflight for the plaintext payload plus
  fixed headroom before creating a temporary archive. Insufficient capacity is
  retryable `AUDIT_UNAVAILABLE` and leaves no archive temporary artifact.

## Verification

- Focused audit-export tests: 5 passed, 0 failed.
- Combined audit-export and persistence slice: 65 passed, 0 failed.
- Focused CLI/config/Keychain-source coverage: 23 passed, 1 skipped, 0 failed.
- Full repository regression: 1,161 total; 1,146 passed, 15 skipped, 0
  failed.
- Typecheck and build passed after the publication identity fix.
- Retention-bound recovery was verified: once the append limit is reached,
  further append is rejected while an encrypted export remains available and
  the ledger is unchanged.

## Remaining limits

- There is no external immutable archive anchor or production archive service.
- Production Keychain identity/provisioning and installed operator
  authentication remain host-gated.
- The archive is a consistent local snapshot at export time; it is not a live
  replication stream.
- Final acceptance remains blocked by the existing host gates: no valid
  Developer ID identity, Accessibility permission denied, target launchd
  labels absent, and no production acceptance record.

## Rollback

The change is additive. Disable callers of `exportAuditArchive` and remove
the archive module from the next release if required; the existing append-only
store, integrity readback, and retention enforcement remain unchanged.
