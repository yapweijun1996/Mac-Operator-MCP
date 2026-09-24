# Request and Job Ledger Export Boundary

Date: 2026-09-23

Status: PASS for the local encrypted terminal-history export, inspection, and
stopped-service rotation boundary; production deployment and final acceptance
remain open.

## Implemented boundary

- `BrokerStore.exportLedgerArchive` validates persisted Request and Job rows
  using the existing state and ownership invariants before selecting terminal
  history.
- Active Requests and queued/running Jobs are excluded. `unknown` Jobs may be
  represented as historical evidence, but the archive never authorizes their
  deletion or replay.
- The versioned `mac-operator-ledger-export-v1` payload records exact bounded
  Request/Job identities and recomputes a snapshot digest over canonical JSON.
- AES-256-GCM, owner-only `0600` publication, protected-parent validation,
  `O_NOFOLLOW`, descriptor identity checks, exclusive hard-link publication,
  and file/directory fsync bind the archive boundary.
- Inspection returns manifest metadata only. Wrong keys, ciphertext tamper,
  symlink substitution, unexpected record shapes, non-terminal records, and
  digest mismatch fail closed.
- The host-only `mac-operator-audit` CLI exposes explicit
  `ledger-export`, `ledger-inspect`, and `ledger-rotate` operations using the
  stopped-service instance lock and the existing separate archive Keychain
  configuration.
- Schema version 17 adds bounded Request/Job tombstones. Rotation publishes
  the encrypted archive first, then atomically records archive-bound
  tombstones and deletes only old known-terminal rows under the runtime fence.
  Job status remains readable after rotation; the original Request ID remains
  replay-denied and the archived Job idempotency key cannot create a new Job.
- Active, queued, running, and `unknown` rows remain live. Tombstones omit raw
  stdout/stderr, validate on Broker restart, and hard-stop when the bounded
  tombstone capacity is reached.
- Export and rotation perform a bounded free-space preflight before creating a
  temporary archive. Injected insufficient-capacity probes return retryable
  `AUDIT_UNAVAILABLE`, leave no temporary archive artifact, and preserve live
  terminal rows when used through rotation.

## Verification

- Focused ledger export/inspection/rotation regression: 6 passed, 0 failed, 0 skipped.
- Focused archive artifact retention regression: 3 passed, 0 failed, 0 skipped.
- Focused audit export regression: 5 passed, 0 failed, 0 skipped.
- Focused archive retention and CLI regression: 5 passed, 0 failed, 0 skipped.
- Full repository regression: 1,161 total; 1,146 passed, 15 skipped, 0 failed.
- `npm run build`, `npm run typecheck`, and `git diff --check`: passed.

## Remaining limits

- The local `archive-prune` boundary now provides explicit age/count retention
  for exact encrypted audit/ledger artifacts with symlink, unfinished-file,
  owner/mode, size, and inode-swap fail-closed checks. Production archive
  lifecycle, physical disk exhaustion, production Keychain provisioning/
  readback, external immutable anchoring, installed operator authentication,
  and final acceptance remain host-gated.
- The local rotation proof does not claim APFS/SSD secure erasure or a
  production archive lifecycle; archive files remain operator-retained.

## Rollback

The feature is additive. Disable the new CLI operations and remove the ledger
archive module in a later release if required; existing Request/Job persistence
and recovery paths remain unchanged.
