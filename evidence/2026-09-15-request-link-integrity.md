# Request Link Integrity

Status: PARTIAL MOP-071/MOP-083 evidence; capability enablement remains gated

Date: 2026-09-15

## Scope

Request-to-Job linkage now resolves and validates the Job inside the same
Broker transaction before writing the Request reference. The linked Job must
match the Request principal, session, tool, target, policy, and (when
present) Edge provenance; missing Jobs return `TARGET_NOT_FOUND` and identity
substitution returns `CONFLICT`.

Broker startup also checks every persisted Request reference. A linked
Approval must exist, match the requesting principal/tool/policy/target, and
show the single consumed request identity. A linked Job must exist and match
the Request owner/tool/target/policy identity. Missing or mismatched links
fail closed as `AUDIT_UNAVAILABLE` before recovery or policy evaluation.

The Request envelope digest and Job/Approval argument digest are deliberately
not compared: they represent different canonical payload domains and are
bound independently by their respective contracts.

## Verification

- Request-link focused tests: 3 passed, 0 failed.
- Non-overlapping package regression: 590 total, 584 passed, 6 skipped, 0 failed.
- `npm run build`: passed.
- `npm run lint`: passed for 596 tracked files.
- `git diff --check`: passed.

The long-running `broker.test.js` and `persistence.test.js` suites were already
active in another process and were intentionally not restarted or terminated.

## Remaining limits

This is local cross-ledger consistency evidence only. It does not prove
physical crash recovery, old-worker process ownership, production Keychain
rotation, remount durability, installed operator recovery, or independent
P0/P1 security review.
