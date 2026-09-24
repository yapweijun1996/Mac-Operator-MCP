# Production acceptance record boundary

Date: 2026-09-22

The completion audit now supports an optional owner-only machine-readable
record at:

```text
evidence/production-acceptance.json
```

The record is intentionally absent until the real production acceptance is
complete. It must use schema `mac-operator-production-acceptance-v1`, be a
strict UTF-8 regular file owned by the current owner with mode `0600` or
stricter, and contain no secrets. The verifier binds it to the current
Darwin/architecture/owner identity, rejects records older than seven days,
and requires every referenced evidence path to be a regular non-symlink file
inside the repository.

The required non-secret assertions are:

- verified Keychain ACL readback and protected helper material;
- verified root-helper and Edge/Broker rollback with final readback;
- an independent security review with status `passed` and zero P0/P1 findings;
- at least four repository evidence references and a non-secret source revision.

The `securityReview.reviewRef` must itself be one of the regular files listed in
`evidenceRefs`; an unlisted or external review reference is rejected. Every
parent directory in the acceptance-record and evidence-reference paths is also
checked with `lstat`; symlinked or group/other-writable parent traversal is
rejected. The shared validator permits only the fixed macOS `/var`, `/tmp`, and
`/etc` system aliases. The final record read is bound to one `O_NOFOLLOW`
descriptor, bounded to 128 KiB, and checked for stable inode/size/time metadata
after reading.

This record does not replace dynamic host checks. `npm run verify:completion`
still requires current Developer ID/Gatekeeper, Accessibility, and persistent
LaunchAgent/LaunchDaemon readback. The record is only accepted after those
checks and its own structural/evidence validation pass. No record was created
for the current host because those external gates remain incomplete.

## Verification

- `node --test scripts/production-acceptance-record.test.mjs` passes 6/6,
  including writable-parent rejection.
- The completion audit reads the record through the descriptor-backed protected
  reader and still reports an absent record as `partial`/fail-closed.
- An absent record leaves the completion audit at `partial`, `failClosed=true`,
  with the reason `owner-only production acceptance record is absent`.
- The verifier rejects host drift, stale timestamps, symlinked evidence, weak
  file ownership/mode, unknown fields, and non-zero P0/P1 findings.
