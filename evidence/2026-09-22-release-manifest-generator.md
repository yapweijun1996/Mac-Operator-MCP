# macOS release manifest generator

Status: `PASS` for the fail-closed manifest handoff boundary; production
release remains blocked until the host provides a valid Developer ID and
notarized artifact.

The new `create:release:manifest` command derives the exact artifact digest and
byte count from the canonical artifact, runs the complete read-only
Developer ID and Gatekeeper preflight, and writes an owner-only manifest only
after that preflight succeeds. The output is created with exclusive creation,
cannot be placed inside the artifact tree, and is never overwritten.

Verification:

- `node --check scripts/create-macos-release-manifest.mjs` passed.
- The generic release verifier now requires an owner-only manifest (`0o600`
  class), canonical artifact identity, a current owner UID, bounded digest and
  byte fields, and string-valued signature identity fields before importing the
  release preflight. Its focused negative suite passes 3/3, including symlink,
  weak-permission, and writable-parent manifests. The root-helper and App
  Sandbox helper verifiers and manifest generator use the same protected-parent
  validator. All manifest reads use one `O_NOFOLLOW` descriptor with bounded
  reads and post-read inode/metadata stability checks.
- `npm run build`, `npm run lint`, and `npm run typecheck` passed.
- The latest full regression passed 1,151 tests: 1,136 passed, 15 skipped,
  and 0 failed.
- Running the command against the current ad-hoc root-helper artifact exited
  non-zero with `SIGNATURE_MISMATCH: ad-hoc code signatures are not release
  eligible`.
- The failed preflight did not create the requested manifest.
- No launchd, Keychain, OAuth, policy, or live R1 state changed.

The command is ready for a future Developer ID artifact:

```text
npm run create:release:manifest -- --artifact /absolute/artifact --output /absolute/manifest.json --identifier com.example.product --team-identifier ABCDE12345 --cdhash <codesign-cdhash>
```
