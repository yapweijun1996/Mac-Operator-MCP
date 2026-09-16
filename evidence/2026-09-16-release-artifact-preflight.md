# macOS release artifact preflight evidence

Date: 2026-09-16
Source revision: `9aca625`
Host: physical Darwin arm64 Mac mini; macOS 26.2

## Change

The Broker now exposes a read-only `runMacOsReleasePreflight` boundary and a
manifest-only CLI (`npm run build && npm run verify:release:macos --
--manifest <canonical-path>`). An owner-only manifest binds one canonical
artifact path, deterministic tree SHA-256, byte count, owner UID, and exact
Developer ID identifier, Team ID, and CDHash. The artifact walker is bounded
to 16,384 entries and 512 MiB, rejects symlinks/special files, group/other
writes, owner changes, and identity swaps, and hashes regular files through an
`O_NOFOLLOW` descriptor with pre/post `fstat` checks. The gate then runs only
the fixed `codesign --verify/--verbose` and `spctl --assess` commands already
used by the package plans, returning bounded signature/notarization evidence
without raw output or host mutation. Ad-hoc signatures and Apple System
Gatekeeper provenance are not release eligible.

## Verification

- `npm run typecheck --silent` passed.
- `npm run build --silent` passed.
- `node --test packages/broker/dist/macos-release-preflight.test.js` passed
  4/4, including digest/identity binding, ad-hoc rejection, digest mismatch,
  symlink denial, accessor/inherited-field denial, and a real Darwin
  `/usr/bin/codesign` ad-hoc probe.
- `npm test --silent` passed 876/876 with 14 explicit skips (890 total).
- `npm run lint --silent` passed.
- No production Developer ID artifact was available on the host; therefore a
  successful release preflight and production enablement remain intentionally
  unproven.

## Evidence boundary

This closes the implementation and local test boundary for release manifest
and provenance admission. It does not establish certificate/key custody,
notarization service submission, immutable distribution, persistent
LaunchAgent/helper installation, or enabled capabilities.

## Rollback

Revert commits `9541b6b`, `5d4963c`, `fc2908b`, and `9aca625` to remove the release
preflight module, CLI, and documentation wiring. The change performs no
host-side mutation.
