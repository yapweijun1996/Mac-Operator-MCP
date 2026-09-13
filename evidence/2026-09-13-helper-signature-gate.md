# Privileged Helper Developer ID Signature Gate Evidence

Date: 2026-09-13
Source commit: `46a3167`
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0

## Implemented boundary

The root-domain privileged-helper package plan now requires all three exact
signature identity fields: helper identifier
`com.mac-operator.privileged-helper`, a ten-character uppercase Developer ID
TeamIdentifier, and a bounded lowercase CDHash. Missing TeamIdentifier or
CDHash is rejected with stable `INVALID_SIGNATURE` before any filesystem,
launchd, or command action. The final codesign readback must return the exact
same values and still passes the fixed `/usr/bin/codesign --verify --strict
--deep` command boundary.

This gate is intentionally stricter than the generic unprivileged service
signature shape. It prevents an ad-hoc or partially bound artifact from being
treated as an installable privileged helper. It does not claim that the
artifact is currently Developer ID signed or notarized; no root-domain install
or launchd mutation was attempted.

## Verification

- Focused helper package suite: 12 passed, 0 failed.
- Full default suite: 398 tests, 395 passed, 0 failed, 3 opt-in sandbox tests skipped.
- `npm run typecheck`: passed.
- Negative coverage: missing TeamIdentifier/CDHash fails with `INVALID_SIGNATURE`.
- Real temporary ad-hoc codesign smoke remains an observation-only parser test;
  it is not accepted as production helper provenance.

## Source hashes

- `360700b522bf2a81ab61c42b62fdb4d2eec141f0476c2a4951f8d8e61bfccddb` `packages/broker/src/privileged-helper-package.ts`
- `285cc7abace987bd9ac209f6b7f6b89a41926877322d31d5bf80ebdc0ff7cd83` `packages/broker/src/privileged-helper-package.test.ts`
