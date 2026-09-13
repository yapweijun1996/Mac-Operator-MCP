# macOS code-signature verification evidence

Status: PARTIAL packaging host evidence for MOP-072 / VT-OPS-01

## Scope

The test creates a synthetic app bundle under a temporary directory, signs it ad hoc (`codesign --sign - --timestamp=none`), and invokes the exact fixed verification command emitted by `buildMacOsInstallPlan`: `/usr/bin/codesign --verify --strict --deep <artifact>`. No Developer ID certificate, private key, Keychain item, launchd service, or production path is touched.

## Evidence

- Host: Darwin arm64, macOS 26.2 build `25C56`, Node `v25.5.0`.
- Test: `signature verification plan accepts a real temporary ad-hoc signed artifact`.
- Source: `packages/broker/src/macos-install-plan.test.ts`.
- Source SHA-256: `426a1cc1e37dc15ea5d7941b2d8c9ec287e878a24fc7b8122832d52737f758ed`.
- `npm test` — 235 passed, 0 failed.
- `npm run typecheck` — pass.
- `npm run verify:contracts` — 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Observed ad-hoc artifact identity: `com.mac-operator.broker`; `codesign --verify --strict --deep` exited successfully.

## Limits

Ad-hoc signing proves only that the fixed verification command works on this host. It does not prove Developer ID signing, notarization, certificate/key custody, package reproducibility, native module identity, launchd bootstrap/readback, or release readiness. The installer remains non-automated and no production capability is enabled by this evidence.
