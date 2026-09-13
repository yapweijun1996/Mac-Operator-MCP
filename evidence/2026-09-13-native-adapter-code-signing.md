# Native adapter build-time code-signature evidence

Status: PARTIAL packaging/build-integrity evidence for MOP-072 and MOP-081 / VT-OPS-01

## Scope

The macOS native adapter build now invokes the fixed `/usr/bin/codesign
--verify --strict` command immediately after compiling
`packages/broker/dist/peer_credentials.node`. A build therefore fails closed
instead of leaving an artifact that macOS cannot verify. The check is performed
on the artifact emitted by that build and does not execute the adapter.

This is a build-integrity check, not a provenance boundary. It does not select
a signing identity, access a Keychain, establish Developer ID trust, verify a
notarization ticket, or prove that a future installed artifact came from this
source tree. The JavaScript loader still protects the pre-load path with
canonical path, ownership, mode, identity, digest, export, and N-API checks.

## Host evidence

- Host: Darwin arm64, macOS `26.2` build `25C56`.
- Runtime: Node `v25.5.0`, npm `11.8.0`.
- Source commit: `18a418a` (`build: verify native adapter code signature`).
- Captured: `2026-09-13`; source working tree was clean at test capture.
- Build: `npm run build` passed, including the strict native signature check.
- Direct readback: `/usr/bin/codesign --verify --strict packages/broker/dist/peer_credentials.node` passed.
- Observed artifact: `Identifier=peer_credentials.node`,
  `CandidateCDHashFull=52f0e1c06ec2fc395763bb3d5185942652318f32f341eb37a1d7121ffca26cec`,
  `Signature=adhoc`, `TeamIdentifier=not set`.
- Negative readback: removing the temporary copy's signature caused strict
  verification to reject it with `code object is not signed at all`.

## Regression verification

- `npm test` — 296 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- `npm run typecheck -- --pretty false` — pass.
- `npm run verify:contracts` — 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- `git diff --check` — pass.
- Production source boundary check — no direct `.node` requires outside test
  fixtures.

## Source identity

- `packages/broker/scripts/build-peer-credentials.sh` SHA-256:
  `e589b1aa8418943f990d36268eeadedc962076ba3c555f4f4dd01328d62a76eb`.

## Limits and next gate

This evidence closes only the build-time verification step. Developer ID
identity, notarization, native-module identity binding at installation, live
launchd startup/readback, protected signing-key distribution, and production
enablement remain open. A release package must add an approved signing
identity/provenance policy and real-host readback before any capability is
enabled.
