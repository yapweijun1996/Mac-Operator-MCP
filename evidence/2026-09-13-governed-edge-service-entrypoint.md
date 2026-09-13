# Governed HTTPS Edge service entrypoint evidence

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Source commit: `0e8612d673b435ee65978f585f939a9a866fb931` (`feat: add governed HTTPS Edge service startup`)
- Documentation commit: recorded separately after this evidence update
- Working tree at source verification: clean before documentation edits
- Platform: macOS host, Node.js 24+, Apple Silicon development machine
- Contract version: `0.1`
- Policy-version binding: startup requires a configured `policy-*` or semver value and signs it into every Broker request

## Boundary implemented

`packages/edge/src/service-main.ts` is a fixed process entrypoint. It loads
only the owner-only `edge-service.json` adjacent to the packaged module; MCP
arguments and ambient environment variables cannot select the Broker socket,
TLS files, authentication key, policy version, JWKS source, or capability.

`service-startup.ts` validates a strict schema, canonical absolute paths,
distinct package/data/runtime roots, owner-only configuration, root-contained
targets, non-symlink parents, and bounded HTTPS/IPC/rate-limit settings. It
loads the contract registry, protected TLS material, and digest-bound
Edge-to-Broker HMAC key, then constructs the existing HTTPS MCP Edge, JWT
verifier, signed IPC request factory, and response-verifying Broker gateway.
The verifier is configured with an explicit HTTPS JWKS URI; no bearer or key
bytes are accepted from startup arguments. The listener readback must match
the configured host/port before the service reaches `running`. Shutdown closes
MCP/HTTPS state and wipes the HMAC, certificate, and private-key buffers.

## Verification

- Focused startup tests: `node --test packages/edge/dist/service-startup.test.js` — 3/3 passed.
- Default full suite: `npm test` — 361 tests, 359 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 361/361 passed, 0 skipped.
- Type/build: `npm run typecheck -- --pretty false` and `npm run build` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary negatives: unknown config fields, non-canonical/traversal paths, root escape, non-HTTPS OAuth/JWKS URLs, weak/symlinked config, protected TLS/key loading, and listener readback mismatch paths are covered by tests.
- No LaunchAgent/LaunchDaemon was installed or changed, no public listener was exposed, and no production OAuth credential or Keychain item was used.

## Source artifact hashes

```text
0244f5131861f762cbe3ee8560c1255bfd4cf3cb6cb4050d08589b9c8fd52a81  packages/edge/src/service-startup.ts
c9484acbf818e4e723424ea9bf22d3bec331cce6a4fe1afc642541837e5d3947  packages/edge/src/service-startup.test.ts
021c2045fcf0022623535c955d78803fe044877c821dea375f87152941f3d10a  packages/edge/src/service-main.ts
a805773e08365113ecc80358eb1a03577fca2012b58d2d17ddbfd643a08c3ef3  packages/edge/src/request-factory.ts
159ec58f0c1292feb1028d05b9fbc023c4e32a2a0a05a97191d163f594b740cc  packages/edge/src/index.ts
```

## Remaining limits

This is local package/process evidence, not a release gate. Live LaunchAgent
bootstrap, Developer ID signing/notarization, Keychain ACLs, external OAuth
issuer issuance/rotation, remote deployment, multi-instance rate limits, and
operator rollback/readback remain unverified. The Edge does not grant Broker
authority; the Broker policy and active key/policy state remain final.
