# Privileged Helper App Builder

Date: 2026-09-23

Status: PASS for the local, ad-hoc packaging and runtime-import probe only.

## Implemented

- Added a production-shaped LaunchDaemon SEA entrypoint and strict runtime
  descriptor parser. Descriptor bytes reject malformed UTF-8 and duplicate
  JSON keys before capability/path validation.
- Added a macOS arm64 app-bundle builder pinned to the official Node.js
  v24.21.0 Darwin arm64 archive SHA-256
  `bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057` and
  Node.js Foundation Team ID `HX7739G8FX`.
- The builder compiles `peer_credentials.node` against headers extracted from
  that checksum-verified archive and loads it under that exact Node runtime to
  verify ABI and process-identity readback. It stages the compiled
  Broker/contracts runtime and production dependency graph, embeds the
  validated descriptor, signs and verifies the app and native addon, and never
  invokes install or launchd commands.
- Production signing requires a valid Developer ID Application identity and
  retains library validation. The only supplied entitlements are V8 JIT and
  unsigned executable memory. Ad-hoc builds are limited to descriptors with no
  enabled privileged capabilities.
- Broker PID/start-time loss closes the helper listener and then notifies the
  outer process so launchd can restart it and capture a fresh identity.

## Verification

- `npm run typecheck`: passed.
- `node --test packages/broker/dist/privileged-helper-main.test.js`: 6/6
  passed, including duplicate-key and invalid UTF-8 descriptor rejection.
- `npm run lint`: passed for tracked files.
- `node scripts/probe-privileged-helper-app.mjs
  /absolute/path/node-v24.21.0-darwin-arm64.tar.gz`: passed on macOS arm64.
  It verified the official archive pin, Node binary signature, matching-header
  native build/load and identity readback, ad-hoc app signature, full packaged
  ESM import, and rejection of ad-hoc capability enablement. Its temporary
  bundle was removed.
- The existing `packages/broker/dist/peer_credentials.node` was not replaced;
  its SHA-256 remains
  `6737113a80155f2e1957ae7213a72d5b273353fdce01b3928b5610720bd6f51a`.

## Limits

- No Developer ID identity was available/used for this probe; production
  signing and the minimal-entitlement runtime were not verified.
- Notarization, Gatekeeper acceptance, production helper-key provisioning,
  root LaunchDaemon installation/start/readback, reboot persistence, and
  enabled service/package/power capabilities remain open.
- No root service or host service state was changed. Overall project progress
  remains 92%; the completion audit remains fail-closed pending host gates.
