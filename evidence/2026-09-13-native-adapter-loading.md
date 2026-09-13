# Native adapter loading boundary evidence

- Source commit: `22881f9` (`fix: route native consumers through protected loader`)
- Host: Mac mini M4, macOS `26.2` (`25C56`), arm64
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Scope: unprivileged Broker native peer adapter loading; no privileged action

## Boundary exercised

`loadNativePeerAdapter` resolves only the package-owned
`peer_credentials.node` path. Before loading, it requires a canonical absolute
path whose realpath is identical to the requested path, a bounded regular file,
no symlink, no group/other write permission, and current-user ownership. The
module is stat-checked again after `require` for stable device, inode, and size
identity, and the required peer IPC exports are checked before the adapter is
returned. Any failure maps to the same unavailable error and callers fail
closed.

All production native consumers (filesystem, process, network, and process-tree
inspection) now use this loader; no production TypeScript module directly
requires the `.node` artifact. Test-only direct loads remain for fault-injection
and native syscall fixtures.

## Verification

- `npm run build` passed, including the warning/error-free native compilation.
- Native peer credential and native IPC focused tests pass 7/7, including symlink,
  writable-artifact, and non-canonical-path rejection.
- `npm test` passes 295/297 tests, with two opt-in real-sandbox tests skipped.
- `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev
  --audit-level=high`, and `git diff --check` pass.

## Artifact hashes

- `packages/broker/src/peer-credentials.ts`:
  `fe4904f6062696ed0b3c04762d8a7a061677371da84de8e21512ff4e1ab9d94a`
- `packages/broker/native/peer_credentials.cc`:
  `25e9a4035a7332f88104322dcec2b9a36cc10991fda8836d07eb55e61011d16b`
- `packages/broker/src/peer-credentials.test.ts`:
  `16a074851be4b9cca9204135b39ef057ff96c4c97029ecfa8c7fc0ea61e2d8fe`

This protects the local load boundary against accidental or simple package
replacement and prevents consumer-specific loading paths from bypassing it. It
does not prove native code
signing/notarization, Developer ID identity, package provenance, runtime ABI
pinning across Node versions, Keychain-backed key distribution, or installed
launchd startup; those remain open under MOP-081 and VT-AUTH-01/VT-COMP-01.
