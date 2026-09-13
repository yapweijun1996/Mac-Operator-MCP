# Native adapter loading boundary evidence

- Source commit: `f12ab8a` (`fix: enforce native N-API compatibility`)
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

The loader also remembers the first successfully loaded artifact and compares
device, inode, size, and SHA-256 on every later load. A changed path therefore
cannot cause Node's cached module to be reused for a different on-disk artifact.

The loader rejects incomplete native modules at the same boundary: all 17
production exports used by IPC, filesystem, process, network, and process-tree
adapters must be functions before the module is returned.

The native module also exposes its compiled N-API version. Loading requires a
supported version (8 or newer) no greater than the active Node runtime's N-API
version, and the focused host test reads this value back from the built addon.

All production native consumers (filesystem, process, network, and process-tree
inspection) now use this loader; no production TypeScript module directly
requires the `.node` artifact. Test-only direct loads remain for fault-injection
and native syscall fixtures.

## Verification

- `npm run build` passed, including the warning/error-free native compilation.
- Native peer credential and native IPC focused tests pass 8/8, including symlink,
  writable-artifact, and non-canonical-path rejection.
- `npm test` passes 296/298 tests, with two opt-in real-sandbox tests skipped.
- `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev
  --audit-level=high`, and `git diff --check` pass.

## Artifact hashes

- `packages/broker/src/peer-credentials.ts`:
  `fcae02c3504c0dc07d0c43a8c36b47470a6dbba84729dd275affc41c414860a8`
- `packages/broker/native/peer_credentials.cc`:
  `a354b468c32213f678f84351931bb45fe95b6cc5443281e3f80c2aca2e633134`
- `packages/broker/src/peer-credentials.test.ts`:
  `b7e6db8335dffbb4f332904762aa6b68e63542e6ec3d6a96ebfa4ab6d6d8362c`

This protects the local load boundary against accidental or simple package
replacement, cached-module target swaps, and consumer-specific loading paths
that would otherwise bypass it. It does not prove native code
signing/notarization, Developer ID identity, package provenance, runtime ABI
pinning across Node versions, Keychain-backed key distribution, or installed
launchd startup; those remain open under MOP-081 and VT-AUTH-01/VT-COMP-01.
