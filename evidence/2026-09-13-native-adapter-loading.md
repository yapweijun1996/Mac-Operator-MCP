# Native adapter loading boundary evidence

- Source commit: `ebe5a62` (`fix: protect native adapter loading`)
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

## Verification

- `npm run build` passed, including the warning/error-free native compilation.
- Native peer credential and native IPC focused tests pass 6/6.
- `npm test` passes 294/296 tests, with two opt-in real-sandbox tests skipped.
- `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev
  --audit-level=high`, and `git diff --check` pass.

## Artifact hashes

- `packages/broker/src/peer-credentials.ts`:
  `5191314e336c8a99f995c15526fc90a42853a05d1c6eeeddb181bab77d5c279a`
- `packages/broker/native/peer_credentials.cc`:
  `25e9a4035a7332f88104322dcec2b9a36cc10991fda8836d07eb55e61011d16b`
- `packages/broker/src/peer-credentials.test.ts`:
  `e7c7b710cede3400cdb300e492a3816d6a6bc7d11541f96eca85851234d1df4d`

This protects the local load boundary against accidental or simple package
replacement and gives a stable export contract. It does not prove native code
signing/notarization, Developer ID identity, package provenance, runtime ABI
pinning across Node versions, Keychain-backed key distribution, or installed
launchd startup; those remain open under MOP-081 and VT-AUTH-01/VT-COMP-01.
