# macOS install preflight plan evidence

## Scope

- Source revisions: `5804f04` (`feat: add macOS install preflight plan`), `8fe6663` (`feat: verify macOS install filesystem preflight`), `b4945c3` (`feat: atomically apply macOS plist plans`)
- Host: Mac mini M4, macOS 26.2 (`25C56`), `arm64`
- Node: `v25.5.0`
- npm: `11.8.0`
- No system service, plist, signature, credential, or remote state was changed.

## Implemented boundary

`packages/broker/src/macos-install-plan.ts` now provides a declarative, non-executing packaging boundary:

- requires an explicit non-root UID and derives only `gui/<uid>`;
- requires the exact per-user `~/Library/LaunchAgents/<label>.plist` path;
- rejects root/LaunchDaemon targets, non-canonical paths, package escapes, and stdout/stderr outside one package-owned log directory;
- requires exactly one package-owned `.js`, `.mjs`, or `.cjs` entrypoint after the program path, preventing shell-style `-c`/`-e` argv;
- creates fixed `/usr/bin/codesign --verify --strict --deep <artifact>` and `/bin/launchctl bootstrap|bootout ...` argv with `/` cwd, an empty environment, a 5-second timeout, and a 128 KiB output cap;
- binds upgrade, rollback, and uninstall to an exact previous source revision; install requires an absent existing service;
- exposes explicit write/bootstrap, bootout/restore/bootstrap, and bootout/remove actions without executing them;
- validates exact launchd, Broker native-runtime, source/contract/policy/capability, and code-signature readback before readiness.
- `inspectMacOsInstallFilesystem` performs read-only double-`lstat` checks over the user-home parent chain, package root, working directory, executable, entrypoint, signed artifact, log directory, and optional plist; it rejects symlinks, foreign owners, group/other write bits, unexpected types, and device/inode changes.
- `applyMacOsPlistPlan` reuses the native descriptor-relative atomic writer for install, upgrade, and rollback; it binds device/inode preconditions, writes same-directory temporary files with `fsync`/`renameat`, verifies reopened content/hash identity, and restores the previous bytes if an upgrade write fails. It intentionally does not delete uninstall targets or invoke launchd.

## Boundary tests

The seven focused tests in `packages/broker/src/macos-install-plan.test.ts` cover:

- fixed command argv, empty environments, budgets, and rollback/uninstall actions;
- root domain, LaunchDaemon, package escape, script-like argv, and traversal denial;
- signature, launchd, Broker metadata, native transport, and capability readback matching;
- exact previous-revision preconditions for upgrade and uninstall;
- malformed nested readback returning the stable `INVALID_READBACK` error class.
- real temporary-directory filesystem preflight, writable-path denial, symlink denial, and stable device/inode readback.
- temporary-root install, upgrade backup, rollback restoration, and native atomic-write readback.

## Verification

- `npm test`: 232 passed, 0 failed.
- `npm run typecheck`: passed.
- `npm run verify:contracts`: `Validated 44 unique tool contracts.`
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.
- `plutil -lint packaging/macos/com.mac-operator.broker.plist.in`: `OK`.

## Artifact hashes

```text
packages/broker/src/macos-install-plan.ts       8a1ea68d3b3eeaca73702d29b02584324c25e8e88fc5ff8bae5a7fe5d0128a3d
packages/broker/src/macos-install-plan.test.ts  8d0de52973346f1a028aa8e78dcbe7425988d198323691992da1832e02be5e26
packages/broker/src/filesystem-inspector.ts     bcd476737b2b2ab711520392fec685baa9f9a21d94d4b7fa23347245139c47a9
packaging/macos/README.md                       0459c6c9b15ecc4ebc22f9b3aabf12d249be64f3d30245b0271f5389e3bc439b
DEPLOYMENT.md                                   2b5e275a77a35cf45fcbe781ca72d2dd9579a47bf90d191f6174581d2c8e0ced
ROLLBACK.md                                     08c07d3f074ef99a68ba80c08556393a92590157c8f2afd16365e40ba2ff7abd
```

## Not proven

This evidence is source-level plus read-only temporary-directory preflight. No `/usr/bin/codesign` verification was run against a signed artifact; no plist was written; no `launchctl bootstrap`, `bootout`, or `print` was run; no descriptor-relative atomic-write installer exists; and no live upgrade, rollback, uninstall, notarization, Keychain distribution, or installed-service readback is claimed.
