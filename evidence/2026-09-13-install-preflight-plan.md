# macOS install preflight plan evidence

## Scope

- Source revisions: `5804f04` (`feat: add macOS install preflight plan`), `8fe6663` (`feat: verify macOS install filesystem preflight`), `b4945c3` (`feat: atomically apply macOS plist plans`), `662801b` (`feat: add guarded macOS plist uninstall`)
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
- `applyMacOsPlistPlan` uses a separate native `unlinkat` path for exact plist/backup uninstall, with root/regular-file/device/inode checks, parent `fsync`, absence readback, and plist restoration if backup removal fails. It exposes no recursive deletion and never invokes launchd.

## Boundary tests

The seven focused tests in `packages/broker/src/macos-install-plan.test.ts` cover:

- fixed command argv, empty environments, budgets, and rollback/uninstall actions;
- root domain, LaunchDaemon, package escape, script-like argv, and traversal denial;
- signature, launchd, Broker metadata, native transport, and capability readback matching;
- exact previous-revision preconditions for upgrade and uninstall;
- malformed nested readback returning the stable `INVALID_READBACK` error class.
- real temporary-directory filesystem preflight, writable-path denial, symlink denial, and stable device/inode readback.
- temporary-root install, upgrade backup, rollback restoration, exact-target uninstall, and native atomic-write/unlink readback.

## Verification

- `npm test`: 232 passed, 0 failed.
- `npm run typecheck`: passed.
- `npm run verify:contracts`: `Validated 44 unique tool contracts.`
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.
- `plutil -lint packaging/macos/com.mac-operator.broker.plist.in`: `OK`.

## Artifact hashes

```text
packages/broker/src/macos-install-plan.ts       9f9c56495d620568e951e0416b56ee128a59d933015ef2a1baa2c4b7a8d472bc
packages/broker/src/macos-install-plan.test.ts  c5aad21ba54d896dbb825ee91b028b757309e6fea2b33b8b6bceeda0b39b6f3b
packages/broker/src/filesystem-inspector.ts     30faf1db6dfa2ae1b0c2d617fc6e0e529d19a1a3ba51cbfb8b807609cf66edab
packages/broker/native/peer_credentials.cc      2b44d259a8ee674548e054b3767d8048c0ba18602833efc3a93e9e9036aebbbf
packaging/macos/README.md                       409c688a97904f7b57a11acd391ef947a70bbff30fb8e0b60629ee9a8a01eca6
DEPLOYMENT.md                                   6e0eb08e4a633001ef654fe57967df7387f70a9f1eaa9125f77bc7a3049c642a
ROLLBACK.md                                     ef6ff19354ec39ab49886f69da42b394dacd7fde3ef4cce0355c1cf9cf7a0382
```

## Not proven

This evidence is source-level plus read-only temporary-directory preflight. No `/usr/bin/codesign` verification was run against a signed artifact; no plist was written; no `launchctl bootstrap`, `bootout`, or `print` was run; no descriptor-relative atomic-write installer exists; and no live upgrade, rollback, uninstall, notarization, Keychain distribution, or installed-service readback is claimed.
