# macOS install preflight plan evidence

## Scope

- Source revisions: `5804f04` (`feat: add macOS install preflight plan`), `8fe6663` (`feat: verify macOS install filesystem preflight`)
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

## Boundary tests

The six focused tests in `packages/broker/src/macos-install-plan.test.ts` cover:

- fixed command argv, empty environments, budgets, and rollback/uninstall actions;
- root domain, LaunchDaemon, package escape, script-like argv, and traversal denial;
- signature, launchd, Broker metadata, native transport, and capability readback matching;
- exact previous-revision preconditions for upgrade and uninstall;
- malformed nested readback returning the stable `INVALID_READBACK` error class.
- real temporary-directory filesystem preflight, writable-path denial, symlink denial, and stable device/inode readback.

## Verification

- `npm test`: 231 passed, 0 failed.
- `npm run typecheck`: passed.
- `npm run verify:contracts`: `Validated 44 unique tool contracts.`
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.
- `plutil -lint packaging/macos/com.mac-operator.broker.plist.in`: `OK`.

## Artifact hashes

```text
packages/broker/src/macos-install-plan.ts       7094ac91a6a93cf7850e2c24f8de962582742b54435f510c8989bd8fe5ea8546
packages/broker/src/macos-install-plan.test.ts  a1c337073d7ef7d8895e699bc46d5eaa61c57d54ff8a05939e95d0aeb38b6af3
packaging/macos/README.md                       7ca80b8af2a3c8d3697fec442c35fd45822ef400fa41f4eff054afbb81289bf1
DEPLOYMENT.md                                   53c381dd022195af66c6a39c7e2b26e553c45fd7d6a4cbf0651b751a8d4dde43
ROLLBACK.md                                     25702346d33d4f7da4b14ba0edb95daca12f5394b08872e5b3ca0db552a096a7
```

## Not proven

This evidence is source-level plus read-only temporary-directory preflight. No `/usr/bin/codesign` verification was run against a signed artifact; no plist was written; no `launchctl bootstrap`, `bootout`, or `print` was run; no descriptor-relative atomic-write installer exists; and no live upgrade, rollback, uninstall, notarization, Keychain distribution, or installed-service readback is claimed.
