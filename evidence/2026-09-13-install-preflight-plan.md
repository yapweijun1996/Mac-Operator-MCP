# macOS install preflight plan evidence

## Scope

- Source revision: `5804f04` (`feat: add macOS install preflight plan`)
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

## Boundary tests

The five focused tests in `packages/broker/src/macos-install-plan.test.ts` cover:

- fixed command argv, empty environments, budgets, and rollback/uninstall actions;
- root domain, LaunchDaemon, package escape, script-like argv, and traversal denial;
- signature, launchd, Broker metadata, native transport, and capability readback matching;
- exact previous-revision preconditions for upgrade and uninstall;
- malformed nested readback returning the stable `INVALID_READBACK` error class.

## Verification

- `npm test`: 230 passed, 0 failed.
- `npm run typecheck`: passed.
- `npm run verify:contracts`: `Validated 44 unique tool contracts.`
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.
- `plutil -lint packaging/macos/com.mac-operator.broker.plist.in`: `OK`.

## Artifact hashes

```text
packages/broker/src/macos-install-plan.ts       47c48963cb1b3311d19f0d40d3546cb72ffac89ba425fc9195e5d5766f7568bd
packages/broker/src/macos-install-plan.test.ts  de986dab6944abb66cd95d8744664834b44fa2f1c15a2d59fd96569bfc1a12c8
packaging/macos/README.md                       31072cf5ad75db30414afc3ae078cfd27dbc545ad666016e5c734148a03239f0
DEPLOYMENT.md                                   10bd5bafc4296ec7abb951ebf9a9270837a85bf20c6050948ca209dd2bb7b21b
ROLLBACK.md                                     b16cb988ead690bdb3558f6fc81e6594790d4e4482efe4bbb20fb6cf518abcff
```

## Not proven

This evidence is source-level only. No `/usr/bin/codesign` verification was run against a signed artifact; no plist was written; no `launchctl bootstrap`, `bootout`, or `print` was run; no owner/mode/symlink/atomic-write installer exists; and no live upgrade, rollback, uninstall, notarization, Keychain distribution, or installed-service readback is claimed.
