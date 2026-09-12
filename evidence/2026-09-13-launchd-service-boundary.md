# macOS launchd service boundary evidence

- Source commit: `fde73417f310cac76293f42a19a3e092fdcad3b4`
- Source worktree: clean at source verification; documentation follow-up is the only subsequent change.
- Contract version: `0.1`
- Policy fixture version: `policy-0.1`
- Target host: Mac mini (Apple M4), macOS `26.2` (`25C56`), `arm64`
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Timestamp: `2026-09-13` (Asia/Kuala_Lumpur)
- Verification: `npm test` — 225 passing, 0 failing; `npm run typecheck` — pass; `npm run verify:contracts` — 44 unique contracts; `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.

## Covered behavior

- `renderLaunchdPlist` validates a fixed service-label namespace, canonical absolute program/cwd/log paths, bounded argv count/bytes, first-argv program identity, XML escaping, and bounded restart throttling.
- The renderer emits only separate `ProgramArguments`, no shell string, no environment variables, no `UserName`, and no privileged launchd keys; the readback explicitly reports unprivileged/no-shell/no-environment properties.
- `BrokerServiceEntrypoint` delegates start/stop ordering to `LocalBrokerRuntime`, fails closed on startup or shutdown errors, handles `SIGINT`/`SIGTERM`, and returns bounded component/source/contract/policy/runtime/capability readback.
- `packaging/macos/com.mac-operator.broker.plist.in` is a reviewable LaunchAgent template with no secrets or authority-bearing environment values.

## Artifact hashes

- `packages/broker/src/launchd.ts`: `eba5bfe30b405f03bc878b06f0a74f48bdf755450e901a3ee1a88b2bfb6e6548`
- `packages/broker/src/launchd.test.ts`: `a9db5bed82ef19ce7f003d0410573142b5feeefc711b1303bdcaf946e8216cd4`
- `packages/broker/src/service-entrypoint.ts`: `5ca64d83397ba4f56ca5ab7eeb1643f4a6abbfa01a6829fa2d5f5a53659acf43`
- `packages/broker/src/service-entrypoint.test.ts`: `6fdcf34eaea786666db7f9c0e4cd0b0f19b3b80fda5cb6076601cad799ea95fa`
- `packaging/macos/com.mac-operator.broker.plist.in`: `f15c1cf1ec4fb489cabe1b0776c5eb33f936e95a88d98022195d26bd6665e258`
- `packaging/macos/README.md`: `d919334544764eeb273033ec61cc9bee09b24947524d8d9bd88bfb2a2ab9aade`

This evidence proves the source-level launchd boundary and bounded readback only. No service was installed or loaded, no code-signature/notarization check was performed, and no `launchctl bootstrap`, upgrade, uninstall, rollback, or live launchd readback is claimed.
