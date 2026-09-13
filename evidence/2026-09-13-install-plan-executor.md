# macOS install-plan executor evidence

Status: PARTIAL host-side installation orchestration for MOP-072 / VT-OPS-01

## Boundary exercised

Commit `c59983e` adds the host-only `executeMacOsInstallPlan` boundary. It
requires an exact operation confirmation and an authoritative existing-service
readback before any mutation. It runs only fixed `/usr/bin/codesign` and
`/bin/launchctl` command specifications with empty environments and bounded
ProcessSupervisor limits, applies the descriptor-backed atomic plist plan,
bootstraps the exact per-user `gui/<uid>` service, and requires final
`launchd`/Broker/signature readback before returning success.

The executor never treats a successful `launchctl` command as readiness. A
readback mismatch boots out the exact service and leaves the plist/backup for
an explicit rollback plan; it does not overwrite a target whose identity may
have changed. If a pre-mutation stop fails, it attempts to restore the prior
service. MCP handlers do not call this boundary, and the confirmation value is
host-side intent rather than a capability or permission grant.

## Host evidence

- Host: Darwin arm64, macOS `26.2` build `25C56`.
- Runtime: Node `v25.5.0`, npm `11.8.0`.
- Source commit: `c59983e` (`security: execute launchd install plans with final readback`).
- Focused install-plan tests: 10 passed, 0 failed.
- Full regression: 304 passed, 0 failed, 2 opt-in real-sandbox tests skipped
  (306 total).
- `MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js`:
  7 passed, 0 failed.
- Typecheck, contract verification (44 unique contracts), high-severity npm
  audit, and `git diff --check` passed.
- The executor tests use a bounded fake command runner and temporary owner-only
  roots; they verify no command is issued without matching confirmation,
  success requires the full readback, and a mismatched readback boots out the
  service while preserving the upgrade backup.

## Source identity

- `packages/broker/src/macos-install-plan.ts` SHA-256:
  `e80439dd74404b44efbb28c9de767e662a173d0724c9f8c6e1e66808623b8571`
- `packages/broker/src/macos-install-plan.test.ts` SHA-256:
  `5978a886cb1e70a21ba3e4a46386a9f8899b0f40af4f3fdd10d75fc84b954603`

## Limits and next gate

This is executable command orchestration and temporary-root evidence only. No
live LaunchAgent was installed, bootstrapped, upgraded, rolled back, or
uninstalled on the host. Developer ID signing/notarization, protected signing
key distribution, live launchd readback, an installed Edge-to-Broker identity
handshake, Keychain distribution, and production capability enablement remain
open.

## Fresh current-revision readback

The focused suite was rerun from clean source revision `c1defff` after the
capability compatibility changes. Result: 10 passed, 0 failed, 0 skipped.
The source hashes remain unchanged from the original boundary evidence:

- `packages/broker/src/macos-install-plan.ts`:
  `e80439dd74404b44efbb28c9de767e662a173d0724c9f8c6e1e66808623b8571`
- `packages/broker/src/macos-install-plan.test.ts`:
  `5978a886cb1e70a21ba3e4a46386a9f8899b0f40af4f3fdd10d75fc84b954603`

This readback confirms the install-plan boundary is still valid at the current
revision. It does not change the partial status or provide live launchd,
Developer ID, notarization, installed Edge identity, or rollback evidence.
