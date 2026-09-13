# Uninstall authority revocation boundary evidence

Status: PARTIAL host-only implementation evidence for MOP-071 / MOP-072 / VT-OPS-01

Source commit: `f24b506` (`security: revoke authority before uninstall`)
Working tree: clean before verification commands
Scope: per-user LaunchAgent uninstall coordination; no live service mutation

## Boundary implemented

`executeMacOsUninstallPlan` is a host-only coordinator and is not exposed as an
MCP tool. It requires an explicit `uninstall` operation, a bounded Edge
identity, and callbacks supplied by the separately authenticated authority
channel. The coordinator performs these steps in order:

1. Persist the global kill switch as disabled.
2. Persist revocation of the selected Edge identity.
3. Read back both authority states and fail closed if either is missing,
   malformed, or still enabled.
4. Execute the existing exact-revision uninstall plan and require service
   absence readback.
5. Read back the authority states again before returning success.

Authority is never automatically re-enabled if plist removal, launchd
bootout, or final readback fails. Recovery remains an explicit operator action.
The existing uninstall executor still uses fixed `/bin/launchctl` argv, owner-
only descriptor-relative plist removal, and bounded command/readback checks.

## Verification

- Focused `macos-install-plan` suite: 11 passed, 0 failed, 0 skipped.
- Full `npm test`: 328 tests, 326 passed, 0 failed, 2 opt-in real-sandbox
  tests skipped.
- Negative test confirms incomplete authority readback issues no filesystem or
  launchd command.
- Success test confirms the ordering `disable-global`, `revoke-edge`, authority
  readback, uninstall, and final authority readback.
- `npm run typecheck -- --pretty false`: PASS.
- `npm run verify:contracts`: PASS, 44 unique contracts.
- `npm audit --omit=dev --audit-level=high`: PASS, 0 vulnerabilities.
- `git diff --check`: PASS.

No live LaunchAgent was bootstrapped, stopped, upgraded, rolled back, or
uninstalled. The callbacks were test doubles; this evidence does not prove
installed authority-channel packaging, Developer ID/notarization, live
launchd readback, Edge key cleanup, or production uninstall approval. VT-OPS-01
therefore remains `OPEN`.
