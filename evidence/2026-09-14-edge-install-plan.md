# Edge install-plan and readback evidence

Date: 2026-09-14
Host: Darwin arm64 development host

## Scope

This evidence covers the source-level Edge packaging boundary. It does not
claim a production signed artifact, unattended installer authorization, or a
persistent LaunchAgent deployment.

The Broker package now exposes component-specific boundaries:

- `buildMacOsEdgeInstallPlan` requires the fixed
  `com.mac-operator.edge` per-user LaunchAgent label and an explicit expected
  listener host/port.
- `composeMacOsEdgeInstallReadback` and
  `validateMacOsEdgeInstallReadback` bind launchd service identity, exact
  ProgramArguments, PID/start-time, descriptor-backed plist identity, code
  signature identity, and an independently observed running/listening Edge.
- `createMacOsEdgeInstallHostObserver` accepts an Edge-owned readback source
  only; it cannot use the Broker status channel as a substitute.
- `executeMacOsEdgeInstallPlan` requires exact host operation confirmation and
  an existing-service precondition before atomic plist or launchd mutation.

## Verification

Commands:

```text
npm test
npm run typecheck
npm run verify:contracts
npm audit --omit=dev --audit-level=high
git diff --check
```

Results at capture time:

- 431 tests: 427 passed, 0 failed, 4 explicit opt-in skips.
- 44 tool contracts plus the versioned ledger-record schema validated.
- Production dependency audit reported 0 vulnerabilities.
- Edge tests cover listener substitution, component/label substitution,
  launchd target swap, and pre-confirmation rejection.

## Remaining gates

Developer ID/notarization, production package installation and upgrade/
rollback, remote issuer interoperability, Keychain ACL review, and final
operator runbooks remain open.
