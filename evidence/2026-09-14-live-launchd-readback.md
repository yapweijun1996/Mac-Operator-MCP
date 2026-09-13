# Live launchd Readback Evidence

Status: Implemented parser hardening with reversible physical-macOS smoke evidence

## Scope

This evidence validates the read-only launchd metadata boundary and its
transient-state handling. It does not install the Broker, Edge, privileged
helper, or any persistent production service.

## Host and procedure

- Host: Darwin arm64, macOS 26.2-era user domain, non-root UID `501`.
- A unique temporary `gui/<uid>` LaunchAgent was bootstrapped from a `0600`
  plist in a temporary directory.
- The only program was `/bin/sleep 30` with exact arguments; no shell,
  environment injection, network operation, or repository path was involved.
- The bounded Broker `readLaunchdJobReadback` adapter read the live service,
  then `launchctl bootout` removed it and a final `launchctl print` confirmed
  absence. The temporary directory was removed in a `finally` path.

Observed typed readback:

```text
serviceId=gui/501/com.mac-operator.mops-parser-3437
type=LaunchAgent
state=launching
program=/bin/sleep
arguments=[/bin/sleep,30]
pid=3439
```

## Finding and fix

Immediately after bootstrap, macOS can report `state = xpcproxy` before the
same job reaches `state = running`. The parser previously treated this valid
transient state as malformed and failed the readback. It now maps `xpcproxy`
to the existing stable `launching` state. This does not authorize a running
service: Edge and privileged-helper startup paths still require an explicit
`running` state and a positive native PID/start-time identity.

The Edge identity capture path now retries only this explicit `xpcproxy`
transient, with a five-second global deadline and per-command timeout bounded
by the remaining budget. It never retries a missing/malformed service,
non-running state, or failed native PID/start-time capture.

## Verification

- `node --test packages/broker/dist/launchd-readback.test.js`: 4/4 passed,
  including the `xpcproxy` regression and the real system-service smoke.
- The default suite reports 419 tests: 416 passed, 0 failed, and 3 opt-in
  sandbox tests skipped; `MOPS_REAL_SANDBOX=1 npm test` reports 419 passed,
  0 failed, and 0 skipped.
- A live temporary LaunchAgent was bootstrapped, parsed through the production
  readback adapter, booted out, and confirmed absent.
- A second temporary user LaunchAgent was read by the production
  `captureLaunchdEdgeProcessIdentity` path; it captured a positive PID and
  native start-time identity, then was booted out and confirmed absent.
- No persistent plist, service, helper, credential, or capability was left
  installed or enabled.

One earlier full host run had a timing failure in the unrelated detached-
descendant recovery test. The focused process-supervisor suite then passed
13/13, followed by two consecutive full `MOPS_REAL_SANDBOX=1` runs at 419/419.
The failed attempt is retained as a host-timing signal rather than treated as
proof of a launchd regression.

Remaining packaging acceptance still includes signed production artifacts,
installed Broker/Edge identity handshake, upgrade/rollback/uninstall of the
real package, and final operator runbook evidence.
