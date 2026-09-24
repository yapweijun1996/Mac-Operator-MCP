# Real macOS user-service mutation boundary evidence

- Date: 2026-09-22
- Host: physical macOS arm64, non-root uid 501
- Probe status: PASS
- Probe command: `npm run probe:user-service-mutation`
- Capability: bounded owner-domain `mac_service_control` candidate through the standard Broker admission and Job executor

## Fixed disposable identity

- Service identity: `gui/501/com.mac-operator.boundary-probe`
- LaunchAgent plist: `/Users/yapweijun/Library/LaunchAgents/com.mac-operator.boundary-probe.plist`
- Program: `/bin/sleep`
- Fixed arguments: `[/bin/sleep, 60]`
- Source revision: `d030e3336d95038e5e03026f54efb1ba9b3d24f406b6f89352644470daf509df`
- Command boundary: `/bin/launchctl`, direct argv execution, empty environment, `/` working directory, bounded timeout/output
- Postcondition boundary: transient launchd `launching`/`waiting`/`loaded` states are settled for at most eight 50 ms readback attempts before strict verification or rollback.

## Observed lifecycle

1. Confirmed the fixed service identity was absent before setup.
2. Created an owner-only regular plist with exclusive creation and verified its uid, mode, canonical path, and source digest.
3. Bootstrapped the exact plist into the uid-501 GUI domain.
4. Issued an authenticated, owner-only exact approval through `ApprovalAuthority`.
5. Broker `start` request: `stopped -> running`, post-state and source revision verified.
6. Broker `stop` request: `running -> stopped`, post-state and source revision verified.
7. Target-swap negative case: unloaded the original identity, bootstrapped the same label with a changed `/bin/sleep 61` argument, and sent the original binding request. Broker returned `PRECONDITION_FAILED`; one exact approval was consumed, no command was dispatched, and launchd readback remained `stopped`. The swapped identity was then unloaded and the original plist was recreated with the original source revision.
8. Active-revocation case: after the real `start` command crossed the host boundary, the mutation kill-switch was durably enabled during post-readback. Broker returned retryable `UNKNOWN_OUTCOME`; the Request and Job remained `UNKNOWN`, while launchd readback showed the service `running` for exact cleanup.
9. Restart-recovery case: the running Job was durably marked `UNKNOWN` through the existing `reconcileInterruptedJobs()` restart path, then a fresh `BrokerStore` and `UserServiceControlJobExecutor` performed one exact service identity readback. Recovery reported `inspected: 1`, `readback: 1`, `identityMismatch: 0`, `unavailable: 0`, and `unknown: 0`; the Job remained `UNKNOWN` and no mutation was replayed.
10. Booted out the exact plist identity, verified the service was unloaded, and removed the exact probe plist.
11. Removed the probe's temporary persistence directory and zeroed the in-memory probe keys.

The JSON result reported verified positive lifecycle, target-swap rejection, active-revocation UNKNOWN handling, restart readback recovery without replay, and `realMutation: true`. No ordinary user service, system daemon, root helper, or unrelated plist was touched.

## Boundary and limitations

- This is evidence for the fixed disposable user-domain boundary only; it does not enable the public OAuth/MCP profile.
- Restart recovery uses the production restart-reconciliation state transition and a fresh Store/Executor instance in one bounded probe; it does not simulate an unbounded process crash or promote an UNKNOWN Job.
- Default policy and the personal public deployment remain fail-closed for `mac_service_control`.
- The probe does not establish Developer ID signing, notarization, OAuth grant wiring, ChatGPT tool-list exposure, system/root service mutation, arbitrary target-swap resistance beyond this fixed source-revision case, or privileged helper production readiness.
- The correct launchd interpretation is that `stop` stops the process while the label remains loaded; final unload is a separate exact `bootout` cleanup step.
