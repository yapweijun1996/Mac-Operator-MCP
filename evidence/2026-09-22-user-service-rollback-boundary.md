# Real macOS user-service rollback boundary evidence

- Date: 2026-09-22
- Host: physical macOS arm64, non-root uid 501
- Probe status: PASS
- Probe command: `npm run probe:user-service-rollback`
- Capability: bounded owner-domain `mac_service_control` candidate through the standard Broker admission and Job executor

## Fixed disposable identity

- Service identity: `gui/501/com.mac-operator.boundary-rollback`
- LaunchAgent plist: `/Users/yapweijun/Library/LaunchAgents/com.mac-operator.boundary-rollback.plist`
- Program: `/bin/sleep`
- Fixed arguments: `[/bin/sleep, 60]`
- Source revision: `f26d10f3ea769f73aff533cb8d7cfbdc51c689f854ab5b5ce08a7a87221128d5`
- Command boundary: `/bin/launchctl`, direct argv execution, empty environment, `/` working directory, bounded timeout/output

## Observed rollback

1. Confirmed the fixed service identity was absent before setup.
2. Created and fsynced an owner-only regular plist with exclusive creation, then verified its uid, mode, canonical path, and source digest.
3. Bootstrapped the exact plist into the uid-501 GUI domain and established a verified `running` pre-state through native `ProcessSupervisor` execution.
4. Issued an authenticated exact approval and sent a Broker-mediated `stop` request with expected state `stopped`.
5. The real `/bin/launchctl kill SIGTERM` crossed the host boundary. The test-only command wrapper then waited for launchd's observed 10-second minimum-runtime window and issued a fixed `kickstart` to deliberately create a physical `running` postcondition mismatch.
6. The production adapter returned `VERIFICATION_FAILED`, read back `postState: running`, executed its inverse fixed rollback, and verified `rollbackStatus: verified`, `rollbackState: running`. The Job persisted `failed / verification_failed`; no success was promoted.
7. Booted out the exact identity, verified it was unloaded, removed the exact plist, closed the temporary Broker store, and zeroed probe keys.

The probe JSON reported `preState: running`, `postState: running`, `rollbackStatus: verified`, `rollbackState: running`, `jobState: failed`, `serviceState: running`, and `realMutation: true`.

## Boundary and limitations

- The postcondition mismatch is deliberately forced by a test-only wrapper after a real fixed `launchctl kill`; the wrapper is not production command authority and is not exposed to requests.
- The production adapter remains fixed to policy-owned service identities, fixed `/bin/launchctl` argv, empty environment, bounded output/time, source-revision readback, and strict inverse-state verification.
- This evidence covers physical rollback only for the disposable owner-domain identity. It does not enable the public OAuth/MCP profile, ordinary user-service control, system/root service mutation, Developer ID/notarization, or ChatGPT tools-list exposure.
