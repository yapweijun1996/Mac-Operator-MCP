# Privileged Helper Package Boundary Evidence

Date: 2026-09-13
Source commit: `eb9ee6a`
Dirty-state: clean at capture
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0
Tool contract version: 0.1
Policy version: policy-0.1

## Scope

This record covers the source-level packaging boundary for a separately
authenticated privileged helper. It is a non-executing plan: no LaunchDaemon
was installed, no `launchctl` mutation ran, no signing was performed, and no
root or privileged operation was started.

## Implemented boundary

`buildPrivilegedHelperPackagePlan` produces only the exact system
`com.mac-operator.privileged-helper` LaunchDaemon shape. It requires a
canonical helper root, native helper executable, exactly one argv entry, no
shell/interpreter/script entrypoint, exact helper code-signature identifier,
root-owned `0600` plist actions, protected helper key/socket paths, and a
Broker peer UID/GID binding. The helper socket cannot equal the Broker socket.

The plan includes fixed bounded `codesign` and `launchctl` argv, exact
install/upgrade/rollback/uninstall commands, source-revision preconditions,
and readback checks for system domain, root execution, native transport,
socket identity, Broker peer identity, contract/policy versions, signature,
and disabled adapter/capability state. The plan is not exposed through MCP.

## Verification

- `npm test`: 349 tests, 347 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- Focused package-boundary tests: 10 passed, 0 failed.
- `MOPS_REAL_SANDBOX=1 npm test`: 349 tests, 349 passed, 0 skipped.
- `npm run typecheck -- --pretty false`: passed.
- `npm run build -- --pretty false`: passed.
- `npm run verify:contracts`: 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.

Negative coverage rejects per-user plist paths, interpreter/script argv,
extra arguments, socket reuse, user-home helper roots, mismatched signatures,
missing upgrade revisions, enabled adapter readback, and signature readback
mismatch. On the real macOS host, the temporary bundle smoke test also ran the
fixed ad-hoc signing command, verified the plan's strict signature command,
and read back `com.mac-operator.privileged-helper`. The package filesystem
preflight double-checks root-owned paths and device/inode identity, and its
pure readback tests reject unsafe mode/owner/type substitutions. The host-only
plist apply primitive rejects mismatched operation confirmation and non-root
ownership before filesystem access; it also verifies the actual current
process UID, rejects a forged `ownerUid: 0` before the filesystem preflight,
and pins the writer to the internal root filesystem inspector rather than
caller-injected state.
Successful root-owned apply/rollback was not run.

The dry-run execution contract validates an absent service for install and an
exact prior source revision for upgrade, rollback, and uninstall. The gated
executor consumes that contract with bounded `ProcessSupervisor` commands,
requires root before access, and performs fixed recovery after bootstrap or
readback failure. The current host run stopped at the non-root gate and did
not invoke launchctl or mutate the system plist; successful root-owned
execution remains unverified.

## Remaining gates

Developer ID signing and provenance (the smoke test is ad-hoc only),
successful root-owned descriptor-relative installation, root-owned filesystem
preflight on an installed package, caller PID/start-time provenance across a
real helper/root process boundary, Keychain ACL approval, launchd
install/rollback/readback, helper adapters, crash recovery, and independent
security review remain open. The separate native cross-process caller-spoof
test is recorded in
`evidence/2026-09-13-privileged-helper-native-caller.md`; it does not prove a
root-domain installation. The helper remains disabled.
