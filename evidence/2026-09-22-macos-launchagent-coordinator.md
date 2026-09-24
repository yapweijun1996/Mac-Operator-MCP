# macOS LaunchAgent Deployment Coordinator Evidence

Date: 2026-09-22

Status: `PASS` for the host-owned two-component and three-component
transaction boundaries; production signing, persistent installation, and final
host acceptance remain open.

Source revision: `540541c` plus the uncommitted working-tree changes recorded
in this evidence update. Target: macOS 26.2, Darwin arm64, owner UID 501.
Contract: host-owned `macos-launchagent-coordinator` boundary.

## Boundary

`packages/broker/src/macos-install-coordinator.ts` coordinates the already
reviewed Edge, Broker, and owner-domain Authority LaunchAgent executors without
accepting MCP arguments, reading secrets, or invoking child processes. Each
component action must be assembled by the host-owned controller and must
perform its own exact precondition, confirmation, atomic plist mutation,
launchd command, and final readback. Authority has a dedicated readback type;
it is never represented as Broker status.

The existing two-component coordinator enforces the deployment order:

- `install`, `upgrade`, and `rollback`: Edge, then Broker;
- `uninstall`: Broker, then Edge, after the caller's authority-shutdown gate.

Every action must provide a host-owned inverse action. If the second component
fails, the completed first component is recovered. A successful recovery throws
a structured `COMMAND_FAILED` with `recoveryState: recovered`; an unsuccessful
recovery throws `RECOVERY_FAILED` with `recoveryState: recovery-required`.
Neither state is reported as a successful deployment.

`executeMacOsLaunchAgentPlans` is the concrete host assembly. It calls the
existing Edge/Broker executors, rejects production plan sets unless every
primary and inverse plan is Developer ID plus notarization eligible, and
requires the existing authority-gated `executeMacOsUninstallPlan` path for a
Broker uninstall. It also rejects inverse operations that do not match the
expected recovery pair (`install`/`uninstall`, `upgrade`/`rollback`, and so on)
before any host mutation.

`executeMacOsLaunchAgentPlansWithAuthority` is the three-component host
assembly. It enforces `Authority → Edge → Broker` for install, upgrade, and
rollback because Broker startup binds both stable peer identities, and
`Broker → Edge → Authority` for uninstall. If a later component
fails, all completed components are recovered in reverse order; a recovery
failure is reported as `RECOVERY_FAILED` and never as success. Authority's
operator socket path, full parent-chain safety, and owner-only device/inode
identity are part of the plan readback and are double-sampled before final
acceptance.

## Verification

Focused tests pass 12/12:

- successful install order and result binding;
- Broker failure with Edge recovery;
- recovery failure and explicit operator-recovery state;
- reverse uninstall order with Broker recovery;
- operation mismatch and missing inverse action rejection before mutation;
- production rejection of ad-hoc primary/inverse artifacts;
- Broker uninstall rejection without the authority-gated path.
- three-component Authority/Edge/Broker order and reverse recovery;
- Authority plist/process/signature/operator-socket parent-chain, path, and
  device/inode readback binding.

The coordinator is host-owned and not an MCP handler. No live R1 service,
LaunchAgent, plist, Keychain item, OAuth grant, or production capability was
changed by this implementation or its tests.

Follow-up verification after the Authority integration, shared socket boundary,
and combined handoff: `npm test` reports 1,113 total, 1,098 passed, 15 skipped,
and 0 failures.
`npm run lint`,
`npm run verify:matrix`, `npm run verify:docs`,
`npm run verify:process-boundaries`, `npm audit --omit=dev --audit-level=high`,
and `git diff --check` all pass. `npm run verify:completion` remains the
intentional non-zero partial audit at 92% because host release and production
acceptance gates are still absent.

## Reproduction

```text
npm run typecheck
npm run build
node --test packages/broker/dist/macos-install-coordinator.test.js
```
