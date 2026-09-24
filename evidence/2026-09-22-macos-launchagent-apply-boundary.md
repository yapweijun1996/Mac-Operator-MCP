# macOS LaunchAgent apply boundary

Date: 2026-09-22

## Result

The repository now contains an explicit, owner-invoked apply entrypoint for
the Edge/Broker transaction and an optional Authority/Edge/Broker transaction:

```text
npm run apply:macos:launchagents -- --manifest PRIMARY.json --recovery INVERSE.json --confirm install|upgrade|rollback|uninstall --apply
```

The command is separate from the read-only plan compiler. It requires two
owner-only manifests, exact inverse operations, production signature policy,
authenticated Edge and Broker status channels, and prebound recovery plans.
Any three-component manifest, or any primary or recovery uninstall operation,
additionally requires the authenticated authority-control database, owner
operator socket, key configuration, and exact Edge identity.

## Implemented boundary

- No `--apply` flag means no apply path is entered; the command returns a
  bounded usage error without importing runtime mutators.
- Primary and recovery manifests are strict UTF-8 owner-only regular files
  with exact schema fields, canonical paths, bounded status sockets/keys, and
  matching component identity/status-channel bindings. A three-component
  manifest additionally binds the Authority config and operator socket in
  both primary and inverse manifests.
- Development ad-hoc plans are rejected by the production apply entrypoint.
- Edge and Broker status readback uses owner-only HMAC-authenticated local IPC;
  status responses are bound to request identity, freshness, replay state, and
  socket identity.
- The coordinator receives both component inverse actions before mutation and
  returns verified final readback or an explicit recovery-required result.
- The three-component coordinator uses `Authority -> Edge -> Broker` for
  install/upgrade/rollback and `Broker -> Edge -> Authority` for uninstall;
  Authority has a dedicated readback type, including owner-only operator-socket
  parent-chain and device/inode identity, and is never represented as Broker
  status.
- Status keys are digest-checked and wiped in the final cleanup path.
- Install, upgrade, rollback, and uninstall remain host-owned; no MCP handler,
  OAuth scope, or live R1 service state was changed.

## Verification

- `node --check scripts/apply-macos-launchagents.mjs` passed.
- `npm run typecheck` passed.
- `npm run build` passed.
- Edge status IPC plus startup integration focused tests passed 8/8.
- The initial boundary slice passed 1,077 total: 1,062 passed, 15 skipped,
  0 failed; the latest full repository regression after Authority, shared
  socket-boundary, and combined handoff integration passes 1,113 total: 1,098
  passed, 15 skipped, 0 failed.
- Real child-process handoff smoke passes 4/4: two read-only plan tests and two
  fail-closed apply CLI tests. The apply tests reject ad-hoc release plans and
  duplicate Authority socket aliases before host mutation.
- `git diff --check` passed.
- A live production apply was not run because the current host still lacks
  Developer ID/notarized release evidence, persistent target service labels,
  and the required production status-channel configuration. The existing
  personal R1 deployment was not restarted or modified.

## Remaining gates

This evidence closes the code-level apply handoff boundary only. It does not
close Developer ID/notarization, Accessibility, persistent production
LaunchAgent/LaunchDaemon lifecycle, protected production material and
rollback acceptance, or independent P0/P1 review.
