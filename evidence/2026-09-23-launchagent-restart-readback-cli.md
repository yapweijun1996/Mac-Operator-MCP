# LaunchAgent restart readback CLI

## Decision

Operator recovery needs a read-only verification path that can be run after a
controller or service restart without re-entering an apply or uninstall path.
The existing host-owned apply handoff now supports `--readback` and has a
dedicated `readback:macos:launchagents` npm entrypoint. It loads the same
owner-only manifest pair and protected Edge/Broker status material used by the
apply controller, then checks every planned component through its existing
launchd, process identity, plist, signature, metadata, and authenticated status
observers. It performs no plist write, launchctl bootstrap/bootout, authority
mutation, or capability change.

## Evidence

- A readback invocation is distinct from `--apply`; passing both or neither is
  rejected by the command parser.
- Development ad-hoc plans are accepted only for readback inspection; they are
  still rejected for apply.
- A readback with absent protected status material fails closed before it can
  claim a service is verified.
- Focused handoff regression: 5/5 passed, including the new readback mode.
- `node --check scripts/apply-macos-launchagents.mjs` passed.

## Limits

This adds a safe post-restart readback entrypoint and does not claim that the
current host has an installed production operator. The completion audit still
reports absent target LaunchAgents, zero Developer ID identities, denied
Accessibility, and no production acceptance record. Live installation,
production signing, active-work termination, and recovery after a real host
crash remain open.

## Rollback

Remove the readback npm alias, parser branch, focused test, documentation, and
this evidence file. The existing apply path and component readback observers
remain unchanged.
