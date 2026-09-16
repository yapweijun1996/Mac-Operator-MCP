# Helper runtime service-control IPC evidence

- Date: 2026-09-16
- Scope: authenticated root-helper runtime to service-control adapter

## Implementation

The root-helper key-material runtime now has a regression path that dispatches
an authenticated `service_control` command through the actual
`createPrivilegedServiceControlHelper` handler map. The fixture supplies only
host-test seams for command execution and launchd readback; the helper runtime
still loads protected key material, authenticates its peer, uses the separate
authority-poll channel, and verifies the helper response proof.

The adapter returned a verified transition from `stopped` to `running`. The
captured command was exactly `kickstart system/com.example.test`, with `/bin/launchctl`
and an empty environment; no shell or caller-supplied executable/argv was
introduced.

## Verification

```text
npm run typecheck --silent
node --test packages/broker/dist/privileged-helper-runtime.test.js
tests 8
pass 8
fail 0
```

This proves runtime-to-adapter wiring and authenticated response handling in a
host-only fixture. It does not prove descriptor execution, root installation,
Developer ID provenance, or live launchd mutation on the physical Mac.

## Rollback

Revert the runtime regression test and this evidence file. No service,
filesystem, signing identity, or credential store was changed.
