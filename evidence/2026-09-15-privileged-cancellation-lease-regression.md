# Privileged Job cancellation and lease regression

- Source revision: `70fd587`
- Focused command: `npx tsc -b packages/broker/tsconfig.json --pretty false && node --test packages/broker/dist/privileged-helper-executor.test.js packages/broker/dist/privileged-broker-dispatch.test.js`
- Focused result: 12 tests passed, 0 failed, 0 skipped.
- Physical command: `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1 node --test --test-timeout=120000 <all built tests except broker.test.js and persistence.test.js>`
- Physical result: 606 tests passed, 0 failed, 0 skipped.

The executor now terminalizes a running Job when cancellation wins before
helper dispatch, checks again after command signing before crossing the helper
IPC boundary, and preserves `UNKNOWN_OUTCOME` when cancellation wins after a
command may already have crossed the boundary. Long helper calls renew their
Broker-owned lease at a bounded interval; the focused test observes the
extended lease before a verified completion is persisted.

The physical run exercised the existing macOS sandbox, Keychain ACL,
LaunchAgent, IPC, filesystem, guest, Edge, and adapter boundaries after this
change. The long-running Broker/Persistence test process was left untouched.
No root process, real privileged adapter, Developer ID signing, or privileged
capability enablement was performed.
