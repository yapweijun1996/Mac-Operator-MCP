# Broker-backed privileged helper authority gate

- Source revision: `91806ae`
- Focused command: `npx tsc -b packages/broker/tsconfig.json --pretty false && node --test packages/broker/dist/privileged-helper.test.js packages/broker/dist/privileged-helper-executor.test.js packages/broker/dist/privileged-broker-dispatch.test.js`
- Focused result: 26 tests passed, 0 failed, 0 skipped.
- Physical command: `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1 node --test --test-timeout=120000 <all built tests except broker.test.js and persistence.test.js>`
- Physical result: 607 tests passed, 0 failed, 0 skipped.

`assertPrivilegedHelperCommandAuthority` is a reusable Broker-owned callback
for the helper IPC server. It resolves the original Request and Job through
the consumed Approval, verifies the operation/target/payload/policy and
deterministic command/intent identities, and rejects disabled global,
mutation, or privileged switches, revoked Edge/key/principal/session
identities, cancelled Jobs, expired approvals, and non-running Jobs. The
signed command continues to omit principal, session, and raw request fields;
the authority gate reconstructs them from durable Broker state.

The physical run exercised the existing macOS sandbox, Keychain ACL,
LaunchAgent, IPC, filesystem, guest, Edge, and adapter boundaries after this
change. The long-running Broker/Persistence test process was left untouched.
No root process, real privileged adapter, Developer ID signing, or privileged
capability enablement was performed.
