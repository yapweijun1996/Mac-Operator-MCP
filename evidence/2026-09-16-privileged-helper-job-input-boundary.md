# Privileged Helper Job Input Boundary Evidence

- Source revision: `340eb2c`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T19:35:52Z`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: the privileged Helper Job executor now validates its operation
  allowlist plus Broker Job and Lease identity fields before accessing the
  store, renewing a lease, signing a command, or crossing helper IPC.
- Source artifact SHA-256:
  - `packages/broker/src/privileged-helper-executor.ts`:
    `1d8942481e3a844ad61fb41b1cdc727ab4f0a692b7da58db2a64cc7cc10a4efc`
  - `packages/broker/src/privileged-helper-executor.test.ts`:
    `9c5583d895584c5b04cf3110c355cfdb5d9a89da58d47336ac74323db441d30e`

## Verification

```text
npm run build
node --test packages/broker/dist/privileged-helper-executor.test.js
tests 10
pass 10
fail 0

npm run typecheck
npm run lint
git diff --check

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 669
pass 664
fail 0
skipped 5
```

The five skips are explicit descriptor-capability real-sandbox probes. The
three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes malformed local Helper Job input before dispatch only. It does not
prove the separately authenticated privileged helper deployment, root-host
filesystem isolation, installed provenance, or capability enablement.

## Rollback

Revert commit `340eb2c`. No installed service, policy, signing key, or
credential store was changed.
