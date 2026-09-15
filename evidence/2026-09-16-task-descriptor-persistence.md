# Task descriptor persistence boundary

Date: 2026-09-16
Source revision: `0229fe3`
Host: Darwin 25.2.0, arm64, Node v25.5.0

Schema alignment revision: the versioned ledger schema now accepts the
optional `taskDescriptorDigest` and host-owned `ownershipProof` process
metadata fields; runtime validation remains authoritative for cross-field
invariants and legacy-row compatibility.

## Boundary

Before a task process is admitted, the Broker resolves the versioned
`TaskProfile` into the exact executable, arguments, cwd, environment,
filesystem/network/credential/process-tree policy, sandbox, verification
strategy, and resource budgets. `taskDescriptorDigest` computes a canonical
SHA-256 digest of that resolved descriptor. The first process ownership
snapshot stores the digest in Job metadata; every later ownership update must
carry the same digest, so a changed task descriptor cannot replace the process
identity associated with a running Job. Metadata parsing accepts legacy rows
without this field for compatibility, but malformed digests fail closed and
legacy rows are not upgraded automatically. Only the digest is persisted; raw
arguments, environment values, credentials, and host paths are not copied into
the process metadata.

## Verification

```text
npm run build
npm run typecheck
npm run lint
node --test packages/broker/dist/process-job-descriptor.test.js
tests 2
pass 2
fail 0

node --test packages/contracts/dist/ledger-contract.test.js
tests 3
pass 3
fail 0

npm run verify:contracts

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 648
pass 643
fail 0
skipped 5
```

The focused regression proves that changing resolved arguments or environment
changes the digest, a mismatched ownership update is rejected with stable
`PRECONDITION_FAILED`, a matching update succeeds, and a BrokerStore reopen
preserves the digest. The physical run completed without failures; its five
skips are the descriptor-gated real sandbox probes because this host still has
no verified native descriptor executable launcher.

The three pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This is metadata binding and restart readback evidence, not kernel-held
descriptor execution. It does not prove an immutable executable snapshot,
in-syscall remount resistance, credential/process isolation, or production
task enablement. `VT-FS-02`, `VT-SBX-01`, and the `mac_task_run` release gate
remain open.

## Rollback

Revert commit `0229fe3`. No installed service, host configuration, signing
key, or credential store was changed.
