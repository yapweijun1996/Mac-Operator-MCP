# Authority Lifecycle State-Machine Evidence

Status: bounded deterministic hardening; release gates remain open

Date: 2026-09-15

Host: physical Apple silicon Mac mini, macOS 26.2 (Build 25C56), Darwin 25.2.0, arm64

Source revision: `d0c96be`

## Boundary exercised

`packages/broker/src/persistence.test.ts` now runs 16 deterministic seeds with
72 authority/job actions per seed. Each sequence covers independent global,
mutation, process, network, GUI, destructive, and privileged switches;
principal, session, and upstream Edge revocation; expected-state conflicts;
queued cancellation; running cancellation; terminal completion; and restart
reconciliation.

The model checks that blocked queued Jobs are cancelled transactionally,
unrelated principals remain queued, running Jobs are not silently rewritten by
queued-only authority reconciliation, terminal Jobs never change state,
revision numbers never regress, and restart reconciliation leaves no queued or
running Job unresolved.

The privileged case uses a canonical, digest-bound `power` descriptor only; no
privileged process or host mutation is executed.

## Verification

Focused persistence regression:

```text
node --test packages/broker/dist/persistence.test.js
46 tests, 46 passed, 0 failed
```

Full physical-host regression:

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
524 tests, 524 passed, 0 failed, 0 cancelled, 0 skipped
```

## Remaining release gates

This is bounded model-based regression coverage, not exhaustive fuzzing or a
proof of active process-tree termination, remote revocation propagation,
kernel-enforced isolation, restart readback of every adapter, or production
service enablement. The VM guest and privileged helper remain disabled or
blocked pending their separate host evidence.
