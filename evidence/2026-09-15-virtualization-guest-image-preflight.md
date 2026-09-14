# Virtualization Guest Image Preflight Evidence

Status: host image binding implemented; guest execution remains disabled

Date: 2026-09-15

Host: physical Apple silicon Mac mini, macOS 26.2 (Build 25C56), Darwin 25.2.0, arm64

Source revisions: `846eca5`, `81faff0`

## Boundary implemented

`packages/broker/src/virtualization-guest-image.ts` reads a startup-owned,
absolute image path only when it resolves to a current-user-owned regular file
with owner-only permissions. It rejects final symlinks, unsafe parent
directories, malformed digests/runtime versions, and images above the bounded
size budget. Hashing occurs through one descriptor in bounded chunks; device,
inode, and size are checked before and after hashing.

`VirtualizationTaskRunner` now requires a preflighted image identity to become
available. The proof identity, preflight identity, and native executor identity
must match. Before each task dispatch and restart status recovery, the Broker
re-reads and re-hashes the same image and rejects content replacement or
device/inode/size changes. MCP arguments cannot provide or replace this image
binding.

## Verification

Focused task-runner and image tests:

```text
node --test packages/broker/dist/task-runner.test.js packages/broker/dist/virtualization-guest-image.test.js
15 tests, 15 passed, 0 failed
```

The runner test replaces the image after a successful preflight and confirms
that dispatch is denied before the executor is called.

Full physical-host regression:

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
523 tests, 523 passed, 0 failed, 0 cancelled, 0 skipped
```

## Remaining release gates

This evidence does not prove that the image is a signed/approved macOS guest,
that Virtualization.framework can boot it, or that guest filesystem, network,
credential, process-tree, cancellation, postcondition, restart, and attestation
properties hold. No VM was booted and no `mac_task_run` capability was enabled.
