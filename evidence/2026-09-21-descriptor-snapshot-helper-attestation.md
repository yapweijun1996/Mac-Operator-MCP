# Descriptor Snapshot and Helper Attestation Evidence

Date: 2026-09-21

Scope: MOP-045/MOP-086 descriptor-backed task execution and the future
host-owned helper handoff.

## Implemented boundary

`packages/broker/src/descriptor-snapshot-attestation.ts` adds a separate,
disabled-by-default `DescriptorSnapshotRegistry` and a versioned Ed25519
attestation contract. A Broker-owned preparation call:

- opens the canonical executable and working-directory descriptors with
  `O_NOFOLLOW` and the directory flag where applicable;
- compares the opened descriptor metadata with the Broker's canonical path
  identity and hashes the opened executable content;
- creates a one-shot opaque `snapshot:<random>` reference with a bounded
  lifetime;
- signs only non-secret plan facts and identity digests; and
- exposes borrowed descriptor numbers only inside a callback, never a path,
  argv, environment value, filesystem root, or network destination.

The exported `assertDescriptorSnapshotIdentity` function is the future native
helper-side contract: it accepts only FD-derived identity facts and the signed
attestation. The contract explicitly labels immutable selection as
`revalidation-only`; it does not claim kernel-held executable selection or
close-on-exec proof.

The registry consumes a snapshot exactly once, revalidates both held
descriptors immediately before the callback, and closes them on success,
failure, or replay rejection. A content mutation of the held executable is
denied before handoff.

## Verification

- `npm run build` passed.
- `packages/broker/src/descriptor-snapshot-attestation.test.ts` passed 5/5:
  default-off behavior, opaque signed handoff, one-shot replay rejection,
  held-descriptor mutation denial, signature/expiry/revocation denial, and
  pathname-free identity binding.
- No MCP scope, policy entry, runtime tool, helper package, or host service was
  enabled or changed.

## Remaining release gates

This evidence does not prove a native descriptor launcher, SCM_RIGHTS or
equivalent cross-process FD transfer, immutable kernel executable selection,
close-on-exec behavior at the helper boundary, remount resistance, sandbox
credential isolation, signed Developer ID deployment, or production task
enablement. The current host capability gate remains fail-closed and
`mac_task_run` remains disabled.

## Rollback and readback

Rollback is removing the disabled module/export and its tests/docs; no
database, policy, OAuth grant, launchd service, helper package, or host file
was changed by this work. The current readback is the repository build and
focused suite above; a real helper readback is intentionally not claimed.
