# Virtualization Guest Attestation Keyring Evidence

- Date: 2026-09-15
- Host: physical Darwin arm64, macOS 26.2 (25C56)
- Source revision: `73148a6`
- Status: guest attestation public-key loading, activation, revocation, and rollback implemented; VM execution remains disabled

## Boundary implemented

`VirtualizationGuestAttestationKeyManager` is a Broker startup/operator boundary,
not an MCP Edge tool. It loads a versioned configuration from an owner-only,
canonical regular file and reads each Ed25519 public key through an owner-only,
non-symlink, `O_NOFOLLOW` descriptor. Device/inode identity is checked between
path inspection and open, file sizes are bounded, and each key is digest-bound
to the configuration. Duplicate key IDs and paths, weak modes, traversal-like
paths, non-Ed25519 keys, and digest replacement fail closed.

The active configuration is persisted independently from policy, Edge, helper,
and authority key state in BrokerStore schema version 8. Activation requires a
monotonic revision and expected previous revision, writes redacted intent and
completion audit events, and survives restart through exact payload-digest
readback. Operator rollback is restricted to a verified historical revision and
requires an explicit reason code. Revocation uses the dedicated
`guest_attestation_key` kind; queued work is cancelled conservatively and every
new verifier checks revocation dynamically.

The manager creates the signed guest-attestation verifier with startup-owned
validity windows, bounded lifetime, clock skew, and the durable revocation
callback. No private signing key is loaded or persisted by the host; native
guest-side signing and Keychain-backed distribution are separate future work.

## Verification

- Focused persistence and keyring tests: 49/49
- Focused signed-attestation and runner tests: 15/15
- Full physical-Darwin regression:
  `MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
  -> 530/530 passed
- `npm run typecheck` passed
- `npm run lint` passed
- `git diff --check` passed

## Remaining release-gate work

This evidence does not claim a native guest attestation producer, protected
private-key provisioning/distribution, an approved VM image, Virtualization
framework boot, guest filesystem/network/credential/process isolation, or
`mac_task_run` capability enablement. Those remain gated by MOP-086/MOP-045 and
the corresponding VM readback evidence.
