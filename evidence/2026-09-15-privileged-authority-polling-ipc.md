# Privileged helper authority-polling IPC evidence

Date: 2026-09-15
Source revision: `b9d038a` (authority polling implementation: `2660bdf`)
Status: implemented boundary; disabled by default and not a privileged-release acceptance

## Scope

This checkpoint adds an independent helper-to-Broker authority channel. The
root helper does not read Broker SQLite and cannot decide authority locally.
The Broker endpoint authenticates the helper peer, verifies a direction-specific
HMAC envelope, rejects replayed request IDs/nonces through the durable helper
ledger, authenticates the nested Broker-signed command, and calls the reusable
`assertPrivilegedHelperCommandAuthority` gate. The gate re-reads switches,
revocations, Approval, Request, Job, target, payload, policy, and deterministic
command/intent identity.

The helper-side client authenticates the Broker peer before sending, fences the
authority socket device/inode before and after each exchange, bounds request /
response bytes and time, verifies the response proof, and clears its key on
dispose. An active helper operation performs an initial poll, bounded periodic
polls, and a final poll. Any authority loss after execution begins prevents a
success response and is reported as retryable `UNKNOWN_OUTCOME`.

The key manager can construct this poller from the same activated helper-key
binding as the command server. Key expiry, revocation, and activation changes
are checked for every poll. Runtime construction rejects an enabled adapter
when no separately authenticated authority poller is supplied.

The native Broker startup assembly restores the active helper-key configuration,
constructs the Broker-owned authority listener, appends it to the native
runtime channel set, and closes it on startup rollback. The helper authority
socket is required to be distinct from the MCP Broker socket and to carry an
explicit native helper process identity.

## Verification

- `npx tsc -b packages/broker/tsconfig.json --pretty false` — passed.
- `npm run lint -- --quiet` — passed for 628 tracked files.
- `node --test packages/broker/dist/privileged-helper-authority-ipc.test.js packages/broker/dist/privileged-helper.test.js` — 18/18 passed.
- `node --test packages/broker/dist/privileged-helper-runtime.test.js packages/broker/dist/privileged-helper-keyring.test.js` — 7/7 passed in the combined focused run.
- `node --test packages/broker/dist/native-runtime-startup.test.js` — 8/8 passed.
- Physical non-overlapping built suite with `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1` — 613/613 passed, zero failures and zero skips.
- Existing long-running `broker.test.js` / `persistence.test.js` process was observed and left undisturbed.

## Boundary cases covered

- Successful authority poll over a real Unix socket with response proof.
- Broker revocation denial on a subsequent poll.
- Wrong Broker peer rejection before request publication.
- Response identity/proof tampering rejection.
- Durable replay-adapter timestamp mapping.
- Helper initial and final polls around an active adapter call.
- Post-dispatch authority loss maps to retryable `UNKNOWN_OUTCOME`.
- Native Broker startup restores the helper key, owns the authority listener,
  and rolls the listener back when runtime construction fails.
- Disabled-by-default policy and helper operation state remain unchanged.

## Open evidence

This is a local protocol and integration boundary. It does not prove a
Developer ID-signed/notarized root helper, production launchd installation,
real privileged adapters, credential-isolated root execution, or independent
P0/P1 review. Those release gates remain open.
