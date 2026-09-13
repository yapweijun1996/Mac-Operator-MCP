# Privileged Helper Authenticated Status IPC Evidence

Date: 2026-09-13  
Implementation commit: `2240870`  
Documentation commit: `35aa78e`  
Dirty-state: clean after documentation commit  
Host: macOS 26.2 (25C56), arm64  
Runtime: Node.js v25.5.0  
Tool contract version: 0.1  
Policy version: policy-0.1

## Scope

This record covers the helper-owned, read-only runtime-status channel. It does
not install a LaunchDaemon, mutate launchd, start a root process, expose an MCP
operation, or enable a privileged adapter.

## Implemented boundary

`PrivilegedHelperIpcServer` recognizes only a strict `kind: "status"` envelope
after the same OS peer check used by the command channel. Status requests use a
separate HMAC domain, protocol/contract identity, bounded timestamp and expiry,
strict request IDs/nonces, and the durable BrokerStore replay ledger. The
Broker-owned `authorizeStatus` gate runs after authentication and replay
admission; `readStatus` is an explicit helper-owned source and is never derived
from launchd state or caller arguments.

The signed response is bound to the exact unsigned request with a separate
response HMAC domain. Success accepts only the fixed runtime shape: running
state, native transport required, disabled adapter, canonical distinct helper
and Broker sockets, positive Broker UID, optional non-negative GID, bounded
source/contract/policy versions, and an empty enabled-capability list. Failure
responses use the shared stable error classes and bounded messages.

`readPrivilegedHelperStatus` is a host-side client. It snapshots socket
device/inode before connecting, authenticates the response, and snapshots the
identity again before returning. Socket replacement, malformed JSON, timeout,
oversized output, authentication failure, replay, or helper authority failure
are fail-closed and never produce a runtime success.

`PrivilegedHelperRuntimeOptions` exposes the status source and authority gate as
first-class inputs. `PrivilegedHelperKeyManager.createServer` wraps that gate
with active key validity, revocation, and configuration revision/digest checks,
so an already-created server cannot continue status reads after helper-key
authority changes.

## Verification

- `npm test`: 398 tests, 395 passed, 0 failed, 3 opt-in sandbox tests skipped.
- `npm run typecheck`: passed.
- `npm run verify:contracts`: 44 unique contracts validated.
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.
- Status IPC coverage proves successful authenticated readback, durable replay
  denial, helper-owned source invocation, host-client round trip, malformed
  JSON handling, and native peer-denial behavior.

## Remaining gates

Developer ID signing/provenance, protected Keychain ACLs and cross-process key
delivery, installed root-domain launch/readback, crash recovery, privileged
adapters, real host evidence for the installed helper, and independent P0/P1
review remain open. This is local contract and test evidence only.

## Source hashes

- `354ce2285c5e60a0e043b580f150b6a256d68aa089dd08cbe01268398f8a7c38` `packages/broker/src/privileged-helper.ts`
- `76b15e16ab2488bbb4959d9c2e008f3545d77b7716d2712e0412dcb0ea1f554f` `packages/broker/src/privileged-helper.test.ts`
- `3930b16f720d8a25f2b5ea85e762fa28e40e42c5ed8ca17f877bbabf1a1f0fc4` `packages/broker/src/privileged-helper-runtime.ts`
- `8233c2e2c919d0787ff4a515176d09ac8a26dceb51579b05ba7816206113693d` `packages/broker/src/privileged-helper-keyring.ts`
