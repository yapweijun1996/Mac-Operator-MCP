# Virtualization Guest Channel Evidence

Status: partial authenticated-channel implementation; VM execution remains disabled

Date: 2026-09-15

Host: physical Apple silicon Mac mini, macOS 26.2 (Build 25C56), Darwin 25.2.0, arm64

Source revisions: `521eecc`, `4592cad`

## Boundary implemented

`packages/broker/src/virtualization-guest-channel.ts` implements the Broker-side
channel used by a future native Virtualization.framework adapter. It is not a
VM implementation and is not wired into capability enablement.

- The socket path is startup-owned, absolute, bounded, and never selected by an
  MCP argument.
- The socket parent and target are owner-only, regular protected filesystem
  objects; symlink targets are rejected. Device/inode identity is read before
  connect and re-read after connect.
- The connected socket is authenticated through the existing native
  `getpeereid`/`LOCAL_PEERPID` adapter and the Broker-owned UID/GID/PID plus
  optional PID/start-time policy. Peer authorization completes before a frame
  is parsed or a response can be accepted.
- Each connection carries exactly one bounded big-endian length-prefixed frame.
  Request and response sizes, timeout, cancellation, close, trailing bytes, and
  malformed/oversized response cases fail closed.
- Transport loss after a request was sent maps to retryable `UNKNOWN_OUTCOME`;
  pre-send failures do not claim guest execution.

The channel carries only the already-authenticated guest transport frame. The
Broker still sends no host path, raw executable, credential, or arbitrary
command to this boundary.

## Verification

Focused test:

```text
node --test packages/broker/dist/virtualization-guest-channel.test.js
4 tests, 4 passed, 0 failed
```

The focused real-socket tests cover successful exchange, peer substitution,
cancellation, response-size limits, trailing frame data, and symlinked socket
denial.

Full physical-host regression:

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
523 tests, 523 passed, 0 failed, 0 cancelled, 0 skipped
```

## Remaining release gates

This evidence does not prove a native guest server, VM boot, signed guest
attestation, image/runtime provenance, guest filesystem/network/credential/process
isolation, guest cancellation semantics, postcondition readback, restart
recovery, Developer ID packaging, or production `mac_task_run` enablement.
The channel remains an independently testable, fail-closed transport seam.
