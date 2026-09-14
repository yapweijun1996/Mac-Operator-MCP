# Virtualization Guest Virtio Connector Evidence

Date: 2026-09-15
Host: physical Darwin arm64 development host
Implementation commit: `b8551d6`

## Native connector boundary

The native lifecycle artifact now exposes a Broker-owned
`exchangeGuestFrame(handle, port, frame, responseCap, timeout)` operation over
`VZVirtioSocketDevice.connectToPort`. The connector accepts only a startup-held
VM handle, a bounded guest-owned port, and a bounded byte frame. It wraps the
request and response in one four-byte length-prefixed frame, uses a monotonic
deadline for connect/write/read, rejects empty or oversized responses and
trailing data, protects the socket from SIGPIPE, and releases the
`VZVirtioSocketConnection` on success, failure, timeout, or callback race.
Native errors are generic and do not expose framework or path details.

`NativeVirtualizationGuestChannel` adapts this operation to the existing
`VirtualizationGuestTransportClient`, which still owns HMAC authentication,
freshness, replay admission, request/response binding, output redaction, and
status recovery. The guest agent remains the only component that can interpret
the signed payload; no host path, executable, credential, or arbitrary command
is sent over virtio.

## Verification

Focused lifecycle/native-adapter/channel tests: 10/10 pass.

Full physical-Darwin regression:

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
tests 552
pass 552
fail 0
cancelled 0
skipped 0
```

The native artifact compiled with the active macOS SDK and passed
`/usr/bin/codesign --verify --strict`. The current host still rejects the
synthetic VM configuration before a VM can be created, so no guest connection
or task execution was attempted. This evidence proves the connector's native
boundary and bounded framing implementation, not a running guest server or
independent VM isolation.
