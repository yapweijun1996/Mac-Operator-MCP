# Native Virtualization Guest Lifecycle Evidence

Date: 2026-09-15
Host: physical Darwin arm64 development host
Implementation commit: `40f0461`

## Native boundary

`virtualization_guest_lifecycle.node` is a separate Objective-C++ N-API
artifact linked against the host `Virtualization.framework`. Its startup-only
constructor revalidates a canonical owner-only image through device, inode,
size, and SHA-256 identity, creates a read-only block attachment, uses a
serial Virtualization.framework queue, configures no host network or directory
sharing, and exposes one bounded virtio-socket device for the future guest
agent. Start and stop are asynchronous and return an adapter-owned random
boot ID; status is asynchronous and maps intermediate/error states to
`unknown`; close refuses to discard a non-stopped machine. Native failures are
returned as generic messages so framework details do not enter Broker output.

The TypeScript adapter loads only the protected, digest-bound artifact,
rechecks the startup-owned image before each operation, never accepts an MCP
path or executable, and maps malformed identity, cancellation, transport, and
close outcomes to the Broker lifecycle contract. It is still disabled unless
the independent host evidence gate is enabled.

## Host result

The artifact compiled on the physical host with the active Node headers and
macOS SDK and passed `/usr/bin/codesign --verify --strict`. A synthetic
owner-only image was intentionally used only for a configuration preflight;
the host rejected VM creation because the current process lacks a valid
entitled/bootable Virtualization.framework configuration. No VM boot was
attempted and no guest isolation guarantee is inferred.

## Verification

Focused lifecycle and native-adapter tests: 9/9 pass.

Full physical-Darwin regression:

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
tests 551
pass 551
fail 0
cancelled 0
skipped 0
```

Static checks: `npm run typecheck` and `npm run lint` pass.

## Remaining release evidence

A production host still needs a Developer ID-signed, virtualization-entitled
Broker runtime, a reviewed bootable guest image, an authenticated virtio guest
server, signed attestation production, and independent filesystem, network,
credential, and process-tree isolation tests before VM-backed task execution
can be enabled.
