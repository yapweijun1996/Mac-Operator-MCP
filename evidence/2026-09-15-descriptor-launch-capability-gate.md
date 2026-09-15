# Descriptor executable launch capability gate

Date: 2026-09-15
Source revision: `07ba885`
Host: Darwin 25.2.0, arm64, Node v25.5.0

## Result

The Broker now exposes a versioned, host-owned descriptor-execution
capability record. The record is available only when the protected native
adapter supplies both a descriptor launcher and a matching capability
attestation proving immutable executable selection and close-on-exec
behavior. Missing or malformed native support returns `available: false`;
`requireProcessDescriptorExecution()` maps that state to stable
`POLICY_DENIED` and never falls back to a pathname launch.

The current Darwin adapter exports neither the descriptor launcher nor the
capability attestation, so the capability remains unavailable. This preserves
the previously recorded finding that the public Darwin SDK has no supported
`fexecve`/`execveat` or executable-file-descriptor `posix_spawn` operation.

## Verification

```text
node --test packages/broker/dist/process-launch-capability.test.js
tests 3
pass 3
fail 0

npm run typecheck
exit 0

npm run lint
Style check passed for 671 tracked files.
```

The focused tests also reject incomplete attestation, unknown fields,
prototype-provided authority, and accessor-backed fields. No host configuration
or installed service was changed.

## Remaining gate

This is an explicit fail-closed capability boundary, not a descriptor launch
implementation. `VT-FS-02`, immutable snapshot alternatives, and production
`mac_task_run` enablement remain open until a reviewed native launcher or an
independently verified immutable executable snapshot is available.

## Rollback

Revert commit `07ba885`; no runtime or host state needs restoration.
