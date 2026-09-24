# Virtualization Task-Scoped VM Lifecycle — 2026-09-23

Status: SOURCE-LEVEL FRESH-VM CANDIDATE IMPLEMENTED AND REGRESSION-TESTED. No
native VM was booted, and no production task gate changed.

## Change

The Broker now serializes each virtualization task or guest-status recovery
inside a `fresh VM object -> start -> operation/result journal -> hard-stop`
cycle. Before task dispatch, the lifecycle requires a confirmed stopped state
and a fresh-instance result bound to the expected guest identity. If a runtime
VM is already running, it is hard-stopped before replacement. The task runner's
verified-result callback completes before teardown. A stop/reset error leaves
lifecycle state `unknown`, fails the current request as unresolved, and fences
later tasks until status recovery establishes a stable state.

`VirtualizationTaskRunner` now requires the Broker-owned lifecycle instance,
and binds it to the same guest identity used by its proof, image, and executor.
An otherwise valid runner assembled without that lifecycle remains unavailable;
it can no longer fall back to calling the executor directly.

The native adapter retains one Broker-owned handle and startup-bound
`VZVirtualMachineConfiguration`, but replaces the underlying
`VZVirtualMachine` object before every task. It recreates the virtio listeners
and fences old pending accepts. The VM configuration has no network,
directory-sharing, or serial device, and its disk attachment is read-only.
Apple documents that each VM stores a copy of its configuration and that a
read-only attachment prevents guest writes to the image. This supports the
source-level reset design, but does not prove actual guest reset behavior on
this host. The existing guest status ledger is memory-only, so a stopped guest
may no longer answer an uncertain task lookup. Such jobs stay `UNKNOWN`;
execution is never replayed.

See [Apple `VZVirtualMachine`](https://developer.apple.com/documentation/virtualization/vzvirtualmachine),
[Apple `init(configuration:queue:)`](https://developer.apple.com/documentation/virtualization/vzvirtualmachine/init%28configuration%3Aqueue%3A),
and [Apple read-only disk attachment semantics](https://developer.apple.com/documentation/virtualization/vzdiskimagestoragedeviceattachment/isreadonly?language=objc).

## Verification

- `npm run typecheck` — passed.
- Native Virtualization lifecycle module build — passed.
- Focused VM lifecycle, native adapter, task runner, startup, and attestation suites — 49 passed,
  0 skipped, 0 failed.
- `npm test` — 1,223 tests: 1,207 passed, 16 skipped, 0 failed; native build
  steps completed.
- The first full-suite attempt exposed a timing-sensitive process-supervisor
  test whose 150 ms child could exit before the observer sampled it. The fixture
  now keeps the descendant alive with inherited output descriptors closed; the
  isolated test and subsequent full suite pass, confirming unresolved outcome
  plus observed cleanup.
- No VM image was obtained or booted. No native VZ stop/start cycle, hostile
  guest descendant probe, Developer ID release, or production acceptance was
  exercised.

## Release gate

Keep public `mac_task_run` and VT-SBX-01/02 disabled. Before adoption, validate
repeated native start/run/stop cycles on an approved image, including a hostile
descendant and restart/result-loss cases; establish that mutable guest state
does not cross task boundaries; and retain `UNKNOWN` without replay whenever
result durability or stop readback is uncertain. The App Sandbox
double-fork/`setsid` escape remains unresolved.
