# Process inspection start-time identity evidence

- Source revision: `f01ddb8`
- Capture date: 2026-09-16 (Asia/Kuala_Lumpur)
- Host: macOS 26.2, Darwin 25.2.0, arm64
- Contract version: `0.1`

## Boundary exercised

The native process inspector now reads the requested process identity before
and after collecting bounded metadata. The Broker rejects the observation if
the PID or native `startTimeMicros` changes, preventing a PID-reuse result from
being returned as the original target. The start time remains an internal
lifecycle guard and is not exposed in the public process result.

## Verification

```text
npx tsc -b --pretty false                                      pass
node --test --test-name-pattern='process inspector|mac_process_inspect' \
  packages/broker/dist/process-inspector.test.js \
  packages/broker/dist/broker.test.js
8 tests, 8 passed, 0 failed
node --test --test-timeout=120000 \
  packages/broker/dist/l0-l1-host-readback.test.js
1 test, 1 passed, 0 failed
npm run lint                                                   pass (746 tracked files)
git diff --check                                               pass
```

The focused unit test covers stable identity, changed start time, and a PID
change. The physical Mac readback confirms the current native process can be
inspected through the guarded path without exposing argv or environment.

## Limitations

The before/after fence narrows the observation race but is not a kernel-held
process handle and cannot prove identity outside those two native reads. It
does not authorize process mutation, guarantee post-readback liveness, or
provide installed-service and remote revocation evidence.
