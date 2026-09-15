# Process inspection target binding evidence

- Source revision: `93daffb`
- Capture date: 2026-09-16 (Asia/Kuala_Lumpur)
- Host: macOS 26.2, Darwin 25.2.0, arm64
- Contract version: `0.1`

## Boundary exercised

`mac_process_inspect` now treats the requested PID as the result identity. The
Broker rejects a successful-looking adapter result when its returned `pid`
differs from the request argument, before response serialization or completion
audit. The rejection is a stable `CONFLICT` result and the request is persisted
as failed; the policy's bounded `process:all` domain does not permit an adapter
to substitute another process identity.

## Verification

```text
npx tsc -b --pretty false                         pass
node --test --test-name-pattern='mac_process_inspect' packages/broker/dist/broker.test.js
2 tests, 2 passed, 0 failed
npm run lint                                      pass (745 tracked files)
git diff --check                                  pass
```

The negative test injects a different PID from the process executor and checks
that no success is published, the request state is `FAILED`, and the audit pair
contains an authorized decision followed by a `CONFLICT` completion.

## Limitations

This is an adapter/Broker identity-boundary test. It does not prove that a PID
cannot be recycled by the operating system between native observations, nor
does it provide installed-service or remote revocation evidence. A native
start-time identity readback is still required for lifecycle-sensitive process
operations.
