# HTTPS Edge mutation authority evidence

Date: 2026-09-16
Source revision: working tree after `npm run build` and commit pending
Host: Darwin arm64, Node.js 25.5.0

## Boundary exercised

The authenticated MCP client connects to the HTTPS Edge. The Edge discovers
the Broker projection, sends the signed mutation over local IPC, and the
Broker owns approval, Job, kill-switch, revocation, and final result state.

## Evidence

- `packages/edge/src/edge-broker-https.test.ts` enables the otherwise disabled
  `mac_write_file_atomic` contract only with a bounded write root and a
  single-use `trusted_write` approval.
- The custom test executor flips the Broker `mutations` kill switch while the
  write is active and returns a worker-shaped result. Broker authority
  revalidation rejects publication as `CANCELLED`, persists the write Job as
  `UNKNOWN`, and no target file is created.
- A queued write Job is created with Edge provenance, then the same
  persistence transaction that enables the `mutations` kill switch cancels it.
  `mac_job_status` is read back through HTTPS -> IPC -> Broker and reports the
  terminal `cancelled` state.
- A second queued write Job is cancelled by `Broker.revokeEdge`; the persisted
  state is checked before the revoked Edge attempts another request.
- The same MCP session then attempts `mac_health` after Edge revocation. The
  cached capability projection keeps routing available, while Broker returns
  the stable `REVOKED` result. A repeated signed request remains
  `REPLAY_DENIED` before revocation.

## Verification commands

```text
npm run typecheck -- --pretty false
node --test packages/edge/dist/edge-broker-https.test.js
node --test packages/edge/dist/*.test.js
```

Results: 2/2 focused HTTPS tests pass; complete Edge suite 66/66 passes.

## Limits

This is deterministic authority-boundary evidence with a controlled executor;
it is not physical filesystem durability evidence, a production launchd
deployment, or proof that an arbitrary external worker can be terminated
after an OS-level kill race.
