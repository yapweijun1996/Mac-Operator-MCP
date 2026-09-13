# Task isolation proof gate evidence

Status: PARTIAL Broker admission hardening for MOP-086 / VT-SBX-01 / VT-SBX-02

## Change

`TaskRunner` now carries a versioned `TaskIsolationProof`. Broker admission rejects an available runner unless the proof has all of these exact claims: the selected sandbox profile, enforced filesystem policy, enforced network policy, isolated credentials, and owned process-tree cleanup. The proof reference is bounded and unknown fields are rejected. Dispatch checks the proof again after profile resolution so a proof for another sandbox profile cannot be reused.

## Evidence

- Source: `packages/broker/src/task-runner.ts`, SHA-256 `135b0ad9a197e6f733cdf682faae3a08bae0e81c81cd1d8c34cd414b49a4d4fc`.
- Broker integration: `packages/broker/src/broker.ts`, SHA-256 `105b42351e485df7542aee4ef42d31ebdce8634ebdde4746975ae7831a502028`.
- Tests: `packages/broker/src/task-runner.test.ts` SHA-256 `eb1135c99fa100af56c8b4294b74eb626b042dcb2e6b4d90effee4031662d842`; `packages/broker/src/broker.test.ts` SHA-256 `20f1b009bf9939a8f0d152e7c80176111aeb8ad970efe6b7f54afeeff905fd52`.
- `npm run typecheck` — pass.
- `npm test` — 234 passed, 0 failed.
- Negative cases pass for missing proof, incomplete credential status, invalid evidence reference, unknown fields, and sandbox-profile mismatch.

## Limits

The test runner uses a synthetic test-only proof to exercise the Broker gate. This record does not prove any OS sandbox, credential isolation, network enforcement, persistence prevention, or process-tree ownership. The default `FailClosedTaskRunner` remains unavailable and `mac_task_run` remains disabled until independent real-Mac evidence satisfies MOP-086.
