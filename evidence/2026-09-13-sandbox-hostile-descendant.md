# Real macOS sandbox hostile-descendant readback

- Source commit: `01a26ba32c2f22dcca3c67d71628189989d572b4`
- Working tree: clean before this evidence document was added
- Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
- Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Scope: opt-in `SandboxExecTaskRunner` smoke only; no service install, privilege escalation, credential access, or network beyond existing loopback fixtures

## Procedure

The test resolved a temporary canonical root and ran `/usr/bin/perl` through
the Broker-owned default `single_process` profile. The inline fixture attempted
to `fork()`, call `setsid()` in the child, write the child PID to a marker under
the authorized root, and sleep briefly. A successful fork would therefore have
left a test-owned marker and returned `fork-succeeded`.

## Observed result

- `MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js`: 8 tests, 8 passed, 0 failed, 0 skipped
- Hostile fixture result: non-success (`EXECUTION_FAILED`), exit code `42`, stdout `fork-denied`, no marker (`ENOENT`)
- `MOPS_REAL_SANDBOX=1 npm test`: 373 tests, 373 passed, 0 failed, 0 skipped
- Default `npm test`: 373 tests, 370 passed, 0 failed, 3 opt-in real-sandbox tests skipped
- `npm run typecheck -- --pretty false`: passed
- `npm run verify:contracts`: passed (44 unique contracts)
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities
- `git diff --check`: passed

## Interpretation and limits

This is host evidence that the default deny-default profile blocks a direct
fork before a child can call `setsid()` or create a marker in the authorized
root. It does not prove `owned_group` enforcement, post-snapshot session escape
resistance, crash/restart cleanup, credential-content isolation, persistence or
Docker isolation, physical remount behavior, or production task-runner safety.
`SandboxExecTaskRunner` remains opt-in and `mac_task_run` remains disabled.

Source hash at capture:

```text
05e77a61ca35a6c7f75bdb173f76e057ffabbd54efaade38f991520ca94d32d3  packages/broker/src/sandbox-profile.test.ts
```
