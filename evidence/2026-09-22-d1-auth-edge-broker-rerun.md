# D1 Auth-to-Edge-to-Broker physical canary rerun

- Date: 2026-09-22
- Scope: staging-only D1 OAuth grant, Edge MCP, Broker approval/Job, and physical task boundary
- Status: one end-to-end canary passed; live R1 remains unchanged
- Host boundary: owner-authenticated Auth, HTTPS Edge test server, unprivileged Broker, fixed system-published task executables

## Verification

The latest focused run was:

```text
npm run build && MOPS_REAL_SANDBOX=1 \
  node --test --test-timeout=120000 \
  --test-name-pattern='isolated D1 canary binds the Auth grant to Edge tools/list and owner-approved write' \
  packages/auth/dist/auth.test.js
```

Result: 1/1 passed, 0 failed, 0 skipped.

The canary binds the exact D1 grant to Edge authentication and MCP
`tools/list`, then exercises missing-approval denial with durable preview,
owner-approved atomic write and bounded patch readback, explicit local Git
staging/commit with staged-digest precondition failure, owner-bound queued Job
cancellation, and the opt-in physical `d1.printf`/`d1.sleep` task profiles.
The task path verifies fixed executable selection, bounded environment/output/
timeout, no-network and single-process ownership, active owner cancellation,
host-lifecycle Edge revocation to a recovery-preserving `UNKNOWN` Job, terminal
status readback, process metadata cleanup, and redacted audit evidence.

The test uses the explicit system-published `/usr/bin/printf` and `/bin/sleep`
allowlist. It is not generic repository-script execution and does not add a
public task scope to the live deployment.

## Limits and rollback

This is a disposable staging canary with temporary Auth/Broker state. It does
not prove Developer ID/notarization, App Sandbox production packaging,
root-helper installation, ChatGPT live D1 consent, public D1 tools/list, or
production task enablement. The current public deployment remains R1
read-only. Temporary state is removed by the test fixture.
