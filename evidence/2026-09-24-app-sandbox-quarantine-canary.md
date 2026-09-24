# Physical App Sandbox quarantine canary

Date: 2026-09-24

## Result

The opt-in Auth → Edge → Broker D1 canary passed on the physical macOS host:

```sh
npm run probe:d1:app-sandbox:quarantine
```

The hostile task exercised a Perl double-fork/`setsid` descendant. The helper
returned an unknown outcome while the detached process was still alive outside
the recorded helper process and process group. The canary terminated only the
captured PID/start-time identity and verified that exact process was absent.
This confirms the process-containment gap; it does not claim the helper contained
or killed the descendant.

Afterward, the canary verified that the host `mac_task_run` capability was
disabled, closed the Broker and SQLite store, reopened them, and created a fresh
Broker/runner. The capability remained unavailable after restart, and a new
approved request was denied with `POLICY_DENIED`, its approval remained unused,
and no Job was linked. The unresolved host-task quarantine remained durable.

The restart path also exposed a ledger invariant issue: approval and Job targets
are bound to the admitted intent target, while a terminal Request may refine its
target to the canonical execution path. Startup validation now checks those
links against the unique intent audit evidence rather than the refined terminal
target. Focused request-link tests cover both the allowed refinement and a
mismatched approval target failing closed.

## Verification

- Physical D1 Auth → Edge → Broker quarantine canary: 1 passed, 0 failed.
- Full `npm test`: 1,219 passed, 16 skipped, 0 failed (1,235 tests).
- `npm run lint`: passed.
- `npm run verify:docs`: passed.
- `npm run verify:matrix`: passed.
- `npm run verify:process-boundaries`: passed with no unreviewed entries.
- `git diff --check`: passed.
- Reused helper executable SHA-256:
  `8531eae9911b19fb93018af962a8665acfed76f6608bcd5540cea29ff543432c`.
- `codesign --verify --deep --strict` on the helper bundle: passed.

## Limits

The test verifies quarantine and restart behavior after an observed escape. It
does not establish kernel-enforced process-tree ownership or descendant
containment. Public `mac_task_run` remains gated. The read-only completion audit
remains partial at 92% (2 requirement rows pass, 23 are open, 4 are blocked).
Developer ID/notarized release readiness, Accessibility authorization,
persistent service readback, production acceptance material, and the remaining
requirement-matrix gates are still outstanding.
