# App Sandbox shared-container admission follow-up

Date: 2026-09-23

Status: PARTIAL — source-level admission is serialized and fails closed after
an uncertain helper outcome; OS-enforced task isolation and production use
remain unproven.

## Finding

`NativeAppSandboxTaskExecutor` materializes each authorized filesystem root
under a random per-run directory beneath one configured `containerRoot`. The
signed helper has the `com.apple.security.app-sandbox` entitlement. Apple
documents that a sandboxed app has unrestricted read/write access to its own
container ([Protecting user data with App Sandbox](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox)).
Consequently, separate `0700` directories do not provide task-to-task access
control when tasks run under the same user and helper identity. Concurrent
helper runs could expose each run's staged files to the other run.

The physical double-fork/`setsid` probe separately established that a task
descendant can outlive the helper response. Releasing the shared container to
a later task after `UNKNOWN_OUTCOME` would therefore also leave a possible
cross-run window.

## Change

The Broker-owned `AppSandboxRunAdmission` permits only one active helper run.
It permanently rejects further runs from the same executor instance after an
`UNKNOWN_OUTCOME` response or a failure after helper spawn. Pre-spawn failures
may release admission because no task process was started. After quarantine,
the executor and runner report `available: false` and `publicEnablement:
unavailable`. This is a fail-closed reduction in cross-run exposure, not a
process-containment proof.

## Verification

- Admission unit tests: 2/2 pass (overlap rejection, then safe reuse; uncertain
  outcome poisons later admission).
- Runner quarantine integration coverage: 1/1 pass; availability turns off and
  task execution is rejected before snapshot preparation.
- `npm run build`: passed, including native addons and TypeScript build.
- Focused App Sandbox suite: 15/15 pass.
- `npm test`: 1,212 passed, 16 skipped, 0 failed.
- `npm run lint`: passed for 821 tracked files.
- `npm run verify:docs`: passed for 33 README local links and 8 required
  runbooks.
- `npm run verify:matrix`: passed for 29 targets, 25 threats, 31 tasks, and 19
  evidence references.
- `git diff --check`: passed.

No physical helper execution, service installation, VM boot, permission change,
or capability enablement was performed. The in-memory quarantine does not
survive Broker restart, and the original `setsid` escape remains. VT-SBX-01/02
and public `mac_task_run` remain gated; overall completion remains 92%.
