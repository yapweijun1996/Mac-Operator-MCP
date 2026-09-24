# Seatbelt fixed-script task runner physical rerun

Date: 2026-09-23

Status: PASS for the narrow fixed-script filesystem/network/environment/no-fork
probes; `sandbox-exec` remains deprecated and staging-only. This does not
remediate the App Sandbox double-fork escape recorded in
[`2026-09-23-app-sandbox-executor-rerun.md`](2026-09-23-app-sandbox-executor-rerun.md)
or enable public `mac_task_run`.

## Scope and result

- Host: physical Mac mini, Darwin 25.2, arm64, unprivileged user Broker.
- `npm run build` passed, including native adapters and TypeScript build.
- The Broker resolves a named `posix-sh-script` profile, reads the regular
  script as strict UTF-8, and binds its bytes to SHA-256. The Seatbelt runner
  rechecks that digest and passes the bounded source only over stdin to the
  fixed `/bin/sh -s --` path. Neither script source nor script path is placed
  in argv; stdin remains bounded and non-persisted by `ProcessSupervisor`.
- On this macOS host `/bin/sh` consults `/private/var/select/sh` and dispatches
  to the root-owned `/bin/bash` implementation. The rendered script policy
  permits only that fixed system implementation and keeps `process-fork`
  denied. The runner independently validates the protected system paths.
- The real system-published runner completed a Broker-owned script using only
  shell builtins. It wrote and read back a file inside the approved task root,
  while synthetic `.env` and sibling-root canaries were unreadable. `HOME` and
  `SSH_AUTH_SOCK` were absent from the task environment. A direct loopback TCP
  attempt was denied and the listening fixture observed zero connections.
  A second fixed script attempted a subshell; the kernel returned
  `fork: Operation not permitted`, the runner returned a non-success result,
  and the exact temporary child marker remained absent.
- Physical focused sandbox suite: 17 passed, 5 opt-in tests skipped, 0 failed.
- Full repository regression: 1,211 tests, 1,195 passed, 16 skipped, 0 failed.
- `npm run lint`, `npm run verify:docs`, and `npm run verify:matrix` passed.
- `npm run probe:sandbox` also passed its direct Seatbelt checks: allowed and
  denied reads/writes behaved as expected; `forkDenied` and
  `detachedChildMarkerAbsent` were both true; output and timeout bounds held.
- `npm run verify:completion` remains fail-closed and `partial` at 92%: 2/29
  requirement rows pass, 23 are open, 4 blocked, and 0 fail. Developer ID is
  absent, Accessibility is permission-denied, persistent labels are absent,
  and the production acceptance record is absent.
- `git diff --check` passed. No persistent service was installed or started.

## Limits

This proves one fixed system-published shell path on this host, not a supported
replacement for the deprecated Seatbelt API. The installed macOS SDK also says
that `sandbox_init` is deprecated and, when the current process is already
sandboxed, ignores a new profile and returns an error; nested Seatbelt is not a
viable way to repair the App Sandbox helper boundary. The runner's public
enablement remains `staging-only`; release signing, broader credential/
persistence/Docker isolation, external network policy, cancellation/restart
acceptance, and independent review remain open. The separate App Sandbox
process monitor still fails the double-fork/`setsid` adversarial case, so it
must remain gated.
