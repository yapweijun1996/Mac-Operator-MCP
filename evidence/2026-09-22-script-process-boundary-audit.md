# Repository-script process boundary audit

Date: 2026-09-22
Scope: probe, verification, and host-readiness scripts that invoke child processes

## Result

`npm run verify:process-boundaries` now audits both production runtime sources
and repository scripts. The current output reports:

- 3 production child-process source files;
- 11 repository-script child-process files;
- explicit `shell: false` in every reviewed invocation;
- explicit working-directory and minimal-environment boundaries;
- bounded timeout and output handling, with cancellation/termination for
  asynchronous spawned probes;
- 0 unreviewed production entries;
- 0 unreviewed script entries.

The reviewed scripts include host readiness, completion auditing, temporary
LaunchAgent probes, App Sandbox and root-helper probes, the Git boundary probe,
and the repository style checker. `execFile` calls also carry an explicit
`shell: false` option; no child process relies on Node's default implicitly.
The checker now fails if a reviewed script loses its explicit cwd, minimal env,
timeout/output bound, or asynchronous kill path.

## Safety boundary

This is a source-level audit. It does not grant permissions, install services,
execute a production helper, read secrets, or enable MCP capabilities. The
real probes remain separately opt-in and retain their own host-state gates.
