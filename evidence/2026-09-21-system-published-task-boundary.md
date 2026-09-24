# System-published task execution boundary

- Date: 2026-09-21
- Scope: MOP-045 / MOP-102 restricted host task execution
- Status: implemented and opt-in physical evidence; not public `mac_task_run` enablement
- Host: Darwin arm64, unprivileged Broker

## Boundary

`SandboxExecTaskRunner` now supports a second executable-selection mode in
addition to the existing descriptor-backed mode. The
`system-published` mode requires all of the following Broker-owned conditions:

- explicit `systemPublishedExecutableAllowlist`;
- the selected executable is in that allowlist;
- the selected executable and `/usr/bin/sandbox-exec` are root-owned,
  non-symlink, non-group/other-writable, and have no setuid/setgid bits;
- every canonical ancestor directory is root-owned, non-symlink, and not
  group/other writable;
- macOS, an unprivileged Broker, explicit host evidence acceptance, and a
  proof with `executableSelection: system-published-root-owned-v1`;
- the existing deny-default Seatbelt, empty environment, timeout, output cap,
  cancellation, process-tree, filesystem-volume, and result-verification gates.

This mode does not accept MCP-selected executable paths, user-owned binaries,
interpreters, dispatch launchers, repository scripts, or an arbitrary shell. Descriptor mode and
the generic task path remain fail-closed when their native capability is not
available. The public task scope and policy remain unchanged.

## Physical evidence

After building the native and TypeScript artifacts, run:

```text
npm run probe:sandbox:system-published
```

The opt-in physical run passed the new real task case:

- `/usr/bin/sandbox-exec` launched `/usr/bin/printf` through the Broker-owned
  deny-default Seatbelt profile;
- output was `real-system-published`;
- the result was `SUCCEEDED` with `verification.status=verified`;
- no user-owned executable, shell, repository script, permission, or service
  state was changed.

The default focused sandbox suite passes 15/21 with 6 explicit skips; the
opt-in physical run passes 16/21 with 5 separately gated real-sandbox cases
skipped. The complete repository regression passes 969 total tests: 954
passed, 15 explicit skips, and 0 failures. Build, lint, typecheck,
documentation-link, verification-matrix, and diff checks also pass.

## Release boundary

This evidence supports only a restricted system-published executable profile.
It does not prove arbitrary developer task execution, child executable
coverage for profiles that fork, credential isolation beyond the tested
single-process profile, public policy materialization, approval/readback for
task mutations, or release of `mac_task_run`.

## Rollback

Remove the `system-published` runner mode, proof field, allowlist option, test
gate, package script, and this evidence. Descriptor-mode behavior and the
existing default-disabled task runner remain unchanged.
