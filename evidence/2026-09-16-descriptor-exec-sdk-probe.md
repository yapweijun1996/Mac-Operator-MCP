# Descriptor-exec SDK probe

- Date: 2026-09-16
- Host: Darwin 25.2.0 / macOS 26.2, arm64, Node v25.5.0
- Scope: native child-process executable selection boundary

## Probe result

The installed macOS 26.2 SDK exposes descriptor-relative cwd actions:
`posix_spawn_file_actions_addfchdir` and `posix_spawn_file_actions_addinherit_np`.
It does not expose an executable-file-descriptor `posix_spawn` operation. A
compiled probe opened `/bin/pwd` and `/tmp`, inherited the executable FD, used
`addfchdir`, and attempted `posix_spawn("/dev/fd/<fd>", ...)` with
`POSIX_SPAWN_CLOEXEC_DEFAULT`. The host returned:

```text
spawn:Permission denied
PROBE_EXIT:16
```

An independent `fork`/`execve("/dev/fd/<fd>")` probe also returned
`exec:Permission denied`. The probe used only `/bin/pwd` and `/tmp`; it did not
open repository or credential content and did not mutate Broker state.

## Decision

The Broker must keep `darwin-descriptor-exec-v1` unavailable. Cwd descriptor
support is not executable descriptor support, and `/dev/fd` is not an accepted
fexec substitute on this host. `ProcessSupervisor` therefore must not wire a
pathname or `/dev/fd` shim into `descriptorSpawnAdapter`. Production task
execution remains fail-closed until a supported kernel primitive or an
independently verified immutable executable snapshot is available.

## Verification

Existing `process-launch-capability` and `ProcessSupervisor` tests continue to
reject descriptor-required execution before any child spawn. The complete
repository regression remains the authoritative runtime check.
