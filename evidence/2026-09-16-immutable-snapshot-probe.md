# macOS immutable snapshot probe

- Date: 2026-09-16
- Host: Darwin 25.2.0 / macOS 26.2, arm64, user `yapweijun`
- Scope: unprivileged executable snapshot boundary for `ProcessSupervisor`

## Probe result

The host permits the current user to set and clear the user immutable flag
(`UF_IMMUTABLE` / `uchg`) on a user-owned file. A write is rejected while the
flag is set, but the same user can clear the flag and replace the file. This
does not provide an attacker-resistant immutable snapshot.

The system immutable flag (`SF_IMMUTABLE` / `schg`) could not be set by the
unprivileged user:

```text
flag_code=1
flag_output=chflags: .../probe.bin: Operation not permitted
write_code=0
write_output=replacement
flags=- mode=0 owner=yapweijun
```

The probe used a temporary user-owned file, did not open repository or
credential content, and did not mutate Broker state.

## Decision

macOS immutable flags do not establish the executable snapshot boundary needed
by the unprivileged Broker on this host. `uchg` is reversible by the file
owner, while `schg` requires a privilege the Broker must not possess. The
Broker must not claim immutable selection or replace descriptor execution with
a pathname snapshot guarded only by file flags. Descriptor-required execution
therefore remains unavailable until a supported kernel primitive or a
separately authenticated, allowlisted helper owns the stronger boundary.

## Verification

The descriptor-exec SDK probe independently showed that both
`posix_spawn("/dev/fd/<fd>", ...)` and `execve("/dev/fd/<fd>")` return
`Permission denied` on this host. Together these probes leave the native
descriptor launcher fail-closed and keep the privileged helper boundary
explicit rather than silently weakening executable identity.
