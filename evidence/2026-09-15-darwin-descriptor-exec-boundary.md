# Darwin descriptor-exec boundary evidence

Date: 2026-09-15
Host: Darwin 25.2.0, arm64, Node v25.5.0

## Boundary

`ProcessSupervisor` currently opens and hashes an approved executable, then
launches it by canonical pathname and rechecks the pathname identity around
startup. That closes ordinary replacement detection but does not make the
kernel's executable selection atomic. The next hardening step must therefore
not be described as complete until the host can execute an already-open file
descriptor or an equivalently isolated immutable snapshot.

## Host probe

The installed Command Line Tools SDK has no public `fexecve` or `execveat`
declaration, and its `spawn.h` has no executable-file-descriptor API. A direct
probe of the Darwin descriptor namespace also fails:

```text
/bin/sh -c 'exec /dev/fd/3 fd-probe' 3</usr/bin/printf
status=126
/bin/sh: /dev/fd/3: Permission denied
```

The probe uses a read-open descriptor for a known system Mach-O executable and
does not involve Broker policy or user-controlled content. The result is a
host capability limitation, not evidence that `/dev/fd/N` is a safe fexec
substitute.

## Decision

Keep descriptor/fexec execution unavailable and fail closed. Do not add a
pathname-based shim and call it fexec. Any future implementation must provide
one of the following with real-host evidence:

1. a supported kernel/native descriptor-exec primitive with identity and
   close-on-exec proof; or
2. an immutable, Broker-owned executable snapshot whose code-signing and
   lifecycle guarantees are independently verified.

Until then, `VT-FS-02` and the `mac_task_run` production gate remain open. The
existing path launch, no-follow checks, content digest, and pre/post startup
revalidation remain compensating controls only.

## Rollback

Remove this evidence note and its references; no runtime or host configuration
was changed.
