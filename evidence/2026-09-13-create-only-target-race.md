# Create-only target race evidence

Status: PARTIAL filesystem/write-boundary evidence for MOP-036 / MOP-046 / VT-FS-02

## Scope

The fixture uses a temporary authorized root, a synthetic outside canary, and a worker that repeatedly removes the target, creates an attacker regular file, replaces it with a symlink to the outside canary, and removes it again. The Broker native writer is asked to create the target with `createOnly=true` and a unique temporary name. No real user data is used.

## Evidence

- Host: Darwin arm64, macOS 26.2 build `25C56`, Node `v25.5.0`.
- Test: `descriptor-backed create-only write resists a concurrent target create and symlink swap`.
- Iterations: 500 bounded attempts; at least one Broker create succeeded, and competing target states were rejected or left untouched.
- Native boundary: `openat(... O_NOFOLLOW|O_EXCL)`, identity precondition, `renameatx_np(..., RENAME_EXCL)`, parent fsync, and descriptor readback.
- Outside canary: content remained exactly `outside` after the attacker stopped.
- Source: `packages/broker/src/filesystem-inspector.test.ts`.
- Source SHA-256: `0f85c1f73bc34be8866123275e9a8d6e657ecb58bda15e5afa06a48e5134bf3c`.
- Command: `npm test -- --test-name-pattern='concurrent target create and symlink swap'`.

## Limits

This proves the tested create-only same-directory race behavior on the recorded host. It does not prove all directory rename/mount/remount races, Unicode/case normalization, crash durability, or complete write recovery. The write capability remains disabled and release-gated.
