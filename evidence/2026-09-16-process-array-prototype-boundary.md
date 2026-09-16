# ProcessSupervisor argument array prototype boundary evidence

Date: 2026-09-16
Source revision: `6e3a4dc`
Host: physical Darwin arm64 (`yaps-Mac-mini.local`, Darwin 25.2.0)
Node: `v25.5.0`

## Decision

ProcessSupervisor now requires its argument vector to be a dense string array
with the native `Array.prototype` before executable validation or child spawn.
This prevents custom array methods or iterators from changing the bounded
argument, secret-screening, and process-launch decision.

The existing explicit cwd, executable identity, environment allowlist, timeout,
output cap, cancellation, and process-tree ownership controls are unchanged.
Descriptor-required execution remains fail-closed when the native launcher is
unavailable.

## Verification

- ProcessSupervisor suite: 44/44 passed, 0 skipped, 0 failed.
- Full default repository regression: 894 total, 880 passed, 14 explicit
  skips, 0 failed.
- Build, typecheck, lint, and `git diff --check` passed.
- A hostile custom-prototype argument vector is rejected before any child
  process starts.

## Remaining gate

This closes custom-prototype authority for process argument vectors. It does
not provide the missing descriptor-backed launcher, production task isolation,
or capability enablement.
