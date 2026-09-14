# Process exit observation-window evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Status: partial MOP-086 evidence; production task enablement remains disabled

## Boundary

Strict governed task exits now begin process-tree proof at the child `exit`
event instead of waiting for Node's `close` event. A detached child can keep
stdout/stderr pipes open after the root exits, so waiting for `close` alone can
miss it after it has been reparented. The Broker now records process-group
survival at `exit`, performs a second native descendant observation after one
bounded poll interval, and waits for stream `close` only to finish output
drain. Any live group, descendant, observer failure, truncation, or target
replacement remains `UNKNOWN_OUTCOME`.

## Verification

- Strict `/usr/bin/printf` exit remains `SUCCEEDED` only after the exit-anchored
  observation window.
- A Darwin Python fixture that forks a child, exits the root immediately, and
  keeps the child alive is rejected as `UNKNOWN_OUTCOME`; the child is drained
  during supervisor close.
- Focused process-supervisor suite: 20/20 passed.
- Full `MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`: 478 tests, 477
  passed, 0 failed, 1 explicit skip.

## Limits

The observation window is bounded and not a kernel-held process or mount
namespace. A descendant created after the final window, remount races, real
credential-content isolation, and production sandbox support remain open.
