# Process Quota Isolation Evidence

Date: 2026-09-15
Source commit: `a135396`
Host: physical Darwin arm64 development host

## Implemented boundary

The shared Broker-owned `ProcessSupervisor` now counts both active and pending
starts by canonical executable path, in addition to its global process pool.
The default per-executable cap is 4 and the constructor accepts only bounded
values from 1 through 64. A saturated executable returns retryable
`CONFLICT`, while another executable can use remaining global capacity.
Capacity is released after normal completion, cancellation, startup abort,
unknown-outcome drain, and close.

## Verification

- Focused ProcessSupervisor regression: 26/26 pass.
- Tests prove invalid quota rejection, same-executable isolation, another
  executable using available global capacity, and correct counting of four
  concurrent starts.
- Complete physical-Darwin regression with install, sandbox, and Keychain
  gates: 592/592 pass, 0 skipped, 0 failed.
- `npm run build`, `npm run typecheck`, `npm run lint`, contract verification,
  native canonical JSON verification, and `git diff --check` pass.

## Remaining boundary

This closes shared per-executable process admission only. Adapter-specific
semantic quotas, disk/depth budgets, kernel-level resource limits, and final
release acceptance remain open.

## Rollback

Revert `a135396`. The shared ProcessSupervisor would retain only its global
pool and would no longer isolate active starts by executable.
