# Runtime Contract-Integrity Evidence

Date: 2026-09-15
Source revision: `2dedae0`
Host: physical Darwin arm64 development host

## Implemented boundary

The Edge `ToolContractRegistry` now requires a regular, non-symlink contract
directory that is not writable by group or other users. Each contract file is
checked before opening and after reading for regular-file type, mode, and
device/inode identity. The directory is checked again after the complete
bounded load. A package or target swap therefore fails closed before the
contract is exposed to MCP registration; the Broker remains the final
authorization authority for every request.

## Verification

- Focused contract-registry regression: 5 pass, 0 fail.
- Physical-Darwin command
  `MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
  passes 598/598 tests with 0 skips and 0 failures.
- `npm run lint`, `npm run verify:contracts`,
  `npm run verify:canonical:native`, and `git diff --check` pass.

## Remaining boundary

This protects the local contract supply path but does not prove Developer ID
provenance, notarization, or installed-service package integrity. MCP schemas
remain descriptive; Broker authorization and target checks are authoritative.

## Rollback

Revert source revision `2dedae0`. Contract loading would retain the prior
symlink/size/UTF-8 checks but would no longer reject writable package paths or
perform directory/file mode and inode readback.
