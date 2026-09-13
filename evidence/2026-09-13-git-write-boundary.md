# Governed Git Write Boundary Evidence

- Date: 2026-09-13
- Source commit: `e1348f0`
- Repository state: dirty after the source commit because documentation updates are pending; no production policy change
- Scope: local Broker and Git inspector prototype on the development Mac
- Policy state: `mac_git_stage` and `mac_git_commit` are implemented but disabled by the default policy

## Boundary implemented

The Broker exposes two mutation plans behind the existing approval and Job lifecycle:

- `mac_git_stage` accepts a bounded list of explicit literal relative paths under an authorized project root.
- `mac_git_commit` commits only the already staged index and optionally requires an exact staged-diff SHA-256 precondition.

Both plans bind the project target, arguments, policy version, approval, mutation intent, idempotency key, and Job execution lease. They revalidate authority before dispatch and map timeout, cancellation, output overflow, target identity changes, command failure, and unresolved postconditions to stable failures or `UNKNOWN` Job state.

The inspector uses a fixed `/usr/bin/git` command surface with an explicit empty/safe environment and bounded timeout/output. Hooks, fsmonitor, optional locks, signing, external integrations, and network behavior are disabled. No push, reset, remote mutation, shell expansion, or arbitrary Git subcommand is exposed.

Before and after mutation, the boundary checks canonical project identity and path identities. Stage rejects traversal, `.git`, secret paths, symlink components, and target swaps. Results expose only sanitized paths, hashes, commit/parent identities, index state, working-tree state, warnings, and truncation metadata; raw staged content is never returned or audited.

## Verification performed

- Validator tests reject traversal, `.git`, secret paths, unsafe commit control characters, and malformed staged-diff hashes.
- Inspector boundary tests assert fixed argv, explicit path staging, no `--all`, no push/reset command surface, no-verify/no-gpg-sign commit behavior, staged-diff binding, HEAD/parent readback, and empty-index postconditions.
- Broker integration test verifies trusted-write approval binding, mutation intent, generic Job creation/lease dispatch, staged readback, completion audit, and idempotency linkage.
- Commands run after implementation: `npm test` (251 passing), `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev --audit-level=high`, and `git diff --check`.

## Limits and remaining release work

This is controlled source/fake-boundary evidence, not production enablement. No real project was mutated and no real-Mac temporary-repository workflow was used. The contract files intentionally remain `planned`; runtime policy remains disabled. Real-Mac repository compatibility, crash-window and concurrent-index coverage, remount durability, external-actor attribution, stronger redaction corpus, and final readback/recovery evidence remain open under `MOP-046`, `MOP-047`, `VT-GIT-01`, `VT-REL-01`, `VT-AUD-01`, and `VT-DOS-01`.
