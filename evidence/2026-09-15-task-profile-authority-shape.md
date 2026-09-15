# Task-profile authority shape evidence

Date: 2026-09-15
Source commit: `956e95f`
Host: physical Darwin arm64 development host

## Boundary

Named task profiles define executable, cwd, filesystem, network, environment,
argument, credential, process-tree, and budget authority. Task-run requests
select a named profile but must not smuggle authority through inherited,
accessor, sparse, symbolic, or unknown fields.

## Implementation

`TaskProfileRegistry` now rejects non-plain profile records and unknown fields,
requires dense bounded string arrays for paths, arguments, and network
destinations, and keeps environment records data-only. `validateTaskRunArguments`
and `TaskProfileRegistry.resolve` apply the same boundary before resolving the
Broker-owned executable/cwd and copy accepted argument arrays before execution.

## Verification

- The focused task-profile/task-runner suite passes 18/18.
- Hostile tests cover inherited profiles and requests, accessor fields,
  symbolic fields, sparse arrays, and unknown profile fields.
- The non-overlapping package regression passes 513 total (507 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This closes local task-profile representation integrity only. It does not prove
credential/persistence isolation, sandbox enforcement, VM boot or guest
isolation, production signing, or `mac_task_run` enablement.

## Rollback

Revert commit `956e95f`. No MCP wire schema or persisted ledger format changes
are introduced.
