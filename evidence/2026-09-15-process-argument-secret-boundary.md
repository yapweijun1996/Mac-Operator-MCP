# Process argument secret boundary evidence

Date: 2026-09-15
Source commit: `17d10e2`
Host: physical Darwin arm64 development host
Scope: Broker task-profile and child-process argument handling

## Finding

Task profile argument patterns and fixed environment validation did not by
themselves prevent a caller or profile author from placing credentials in
process arguments. Arguments are observable through the host process table,
so this would bypass the existing file and environment secret boundaries.

## Implementation

The shared secret policy now rejects credential-bearing argument names such as
`--token`, `--password`, `--api-key`, `--private-key`, and equivalent
separator-delimited forms before execution. Known token and authorization
signatures are also rejected in arguments. The check runs when fixed profile
arguments are loaded, after fixed and requested task arguments are combined,
and again in `ProcessSupervisor` immediately before `spawn`.

## Verification

- Secret-policy tests pass 5/5, including sensitive option names, assigned
  values, authorization headers, and ordinary non-sensitive arguments.
- Task-profile tests pass 4/4, proving fixed and requested arguments fail
  closed before profile resolution can dispatch them.
- Process-supervisor tests pass 30/30, proving the final spawn boundary also
  rejects a sensitive option.
- The non-overlapping physical-Darwin regression passes 489/489 with 0
  skipped tests.
- `npm run build`, `npm run typecheck`, `npm run lint`, `npm run verify:contracts`,
  `npm run verify:canonical:native`, `npm audit --audit-level=high`, and
  `git diff --check` pass.

## Boundary

This prevents known credential-bearing option names and signatures from being
placed in child argv. It does not infer that arbitrary opaque strings are
secrets, and it does not replace profile argument allowlists, empty
environments, sandbox isolation, or a separate Broker-managed credential
workflow.

## Rollback

Revert commit `17d10e2`. The existing environment, filesystem, and output
redaction boundaries remain unchanged; only the argument-level denial gate is
removed.
