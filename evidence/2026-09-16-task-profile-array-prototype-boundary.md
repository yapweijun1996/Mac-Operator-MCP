# Task profile array prototype boundary evidence

Date: 2026-09-16
Source revision: `a3625e1`
Host: physical Darwin arm64 (`yaps-Mac-mini.local`, Darwin 25.2.0)
Node: `v25.5.0`

## Decision

Task profile validation now requires every profile-owned string array and task
request argument array to use the native `Array.prototype`. Existing dense
descriptor checks continue to reject symbols, hidden fields, sparse slots,
accessors, and non-string values. This prevents custom array methods from
altering executable arguments, authorized roots, or network destinations before
the task profile is resolved.

The change preserves explicit executable/cwd/argument/environment/network
budgets, `credentialPolicy: none`, and the disabled-by-default task runner.

## Verification

- Task profile suite: 6/6 passed, 0 skipped, 0 failed.
- Full default repository regression: 894 total, 880 passed, 14 explicit
  skips, 0 failed.
- Build, typecheck, lint, and `git diff --check` passed.
- Hostile custom-prototype fixed-argument and request-argument arrays fail
  closed during validation.

## Remaining gate

This closes custom-prototype authority for task profile arrays. It does not
provide descriptor-backed execution, credential-isolation proof, VM/guest
isolation, production packaging, or task capability enablement.
