# Process argument secret-policy boundary evidence

Date: 2026-09-15
Source revision: `7231964`

## Boundary

The Broker's argv policy now applies sensitive-option-name matching only to
arguments that are syntactically explicit Unix options (`-name` or
`--name`). It continues to scan every argument for concrete token and
credential signatures. This preserves denial of credential-bearing options
while allowing a bounded shell-script argument to reference a canary variable
such as `MOP_CONTROLLER_SECRET-unset` without treating the script text as an
option name.

## Verification

- A real-Darwin sandbox run initially exposed the false positive, then passed
  after the fix: sandbox-profile tests 16/16.
- Process-supervisor and secret-policy tests: 35/35 pass.
- Non-overlapping package regression (excluding the two pre-existing long-running broker test processes): 494 total, 488 pass, 6 skipped, 0 fail.
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check` — pass.

This closes the option-name false-positive boundary only. Opaque secrets,
split-range signatures, configurable classification, production credential
isolation, and production task-runner enablement remain open.

## Rollback

Revert source revision `7231964`; no runtime data or host configuration is
changed.
