# Policy Query Target Normalization Evidence

Date: 2026-09-16
Source revision: `81bf9fa`

## Boundary

`mac_policy_explain` now normalizes target references with a target-kind-specific
grammar before policy lookup. The Broker accepts only canonical host, path,
project, process, Job, task-profile, app, app-window, UI element, service, log,
Docker runtime/object, package, and power references. Absolute paths must be
lexically canonical; app/window identities require the `bundle:` form; UI
elements require the 48-hex snapshot identity; service and log references reject
traversal components; Docker runtimes are fixed to `local`; and Docker objects,
Jobs, packages, and profiles remain bounded identifiers. The previously omitted
`docker_runtime` target kind is now representable.

The normalizer runs before `authorizeTool` and `authorizeTarget`, so malformed
or cross-kind references fail with stable `PRECONDITION_FAILED` instead of
reaching policy matching. Filesystem paths remain lexical at this boundary and
still require descriptor-backed root planning before an allow decision.

## Verification

Focused `policy-query-target.test.ts` coverage passes 3/3:

- canonical app/window/UI, filesystem, service/log, Docker, Job, package, and
  task-profile references are accepted;
- traversal, malformed bundle/window/UI identities, cross-kind host/runtime
  values, relative projects, and unknown kinds are rejected;
- omitted targets default only to `host:broker`, while null, extra fields, and
  control characters are rejected.

`npx tsc -b --pretty false`, `npm run lint`, and `git diff --check` pass. This
closes the in-process policy-query reference grammar only; signed policy target
validation, native transport, remote issuer, live app/resource readback, and
release-gate evidence remain independent.
