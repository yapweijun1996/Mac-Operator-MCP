# Broker policy array prototype boundary evidence

Date: 2026-09-16
Source revision: `dac0cb8`
Host: physical Darwin arm64 (`yaps-Mac-mini.local`, Darwin 25.2.0)
Node: `v25.5.0`

## Decision

Broker policy validation now accepts only arrays whose prototype is the native
`Array.prototype`. The existing dense-array checks still reject symbols,
hidden properties, sparse slots, and accessor descriptors. This closes the
remaining inherited-authority path before policy validation invokes array
operations such as scope and target matching.

The restriction applies to principal scopes, target rules, filesystem roots,
tool metadata, and parameterized target references. It does not change the
target model, default-deny behavior, deny-over-allow ordering, or capability
enablement state.

## Verification

- Policy and target-authority suite: 14/14 passed, 0 skipped, 0 failed.
- Full default repository regression: 893 total, 879 passed, 14 explicit
  skips, 0 failed.
- Build, typecheck, lint, and `git diff --check` passed.
- Custom-prototype principal-scope and target-rule arrays fail closed before
  policy authorization or capability projection.

## Remaining gate

This closes custom-prototype authority for the Broker policy boundary only. It
does not close task isolation, production signing/installation, VM/guest
isolation, or the independent P0/P1 review.
