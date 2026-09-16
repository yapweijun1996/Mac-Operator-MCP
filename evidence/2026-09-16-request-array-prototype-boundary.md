# Broker request array prototype boundary evidence

Date: 2026-09-16
Source revision: `8ba9e67`
Host: physical Darwin arm64 (`yaps-Mac-mini.local`, Darwin 25.2.0)
Node: `v25.5.0`

## Decision

The signed Broker request parser now rejects arrays whose prototype is not the
native `Array.prototype`. Scope validation also uses descriptor-backed indexed
reads and a local duplicate set, so custom iterators and array methods cannot
project extra principal authority. The recursive request-value check applies
the same native-prototype requirement before the immutable request snapshot is
created.

This is a parser boundary hardening change only. It does not expand scopes,
change authentication proofs, or alter the Broker's independent target and
kill-switch decisions.

## Verification

- Request and policy boundary suite: 13/13 passed, 0 skipped, 0 failed.
- Full default repository regression: 894 total, 880 passed, 14 explicit
  skips, 0 failed.
- Build, typecheck, lint, and `git diff --check` passed.
- A signed request whose principal scope array has a hostile custom prototype
  is rejected before authorization with the stable unsupported-values error.

## Remaining gate

This closes custom-prototype authority in request parsing. It does not close
the descriptor-backed task launcher, production signing/installation, VM/guest
isolation, or independent P0/P1 review.
