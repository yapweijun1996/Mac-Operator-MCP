# Policy prototype authority-boundary evidence

Date: 2026-09-15
Source commit: `b164da0`
Host: physical Darwin arm64 development host

## Boundary

Broker policy objects are authority inputs. In-memory callers must not be able
to provide inherited fields that the validator mistakes for explicit policy
state, including kill switches, key validity windows, principal grants, or
tool contracts.

## Implementation

`validateBrokerPolicy()` now accepts only ordinary records or null-prototype
records at every `hasOnlyKeys()` boundary. Prototype-bearing objects and
objects whose key enumeration throws fail closed before policy use or
capability advertisement. Kill-switch shape validation remains part of the
top-level malformed-policy check.

## Verification

- Policy tests pass 4/4, including inherited kill-switch, tool, and principal
  authority rejection.
- The security-fuzz policy corpus passes 7/7.
- The non-overlapping package regression passes 497 total (491 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence covers policy object-shape integrity only. It does not close
production policy signing, Keychain distribution, VM isolation, privileged
helper installation, or capability enablement gates.

## Rollback

Revert commit `b164da0`. No wire contract, persisted state, or enabled-tool
behavior changes are involved.
