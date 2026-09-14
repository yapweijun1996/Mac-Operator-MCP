# Strict UTF-8 Boundary Evidence

Date: 2026-09-15
Source commit: `1ce5bee`
Host: physical Darwin arm64 development host

## Implemented boundary

The versioned contracts package now exposes strict UTF-8 decoding. Broker,
Edge, approval, policy-signer, authority-control, status, helper, Keychain,
and virtualization guest JSON paths use it for untrusted frames and protected
configuration reads. Malformed byte sequences fail closed instead of being
silently replaced by Node's lossy UTF-8 decoder. The Keychain server maps the
decode failure to its bounded invalid-request response without consuming a
replay entry.

## Verification

- Contract strict-decoder regression and Broker IPC malformed-byte regression
  pass.
- Focused contract, IPC, persistence, audit, package, service-lock, and Edge
  registry tests pass 78/78.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  587/587 pass, 0 skipped, 0 failed.
- Native canonical JSON probe passes 5/5 fixed wire vectors.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.

## Remaining boundary

This closes malformed UTF-8 handling at the implemented protocol and JSON
configuration boundaries. It does not establish full cross-runtime numeric
canonicalization, duplicate-key rejection for already-parsed JavaScript
objects, or final release-gate acceptance.

## Rollback

Revert `1ce5bee`. Protocol and configuration readers would again use lossy
UTF-8 replacement in the affected paths.
