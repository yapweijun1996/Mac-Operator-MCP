# Broker Startup Configuration Boundary Evidence

Date: 2026-09-15
Source revision: `345b329`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T06:12:01Z
Artifact hashes: `packages/broker/src/service-startup.ts` SHA-256
`73c266b6a584d6dc9c901e85de999349979c776a3d0331b9c9ebfd73333c6afd`;
`packages/broker/src/service-startup.test.ts` SHA-256
`f2b7d1fd123694039ffd1751b446ef8fd039170da982a4669fcbbfefe594d175`.

## Decision

Startup configuration controls package, data, runtime, socket, policy, and
key paths. It must be plain data before any path normalization, root
containment, identity, or authority checks.

## Implemented controls

- `validateBrokerServiceStartupConfig` rejects accessors, inherited fields,
  symbols, and non-data objects through the shared plain-record boundary.
- Existing exact field, canonical path, root containment, ownership, launchd
  identity, version, and revision checks remain unchanged.
- The loader continues to require owner-only regular files and strict JSON;
  the validator also protects direct in-process callers.

## Verification

Focused command:

```text
npm run build && node --test --test-name-pattern='Broker service startup config is strict' packages/broker/dist/service-startup.test.js
```

Result: 1 test passed, 0 failed, 0 skipped. Accessor and inherited config
fixtures are rejected with the stable malformed-config boundary. The
non-overlapping package regression passes 538 total tests (532 passed,
6 skipped, 0 failed).

## Boundary status

This proves startup configuration representation integrity only. It does not
prove Developer ID provenance, installed upgrade/rollback, Keychain ACLs,
remote deployment, privileged helper enablement, or final release acceptance.
Those gates remain fail-closed and incomplete.
