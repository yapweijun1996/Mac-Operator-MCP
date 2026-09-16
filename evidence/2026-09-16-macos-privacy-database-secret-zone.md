# macOS privacy and account database secret-zone boundary

- Date: 2026-09-16
- Source revision: `94f7faf`
- Scope: Broker filesystem content authorization and bounded log redaction

## Change

The Broker now denies macOS privacy, account, configuration, keychain, and
device-pairing database paths before any content read. Covered zones include
per-user and system TCC stores, `dslocal`, ConfigurationProfiles, system
keychains, `authd`, and `lockdown` databases, with both `/var` and
`/private/var` spellings. User TCC application-support paths are also denied.

Bounded diagnostics redact the same user/system path families. The policy
never opens these databases and never returns their contents; the rule is a
path-boundary decision owned by the Broker.

## Verification

Commands run on the physical Darwin host:

```text
npm run build --silent
node --test packages/broker/dist/secret-policy.test.js
npm test
npm run lint
npm run verify:docs
npm run verify:matrix
```

Result: focused secret-policy tests pass 9/9. The complete regression passes
876/876 with 14 explicit skips (890 total), and build/lint/document/matrix
checks pass. The focused cases cover user and system TCC, `dslocal`,
ConfigurationProfiles, system keychains, and lockdown paths, plus log
redaction for TCC and `dslocal` paths.

## Limit

This closes fixed macOS database path variants only. It does not claim opaque
secret detection, complete credential-store isolation, or production task
runner enablement; those remain governed by the existing `VT-SEC-01` and
sandbox release gates.
