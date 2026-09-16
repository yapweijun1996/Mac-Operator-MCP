# Opaque signing-container boundary

- Date: 2026-09-16
- Source revision: `8dce667`
- Host: physical macOS Darwin arm64 development host
- Boundary: F0 content path authorization and bounded evidence redaction

## Change

The Broker denies content reads and writes whose normalized basename ends in
`.key`, `.p8`, `.p12`, `.pfx`, `.ppk`, `.jks`, `.keystore`, `.mobileprovision`,
or `.provisionprofile`. This path-level rule runs before content access so an
encrypted or opaque private-key container cannot bypass the content scanner.
Bounded log redaction removes matching absolute path forms before diagnostics
or audit evidence are returned.

The rule is conservative: a file with one of these suffixes is treated as a
secret zone even when its bytes have not been parsed. No capability was
enabled and no host credential or key material was opened.

## Verification

```text
npm run typecheck --silent
npm run build --silent
node --test packages/broker/dist/secret-policy.test.js
  9 passed, 0 failed

node --test packages/broker/dist/secret-policy.test.js \
  packages/broker/dist/security-fuzz.test.js \
  packages/broker/dist/process-supervisor.test.js \
  packages/broker/dist/task-profile.test.js \
  packages/broker/dist/virtualization-guest-executor.test.js \
  packages/edge/dist/*.test.js
  145 passed, 0 failed
```

`git diff --check` passed. The full `npm test --silent` regression was also
run before this change with 846 passed, 14 skipped, and 0 failed; the focused
regression above covers the changed secret boundary after the change.

## Remaining limits

This does not classify arbitrary opaque token values or prove production
credential-store isolation. Sandbox enablement, protected production
Keychain distribution, and independent review remain gated.
