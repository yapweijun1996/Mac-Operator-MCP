# Private root secret-zone verification

Date: 2026-09-16

## Boundary

Content-path authorization now treats both `/private/var/root/` and
`/var/root/` as protected secret zones, including otherwise opaque filenames.
This is independent of the narrower `.ssh`, `.docker`, Keychain, Mail, and
browser path rules. Log redaction also removes arbitrary paths under the
private root instead of exposing an unrecognized basename.

## Verification

Commands run on the physical Darwin host:

```text
npm run build --silent
node --test packages/broker/dist/secret-policy.test.js
node --test packages/broker/dist/security-fuzz.test.js --test-name-pattern='secret|path'
```

Result: secret-policy 8/8 and the focused security-fuzz corpus 8/8 passed.
The tests cover both private-root spellings, a nonstandard private-root
filename, and generic private-root log redaction. No credential bytes or
private-root file contents are read.

