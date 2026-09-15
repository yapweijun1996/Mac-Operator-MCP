# Audit evidence credential-field redaction

Date: 2026-09-15

## Scope

The Broker persistence boundary now treats common credential field aliases as
secret-bearing when recursively redacting audit evidence. The matcher covers
API/access/refresh tokens, API/client/HMAC/signing/SSH keys, bearer/JWT values,
passwords/passphrases, cookies, credentials, and private/secret fields.

## Verification

`audit-evidence-redaction.test.ts` passes with `api_key`, `access_token`,
`signing_key`, `hmacKey`, and `client_secret` values replaced by
`[REDACTED]`, while an unrelated field remains unchanged. `npm run build` and
`git diff --check` pass.

The redaction remains field-name based and is applied before canonical JSON
serialization and audit hashing. Adapters still perform content and path
secret checks; this change does not claim complete corpus or physical-host
secret isolation and does not close VT-SEC-01/02.
