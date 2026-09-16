# Secret corpus and split-argv guard evidence

Date: 2026-09-16
Source revision: `2e5d08b`
Host: Darwin arm64, Node.js 25.5.0

## Boundary exercised

The Broker secret policy now covers additional synthetic AWS access-key
prefixes, Google OAuth access/client tokens, GitHub fine-grained tokens,
GitLab/npm/PyPI tokens, Stripe keys, legacy OpenAI keys, Cloudflare tokens,
and Heroku key assignments. The same bounded signatures are used for content
denial, environment-value checks, argv admission, and log redaction.

Arguments are also rejected when a credential label and its value are split
across adjacent argv entries, including `Bearer <value>` and `-H
Authorization: <value>` forms. This prevents process-table exposure when no
single argv entry contains a complete token signature.

## Verification

- Secret-policy tests use synthetic values only and cover the expanded token
  corpus, split labels, redaction, and safe-argument false positives.
- ProcessSupervisor and named-task profile tests continue to exercise the
  final child-spawn and profile-resolution secret gates.
- No real credential, private key, browser profile, or Keychain item was read.

Commands:

```text
npm run typecheck -- --pretty false
node --test packages/broker/dist/secret-policy.test.js
node --test packages/broker/dist/process-supervisor.test.js packages/broker/dist/task-profile.test.js
npm run lint
npm run verify:docs
npm run verify:matrix
```

Result: secret-policy tests pass 6/6; the related ProcessSupervisor/task-profile
suites pass 47/47; typecheck, lint, documentation, and matrix checks pass.

## Limits

This expands known credential signatures and closes split-label argv forms; it
does not prove binary/base64 secret detection, opaque arbitrary secrets,
complete credential-store coverage, false-positive analysis, retention/access
control, or production child-process isolation. No capability was enabled.
