# Secret Signature Corpus Expansion

Date: 2026-09-23

Status: PASS for the covered local secret-signature and redaction boundary;
broader opaque-secret coverage, false-positive analysis, and production
release evidence remain open.

## Change

The Broker secret policy now recognizes and redacts additional provider-shaped
credential signatures without using entropy heuristics:

- Stripe restricted keys (`rk_live_` and `rk_test_`)
- SendGrid tokens (`SG.<header>.<payload>`)
- Hugging Face tokens (`hf_`)
- Sentry tokens (`sntrys_`)
- Vercel tokens (`vercel_`)
- Supabase secret keys (`sb_secret_`)
- AWS SigV4 presigned URL signatures and session-token query values
- Azure Storage SAS `sig` values when accompanied by recognized SAS fields

The same signatures are enforced before content/environment/argument
publication and during bounded log redaction. Unknown high-entropy values and
ordinary documentation remain permitted unless they match an explicit
protected signature or existing credential rule.

Cloud URL checks use synthetic values only. The AWS signature case requires a
64-character hexadecimal `X-Amz-Signature`; the Azure case requires a long
query `sig` value plus the SAS `sv`, `sp`, and `se` fields. Short values,
unrelated 64-character digests, and generic `sig` query parameters remain
unchanged.

## Verification

- `npm run build` passed.
- `node --test packages/broker/dist/secret-policy.test.js` passed 10/10.
- `npm test` passed: 1,170 tests passed, 15 skipped, 0 failed.
- Lint, documentation, verification-matrix, process-boundary, and diff checks passed.
- The completion audit remains fail-closed at 92% because the host release gates remain incomplete.
- The expanded corpus is checked both for content denial and for removal from
  redacted log output.
- The shared `ProcessSupervisor` regression emits synthetic provider tokens in
  separate stdout and stderr chunks and verifies that each complete token is
  redacted after capture, with no cross-stream concatenation.
- No real credential, token, key, or account material was used or persisted.
- Primary references: [AWS presigned URL logging guidance](https://docs.aws.amazon.com/prescriptive-guidance/latest/presigned-url-best-practices/logging-interactions.html), [AWS SigV4 query-string authentication](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html), and [Azure Storage service SAS](https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas).

## Remaining limits

This closes only an explainable provider-signature slice of `VT-SEC-01` and
does not prove exhaustive opaque-secret detection, complete false-positive
analysis, or production-scale release evidence. The policy remains
fail-closed for protected zones and known signatures while avoiding a generic
entropy detector.

## Rollback

Remove the added provider and signed-URL patterns and their corpus entries from
`packages/broker/src/secret-policy.ts` and
`packages/broker/src/secret-policy.test.ts`. No host state or persisted data
is affected.
