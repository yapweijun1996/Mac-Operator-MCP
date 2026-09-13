# Testing Strategy

Status: Draft strategy

## Test layers

- Schema tests: contracts, policy/config, request/result, persistence records, and version negotiation.
- Unit tests: normalization, policy precedence, redaction, state transitions, and conflict handling.
- Integration tests: Edge/Broker IPC, persistence, adapters, jobs, audit, revocation, and kill switches.
- Adversarial tests: `THREAT_MODEL.md` attack paths and `FILESYSTEM_POLICY.md` required cases.
- Real-Mac tests: filesystem races, permissions, processes, apps, Accessibility, packaging, and helper behavior.
- End-to-end tests: authorized remote client through Edge to verified result and audit evidence.

## Evidence requirements

Tests record the exact source commit, dirty state, contract and policy versions, host profile, command/procedure, timestamps, result, and artifact hashes. Redact secrets before persistence. A passing result applies only to the tested revision and configuration.

## Release use

`VERIFICATION.md` is the traceability matrix. A release gate remains open until each required row has a current test and evidence reference. The current runtime test suite covers the bounded Edge/Broker foundation, descriptor-backed metadata/content reads, worker bounds, and initial Request/Approval/Job Ledger behavior. Release evidence still requires clean-revision CI and authenticated approval issuance, remote, complete filesystem/secret, sandbox, mutation recovery, GUI, helper, packaging, and operational layers listed above.

The local baseline is:

```text
npm run lint
npm run typecheck
npm test
npm run verify:contracts
npm audit --audit-level=high
```

`npm run lint` is a dependency-free tracked-file check for text encoding,
line endings, trailing whitespace, final newlines, and regular-file identity;
it does not execute repository content or inspect ignored build artifacts.
