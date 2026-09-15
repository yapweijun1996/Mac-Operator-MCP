# Read-Only Adapter Result Boundary Evidence

Date: 2026-09-15
Source revisions: `a9d1b2a`, `e1ae276`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:21:25Z
Artifact hashes: `packages/broker/src/network-inspector.ts` SHA-256
`eade8bcc9b89fa93761fa5f2eaac97a29fb1404446274af6d9057ca38f016755`;
`packages/broker/src/network-inspector.test.ts` SHA-256
`45190fea74038be306b3be5afca321bce248a0b3d30ee8b526284fd5f6f7b7d5`;
`packages/broker/src/app-inspector.ts` SHA-256
`124a6c7858e434c0fa759a9cbeca0add22e2b02076babeda2ffc321340fe4cb8`;
`packages/broker/src/app-inspector.test.ts` SHA-256
`7bf27ae1c102feff4d3601d68697e11cbf35e612c7c84ed9973de8f22aa5067e`;
`packages/broker/src/ui-inspector.ts` SHA-256
`0936c19c4d3d942cfdc35db429dd37eaa811258e0ba0345401f263c58c2b4b31`;
`packages/broker/src/ui-inspector.test.ts` SHA-256
`935b9845f546119cf70dcb05e6d831cd337722b8a232699ccb231dfc420e4bcd`.

## Decision

Read-only network, app, and Accessibility adapters receive data from native
code or Broker-owned subprocesses. The Broker must not treat extra fields,
unstable object shapes, or sparse collections as trusted result authority.

## Implemented controls

- Native network result records require exact top-level fields; interfaces and
  listeners require exact nested fields and bounded dense arrays.
- App inventory records require exact required fields plus an optional version;
  unknown fields fail before bundle identity projection or metadata redaction.
- Accessibility observation/action success and error envelopes have separate
  exact schemas. Observation nodes are plain records with exact fields in a
  dense bounded array; action readback rejects extra authority fields.
- Plain-data validation rejects inherited, symbolic, non-enumerable, and
  accessor properties before semantic checks.
- Parsers copy only declared values into fresh public records and preserve the
  existing sensitive-target and redaction policies.

## Verification

Focused command:

```text
npm run build && node --test packages/broker/dist/app-inspector.test.js packages/broker/dist/ui-inspector.test.js packages/broker/dist/network-inspector.test.js
```

Result: 15 tests passed, 0 failed, 0 skipped. Hostile fixtures reject
unknown top-level fields, nested accessors, and unstable array/node shapes.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 523 tests total, 517 passed, 6 skipped,
0 failed. The same regression had two unrelated ProcessSupervisor timing
failures under concurrent package load; the immediate rerun passed, and the
focused ProcessSupervisor suite passes 32/32.

## Boundary status

This proves local read-only adapter result-shape integrity only. It does not
prove native code provenance, permission-granted GUI behavior, kernel
sandboxing, credential or persistence isolation, VM/guest attestation,
production resource behavior, or capability enablement. Those gates remain
fail-closed and disabled.
