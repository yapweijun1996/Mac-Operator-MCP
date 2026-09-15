# Sandbox UDP allowlist evidence

Date: 2026-09-15
Source revision: `02fec55` (`test: verify sandbox UDP allowlists`)

## Boundary

The existing Broker-owned Seatbelt renderer's `udp://localhost:port`
allowlist is exercised on physical Darwin. A Perl `Socket` task sends one
datagram to a listed loopback port and the fixture receives it. The same task
targeting a different loopback port fails and the second fixture receives no
datagram. No DNS, external address, wildcard port, or unrestricted network
permission is introduced.

## Verification

Commands run from the repository root:

```text
npm run lint
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 node --test --test-concurrency=1 packages/*/dist/**/*.test.js
npm run verify:contracts
npm run verify:canonical:native
git diff --check
```

Results:

- Sandbox-profile tests: 16 passed, 0 failed.
- Complete serial physical-Darwin suite: 607 passed, 0 failed, 0 skipped.
- Style, build, contract, native canonical-vector, and diff checks passed.

## Limits

This closes only loopback UDP allowlist behavior for the experimental
`sandbox-exec` runner. External allowlisted networking, DNS policy, production
runner wiring, process-tree ownership, and credential/persistence isolation
remain evidence-gated and disabled.
