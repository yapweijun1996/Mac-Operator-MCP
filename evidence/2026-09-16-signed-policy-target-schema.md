# Signed Policy Target Schema Evidence

Date: 2026-09-16
Source revision: `3c76604`

Follow-up implementation revision: `9a4554e`

## Boundary

The signed policy document schema now represents the complete Broker target
vocabulary, including `docker_runtime` and `docker_object`, and applies
kind-specific constraints for host, path, process, Job, profile, UI, service,
log, Docker, package, and power references. `PolicyBundleVerifier.verify()` now
also runs `validateBrokerPolicy()` on the materialized policy before returning
it, so a signed bundle cannot be treated as verified while its active target
rules fail the Broker's stricter authority grammar.

## Verification

The new policy-loader regression accepts `docker_runtime:local` and rejects a
traversal-shaped Docker object after signature and schema validation. The
policy-loader suite passes 16/16; the combined policy, loader, target-authority,
and policy-query suites pass 30/30. Typecheck, lint, documentation, matrix, and
diff checks pass. Revision `9a4554e` centralizes the query and signed-policy
grammars in one Broker target-authority module; the same 30/30 regression was
rerun after that refactor.

This closes schema/runtime alignment and early target-rule validation only;
parameterized grant serialization, live Docker/resource identity readback,
native transport, remote issuer, and release evidence remain open.
