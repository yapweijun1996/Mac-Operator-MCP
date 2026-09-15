# Edge TLS Host Binding Evidence

Date: 2026-09-16
Source revision: `9c647db`
Host: physical Mac mini test runtime

## Boundary implemented

The protected startup loader now accepts the configured resource hostname as a
Broker/Edge-owned expectation. It verifies the parsed certificate with
`X509Certificate.checkHost` after certificate/private-key pairing and before
the HTTPS listener is constructed. A valid pair for another hostname is
rejected; direct callers that do not have a startup hostname may still use the
pair-only helper for isolated tests.

## Verification

The focused TLS-material suite passes 5/5, including real OpenSSL-generated
pair, mismatched-key, and wrong-hostname negatives. HTTPS Edge, cross-process
Edge/Broker, and service-startup suites pass 10/10. Typecheck, build, lint,
documentation, matrix, and diff checks pass.

This proves startup binding to the configured resource hostname only; complete
certificate-chain trust, external issuer availability, and production launchd
deployment remain separate gates.
