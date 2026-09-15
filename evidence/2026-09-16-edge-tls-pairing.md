# Edge TLS Certificate/Key Pairing Evidence

Date: 2026-09-16
Source revision: `3dacdbe`
Host: physical Mac mini test runtime

## Boundary implemented

Protected Edge TLS loading now parses the certificate and private key in
memory, derives both public SPKI values, and compares them before the HTTPS
listener is created. Invalid material and mismatched pairs fail closed with a
generic startup error; the private-key buffer is cleared when pairing fails.
Path ownership, owner-only permissions, non-symlink checks, bounded size, and
open/read target-identity checks remain in force.

## Verification

The focused TLS-material suite passes 4/4, including a real OpenSSL-generated
certificate/key pair and a mismatched-key negative case. The HTTPS Edge,
cross-process Edge/Broker, and service-startup suites pass 10/10. Typecheck,
build, lint, documentation, matrix, and diff checks pass.

This proves startup pairing and protected loading only; certificate chain trust,
hostname validation against the deployment certificate, external issuer
availability, and production launchd installation remain separate gates.

