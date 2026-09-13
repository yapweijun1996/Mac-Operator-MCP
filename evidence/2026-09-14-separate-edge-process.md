# Separate Edge Process Evidence

Status: Partial real-Mac process-boundary evidence; installed deployment remains open

## Scope

This smoke exercises an independently spawned Edge Node process over HTTPS to a
parent-process native Broker listener. It is intentionally a process-boundary
fixture, not a claim of launchd installation or package signing.

## Procedure and result

- Generated owner-only temporary TLS and Edge-to-Broker authentication
  material, with the authentication key loaded by the child through the
  protected-key loader and digest check.
- Spawned the Edge child with a minimal environment and fixed root working
  directory. The child loaded the real compiled Edge package, tool contracts,
  TLS material, local JWT verifier, and `BrokerIpcClient`, then exposed the
  HTTPS MCP listener.
- Captured the child PID/start-time identity before starting
  `MacOsNativeBrokerIpcServer`; the Broker accepted only that UID/GID and exact
  Darwin process identity.
- Used the official MCP client over TLS with Host/Origin allowlists to perform
  version negotiation and `mac_health`. The result was `SUCCEEDED`, and the
  bearer token was absent from the Broker audit ledger.
- Stopped the child and native listener in `finally` cleanup and removed the
  temporary socket, database, certificate, and key material.

## Verification

`node --test packages/edge/dist/edge-broker-https.test.js` passed 2/2 on the
physical Darwin arm64 host, including the separately spawned Edge case.

## Boundary

This proves independent Edge-process startup around the compiled Edge package,
authenticated HTTPS request handling, native Broker peer binding, signed local
IPC, and redacted audit evidence. It does not prove launchd installation,
service readback, Developer ID/notarization, remote OAuth/JWKS hosting, or
production key rotation/hot reload.

Host: Darwin arm64, Node v25.5.0. No secret bytes or private keys are recorded.
