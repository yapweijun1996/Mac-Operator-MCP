# HTTPS request-body boundary evidence

Date: 2026-09-16
Source revision: `f7669d2`
Host: Darwin arm64, Node.js 25.5.0

## Boundary exercised

The Edge JSON parser remains bounded at 1 MiB. Parser failures are now mapped
at the HTTPS boundary to stable, non-diagnostic responses: malformed JSON is
HTTP 400 `{ "error": "invalid_json" }`, and an oversized body is HTTP 413
`{ "error": "request_too_large" }`. Internal parser error text is never
returned to the MCP client. Authentication, host/origin checks, and Broker
authorization remain unchanged.

## Verification

The physical-Darwin HTTPS integration sends a validly authenticated malformed
JSON request and an over-limit request, then verifies both status codes and
exact bounded response bodies. The full Edge regression also covers native IPC,
JWT validation, capability projection, revocation, TLS binding, and rate
limiting:

```text
npm run typecheck -- --pretty false
npm run lint
npm run build --silent
node --test packages/edge/dist/https-edge.test.js
tests 3
pass 3
fail 0

node --test packages/edge/dist/*.test.js
tests 66
pass 66
fail 0
```

## Limits

This closes response classification for JSON parser/body-size failures. It
does not change the fixed parser budget, add durable distributed rate limits,
or prove deployment-scale ingress capacity. No capability was enabled and no
host configuration changed.

## Rollback

Revert commit `f7669d2`; no installed service, credential, or key material was
changed.
