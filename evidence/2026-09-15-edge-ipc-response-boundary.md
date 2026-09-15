# Edge IPC Response Boundary Evidence

Date: 2026-09-15
Source revision: `adddedd`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:52:06Z
Artifact hashes: `packages/edge/src/ipc-client.ts` SHA-256
`4c2b5d2afb70410de7f244968b992a8b7eb43f3dc160a303df00f833beb35e78`;
`packages/edge/src/ipc-client.test.ts` SHA-256
`27ad0f69778b3953bfe4d2708c778f77241e268a2f8b734a3fd21399d59c7511`.

## Decision

The Edge must validate a Broker IPC response envelope and its stable result
shape before returning data to MCP callers. Authentication proves provenance;
it does not make malformed or authority-shaped result data safe to consume.

## Implemented controls

- The response envelope requires plain data and an exact six-field shape with
  bounded request/key/digest identifiers.
- Broker success and failure results require exact field sets, stable tool and
  error classes, bounded duration/warnings, plain verification/error records,
  and no unknown nested authority fields.
- Existing socket identity revalidation, UTF-8/JSON strict parsing, response
  MAC verification, request/tool binding, cancellation, timeout, and output
  caps remain in force.

## Verification

Focused command:

```text
npm run build && node --test packages/edge/dist/ipc-client.test.js
```

Result: 4 tests passed, 0 failed, 0 skipped. A valid signed round trip stays
green while unknown envelope/result fields and accessor-shaped observations are
rejected before publication.

## Boundary status

This proves the Edge-side IPC response representation gate only. It does not
prove Broker correctness, remote OAuth/JWKS deployment, installed service
provenance, production key lifecycle, or capability enablement. Those gates
remain fail-closed and incomplete.
