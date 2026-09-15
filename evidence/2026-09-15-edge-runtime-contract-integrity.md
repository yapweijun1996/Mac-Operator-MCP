# Edge runtime contract-integrity evidence

Date: 2026-09-15
Host: physical Mac mini (Darwin arm64)
Source revision: `d35f1f7`

## Boundary

The Edge contract registry now fails closed unless every loaded tool contract
contains the complete versioned governance envelope: capability level,
safety class, known required scopes, normalized target type, bounded timeout
and output budgets, filesystem/network/secret/approval policies, idempotency,
postcondition verification, audit class, delivery wave, planned lifecycle
state, functional JSON schemas, and the repository provenance record.

The loader still treats the contract directory and each file as untrusted:
owner-only permissions, regular non-symlink files, `O_NOFOLLOW`, device/inode
readback, and bounded byte counts remain required. A missing field, unknown
scope, unsupported enum, malformed postcondition/schema, or invalid provenance
is rejected before MCP tool registration.

## Verification

Commands:

```text
npm run build
npm run typecheck
npm run lint
node --test --test-concurrency=1 packages/edge/dist/*.test.js
npm run verify:contracts
node --input-type=module -e 'import { ToolContractRegistry } from "./packages/edge/dist/contract-registry.js"; await ToolContractRegistry.load("./tool-contracts"); console.log("all contracts loaded");'
git diff --check
```

Results:

- Edge package regression: 52 passed, 0 failed, 0 skipped;
- complete repository contract directory load: successful;
- contract verifier: 44 unique tool contracts and the versioned ledger schema validated;
- typecheck, build, lint, and diff checks: passed;
- focused adversarial coverage rejects incomplete authority metadata,
  unknown scopes, and malformed postcondition metadata.

## Limits

This closes runtime contract-shape integrity only. Broker policy remains the
final authority for scopes, targets, lifecycle enablement, approvals, and
execution. Developer ID provenance, installed-service evidence, and production
deployment gates remain open.
