# TLS Material Lifetime Evidence

- Source revision: `96adc2d`
- Date: 2026-09-15
- Scope: Edge protected TLS certificate and private-key loading

## Decision

The protected TLS loader now returns the single validated file buffer it owns
and clears the certificate buffer if private-key loading fails after the
certificate has been read. A partial startup result therefore does not leave
certificate bytes resident after an error, while the successful result still
transfers ownership of both buffers to the Edge listener lifecycle.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed across 647 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Focused Edge TLS/service-startup suite: 8 passed, 0 failed.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Production TLS key packaging, listener shutdown readback, and full
HTTPS Edge regression remain open.
