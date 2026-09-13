# Privileged helper Job executor boundary

## Scope

`packages/broker/src/privileged-helper-executor.ts` adds a Broker-owned,
disabled-by-default executor for an already admitted privileged Job. It does
not add an MCP route, enable a privileged policy entry, install a helper, or
perform a launchd/root mutation.

The executor renews and holds the Job lease, rechecks the Broker authority
callback before issuing and after receiving the helper response, requires the
command factory to bind operation/target/payload/policy identity, and persists
only terminal states allowed by the Job ledger. A verified `completed` helper
result is the only success path. Accepted-but-not-completed, timeout,
transport loss, malformed/uncertain execution, or a post-dispatch authority
change becomes retryable `UNKNOWN_OUTCOME` and never becomes success.

The command-client binding delegates to the existing bounded authenticated
helper client and zeroes the short-lived key buffer after use. Helper result
evidence is schema-validated and redacted before it is returned or persisted.

The `Broker` now owns this boundary through an optional
`privilegedHelperExecutor` dependency and the host-only
`executePrivilegedHelperJob()` seam. Broker authority is checked once before
delegation and again by the executor before command issuance and after helper
readback. The default Broker constructor supplies a disabled executor, so no
MCP request path changes.

## Verification

- `node --test packages/broker/dist/privileged-helper-executor.test.js`: 5/5
- Broker regression including the disabled seam: 67/67
- `npm run typecheck`: pass
- `npm test`: 406 tests, 403 passed, 0 failed, 3 opt-in sandbox tests skipped
- `git diff --check`: pass

## Remaining boundary

The executor remains an integration primitive. `mac_priv_*` tools are still
not registered in the default policy/dispatch path, the helper adapter remains
disabled, no privileged key is provisioned, and no root helper or launchd
service was installed. Real-Mac helper IPC, package identity, crash/restart,
rollback, and independent P0/P1 review remain open gates.

## Rollback

Remove the executor export and module, or leave it unconstructed; the default
`enabled: false` path performs no Job mutation. No host service state is
changed by this slice.
