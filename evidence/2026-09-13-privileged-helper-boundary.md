# Privileged Helper Boundary Evidence

- Date: 2026-09-13
- Source commit: `7658465`
- Host: macOS arm64 development host
- Scope: protocol and IPC boundary only; no root process or privileged operation was started
- Policy state: all `mac_priv_*` tools remain planned and disabled; the `privileged` kill switch remains disabled

## Boundary implemented

The helper channel uses owner-only Unix IPC with OS peer authorization before request parsing and a separate HMAC key from the MCP Edge request path. Commands are versioned and digest-bound to the Broker's normalized target, argument digest, active policy, approval identity, and mutation-intent identity. Only `service_control`, `package_install`, and `power` operation names are representable; the envelope has no executable, shell, raw argument, filesystem-root, or credential field.

The helper admits request IDs and nonces through a separate durable SQLite ledger, rejects replay after store reopen, validates exact service/package/host target forms, and binds authenticated responses to the complete command digest. Results are bounded to flat fields, warnings, and allowlisted postcondition verification; secret-shaped evidence is redacted before return. Unsupported handler-map keys are rejected, the default adapter is unavailable, and an explicit handler map is required for any future operation.

## Verification performed

- Unit and IPC tests cover command signing/tampering, unknown-field rejection, target/operation mismatch, no-raw-execution authority, secret evidence redaction, response command binding, OS peer denial before parsing, wrong-key denial, operation allowlisting, durable replay denial, and malformed/unverified success rejection.
- The full suite passes with 282 tests; `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev --audit-level=high`, and `git diff --check` pass.
- No privileged process, root command, package installation, service mutation, reboot/shutdown, launchd persistence, signing key, or production helper socket was used.

## Limits and remaining release work

This is a source-level helper protocol candidate, not privileged capability evidence. Caller identity across a real root boundary, protected key distribution, code signing/notarization, helper packaging and launch ownership, operation-specific adapters, preconditions/postconditions, crash/rollback recovery, real caller-spoof tests, and independent P0/P1 review remain open. ADR-0009 remains Proposed and VT-PRIV-01 remains BLOCKED.
