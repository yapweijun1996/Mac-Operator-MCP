# Virtualization guest profile executor evidence

Date: 2026-09-15

## Decision and boundary

Guest execution now resolves an authenticated request only against a
startup-owned manifest packaged with the reviewed guest image. The request
contains profile/task digests and bounded budgets; the manifest owns the
executable, arguments, cwd, environment, filesystem roots, network policy,
credential policy, process-tree policy, and verification strategy.

The registry recomputes the same canonical profile/task digests used by the
Broker, rejects shell executables and unsafe environment keys, denies broad
protected filesystem roots, and rechecks canonical regular-file/directory
targets immediately before dispatch. A bounded terminal ledger supports a
fresh authenticated status lookup without replaying execution. Adapter errors
map to stable result classes with fixed summaries so internal paths and error
text do not cross the guest protocol.

Guest responses apply the bounded Broker log-redaction policy to stdout,
stderr, and verification summaries before they cross the guest protocol.
`VirtualizationGuestProcessExecutor` is a concrete ProcessSupervisor adapter
for a future guest image, but remains unavailable unless both explicit enable
and independently accepted isolation-evidence gates are true. Process bounds
are supplied by ProcessSupervisor; guest-private filesystem, profile-bound
network, host-credential absence, and guest process ownership still require
the reviewed Virtualization image and real-Mac evidence.

## Verification

- Guest profile executor focused tests: 7/7 pass.
- Tests cover digest binding, target replacement, shell/environment rejection,
  bounded status recovery, factory composition, redacted failure mapping, and
  fail-closed adapter gating.
- Full physical-Darwin regression after this change: 569/569 pass, 0 skipped.
- `npm run typecheck`, `npm run lint`, and `git diff --check` pass.

## Remaining evidence

No production VM or guest image was booted. A signed entitled image, guest
AF_VSOCK service, filesystem/network/credential/process isolation proof,
attestation producer, and final capability enablement remain required. This
boundary does not enable unrestricted shell/root execution or arbitrary MCP
commands.

## Rollback

Remove the Guest profile executor export and factory wiring; the existing
protocol callback seam remains available and no persisted Broker schema or MCP
contract changes are required.
