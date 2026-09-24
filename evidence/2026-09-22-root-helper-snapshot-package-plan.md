# Root Helper Snapshot Package Plan Evidence

Date: 2026-09-22
Host: Darwin arm64 physical Mac, current process UID 501
Status: `implemented` as a non-executing root-domain LaunchDaemon plan; installation and public enablement remain blocked

## Boundary

`packages/broker/src/root-helper-snapshot-package.ts` now defines a separate
package contract for `com.mac-operator.root-helper-snapshot`. It does not reuse
the fixed `com.mac-operator.privileged-helper` runtime contract because the
snapshot service has different socket, capability, and runtime readback
semantics.

The plan binds the exact system plist path, native-only signed artifact,
Developer ID identifier/team/CDHash, protected package paths, separate HMAC and
Ed25519 attestation public-key configuration paths, Broker UID/GID, version
metadata, host evidence reference, and distinct snapshot/status/Broker/
Broker-authority/reserved socket paths. The root-helper runtime now requires
the Broker authority poller for availability and uses the explicit authority
socket. Runtime close wipes server and poller key copies even when startup is
refused by the host gate. The rendered plist has no environment variables or
shell and runs as root with bounded launchd lifecycle settings. The plan also
contains fixed signature/notarization checks and reviewable install,
rollback, and uninstall command/file steps.

The plan's preflight now separately requires evidence for a supported
production sandbox mechanism and native Ed25519 attestation verification;
generic host evidence and structural signature checks cannot satisfy either
capability gate. The attestation public-key config is an explicit protected,
revisioned, digest-bound package input rather than an implicit native argument.

The package plan now also requires the persisted release-preflight evidence for
the exact native executable. It validates the artifact digest/identity,
Developer ID signature, and notarization, requires the LaunchDaemon `Program`
to equal that artifact path, and freezes the accepted evidence snapshot before
returning the plan.

A host-only executor now consumes this plan behind a root-process gate. It
uses fixed signature/notarization and `launchctl` commands, double-samples the
existing service precondition, applies only descriptor-relative plist actions,
restores or stops the exact service on uncertainty, and requires independent
LaunchDaemon/process/plist/release readback before success. After bootstrap,
the executor itself samples the root-helper, root-helper status, Broker, and
Broker-authority sockets twice through the shared stable-socket boundary; the generic readback
callback cannot inject endpoint identity. The production-shaped host observer
also double-samples launchd, process identity/credentials, and plist identity,
and requires owner-controlled release evidence rather than copying those
sources from a generic callback. It is not an MCP handler and is not enabled
on the current host.

This is intentionally a dry-run boundary. It never writes
`/Library/LaunchDaemons`, invokes `launchctl`, changes ownership, loads a key,
starts a root process, or enables an MCP scope. It rejects JavaScript,
interpreters, shell scripts, non-system plist paths, and socket reuse before a
plan is returned.

## Verification

- Focused package-plan, executor, and authenticated status tests passed 14/14, including artifact and
  LaunchDaemon program mismatch negatives, host-observer process replacement,
  confirmation, and non-root denial.
- Focused root-helper authority tests passed 4/4, including native-peer
  round-trip, HMAC response binding, replay rejection, and active-request
  revocation/expiry.
- Focused root-helper service/runtime tests passed 4/4, covering exact
  LaunchDaemon identity, native PID/start-time and uid-0 readback, Broker
  identity binding, and fail-closed entrypoint lifecycle.
- The current full repository regression is 1,074 passed, 15 skipped, 0 failed
  out of 1,089 tests.
- `npm run typecheck` and `npm run build` passed.
- The existing root-helper physical probe remains fail-closed on the non-root
  host with `POLICY_DENIED`; no host service or permission changed.

## Remaining gates

This evidence does not prove a native root-helper executable, Developer ID or
notarized artifact, protected production HMAC/public-key distribution, root-owned package filesystem, LaunchDaemon installation, live root-domain process/socket
readback, crash/restart recovery, independent security review, or public task
enablement. The executor is implemented but cannot be accepted until the
current host supplies those production prerequisites and a real root-domain
readback.

## Rollback

The executor contains explicit install, upgrade, rollback, and uninstall
actions, but no live rollback was run. No host service, launchd job, OAuth
grant, policy, database, or credential store was changed.
