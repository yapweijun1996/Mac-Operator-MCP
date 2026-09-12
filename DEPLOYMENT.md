# Deployment Plan

Status: Draft plan

## Sequence

1. Build and test contracts locally.
2. Run Edge and Broker as separate unprivileged local processes over authenticated IPC. The packaged macOS service must select the native Broker UDS transport, not the legacy private-Node-descriptor compatibility path.
3. Verify the L0/L1 slice on the physical Mac.
4. Select and configure remote authentication and HTTPS/tunnel transport.
5. Render the reviewed LaunchAgent template through `renderLaunchdPlist`, build a non-executing `buildMacOsInstallPlan`, verify its fixed `codesign`/`launchctl` argv and rollback preconditions, use `BrokerServiceEntrypoint` with `createMacOsNativeBrokerRuntime`, then add signed/package-managed launch, including the separate policy-signer operator socket and protected operator key, only after ADR-0007 is accepted.
6. Add the privileged helper only after lower-boundary gates pass.

## Required deployment inputs

Supported macOS/hardware versions, component identities, install paths, permissions, launch ownership, protected TLS certificate/private-key references, other secret references, policy version, persistence location, audit retention, port/socket ownership, health checks, upgrade and rollback compatibility, and uninstall procedure.

The source template, renderer, and install plan are not installation authorization. A future installer must run `inspectMacOsInstallFilesystem`, verify the exact package signature, owner/mode/symlink state, native module identity, source/contract/policy readback, exact existing-service revision, and rollback backup before any `launchctl bootstrap` call. The plan and filesystem preflight are read-only/declarative and do not invoke `codesign`, `launchctl`, or filesystem writes.

## Release rule

No deployment may describe planned tools as enabled. Deployment readback must list exact component, contract, policy, and source versions and confirm Broker privacy, capability switches, credentials, and rollback readiness without exposing secrets.
