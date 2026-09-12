# Deployment Plan

Status: Draft plan

## Sequence

1. Build and test contracts locally.
2. Run Edge and Broker as separate unprivileged local processes over authenticated IPC.
3. Verify the L0/L1 slice on the physical Mac.
4. Select and configure remote authentication and HTTPS/tunnel transport.
5. Add signed/package-managed launch only after ADR-0007 is accepted.
6. Add the privileged helper only after lower-boundary gates pass.

## Required deployment inputs

Supported macOS/hardware versions, component identities, install paths, permissions, launch ownership, secret references, policy version, persistence location, audit retention, port/socket ownership, health checks, upgrade and rollback compatibility, and uninstall procedure.

## Release rule

No deployment may describe planned tools as enabled. Deployment readback must list exact component, contract, policy, and source versions and confirm Broker privacy, capability switches, credentials, and rollback readiness without exposing secrets.
