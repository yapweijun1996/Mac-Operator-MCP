# R1 loopback snapshot rollout evidence

Date: 2026-09-21

## Scope

This record covers the owner-authorized rollout of the loopback-enabled
personal R1 snapshot. It does not enable mutation, GUI, destructive, task, or
privileged MCP capabilities.

## Snapshot identity

- Release: `~/Library/Application Support/MacOperator/releases/personal-20260921-r1f`
- Data root: `~/Library/Application Support/MacOperator-r1f`
- Source revision: `6e971c38a660588fbea6bfbfc067896ebbad7aa2a7c46f7220d3f8726989fdf1`
- Project target: `/Users/yapweijun/Documents/GitHub/Mac-Operator-MCP`
- Previous rollback snapshot: `personal-20260921-r1e`

The R1 policy authorizes the exact canonical workspace as the finite Git and
package project target. The release directory remains separate from the Git
project and is not treated as a repository.

## Preflight and local readback

`verify-personal-snapshot.mjs` passed with:

```text
Personal snapshot preflight passed: sourceRevision=6e971c38a660588fbea6bfbfc067896ebbad7aa2a7c46f7220d3f8726989fdf1 loopbackStatus=bound
```

PM2 readback passed with the service online, zero restarts after cutover,
`/opt/homebrew/bin/node` as the executable, the r1f release as `pm_cwd`, and
the r1f data root as the start argument. Local TLS discovery passed for the
Auth listener on loopback port 3444 and the Edge listener on loopback port
3443 using the protected origin CA and issuer Host/SNI.

The PM2 process list was saved after verification.

## Public acceptance

With the real owner account loaded from the protected `.env`, the verifier
passed:

- public OAuth discovery and unauthenticated MCP challenge;
- owner login, explicit consent, S256 token exchange, and 17/17 scope claims;
- exact 30-tool discovery;
- 29 bounded R1 read calls, including Git, package, Docker, project, process,
  network, service, and storage inspection;
- temporary grant revocation followed by rejection of the next MCP request.

The verifier printed no credentials or response payloads. Verification-created
registrations were cleaned up and their grants revoked.

## Rollback

The prior r1e release and data root were retained. A rollback is the following
explicit PM2 operation, followed by the local preflight and public verifier:

```sh
pm2 stop mac-operator-personal
pm2 delete mac-operator-personal
pm2 start /opt/homebrew/bin/node --name mac-operator-personal \
  --cwd "$HOME/Library/Application Support/MacOperator/releases/personal-20260921-r1e" -- \
  packages/auth/dist/personal-service.js start \
  "$HOME/Library/Application Support/MacOperator-r1e"
```

Rollback is not required by the successful rollout, and no old deployment
files were deleted.
