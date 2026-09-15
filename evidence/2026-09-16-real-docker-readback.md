# Real Docker readback evidence

- Source revision: `a0c753a`
- Capture date: 2026-09-16 (Asia/Kuala_Lumpur)
- Host: Apple silicon Mac mini, macOS 26.2, Darwin 25.2.0, arm64
- Docker CLI: 29.1.3
- Docker context: `desktop-linux`

## Boundary exercised

The fixed local Docker adapter was run against the host's Docker Desktop
daemon with `DOCKER_CONFIG=/var/empty`, `HOME=/var/empty`, and the explicit
`unix:///var/run/docker.sock` endpoint. Docker 29 emits a bounded `Platform`
field in `ps --format '{{json .}}'`; the strict container-record allowlist now
accepts that known metadata field while continuing to reject unknown fields.

## Verification

```text
node --test packages/broker/dist/docker-inspector.test.js
9 tests, 9 passed, 0 failed

DockerInspectorImpl.status(false, false)
daemon.available=true, version=29.1.3, context=local
containerCount=24, warnings=[], truncated=false

DockerInspectorImpl.inspect("container", <bounded-id>)
objectType=container, state=running, warnings=[], truncated=false
```

The adapter returned only bounded IDs, names, states, image, ports, and
sanitized mounts. No Docker environment, credential, or log content was
requested or returned. Typecheck, lint, documentation, matrix, and diff checks
also pass for this change.

## Limitations

Docker Desktop exposes a Linux VM (`desktop-linux`), not a native macOS
container daemon. This proves compatibility with the installed local Docker
Desktop endpoint and the adapter's read-only boundary, not arbitrary Docker
socket access, container mutation, VM isolation, or production deployment.
