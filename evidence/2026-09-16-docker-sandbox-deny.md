# Docker Socket Sandbox Denial Evidence

Date: 2026-09-16
Host: physical Mac mini source tree; real sandbox capability unavailable in
this runtime
Source revision: `314189c`

## Boundary implemented

The Broker-owned Seatbelt renderer now emits explicit deny rules for both
`/var/run/docker.sock` and `/private/var/run/docker.sock`, covering read and
write operations. The rules are emitted in addition to the deny-default
profile and cannot be supplied or removed by task arguments. This protects
against a task profile later gaining a broad filesystem root without silently
exposing the Docker authority endpoint.

## Verification

The deterministic renderer test asserts the explicit read and write rules for
both path spellings. The focused sandbox-profile suite passes 13/13 with five
real-macOS opt-in skips. TypeScript compilation passes. The existing physical
sandbox canary already records `docker-socket-denied`, but this revision was
not executed under `MOPS_REAL_SANDBOX=1` because the host descriptor launcher
capability is unavailable (`available=false`); no physical isolation claim is
made here.

## Remaining limits

Static SBPL rules do not prove kernel enforcement on a host where the sandbox
runner is not enabled, nor do they prove that a task cannot use another Docker
API endpoint or a future socket alias. Native descriptor execution, physical
sandbox evidence, Docker daemon/VM isolation, and mutation remain separate
gates.
