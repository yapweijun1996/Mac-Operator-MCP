# Docker CLI Code-Signature Evidence

Date: 2026-09-16
Host: physical Mac mini, Darwin 26.2 arm64
Source revision: `872198b`

## Boundary implemented

`DockerInspectorImpl` can require a Broker-owned code-signature attestation
before `status`, `inspect`, or `logs`. When enabled by the Broker default, the
adapter invokes only `/usr/bin/codesign` with fixed arguments, `/` as cwd, an
empty environment, bounded timeout/output, and the caller cancellation hook.
The strict verification command must succeed, and the bounded `-dv
--verbose=4` readback must contain exactly one valid `Identifier`,
`TeamIdentifier`, and optional `CDHash` field matching the fixed Broker trust
policy. Raw codesign output never crosses the tool or audit boundary. Any
missing, malformed, duplicate, or mismatched identity fails closed as
`POLICY_DENIED`; cancellation and timeout remain stable control outcomes.

The Broker default expects Docker Inc's Developer ID identity
`Identifier=docker`, `TeamIdentifier=9BNSXJN65R`. Unit tests also cover a
trusted readback and an untrusted identifier, proving that no Docker daemon
command is attempted after a signature mismatch. The adapter can still be
constructed with signature enforcement disabled for deterministic injected
fakes; this is not the Broker production default.

## Physical host readback

The following bounded host commands were run without exposing raw command
output to MCP:

```text
/usr/bin/codesign --verify --strict --deep /Applications/Docker.app/Contents/Resources/bin/docker
exit status: 0

/usr/bin/codesign -dv --verbose=4 /Applications/Docker.app/Contents/Resources/bin/docker
Identifier=docker
CDHash=56df8f23b2a6bfd9d54bb07516561e3e24805ccd
Authority=Developer ID Application: Docker Inc (9BNSXJN65R)
TeamIdentifier=9BNSXJN65R

Docker version --format '{{.Server.Version}}'
29.1.3
```

The selected executable is the canonical regular file
`/Applications/Docker.app/Contents/Resources/bin/docker`, owned by the current
user (`uid=501`, `gid=80`) with mode `100755`. The attested executable content
SHA-256 is carried into each Docker child admission; ProcessSupervisor
recomputes the digest before spawn and rejects a replacement between signature
readback and launch. The shared supervisor also continues to enforce the fixed
user-owned Docker exception and canonical, owner-only executable boundary.

## Verification

- Docker inspector tests: 16 passed, 1 explicit real-host skip.
- Real Docker Desktop signature, status, and inspect readback with
  `MOPS_REAL_DOCKER=1`: 1/1 passed.
- Broker Docker handler identity recheck: 1/1 passed.
- `npx tsc -b --pretty false`: passed.
- `npm run verify:contracts`: 44 unique contracts and ledger schema passed.
- `npm run lint`: 750 tracked files passed.
- `npm run verify:docs`: 29 README links and 8 runbooks passed.
- `npm run verify:matrix`: 28 targets, 24 threats, 30 tasks, 4 evidence refs passed.
- `git diff --check`: passed.

## Remaining limits

This proves the selected executable's current macOS code-signature identity and
a bounded content handoff, not notarization policy, a kernel-held executable
descriptor, or an atomic signature-to-exec binding. A replacement after the
content digest is captured but before the signature command is covered by the
digest mismatch at Docker spawn; a native descriptor-backed launcher is still
needed to eliminate all pathname races. The Docker daemon remains a Linux VM endpoint;
raw socket proxying and Docker mutation are still excluded.
