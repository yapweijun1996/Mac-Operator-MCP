# Descriptor launcher executable-and-cwd boundary evidence

- Source revision: `d8f0202`
- Working tree: clean before this evidence-only documentation update
- Captured: `2026-09-15T18:45:42Z`
- Tool contract version: `0.1`
- Policy version: `policy-0.1`
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Boundary: descriptor-required `ProcessSupervisor` execution opens both the
  Broker-validated executable and working directory with no-follow flags,
  rechecks complete descriptor metadata, and passes only borrowed executable
  and cwd FDs to the native adapter. The adapter receives neither pathname and
  must consume or duplicate both FDs before returning.
- Source artifact SHA-256:
  - `packages/broker/src/process-supervisor.ts`: `4b59f5d76861970835c7c81d067d59c69a8b8333bc2613332c580bc78bee2a2c`
  - `packages/broker/src/process-launch-capability.ts`: `ad4dd0e14bfbc01d1c202cb5ef1f980fb381d9329d063c37f07b35cccd53d07a`

## Verification

```text
npm run typecheck
npm run lint
node --test packages/broker/dist/process-supervisor.test.js \
  packages/broker/dist/process-launch-capability.test.js
tests 42
pass 42
fail 0

MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 <all dist tests except the three
  pre-existing long-running suites>
tests 662
pass 657
fail 0
skipped 5
```

The host still reports no complete native descriptor launcher, so the five
descriptor-capability real-sandbox probes remain explicit skips. The three
pre-existing long-running suites were excluded and left untouched:
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js`.

## Remaining gate

This closes the executable-and-cwd pathname-reopen ambiguity in the
Broker-to-adapter contract. It does not prove that a native adapter exists,
performs atomic descriptor execution, enforces close-on-exec, snapshots
immutable bytes, resists remounts, or enables production task execution.

## Rollback

Revert commit `d8f0202`. No installed service, host configuration, signing
key, or credential store was changed.
