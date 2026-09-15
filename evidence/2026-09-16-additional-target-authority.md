# Additional-Target Authority Evidence

- Date: 2026-09-16
- Host: physical macOS host used by the repository test harness
- Source revision: `b2d3264`
- Contract/policy versions: 0.1
- Evidence class: local and physical Broker lifecycle-authority regression

## Decision

Broker success publication must revalidate every normalized target in the
execution plan, including additional filesystem roots. A policy change that
removes authority for any requested root therefore cancels the request before
the result or completion audit can claim success.

## Implemented controls

`Broker.handle` now passes `execution.additionalTargets` to the final
`ensureActiveAuthority` call immediately after dispatch. The existing
execution-control callback already checks all targets during worker activity;
this change closes the final readback-to-publication gap for multi-root
inspection tools.

## Verification

Focused command:

```text
npm run build
node --test packages/broker/dist/broker-additional-target-authority.test.js
npm run lint
npm run typecheck
npm run verify:docs
git diff --check
```

Result: 1/1 focused regression passed. The synthetic filesystem executor
activated a same-version policy revision that removed the second root during
dispatch; Broker returned `CANCELLED`, persisted the Request as `CANCELLED`,
and recorded a cancellation completion rather than success.

The serial physical regression ran with install, sandbox, and Keychain opt-ins
and passed 642/642 tests, with zero skips and failures. The pre-existing
long-running Broker, persistence, and privileged-helper IPC suites were
excluded and left undisturbed. Run log:
`/tmp/mops-additional-target-authority-physical-regression.log`.

Artifact SHA-256:

```text
packages/broker/src/broker.ts
5779d900701c2a94d402756989b6b458ba88e4fc07475eac1f16d796dd784edb
packages/broker/src/broker-additional-target-authority.test.ts
e03cc2f19b91f4129ffdf21264300a6f2aa1ea5c9e4add184b2cb5d1fc5c22fa
```

## Boundary status

This closes the Broker final-success authority check for normalized additional
targets. It does not close remote revocation propagation, installed-service
recovery, physical remount races, or production capability enablement.
