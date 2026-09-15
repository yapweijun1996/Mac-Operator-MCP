# Docker Result Boundary Evidence

Date: 2026-09-15
Source revision: `50fd2fb`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:43:54Z
Artifact hashes: `packages/broker/src/docker-inspector.ts` SHA-256
`765d757c5d48b349cb4618a001688cc85637be40fa676f907ed635f03a86595d`;
`packages/broker/src/docker-inspector.test.ts` SHA-256
`90b1cfc7dc87bcc65b69a13265943bcfd539abd3d870ff3879fe53bbfc529eab`.

## Decision

Docker CLI output is an untrusted child-process result. Only bounded,
plain-data, known-field records may become Broker-owned status data; daemon
metadata, environment values, and raw socket behavior remain outside this
adapter's result contract.

## Implemented controls

- Container and image line records require plain data, reject unknown fields,
  reject invalid or conflicting `ID`/`Id` aliases, and project only stable
  identifiers, names, tags, and state.
- Inspection identity aliases fail closed when conflicting or malformed;
  nested state, config, network, port, and mount values are consumed only from
  plain records and dense bounded arrays.
- Docker logs cap both the number of lines and each line's bytes before
  redaction and return, while preserving explicit truncation warnings.
- Fixed executable, cwd, environment, local socket endpoint, timeout,
  cancellation, output caps, and secret redaction remain unchanged; no raw
  Docker socket proxy is introduced.

## Verification

Focused command:

```text
npm run build && node --test packages/broker/dist/docker-inspector.test.js
```

Result: 9 tests passed, 0 failed, 0 skipped. Hostile accessor, unknown-field,
conflicting-identity, line-count, and line-size fixtures fail closed or stay
within the bounded projection.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 533 tests total, 527 passed, 6 skipped,
0 failed.

## Boundary status

This proves Docker CLI result-shape and output-budget integrity only. It does
not prove Docker daemon-version compatibility, storage readback, credential or
container isolation, raw-socket denial on every host, production packaging,
or capability enablement. Those gates remain fail-closed and incomplete.
