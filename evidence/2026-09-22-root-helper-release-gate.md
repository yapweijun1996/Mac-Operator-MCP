# Root-helper release provenance gate

Status: `PASS` for the source and staging gate; physical production release is
still blocked by the host's missing Developer ID/notarization evidence.

The root-helper server, protected runtime factory, Broker task executor, and
native transport capability now require an explicit `development-probe` or
`production` release mode before they can advertise availability. Production
mode requires the exact native helper artifact path, pinned Developer ID
identifier/Team ID/CDHash, and redacted notarization readback produced by the
read-only macOS release preflight. The capability projection records the
release mode and refuses an incomplete production projection.

The disabled path and development probe remain available for contract and
boundary tests without claiming production provenance. The production path
does not execute or install anything until the host provides a valid signed,
notarized artifact and the protected root-helper lifecycle is installed and
read back.

The reproducible verifier is available through
`npm run build && npm run verify:release:root-helper -- --manifest <canonical-path>`.
It accepts only an owner-only manifest and regular native artifact, runs the
generic Developer ID/notarization preflight, and emits only the redacted
evidence consumed by the production gate.

Verification:

- `npm test`: 1,057 tests; 1,042 passed, 15 skipped, 0 failed.
- Root-helper regression covers missing production evidence, regular-file
  native helper evidence, capability completeness, and development-probe
  compatibility.
- A missing-manifest invocation of `verify:release:root-helper` exits non-zero
  with `release manifest is unavailable` and makes no host change.
- No live PM2, Auth, Edge, LaunchAgent, LaunchDaemon, OAuth grant, or policy
  state was changed.
