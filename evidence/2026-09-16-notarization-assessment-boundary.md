# Notarization assessment boundary evidence

Date: 2026-09-16
Source revision: `32f2c6c`
Host: physical Darwin arm64 Mac mini; macOS 26.2

## Change

The Broker now exposes a host-only Gatekeeper assessment contract for a
canonical artifact path. It invokes only `/usr/sbin/spctl` with the fixed
arguments `--assess --type execute --verbose=4 <artifact>`, an empty
environment, a five-second timeout, and a 131072-byte output cap. The parser
returns only bounded readback fields and accepts exactly one `accepted` result
whose source is `Notarized Developer ID` and whose Developer ID authority
contains the expected Team ID. Apple System, malformed, mismatched, failed,
oversized, and non-canonical results fail closed with stable errors.

This is an assessment boundary, not an installer release approval. Package
plans do not yet call this contract, so no capability or service is enabled by
it.

## Verification

- `npm run typecheck --silent` passed.
- `npm run build --silent` passed.
- `node --test --test-timeout=120000 packages/broker/dist/macos-notarization.test.js` passed 2/2.
- `npm test --silent` passed 872/872 with 14 explicit skips (886 total).
- On the physical host, `/usr/sbin/spctl --assess --type execute
  --verbose=4 /usr/bin/true` returned exit 3 (`rejected`), and the same fixed
  command against `/System/Library/CoreServices/Applications/Archive Utility.app`
  returned exit 0 with `source=Apple System`; neither is a notarized Developer
  ID release artifact.

## Evidence boundary

No Developer ID certificate, notarized distribution artifact, persistent
service, helper, credential, or capability was installed or enabled. A real
Developer ID/notarization assessment for the target release artifact remains
required before packaging enablement.

## Rollback

Revert commit `32f2c6c`. The contract has no host-side mutation or persistent
state.
