# Notarization assessment boundary evidence

Date: 2026-09-16
Source revision: `14317d1`
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

The Broker and Edge LaunchAgent plans now include this command for production
Developer ID policy, execute it after code-signature verification and before
any plist or launchd mutation, and require the same evidence in final service
readback. The root helper package plan includes the same preflight and an
explicit `verify-notarization` execution step. Explicit ad-hoc development
plans omit the command and cannot publish notarization evidence.

## Verification

- `npm run typecheck --silent` passed.
- `npm run build --silent` passed.
- `node --test --test-timeout=120000 packages/broker/dist/macos-notarization.test.js` passed 2/2.
- Broker/Edge install-plan tests passed 25/25; privileged-helper package tests
  passed 20/20.
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

Revert commit `14317d1` to remove package-plan enforcement, then revert
`32f2c6c` if the standalone contract is also intentionally removed. These
commits have no host-side mutation or persistent state.
