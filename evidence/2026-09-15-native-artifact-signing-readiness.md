# Native artifact signing-readiness evidence

Date: 2026-09-15
Host: physical Mac mini, Darwin arm64
Source revision: `54d4590`

## Boundary

This is a read-only release probe for every Broker-owned native extension. It
does not import or execute an untrusted artifact and does not mutate Keychain,
launchd, or a production package.

## Verification

Commands:

```text
security find-identity -v -p codesigning
/usr/bin/codesign --verify --strict packages/broker/dist/peer_credentials.node
/usr/bin/codesign --verify --strict packages/broker/dist/virtualization_guest.node
/usr/bin/codesign --verify --strict packages/broker/dist/virtualization_guest_lifecycle.node
/usr/bin/codesign -dvv --verbose=4 <each-native-artifact>
```

Results:

- `security find-identity -v -p codesigning`: `0 valid identities found`;
- strict verification passed for all three native artifacts;
- all three report `Signature=adhoc` and `TeamIdentifier=not set`;
- bounded CDHashes were read back for each artifact, but none is a production
  Developer ID identity.

## Decision

The package and helper gates remain fail-closed. Ad-hoc artifacts can support
explicit development fixtures only; they cannot enable capabilities or root
helper installation. Production release still requires an approved Developer
ID certificate, notarization evidence, exact component identifiers, and final
installed readback.
