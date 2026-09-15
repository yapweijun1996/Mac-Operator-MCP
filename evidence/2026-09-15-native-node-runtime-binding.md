# Native Node runtime-binding evidence

Date: 2026-09-15
Host: physical Mac mini, Darwin arm64
Source revision: `54d4590`

## Boundary

The three Broker-owned native addons now export the exact build-time
`NODE_VERSION_STRING`. Each TypeScript loader requires that value to match the
running `process.versions.node` in addition to the existing N-API floor and
ceiling. Missing, malformed, or mismatched values fail closed before an addon
is admitted. This prevents a copied `.node` artifact built for another Node
patch/runtime from being loaded accidentally.

## Verification

Commands:

```text
npm run build
npm run typecheck
npm run lint
node --test --test-concurrency=1 \
  packages/broker/dist/peer-credentials.test.js \
  packages/broker/dist/virtualization-guest-native.test.js \
  packages/broker/dist/virtualization-guest-vm-native.test.js
node -e 'const p=require("./packages/broker/dist/peer_credentials.node"); const v=require("./packages/broker/dist/virtualization_guest.node"); const l=require("./packages/broker/dist/virtualization_guest_lifecycle.node"); console.log(JSON.stringify({runtime:process.versions.node,peer:p.nativeNodeVersion,guest:v.nativeNodeVersion,lifecycle:l.nativeNodeVersion,napi:[p.nativeNapiVersion,v.nativeNapiVersion,l.nativeNapiVersion]}))'
git diff --check
```

Results:

- native build, typecheck, and lint: passed;
- focused native loader and boundary regression: 22 passed, 0 failed,
  0 skipped;
- runtime readback: `25.5.0` for the process and all three addons;
- N-API readback: `8` for all three addons;
- diff checks: passed.

## Limits

Exact runtime binding intentionally requires rebuilding all native addons after
the Node runtime changes. It does not prove Developer ID signature/notarization
provenance, installed LaunchAgent lifecycle, or cross-host artifact delivery;
those remain separate release gates.
