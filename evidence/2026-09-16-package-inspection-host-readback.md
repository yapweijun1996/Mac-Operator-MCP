# Package inspection host readback evidence

Date: 2026-09-16
Source revision: `0260dde`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

The read-only package inspector was run against the canonical repository root.
It selected the `npm` manager from the local lockfile, parsed bounded manifest
metadata, and returned a dependency count and lockfile presence without
executing a package manager or opening protected content. The inspector's
existing descriptor/no-follow, root-identity, size, UTF-8, and secret-content
checks remained in force.

## Verification

Physical host readback:

```json
{"projectRoot":"/Users/yapweijun/Documents/GitHub/Mac-Operator-MCP","manager":"npm","dependencyCount":4,"lockfile":{"present":true,"path":"package-lock.json"},"warnings":[],"truncated":false}
```

Focused regression:

```text
node --test packages/broker/dist/package-inspector.test.js
tests 5
pass 5
fail 0
```

No package installation, registry lookup, credential-store access, or
filesystem mutation occurred.

## Limits

This is bounded metadata readback only. Outdated lookups remain disabled;
dependency manifests are not a supply-chain trust decision, and package
installation/mutation, production capability enablement, and broader
filesystem remount/resource evidence remain open.

## Rollback

Remove this evidence record; no runtime or host configuration changed.
