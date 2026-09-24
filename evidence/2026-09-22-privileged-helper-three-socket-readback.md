# Privileged helper and root-helper three-socket readback

Date: 2026-09-22

## Boundary

The privileged-helper package independently observes its three local Unix
sockets; the root-helper package independently observes four endpoints,
adding a separate authenticated status socket before composing final
readiness. The root-helper executor owns its socket observation after
bootstrap; its generic readback callback cannot inject socket identity fields:

Privileged-helper endpoints:

- root-owned helper command socket;
- Broker-owned unprivileged Broker socket;
- Broker-owned authority polling socket.

Root-helper endpoints:

- root-owned root-helper task socket;
- root-owned root-helper status socket;
- Broker-owned unprivileged Broker socket;
- Broker-owned authority polling socket.

Each endpoint is sampled twice with `lstat`. The readback requires a stable
device/inode, socket type, canonical planned path, expected UID/GID, and no
group/other permissions. Its parent chain is also checked as non-symlink
directories with an owner-bound immediate parent; only macOS's fixed `/var`
and `/tmp` aliases are accepted. The final package readback carries each
owner/mode/device/inode record separately from the helper's authenticated
runtime metadata. A path-only status response therefore cannot claim socket
identity or ownership. The root-helper package also rejects Broker socket path
drift before release evidence validation.

## Verification

- Focused `privileged-helper-package` coverage passes 21/21, and
  root-helper package/status coverage passes 14/14.
- The root-helper production-shaped observer independently double-samples
  launchd, process identity/credentials, and plist identity, and requires
  owner-controlled release evidence before composing final readiness.
- Tests reject helper-socket owner drift, Broker-socket path drift in both
  package readback paths, a group-readable socket, and a symlink replacement.
- `npm run typecheck` and `npm run build` pass.
- No root-domain service, privileged adapter, or live R1 deployment was
  changed; production Developer ID, root installation, and independent review
  remain external gates.
