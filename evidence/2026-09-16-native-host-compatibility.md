# Native adapter host compatibility

## Decision

Each macOS native N-API artifact now exports the host tuple compiled into the
bundle: `nativePlatform = darwin` and `nativeArch = arm64` or `x64`. Broker
loaders require that tuple to match the running Node process before exposing
peer, filesystem, process, or Virtualization.framework operations.

## Boundary

The check is independent of MCP arguments and remains inside the startup
artifact loader. It complements protected canonical-path, owner/mode,
device/inode/digest, N-API, and exact Node-runtime checks. A mismatched or
unknown tuple maps to the existing unavailable/fail-closed path; no fallback
to a pathname or alternate native module is allowed.

## Verification

- `peer_credentials.node`, `virtualization_guest.node`, and
  `virtualization_guest_lifecycle.node` export and validate the tuple.
- Focused peer/Virtualization native tests pass 24/24 on the physical Darwin
  arm64 host, including explicit platform/architecture drift rejection.
- Typecheck and native build pass; strict ad-hoc code-signature verification
  remains a build check only.
- No capability was enabled and no service, Keychain item, or VM was mutated.

## Remaining risk

The current artifacts are still ad-hoc/linker-signed and do not establish
Developer ID provenance, notarization, or an immutable release distribution.
