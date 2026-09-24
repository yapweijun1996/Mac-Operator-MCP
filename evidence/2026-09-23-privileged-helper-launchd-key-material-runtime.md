# Privileged Helper Launchd-Bound Key-Material Runtime

Date: 2026-09-23

Status: PASS for the local runtime assembly and rejection boundary. A native
production helper executable, signed artifact, root-domain installation,
live readback, and privileged capability enablement remain open.

## Implemented boundary

- `createPrivilegedHelperRuntimeFromKeyMaterialForLaunchdBroker` accepts the
  exact Broker LaunchAgent service ID and expected UID/GID, but no caller-built
  peer identity.
- It performs bounded Launchd readback and native PID/start-time capture before
  opening helper key material or constructing the helper runtime.
- It builds the peer policy internally and delegates to the existing
  key-material runtime, preserving the separate helper key, authority socket,
  and durable replay ledger boundaries.
- An invalid or smuggled service label is rejected before invoking the command
  executor. The negative fixture also supplies paths that must not be opened,
  proving the startup factory fails before key and helper-root processing.

## Verification

- `npm run typecheck` passes.
- `npm run build` passes, including native peer-credential compilation and
  TypeScript project builds.
- The focused real key-material runtime integration and caller-capture
  regression pass 2/2 on this macOS host.
- No LaunchDaemon was installed or started, and no root-owned host state was
  changed.

## Remaining limits

The repository still lacks the production native privileged-helper executable
and its packaging/build path. This factory is a runtime assembly boundary, not
an executable entrypoint or proof of root-domain operation. Developer ID
signing/notarization, protected Keychain provisioning, live launchd/helper
readback, rollback, and capability acceptance remain host-gated.

## Rollback

Remove the factory, its positive/negative test coverage, this evidence note,
and the corresponding ADR/PROGRESS addenda. No host installation or service
state was changed by this work.
