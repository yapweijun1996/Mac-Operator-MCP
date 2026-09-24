# Virtualization Host Prerequisite Audit — 2026-09-23

## Result

The physical Mac mini supports `Virtualization.framework`, but the current
installation is not ready to boot a guest. This is a read-only host and source
audit; no VM was booted, no image was downloaded, and no entitlement or signing
configuration was changed.

## Host evidence

- Host: macOS 26.2 (build 25C56), Darwin arm64.
- The installed Command Line Tools SDK exposes `Virtualization.framework`.
- `npm run build:native:virtualization-probe --workspace @mac-operator/broker`
  completed. Its output reports `virtualization_supported: true`,
  `configuration_valid_without_guest: false`, and `vm_boot_attempted: false`.
  The invalid configuration is deliberately guest-less; it is not evidence of
  an entitlement rejection. Framework support does not prove that a guest can
  be configured or booted.
- A local inventory found no indexed `.utm`, `.vmwarevm`, `.ipsw`, `.qcow2`, or
  `.vdi` assets; no VM applications or common VM storage locations were found,
  and the repository contains no guest image artifact. This is a bounded local
  inventory, not proof that no image exists elsewhere.
- The active Homebrew Node executable is ad-hoc signed, has no TeamIdentifier,
  and carries no entitlements. The privileged-helper app builder currently
  adds only JIT and unsigned-executable-memory entitlements to its Node runtime;
  it does not add `com.apple.security.virtualization`.
- The native guest lifecycle source builds a generic platform/EFI configuration
  and a protected read-only disk attachment, but the inspected path does not
  provide an installable macOS restore workflow or a Linux kernel/initrd. It
  also intentionally configures no network or shared-directory devices.

## Engineering consequence

Apple documents that VM creation requires the `com.apple.security.virtualization`
entitlement and that macOS guests need a restore image and guest-specific boot
state; Linux guests need a compatible kernel/initrd or bootable EFI disk. The
current probe has not tested entitlement acceptance because it does not attempt
VM creation with a valid guest configuration.

Because the native bridge is loaded into a Node host process, the executable
whose signature supplies process entitlements must be the unprivileged Broker
host that loads the bridge. This is an architecture inference from the current
N-API loading boundary and Apple's code-signing model. Do not add VM entitlement
to the privileged root helper as a shortcut: that would combine VM control with
root authority and widen the security boundary. A separately isolated,
unprivileged VM host remains an alternative if its IPC contract is justified.

## Runtime entitlement gate

The native lifecycle bridge now reads `com.apple.security.virtualization` from
the current process using `SecTaskCreateFromSelf` and
`SecTaskCopyValueForEntitlement`. Both the TypeScript VM adapter and native
`createGuestVm` entry point fail closed when the value is absent, false, or
unreadable. The native check is repeated at the VM-creation boundary so an
internal caller cannot bypass the TypeScript preflight. This proves only
runtime entitlement readback and denial behavior; it does not sign the Broker,
grant an entitlement, validate an entitled bundle, or boot a guest.

## Next gates

1. Design an unprivileged, Developer ID-signed Broker host path with the
   virtualization entitlement; validate its signature and entitlement before
   attempting VM creation.
2. Separately authorize and acquire a suitable guest boot source (macOS restore
   image or Linux kernel/initrd), then test valid configuration and boot on the
   physical host.
3. Keep `VirtualizationTaskRunner` disabled until guest isolation, attestation,
   transport, and postcondition evidence pass independently.

## Sources

- [Apple: Adding the Virtualization Entitlement](https://developer.apple.com/documentation/virtualization/adding-the-virtualization-entitlement-to-your-project)
- [Apple: Virtualization entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.virtualization)
- [Apple: Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/)
- [Apple: Installing macOS on a Virtual Machine](https://developer.apple.com/documentation/virtualization/installing-macos-on-a-virtual-machine)
- [Apple: Creating and Running a Linux Virtual Machine](https://developer.apple.com/documentation/virtualization/creating-and-running-a-linux-virtual-machine)
- [Apple: SecTaskCreateFromSelf](https://developer.apple.com/documentation/security/sectaskcreatefromself%28_%3A%29)
- [Apple: SecTaskCopyValueForEntitlement](https://developer.apple.com/documentation/security/sectaskcopyvalueforentitlement%28_%3A_%3A_%3A%29)
