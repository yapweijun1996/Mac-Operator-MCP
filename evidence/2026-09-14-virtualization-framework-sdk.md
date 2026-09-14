# Virtualization.framework SDK Candidate Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: SDK capability probe only; no VM boot or task capability enablement

## Commands and observed output

```text
uname -m
arm64

sw_vers -productVersion
26.2

sw_vers -buildVersion
25C56

xcrun --sdk macosx --show-sdk-version
26.2

swift --version
swift-driver version: 1.127.14.1 Apple Swift version 6.2.3 (swiftlang-6.2.3.3.21 clang-1700.6.3.2)

xcrun --find swiftc
/Library/Developer/CommandLineTools/usr/bin/swiftc

Virtualization.framework in the active macOS SDK
present

npm run build:native:virtualization-probe --workspace @mac-operator/broker
{"framework":"Virtualization.framework","configuration_type":"VZVirtualMachineConfiguration","virtualization_supported":true,"configuration_valid_without_guest":false,"validation_error_present":1,"vm_boot_attempted":false,"host_version":"Version 26.2 (Build 25C56)"}
```

The SDK contains the `Virtualization.framework` module and headers, including
`VZVirtualMachine`, `VZMacOSVirtualMachine`, guest storage, directory-share,
and network-device declarations. The native Objective-C probe links the
framework and constructs a `VZVirtualMachineConfiguration` without booting a
VM. The host reports virtualization support, while an intentionally guest-less
configuration is invalid as expected. Xcode is not installed on this host; the
Command Line Tools `swiftc` also reports an SDK/compiler interface-version
mismatch, so this probe does not
establish a production Swift build or code-signing pipeline.

## Boundary and limitations

This proves only that the current Command Line Tools SDK exposes the framework
surface needed for a future native adapter. It does not prove entitlement
availability, VM boot, guest identity attestation, filesystem or network
isolation, credential isolation, process-tree ownership, cancellation, or
postcondition readback. The TypeScript `VirtualizationTaskRunner` therefore
remains disabled unless an externally reviewed proof and a native adapter with
a matching guest image identity are supplied. `mac_task_run` remains disabled.

The TypeScript seam now also requires a versioned native-adapter attestation
whose digest covers the immutable guest identity, selected sandbox profile,
guest-private filesystem, profile-bound network, unavailable host credentials,
guest-owned process tree/policy, and the same external evidence reference as the
`TaskIsolationProof`. The runner validates that attestation at construction and
again immediately before dispatch. This prevents a changed or structurally
inconsistent adapter claim from passing the guest-identity check, but it is not
independent host evidence and does not enable the capability.
