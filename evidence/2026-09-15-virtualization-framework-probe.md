# Virtualization.framework Host Probe Refresh

Date: 2026-09-15
Source commit: `75c8fd7`
Host: physical Darwin arm64 development host
Scope: SDK and host-support readback only; no VM boot or capability enablement

## Command

```text
npm run build:native:virtualization-probe --workspace @mac-operator/broker
```

## Observed result

```json
{"framework":"Virtualization.framework","configuration_type":"VZVirtualMachineConfiguration","virtualization_supported":true,"configuration_valid_without_guest":false,"validation_error_present":1,"vm_boot_attempted":false,"host_version":"Version 26.2 (Build 25C56)"}
```

The active SDK is macOS 26.2 on Darwin arm64. The probe links the framework,
constructs a guest-less configuration, and confirms that the framework rejects
that incomplete configuration. It intentionally does not fetch an image, boot
a VM, attach a filesystem/network device, or expose a guest channel.

## Boundary

This refresh proves SDK presence and host virtualization support only. It does
not prove entitlement, image provenance, guest identity attestation, guest
filesystem/network/process isolation, credential unavailability, cancellation,
postcondition readback, or production signing. `VirtualizationTaskRunner` and
`mac_task_run` therefore remain disabled pending those independent gates.
