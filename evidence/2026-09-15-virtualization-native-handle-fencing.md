# Virtualization Guest Native-Handle Fencing Evidence

Date: 2026-09-15
Source commit: `8aa6f70`
Host: physical Darwin arm64 development host

## Implemented boundary

The Native Virtualization.framework VM handle now uses an atomic validity
marker. Retained asynchronous transition completion no longer writes the
valid marker back after `closeGuestVm()` has invalidated the handle. The close
path also retains the serial dispatch queue until the external N-API handle
finalizer runs. Delayed callbacks can therefore observe the native `closed`
state and fail closed; they cannot resurrect a handle or dispatch through a
null queue.

## Verification

- Native lifecycle build: `npm run build:native:virtualization-guest-lifecycle --workspace @mac-operator/broker` passed, including strict compiler warnings and codesign verification.
- Focused VM-native suite: 7/7 pass.
- Complete physical-Darwin regression with install, sandbox, and Keychain gates: 576/576 pass, 0 skipped, 0 failed.
- Typecheck, lint, contract verification, and `git diff --check` pass.

## Remaining boundary

This closes a native handle lifecycle race. It does not prove a bootable
approved guest image, VM boot/readback, guest credential isolation, production
attestation, Developer ID installation, or `mac_task_run` enablement.

## Rollback

Revert commit `8aa6f70`; the prior native handle marker and queue teardown
behavior return.
