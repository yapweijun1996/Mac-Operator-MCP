# macOS process-containment candidate audit

Date: 2026-09-24
Host: Mac mini Mac16,10 (Apple M4, 16 GB), macOS 26.2 (25C56), Darwin 25.2.0, arm64; Node v25.5.0
Status: Candidate review only; no capability gate changed

## Conclusion

The currently implemented App Sandbox helper does not contain every descendant:
the physical D1 double-fork/`setsid` canary observed a detached process alive
after the helper returned. Runtime and restart quarantine mitigate repeated
host execution after that uncertainty, but they do not terminate an escaped
process or prove containment.

Among the reviewed host mechanisms, a short-lived Virtualization guest per
untrusted task is the preferred next candidate. The repository already has a
Broker-owned guest lifecycle that calls the host VM stop operation and requires
an identity-matched `stopped` state before teardown. However, no Linux guest has
booted on this host, the current Broker executable is not a signed host with the
Virtualization entitlement, and the hostile descendant canary has not run in a
guest. This is not a production decision or approval to enable `mac_task_run`.

## Candidate findings

### launchd process-group cleanup — insufficient

Apple's launchd plist reference says that, when a job exits,
`AbandonProcessGroup=false` causes launchd to kill processes with the same
process-group ID as the job. The physical hostile fixture calls `setsid`,
changes its session/process group, and survives the helper response. Therefore
the documented process-group rule does not cover the observed escape. Launchd
remains useful for managing service lifecycles, but is not a proven descendant
containment boundary here.

### Endpoint Security — fork observation, not fork denial

Apple's public Endpoint Security event catalogue lists `ES_EVENT_TYPE_NOTIFY_FORK`
as a notification and lists authorization events such as `ES_EVENT_TYPE_AUTH_EXEC`;
it does not list an `AUTH_FORK` event. An exec authorization can constrain a
new executable image, but cannot deny a child that continues in the forked
process without an exec. Fork notifications are useful for detection and
response, not a synchronous no-fork guarantee. Deployment also requires
Apple's `com.apple.developer.endpoint-security.client` entitlement and a signed
system extension; Apple documents that activation can require owner approval.
The current host has no Developer ID identity. This is not a practical current
fix for the acceptance gate.

### Nested Seatbelt — not supported

The local Command Line Tools SDK header `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sandbox.h`
states that the API is no longer supported/deprecated and that if a process is
already sandboxed, a new `sandbox_init` profile is ignored and returns an error.
The local `man sandbox-exec` also labels the command `DEPRECATED`. The App
Sandbox helper is already sandboxed, so adding a second Seatbelt profile inside
it is not a valid repair. The standalone runner's physical no-fork result
remains experimental; deprecation prevents treating it as the selected
production mechanism.

### One Virtualization guest per task — preferred, unverified

Apple documents `VZVirtualMachine.stop` as stopping a running or paused VM; the
guest-directed `requestStop` API only asks the guest OS to stop. The native
adapter currently uses the host `stopWithCompletionHandler` API, checks for
`VZVirtualMachineStateStopped`, closes active virtio connections, and fails
closed on timeout or state mismatch. A stopped VM is the strongest candidate
among those inspected because guest processes cannot continue executing after
the host stops that VM. This inference still requires physical proof against
the project's hostile process fixture, including crash and stop-timeout paths.

For any future untrusted-code path, preserve fixed host tools as Broker-owned
adapters and give the guest only bounded staged inputs/outputs. Do not provide
host credential directories, Docker sockets, broad shared folders, or direct
network access by default. Unknown VM state must keep host task admission
quarantined.

## Host and repository evidence

- Host: Mac mini Mac16,10 (Apple M4, 16 GB), macOS 26.2 build 25C56, Darwin
  25.2.0, arm64, Node v25.5.0.
- Physical D1 quarantine canary:
  [`2026-09-24-app-sandbox-quarantine-canary.md`](2026-09-24-app-sandbox-quarantine-canary.md).
- Current VM prerequisite audit:
  [`2026-09-23-virtualization-host-prerequisites.md`](2026-09-23-virtualization-host-prerequisites.md).
- The prerequisite audit found Virtualization.framework support but no indexed
  guest image/boot source, no entitled signed Broker host, and no attempted VM
  boot. No image was downloaded and no signing or entitlement configuration
  was changed during this review.
- `xcodebuild -version` is unavailable because the active developer directory
  is Command Line Tools, not full Xcode. This is relevant to building/signing a
  System Extension candidate; it does not prevent the existing native addon
  build path.

### Local Virtualization prerequisite recheck (2026-09-24)

The existing read-only SDK probe reports `virtualization_supported=true` on
macOS 26.2, while its intentionally guest-less configuration is invalid and
`vm_boot_attempted=false`. The existing native lifecycle addon passes a strict
Objective-C++ syntax-only compile. Its entitlement readback in the active
Node 25.5.0 process is `false`; `security find-identity` reports zero valid
code-signing identities. A temporary copy of Node plus its matching `libnode`
was ad-hoc signed with the Virtualization entitlement. Strict signature
verification passed; entitlement readback through the project native addon and
the addon's `createGuestVm` gate succeeded, with creation then rejected at the
expected invalid-image identity check. The temporary copies were removed, and
installed Node still reports no entitlement. Focused VM lifecycle/native
adapter tests pass 24/24. The completion audit remains partial at 92% (2 PASS,
23 OPEN, 4 BLOCKED).

These results verify host framework availability and source/test consistency,
and show that the native entitlement guard can be exercised locally with an
ad-hoc-signed disposable process without a Developer ID identity. They do not
prove that Virtualization.framework accepts that signing mode, a valid guest
configuration, guest boot, or process containment. No VM was started, no image
was downloaded, and no installed signing or entitlement configuration was
changed at this prerequisite-only checkpoint.

### Disposable guest-boot probes (2026-09-24 follow-up)

The follow-up used development-only Objective-C probes under
`packages/broker/native/`; no MCP tool, production runner, installed Node, or
installed signing configuration was changed. The probe executables were
ad-hoc signed with only `com.apple.security.virtualization`, passed strict
signature verification, and read the entitlement back as true at runtime.

A 64 MiB sparse raw disk was attached read-only to a minimal EFI VM, with a
new disposable EFI variable store and no network, directory sharing, socket,
or serial devices. Configuration validation passed; start completed in
`running`, `canStop` was true, host hard-stop completed, and state readback was
`stopped`. This proves that this process can start and stop an EFI VM on the
host; it does not prove Linux boot or containment.

For the Linux path, the Apple-documented Fedora ARM64 `pxeboot` kernel and
initrd were fetched through Fedora's HTTPS release URL and their SHA-256 values
matched the release `.treeinfo` entries. The Alpine 3.24.2 ARM64 netboot archive
matched Alpine's published SHA-256 sidecar; its detached GPG signature was not
verified because no local OpenPGP verifier is installed. Both Linux pairs
passed `VZVirtualMachineConfiguration` validation. The boot probes used the
Apple guide's 2 CPU / 2 GiB scale, `console=hvc0`, a Virtio entropy device, and
no network, storage, or directory sharing. The Fedora kernel was also tested
without an initrd. Fedora kernel+initrd was additionally retried using
`initWithConfiguration:` (the framework-default VM queue) instead of the
project's explicit serial queue; it failed identically.

All four Linux start attempts (Alpine kernel+initrd, Fedora kernel+initrd on
both queue strategies, and Fedora kernel-only) completed the API callback with
`VZErrorDomain` code 1, “Internal Virtualization error”; state was `error`,
the serial console received zero bytes, and `canStop` was false. The probe
therefore did not issue an invalid stop and cannot claim a stopped-state
readback for these failed starts. A narrow live unified-log capture showed
only an opaque Virtualization breadcrumb, not a cause. The Fedora result makes
an Alpine-specific image or initrd explanation less likely, but the evidence
does not identify whether the remaining failure is a Linux-bootloader/runtime
issue, a host-service interaction, or another unsupported detail. EFI success
does not imply that Linux boot works.

### Read-only EFI ISO lifecycle probe (2026-09-24)

Apple's Virtualization guide documents presenting a Linux installer ISO through
USB mass storage with EFI. The development-only Objective-C probe at
`packages/broker/native/virtualization_efi_iso_boot_probe.m` implemented that
documented path without adding it to the MCP surface or production runner.
The Alpine 3.24.2 ARM64 `alpine-virt` ISO was downloaded from Alpine's
official HTTPS release directory; its SHA-256 matched that directory's
published sidecar (`a57ba668b5f6b17a670fcf8e799d5d7fe43766ed086d6ce2927b0625bf43dbf6`,
93,304,832 bytes). The detached release signature was not verified.

The probe rechecked the pinned size and digest through an `O_NOFOLLOW` file
descriptor, attached the ISO read-only as USB mass storage, used a fresh
disposable EFI variable store, and configured no network, directory sharing,
socket, or serial devices. Its ad-hoc signature passed strict verification and
runtime entitlement readback was true. Configuration validation passed;
`startWithCompletionHandler` returned with VM state `running`; after a bounded
10-second wait the VM remained running and reported `canStop=true`. This result
repeated twice with a fresh EFI variable store on each run. Both host hard-stops
completed and both VM state readbacks were `stopped`.

This is stronger evidence that the host's EFI + read-only ISO VM lifecycle
works than the empty-disk EFI baseline, and it avoids the Linux kernel URL
bootloader path that returned internal errors. It does **not** prove Alpine's
kernel or userspace booted: the probe had no serial port or guest-side signal,
and VM state `running` alone is not guest readiness. It does not establish a
production-signed image, guest isolation, credential/network boundaries,
hostile-descendant containment, or an attestation chain. VT-VZ-02 and
VT-SBX-01/02 remain open/blocked as recorded; public `mac_task_run` stays
disabled and overall progress remains 92% (2 PASS, 23 OPEN, 4 BLOCKED).

Primary sources: [Apple's Linux VM guide](https://developer.apple.com/documentation/virtualization/running-gui-linux-in-a-virtual-machine-on-a-mac),
[Apple's read-only attachment API](https://developer.apple.com/documentation/virtualization/vzdiskimagestoragedeviceattachment/isreadonly?language=objc),
and [Alpine's ARM64 release directory](https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/).

### Linux kernel/initramfs serial probe (2026-09-24)

A second development-only Objective-C probe,
`packages/broker/native/virtualization_efi_iso_serial_probe.m`, added bounded
Virtio serial capture and host-to-guest read-only diagnostic input. It booted a
checksum-verified derivative of the official Alpine 3.24.2 ARM64 ISO. The only
content edit before repacking was GRUB's console arguments to include `hvc0`;
repacking also changed the ISO9660/Joliet filesystem views. The official source
ISO SHA-256 is
`a57ba668b5f6b17a670fcf8e799d5d7fe43766ed086d6ce2927b0625bf43dbf6` (93,304,832
bytes). The tested derivative SHA-256 is
`dd72dc3cea4b788d9f29a59927b1e6fac9358c259f4944cfa53ea31b2c3f9374` (93,007,872
bytes). The derivative was ad-hoc signed with only the Virtualization
entitlement, passed strict signature verification, and read the entitlement
back at runtime. VM configuration validation and EFI start succeeded; the ISO
attachment was read-only, with no network, directory sharing, or socket
devices.

Serial output contained `Run /init as init process` and `Alpine Init 3.14.1-r0`,
so the guest kernel and Alpine initramfs did execute. USB mass storage exposed
the 92.9 MB image as a write-protected SCSI disk. Alpine's `nlplug-findfs`
reported `Mounting boot media: failed` and opened its initramfs recovery shell.
After that shell appeared, the probe sent a bounded diagnostic command that
mounted the ISO read-only in guest RAM and tested the expected repository
marker. The mounted ISO reported `nojoliet`; its directory entry was
`boot_repository` (without a leading dot), while the expected
`apks/.boot_repository` test returned status 1. Adding hdiutil's
`-keep-mac-specific` option did not change that guest-visible path. This
explains the recovery-shell result for this repacked derivative; it does not
indicate a Linux kernel or Virtualization failure.

An additional UDF-only hdiutil derivative was not a usable alternative: the
Virtualization start callback succeeded, but the VM stopped during the bounded
capture with no guest serial output or boot marker. No hard-stop was needed
because the VM already read back as `stopped`.

The host then hard-stopped that first derivative's VM and read back `stopped`;
a one-second post-stop serial check received zero bytes. The probe reports
separate kernel, initramfs, root-userspace, boot-media, and recovery-shell
markers, so Alpine kernel signing-key text cannot be mistaken for userspace
readiness. For this derivative, its success condition covered kernel/initramfs
execution and verified host stop, not root filesystem boot. The in-guest
diagnostic was read-only against the ISO and created only a temporary mount
point in guest RAM.

Alpine boot-media behavior is implemented by
[mkinitfs initramfs-init](https://github.com/alpinelinux/mkinitfs/blob/master/initramfs-init.in)
and [nlplug-findfs](https://github.com/alpinelinux/mkinitfs/blob/master/nlplug-findfs/nlplug-findfs.c);
the latter scans mounted media for the exact `.boot_repository` marker. Apple
documents the guest serial file-handle direction in its
[Virtualization serial-port API](https://developer.apple.com/documentation/virtualization/vzfilehandleserialportattachment/init%28filehandleforreading%3Afilehandleforwriting%3A%29?language=objc).

### Rock Ridge-preserving EFI guest boot (2026-09-24)

The previous `hdiutil` derivative exposed why the guest entered recovery: its
`nojoliet` mount presented `boot_repository` without the leading dot. I installed
the Homebrew `xorriso` formula (1.5.8.pl02) and used the original Alpine ISO as
input, replacing only `/boot/grub/grub.cfg` with the pinned `hvc0` console
configuration, replaying the source boot metadata, and writing a separate
temporary image. The official source ISO SHA-256 remained
`a57ba668b5f6b17a670fcf8e799d5d7fe43766ed086d6ce2927b0625bf43dbf6` (93,304,832
bytes). The resulting derivative SHA-256 is
`c78a31274e30d8df9181315f6d4fd5501b7d46461f9a43994465588ccc072f5b` (93,323,264
bytes). xorriso read the output tree without Rock Ridge errors, listed
`/apks/.boot_repository`, and reported the EFI El Torito image at
`/boot/grub/efi.img`.

The updated development-only Objective-C probe pins that exact size and digest.
It was compiled with `-Wall -Wextra -Werror`, ad-hoc signed with only the
Virtualization entitlement, passed `codesign --verify --strict`, and read the
entitlement back as true at runtime. On physical macOS 26.2 ARM64, configuration
validation and EFI start succeeded. The 1 GiB / 2-vCPU VM attached the ISO
read-only as USB mass storage and had zero network, directory-sharing, and
socket devices. Guest serial confirmed `Run /init as init process`, Alpine
initramfs startup, `Mounting boot media: ok.`, installation of all 28 local base
packages, the Alpine 3.24 welcome banner, and `localhost login:`. The recovery
shell did not appear. Thus the guest mounted the expected repository and
reached the root userspace login prompt; no login credentials were sent.

After bounded serial capture, the host hard-stop completed and state readback
was `stopped`; a one-second post-stop check received zero bytes. The probe
returned success. Its `boot_repository_marker_found_by_guest_probe` diagnostic
field is false because that extra command is sent only in the recovery shell;
the independent `Mounting boot media: ok.` and package-install/login markers
show the normal boot path succeeded. This closes the first real Linux userspace
boot proof, not guest reset/reuse, hostile-descendant containment, credential
isolation, production Broker signing, or the production task gate. The
completion audit remains fail-closed at 92% (2 PASS, 23 OPEN, 4 BLOCKED), and
`mac_task_run` remains disabled.

### First guest descendant stop canary (2026-09-24)

The probe ran twice with distinct fresh EFI variable stores. In each run it
logged into the disposable live guest as root over its isolated serial console
and confirmed `uid=0(root)`. It issued a nested background-shell command that
starts a `setsid` shell descendant. The parent command returned and emitted
`MOP_GUEST_CANARY_ARMED`; two seconds later the detached descendant emitted
`MOP_GUEST_CANARY_ALIVE`, proving it remained active after that parent
returned. A later marker was scheduled ten seconds after launch.

Once the alive marker arrived, the host invoked the Virtualization VM stop API.
In both runs, the completion callback succeeded and state readback was
`stopped`. The probe monitored the serial pipe for 12 seconds after each stop:
no scheduled late marker arrived, and total post-stop serial bytes were zero.
The canary success predicate required root identity, both armed/alive markers,
no late marker before or after stop, and verified stopped-state readback; both
runs returned exit code 0. The ISO remained read-only and the guest had no
network, directory-sharing, or socket devices.

This is repeatable development-only stop evidence, not complete isolation. The
guest process table and exact
PID/session lineage were not independently enumerated, and this does not prove
repeatability, guest reset/reuse, credential/filesystem/network isolation,
Broker restart recovery, production image identity, or production-runner
acceptance. The guest-isolation and hostile-descendant gates therefore remain
open; `mac_task_run` stays disabled and overall progress remains 92% (2 PASS,
23 OPEN, 4 BLOCKED).

## Decision and acceptance gates

1. Do not use launchd process-group cleanup, fork observation, or nested
   `sandbox_init` as proof that a `setsid` descendant is contained.
2. Keep the current App Sandbox runner staging-only and keep public
   `mac_task_run` disabled.
3. Keep the probes diagnostic-only. Do not integrate or enable a guest runner
   until a signed unprivileged Broker host with the required entitlement and an
   approved, pinned boot source are available.
4. Before enabling any guest task, repeat the double-fork/`setsid` fixture in
   fresh disposable guests. Stop each VM at timeout/cancellation, verify the
   exact VM reaches `stopped`, and prove no guest marker or child continues
   afterward.
5. Repeat the credential, filesystem, network, VM crash/restart, result
   journaling, and Broker restart checks; any uncertain stop remains unknown
   and quarantined.

## Primary sources

- [Apple open-source launchd plist reference](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5)
- [Apple Endpoint Security event types](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t)
- [Apple Endpoint Security fork notification](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_fork)
- [Apple Endpoint Security exec authorization](https://developer.apple.com/documentation/endpointsecurity/es_event_type_auth_exec)
- [Apple Endpoint Security entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)
- [Apple System Extensions](https://developer.apple.com/documentation/systemextensions)
- [Apple Virtualization stop API reference](https://developer.apple.com/documentation/virtualization/vzvirtualmachine/stop%28completionhandler%3A%29)
- [Apple: Running Linux in a Virtual Machine](https://developer.apple.com/documentation/virtualization/running-linux-in-a-virtual-machine)
- [Apple: Creating and Running a Linux Virtual Machine](https://developer.apple.com/documentation/virtualization/creating-and-running-a-linux-virtual-machine)
- [Fedora 44 ARM64 release tree metadata](https://download.fedoraproject.org/pub/fedora/linux/releases/44/Everything/aarch64/os/.treeinfo)
- [Alpine 3.24 ARM64 release index](https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/)
- [Alpine 3.24.2 ARM64 netboot archive SHA-256 sidecar](https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-netboot-3.24.2-aarch64.tar.gz.sha256)
- [Apple System Extension approval callback](https://developer.apple.com/documentation/systemextensions/ossystemextensionrequestdelegate/requestneedsuserapproval%28_%3A%29)
- [GNU xorriso manual](https://www.gnu.org/software/xorriso/man_1_xorriso.html)
- [Homebrew xorriso formula](https://formulae.brew.sh/formula/xorriso)
