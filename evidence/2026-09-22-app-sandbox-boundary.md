# App Sandbox Boundary Probe

Date: 2026-09-22
Host: physical macOS 26.2 (25C56), Darwin arm64, UID 501
Status: candidate evidence only; production task capability remains disabled

## Purpose

The existing `sandbox-exec` path is deprecated and cannot satisfy the
`supported-production` sandbox gate. This probe checks whether the supported
macOS App Sandbox entitlement provides a usable process boundary for a future
Broker-owned task snapshot.

The probe is a separately signed App Sandbox bundle with the fixed bundle
identifier `com.macoperator.mopsandboxprobe`. It performs three fixed checks:

1. read a file outside the App Sandbox container;
2. write a file inside the App Sandbox container; and
3. spawn `/usr/bin/touch` and attempt to write outside the container.

The same physical probe also attempts a loopback connection to a controlled
local listener, writes a unique canary under the existing user
`Library/LaunchAgents` directory, and opens the existing user `.ssh` directory
without reading any credential content. These checks cover network,
persistence, and credential-zone access at the OS boundary.

The child operation is intentionally fixed; no caller-controlled command or
raw shell input is accepted.

## Command

```text
npm run probe:app-sandbox
```

The build signs the bundle with the explicit
`com.apple.security.app-sandbox` entitlement, verifies the bundle signature,
and then runs the fixed native probe. The signing is ad hoc and proves current
host behavior only; it does not prove Developer ID provenance or notarization.

The physical release-identity readback on the same host confirms that this is
not a releasable artifact: `security find-identity -v -p codesigning` reports
zero valid identities, `codesign -dvvv --strict --deep` reports
`Signature=adhoc` and `TeamIdentifier=not set`, and `spctl -a -vv` rejects the
bundle. The helper therefore remains a host-evidence candidate only; no
production identity, signing key, or notarization credential was introduced.

## Observed result

```json
{
  "schema_version": "0.1",
  "probe": "macos-app-sandbox-boundary",
  "bundle_identifier": "com.macoperator.mopsandboxprobe",
  "app_sandbox_entitlement": true,
  "launch": { "code": 0, "signal": null },
  "allowed_container_write": true,
  "child_outside_container_write": false,
  "outside_container_read_fixture": true,
  "network_connect_denied": true,
  "persistence_write_denied": true,
  "credential_zone_denied": true,
  "production_enablement": "disabled"
}
```

The native output also recorded `EPERM` for the outside-container read and
the child write, loopback connect, LaunchAgents canary write, and `.ssh`
directory open, while the container write succeeded. The child therefore
retained the App Sandbox boundary across `posix_spawn` on this host. The
network check used a listener owned by the probe and did not contact an
external service; the credential check opened only the directory and never
read a secret file.

## Authenticated helper round-trip

The follow-up candidate builds the existing native verifier into a separately
signed `AppSandboxHelper.app` bundle with a distinct mechanism, attestation
audience, HMAC domains, and App Sandbox entitlement. It receives the same
bounded `MOPH` descriptor handoff shape, verifies the Node-signed Ed25519
attestation and request HMAC, materializes the fixed `/bin/sh` interpreter and
Broker-owned script descriptor into the helper's OS-owned container, and
verifies the response HMAC. The script invokes fixed `/usr/bin/touch`; it can
write a relative file inside the container while an absolute write to a
temporary host path is denied.

```text
npm run probe:app-sandbox:helper
```

Observed result:

```json
{
  "schema_version": "0.1",
  "probe": "macos-app-sandbox-helper-roundtrip",
  "app_sandbox_entitlement": true,
  "descriptor_handoff": "verified",
  "attestation_audience": "verified",
  "request_hmac": "verified",
  "response_hmac": "verified",
  "container_materialization": "verified",
  "fixed_interpreter": "/bin/sh",
  "script_descriptor": "verified",
  "allowed_container_write": true,
  "outside_container_write_blocked": true,
  "production_enablement": "disabled"
}
```

This probe also found a material limitation: on this host, `execve` of the
freshly materialized arbitrary binary from the App Sandbox container returns
`EPERM`. The candidate therefore uses the fixed system-published `/bin/sh`
interpreter and materializes the script as data; it does not claim arbitrary
executable support.

The Broker-side native executor now performs a physical App Sandbox
round-trip through `AppSandboxTaskRunner` using the same descriptor-only
handoff. The executor verifies the native peer and helper process identity,
authenticates the process-start event and final response, and proves the fixed
script descriptor can read an authorized input and write inside a private
staged root without writing back to the host root. The helper request HMAC,
attestation config, and public key now travel through unlinked close-on-exec
descriptors; no helper key material is left in the task-visible container.
Before reporting availability, the executor also requires a host-owned
SHA-256 identity for the exact helper artifact and rechecks the pathname after
spawn. This is an artifact-substitution fence, not a substitute for the
Developer ID/notarization/Gatekeeper release gate.
The startup contract now makes the trust mode explicit: `development-probe`
is the only mode that can use this ad-hoc candidate, while `production`
requires the complete read-only release preflight evidence for the exact
`AppSandboxHelper.app` bundle. That evidence binds the bundle tree digest,
Developer ID identifier/Team ID/CDHash, and Gatekeeper notarization readback;
the executor re-reads the bundle before each production run and rejects owner,
inode, mode, file-count, byte-count, or digest drift. Production mode cannot
be constructed without this evidence. The physical host still has zero valid
Developer ID identities, so no production evidence was generated or enabled.
The staging path uses the native root-bound listing/read APIs, includes hidden
entries, bounds depth/entries/bytes, and rejects symlinks and unsupported file
types. The physical executor probe places its authorized source root in a
temporary host directory outside the App Sandbox container, then verifies the
task reads and writes only the staged copy.

```text
npm run probe:app-sandbox:executor
```

Observed result:

```json
{
  "probe": "macos-app-sandbox-task-executor-roundtrip",
  "helper_authentication": "verified",
  "descriptor_snapshot": "verified",
  "process_event": "verified",
  "fixed_interpreter": "/bin/sh",
  "script_descriptor": "verified",
  "staged_root_read_write": "verified",
  "outside_read_denied": "verified",
  "control_material_unreachable": "verified",
  "network_connect_denied": "verified",
  "persistence_write_denied": "verified",
  "credential_zone_read_denied": "verified",
  "run_cleanup": "verified",
  "production_enablement": "host-evidence-gated"
}
```

The executor-level script also attempted a controlled loopback connection
through the `/bin/sh` `/dev/tcp` builtin, a unique `~/Library/LaunchAgents`
canary write, and an open of the existing `~/.ssh` directory. The network,
persistence, and credential-zone attempts were all denied inside the helper
boundary; the credential check did not read secret content. This closes only
the no-network hostile case. Positive allowlisted networking, release
signing, rollback, and public capability enablement remain open. The staged
files are intentionally not written back to host roots; host mutations remain
separate governed filesystem tools.

The repeatable hostile variant is:

```text
npm run probe:app-sandbox:executor:hostile
```

Its observed result included `hostile_process_tree: "verified"` and a
terminal result with `resultClass: "UNKNOWN_OUTCOME"` after approximately
52 ms.

The optional hostile process-tree probe starts a background `/bin/sleep` under
the fixed script. The native helper installs a `kqueue` `EVFILT_PROC/NOTE_FORK`
monitor behind a pre-exec gate, detects the fork, terminates the owned process
group, and returns an authenticated `UNKNOWN_OUTCOME` in about 52 ms. The
probe confirms no helper, sleep process, or run-directory residue remains.
This verifies the fixed single-process boundary for the current shell-builtin
script mode; it does not yet prove broader descendant ownership, positive
allowlisted networking, release signing, rollback/recovery, or production
enablement.

## Interpretation

This closes only the narrow host-behavior question that the App Sandbox
entitlement can enforce a container boundary for a separately signed helper
and its fixed child on this physical Mac. The Broker now also has a
disabled-by-default `AppSandboxTaskRunner` seam and a native executor
candidate wired through the startup assembly seam. The executor binds a
descriptor snapshot, a distinct helper audience, bounded arguments/environment,
and authenticated process ownership callbacks without sending host pathnames
across the helper boundary. Broker-side staging now maps authorized regular
files into a private per-run container and passes only the staged cwd FD; the
helper control key is FD-only and close-on-exec. It does not yet prove a
production task runner.
The remaining work is to resolve the `EPERM` executable-selection limitation
for the intended task model, validate the staged-root contract across the
remaining task profiles and write-back semantics, add hostile fixture coverage
for network/credentials/persistence and broader process ownership, complete
Developer ID signing/notarization and exact launch identity readback, and
define rollback/recovery evidence.

The App Sandbox container is therefore a candidate production mechanism, not
an enabled capability. The current `sandbox-exec` runner and public
`mac_task_run` scope remain disabled.

## Release-mode verification

The reproducible helper-specific release gate is
`npm run build && npm run verify:release:app-sandbox -- --manifest <canonical-path>`.
Its owner-only manifest binds the helper executable path, helper-content
SHA-256, exact `AppSandboxHelper.app` bundle path/tree digest, owner UID, and
Developer ID identifier/Team ID/CDHash. The command runs the fixed
`codesign`/Gatekeeper preflight, emits only redacted identity-bound evidence,
and exits non-zero for ad-hoc or otherwise unaccepted artifacts.

The source/staging release-mode regression covers the explicit development
probe path, production construction denial without Developer ID evidence, and
valid/invalid bundle signature and notarization readbacks. The full repository
regression passes 1,074/1,089 tests with 15 explicit skips and 0 failures.
This does not close the host release gate because the current machine still
has no valid signing identity or notarized helper artifact.

## Source-backed constraint

Apple documents App Sandbox as the supported macOS access-control technology
and documents sandbox inheritance for child tools, while the SDK `sandbox.h`
marks `sandbox_init` as deprecated and no longer supported. See:

- https://developer.apple.com/documentation/security/app_sandbox
- https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox
- https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html
