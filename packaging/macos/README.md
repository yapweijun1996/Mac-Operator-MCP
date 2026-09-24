# macOS launchd packaging boundary

## Privileged-helper app bundle

`build:privileged-helper-app` produces a signed macOS arm64 `.app` bundle only;
it never installs or starts a LaunchDaemon. Run it as a non-root user after
`npm run build`, with an owner-only runtime descriptor and the official Node.js
v24.21.0 Darwin arm64 archive. The builder checks the archive's pinned SHA-256,
verifies the extracted Node executable's Node.js Foundation code signature,
compiles and runtime-smokes the native peer adapter with that archive's
matching headers, stages the Broker/contracts runtime and production
dependencies, embeds the validated runtime descriptor into the SEA executable,
and verifies the signed bundle and native-addon signatures.

Production signing uses a valid Developer ID Application identity and the
minimal V8 JIT entitlements; library validation is not disabled. The builder
does not notarize the bundle, approve capabilities, install it into the helper
root, write the LaunchDaemon plist, or execute `launchctl`. An ad-hoc signature
is available only for local packaging verification and is rejected whenever
the runtime descriptor enables a privileged capability. A production package
plan and host release/readback evidence remain separate gates.

Example commands:

```text
npm run build
npm run build:privileged-helper-app -- --runtime-descriptor /absolute/path/runtime-descriptor.json --node-archive /absolute/path/node-v24.21.0-darwin-arm64.tar.gz --output /absolute/path/MacOperatorPrivilegedHelper.app --identity 'Developer ID Application: Owner Name (TEAMID1234)'
npm run probe:privileged-helper-app -- /absolute/path/node-v24.21.0-darwin-arm64.tar.gz
```

The packaging probe creates a temporary fail-closed bundle, verifies dynamic
ESM runtime loading and signature readback, checks that ad-hoc mode cannot
enable capabilities, and removes its temporary output. It is not production
signing, notarization, root-domain installation, or live helper acceptance.

`com.mac-operator.edge.plist.in` and `com.mac-operator.broker.plist.in` are
reviewable LaunchAgent templates, not installed services. The `@...@` values
must be replaced with canonical absolute paths and rendered through
`renderLaunchdPlist` before installation.

The intended unprivileged user-agent layout is:

- Edge plist: `~/Library/LaunchAgents/com.mac-operator.edge.plist`
- Broker plist: `~/Library/LaunchAgents/com.mac-operator.broker.plist`
- install root: an owner-controlled application directory
- logs: an owner-controlled log directory with separate Edge and Broker
  stdout/stderr files
- Edge program arguments: the exact Node binary followed by the exact Edge
  entrypoint; no shell string
- Broker executable and JavaScript entrypoint: both reside inside the signed
  `MacOperatorBroker.app` bundle. The Broker install-plan builder rejects a
  launch target outside that signed artifact so the verified code is the code
  launchd will execute.

For the complete three-component deployment, the Authority agent is bootstrapped
first, then Edge, then Broker. Broker startup reads the exact
`gui/<uid>/com.mac-operator.edge`
launchd identity and binds its native IPC peer policy to that Edge PID/start-time
identity. The Broker status socket is a separate operator/readback channel and
must remain usable by the authenticated installer process; it is not an Edge
request channel.

An enabled operator authority channel must be a separate owner-domain
LaunchAgent with the exact identity
`gui/<uid>/com.mac-operator.authority`. Broker startup accepts that channel
only when its key configuration and socket are distinct, root-bound, and
explicitly configured; it reads the exact launchd record and native PID/start
time before constructing the separately authenticated Authority Control IPC
runtime. `xpcproxy` is retried only as bounded startup transience. The
repository now contains the proxy entrypoint and reviewable plist template, but
does not install, bootstrap, or enable this operator service; absent the
complete identity, startup fails closed.

The operator entrypoint is `authority-control-service.js`. Its reviewed plist
template is `com.mac-operator.authority.plist.in`, and the read-only plan
compiler is `npm run plan:macos:authority`. The plan requires the exact
owner-only `broker-service.json` path as a fixed `--config` argument and emits
inverse plist/bootout actions; it does not install or start the service.

The renderer intentionally emits no `EnvironmentVariables`, `UserName`, `Shell`, or privileged launchd keys. The Edge entrypoint loads the adjacent protected `edge-service.json`; the Broker entrypoint assembles `createMacOsNativeBrokerRuntime`, starts with all capability switches disabled unless a verified policy enables them, and both stop on `SIGTERM`/`SIGINT`.
The Broker startup configuration must also provide an owner-controlled audit
anchor path below the Broker data root plus the fixed Keychain service,
account, and key identifier. Startup loads the HMAC key through the
Broker-executable ACL; a missing or mismatched Keychain item, unsafe anchor
path, or failed sidecar verification aborts before the service reaches
`running`. No environment variable or MCP argument can select these values.
For the host-only encrypted audit archive procedure, the startup config may
also provide `auditArchiveKeyService`, `auditArchiveKeyAccount`, and
`auditArchiveKeyId`. All three are required together and must identify a
separate Broker-executable-ACL Keychain item; the archive CLI derives its
fixed `<dataRoot>/audit-exports` destination from this config and never accepts
an arbitrary destination or raw key.

`buildMacOsEdgeInstallPlan` and `buildMacOsInstallPlan` are the non-executing installer boundaries for Edge and Broker. They require an explicit non-root UID, a package-owned JavaScript entrypoint, a signed artifact path, and an exact per-user plist path. The Edge plan additionally binds the expected listener host/port and requires a running, listening Edge readback; the Broker plan requires the running native transport and capability set. Both plans expose fixed `/usr/bin/codesign` and `/bin/launchctl` argv with `/` cwd, an empty environment, 5-second timeout, and 128 KiB output cap. They materialize write/bootstrap, bootout/restore, and bootout/remove actions without executing them.

Production plans default to `signaturePolicy: "developer-id"` and require the
component's exact code-signature identifier, a 10-character Developer ID Team
Identifier, and a CDHash before a plan can be rendered. The explicit
`development-ad-hoc` policy exists only for temporary host fixtures and rejects
any enabled capability; it is never a production enablement path.

`validateExistingServicePrecondition` binds upgrade, rollback, and uninstall to an exact previous source revision; install requires the service to be absent. `validateMacOsEdgeInstallReadback` and `validateMacOsInstallReadback` require the exact `gui/<uid>` domain, plist/program/**ProgramArguments**/log identity, native PID/start-time identity, descriptor-backed plist device/inode/digest, unprivileged/no-shell/no-environment launchd facts, matching source/contract/policy metadata, listener or native-transport readiness, and code-signature identity before readiness is accepted. `composeMacOsEdgeInstallReadback` and `composeMacOsInstallReadback` accept only bounded `launchctl print` readback whose argument list exactly matches the planned Node binary and component entrypoint.

For Broker, the signed-artifact path also encloses both the executable and its
JavaScript entrypoint. This binds signature/notarization verification to the
launch target and keeps any Virtualization.framework entitlement on the
unprivileged Broker executable that hosts the native bridge, not on the root
helper. This is path validation only: it does not produce a production Broker
bundle or prove Developer ID signing, notarization, or VM boot.

macOS can report a freshly bootstrapped LaunchAgent as `state = xpcproxy`
before it reaches `running`. The generic readback adapter normalizes this
transient value to `launching`; production Edge/helper readiness remains
strict and accepts only `running` plus a matching native PID/start-time
identity.

`inspectMacOsInstallFilesystem` is the read-only filesystem preflight. It checks the complete user-home parent chain plus package root, working directory, executable, entrypoint, signed artifact, log directory, and (when required) plist with `lstat` twice. It rejects symlinks, foreign owners, group/other write bits, unexpected types, and device/inode changes; the eventual writer must still use descriptor-relative atomic operations.

`applyMacOsPlistPlan` is the bounded mutation primitive for `install`, `upgrade`, `rollback`, and exact-target `uninstall` in a testable package root. It binds the target device/inode precondition, uses the native `openat`/`renameat`/`fsync` writer or `unlinkat` remover, verifies postconditions, and restores the previous bytes if an upgrade/uninstall step fails. It never exposes recursive deletion and never invokes `launchctl`.

Installation is intentionally not automated in this repository. A future
installer must still perform owner/mode/symlink/atomic-write checks for package
files, both plist parent directories, and logs, then execute the reviewed plans
only after signature verification and rollback backup success. Install order is
Edge, Edge identity readback, Broker, Broker readback; uninstall order is the
reverse after authenticated authority disable/revocation. Readback should use
`launchctl print gui/<uid>/com.mac-operator.edge`,
`launchctl print gui/<uid>/com.mac-operator.broker`, and the bounded Broker
status channel; none of these commands is run by the build or default test
suite.

The declarative handoff is available as the read-only
`npm run plan:macos:launchagents -- --manifest <absolute-path>` compiler. It
delegates validation to the Edge/Broker plan builders and emits exact plist,
launchd, signature, metadata, and preflight readback without writing or
bootstrapping anything. A separate explicit host-owned apply command is
available only with a primary and exact-inverse recovery manifest:

```text
npm run apply:macos:launchagents -- --manifest PRIMARY.json --recovery INVERSE.json --confirm install|upgrade|rollback|uninstall --apply
```

The same host-owned command has a read-only restart verification mode:

```text
npm run readback:macos:launchagents -- --manifest PRIMARY.json --recovery INVERSE.json --confirm install --readback
```

Readback never writes plists, calls `launchctl bootstrap`/`bootout`, or changes
authority. It reuses the protected status keys and exact component observers;
all planned components must match launchd, PID/start-time, plist, signature,
metadata, and status-channel readback. An absent or substituted component
fails closed.

Apply and readback also bind to the owner-only deployment journal at
`.macos-launchagent-deployment.journal.json` under the planned install root.
Publication is bounded and atomic (`O_NOFOLLOW`, owner-only mode, `fsync`,
same-directory rename, and readback). It records no secret or command output;
an interrupted controller leaves `in-progress`, while `recovery-required`
remains fail-closed until an operator performs the inverse recovery and a
fresh readback.

Apply rejects development ad-hoc plans, requires authenticated Edge/Broker
status channels and production release evidence, and requires Broker authority
control material whenever either manifest operation is uninstall. The command
is never an MCP handler and does not run by default; absent the explicit
`--apply` flag it performs no mutation.

The root-helper handoff is separately compiled by the strict read-only command
`npm run plan:root-helper -- --manifest <absolute-path>`. It delegates to the
root-helper package plan builder, emits native artifact/release metadata,
protected paths, rollback commands, and all four socket bindings, and always
reports `apply.available: false`. It does not load key material, write the
system plist, invoke `launchctl`, or install the root service. The separate
host-only apply handoff is `npm run apply:root-helper -- --manifest
<absolute-path> --confirm install` (use `upgrade`, `rollback`, or `uninstall`
for those exact operations); it requires root, exact operation confirmation,
authenticated root-helper status readback, and fixed rollback behavior.

The separately authenticated privileged helper has the same host-only handoff
shape. The read-only plan command is:

```text
npm run plan:privileged-helper -- --manifest <absolute-path>
```

It validates the exact `system/com.mac-operator.privileged-helper`
LaunchDaemon, native-only signed artifact, distinct helper/Broker/authority
sockets, Broker peer identity, protected key configuration, and explicit
capability release without writing or bootstrapping anything. The gated apply
command is:

```text
npm run apply:privileged-helper -- --manifest <absolute-path> --confirm install|upgrade|rollback|uninstall
```

Apply requires a root process, loads the protected helper key, samples the
existing service twice, verifies the Developer ID/notarized artifact, applies
the exact plist through the descriptor-relative writer, runs only the planned
`launchctl` command, and requires authenticated helper status plus launchd,
socket, plist, signature, and process-identity readback. Any failed step uses
the plan's inverse recovery and refuses to report success if recovery is not
verified. This command is host-only and is never an MCP handler; it was not
run as part of repository verification.

The host-owned coordinator in
`packages/broker/src/macos-install-coordinator.ts` binds the component
executors into one fixed-order transaction. It runs Edge before Broker for
install, upgrade, and rollback, reverses the order for uninstall, and requires
an inverse action for every completed component. A second-step failure is
reported separately from a recovered failure and a `recovery-required` failure;
the coordinator never converts either into success. Its concrete plan-set
controller calls the existing component executors, rejects ad-hoc or
non-notarized plans in production mode, and requires the separately
authority-gated Broker uninstall path. It is not an MCP handler and remains
disabled until a production host controller supplies the required release,
authority, and readback evidence.

The physical-host evidence includes a reversible temporary LaunchAgent smoke
that uses the plan's real signature, preflight, atomic plist, bootstrap,
readback, bootout, and uninstall primitives, plus a separate Broker startup
smoke with signed policy/key restore and zero enabled capabilities. A
Darwin-only cross-process Edge smoke completes the signed HTTPS-to-native-
Broker exchange and binds the native peer to the exact Edge UID/GID and
PID/start-time identity. These are temporary host/process-boundary checks;
they do not establish persistent Edge/Broker LaunchAgent installation,
Developer ID provenance, remote issuer interoperability, or production key
distribution.

The opt-in packaged-service smoke (`MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1
node --test packages/broker/dist/packaged-service-smoke.test.js`) starts both compiled
entrypoints as real per-user LaunchAgents, reads back launchd and Broker status
plus the Keychain-backed audit anchor, and verifies bounded bootout/absence. It refuses to run when either
fixed label is already loaded and copies dependencies into a temporary package
root so workspace symlinks are not part of the evidence.

The test suite includes a real macOS smoke check that creates a synthetic app bundle in a temporary directory, signs it ad hoc with `/usr/bin/codesign`, and verifies it through the plan's fixed `--verify --strict --deep` command. This proves command wiring and basic host compatibility only; it is not production Developer ID signing, notarization, certificate/key protection, or installed-service evidence.

The release candidate gate is the read-only `runMacOsReleasePreflight` boundary
and its manifest CLI (`npm run build && npm run verify:release:macos --
--manifest /absolute/path/release-manifest.json`). The owner-only manifest binds
one canonical artifact path, its expected deterministic tree SHA-256 and byte
count, the release owner's UID, and the exact Developer ID identifier, Team ID,
and CDHash. The gate re-hashes regular files through an `O_NOFOLLOW` descriptor,
rejects symlinks/special files, writable entries, owner changes, identity/path
swaps, 64-level depth and entry/byte-budget overruns, and digest mismatches,
then runs only fixed
`/usr/bin/codesign` and `/usr/sbin/spctl` commands with `/` cwd, empty
environment, 5-second timeout, and 128 KiB output caps. It emits bounded
artifact/signature/notarization evidence and never writes host state. Ad-hoc
signatures and Apple System Gatekeeper provenance fail closed.
