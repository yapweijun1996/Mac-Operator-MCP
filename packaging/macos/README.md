# macOS launchd packaging boundary

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
- program arguments: the exact Node binary followed by the exact component
  entrypoint; no shell string

The Edge agent must be bootstrapped and reach `running` before the Broker agent
is started. Broker startup reads the exact `gui/<uid>/com.mac-operator.edge`
launchd identity and binds its native IPC peer policy to that Edge PID/start-time
identity. The Broker status socket is a separate operator/readback channel and
must remain usable by the authenticated installer process; it is not an Edge
request channel.

The renderer intentionally emits no `EnvironmentVariables`, `UserName`, `Shell`, or privileged launchd keys. The Edge entrypoint loads the adjacent protected `edge-service.json`; the Broker entrypoint assembles `createMacOsNativeBrokerRuntime`, starts with all capability switches disabled unless a verified policy enables them, and both stop on `SIGTERM`/`SIGINT`.
The Broker startup configuration must also provide an owner-controlled audit
anchor path below the Broker data root plus the fixed Keychain service,
account, and key identifier. Startup loads the HMAC key through the
Broker-executable ACL; a missing or mismatched Keychain item, unsafe anchor
path, or failed sidecar verification aborts before the service reaches
`running`. No environment variable or MCP argument can select these values.

`buildMacOsEdgeInstallPlan` and `buildMacOsInstallPlan` are the non-executing installer boundaries for Edge and Broker. They require an explicit non-root UID, a package-owned JavaScript entrypoint, a signed artifact path, and an exact per-user plist path. The Edge plan additionally binds the expected listener host/port and requires a running, listening Edge readback; the Broker plan requires the running native transport and capability set. Both plans expose fixed `/usr/bin/codesign` and `/bin/launchctl` argv with `/` cwd, an empty environment, 5-second timeout, and 128 KiB output cap. They materialize write/bootstrap, bootout/restore, and bootout/remove actions without executing them.

Production plans default to `signaturePolicy: "developer-id"` and require the
component's exact code-signature identifier, a 10-character Developer ID Team
Identifier, and a CDHash before a plan can be rendered. The explicit
`development-ad-hoc` policy exists only for temporary host fixtures and rejects
any enabled capability; it is never a production enablement path.

`validateExistingServicePrecondition` binds upgrade, rollback, and uninstall to an exact previous source revision; install requires the service to be absent. `validateMacOsEdgeInstallReadback` and `validateMacOsInstallReadback` require the exact `gui/<uid>` domain, plist/program/**ProgramArguments**/log identity, native PID/start-time identity, descriptor-backed plist device/inode/digest, unprivileged/no-shell/no-environment launchd facts, matching source/contract/policy metadata, listener or native-transport readiness, and code-signature identity before readiness is accepted. `composeMacOsEdgeInstallReadback` and `composeMacOsInstallReadback` accept only bounded `launchctl print` readback whose argument list exactly matches the planned Node binary and component entrypoint.

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
rejects symlinks/special files, writable entries, owner changes, identity swaps,
entry/byte-budget overruns, and digest mismatches, then runs only fixed
`/usr/bin/codesign` and `/usr/sbin/spctl` commands with `/` cwd, empty
environment, 5-second timeout, and 128 KiB output caps. It emits bounded
artifact/signature/notarization evidence and never writes host state. Ad-hoc
signatures and Apple System Gatekeeper provenance fail closed.
