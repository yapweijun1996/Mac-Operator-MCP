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

`buildMacOsInstallPlan` is the non-executing installer boundary. It requires an explicit non-root UID, a package-owned JavaScript entrypoint, a signed artifact path, and an exact per-user plist path. The plan exposes fixed `/usr/bin/codesign` and `/bin/launchctl` argv with `/` cwd, an empty environment, 5-second timeout, and 128 KiB output cap. It also materializes write/bootstrap, bootout/restore, and bootout/remove actions without executing them.

`validateExistingServicePrecondition` binds upgrade, rollback, and uninstall to an exact previous source revision; install requires the service to be absent. `validateMacOsInstallReadback` requires the exact `gui/<uid>` domain, plist/program/**ProgramArguments**/log identity, native PID/start-time identity, descriptor-backed plist device/inode/digest, unprivileged/no-shell/no-environment launchd facts, running native Broker runtime, matching source/contract/policy metadata, capability set, and code-signature identity before readiness is accepted. `composeMacOsInstallReadback` accepts only a bounded `launchctl print` readback whose argument list exactly matches the planned Node binary and Broker entrypoint.

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
readback, bootout, and uninstall primitives. It intentionally stops before
Broker readiness: the final installer callback must provide an independently
observed Broker metadata/native transport/signature readback, not a synthetic
success from a temporary process.

The test suite includes a real macOS smoke check that creates a synthetic app bundle in a temporary directory, signs it ad hoc with `/usr/bin/codesign`, and verifies it through the plan's fixed `--verify --strict --deep` command. This proves command wiring and basic host compatibility only; it is not production Developer ID signing, notarization, certificate/key protection, or installed-service evidence.
