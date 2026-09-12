# macOS launchd packaging boundary

`com.mac-operator.broker.plist.in` is a reviewable LaunchAgent template, not an installed service. The `@...@` values must be replaced with canonical absolute paths and rendered through `renderLaunchdPlist` before installation.

The intended unprivileged user-agent layout is:

- plist: `~/Library/LaunchAgents/com.mac-operator.broker.plist`
- install root: an owner-controlled application directory
- logs: an owner-controlled log directory with separate stdout/stderr files
- program arguments: the exact Node binary followed by the exact Broker entrypoint; no shell string

The renderer intentionally emits no `EnvironmentVariables`, `UserName`, `Shell`, or privileged launchd keys. The service entrypoint must assemble `createMacOsNativeBrokerRuntime`, start with all capability switches disabled unless a verified policy enables them, and stop on `SIGTERM`/`SIGINT`.

`buildMacOsInstallPlan` is the non-executing installer boundary. It requires an explicit non-root UID, a package-owned JavaScript entrypoint, a signed artifact path, and an exact per-user plist path. The plan exposes fixed `/usr/bin/codesign` and `/bin/launchctl` argv with `/` cwd, an empty environment, 5-second timeout, and 128 KiB output cap. It also materializes write/bootstrap, bootout/restore, and bootout/remove actions without executing them.

`validateExistingServicePrecondition` binds upgrade, rollback, and uninstall to an exact previous source revision; install requires the service to be absent. `validateMacOsInstallReadback` requires the exact `gui/<uid>` domain, plist/program/log identity, unprivileged/no-shell/no-environment launchd facts, running native Broker runtime, matching source/contract/policy metadata, capability set, and code-signature identity before readiness is accepted.

`inspectMacOsInstallFilesystem` is the read-only filesystem preflight. It checks the complete user-home parent chain plus package root, working directory, executable, entrypoint, signed artifact, log directory, and (when required) plist with `lstat` twice. It rejects symlinks, foreign owners, group/other write bits, unexpected types, and device/inode changes; the eventual writer must still use descriptor-relative atomic operations.

`applyMacOsPlistPlan` is the bounded mutation primitive for `install`, `upgrade`, and `rollback` in a testable package root. It binds the target device/inode precondition, uses the native `openat`/`renameat`/`fsync` writer, verifies the reopened content and identity, and restores the previous bytes if an upgrade write fails. It does not implement uninstall deletion and never invokes `launchctl`.

Installation is intentionally not automated in this repository. A future installer must still perform owner/mode/symlink/atomic-write checks for package files, plist parent directories, and logs, then execute the reviewed plan only after signature verification and rollback backup success. Readback should use `launchctl print gui/<uid>/com.mac-operator.broker` and the bounded Broker service readback; neither command is run by the build or test suite.
