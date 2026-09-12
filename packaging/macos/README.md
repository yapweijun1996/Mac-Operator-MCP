# macOS launchd packaging boundary

`com.mac-operator.broker.plist.in` is a reviewable LaunchAgent template, not an installed service. The `@...@` values must be replaced with canonical absolute paths and rendered through `renderLaunchdPlist` before installation.

The intended unprivileged user-agent layout is:

- plist: `~/Library/LaunchAgents/com.mac-operator.broker.plist`
- install root: an owner-controlled application directory
- logs: an owner-controlled log directory with separate stdout/stderr files
- program arguments: the exact Node binary followed by the exact Broker entrypoint; no shell string

The renderer intentionally emits no `EnvironmentVariables`, `UserName`, `Shell`, or privileged launchd keys. The service entrypoint must assemble `createMacOsNativeBrokerRuntime`, start with all capability switches disabled unless a verified policy enables them, and stop on `SIGTERM`/`SIGINT`.

Installation is intentionally not automated in this repository. Before a future installer calls `launchctl bootstrap`, it must verify the package signature, owner/mode of the plist and parent directories, native module identity, exact source/contract/policy readback, and rollback readiness. Readback should use `launchctl print gui/$(id -u)/com.mac-operator.broker` and the bounded Broker service readback; neither command is run by the build or test suite.
