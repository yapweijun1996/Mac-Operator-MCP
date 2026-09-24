# Install-plan LaunchAgent lifecycle probe — 2026-09-22

Status: `PASS` for the disposable owner-domain lifecycle boundary; production
signed deployment remains gated by Developer ID/notarization and the separate
Broker/Edge runtime readback requirements.

The new opt-in probe exercises the actual macOS install-plan filesystem and
launchd commands without using the live R1 installation. It creates a
temporary owner-only install root, ad-hoc signs a disposable artifact, renders
and atomically writes the exact `com.mac-operator.broker` LaunchAgent plist,
bootstraps `gui/<uid>`, and reads back the exact service identity, program,
arguments, plist path, type, and running state. It then boots out the service,
applies the uninstall plan, and verifies both the launchd identity and plist
are absent.

Verification:

```text
MOPS_REAL_INSTALL_PLAN=1 npm run probe:install-plan:launchagent
```

Result: `macos-install-plan-launchagent-v1` returned
`readbackVerified=true`, `bootoutVerified=true`, and `cleanupVerified=true`.
A separate post-probe `launchctl print gui/<uid>/com.mac-operator.broker`
returned exit code `113` and the service was absent.

The probe is staging evidence only. It uses an ad-hoc disposable artifact,
does not install the live personal service, does not enable any MCP capability,
does not touch the root domain, and does not satisfy the production signing,
runtime, Keychain, Accessibility, or independent-review gates.
