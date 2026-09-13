# Live macOS Install-Plan Evidence

Status: Partial real-host packaging lifecycle; Broker readiness remains closed

## Scope

This smoke exercises the existing host-only install-plan primitives against a
temporary user-domain LaunchAgent. It deliberately does not install the real
Broker, Edge, privileged helper, or a persistent production service.

## Procedure

- Created a unique owner-only temporary package root and copied the current
  Node runtime into its package-owned `bin` directory.
- Created a minimal package-owned JavaScript entrypoint that only waits, and a
  temporary app bundle signed ad hoc with the fixed `/usr/bin/codesign`
  command. No Developer ID identity or private signing key was used.
- Built a plan with the real `buildMacOsInstallPlan`, ran its signature
  verification and filesystem preflight, then used `applyMacOsPlistPlan` for
  descriptor-relative atomic plist publication.
- Executed only the plan's fixed `/bin/launchctl bootstrap` command in the
  current user's `gui/<uid>` domain. The production readback adapter observed
  the running LaunchAgent and the native peer adapter captured its PID and
  start-time identity.
- Executed the exact plan bootout, applied an exact uninstall plan, and
  confirmed the service was unavailable and the plist absent. Temporary files
  and directories were removed in a `finally` path.

Observed result:

```text
serviceId=gui/501/com.mac-operator.mops-plan-32478
state=running
pid=32482
plistBytes=1274
preflightEntries=9
plistMode=600
applied=install
removed=uninstall
```

## Acceptance boundary

This proves real launchd command compatibility, owner-only plist publication,
live readback, native PID/start-time capture, bootout, and uninstall absence.
It does not prove `executeMacOsInstallPlan` final readiness because that API
correctly requires an independently observed Broker metadata/readback source;
the temporary waiting process was never represented as a Broker. It also does
not prove Developer ID signing, notarization, installed Broker/Edge identity,
upgrade rollback of the production artifact, or helper installation.

The first smoke harness attempt tried to read the plist mode after uninstall
and received the expected `ENOENT`; cleanup completed and the corrected rerun
passed the full lifecycle above.
