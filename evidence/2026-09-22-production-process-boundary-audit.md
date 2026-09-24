# Production child-process boundary audit

Date: 2026-09-22
Status: source gate passed; host capability enablement remains unchanged

## Command

```text
npm run verify:process-boundaries
```

Observed output:

```json
{
  "schemaVersion": "0.1",
  "mechanism": "production-child-process-boundary-audit-v1",
  "auditedFiles": [
    "packages/auth/src/personal-service.ts",
    "packages/broker/src/app-sandbox-task-executor.ts",
    "packages/broker/src/process-supervisor.ts"
  ],
  "auditedScripts": [
    "scripts/check-completion-audit.mjs",
    "scripts/check-style.mjs",
    "scripts/probe-app-sandbox-boundary.mjs",
    "scripts/probe-app-sandbox-helper.mjs",
    "scripts/probe-d1-git-boundary.mjs",
    "scripts/probe-host-readiness.mjs",
    "scripts/probe-root-helper-native-auth.mjs",
    "scripts/probe-sandbox-boundary.mjs",
    "scripts/probe-user-service-mutation-boundary.mjs",
    "scripts/probe-user-service-rollback-boundary.mjs",
    "scripts/record-host-readiness.mjs"
  ],
  "shell": "explicit-false",
  "limits": "explicit-cwd-minimal-env-timeout-output-cap-cancellation",
  "unreviewedEntries": 0,
  "unreviewedScriptEntries": 0
}
```

The verifier recursively scans production Auth, Edge, and Broker TypeScript
sources, excludes test fixtures, identifies direct `node:child_process` imports
and process-launch calls, and rejects any entry outside the reviewed allowlist.
Every reviewed entry must contain an explicit `shell: false` option and no
`shell: true` option. The current production paths therefore remain limited to
the fixed Auth/Edge supervisor children, the bounded Broker process supervisor,
and the fixed App Sandbox helper.
The verifier also requires the production sources to expose their relevant
working-directory, minimal-environment, timeout, output-cap, and cancellation
controls; long-lived Auth/Edge children satisfy cancellation through the fixed
supervisor stop path.

This is a source-regression gate, not proof of Developer ID provenance,
macOS sandbox enforcement, or live capability enablement. Those require the
separate physical-host and release evidence recorded in the completion audit.
The command performs no host mutation and does not restart the R1 deployment.

## Physical host readback

Command:

```text
node scripts/probe-system-published-executable.mjs
```

Observed output:

```json
{
  "schemaVersion": "0.1",
  "mechanism": "darwin-system-published-executable-v1",
  "paths": {
    "/bin/launchctl": true,
    "/usr/bin/sandbox-exec": true,
    "/usr/bin/printf": true
  }
}
```

The current Darwin host therefore passes the fixed system-published executable
identity check for the reviewed child-process paths. This is additional
readback evidence for the allowlisted boundary; it does not close the separate
Developer ID, notarization, sandbox-capability, Accessibility, or persistent
service gates.

The physical fixed Seatbelt probe also passed its bounded output and timeout
readback together with the allowed/denied filesystem cases. The standalone
App-Sandbox helper round-trip now passes its bounded descriptor handoff,
attestation/HMAC, fixed-interpreter, container-write, and outside-write-denial
cases. The native fix preserves the cwd descriptor across control-descriptor
cleanup; the fixture uses a shell builtin write so the single-process policy is
tested without an unrelated external child. The packaged executor probe also
passes its descriptor-backed staging, hostile-process, and cleanup checks.
