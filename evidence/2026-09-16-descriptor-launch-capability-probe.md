# Descriptor Launch Capability Probe

Date: 2026-09-16
Host: physical Mac mini; macOS 26.2 arm64
Source revision: `81a67b1`

## Result

The native peer addon now exposes a versioned host capability record for the
descriptor-execution boundary. On this host the record is deliberately
unavailable:

```json
{"schemaVersion":"0.1","mechanism":"darwin-descriptor-exec-v1","available":false,"executableCoverage":"unproven","immutableSelection":"unproven","closeOnExec":"unproven","evidenceRef":"mac-operator-native-descriptor-exec-unavailable-v1"}
```

The Broker therefore keeps descriptor-required task execution closed and
returns the stable `POLICY_DENIED` admission error. The native adapter loader
also requires the capability export, so an older or partially rebuilt addon
cannot silently look like a complete host boundary.

## Verification

`npm run build`, `npm run typecheck`, `npm run lint`, `npm run verify:docs`,
`npm run verify:matrix`, and the focused process-launch and ProcessSupervisor
tests pass. No physical sandbox claim is made: immutable executable selection,
close-on-exec, and all-child coverage remain unproven until a real native
descriptor launcher is implemented and independently exercised.

