# Repository Child-Process Script Audit — 2026-09-23

## Scope

The process-boundary checker identified three privileged-helper build/probe
scripts that invoked child processes but were not yet in its reviewed set. The
scripts were inspected and their command invocations now explicitly disable
shell interpretation, use a declared working directory/environment, and bound
runtime and captured output. Probe/build children continue to use fixed
executables and argument arrays. No helper build, signing operation, service
installation, or launchd mutation was performed as part of this audit.

## Verification

`npm run verify:process-boundaries` passes. Its readback reports 3 reviewed
production child-process source files, 15 reviewed repository scripts, 0
unreviewed production entries, and 0 unreviewed script entries. The three
newly reviewed scripts are:

- `scripts/build-privileged-helper-app.mjs`
- `scripts/probe-privileged-helper-app.mjs`
- `scripts/probe-privileged-helper-sea.mjs`

This static check is an inventory and bounded-source assertion; it does not
prove that packaging, signing, notarization, or a production helper launch
succeeds. Those remain separate release gates.
