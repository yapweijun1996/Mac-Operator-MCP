# Governed App Inventory Boundary Evidence

- Date: 2026-09-13
- Source commit: `072cbd4`
- Repository state: dirty after the source commit because documentation updates are pending; no production policy change
- Host: macOS arm64 development host
- Scope: read-only app inventory; app launch, focus, Accessibility, and GUI actions remain unavailable
- Policy state: `mac_app_list` is implemented and enabled as a bounded read-only inspection tool when `enableReadTools` is selected; app mutation and GUI tools remain disabled or unimplemented

## Boundary implemented

`mac_app_list` binds the Broker-owned target `app_set:all` and independent `mac.app.read` scope. It accepts only boolean `running_only` and `include_installed` filters. The adapter owns a fixed `/usr/bin/osascript -l JavaScript` invocation and a constant JXA program; caller-provided scripts, paths, executable names, and arguments are not accepted.

The JXA program reads bundle metadata from fixed macOS application roots and `NSWorkspace` running-application metadata. The result crosses the boundary only as a bounded list of stable `bundle:<bundle_id>` identity, bundle ID, redacted name, optional redacted version, and running state. Paths, PIDs, process arguments, environments, and raw script output are omitted. Parsing enforces identifier, string-length, count, filter, duplicate, and output-budget limits and returns stable warnings for redaction or truncation.

## Verification performed

- Parser tests cover filtering, sorting, duplicate handling, malformed metadata, traversal-like bundle identifiers, and redaction.
- Adapter boundary tests assert `/usr/bin/osascript`, `-l JavaScript`, the constant Broker-owned JXA, `/` cwd, and an empty environment.
- Broker integration verifies exact `app_set:all` target authorization, independent `mac.app.read` scope, sanitized result metadata, verification hashing, and audit target binding.
- Contract and policy conformance cover the app-set target kind and `mac_app_list` request shape.
- A real macOS host query returns a bounded running-app list and validates stable bundle identities without exposing bundle paths or process details.
- Commands run after implementation: `npm test` (257 passing), `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev --audit-level=high`, and `git diff --check`.

## Limits and remaining release work

This is bounded read-only prototype evidence, not GUI release evidence. Installed-app completeness, app launch/focus, app/window identity freshness, Accessibility permission and tree observation, sensitive-surface/credential-UI policy, action adapters, crash/revocation behavior for GUI work, packaging, and final readback remain open under `MOP-050` through `MOP-055` and `VT-UI-01`/`VT-UI-02`.
