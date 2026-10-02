# Chrome GUI reusable authorization repair — 2026-10-02

Historical record of the earlier repair and permission renewal. The follow-up
[window-resolution report](2026-10-02-chrome-window-resolution.md) records the
current deployed production MCP acceptance, which now passes. Evidence below
belongs to that earlier deployment and is retained as historical provenance.

## Root cause and current deployment

- The supplied g1 environment is historical. Live PM2 was running
  `personal-20261002-terminal-codex-b`, source
  `806635607dc552a5fa8bf4322334b74f453d1896`, with state in
  `~/Library/Application Support/MacOperator-o1-20261001a` and policy-3.
- Initial connector focus request `a47b97d8-5ff0-4161-a1e9-8c89777db9ab`
  returned `POLICY_DENIED: No valid approval matches this mutation`.
  Protected metadata inspection found only a revoked policy-1 Chrome consent.
  This was not missing OAuth authority.
- Initial `capture_mode=none` request
  `e652c510-0c47-43ba-bda3-5c9fda5c631a` returned Accessibility denial. It ran
  the metadata-only `/usr/bin/osascript` branch, whereas screenshots and focus
  ran the native application. The installed old native app reported both
  permissions granted and successfully performed screenshot-backed operations.
- Current canonical focus and GUI mutation approval is `trusted_gui`.
  `trusted_app_control` is not a supported current approval class. No alias,
  weakened read classification or policy migration was introduced.
- A policy dry-run with no app-window target defaulted to host/broker and
  returned PRECONDITION_FAILED. Supplying the resolved app-window target instead
  returned AUTHORIZED (`bd4037a9-44d0-4050-adfc-f4d3b09a5902`). Dry-runs do not
  create consent or prove adapter execution.

## Request and approval architecture

MCP `/mcp` -> Edge bearer/OAuth status and scope projection -> signed Broker
request/nonce -> principal, policy, scope and target checks -> resolved app or
caller/session-owned UI snapshot -> GuiSessionApprovals -> owner issuer IPC ->
exact approval consumption in BrokerStore -> durable Job -> GuiProcessSupervisor
-> fixed gui_launcher -> LaunchServices -> fixed native app -> AX/ScreenCaptureKit
-> bounded parsed result and reobservation.

AuthStore `records(kind=browser_grant)` stores persistent owner consent.
Temporary consent is held by the supervisor, lasts 30 minutes and reserves at
most 500 operations. Permanent consent is revocable, survives restart and is
not an expiring approval-login cookie. Consent matches exact app/principal/policy;
temporary consent additionally matches the original OAuth session. Incoming
OAuth expiry/revocation, scopes and signed target policy are checked independently.
Old consent is not upgraded and revoked rows are not repaired by direct writes.

Every permitted mutation receives an exact tool, target, payload, contract,
principal and policy-bound child approval through the attended issuer. The
reserved child ID includes the authenticated request identity. TTL is at most
30 seconds, use limit one. BrokerStore checks expiry, revocation and usage before
consuming it, and rechecks active request authority before dispatch/completion.
Grant revocation removes authority before cleanup and revokes outstanding children;
issuance rechecks consent after its asynchronous IPC boundary.

This repair also validates the focus/element delegation target shape. Reusable
consent does not cover submit=true, Enter submission or named sensitive AX
actions; those need the independent exact operation approval. Named sensitive
visual hits remain denied. Scope/target/TCC checks stay fail-closed.

Read-only observation uses its existing `mac.ui.observe` scope and signed browser
target allowlist; it does not consume a mutation approval. The reusable grant
does not expand those read permissions. The repaired live consent is Chrome only.

## Process identity and permissions

- App: `/Users/yapweijun/Applications/Mac Operator GUI.app`
- Bundle: `dev.macoperator.personal.gui`
- AX executable: the app's `Contents/MacOS/gui_vision` (arm64).
- Fixed launcher: the active release's `packages/broker/dist/gui_launcher`.
- Broker/Auth Node performs authorization and transport, not the production AX calls.

All production observe modes now use the native app. Its bounded AX tree includes
only the selected window, retains the focused node at index zero for typing,
avoids field values, masks secure labels and does not traverse secure descendants.
AX element actions validate current index/role/label/enabled/non-secure identity.
Snapshot expiry, owner/session binding and screenshot revalidation are preserved.

| Operation | Accessibility | Screen Recording |
| --- | --- | --- |
| Native focus / AX action / metadata-only observation | Required | No capture request |
| active_window / selected_window / screen | Required for AX observation | Required, checked before capture |

ScreenCaptureKit captures still JPEGs, no audio. All screenshot modes share the
CGPreflightScreenCaptureAccess guard. Screen mode further rejects visible outside
windows/overlays. Apple reference:
[Screen and system audio permissions](https://support.apple.com/guide/mac-help/control-access-screen-system-audio-recording-mchld6aa7d23/mac).

Installed/build executable SHA-256:
`112dabaa5891a03b8db25ea7b14eec85dbcc5e6f7ba4d4fda10229777580538c`.
The bundle is ad-hoc signed; native replacement changed its TCC identity. Before renewal, direct
interactive execution reported true/true, but **the production LaunchServices
launcher reported false/false**. System Settings still showed its old entry on.
Direct launch is not authoritative service permission evidence.

Completed renewal: the owner performed the macOS system authentication, then
only the exact installed application was removed/re-added and enabled in
System Settings -> Privacy & Security -> Accessibility and Screen & System Audio
Recording. The production gui_launcher permission probe now reports
Accessibility=true and Screen Recording=true, matching direct launch. No native
rebuild or service restart was needed. Do not rebuild/reinstall again after renewal. No Node
grant, TCC database edit, SIP change or password access was performed.

## Tests and observed live evidence

Prior GUI repair `npm test`: 1605 total, 1587 passed, 18 conditional skips, zero failures.
Native compilation, TypeScript, lint, doc links and diff whitespace checks pass.
The final inspector suite passed 25/25 after adding native AX command routing
and secure pre-dispatch assertions. The permission probe now uses gui_launcher
instead of the racy open -W path and was executed successfully, reporting the
direct/LaunchServices mismatch without changing either grant.
The added focus regression originally expected POLICY_DENIED for missing scope;
the actual stable class is SCOPE_DENIED. Its assertion was corrected and the
final full suite passed. The skips are pre-existing opt-in host/production probes,
not evidence of GUI acceptance.
No tests were rerun for the final commit/main handoff, as requested by the owner.

New/updated checks cover:

- Chrome scope with no approval denies; missing scope denies before issuance.
- Valid exact Chrome grant allows focus; unapproved app cannot issue or dispatch.
- Grant target mismatch and sensitive operation cannot issue delegated approval.
- Existing expired/revoked/wrong-principal/session/app/policy grants deny.
- Existing session TTL/500-use bound, persistent restoration and issuance races.
- Metadata-only observation uses the fixed native identity and preserves provenance.
- Existing secure-node redaction, secure typing/action denial and stale postconditions.
- Native hit guards for purchase/send/delete/security labels.
- Owner review page offers temporary and revocable persistent choices.

Actual connector evidence before native replacement:

- Health `d23319aa-b322-4a23-8d95-949014913597`: healthy.
- Inventory `822173b2-f031-4064-a3ae-e633d13137b1`: Chrome running.
- Owner browser UI showed an active policy-3 Chrome until-revoked consent.
- Focus `ea31a649-401c-4122-8261-24ba9c555515`: SUCCEEDED, focused readback.
- active_window `319143c8-959e-4e06-87dd-e040148d534a`: SUCCEEDED, focused
  window identity, one AX node, opaque visual_ref and 1200x916 JPEG returned.
  The one-node limit motivated the bounded tree repair; this is historical
  pre-update evidence, not acceptance of the final native adapter.

After final deployment:

- Health `06e32a41-4e12-4fbb-8c4f-f106b843890b`: healthy.
- Focus `887f1ca7-c460-4da7-a7cc-45c7d912a545`: POLICY_DENIED, Accessibility
  missing. Read-only approval metadata proves its exact Chrome child approval
  was issued and consumed, trusted_gui, TTL 30000 ms, use limit/used count 1/1.
  The missing-grant blocker was resolved; the new TCC binding was renewed later
  through System Settings as recorded above. This failed historical focus call
  has not been rerun after renewal.
- Auth metadata shows policy-3 Chrome consent unrevoked; old policy-1 revoked.
- The initial GUI rollout selected `personal-20261002-gui-a`. The current
  PM2 release is `personal-20261002-terminal-protocol-c`, carrying forward the
  same four GUI runtime modules and native source. These are byte-identical to
  the workspace, and the installed native executable retains the hash above.
  PM2 is online. This deployment readback is not live GUI acceptance.

## Deployment and rollback

The GUI snapshot preserves the previous V2/O1 modules, existing OAuth connections,
signed policy, scopes, state directory and native launcher. Only Auth pages/session
delegation and Broker GUI adapter/delegation modules are overlaid. GUI-HOTFIX.json
records the GUI commit separately from the release's original base revision.
The current terminal-protocol-c release already runs these exact GUI modules;
recording the commit does not require rebuilding the native app or restarting
the service.

Protected backup: `~/Library/Application Support/MacOperator/backups/gui-20261002`.
It contains previous-launch.json, edge-service.json and the original native app.
With the service stopped, restore the old startup config, restore the original
app at its fixed installed path, restart PM2 with previous-launch.json and save
PM2 configuration. Verify service health and production launcher permissions.
This original GUI backup predates the terminal compatibility update. Restoring
it would also revert that update, so preserve the current release as the baseline
for any new rollback. There is no schema migration; do not roll back or erase current OAuth/approval/audit
database history. Native rollback may require TCC renewal for the old signature.

## Files and remaining acceptance

Runtime: packages/broker/native/gui_vision.m, packages/broker/src/ui-inspector.ts,
packages/broker/src/broker.ts, packages/auth/src/gui-session-approval.ts,
packages/auth/src/pages.ts. Tests: corresponding Broker/Auth/inspector tests and
scripts/gui-hit-testing.test.mjs and scripts/probe-gui-launch-context.mjs.
Documentation: GUI runbook, deployment runbook,
this evidence file and an additive progress entry. Unrelated pre-existing progress
and evidence changes are preserved. No new dependency, shell interface or OAuth
scope was added; no secrets were printed.

Remaining owner acceptance: use this same MCP connector for
health -> inventory -> focus -> active_window AX tree/JPEG -> safe click/focus
-> reobserve -> harmless text in a non-secure fixture -> reobserve and visibly
verify the exact text. Also check selected_window readback, metadata-only
observation and live secure-field denial. None of those final-adapter operations
is being claimed passed yet.

Residual limits: raw screenshots are not semantic secret detection or pixel
redaction; label-based transaction guards cannot classify every custom control.
Agents still need explicit authorization for consequential intent. Exact image
revalidation can reject animated pages. The unsigned personal deployment still
requires TCC renewal when its native code identity changes.
