# GUI launch permission attribution

## Verified host observations

- The owner browser successfully issued a real `mac_app_focus` approval.
  Broker consumed it before the native adapter reported missing Accessibility
  permission. The approval transport is no longer the immediate blocker.
- Direct launch through the background PM2 process attributes TCC responsibility
  to `/opt/homebrew/Cellar/node/25.5.0/bin/node`. Both permission preflights fail.
- Launching the existing installed GUI bundle through LaunchServices changes
  the TCC subject to `dev.macoperator.personal.gui`, but both preflights still
  fail. This was a permission-only probe, not a browser control operation.
- TCC explicitly reports `Failed to match existing code requirement` for that
  subject under both Accessibility and ScreenCapture. The stored requirement
  and installed code have different cdhash values. The installed bundle passes
  strict code-signature verification and has an ad-hoc signature.
- System Settings shows Mac Operator GUI enabled. That visible switch does not
  establish that the grant matches the currently installed executable.
- The file picker did not allow selecting the standalone Node executable for
  addition to Accessibility. A normal background permission request returned
  false and did not resolve the grant.

## Decision and remaining work

Renew the installed GUI application's grants through System Settings, then
repeat the read-only probe from the background service context. Do not rebuild
or replace that app during permission verification. Do not edit TCC databases,
use private responsibility APIs, grant Node broad access, or disable Broker
approvals to address this problem.

LaunchServices is a candidate execution route, not yet a deployed replacement
for the direct adapter. Before adopting it, implement and test exact app
identity validation, bounded output transport, cancellation of the actual app
instance, and exit/readback handling. `open -W` emitted a process-wait warning
for the short-lived permission probe, so wrapping existing calls in `open`
without lifecycle verification is insufficient.

`scripts/probe-gui-launch-context.mjs` performs fixed permission-only checks.
Run it under the same background launch context as the service. It writes
temporary owner-only output, cleans it up, and performs no GUI mutations or
permission changes. A terminal-only success does not prove service readiness.

No production GUI launch adapter was changed in this investigation. Browser
focus, screenshot, click, and typing acceptance remain incomplete.

## Owner grant renewal verification

After the owner re-added the installed GUI app in Accessibility and Screen &
System Audio Recording, the PM2 permission probe exited successfully and returned:

```json
{"direct":{"accessibility":false,"screenRecording":false},"launchServices":{"accessibility":true,"screenRecording":true},"launchWaitWarning":true}
```

Both grants now work for the application launched through LaunchServices.
The production direct-launch path remains blocked. The process-wait warning
also remains, so this result verifies permissions only, not GUI operation
execution or reliable lifecycle management. No further grant renewal is
indicated by this result. The temporary PM2 probe was removed after verification.

## References

- Apple NSWorkspace.OpenConfiguration:
  https://developer.apple.com/documentation/appkit/nsworkspace/openconfiguration
- Apple DTS discussion of responsible-code attribution:
  https://developer.apple.com/forums/thread/702907

## Transport implementation follow-up

The candidate was replaced by a native NSWorkspace launcher with a private,
owner-only Unix socket and exact process peer verification. The Broker now
routes native visual operations through it. The application waits for a bounded
request and exits if the launcher disconnects; a native fixture test confirmed
that cancellation interrupts an otherwise busy application. Background PM2
readback through the actual GuiProcessSupervisor returned SUCCEEDED and
terminationObserved=true. After the required app binary update, both permission
preflights returned false, so grant renewal and GUI operation acceptance remain
outstanding. The earlier successful grants applied to the prior binary.

Restart discovered an independent persisted preview/retry request-ID bug.
Regression tests reproduced both fresh-request and historical-issued failures.
The fix preserves existing audit linkage verification, matches consumed previews
by approval ID, and permits the verified historical state without rewriting it.
All 99 persistence and GUI adapter tests passed after the fix.

After deployment, MCP `mac_health` returned overall healthy. Broker regression
results: 90 passed, 6 skipped, 0 failed. Typecheck, lint, documentation links,
strict installed-bundle signature verification, and diff whitespace checks
passed. The native transport cancellation fixture also passed. System permission
confirmation is pending; no real focus/capture/click/type success is claimed.

After the owner explicitly confirmed renewal for the updated binary, both
System Settings grants were re-added. The PM2 probe using the deployed
GuiProcessSupervisor returned SUCCEEDED, terminationObserved=true,
accessibility=1, and screen_recording=true. The temporary probe was removed.
This verifies the production transport permission context, not final GUI
operation acceptance; the Broker still requires an attended operation approval.

The first post-renewal real focus attempt consumed its approval but failed with
`Executable is not root-owned`: the Broker's shared supervisor still trusted
the old direct GUI executable rather than the launcher. The fixed trust entry
now names only the launcher for this adapter. A regression test checks denial
without that entry and successful permission readback with the production
root-ownership gate enabled. The same strict configuration succeeded under PM2
using the deployed modules, with both permissions true and termination observed.
Broker/transport tests: 93 passed, 6 skipped; the explicitly enabled native
transport subset passed all 3 tests. MCP health passed after restart. Another
attended approval is required for actual focus acceptance; none was replayed.

## First successful end-to-end GUI operation

At 2026-09-26T19:21:44.809Z, the public Mac Operator GUI MCP
`mac_app_focus` call for `com.google.Chrome` returned SUCCEEDED, focused=true,
and verification.status=verified after owner approval. Request ID:
`5fbd1755-09c2-4ecd-b8d5-ceadfefe1f6f`. The Broker reobserved the exact Chrome
window as focused. This verifies the OAuth/Broker approval/native transport/
Accessibility/readback chain. Screenshot, click, and typing acceptance are
separate remaining checks; unrestricted or unattended control is not enabled.

The first active-window observation exposed a native NSNumber representation:
`truncated` was an integer, while the TypeScript parser required a boolean.
A narrow native-only compatibility conversion accepts exactly 0 or 1 for that
field; JXA input and all other metadata validation remain strict. All 18 UI
inspector tests passed, including rejection of other numeric/string values.
Only `ui-inspector.js` was deployed, with `.before-native-truncation` backup;
the installed app and its grants were unchanged.

MCP `mac_ui_observe` subsequently returned SUCCEEDED with a real active Chrome
window JPEG (1200 by 916), focused=true, and a visual reference. Request ID:
`98a9cd7c-b2ec-4400-b5aa-6f0ab436df0a`. The MCP client received the image block.
The Accessibility node list was empty and marked truncated; visual capture
works, but full Accessibility tree coverage is not established. Click and
text-input acceptance remain outstanding.

## Click acceptance blocker

The Web form window was successfully focused after live waiting for owner
approval (request eb17636b-3879-45ed-b662-aec085529345). Its MCP active-window
observation also succeeded. A click preview targeted the first non-secure text
input at screen point (222, 246). The approval remained pending during a bounded
45-second wait; no click or typing was executed.

The visual reference expires after UI_SNAPSHOT_TTL_MS=30000, while approval
previews permit 120000 ms. Visual references are randomly generated for each
observation, so simply obtaining a new reference does not preserve the approved
payload binding. Repeated manual approval attempts cannot reliably complete
this workflow. A future fix must revalidate the actual target after approval
without silently extending stale-target authority or substituting a new target.
Separately, a prior approval was issued with only 4760 ms remaining before its
original preview deadline; the next chat turn arrived too late. Live waiting
solved that focus handoff, but does not solve the visual-reference lifetime.

## Approval-time revalidation implementation

Implemented bounded retention of screenshot-backed targets through the original
120-second approval-preview deadline. The original observation timestamp and
payload reference remain unchanged. Every retained target is reobserved before
mutation, including targets still inside the normal 30-second snapshot TTL.
Exact screenshot and window checks reject changed pixels, geometry or focus;
node targets additionally reject changed or secure fields. The first deadline
is not extended by repeated retention or newer observations.

Validation: ui-inspector and broker suites reported 111 passes and 6 skips.
Typecheck, lint and diff whitespace checks passed. Tests cover ownership,
non-extension, pruning, changed screenshots/geometry/focus, unchanged click
dispatch and changed secure typing targets. These are automated adapter tests,
not proof of a real native click or text entry.

Deployed only broker.js and ui-inspector.js with before-approval-revalidation
backups. Service restarted and MCP health request
444426aa-f1d9-4b96-a95e-0a90057e9b14 reported healthy. Native app/signature and
macOS permissions were not changed. Real click and typing remain pending owner
approval and a matching foreground test window; exact pixel comparison may
reject dynamic pages or a blinking caret.

## Follow-up: independent observation and approval lifecycles

Review reproduced a stale-field bug: a pending retention record blocked newer
observations of the same deterministic field reference, and survived successful
input until expiry. Explicit subsequent input compared against the old image;
implicit input could no longer find a field matching the latest observation.

Fixed by separating current observations from approval evidence, scoped by
principal, session, tool and exact argument digest. Broker retries resolve their
retained copy, including implicit focused-field requests. Consumed requests
release evidence in finally on success or failure. Missing retained evidence
fails before dispatch instead of authorizing a replacement image.

Verification: 114 tests passed and 6 skipped across ui-inspector and Broker.
Typecheck, lint and diff whitespace checks passed. New tests cover consecutive
identical inputs with both explicit and implicit targets, preservation across
intervening observations, independent pending bindings, cross-owner release,
failed input cleanup and refusal to dispatch when approval evidence is missing.
Tests use simulated adapters; real native click and input remain unverified.

Deployment completed for broker.js and ui-inspector.js with
.before-ui-evidence-lifecycle backups. Both deployed files match the verified
build byte-for-byte. PM2 restarted the personal service; real MCP health request
9d5c7e9d-6fe3-4a46-9591-3fdc508f91cd returned overall healthy.

## Bounded browser session rollout

Root cause of repeated sign-in was explicit approval-session deletion after each
successful approval/decline, in addition to the short preview deadline. Changed
these transitions to rotate cookie/CSRF while preserving authenticated sign-in.
Authentication now lasts 30 minutes; browser focus/session previews last ten
minutes. Visual action/type previews still last two minutes.

An explicit owner-selected 30-minute, 500-operation grant now covers one browser,
OAuth principal/session and policy version. The keyless Auth bridge requests
start/status/revoke; the supervisor owns runtime-only grants and issues exact
single-use approvals through the existing authenticated issuer IPC. Broker checks
policy first. Reserved child approval IDs bind issuance to the exact authenticated
request so another connection cannot consume identical-payload authorization.
The authenticated session page exposes immediate revocation. Shutdown revokes
children; crash-surviving issued approvals expire within thirty seconds.

Validation: 223 passes, 6 skips across Auth, browser controller (real local IPC),
personal service, Broker, persistence and UI inspector tests. Added tests cover
login reuse after approval, session CSRF, scope/identity isolation, consecutive
input without per-step previews, expiry, 500-use limit, replay, revocation during
issuance and competing request rejection. Typecheck, lint and diff checks pass.

Deployed nine JavaScript modules, including new gui-session-approval.js, with
.before-gui-session backups for existing modules. Native binaries, macOS grants,
policy signatures, credentials and existing database rows were not rewritten.
Initial health reconnect calls returned transport internal errors after restart;
the focus request subsequently reached Broker, and health request
d28c3ada-ab04-44aa-80ac-f78a96391b95 returned healthy. New focus preview
77080189-e4d3-4bae-82c9-e0907601471d displayed a ten-minute expiry in the live
login page. The owner has not yet activated a session. Real native click/type
acceptance remains unverified; deployment does not itself grant session access.


## Persistent browser authorization follow-up (deployed and enabled)

The owner rejected the temporary 30-minute/500-operation behavior and explicitly
requested long-term browser access without repeated approvals. The replacement
stores explicit consent in protected AuthStore browser-grant records, scoped to
owner principal, browser app and policy version. It survives service restart and
same-owner OAuth reconnection; legacy temporary consent remains temporary.

Independent management login at `/approval/access` supports revocation after
preview/cookie expiration. A local-owner setup command with `--until-revoked`
uses the same audited consent path while holding the exclusive service lock.
Validation: TypeScript, lint and diff whitespace checks pass. The affected Auth,
Broker, persistence and UI suite has 227 passing tests and 6 conditional skips.
Focused persistence/provisioning tests cover database reopen, one-year simulated
passage, 501 operations, owner/browser/policy mismatch, revoked OAuth, durable
reset, consent replay and issuance/revocation races.

Eight Auth JavaScript modules were deployed with `.before-persistent-browser-grant`
backups. The owner's explicit request was applied through the local-owner setup
command, using fresh focus preview `88971e75-6641-492f-b8cf-7fbd5b4f9bd0`.
Chrome grant `gui-session:ddf3efb6-2ac3-4556-b8b7-cdbe7ae6a612` is durable and
unrevoked. No browser login or additional approval was requested during setup.
The native app and macOS permissions were not modified.

Live verification:
- Broker health: `216ee53a-c1e3-4806-baf7-29aef401559f`, healthy.
- Focus without further approval: `91a5ba66-2ae0-4026-a520-1d68e42a7dfb`, verified.
- Restarted the live service again, then focus:
  `328e7b1b-310d-491b-8f70-bb4c91b9d446`, verified without approval.
- Observe: `8f0f0596-fca6-41a9-897b-4083d9d57bd0`, screenshot returned.
- Click attempt: `c6e463db-ec0e-4e4a-a1ca-2abd43e4a4e6` passed authorization
  but returned `SECRET_BOUNDARY_DENIED` from the existing visual-action guard
  (secure/covered target). No form was submitted. Actual click/type usability is
  still unverified; persistent permission does not disable this guard.

The long-term authorization change is complete. A separate investigation of
native hit testing / covered-target classification is the next GUI usability
step; do not treat this as another missing approval or relax the guard blindly.


Public management verification initially found 404 responses because the local
Cloudflare Tunnel Auth ingress regex only covered the older approval routes.
Updated only that regex in `~/.cloudflared/config.yml`, with
`config.yml.before-persistent-browser-grant` backup, validated ingress, confirmed
the revoke path maps to Auth on port 3444, and restarted PM2 `tunnel`.
Public readback now verifies management entry 303, independent login page 200,
expired-session recovery 303 and unauthenticated revoke rejection 400. Auth
route tests separately verify authenticated listing and CSRF-protected revoke.


## Dock overlay fix follow-up (permission renewal completed on 2026-09-28)

Verified a Dock-owned, layer-20, alpha-1 full-display window ahead of Chrome.
At global screen point (222,246), app-scoped and system-wide AX both resolve
Chrome PID 459 and the ordinary Text input AXTextField. The old geometry-only
occlusion loop denied that click before input was posted. Chrome's initial
AXEnhancedUserInterface was false; enabling it exposed its focused AXWebArea.

Changed native/gui_vision.m to request Chrome AX information and allow only the
verified pass-through Dock overlay case. Added native classifier regression
coverage for real Dock hits, other app overlays, unknown hit PID and other layers.
Native build/signature verification, typecheck, lint and diff checks pass.
Targeted suite: 26 passing, 1 conditional skip (27 total). No security guard was
removed. Runtime Chrome authorization remains durable.

Installed the fixed app with previous bundle saved as
`~/Library/Application Support/MacOperator/gui-before-hit-testing.zip`.
The designated ad-hoc hash changed from 0dadd8d65083836b736254bf394b4be997cc22af
to eacd51c4a228e1a8da3df3fe51757216d4942c90. Direct terminal preflight is true/true,
but actual LaunchServices preflight is false/false, demonstrating why terminal
success is not service acceptance. System Settings still shows the old on switch;
refreshing it opened an owner password sheet. User handoff was requested without
asking the user to disclose a password in chat.

Next: after the owner completes the macOS password sheet, refresh Accessibility
and Screen Recording for the same app, verify LaunchServices permission readback,
then use the actual MCP focus/observe/click/type sequence on Selenium's ordinary
Text input. Do not submit the form or target credentials. Actual click/type is not
yet accepted. Do not rebuild the app again during that permission renewal.


## Final live acceptance (2026-09-28)

The previously pending owner step is complete. Re-adding the exact installed
app in Accessibility and Screen Recording refreshed stale ad-hoc signature
bindings. Both direct and LaunchServices preflight are now true/true. No other
application permission was changed. No password was captured or stored.

Two public output-schema defects were fixed and deployed: conflicting action
strategy const/enum, and missing input job_id. PM2 mac-operator-personal was
restarted; existing durable Chrome consent still authorized the next focus.
Runtime contract backups have the suffix `.before-gui-result-fix`.

Real input exposed a second native issue: a 17-character event produced no
text, while a one-character event produced x. Scalar events without delivery
grace produced only the first two characters. Preserving surrogate pairs,
clearing modifiers and keeping the sender alive for 250 ms produced complete
English, Chinese and emoji input. The same grace period was added to visual
actions after a reported successful click initially left focus unchanged.
The intermediate bundle is archived as `gui-before-unicode-input.zip`.

Final actual MCP evidence:
- Click request 76660e7e-3780-4c8f-b37c-0d6dd2baf425 succeeded at global
  (200,410); screenshot and subsequent observation confirmed Textarea focus.
- Observation 978022d5-ba18-4680-ae80-f5503dd1ce01 confirmed AXTextArea.
- Input request f8a30d07-4250-4c25-a0dc-99a3c04d7cc4 delivered 23 UTF-16 units,
  with submitted=false. Independent CUA AX readback and screenshot confirmed
  the complete expected English text, two Chinese characters and smiling emoji.
- CUA was used to prepare a static, unfocused test page and independently read
  the result; the accepted click and text entry were executed by Mac Operator MCP.
- No password field was targeted and the form was not submitted.

Known remaining issue: exact screenshot matching rejects some observations
because of caret animation; fresh observations and retries were needed. The
protection was not relaxed. Native success confirms dispatch/focus, so visual
readback remains required. This acceptance does not establish reliability on
all animated pages or maximum-length input.

Final validation: typecheck, lint and diff whitespace checks passed. Targeted
GUI supervisor/inspector/transport/native/contract suite: 28 passed, 1 conditional
skip, 0 failed (29 total). Installed and build binary SHA-256 match:
`55845b25003c12c4a387599450f9124781160649818d75e98d19903965e25c97`.
Both permission preflights were rechecked true/true after the final install.
Screenshot: `mac-operator-click-type-verified.png` in the current chat's
visualization directory.

## Bounded caret-phase recovery (2026-09-28)

Implemented in Broker ui-inspector: up to four observations, 175 ms between
mismatches, sharing the original execution deadline. The exact screenshot hash
is still required. Identity checks run before retry, and cancellation/deadline
checks run before and after observation. Original approval evidence and expiry
are unchanged. Persistent changed pixels/geometry still deny dispatch.

Targeted inspector suite: 24 passed. New tests cover recovery after two changed
frames with exactly one dispatch, exhaustion after four changed frames, immediate
identity rejection, cancellation and deadline. Typecheck/lint/diff checks passed.
Only deployed packages/broker/dist/ui-inspector.js changed; backup suffix
`.before-caret-revalidation`. PM2 personal service restarted successfully.
No native rebuild, TCC regrant or additional browser approval was required.

Live MCP requests, each called once with no client retry:
- 31fb85dd-65b8-425d-9454-e4bdfacae765: appended caret-1 marker.
- 04ab649b-cc26-4dc4-b8cc-f6a5985d1f97: appended caret-2 marker.
- a49e08f4-89a7-4e13-a751-df70c27fba3e: appended caret-3 marker.
- 217a7102-78bc-467b-9ce4-33d3c995a135: clicked Text input from the
  focused Textarea, completing in 3622 ms.
Independent CUA readback verified all three markers exactly once and Text input
focus. No form submission. Screenshot: mac-operator-caret-revalidation.png in
the current chat visualization directory. Continuous animation can still exhaust
the bounded observations; screenshot matching has not been relaxed.

## GUI connector disappearance investigation (2026-09-28)

Read-only ChatGPT Plugins settings showed Mac Operator MCP (connected Sep 25,
three linked accounts) and MAC-MCP (connected Sep 28, one account), both using
the same /mcp endpoint. Mac Operator GUI was absent from the installed list.
Calls through its previously advertised namespace now fail with Unknown tool
before returning a Broker result. Existing Mac Operator MCP health remains
healthy; its three linked accounts report scope_not_granted for GUI tools.

Auth database readback found the existing GUI-capable grant unrevoked and
unexpired, with its client registration still present. Persistent Chrome browser
consent also remains unrevoked. This locates the missing tool route on the
ChatGPT connection/registration side rather than a revoked server grant or dead
Broker. Available evidence does not establish who removed it, whether it was
uninstalled versus hidden, or the platform event responsible. No connection,
permission, token, or application setting was changed during this investigation.

## GUI connection restoration initiated (2026-09-28)

Personal directory search did not find the former GUI application. Recreated
Mac Operator GUI through ChatGPT's Create MCP App UI against the existing /mcp
endpoint, using OAuth DCR and the original advertised G1 scope set, including
mac.app.control, mac.ui.observe and mac.ui.control. Creation progressed to
Connect Mac Operator GUI, then /oauth/login. The browser is handed to the owner
for account login; connection completion and screenshot acceptance are pending.
No password was read or stored. Existing non-GUI applications were unchanged.

Restoration login completed: ChatGPT shows Mac Operator GUI with a connected
Primary account. New app ID: asdk_app_6ab9ea7ca0d88191a04d694e34d42467.
The app details list 37 tools (28 read, 9 write), including mac_ui_observe,
mac_app_focus, mac_ui_action and mac_ui_type. Read-only Auth DB inspection
confirms a new unrevoked, unexpired grant with all three GUI scopes.
The current conversation's old mac_operator_gui tool route still returns
Unknown tool. Actual screenshot acceptance through the newly created app is
therefore pending selection of the new connection in a refreshed tool context;
registration success is not being reported as screenshot execution success.


## Screen obstruction diagnostics and Dock exclusion (2026-09-28)

The native screen validator previously treated Dock's layer-20 full-display
surface as an obstruction. Ordinary window geometry failures also mapped to a
generic secret-boundary message. The updated native adapter excludes only
Dock-owned layer-20 windows from both validation and the ScreenCaptureKit
capture filter. Other app windows and overlays retain the existing restriction.
Broker messages distinguish above-browser obstruction, visible outside windows,
known sensitive app/title, and denied capture targets. The public failure class
remains SECRET_BOUNDARY_DENIED for compatibility; no semantic pixel-based secret
detection is claimed.

Verification: native build, typecheck, lint and diff checks passed. The combined
native helper and UI inspector suite passed 26 tests with zero failures/skips.
Installed binary SHA-256:
1d6c753b45da3907f5c5d3f51b0d4a4abf5f65598d28d5d9c09a83bc236b094c.
The updated Broker parser was deployed and mac-operator-personal restarted.
The prior bundle is archived as gui-before-screen-overlay-fix.zip under the
MacOperator Application Support directory. Removing and re-adding the same
installed application refreshed its prior TCC bindings; direct and
LaunchServices preflight both report Accessibility and Screen Recording true.

Live tests used GuiProcessSupervisor and the installed app through its normal
LaunchServices transport, rather than the stale ChatGPT tool namespace. Focus
succeeded and active_window captured the Selenium Web form at 1200x916. The
image was visually inspected. Screen mode returned screen_window_occluded,
both before and after maximizing Chrome. Window metadata showed the computer
use service's layer-102 overlay (126x126) above Chrome, plus other visible
windows; the old Dock obstruction is no longer the only candidate. Thus the
ordinary-obstruction error path is verified, but unobstructed full-screen
success and the new ChatGPT connection's end-to-end capture remain unverified.
The UI overlay was not exempted to make the test pass. No page was submitted,
no new OAuth approval was needed, and no unrelated permissions were changed.


## ChatGPT active-window acceptance blocked (2026-09-28, 13:36 MYT)

Sent the authorized active_window acceptance request in the existing Mac
Screenshot Request conversation. The first response used a nonexistent function
name and returned TypeError. A follow-up explicitly requiring actual tool
discovery reported no callable mac_app_focus or mac_ui_observe. The conversation
plugin picker did not show Mac Operator GUI. Reloading the previously verified
plugin detail URL for asdk_app_6ab9ea7ca0d88191a04d694e34d42467 displayed
Failed to load plugin / Plugin not found. This is direct UI evidence of current
plugin unavailability, not proof of deletion or its cause. Broker GUI audit
readback remained at the earlier SECRET_BOUNDARY_DENIED request; no new
acceptance request arrived. No new login, grant, approval, permission change,
click/input dispatch, or connector recreation was performed. ChatGPT screenshot
and input acceptance remain blocked on the unavailable plugin route.


## Follow-up plugin availability investigation (2026-09-28)

See 2026-09-28-chatgpt-plugin-unavailable.md for current platform lookup, directory, OAuth client/grant and public endpoint checks. The immediate failure boundary is ChatGPT plugin availability; platform lifecycle root cause remains unknown. A sanitized support request is prepared but not sent. No new connection or permission change was made.
