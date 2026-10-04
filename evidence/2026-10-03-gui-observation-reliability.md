# GUI observation and action reliability — 2026-10-03

Status: final source regressions verified and the GUI-session overlay deployed;
production TCC permissions restored. Final physical acceptance is blocked by a protected desktop and missing Calculator-close authorization.
This record distinguishes compiled regression fixtures from actual macOS GUI
observations. The task is not complete until the repaired installed helper and
service pass the physical acceptance matrix.

## Environment and real baseline

- macOS 26.6.2, build 25G83, arm64. Use Node.js 24; the interactive default
  Node.js 23.10.0 does not satisfy the project runtime requirement.
- Original observed local PM2 baseline: `mba-mcp`, immutable release
  `~/Library/Application Support/MacOperator-mba-releases/v2-43e044c`.
- Current GUI-session overlay:
  `~/Library/Application Support/MacOperator-mba-releases/v2-gui-session-20261003-a7783e1`.
- Production transport: fixed `packages/broker/dist/gui_launcher` launching
  `~/Applications/Mac Operator GUI.app` through LaunchServices.
- Disposable TextEdit file: `/tmp/mba-gui-reliability-before/MBA-MCP-Reliability.txt`.
  No existing user document or credential value was read.
- The repository was initially clean. Unrelated staged Auth/container changes
  appeared during the task and were preserved outside the GUI repair.

Actual installed-helper focus → inspect → type baseline:

```json
{"phase":"focus","status":"ok","focused":true,"window_identity":"28189:1791031512495:6629"}
{"phase":"inspect","status":"ok","nodes":[{"role":"AXTextArea","focused":true,"secure":false,"enabled":false,"index":0}]}
{"phase":"type","status":"error","error":"secure_target"}
```

The bounded AX metadata diagnostic independently reported:

```json
{"role":"AXTextArea","enabled":{"error":-25205,"type":"none","bool":null},"value_settable":{"error":0,"bool":1},"window":{"owner_matches":1,"matches_focused_window":1}}
```

Calculator baseline, repeated twice through the installed production launcher:

```json
{"phase":"focus","status":"error","error":"activation_failed"}
{"phase":"inspect","status":"ok","identity":"31569:1791031669835:6650","focused":true,"node_count":34}
```

After initializing the same NSApplication lifecycle used by the production
socket route, the independent bounded diagnostic confirmed:

```json
{"activation_accepted":true,"exact_window_focused":true,"raise_attempted":true,"raise_error":-25205}
```

This proves Calculator activation succeeds but its ordinary window does not
support the unconditional `AXRaise` call. The original focus failure was a false
negative. An earlier diagnostic without NSApplication initialization returned
system AX error -25204 and therefore refused activation; that blocked attempt
was not treated as Calculator acceptance.

The connector successfully launched TextEdit and Calculator, with request IDs
`f6a84799-b122-4655-b49d-d8072a0f15e1` and
`0264a206-ccde-4190-b083-26b7d7ece743`. Later focus/observe calls returned
`McpServerError: Tool mac_app_focus not found` / `mac_ui_observe not found`.
The dynamic connector exposure failure is not silently classified as fixed.
Installed-helper diagnostics still used the fixed production transport.

## Issue reports

### Input and reference security trace

1. `Broker.handle` checks authenticated principal projection, live scopes,
   revocation, signed policy version and exact app-window authority. Planning
   calls `validateUiTypeRequest`: bounded text, NUL rejection, secret-content
   guard, allowlisted bounded keys and strict submit boolean.
2. `UiSnapshotRegistry.resolve` checks opaque ref, principal/session, ordinary
   30-second TTL or exact approval retention binding, sensitive app/window,
   secure flag and redacted labels. `resolveFocused` chooses only the latest
   same-window focused text target. AXTextArea is an explicit ordinary text
   role, not sensitive by default.
3. Existing GUI consent and exact `trusted_gui` approval consumption remain
   separate from scopes. Submissions/Enter/newlines and named sensitive actions
   retain exact-operation approval; the credential-free HTTPS native browser
   toolbar exception retains native ancestor provenance. Protected-session
   delegation is never granted by `secure=false`.
4. `MacUiInspectorImpl.revalidateRetainedSnapshot` reobserves expected native
   window identity, exact app/window/title, ref/index/role/label and secure/enabled
   status before dispatch. Typing requires the current target still focused.
   Ordinary AX actions omit only that leaf focus requirement, because focusing
   an observed toolbar is itself legitimate. Only an ordinary native AX ref
   authorized by the current owner GUI session uses exact native identity and
   screenshot geometry instead of JPEG byte equality. Visual/desktop/legacy
   refs, explicit submissions and attended approvals retain exact screenshot
   revalidation. Historical GUI-session retention cannot grant current authority.
5. `resolveGuiWindow` rechecks frontmost application using independent
   Workspace/system AX evidence, exact focused AXWindow, process generation,
   sensitive/protected identities, minimization and unambiguous PID/geometry
   CG correlation. Native `focusedInputBlockReason` rechecks the live field,
   exact owner PID/window, AX object, role/label, enabled/editability and the
   complete safe ancestor chain before each event pair and after normal input.
6. Native bounded parsing and navigation dispatch checks apply again before
   events. `parseUiTypeResult` independently validates the exact expected
   metadata, focus/security, count/keys/submission, app/window/native identity
   and indexed opaque reference. Request authority is checked again around
   dispatch/completion; Jobs/audit never persist input text or screenshot bytes.

Observation and action use the same native AX attribute classifier. The actual
TextEdit denial was the unsupported AXEnabled capability, not a stale AX handle,
AXTextArea default sensitivity, a secure AX subrole, a protected session or a
window mismatch. Its live owner window and editability were independently
confirmed; `secure=false` alone was never made sufficient for action.

| Issue | Root cause and fix | Files changed | Security impact | Regression evidence and remaining risk |
| --- | --- | --- | --- | --- |
| 1: ordinary text denied | TextEdit omits AXEnabled. False fallback plus a combined validity predicate mislabeled disabled/identity failures as secure_target. Infer enabled only for explicitly unsupported AXEnabled and independently settable ordinary AXValue; distinguish security from stale/unsupported failures. Revalidate before input events. | native/gui_vision.m; native/gui_desktop.h; scripts/gui-desktop-app.test.mjs | Secure fields, sensitive UI, protected sessions and exact app/window ownership remain mandatory. No field value is read for capability detection. | Compiled TextEdit/browser ordinary textarea, unsupported-editable, read-only, malformed/error/disabled, password/secure/auth/protected and identity-change tests. Real Cocoa and TextEdit input are independently verified; browser input remains pending. TextEdit OCR matcher remains a disclosed harness limitation. |
| 2: fresh toolbar ref denied | Retained reobservation incorrectly required every AX target to be focused. Native focus-prefix traversal and max_nodes-dependent child clipping reordered indices. Later real testing also showed caret/animation changed precise JPEG bytes on otherwise stable targets. Require focus only for typing; use stable bounded BFS and indexed native typing. Current owner GUI-session ordinary native AX refs revalidate exact live identity and geometry; other authorities retain exact pixels. | src/ui-inspector.ts; src/broker.ts; native/gui_vision.m; ui-reference-reliability.test.ts; broker-gui-session-revalidation.test.ts; scripts/gui-desktop-app.test.mjs | TTL, principal/session, secure/enabled, native window generation, role/label/index and geometry checks remain. The native AX path requires current successful owner-session authorization forwarded to both action/type; historical retention, attended approval, visual/desktop/legacy refs and explicit submissions cannot inherit it. | Immediate/delayed actions, focus changes, disappearance, cross-app/window and expiry regressions; ten broker current-authority tests plus inspector pixel/geometry tests. Real immediate and 750 ms toolbar actions, disappearance, 30-second expiry and cross-window/app denial pass. Exact-pixel visual refs may still reject animated-caret contexts. |
| 3: ambiguous verified | The visual strategy verified dispatch and target readback, without an intended UI postcondition. Add dispatch_status=verified and postcondition_status=unknown while preserving existing status/strategy. Reject changed app/window readback before registering fresh refs. | src/broker.ts; broker.test.ts; tool-contracts/mac_ui_action.json; scripts/gui-result-contracts.test.mjs; docs/gui-computer-use.md | Does not grant additional action authority. Fresh readback remains tied to the approved native window. | Deterministic changed/unchanged checkbox regression plus cross-app/window/native-identity readback denials. Actual fixture checkbox handlers independently prove both unchanged and changed UI state; dispatch-only semantics remain explicit. |
| 4: Calculator focus failure | Unconditional AXRaise rejected an already independently focused Calculator window (-25205). AX windows were also enumerated only once after launch. Poll bounded readiness, skip redundant raise only after exact independent focus proof. | native/gui_window.h; scripts/gui-focus-regression.test.mjs; scripts/gui-window-resolution.test.mjs | Existing three-second deadline, process generation, protected session, ambiguity, PID/geometry correlation and final exact focus checks remain. Required failed raise still denies. | Real before evidence confirms activation=true, exact focus=true, unsupported raise. Eight new compiled regression cases. Three already-running background activation cycles pass per final run; cold-start acceptance requires permission to close the existing Calculator process. |
| 5: browser wording | Both fresh and reused visual Job responses hardcoded browser/page terms. Use application window/UI effect and state that only prior dispatch/identity were verified. | src/broker.ts; broker.test.ts; docs/gui-computer-use.md | No authorization change. | Contract and response assertions enforce generic wording and explicit scope. |

## Commands and verified results

```sh
PATH=/opt/homebrew/opt/node@24/bin:$PATH npm test
PATH=/opt/homebrew/opt/node@24/bin:$PATH npm run typecheck
PATH=/opt/homebrew/opt/node@24/bin:$PATH npm run lint
PATH=/opt/homebrew/opt/node@24/bin:$PATH npm run verify:docs
node --test scripts/gui-focus-regression.test.mjs scripts/gui-window-resolution.test.mjs
node --test scripts/gui-desktop-app.test.mjs scripts/gui-hit-testing.test.mjs
node --test packages/broker/dist/ui-reference-reliability.test.js packages/broker/dist/ui-inspector.test.js
node --test packages/broker/dist/broker-gui-session-revalidation.test.js
node scripts/probe-gui-observation-reliability.mjs --prepare-only
MOPS_REAL_GUI=1 node scripts/probe-gui-ax-metadata.mjs
```

Final full suite after current-execution GUI-session authorization fixes:
**1,924 tests, 1,905 passed, 19 conditional skips, zero failures**, exit code 0.
Earlier full runs were 1,907 / 1,888 passed and 1,890 / 1,871 passed, each with
19 skips and zero failures. Native input/hit suite: 85/85 passed. Native
focus/window suite: 22/22 passed. The earlier focused reference/inspector slice
passed 38/38 before the additional GUI-session cases. Broker GUI
response/readback suite: 6/6 passed. Current-execution GUI-session broker
regressions: 10/10 passed. Contract/opt-in probe checks: 4/4 passed. The final
full suite executes these checks and the additional inspector regressions together.

Typecheck, lint, documentation links, diff whitespace and fixture compile-only
preparation pass. Contract verification validated 58 unique contracts.
The full-suite command redirects output to
`/private/tmp/mba-gui-reliability-suite-final3.log`; that output is a local test
log, not a repository artifact or a physical GUI acceptance record.

Independent review reproduced two additional in-scope boundary defects using
the actual compiled native source with controlled AX fixtures: sensitive ancestor
changes during input and reparenting after the final event could previously
return success. The final source proves a bounded, acyclic, same-PID ancestor
chain reaches the exact approved window before/after AX actions and before each
typing event pair. The normal typing postdispatch repeats the complete guard,
including live window ownership and editability. Broken, cyclic, over-depth,
secure/authentication and cross-PID/window chains fail closed. Dedicated
regressions for both independently reproduced failures now pass.

The Node 23 permission probe failed with process startup cleanup unknown.
With Node 24, production permission readback returned Accessibility=true and
Screen Recording=true. The installed helper's JSON uses accessibility=1;
the existing readiness parser already accepts exactly boolean or 0/1. Numeric
serialization was therefore not proven to cause connector tool disappearance.
The native output is normalized to JSON boolean without changing grant checks.

## Physical acceptance matrix

The installed-helper upgrade initially blocked all physical flows on missing
TCC consent. That historical attempt is recorded below. Production permissions
are now restored. Real results below include successful checks and explicit
remaining gaps. At the final attempt, the native layer returned
`PROTECTED_SESSION`; Chrome acceptance and Calculator cold-start acceptance
remain incomplete. The complete task is not marked done.

| Flow | Repaired implementation acceptance |
| --- | --- |
| A: open → focus → active-window observe | TextEdit passed. Already-running Calculator passed three background activation cycles per final run. Chrome launch passed; its exact window acceptance did not pass. Calculator cold-start requires authorization to close the existing process. |
| B: observed AX element → action | Immediate and 750 ms Cocoa AXComboBox focus passed; actual TextEdit font-size focus and editor focus succeeded. |
| C: visual ref → bounded click → fresh observation | Cocoa bounded checkbox clicks passed with fresh visual refs/screenshots and the same window identity. Direct TextEdit visual click with an animated caret was rejected by unchanged exact-screenshot retention; no TextEdit visual success is claimed. |
| D: ordinary textarea → type → independent readback | Cocoa exact state-file readback passed. TextEdit accepted 12 characters and confirmed focus; independent CUA AX and screenshot show `MBA-MCP test`. Production connector added `!`, independently read as `MBA-MCP test!`. Vision OCR harness still failed; browser ordinary textarea real acceptance remains pending. |
| E: known control state transition | Actual checkbox handler activations 0→1 left checked=false; activations 1→2 changed checked=false→true. Both reported dispatch verified/postcondition unknown; independent fixture readback distinguishes the UI effects. |
| F: stale element reference | Actual 30.1-second expiry and element disappearance returned TARGET_NOT_FOUND. |
| G: cross-window/app reference | Second-window ref returned TARGET_NOT_FOUND; cross-app ref and nonfrontmost observation returned PRECONDITION_FAILED. |
| H: secure/sensitive field | Real Cocoa secure ref returned SECRET_BOUNDARY_DENIED before native input dispatch. Password/browser/auth/secure-ancestor guards pass compiled tests. Final production focus attempt returned PROTECTED_SESSION; its exact OS cause was not inspected. Real browser password and system authentication-dialog acceptance remain unexercised. |
| I: screen includes unauthorized application | Real full-screen capture including visible Calculator returned SECRET_BOUNDARY_DENIED. |

During the historical source-repair phase, no production rollout, permission
expansion, credential interaction, policy rewrite or grant-store mutation was
performed. The real
probe uses a private temporary BrokerStore and exact signed test approvals;
its setup/readback/cleanup address only fixture-owned public controls/documents.
The existing signed helper must be preserved for rollback before explicit
upgrade. TCC renewal, if required, belongs to the owner and must not be bypassed.
The concrete native build, source diff and opt-in physical probe are ready.
At that point an asynchronous approval request for the installed helper/service
upgrade was pending; elapsed time was not treated as authorization.

The preceding paragraph records the source-repair phase. The owner subsequently
authorized the rollout with “proceed to fix all”; the approved rollout and its
historical prerequisite failure and current overlay are recorded below.

The disposable baseline text file/directory were removed. Its exact-document
AppleScript close did not complete promptly; only that uniquely identified
task-created AppleScript process was terminated. The public fixture document
may remain open in TextEdit. This also exposes an independent-readback limit:
AppleEvents automation must not be assumed available from the test launcher,
and no broader Node/Terminal grant was requested. TextEdit's actual typed text
will need an independent permitted readback or inspection of its fresh bounded
screenshot during repaired-helper acceptance.

Final probe preparation was rerun after its cleanup safeguards changed:

```json
{"status":"prepared","fixtureCompiled":true,"calculatorUtilityCompiled":true,"uiExecuted":false}
```

The probe's Calculator cleanup utility binds only a probe-launched Calculator
to its exact bundle, PID and process-start generation, requests graceful
termination and independently checks that generation stopped. It never
force-terminates an application. Existing AppleEvents access must be separately
established before setting `MOPS_REAL_GUI_APPLE_EVENTS=1`; the probe does not
request a wider grant. Without that access, TextEdit independent text readback
and document cleanup remain explicitly unverified, and requested Chrome checks
are blocked. A fixture that cannot acknowledge quit retains its private command
and state artifacts for attended cleanup. The four contract/opt-in checks and
diff check passed again after these harness-only refinements; no physical UI
was executed by the compile-only command.

## Authorized rollout and historical TCC prerequisite

Before rollout, the live service had changed concurrently to immutable release
`~/Library/Application Support/MacOperator-mba-releases/v2-ready-a7783e1`.
The new release was copied from that actual live baseline, with only the
unstaged GUI source patch compiled in isolation. Workspace staged Auth/container
changes were not included. A whole-file hash comparison preserved 5,732 files;
eleven changed paths are all within the two GUI runtime modules, their source
and declarations, the three GUI native sources, GUI executable/app and action
contract. `GUI-RELIABILITY-HOTFIX.json` records the exact before/after hashes.

Initial GUI repair runtime:
`~/Library/Application Support/MacOperator-mba-releases/v2-gui-reliability-20261003-a7783e1`.
The original PM2 definition, complete stopped state, original Edge startup
configuration and complete signed helper are retained under private backup
`~/Library/Application Support/MacOperator-mba-backups/gui-reliability-20261003-a7783e1`.
The atomic GUI exchange also retained the original signed app at
`~/Applications/.mac-operator-gui-upgrade-2CmLsu/previous.app`.
Both startup definitions use a relative service entrypoint under their exact
release cwd; this avoids PM2's JSON normalization of space-containing script
paths into shell commands. The first rollout attempt encountered that PM2
rewrite; the retry loop was stopped, a redacted temporary diagnostic established
successful guarded startup, and the PM2 entry was corrected. No guard was
weakened, no unrelated runtime artifact changed, and the diagnostic was removed.

Verified corrected initial PM2 command (historical rollout readback):

```json
{"name":"mba-mcp","pid":52600,"status":"online","script":"/Users/yapweijun/Library/Application Support/MacOperator-mba-releases/v2-gui-reliability-20261003-a7783e1/packages/auth/dist/personal-service.js","args":["start","/Users/yapweijun/Library/Application Support/MacOperator-mba-o1"],"interpreter":"/opt/homebrew/opt/node@24/bin/node","node_version":"24.21.0","restarts":0,"uptime_ms":103026}
```

The corrected definition was saved with private mode 0600. Snapshot preflight
passed with `loopbackStatus=bound`. Policy, policy public key, approval key,
Edge key and Auth configuration were compared byte-for-byte with the stopped
backup and remained unchanged. Actual authenticated `mac_health` request
`330bc133-0d21-4b96-8d6e-f19ed2c2738e` returned `overall=healthy`.

The installed app validated successfully, but replacing its ad-hoc signed
binary invalidated its former TCC consent. Historical production readback:

```json
{"installed":true,"identity_valid":true,"accessibility":false,"screen_recording":false,"transport":"launchservices","reason":"ACCESSIBILITY_PERMISSION_REQUIRED"}
```

Actual authenticated `mac_capabilities` request
`90a76225-c38d-489c-ae1c-fccfd44a62ff` independently returned the same denied
permissions and disabled only GUI-dependent tools. Broker health, non-GUI
capabilities and existing scope boundaries remain available.

The real acceptance command was attempted against the upgraded fixed helper:

```sh
MOPS_REAL_GUI=1 PATH=/opt/homebrew/opt/node@24/bin:$PATH \
  node scripts/probe-gui-observation-reliability.mjs
```

```json
{"name":"production_helper","installed":true,"identity_valid":true,"accessibility":false,"screen_recording":false,"transport":"launchservices","ordinary_apps":null,"desktop_surfaces":null,"reason":"ACCESSIBILITY_PERMISSION_REQUIRED","node":"v24.21.0","helper_sha256":"5011c3b0cd5c814ba75eb58cd9acff0e07b1ca29c31d65ceba386b67d3c248ac"}
{"status":"blocked","error":{"name":"AssertionError","message":"Production GUI prerequisite unavailable: ACCESSIBILITY_PERMISSION_REQUIRED"},"checks":0}
```

Exit code 1; log `/private/tmp/mba-gui-reliability-live.log`. No fixture UI was
launched, no actual repaired UI behavior was claimed and temporary preparation
artifacts were removed. At that point flows A–I remained pending. The owner was asked to renew
Accessibility and Screen & System Audio Recording only for the fixed installed
app. Accessibility settings were opened for that manual action. Node/Terminal
grants, TCC database edits and alternate-helper permission bypasses were not used.

The final harness now verifies TextEdit's public marker independently using
Vision OCR on a fresh authorized screenshot: absent before typing, present
after typing in the exact same window. It also exercises the actual rich-text
font-size toolbar before returning to a fresh editor ref. Its OCR utility never
persists images, emits only a boolean and requests no macOS permissions.
AppleEvents remains optional for TextEdit textual readback and document cleanup;
Chrome setup/cleanup still requires separately established existing access.
Secure-field physical coverage is explicitly a Broker pre-dispatch rejection;
native action-time security coverage remains the compiled native regressions.

## Current GUI-session overlay and pending final physical results

After the owner restored TCC consent, the same fixed production helper returned:

```json
{"name":"production_helper","installed":true,"identity_valid":true,"accessibility":true,"screen_recording":true,"transport":"launchservices","ordinary_apps":true,"desktop_surfaces":true,"node":"v24.21.0","helper_sha256":"5011c3b0cd5c814ba75eb58cd9acff0e07b1ca29c31d65ceba386b67d3c248ac"}
```

This prerequisite readback is recorded in
`/private/tmp/mba-gui-reliability-live-restored.log`. During repaired real
testing, a fixture toolbar ref worked immediately but its 750 ms action, and
an ordinary textarea action, could fail `TARGET_NOT_FOUND: Approved UI target
changed` despite the same live target. Exact JPEG fingerprint revalidation
included caret/animation pixels. The final change therefore chooses
`native_ax` only for ordinary native AX targets under a successful current owner
GUI-session authorization. It still validates the current app/window/process
identity, native ref/index/role/label, secure/enabled state and screenshot
geometry. Visual refs and exact attended approvals retain screenshot equality.
Both `uiInspector.action` and `uiInspector.type` receive the current-execution
authorization flag only when the broker's present session callback succeeds;
retained historical `native_ax` state cannot substitute for that callback.
Pending attended approval cannot be upgraded to GUI-session authority.

The current immutable release is
`~/Library/Application Support/MacOperator-mba-releases/v2-gui-session-20261003-a7783e1`,
copied from the initial GUI repair release. Its
`GUI-SESSION-REVALIDATION-HOTFIX.json` records **5,739 unchanged files** and these
five changed paths:

- `packages/broker/dist/broker.js`
- `packages/broker/dist/ui-inspector.d.ts`
- `packages/broker/dist/ui-inspector.js`
- `packages/broker/src/broker.ts`
- `packages/broker/src/ui-inspector.ts`

The installed signed helper is unchanged, with SHA-256
`5011c3b0cd5c814ba75eb58cd9acff0e07b1ca29c31d65ceba386b67d3c248ac`.
This TS-only overlay does not reinstall the helper or renew its TCC identity.
The previous GUI release and private service backup remain available at
`~/Library/Application Support/MacOperator-mba-backups/gui-session-20261003-a7783e1`;
rollback changes the runtime definition, not the current application database.
The concurrent ready/Auth/container work remains in the actual deployment base
and was not replaced by workspace staged changes.

The physical logs are listed in the final record below. Passing dispatch
responses, partial checkpoints or the complete automated suite do not establish
completion of the physical acceptance matrix.

## Final verified result and remaining prerequisites — 2026-10-04

The final complete automated command was:

```sh
PATH=/opt/homebrew/opt/node@24/bin:$PATH npm test > /private/tmp/mba-gui-reliability-suite-final4.log 2>&1
```

It passed **1,926 tests: 1,907 passed, 19 conditional skips, 0 failures**
(61,792.6 ms). The default workspace sandbox previously blocked native compiler
temporary-file creation and process fixtures; the final command used the
approved macOS execution context rather than changing tests to hide failures.
TypeScript build, lint, documentation links and `git diff --check` also pass.

Real commands:

```sh
MOPS_REAL_GUI=1 MOPS_REAL_GUI_CHROME=1 MOPS_REAL_GUI_CHROME_CUA=1 PATH=/opt/homebrew/opt/node@24/bin:$PATH node scripts/probe-gui-observation-reliability.mjs
MOPS_REAL_GUI=1 MOPS_REAL_GUI_ONLY_CHROME=1 MOPS_REAL_GUI_CHROME_CUA=1 PATH=/opt/homebrew/opt/node@24/bin:$PATH node scripts/probe-gui-observation-reliability.mjs
```

The full runs logged **15/17 checks passed**; failed checks were TextEdit OCR
readback and Chrome exact-window resolution. They are retained as failures in
`gui-reliability-live-final.jsonl` and `gui-reliability-live-final2.jsonl`.
The Chrome-only run did not pass and is recorded in
`gui-reliability-chrome-final.jsonl`.

Actual before/after input evidence:

```json
{"before":{"role":"AXTextArea","focused":true,"secure":false,"enabled":false},"native_type":{"status":"error","error":"secure_target"}}
{"after":{"characters_accepted":12,"focus_confirmed":true},"independent_owned_textedit_ax_value":"MBA-MCP test"}
{"production_request_id":"17740c86-aa18-4ed5-980d-f4f6c7695103","ok":true,"result_class":"SUCCEEDED","characters_accepted":1,"focus_confirmed":true,"independent_owned_textedit_ax_value":"MBA-MCP test!"}
```

CUA independently read only the exact temporary document and showed the public
marker in its screenshot. The strict Vision matcher did not recognize the full
phrase on the original capture despite finding a known prefix and test word;
no fuzzy character substitution or lower confidence threshold was introduced.
A larger empty RTF paragraph still did not make this OCR check pass. This is a
limitation of that harness readback, not evidence that the native input failed.
Independent AX/screenshot observations support the input success. The precise
OCR recognition error remains undiagnosed; no OCR fix is claimed.

The Cocoa visual test independently produced:

```json
{"before":{"checked":false,"activations":0},"after":{"checked":false,"activations":1},"expected_postcondition_satisfied":false,"dispatch_status":"verified","postcondition_status":"unknown"}
{"before":{"checked":false,"activations":1},"after":{"checked":true,"activations":2},"expected_postcondition_satisfied":true,"dispatch_status":"verified","postcondition_status":"unknown"}
```

Chrome attempts were precisely scoped to three fresh local fixture tabs:
`3edb99b1584f`, `8ee90d2dc034`, and `f9e912c2fea5`. A CUA-created tab and DOM
focus did not make its title visible to the native window resolver. A tab-scoped
`Page.bringToFront` setup operation did publish the final owned Chrome title to
native CG metadata (bundle `com.google.Chrome`, PID 46527). Native focus then
returned `WINDOW_IDENTITY_AMBIGUOUS`. Its exact ambiguity was not resolved.
The existing fail-closed behavior was retained. A temporary viewport change
attempted to isolate this owned fixture; the next production request returned:

```json
{"request_id":"8be0f478-5caa-4901-9888-d4b9e70d7a37","ok":false,"result_class":"SECRET_BOUNDARY_DENIED","error":"PROTECTED_SESSION: Unlock the Mac or dismiss the system authorization UI before computer automation"}
```

GUI acceptance stopped at this protection. The exact OS cause was not inspected,
and no lock-screen/authentication bypass was attempted. The temporary viewport
was reset and the exact owned Chrome tabs were closed and independently checked
absent. Two earlier cleanup acknowledgments arrived after their old 120-second
deadline and those harness failures remain in the logs; root separately closed
the exact owned TextEdit documents, verified their absence, and removed their
temporary files. Attended handoff deadlines are now bounded at 300 seconds;
the product's three-second activation deadline remains unchanged.

Calculator's existing PID 31569/generation `1791031669:845460` matched the earlier
baseline process. Its three already-running cycles each activated from the
fixture background and reobserved the same window. Cold-start testing remains
unverified: automatic approval review rejected graceful termination of this
existing process because it could affect the owner's current Calculator
session. Explicit permission to close Calculator was requested; elapsed time
has not been treated as permission. The desktop must also be unlocked before
remaining native GUI acceptance can run.

The five implementation issue reports above remain valid, with these final
limits: issue 1 TextEdit and Cocoa input are independently verified; issue 2
fresh/immediate/delayed and stale/cross-boundary reference cases are verified;
issues 3/5 are verified by actual changed/unchanged controls and contract tests;
issue 4 already-running Calculator is verified, cold launch is not. Browser
textarea/password and direct TextEdit animated-caret visual acceptance are not
claimed complete. Protected sessions, secure ancestry and ambiguous identity
remain fail closed. The production service health request
`91e9b205-88dd-48b2-bd22-d7900aed4dc5` reports healthy.
