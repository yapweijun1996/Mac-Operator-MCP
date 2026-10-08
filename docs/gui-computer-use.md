# GUI Computer Use (G1, O1 and V2)

The personal `g1` grant adds five GUI tools to the existing owner profile:
`mac_app_open`, `mac_app_focus`, `mac_ui_observe`, `mac_ui_action`, and
`mac_ui_type`; O1 and V2 retain this GUI surface. G1 keeps `mac_task_run`
disabled. GUI access defaults to Chrome and Safari. A separate explicit owner
opt-in, `guiAccess=desktop`, allows ordinary applications and display observation
under the signed Broker policy. Existing browser consent never expands into
desktop consent. Both modes retain `trusted_gui` mutation approvals, request
timeouts, revocation checks, sensitive-target guards and audit records.

See [explicit desktop delegation](#explicit-desktop-delegation) for the offline
owner command and [desktop observation](#desktop-observation-and-action-loop)
for display screenshots and actions. Source changes, a healthy Broker and a
durable grant do not establish GUI readiness; verify the production MCP route
and exact installed GUI application's permissions after deployment.

## Historical October 2 GUI repair

The October 2 V2/O1 deployment inherited the browser boundary. The canonical
contracts use `trusted_gui` for focus/action/type; `trusted_app_control` is not
an approval class in the current contract enum. An OAuth scope does not create
browser consent. The earlier Chrome grant was revoked and bound to policy-1;
that deployment used policy-3. Fresh Chrome owner consent must match the
active policy. Do not un-revoke or rewrite old grant rows to restore access.

All production observations, including `capture_mode=none`, now run through
LaunchServices in `~/Applications/Mac Operator GUI.app`, bundle identifier
`dev.macoperator.personal.gui`, executable `Contents/MacOS/gui_vision`. The
Broker's Node process and fixed `gui_launcher` transport do not perform the AX
calls. The previous metadata-only JXA branch executed `/usr/bin/osascript` with
a different TCC identity; granting the native app did not authorize that branch.
The native adapter returns a bounded window tree with no field values, redacts
secure labels, and uses the same app for element actions and focused typing.
Opaque element references remain scoped to the caller/session and fresh window
observation. A capped metadata-only tree is not made actionable by this repair.

Grant **Mac Operator GUI.app**, at the exact installed path above, Accessibility
access. Every screenshot mode (`active_window`, `selected_window`, `screen`)
also requires Screen & System Audio Recording. Metadata-only observation and
AX focus/action use AX window metadata and do not request screen capture.
The adapter captures no audio. Apple documents the
[screen recording permission](https://support.apple.com/guide/mac-help/control-access-screen-system-audio-recording-mchld6aa7d23/mac).
Rebuilding the ad-hoc signed app can invalidate the LaunchServices TCC binding
while System Settings still shows the old entry enabled. Remove/re-add only
this application when that occurs; do not grant all Node executables or edit TCC.
Use the **production `gui_launcher`** for permission readback: an interactive
direct launch can inherit a different responsible process and report true while
the service launch reports false. Do not rebuild again after renewing grants.

The launch/focus review page offers a 30-minute, 500-operation session first, and
retains the separate until-revoked choice. Session authority remains bound to
principal, OAuth session, exact app and policy; persistent authority is bound
to principal/app/policy and requires a live unrevoked OAuth session. Exact
single-use child approvals expire within 30 seconds. Focus target shape and
element target shape are validated before issuance. Web form submissions, generic Enter
submissions and named sensitive AX actions require exact attended approval.
A complete credential-free HTTPS URL submitted directly to a native browser
toolbar address field may use the reusable grant. Native ancestor verification
excludes AXWebArea descendants, including webpage toolbar impersonation; label
text alone never authorizes navigation. Visual hit testing additionally denies
named purchase/send/delete/security controls. These label guards do not claim
to infer all transaction intent or redact sensitive screenshot pixels.

See [live repair evidence](../evidence/2026-10-02-chrome-gui-reusable-grant.md).
The follow-up [window-resolution evidence](../evidence/2026-10-02-chrome-window-resolution.md)
records the current production verification and deployment.

## Canonical window resolution

Application focus, observe, capture and input share the native
`resolveGuiWindow` resolver.
It resolves the exact bundle/PID and focused AXWindow, then correlates the
visible layer-zero CGWindow using owner PID and global AX position/size. AX and
CG titles may differ; browser titles are never the correlation key. Ambiguous
geometry fails closed rather than selecting the first CG entry.

The opaque `window_id` hashes app identity plus PID, process launch generation
and CGWindowID. It remains stable when a tab/title changes. Screenshot and input
requests carry the private native identity and reject changed/replaced windows.
Element references still require a fresh caller/session-owned observation;
retained operation approvals also require their original element/image evidence.

Missing app/window, hidden/minimized window, missing AX permission, missing
screenshot permission, AX metadata failure, correlation ambiguity and capture
failure have distinct errors. A correlation failure is not reported as absence.
Application observation does not activate an unfocused app; call
`mac_app_focus` first. The agent can focus an authorized application through
MCP without requiring the owner to bring it forward manually. Explicit focus
may restore a minimized selected window and waits for exact AX focus readback.

Without `window_hint`, focus retains the process's last `AXFocusedWindow`,
independent of AX/CG array order. An exact title hint selects one AX window;
duplicate matching hints fail closed. Titles are selectors only, never identity.
The selected window is checked for sensitive content before activation. Activation
must be accepted, then Workspace bundle/PID/process generation and system-wide
AX application focus must agree. The same three-second monotonic deadline covers
application and exact window focus propagation; no unconditional sleep is used.
Capture checks the same identity again after ScreenCaptureKit returns.

A locked desktop or active system authorization UI returns
`SECRET_BOUNDARY_DENIED` with `PROTECTED_SESSION` before browser activation.
Unlock the Mac locally or dismiss the authorization UI and retry. Running apps,
healthy Broker status and granted TCC permissions do not prove the desktop is
available. Activation rejection, frontmost timeout, independent app mismatch,
missing focused window, ambiguous identity and missing AX/capture permission
have separate safe diagnostic prefixes within the existing error contract.
No window titles or UI contents are included in these failure diagnostics.

## Observation and action loop

1. Open and focus an authorized ordinary application through `mac_app_open`
   and `mac_app_focus`. Browser mode permits Chrome and Safari; explicit
   desktop mode also permits ordinary apps such as TextEdit.
   Use the concrete bundle ID as `app_id`; an existing
   `bundle:` prefix is also accepted. The Broker normalizes either form before
   applying the signed target policy. `mac_app_open` accepts only `app_id`; navigate
   to a URL through the observed browser address bar.
2. Call `mac_ui_observe` with `app_id` and optional `capture_mode`:
   `active_window` (default), `selected_window` with an exact `window_hint`,
   `screen`, or `none` for Accessibility metadata only.
3. A screenshot observation includes a JPEG `image` content block, window and screen
   dimensions in macOS screen points, image dimensions in pixels, safe
   Accessibility nodes, and a short-lived `visual_ref`.
4. Call `mac_ui_action` with that `visual_ref`. Supported visual actions are
   `click`, `double_click`, `right_click`, `move_pointer`, `scroll`,
   `key_press`, `shortcut`, and `wait`. Pointer coordinates are screen points,
   checked against the observed application window. Global `x` and `y` are
   bounded to -20,000 through 20,000, allowing displays left of or above the
   main display; actual window, display and hit ownership checks still apply.
   Scroll distance is at most 1,000 pixels per axis; wait is at most two seconds. Keyboard input is a
   small allowlist, including `COMMAND_L` for the address bar.
   For visual actions, use an `active_window` or `selected_window` capture.
   Treat `screen` captures as broader visual context and take a window capture
   before choosing action coordinates. Screenshot coordinates are image pixels,
   so convert them before acting on a window capture:
   `x = floor(window_x + image_x * window_width / image_width)` and
   `y = floor(window_y + image_y * window_height / image_height)`. For example,
   with a 1,000-point-wide window rendered as a 1,500-pixel image at `window_x`
   40, image pixel 750 maps to screen point 540. Do not pass image pixels
   directly as action coordinates.
5. Visual actions return a fresh MCP image block and `visual_ref`. Inspect the
   new screenshot before deciding on another action. The Broker records only
   action metadata in durable Jobs and audit logs, never screenshot bytes.
   For `verification.strategy="visual_action_dispatch"`, `status="verified"`
   means the bounded event dispatch and target identity were validated.
   Additive fields make that scope explicit: `dispatch_status="verified"` and
   `postcondition_status="unknown"`. No intended UI postcondition is supplied
   to this tool, so it cannot prove that a checkbox changed, focus moved, or
   navigation completed. A fresh screenshot, even one whose pixels changed,
   is evidence for the caller to evaluate against the intended result.
   Independently observe a known control after the action and compare its
   state with the expected state before continuing. An unchanged control and
   a changed control both have verified dispatch; only the latter satisfies
   the intended transition. A reused Job preserves the prior dispatch evidence
   and does not claim current UI state.
6. Call `mac_ui_type` with `text` and optionally an Accessibility
   `element_ref`. Without a ref, it selects the focused, non-secure text field
   from the most recent observation in the same owner session. Browser address
   bar input requires a complete credential-free HTTPS URL. Observe again
   after typing or submitting.

An example browser flow is: open Chrome, focus it, observe, send
`shortcut(COMMAND_L)`, type a complete HTTPS URL into the focused address bar with `submit=true`, inspect the new screenshot, then click, type, scroll, and
observe until the page result is visible.

### Reliability integration probe

AX references use a stable breadth-first traversal of the selected window.
Moving focus does not reorder existing targets, and a smaller `max_nodes`
returns a prefix of the same bounded tree. A focused control outside that
prefix needs a larger fresh observation before it can receive input. Ordinary
AX actions may target a non-focused enabled control; typing still requires
the exact focused text target. Reference TTL, caller/session ownership, native
application/window generation and retained screenshot checks remain enforced.

Some native editors, including TextEdit, do not implement `AXEnabled` on an
editable text area. Only an explicit `kAXErrorAttributeUnsupported` permits the
adapter to infer enabled state from a non-secure text role whose `AXValue`
attribute is independently reported settable. It never reads that value.
An explicit disabled flag, malformed value, missing value, permission error,
read-only control or secure control cannot use this fallback. Input revalidates
live focus, security and exact window ownership instead of trusting observation
flags. Native typing accepts an optional observed element index; its original
index-zero invocation remains supported for older clients and desktop typing.

Application focus waits for AX window readiness inside its existing three-second
monotonic deadline. The adapter rechecks process generation and protected-session
state while waiting. After activation, it skips `AXRaise` only when independent
Workspace, system AX and exact focused-window observations already prove the
selected window is focused. A required raise that fails remains an error.

After `npm run build`, run the opt-in attended probe with Node.js 24 or newer:

```sh
MOPS_REAL_GUI=1 node scripts/probe-gui-observation-reliability.mjs
```

The probe uses the installed production GUI helper and an isolated ephemeral
Broker store with signed requests and exact per-operation approvals. Ordinary AX
focus/type operations use one-use approvals delegated for their final request by
the authorized owner GUI session; visual actions keep attended snapshot approval.
It creates
an ordinary Cocoa fixture with a text area, toolbar combo, checkbox, secure field
and two windows. Its independent state file contains only fixture-owned public
text and checkbox state; it never reads the secure value or saves screenshots.
Changed and unchanged checkbox scenarios separate verified dispatch from the
independently observed UI result. It also tests live TextEdit with one temporary
document, Calculator, immediate and delayed AX references, disappearance,
expired references, cross-window/app references, non-frontmost observation and
screen capture boundaries. Existing application documents remain outside its
readback and cleanup scope.

Add `MOPS_REAL_GUI_CHROME=1` only when Chrome fixture automation is authorized.
With `MOPS_REAL_GUI_CHROME_CUA=1`, the probe prints an exact local fixture URL,
title, probe ID and HTTP acknowledgment URL. The attending controller creates
one new CUA Chrome tab, retains its exact tab ID, and acknowledges
`{probe_id, tab_id, url}`. The probe then uses MBA-MCP for the tested interactions.
At cleanup the controller closes only that retained tab, independently confirms
it is absent, and acknowledges the same identity with `closed:true`. Each handoff
has a bounded deadline; a missing acknowledgment fails closed. The CUA setup and
cleanup actions are reported separately from MBA-MCP acceptance evidence.
Its own DOM event listener supplies independent textarea and
checkbox readback, without remote debugging or changing browser settings.
The alternative Chrome window setup/cleanup and optional TextEdit AppleScript value readback/cleanup require
separately established AppleEvents access. Set `MOPS_REAL_GUI_APPLE_EVENTS=1`
only when that existing access has already been verified; the probe does not
request broader Terminal or Node permissions. Without either CUA handoff or
existing AppleEvents access, Chrome is explicitly blocked. TextEdit independently
verifies the public test marker was absent before typing and present in a fresh
same-window screenshot afterward, polling observation readiness for at most ten
seconds using a bounded
Vision OCR utility that saves no image and emits only a boolean.
The CUA mode also waits for exact TextEdit cleanup: its emitted request binds
probe ID, app ID, document title, temporary path and observed window ID. The
controller closes only that document, independently confirms its window is
absent, and acknowledges the emitted identity with `closed:true` and
`independently_confirmed_absent:true`. A mismatched or missing acknowledgment
never permits deletion of an unconfirmed open fixture document.
An unclosed temporary TextEdit document and its file are retained and reported
for local cleanup. AppleScript subprocesses are bounded to five seconds;
timeouts terminate only the probe's own subprocess. Calculator cold-start cleanup
uses a test-only AppKit utility restricted to Calculator: bundle, PID and process
generation must match the instance launched by the probe, and only graceful
`NSRunningApplication.terminate` is attempted. Rejection or changed identity
fails closed without force termination.
`node scripts/probe-gui-observation-reliability.mjs --prepare-only` compiles the
temporary Cocoa app, Calculator utility and screenshot checker without launching
or controlling any UI. It also compiles a read-only temporary-bundle resolution
diagnostic. Explicit-path fixture launch is reported separately from temporary
bundle `mac_app_open`; a failed temporary-bundle launch is a disclosed skipped
diagnostic and does not substitute for required Flow A on real applications.
With no opt-in
flag, the normal probe reports `skipped` and performs no GUI actions.

The probe reports each check and its limits. It fails closed on unavailable
helper permissions/capabilities or a protected session. It does not lock the
desktop or open real system authentication UI; those physical scenarios require
separate attended evidence and are explicitly reported as unexercised.

## Desktop observation and action loop

With explicit desktop policy and owner delegation, call:

```json
{"app_id":"desktop","capture_mode":"screen"}
```

This observes one full display without focusing or opening an application. To
select a display, pass `window_hint:"display:<id>"` using its numeric macOS
display ID. The result's canonical `app_id` is
`bundle:dev.macoperator.desktop`; screenshot geometry identifies the observed
display. The screenshot returns an ordinary short-lived `visual_ref`, scoped
to the authenticated principal and OAuth session. Pass it as `element_ref`
to `mac_ui_action`, then inspect the new screenshot/ref before the next action.

For this alias, screenshot modes `active_window` (including the default),
`selected_window` and `screen` normalize to a display `screen` capture;
`selected_window` still requires `window_hint`. Use explicit `screen` to make
the intent clear. `capture_mode=none` returns bounded empty AX nodes without a
screenshot or actionable `visual_ref`; it is not a desktop Accessibility tree.
The `desktop` alias is not accepted by `mac_app_open` or `mac_app_focus`.
Focus a concrete application's bundle ID when the task needs its window or
focused text field.

Desktop action coordinates use global macOS screen points, bounded to
-20,000 through 20,000 on each axis. Convert image pixels using the returned
display bounds: `x = floor(window_x + image_x * window_width / image_width)`
and `y = floor(window_y + image_y * window_height / image_height)`. Negative
origins and secondary displays are supported within these bounds. Native
checks constrain input to the observed display and deny protected sessions,
sensitive applications, secure controls and unsafe hit targets. These guards
do not claim to identify arbitrary secrets embedded in screenshot pixels.

Typing still requires a focused ordinary non-secure text target from a fresh
observation; desktop screenshots do not authorize credential input. Generic
submissions and sensitive purchase/send/delete/security actions retain exact
attended approval. The existing credential-free HTTPS browser-address-bar
exception is unchanged.

## Host requirements and limits

The visual adapter is a dedicated `Mac Operator GUI.app` in `~/Applications`.
The Broker permits that one fixed user-owned executable through its process
supervisor. It checks owner, permissions, path, and content identity around
each launch; other user-owned executables do not gain GUI execution access.
Build it with `npm run build`. Every GUI-enabled deployment must run
`npm run install:native:gui-vision --workspace @mac-operator/broker` from the
selected release before startup. The installer validates the exact bundle ID,
application type, executable and strict code signature. If a valid app is
already installed it returns `action=preserved` without changing its bytes or
signature, even when the new release artifact differs. An absent app is copied
into a temporary directory, verified again, and published with an atomic
exclusive rename. Concurrent installers cannot overwrite or nest an app inside
the installed bundle. Existing invalid apps fail closed and require a deliberate
repair; the installer never replaces them automatically. The `--source` option
selects a preserved signed artifact without rebuilding it; see the exact
[deployment command](personal-deployment.md#gui-deployment-prerequisite).

macOS must grant the installed app Accessibility and Screen & System Audio
Recording. Bundle installation and code identity do not prove these TCC grants.
Run `node scripts/probe-gui-launch-context.mjs` from the service launch context
after installation; only the production `gui_launcher` LaunchServices readback
represents the permission boundary. The app's
`permission` command reports both grants without requesting them;
`request_accessibility` and `request_screen_recording` open the system consent
flow. A denied permission makes the GUI tool fail closed. The personal build
uses ad-hoc signing, so rebuilding and replacing the installed app can change
its privacy identity and require permission again. Keep the installed app fixed
during normal source rebuilds. An intentional GUI binary upgrade is a separate
explicit operation; see [intentional GUI upgrade](personal-deployment.md#intentional-gui-binary-upgrade).
It must be followed by production LaunchServices permission readback and, if
necessary, renewing only this app's grants. Do not repeatedly replace it after
the owner renews those grants.

The current W1 deployment does not gain GUI access merely by updating source
code: G1 requires a new signed policy, owner OAuth consent for the new scopes,
and deployment of the new release. The Broker is the only MCP route to this
app; it enforces the tool scopes, configured signed GUI target rules, bounded
requests, attended approvals, and audit records before invoking the adapter.

An attended GUI mutation creates a short-lived approval request. The public
reverse proxy must route `/approval` and its `/login`, `/review`, and
`/decision` paths to the Auth listener, alongside the OAuth routes. The
supervisor must start Auth with the `approval-browser` bridge enabled so the
approval page can read and issue Broker requests. Verify a pending request
through the public URL before asking the owner to approve; a missing route
returns 404 and an expired request returns 403.

Screen capture uses ScreenCaptureKit and rejects known security and credential
windows. Application-scoped `screen` captures remain limited to the main display
and reject other application windows visible beside or above the target window.
Explicit desktop observation selects a full display and can include ordinary
applications together, including Dock and the menu bar. The native filter excludes
known protected and policy-denied application identities and known sensitive
windows, and validates the visible window set before and after capture. These
checks do not prove pixel redaction: a new protected process that appears only
between the window catalog and capture checks remains a residual race.
For application-scoped captures, Dock-owned layer-20 surfaces are excluded from
both obstruction checks and the actual ScreenCaptureKit image.
Other overlays, including computer-control tool overlays, remain subject to the
existing boundary. Ordinary obstruction and outside-window failures have
specific messages; `SECRET_BOUNDARY_DENIED` alone does not mean secret text was
detected in screenshot pixels.
Actions reject secure Accessibility targets and covered coordinates. Arbitrary
ordinary text displayed by a website cannot be reliably identified as a
secret, so agents must use the existing owner approval boundary and avoid
credential pages or sensitive data when choosing what to observe or submit.
GUI tools do not expose DOM automation, security-setting bypasses or shell
execution; personal owner terminal authority remains a separate scope.

## Live acceptance check

On September 27, 2026, a real browser approval was successfully issued and
consumed by `mac_app_focus`, but execution returned `Accessibility permission
is not granted`. The macOS TCC log attributed the service-launched GUI helper
to `/opt/homebrew/Cellar/node/25.5.0/bin/node`; a shell permission probe from
ChatGPT was instead attributed to `com.openai.codex` and reported access.
Therefore a permission probe launched from the agent terminal does not prove
the background service's permission state. Verify grants through the actual
service execution context before claiming GUI readiness. Live Chrome focus,
capture, click, and typing acceptance remains incomplete.

### Approval issuer identity

The browser approval issuer must have a different identity from the MCP
requesting principal. Personal provisioning derives a stable
`browser-approver-<hash>` identity for that role and keeps attended approval
enabled. Reusing the OAuth principal as the issuer causes Broker issuance to
fail even after the owner submits the approval page.

On September 27, 2026 (Asia/Kuala_Lumpur), the running `personal-20260925-g1a`
deployment's issuer metadata was repaired through `ApprovalIssuerKeyManager`
activation from revision 1 to 2, with the service stopped and its instance lock
held. The metadata backup is `approval-keys.json.before-identity-repair` beside
the active configuration. Restart restore and MCP health passed; capability
grants and `allowUnattended: false` were preserved. This does not establish
successful browser control: a fresh owner approval and GUI readback are still
required. Do not restore the old metadata file alone: persisted activation
requires an exact revision and digest match.

### Expired approval recovery

UI action/type previews expire after two minutes; focus/session previews expire
after ten minutes. The owner browser sign-in lasts
thirty minutes after login. An expired operation is not an expired OAuth connection.
The approval pages now distinguish unavailable operation requests from missing
or expired browser sign-ins, and reject unavailable previews before asking for
login. The login page displays the operation deadline in UTC.

A fresh approval link may reuse an authenticated, unexpired owner approval
session. It rotates the browser session and CSRF token, preserves the original
absolute sign-in expiry. Requests outside an active browser session still
require an explicit decision. Expired operation recovery does not issue an approval or extend
the Broker preview lifetime. Successful approval and decline now rotate, rather than clear, the
browser session.

The September 27 recovery hotfix replaced only `packages/auth/dist/app.js` and
`pages.js` in the running `personal-20260925-g1a` snapshot after 27 Auth/page
tests, typecheck, lint, and diff checks passed. Each previous module is retained
beside it with the suffix `.before-approval-recovery`. Roll back both modules
together while the service is stopped, then restart and verify MCP health.
This is a personal deployment hotfix, not a newly signed release.

The approval review page must also send `Referrer-Policy: same-origin`, just
like the login and decision pages. A review page served with `no-referrer`
can make native browser form submission use `Origin: null`, which the CSRF
check correctly rejects. The September 27 follow-up hotfix adds the review
route to the existing same-origin response policy; null and foreign origins
remain rejected. Its previous `app.js` is retained with the suffix
`.before-review-origin-fix`.

After the owner grants macOS permissions and reconnects with a G1 OAuth grant,
use the public Selenium demonstration page at
`https://www.selenium.dev/selenium/web/web-form.html`. Navigate through the
browser address bar, capture an MCP image, click the non-secret text field,
type `Mac Operator test`, scroll the page, capture another image, click Submit,
and inspect the final screenshot for `Received!`. The test is complete only
when the MCP client receives each image block and the final page visibly shows
that result. Do not enter data in the demonstration password field.

### LaunchServices transport (September 27 hotfix)

`GuiProcessSupervisor` routes the fixed GUI executable through `gui_launcher`.
The launcher validates the installed bundle signature and identifier, starts a
new exact application instance with NSWorkspace, and authenticates its private
Unix socket by owner UID, process ID, and executable URL. Arguments and text
travel in a bounded stdin request, not command-line arguments. The application
waits for this request before acting. A disconnected launcher or a 15-second
watchdog ends the application, including when a GUI API is blocked. The launcher
bounds output and waits for application termination before returning a result.
Existing Broker approval, target validation, and result parsing still apply.

The native app must call `finishLaunching` before waiting for the request so
NSWorkspace can complete launch and identify the process without a deadlock.
The installed app was updated, with the previous bundle preserved at
`~/Applications/Mac Operator GUI.app.before-launch-transport`. Its ad-hoc code
signature changed, so renew Accessibility and Screen & System Audio Recording
for the updated app. Do not rebuild it again after this grant renewal.

The personal snapshot hotfix includes `gui_launcher`, `gui-process-supervisor.js`,
`app-control.js`, `ui-inspector.js`, and `broker.js`. Previous existing modules
have `.before-gui-transport` backups. No approval requirement was removed.
Background transport permission readback succeeded with observed termination;
real approved browser operations remain pending system grant renewal.

Restart also exposed an existing preview lifecycle bug: an MCP retry has a new
request ID, but preview consumption previously searched by the original request
ID. Consumption now finds the preview by approval ID. Startup accepts historical
issued previews with consumed approvals only when the execution request links
back to that approval and passes the existing request/audit integrity checks.
No database rows or audit history were removed or rewritten. The previous
`persistence.js` is retained as `.before-preview-retry-fix`; restoring that bug
would prevent startup with these historical records.

The follow-up deployment trusts the fixed `gui_launcher` path in the Broker's
root-ownership supervisor; simply setting `allowUserOwnedExecutable` is not
sufficient. Native permission readback was tested under that strict policy.
Real MCP Chrome focus and active-window JPEG observation then succeeded.
The installed native adapter boxes its truncation flag as numeric 0/1; the
observation parser normalizes only those values on the native path. Its JXA
path and remaining field validation stay strict. Real click and typing
acceptance are still pending; this is not unrestricted or unattended control.

### Approval-time target revalidation

Screenshot-backed UI action and typing targets are now retained until their
original approval-preview deadline (at most 120 seconds). Ordinary observations
still expire after 30 seconds; retention cannot renew or extend an approval.
Before dispatch, the adapter reobserves the same application and window under
a bounded deadline. It requires matching focus, window identity, geometry and
screenshot fingerprint; element targets also require matching field identity,
state and non-secure status. A changed target fails without dispatch, requiring
new observation and approval. Approved payloads are never rebound to a new ref.
Exact screenshot comparison can reject dynamic content or blinking carets;
real click and typing acceptance remains pending. The deployed JavaScript
modules have `.before-approval-revalidation` backups. The native app was not
rebuilt and its macOS grants were preserved.

Approval evidence and current observations are stored separately. Evidence is
scoped to principal, session, tool and exact argument digest; newer observations
refresh the current field without rebinding a pending operation. After an
approval is consumed, request completion or failure releases its retained copy.
Repeating input can therefore obtain fresh evidence immediately. Each store is
bounded to 2048 entries and preserves its own expiry rules. If retained visual
evidence is missing (including after restart or eviction), an approved visual
mutation fails before dispatch rather than falling back to the latest image.
Directly issued visual approvals also require the preview/retention step.
The lifecycle deployment backs up its two modules with
`.before-ui-evidence-lifecycle`; native binaries and macOS grants are unchanged.


## Default browser access

Setting `"defaultBrowserAccess": true` in `auth/auth-config.json` (profiles g1, o1 and v2) lets
the configured owner principal browse with Chrome or Safari without a manual consent click. The
first ordinary open/focus/action/type call without an active grant creates the same persistent
`browser_grant` as the approval page, bound to the current policy version, audited as
`GUI_DEFAULT_BROWSER_GRANTED` and revocable at `/approval/access`. A policy upgrade creates a fresh
grant for the new version, so a policy bump no longer blocks browsing.

Unchanged limits: operations with `requiresExplicitApproval` (web form submission, Enter submission,
named sensitive controls), credentials, passkeys and secure fields still need the independent
attended approval or the owner's own action. Other principals, non-browser apps and desktop
authority are never created by this flag. A revocation at the same policy version is not undone
automatically. Rollback: remove the key (older readers reject unknown config keys), restart, and
revoke the `default-browser:` grants if desired.

## Persistent browser access

The owner can choose **Allow this browser until revoked** on a Chrome or Safari
focus approval page. This explicitly authorizes focus, click/scroll/key and text
input for the same owner principal, app and policy version, without a time or
operation quota. It survives service restart and owner OAuth reconnection.
Existing temporary consent is never upgraded: previously rendered
`allow-session` forms still create only 30-minute, 500-operation sessions.

The browser approval-page login lasts thirty minutes, independently of durable
browser authority. Expired login cookies do not revoke access or trigger new
operation approvals. OAuth authentication and its own expiry/revocation, signed
policy, screenshot revalidation and macOS permissions remain required. Other
applications, filesystem writes, terminal and system operations are outside
this browser grant.
Focus consent previews last ten minutes; visual-action previews last two minutes.

The protected AuthStore `browser_grant` records are the source of durable
browser authority. The supervisor reloads these records and uses the existing
approval issuer IPC to issue a single-use, exact-payload approval for each
operation. Reserved approval IDs bind issuance to the authenticated request ID.
Audit events link consent and operations. The incoming OAuth session is checked
on every call; a revoked session cannot use a persistent grant. Policy changes
may require new consent. Each issued child approval expires within thirty seconds.
Graceful shutdown revokes children but preserves persistent owner consent.

Visit `/approval/access` to sign in and view or revoke all current owner browser
grants, even without a pending operation preview. Revocation persists before
child cleanup, and is rechecked after in-flight issuance. The auth reset command
also revokes persistent browser grants. Revoked consent markers survive restart
so replaying an old preview cannot restore authority.

For explicitly authorized local-owner setup, stop the personal service and run:

```sh
node packages/auth/dist/personal-service.js browser-access STATE_ROOT REQUEST_ID --until-revoked
```

Use a fresh focus preview from the owner's authenticated MCP connection. The
command requires exclusive service ownership, verifies the G1 signed policy and
owner identity, then invokes the same consent persistence/audit path. Restart
the service afterward. This is a local owner configuration command; it is not
exposed as an MCP tool and does not issue or execute browser operations.

For rollback, retain the updated AuthStore and contract readers while any
`browser_grant` records exist, including revoked consent markers. Older readers
reject the new record kind. Disable the delegation hook to stop issuance rather
than rolling back database readers. Keep the newer Broker persistence validator
for ten-minute focus previews as well. Do not rebuild the native GUI app as part
of this JavaScript-only change.


## Explicit desktop delegation

Desktop computer use is a separate owner consent record and signed-policy
opt-in for G1, O1 or V2. The default remains `guiAccess=browsers`. A durable
`desktop_grant` binds the owner principal, current policy version and explicit
consent request; it has no browser-app binding and persists until revoked.
Existing `browser_grant` records, temporary browser sessions and browser
approval-page choices are never promoted into desktop authority.

After explicit owner authorization, stop the personal service, take a complete
stopped-state backup, and run from the selected release with its source commit
revision:

```sh
node packages/auth/dist/personal-service.js computer-use ROOT REV --enable --until-revoked
```

`ROOT` is the private personal state root and `REV` is the release's hexadecimal
source revision. The command requires exclusive service ownership, verifies
the existing signed policy and owner/Edge bindings, enables only the GUI target
expansion, and records explicit desktop consent with intent/completion audit
events. It preserves non-GUI policy targets and existing OAuth scopes. Repeating
it with a valid grant for the same principal and policy is idempotent. It does
not install the GUI app, grant macOS permissions or prove live tool readiness.
Restart the service and verify [runtime GUI readiness](personal-deployment.md#runtime-gui-readiness)
and actual authenticated MCP observation/action before claiming acceptance.

The delegation issues exact, single-use child approvals for authorized
open/focus/action/type calls; every call still needs live unrevoked OAuth
authentication, current signed policy, native readiness and valid concrete or
observed target evidence. Secure fields, protected applications and sensitive submissions
keep their existing denial or exact attended approval requirements. Desktop
delegation does not confer terminal, filesystem, privileged or security-setting
authority. The agent can focus an authorized concrete app through MCP rather
than asking the owner to bring it forward manually.

Use `/approval/access` to inspect and revoke desktop and browser grants
separately. Revocation persists before child cleanup and is rechecked after
in-flight approval issuance; Auth reset also revokes both record kinds. Policy
changes invalidate mismatched delegation without widening old consent.
Keep updated AuthStore readers while `desktop_grant` records exist, including
revoked records. Disable desktop delegation to stop issuance; for a binary/state
rollback restore the complete consistent stopped-state backup instead of
mixing old readers with new records or partially restored policy/config files.

## Dock hit-testing correction (2026-09-27)

A live click at the Selenium form's ordinary text input was blocked by a Dock
window on layer 20 whose bounds covered the entire 1920x1080 display. Both the
browser-scoped and system-wide AX hit tests resolved that point to Chrome's
`AXTextField` labeled `Text input`. Thus this Dock window was not the click target.
The native adapter now exempts only a `com.apple.dock` layer-20 overlay when the
system-wide hit test identifies the authorized browser PID. Different apps,
layers, actual Dock hits and failed hit tests retain the original denial path.
Secure-field validation remains separate and still runs after the overlay check.

Chrome accessibility is requested via `AXEnhancedUserInterface` before native
inspection/action/input. Chrome exposes its full tree on demand, as documented in
[Chromium accessibility documentation](https://www.chromium.org/developers/design-documents/accessibility/).
This requests browser AX information; it does not grant macOS TCC permission.

The fixed native bundle is installed and both direct and LaunchServices
permission preflights now report Accessibility and Screen Recording available.
After an ad-hoc rebuild, an existing enabled System Settings row can still refer
to the old signature. Removing and re-adding the exact current application in
both permission lists restored the same permissions; toggling alone did not.
Keep the installed signed bundle stable between releases. Previous bundles are
archived under `~/Library/Application Support/MacOperator/`.

## Input delivery and result contracts (2026-09-28)

Live verification found that multi-character Unicode events were dropped and
immediate sender exit could discard queued mouse or keyboard events. The native
adapter now posts one Unicode scalar per event (preserving UTF-16 surrogate
pairs), clears inherited keyboard modifiers and remains alive for 250 ms after
input dispatch. This is a bounded delivery grace period, not proof that every
page handled an event. Callers must inspect the resulting page.

The action output schema no longer combines an Accessibility-only `const` with
an enum that includes visual dispatch. The input output schema now accepts the
Broker's existing `job_id`. Regression tests validate actual success payload
shapes and reject unsupported strategies and unknown fields.

Actual MCP click and input were verified on Selenium's ordinary Textarea:
`Mac Operator test` followed by two Chinese characters and an emoji appeared
completely. The form was not submitted. Persistent Chrome consent remained
usable after the service restart without a new owner approval.

Caret-phase recovery: retained targets now receive up to four observations,
spaced by 175 ms after a pixel mismatch, within the original execution deadline.
App/window identity and focused input identity are checked on every observation;
identity changes, cancellation and timeout stop execution. Dispatch still
requires an exact match to the originally approved screenshot, including its
geometry. The reference evidence is never replaced and no input is sent during
retries. Persistent content changes still fail before dispatch. This reduces
caret false alarms without accepting different pixels; it does not guarantee
success on continuously changing pages. This exact-pixel rule still applies to
attended approvals, sensitive/submitting actions, visual references, desktop and
legacy adapters. Ordinary concrete native AX targets can use identity-based
revalidation only when this execution successfully obtains owner GUI session
authorization. That path independently reobserves the exact application,
window/process generation, target index/role/label, enabled and secure state,
input focus when typing, and all screenshot geometry. It tolerates changing
pixels such as an animated caret; it does not prove that document/page content
is unchanged. A previous GUI authorization cannot authorize this execution, and
an attended approval upgrades retained evidence back to exact-pixel checking
without refreshing its timestamp or expiry. Native event-time security checks
remain mandatory for both paths.

A returned input success currently verifies dispatch and focus, not
exact field value; use a fresh screenshot/readback for acceptance. Safari,
maximum-length input and every OS-level workflow were not covered by this test.
