# GUI Public Exposure Gate

Date: 2026-09-22
Host: Darwin arm64 physical Mac, current process UID 501
Status: `implemented` as a production-startup guard; Accessibility permission remains unavailable

## Boundary

Accessibility-dependent GUI tools are explicitly identified:

- `mac_app_focus`
- `mac_ui_observe`
- `mac_ui_action`
- `mac_ui_type`

Production Broker startup now requires a host-owned `guiPublicEnablement`
state of `production` before any of these tools can be enabled. The default
startup state is `unavailable`; `staging-only` is also rejected for a service
startup. Direct staging Broker probes remain available for boundary testing,
but they do not change production capability publication.

The Broker capability projection reports these tools as runtime-unavailable
when startup readiness is not production, and request planning rejects them
before an Accessibility command or approval-consuming mutation can execute.
`mac_app_open` and `mac_app_list` are not included in this permission gate
because their bounded adapters do not require Accessibility permission.

## Verification

- Focused GUI readiness coverage passed 2/2 tests, including unavailable,
  staging-only, production, and tool classification cases.
- Full repository regression passes 1,045/1,060 tests with 15 explicit skips
  and 0 failures.
- Typecheck and build passed.
- The current read-only host probe still reports Accessibility permission
  denied, so no production GUI state was asserted or enabled.
- No live policy, OAuth grant, LaunchAgent, LaunchDaemon, permission, or GUI
  state changed.

## Remaining gates

The physical host still requires owner-granted Accessibility permission,
permission-granted real-application observation, focus/action/type readback,
target-swap evidence, rollback, and final independent security review before
G1 can be accepted.
