# User-domain service-control candidate

- Date: 2026-09-21; updated: 2026-09-22
- Scope: MOP-104 / proposed `mac_service_control`
- Status: standard Broker lifecycle implemented; default-disabled candidate, not a release acceptance

## Implemented boundary

`packages/broker/src/user-service-control.ts` adds an independently testable
owner-domain LaunchAgent control adapter. It accepts only `start`, `stop`, and
`restart` for a policy-owned `gui/<non-root-uid>/com.mac-operator.*` service
binding. Each binding fixes the LaunchAgent plist path, executable, argument
vector, and source revision. The request cannot supply an executable, plist,
shell string, environment, or arbitrary launchctl arguments.

The command boundary is fixed to `/bin/launchctl` with cwd `/`, an empty
environment, a 5-second command budget, and a 128 KiB output cap. The adapter
is disabled unless an explicit host enablement and both host-only command and
readback seams are supplied. Native production wiring uses the separate
system-published executable boundary for this fixed command: the executable
and every canonical ancestor must be root-owned, non-symlink, and not
group/other writable, the Broker must be unprivileged, and an explicit
operator-acceptance flag is still required. A descriptor launcher remains an
accepted alternative when one is available; neither path authorizes arbitrary
task scripts. The standard Broker/MCP request lifecycle is now wired to this
adapter behind normal policy, target, approval, Job, authority, and
host-runtime gates. The default policy and OAuth profile keep the capability
disabled.

`packages/broker/src/user-service-control-contract.ts` defines the frozen,
versioned, design-only candidate contract, including bounded actions, safety
defaults, verification, rollback, recovery, and audit classification.

`packages/broker/src/user-service-control-executor.ts` adds the isolated Broker
Job execution seam. It persists a non-secret precondition containing the stable
service state and source revision, renews a bounded Job lease, checks authority
and cancellation before dispatch, maps verified results to terminal Job state,
and retains the metadata when the outcome is `UNKNOWN`. The executor is
reachable from the standard Broker path only when the candidate runtime is
explicitly supplied and enabled; the default Broker/MCP surface remains
disabled.

`packages/broker/src/user-service-control-admission.ts` and the internal
`Broker.executeUserServiceControlCandidate` seam now exercise the Broker-owned
admission lifecycle alongside the standard `Broker.handle()` path. A signed request is
revalidated against the normal Edge/principal/revocation authority, the exact
candidate principal and kill-switch gates, and the adapter's bound service
identity. The existing atomic admission transaction then consumes the matching
approval, records decision and intent, persists the precondition-backed Job,
and preserves idempotent reuse. Execution closes the Request audit lifecycle
after the Job's verified readback. The public `handle()` path accepts the tool
only under an explicitly enabled policy and matching OAuth/target/approval
gates; the default policy continues to reject it.

`packages/broker/src/service-startup.ts` now exposes an explicit
`createUserServiceControlRuntime` assembly seam. It constructs the adapter and
Job executor only from owner-supplied bindings, principal allowlists, an
independent source-revision reader, and fixed executable evidence. Broker
startup invokes user-service recovery before listeners are exposed; recovery
performs readback only and never replays a mutation.

## Verification behavior

The adapter reads the exact bound launchd identity and source revision before
dispatch and reads them again after dispatch. It accepts only stable `running`
or `stopped` states. A postcondition mismatch attempts the inverse fixed
command and requires the original state and source revision to read back. If
execution or rollback cannot be established, it returns `UNKNOWN_OUTCOME`.

`packages/broker/src/user-service-control.test.ts` verifies:

- default-disabled behavior;
- exact user-domain target and fixed argv/environment/cwd/output limits;
- idempotent start;
- postcondition mismatch with verified rollback;
- unresolved rollback mapped to `UNKNOWN_OUTCOME`;
- uncertain command result with changed state and verified inverse rollback;
- system, root, unbound, and source-revision-swapped target denial;
- cancellation and unsupported-action denial before dispatch.

## Evidence

- `npm run build` passed, including TypeScript build and native build steps.
- The separate physical-host readback probe passed for a real user-domain
  LaunchAgent; see `evidence/2026-09-21-user-service-readback.md`.
- The focused adapter suite passes 13/13, and the focused admission and
  Job-executor suites pass 14/14, including public
  completed-Job reuse after a second exact approval, active-session
  revocation preserving `UNKNOWN_OUTCOME`, unresolved command/rollback
  handling, durable Job metadata, cancellation fencing, and host-startup
  recovery readback that never promotes an UNKNOWN Job.
- The service-startup assembly suite passes 8/8 and proves that missing fixed
  executable evidence fails closed while explicit host acceptance can assemble
  the bounded runtime on the physical macOS host.
- The original candidate implementation change did not mutate an ordinary
  user service. A separate bounded physical-host disposable probe now covers
  real Broker-mediated start/stop, target-swap rejection, active-revocation
  UNKNOWN handling, restart readback without replay, and exact cleanup; see
  `evidence/2026-09-22-user-service-mutation-boundary.md`. A second physical
  probe covers a real stop command followed by a deliberately forced running
  postcondition and verified inverse rollback; see
  `evidence/2026-09-22-user-service-rollback-boundary.md`.
- The native wiring tests confirm that missing or ambiguous command wiring
  cannot make the candidate available, and the system-published boundary tests
  pass for the physical host's fixed `/bin/launchctl` path. The candidate still
  remains disabled; only the fixed disposable probe identity was mutated.

## Remaining release gates

This does not satisfy ADR-0010's release gate. The candidate now has physical
rollback and restart-recovery evidence, but still needs public
OAuth/tools-list/ChatGPT call evidence.
The current host also lacks the
descriptor-backed executable launcher required for production mutation paths.
The scope and machine-readable contract are now part of the planned runtime
vocabulary, but the default policy records `implemented: true` and
`enabled: false`; no OAuth grant or public tools-list enablement was added.
The standard Broker dispatch path now binds the candidate to normal
authentication, target authorization, approval, durable Job idempotency,
lease/authority checks, and strict service-state readback. Until the remaining
real-Mac and release gates pass, `mac_service_control` remains unavailable to
the public MCP profile.
