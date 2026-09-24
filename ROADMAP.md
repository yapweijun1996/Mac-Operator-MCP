# Mac-Operator-MCP Roadmap

Status: Active implementation with gated release
Version: 0.1
Last verified: 2026-09-23 (guest-result recovery and full regression)

## Current position

The repository has a committed TypeScript/Node implementation baseline. Work
spans the authenticated Edge/Broker foundation, MCP discovery/error mapping,
bounded post-authentication rate limiting, bounded L0/L1 plus
Git/package/Docker inspection, read-only app inventory, GUI boundary
prototypes, and the separately authenticated privileged-helper/package
candidate. Production enablement remains closed where host identity,
signing, installation, permission, or independent review evidence is still
missing.

The latest physical-host evidence includes a temporary Edge-first/Broker-second
LaunchAgent lifecycle smoke and a digest-bound Keychain ACL/retirement rerun.
Both are disposable, zero-capability checks; persistent production install,
Developer ID/notarization, descriptor execution, and privileged enablement
remain release gates.

The production packaging boundary now enforces a fixed Gatekeeper
`Notarized Developer ID` assessment for Broker, Edge, and root-helper plans,
including final identity-bound readback. This closes the implementation gate;
the release preflight now also binds a manifest digest/byte summary and exact
Developer ID identity before assessment. Real signed/notarized release-artifact
evidence and persistent lifecycle proof remain open.

The root-helper release path now has an explicit `development-probe` versus
`production` gate across runtime, server, Broker task, and transport capability
assembly. The production artifact is re-read and identity-compared at startup
and before dispatch. A reproducible owner-only verifier is available through
`npm run verify:release:root-helper -- --manifest <canonical-path>`; it emits
only the redacted evidence accepted by the production gate. This is still
release tooling, not an installed or enabled root helper.

An owner-only personal deployment is now live at the public MCP endpoint. The
R1 service/API profile exposes 30 bounded read-only tools under 17 exact
scopes. A separate owner-approved ChatGPT R1 app is connected and exposes the
same 30 read-only actions; an older app still retains its historical R0 grant.
This deployment is a validated personal snapshot, not acceptance of the formal
Developer ID/notarized release.

The current owner priority is W1: attended file and local Git writes for one
selected repository on this Mac mini. W1 source and provisioning tests are in
place, but the live service remains R1 pending a separate snapshot switch and
ChatGPT reconnect. Task execution, GUI, service control, and privileged work
are outside the current owner request.

The working tree also implements direct owner-issuer revocation push through
the fixed Auth child, owner supervisor, and Edge child, reusing the existing
authenticated Edge-to-Broker revocation event. This is focused-tested source
evidence only; the live personal snapshot was not restarted.

## Owner-only full access expansion

This is the longer-term capability rollout overlay retained for planning. The
current owner request is limited to W1. It does not replace the Phase 0-7
engineering lifecycle below. A contract or policy entry is not remotely usable
until its exact scopes, targets, runtime, approval path, verification evidence,
and release gate all pass.

The following remain excluded from the public MCP surface:
arbitrary shell strings, arbitrary root commands, raw Keychain or private-key
reads, raw Docker socket proxying, arbitrary AppleScript/JXA, generic
click-anywhere automation, credential autofill, Git push/force-reset, and
security-setting bypasses.

### Grant profiles

Scopes are exact and non-inheriting. Each profile requires a fresh grant when
new scopes are introduced; reconnecting an existing ChatGPT app is not assumed
to expand its stored default scopes.

| Profile | Purpose | Scopes | Status |
| --- | --- | --- | --- |
| `R0` | Historical three-tool read-only baseline | `mac.control.read`, `mac.system.read` | Accepted; retained by the older app |
| `R1` | Current full bounded read-only diagnosis | `mac.control.read`, `mac.policy.explain`, `mac.system.read`, `mac.storage.read`, `mac.process.read`, `mac.log.read`, `mac.network.read`, `mac.service.read`, `mac.package.read`, `mac.files.read`, `mac.files.search`, `mac.files.hash`, `mac.project.read`, `mac.git.read`, `mac.docker.read`, `mac.app.read`, `mac.job.read` | Service/API and separate ChatGPT app accepted; 30 tools |
| `W1` | One owner Git project with attended file and local Git writes | `R1` except `mac.docker.read`, plus `mac.files.write`, `mac.project.write`, `mac.git.write`, `mac.job.cancel` | Source and provisioning verified; 32 tools; live switch and ChatGPT write probe pending. Docker reads stay on R1 until descriptor execution is available. |
| `D1` | Controlled developer workflows | `R1` plus `mac.files.write`, `mac.project.write`, `mac.git.write`, `mac.service.control`, `mac.task.run`, `mac.job.cancel` | Staging OAuth/profile parity and production-startup exposure gates implemented for TaskRunner and developer mutations; fresh owner-only host-readiness evidence is required; public enablement remains sandbox/release/approval gated |
| `G1` | Approved application and GUI workflows | `D1` plus `mac.app.control`, `mac.ui.observe`, `mac.ui.control` | Production exposure gate implemented; Accessibility, target, rollback, and real-app evidence gates remain |
| `P1` | Narrow privileged operations | `G1` plus `mac.priv.service`, `mac.priv.package`, `mac.priv.power` | Proposed; helper/release gated |

`R1` is the recommended next ChatGPT grant. `D1`, `G1`, and `P1` should be
separately authorized or explicitly re-consented rather than silently added to
the current app.

### Existing tool rollout

| Phase | Tool set | Required scopes | Exit gate |
| --- | --- | --- | --- |
| A — Read-only expansion | Existing L0/L1 tools, Git/package/Docker inspection, `mac_app_list`, `mac_job_status` | `R1` | Exact allowed roots/targets, secret denial, redaction, public OAuth probe, real ChatGPT list and calls, revocation |
| B — Developer operations | `mac_task_run`, `mac_write_file_atomic`, `mac_apply_patch`, `mac_git_stage`, `mac_git_commit`, `mac_job_cancel` | `D1` additions | Named profiles only, enforceable sandbox, explicit approval, idempotency, readback verification, rollback and `UNKNOWN` handling |
| C — Apps and GUI | `mac_app_open`, `mac_app_focus`, `mac_ui_observe`, `mac_ui_action`, `mac_ui_type` | `G1` additions | Accessibility permission, stable app/window/element identity, sensitive-target denial, stale-target rejection, real-app verification |
| D — Privileged helper | `mac_priv_service_control`, `mac_priv_package_install`, `mac_priv_power` | `P1` additions | Developer ID/notarization, protected Keychain and cross-process identity, root-helper lifecycle, explicit approval, operation allowlist, rollback, independent review |

The D1 task runner remains closed after the physical double-fork/`setsid`
probe escaped the current process cleanup boundary. Broker-side durable result
journaling is now implemented: verified guest responses are bounded, redacted,
audit-bound, restart-recoverable without a second guest lookup, and retained in
encrypted ledger archives. A disabled source-level candidate now serializes
guest work as start → operation/result journal → hard-stop; a stop failure
leaves the VM state unknown and fences later tasks. It reuses one startup VM
handle and read-only image, so mutable-state reset and native hard-stop remain
unproven. It still requires an approved guest image and repeated real
boot/run/stop plus adversarial descendant checks before adoption. Uncertain
outcomes remain `UNKNOWN` and are never replayed. See
[`evidence/2026-09-23-virtualization-guest-result-journal.md`](evidence/2026-09-23-virtualization-guest-result-journal.md),
[`evidence/2026-09-23-virtualization-task-scoped-lifecycle.md`](evidence/2026-09-23-virtualization-task-scoped-lifecycle.md),
and [`evidence/2026-09-23-virtualization-task-fence-review.md`](evidence/2026-09-23-virtualization-task-fence-review.md).

### Missing bounded tools for broader Mac operations

The 45-tool catalog does not yet cover every useful host-control family. If
the owner wants broader management, add separate contracts and exact scopes;
do not widen an existing read or task scope:

| Proposed tool | Proposed scope | Boundary |
| --- | --- | --- |
| `mac_process_control` | `mac.process.control` | Stop/restart only an allowlisted process or Broker-owned job; never arbitrary PID signalling |
| `mac_docker_control` | `mac.docker.control` | Start/stop/restart approved Docker objects; never expose the Docker socket or arbitrary `exec` |
| `mac_network_control` | `mac.network.control` | Bounded interface, route, DNS, or firewall changes with rollback/readback |
| `mac_system_settings` | `mac.system.settings` | Allowlisted macOS settings only; no privacy/security bypass |
| `mac_package_manage` | `mac.package.write` | Install/update/remove approved package identities and versions; no arbitrary installer command |
| `mac_service_control` | `mac.service.control` | Broker dispatch, adapter, and durable Job/readback path implemented but disabled by default; user-domain allowlisted service lifecycle; system/root services remain helper-owned |

The five remaining rows are design vocabulary only. `mac.service.control` is now
materialized as a planned scope and contract, with disposable physical
mutation/rollback probes and an opt-in D1 Auth -> HTTPS Edge -> Broker -> Job
-> launchd readback canary. It is not in the R1 OAuth grant and remains
disabled in the default policy. Public enablement, persistent lifecycle,
production signing, and ChatGPT call evidence remain open. The bounded
contract matrix and family-specific safety rules are recorded in
[`docs/adr/0010-bounded-host-control-contracts.md`](docs/adr/0010-bounded-host-control-contracts.md).
The remaining proposed scopes must not be added to OAuth or policy until a
materialized contract, adapter, target model, approval class, rollback test,
and real-Mac readback exist.

### Cross-cutting acceptance gates

Every expansion phase must complete all of the following:

1. Contract schema, scope, target type, safety class, output cap, and
   postcondition are reviewed and parity-checked.
2. Broker policy is default-deny, owner-only, finite-target, kill-switchable,
   and independently revocable.
3. Mutation and privileged calls have explicit approval, redacted audit, and
   verified readback; uncertain outcomes remain `UNKNOWN`.
4. Real-Mac tests cover target swaps, secret denial, timeout, cancellation,
   restart, rollback, and permission failures.
5. The public OAuth challenge, active grant, MCP `tools/list`, and real
   ChatGPT `tools/call` all show the same scope/tool set.
6. A revoke/rollback test proves the newly exposed capability can be removed
   without restoring stale authority.

Phase A / profile `R1` is implemented and accepted at the service/API boundary,
and the separate owner-approved ChatGPT R1 app has a fresh 17-scope grant with
30 discovered read-only actions and representative successful calls. Existing
OAuth grants are not widened implicitly. The current loopback-enabled r1f
snapshot is live and API-verified; the formal signed-release gate and any
future client reconnect after a material contract/scope change remain explicit
operations. No D1, G1, P1, arbitrary shell, unrestricted root, or privileged
control is enabled by this R1 deployment.

## Phase 0 — Foundation and contracts

Status: `IN_PROGRESS`

Materialize locked KB security, filesystem, and tool contracts; confirm runtime and package strategy; create project structure; freeze request/result/error schemas and principal, scope, identity/IPC, approval, policy, persistence, job, idempotency, audit, and revocation contracts; complete sandbox research; maintain the threat and verification matrices; establish formatting, lint, typecheck, unit, security, and CI checks.

Exit: documentation and schemas agree; the baseline is reproducible; security invariants have failing-then-passing tests; no host mutation capability is enabled.

## Phase 1 — Local Broker vertical slice

Status: `IN_PROGRESS`

Implement protected local IPC, Broker health and capabilities, policy explanation, principal validation, replay defense, target normalization, policy evaluation, audit events, kill switches, and one safe file-read adapter.

Exit: local integration tests and real-Mac evidence cover success, unauthorized access, secret denial, path escape, target swap, output cap, timeout, lock, revocation, and restart behavior.

## Phase 2 — Remote MCP Edge

Status: `IN_PROGRESS`

Implement MCP transport, remote authentication, principal projection, tool-state discovery, request signing, rate limits, revocation, and a deployment-independent local test mode. Select and configure the authenticated HTTPS/tunnel path after the local boundary passes.

Exit: a real authorized client reaches the Phase 1 slice remotely; forged, replayed, expired, revoked, and scope-invalid calls fail closed.

## Phase 3 — L0/L1 inspection expansion

Status: `IN_PROGRESS`

Add system, storage, process, service, network, approved log, directory, search, hash, recent-file metadata, project discovery, summary, and bounded tree tools. Expand secret, filesystem-race, redaction, and resource-exhaustion tests.

Exit: the Mac can be diagnosed safely through released read-only tools with exact-revision evidence.

## Phase 4 — L2 developer operations

Status: `IN_PROGRESS`

Bounded Git, package, and fixed local-only Docker inspection are implemented with independent scopes and target authorization. An experimental, disabled-by-default macOS `SandboxExecTaskRunner` now renders a Broker-owned deny-default profile with a default single-process/no-fork policy and passes explicit execution limits through `ProcessSupervisor`; a direct physical-host Seatbelt probe now verifies allowed-root read/write behavior, but the Broker's complete execution-boundary evidence is still partial. Continue with named test/build profiles and Broker-owned jobs only after sandbox evidence; prove executable selection, filesystem, network, environment, process-tree, and credential isolation before enabling controlled writes. Atomic file writes, a separate bounded textual patch path, explicit staging, and local commits now have preconditions and verification boundaries; all mutation tools remain disabled by default pending release evidence.

Fixed host adapters now have a separate `darwin-system-published-executable-v1`
pathname boundary for commands such as `/bin/launchctl`: root-owned,
non-symlink, non-group/other-writable ancestors, no setuid/setgid target bits,
and an unprivileged Broker are required. This is a same-user target-swap
control for fixed adapter commands only; it is not a generic task-script or
`mac_task_run` substitute, and the public service-control capability remains
disabled pending its own approval, policy, rollback, and live readback gates.

The experimental `SandboxExecTaskRunner` also has an explicit
system-published executable mode for a Broker-owned fixed allowlist. A
physical opt-in run verified `/usr/bin/printf` through deny-default Seatbelt,
but this does not authorize repository scripts, arbitrary task paths, or the
public task scope; generic descriptor-mode execution remains fail-closed.
Evidence:
[`evidence/2026-09-21-system-published-task-boundary.md`](evidence/2026-09-21-system-published-task-boundary.md).

A dedicated Darwin arm64 temporary-root mutation probe now verifies the existing
atomic-write and bounded-patch adapters through the real Broker: signed
preview-bound ApprovalAuthority issuance, unapproved write denial, Job
completion, idempotent retry, physical readback, audit redaction, and
temporary-file cleanup all pass. This advances the file-mutation evidence
without enabling public D1 scopes; generic task execution remains closed until
executable selection and complete isolation are proven. Evidence:
[`evidence/2026-09-21-d1-mutation-boundary.md`](evidence/2026-09-21-d1-mutation-boundary.md).

A companion Darwin arm64 temporary-Git probe now verifies the explicit staging
and local-commit adapters through the real Broker: signed preview-bound
approval, unapproved staging denial, staged-digest precondition rejection
with preserved index and `UNKNOWN` Job state, verified local commit and
HEAD/index/worktree readback, no configured remote, and redacted audit output.
This advances D1 Git evidence without enabling public mutation scopes or
generic repository-script execution. Evidence:
[`evidence/2026-09-21-d1-git-boundary.md`](evidence/2026-09-21-d1-git-boundary.md).

A Broker-level Darwin arm64 task probe now verifies the fixed system-published
task boundary through signed named-profile requests: unapproved denial,
verified `/usr/bin/printf` output, single-process/no-network policy, process
identity capture, active `/bin/sleep` cancellation, terminal Job readback, and
audit redaction. The probe found and fixed a real Job-revision race when active
cancellation changed the Job before terminal persistence. This evidence does
not enable public `mac_task_run`, interpreters, repository scripts, or generic
descriptor-backed executable selection. Evidence:
[`evidence/2026-09-21-d1-task-boundary.md`](evidence/2026-09-21-d1-task-boundary.md).

A follow-up physical recovery probe closes and reopens the BrokerStore while a
fixed `/bin/sleep` task is running, then uses a second Broker instance to drain
the exact persisted PID/start-time identity. The Job remains `UNKNOWN`, no
task replay or success promotion occurs, and the completion audit reads
`PROCESS_DRAINED`. This is restart-recovery evidence only; generic descriptor
execution, VM/guest isolation, production packaging, and public D1 enablement
remain gated. Evidence:
[`evidence/2026-09-21-d1-task-recovery-boundary.md`](evidence/2026-09-21-d1-task-recovery-boundary.md).

The future authenticated root-helper boundary now has a strict,
disabled-by-default Broker adapter and native transport/server seam. It
requires independent host proof for FD identity, immutable selection,
root-owned private snapshots, close-on-exec, and native peer/HMAC
authentication; verifies signed plan digests before dispatch; omits
executable/cwd paths; and fails closed on incomplete capability, unobserved
termination, or transport failure. The physical non-root gate is verified, but
this is not production helper installation, immutable launch proof, or public
task enablement. Evidence:
[`evidence/2026-09-21-root-helper-snapshot-contract.md`](evidence/2026-09-21-root-helper-snapshot-contract.md).
[`evidence/2026-09-21-root-helper-snapshot-transport.md`](evidence/2026-09-21-root-helper-snapshot-transport.md).

The next helper handoff seam is now represented by a separate,
disabled-by-default descriptor snapshot registry. It retains Broker-opened
executable/cwd descriptors behind one-shot opaque refs and signs only bounded
plan and FD-identity digests; it revalidates held descriptors before callback
handoff and exposes no path, argv, environment, or filesystem-root data. Its
attestation deliberately says `revalidation-only`, so this does not close the
native immutable-selection, close-on-exec, cross-process FD-transfer, or
sandbox release gates. Evidence:
[`evidence/2026-09-21-descriptor-snapshot-helper-attestation.md`](evidence/2026-09-21-descriptor-snapshot-helper-attestation.md).
The native addon separately verifies local `SCM_RIGHTS` transfer and receiver
`FD_CLOEXEC` handling. A separate disabled-by-default receiver now authenticates
the UNIX stream peer before consuming one bounded opaque frame; this transport
capability remains outside task admission and does not establish immutable
executable selection, production helper packaging, or helper launch. The
spawned receiver fixture proves only the cross-process transport boundary.
Evidence:
[`evidence/2026-09-21-native-scm-rights-capability.md`](evidence/2026-09-21-native-scm-rights-capability.md).
[`evidence/2026-09-21-native-descriptor-handoff-frame.md`](evidence/2026-09-21-native-descriptor-handoff-frame.md).

Exit: approved real-project workflows pass without exposing a generic shell or controller credentials.

## Phase 5 — L3/L4 apps and GUI

Status: `IN_PROGRESS`

App inventory, disabled-by-default approval-bound app launch/focus slices, the read-only Accessibility observation boundary, and a disabled-by-default snapshot-bound `mac_ui_action` boundary are implemented with stable bundle identities and exact app/window/element target rules. Add structured native automation next. Extend app/action scopes, sensitive-surface rules, and macOS permission recovery before any GUI capability is enabled.

Exit: approved workflows pass real-application tests and sensitive or stale targets fail closed.

## Phase 6 — L5 privileged helper

Status: `IN_PROGRESS` (release gated)

The helper protocol, separately authenticated IPC boundary, runtime,
non-executing root-domain package plan, and Broker Job dispatch paths are
implemented as fail-closed candidates: OS peer authorization precedes parsing,
HMAC commands/responses are digest-bound, helper request/nonce replay is
durable, only three operation names are representable, and a Broker-owned
factory signs commands only for matching explicit-approval, intent-linked
running Jobs after active authority checks. Focused helper/runtime/package,
install-plan, and Broker-dispatch tests pass on the physical macOS host. The
Broker executor now also requires an explicit operation allowlist, and
capability discovery/planning gate each privileged tool against that allowlist.
The default policy and executor remain disabled. The helper runtime now requires a
separately authenticated Broker authority poller whenever an adapter is
enabled; polls occur before dispatch, during execution, and before success,
with post-dispatch authority loss mapped to `UNKNOWN_OUTCOME`. Native Broker
startup now restores the active helper key and owns this authority listener
with rollback on partial startup; production startup rejects root-as-Broker or
non-root-as-helper peer-role substitutions. Finalize Developer ID provenance,
and use the root-helper key-material startup path that does not open
`BrokerStore`; revocation and active authority remain Broker-owned through the
authenticated poll channel. The older BrokerStore-backed runtime factory is
retained only for Broker-side activation and compatibility paths. Also finalize
the root-domain package plan's explicit Broker-owned authority socket and
exact three-socket runtime readback, including Broker-owned socket UID/GID,
mode, and device/inode readback, then finalize
 protected production Keychain material, root-domain lifecycle readback,
operation-specific rollback and recovery, compatibility, real adapters, and
independent review before enabling any privileged adapter.

The fixed `mac_priv_service_control` adapter now has a separate
system-published `/bin/launchctl` pathname boundary for hosts without the
descriptor launcher. This is still a disabled release candidate: explicit
host acceptance, root-helper packaging/install, Developer ID/notarization,
authority/readback evidence, live rollback, and independent review remain
required. Evidence:
[`evidence/2026-09-21-privileged-service-published-boundary.md`](evidence/2026-09-21-privileged-service-published-boundary.md).

The native root-helper snapshot transport/server seam is now implemented as a
separate disabled-by-default boundary. It authenticates the helper peer,
transfers only bounded descriptors and signed digests, verifies executable
content before creating a private root-owned snapshot, and binds the child to
the authenticated Broker identity. The current physical host is non-root, so
the server advertises no capability and refuses to listen with `POLICY_DENIED`.
This advances implementation evidence only; root-owned installation, live
round-trip/readback, recovery, signing, and public task enablement remain open.
The native descriptor receiver now bounds the initial frame, continuation
bytes, and stream-close observation with one absolute deadline.
The working tree also provides a separate key-material runtime factory that
loads the protected helper key without `BrokerStore`, rejects socket reuse and
unnamed Broker peers, and preserves the same fail-closed host gate. It is a
startup seam only; it does not install or bootstrap a LaunchDaemon. Broker
startup now has an explicit root-helper authority-channel assembly, and the
root-helper service entrypoint binds the Broker LaunchAgent through launchd
readback plus native PID/start-time and uid-0 ownership checks. The transport
and authority endpoint share a Broker-owned active request-digest registry, so
an authenticated helper poll is denied unless a matching snapshot exchange is
currently active. The final Broker task admission wraps registry admission
with a fresh request/target/policy/revocation check and passes the same
one-shot gate through the root-helper TaskRunner, executor, and transport; the
runner refuses execution when that gate is absent. A separate
non-executing root-helper snapshot package plan now fixes the future
`com.mac-operator.root-helper-snapshot` system plist, native-only artifact,
Developer ID/notarization checks, protected paths, distinct snapshot/Broker/
authority sockets, named Broker identity, and install/rollback/uninstall steps.
The plan now requires and freezes artifact-bound Developer ID/notarization
evidence, and its LaunchDaemon `Program` must equal the proven native
artifact path before an installation plan is accepted. A separate root-only
host executor now implements those fixed lifecycle actions and requires exact
service/process/plist/release readback; it remains unenabled until the host
release and root-domain gates are present.
The root-helper-specific authority IPC channel now binds short-lived HMAC
polls to the snapshot digest, rechecks Broker authority before/during/after
execution, and maps authority loss to `UNKNOWN_OUTCOME`. It does not execute
`launchctl` or enable the public task scope. Evidence:
[`evidence/2026-09-22-root-helper-snapshot-package-plan.md`](evidence/2026-09-22-root-helper-snapshot-package-plan.md).
The production Broker startup seam now explicitly assembles a disabled
descriptor registry, root-helper executor, and TaskRunner without reading
helper keys or querying launchd. An enabled assembly requires independent
capability evidence, protected persisted helper-key activation, host-owned
descriptor keys, exact root LaunchDaemon identity, and a distinct snapshot
socket before native transport construction. Evidence:
[`evidence/2026-09-22-root-helper-task-startup.md`](evidence/2026-09-22-root-helper-task-startup.md).
Startup evidence:
[`evidence/2026-09-22-root-helper-snapshot-service-startup.md`](evidence/2026-09-22-root-helper-snapshot-service-startup.md).
Task-admission evidence:
[`evidence/2026-09-22-root-helper-task-admission.md`](evidence/2026-09-22-root-helper-task-admission.md).
The native helper boundary now also has a separately built, ad-hoc-signed
candidate with a real local Unix/SCM_RIGHTS round-trip probe. A cross-process
probe sends a signed envelope to the native candidate, verifies the HMAC-bound
failure response, confirms forged-proof rejection, and verifies digest-bound
private snapshot materialization and cleanup. The candidate verifies peer
credentials, bounded frame structure, descriptor transfer, and close-on-exec
readback, while its production serve mode remains disabled with
`POLICY_DENIED`. Protected production key loading, root-domain execution,
signed release provenance, LaunchDaemon installation, recovery, and public task
enablement remain open. Evidence:
[`evidence/2026-09-22-root-helper-native-roundtrip.md`](evidence/2026-09-22-root-helper-native-roundtrip.md).
The same native probe now covers an independent authority socket: native peer
and socket identity checks, digest-bound HMAC polls, and fail-closed
`UNKNOWN_OUTCOME` after authority denial. This remains probe-only evidence;
installed Broker polling/cancellation and root-domain lifecycle are not yet
enabled.
Evidence:
[`evidence/2026-09-21-root-helper-snapshot-transport.md`](evidence/2026-09-21-root-helper-snapshot-transport.md).

Exit: independent review and adversarial real-host tests pass; no arbitrary root execution path exists.

## Phase 7 — Production hardening and controlled expansion

Status: `IN_PROGRESS` (release gated)

Complete fuzzing, denial-of-service controls, audit privacy/integrity, credential rotation, crash and upgrade recovery, packaging, signing, observability, backups, rollback, operator runbooks, and release review. Add capabilities only through the same policy, scope, audit, and evidence model.

Exit: P0=0 and P1=0 for affected boundaries, release checklist green, rollback verified.

## Dependency order

```text
Contracts
  -> Local authority boundary
  -> Remote identity boundary
  -> Read-only host capabilities
  -> Isolated developer execution
  -> Controlled writes
  -> App and GUI control
  -> Privileged operations
  -> Broader operator capabilities
```

The 45 contracts use `tool_delivery_wave` (`wave_1` through `wave_5`) for capability sequencing. This is intentionally distinct from the project lifecycle `Phase 0` through `Phase 7` used by this roadmap. The migration and evidence are recorded in `CONFLICTS.md` and `KB_SYNC.md`.

## Priority rule

Authority and credential defects take priority over functional expansion. Then address broken core behavior, secret boundaries, reliability, read-only capabilities, developer operations, GUI control, privileged operations, and convenience features.

## Current blockers and decisions required

- Confirm implementation runtime through ADR-0001; TypeScript/Node is the current candidate.
- Accept identity and Edge-to-Broker IPC through ADR-0002.
- Accept remote authentication through ADR-0003.
- Freeze policy/config and audit persistence through ADR-0004 and ADR-0005.
- Select an enforceable supported macOS child-process sandbox; the current native probe uses deprecated `sandbox_init` only as local evidence and is not a production selection.
- Close scope and approval semantics through `MOP-080` and `MOP-082`.
- Complete input/output schema detail and automated validation for all 45 machine-readable tool contracts; the mandatory audit/postcondition fields and delivery-wave naming are already closed.
- Select remote authentication/tunnel only after the local vertical slice is verified.
- Define packaging/signing before GUI and privileged distribution.

## Related documents

See `EPIC.md`, `TASK.md`, `PROGRESS.md`, `VERIFICATION.md`, and `docs/adr/README.md`.
