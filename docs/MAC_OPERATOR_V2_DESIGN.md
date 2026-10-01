# Mac Operator V2 — Safe AI Development Gateway

## Audit baseline (completed before implementation)

Source baseline: `0be86f5`, wire/protocol version `0.1`, application `0.1.0`.
Physical host: macOS arm64 Mac mini. Live `mac_health` reported healthy;
`mac_capabilities` reported `mac_task_run` disabled by policy. Codex CLI
`0.153.4` and Docker Engine `29.1.3` are installed. Installation is not isolation
or authentication evidence. This V2 task changed no live policy or service.
The later independent O1 rollout is distinguished in the change report.

### Current architecture and ownership

Authenticated HTTPS MCP requests enter Edge, which validates the immutable
contract registry and projects OAuth authority over authenticated local IPC.
Local Broker independently validates request authentication, replay, principal,
scopes, signed policy, normalized targets, kill switches and operation approval.
Broker owns adapters, path authorization and durable SQLite request/job/audit
ledgers. Edge cannot supply commands, environment, or execution authority.

Relevant sources: `packages/edge/src/mcp-server.ts`,
`packages/broker/src/broker.ts`, `policy.ts`, `policy-loader.ts`,
`filesystem-inspector.ts`, `git-inspector.ts`, `persistence.ts`,
`task-profile.ts`, `task-runner.ts`, `service-startup.ts`.

### Reusable components

- Canonical, descriptor-pinned filesystem plans, secret/content denial and
  bounded workers; atomic write/patch and postcondition verification.
- Fixed `/usr/bin/git`, empty ambient environment, blocked executable Git
  config, disabled hooks/GPG, literal explicit stage paths and commit digest
  preconditions. Ordinary repositories require directory `.git` metadata.
- Named `TaskProfileRegistry`: pinned executable hash, fixed args, approved
  cwd/filesystem roots, credential-free environment, bounded runtime/output,
  explicit network policy. `mac_task_run` is not an arbitrary-shell API.
- BrokerStore atomic approval/intent admission, owner-bound jobs, revisions,
  leases, cancellation, output redaction, tamper-evident audit and conservative
  restart reconciliation. Queued tasks cancel; interrupted running jobs become
  UNKNOWN and are never automatically replayed.
- SandboxExec, App Sandbox and Virtualization adapters and hostile tests.
  These are candidates, not accepted production execution boundaries.

### Missing components and verified conflicts

1. Linked worktree `.git` files are rejected by all existing Git inspectors.
   Add a provenance-checked resolver only for Broker-created worktrees.
2. `async:true` is accepted by the contract but rejected by the task validator.
   Existing task requests await completion and use request ID as retry identity.
3. No managed worktree inventory, Codex admission/preflight, named test/build
   convenience tools, review preparation, or bounded execution audit MCP API.
4. Exact project target authorization does not inherit to worktrees. Managed
   worktrees must retain original project and principal/task ownership.
5. Credential path rules need explicit Codex/Claude/Firefox/MCP state coverage.
6. Current task profiles grant read/write together; a prompt or Codex sandbox
   flag cannot prove readonly/test-only enforcement at the outer boundary.

### Why task execution is disabled

Default Broker uses `FailClosedTaskRunner`; personal R1/W1/G1 exclude task
execution. Production startup requires a production runner release. Existing
runner candidates are staging-only. SandboxExec proves a no-fork single-process
boundary, unsuitable for ordinary Codex/npm process trees. App Sandbox hostile
double-fork/setsid evidence found escape; quarantine prevents later executions
but does not repair containment. Virtualization requires a boot image,
entitlement, authenticated guest and host acceptance evidence not present in
this deployment. Task credentials are explicitly `none`; existing network
allowlists accept only precise loopback destinations. Mounting `~/.codex` or
injecting a user token would violate this task's credential boundary.

## Proposed additive architecture

ChatGPT → unchanged Edge/authenticated IPC → unchanged Broker authorization →
managed project worktree → governed coding/task adapter → existing managed
job ledger → bounded validation evidence → existing Git review/stage/commit.

Broker owns a protected worktree inventory with canonical root, directory and
Git metadata identities, original project, principal, task ID and request
fingerprint. Inventory is separate worktree provenance state, not a second job
queue. Creation never switches the primary checkout or overwrites a target.
Deletion requires ownership and clean status, blocks the primary checkout and
active jobs, and verifies removal. Dirty deletion remains denied; an MCP
boolean must not be treated as a separate destructive approval.

V2 contracts are additive; wire version stays `0.1`. Execution uses the existing
task profiles, isolation proof, approval, jobs and recovery machinery. Test and
build names resolve only to operator-registered profiles. Manifest commands
are observations until explicitly registered; untrusted manifests are code,
not authorization. Push has a concrete denied contract and remains unavailable
even if ordinary coding authority is approved. PR preparation never publishes.

Codex preflight is read-only. It reports runtime and authentication readiness
from a trusted adapter without reading or returning user credential contents.
An absent accepted adapter reports unknown/not-ready and denies execution
before approval is consumed. No fallback to host `spawn`, shell, sudo, Docker
socket access, or merely setting the CLI cwd is permitted. Existing sandbox
proof gates are retained. A complete live coding E2E requires a separately
verified credential-free agent runtime with enforced read/write profiles,
owned descendants and an explicit inference network route.

## Threat model

| Threat | Control | Evidence/remaining dependency |
| --- | --- | --- |
| Prompt injection / hostile project scripts | Fixed profiles; outer isolation gate; no host command input | Profile/security tests; production multi-process isolation pending |
| Traversal, symlink or `.git` pointer escape | Canonical roots, pinned identities, inventory-bound metadata | Filesystem regressions and worktree hostile fixtures |
| Credential exfiltration | Hard-deny zones; credential-free execution; bounded redaction | Secret corpus; accepted inference proxy pending |
| Arbitrary Git hooks/filters | Existing config validation and fixed disabled integrations | Git regression tests |
| Idempotency replay / cross-owner access | Owner+payload+policy binding and managed inventory | Duplicate/conflict tests |
| Cancellation, timeout or restart lies | Existing leases/revisions; UNKNOWN after uncertain interruption | Job regressions; no auto-replay |
| Agent edits primary checkout | Worktree provenance; mandatory isolated execution | Primary HEAD/index/content checks |
| Implicit push / destructive mutation | Separate high-risk scope; implementation fails closed | Default push denial tests |
| Audit leakage / audit failure | No prompts/file contents in audit; redacted bounded evidence; fail closed | Audit regression tests |

## Permission matrix

| Tier | Operations | Requirements |
| --- | --- | --- |
| READ | Existing reads, worktree list, Codex preflight, PR preparation, audit | Existing caller scope and exact project/owner authority |
| SAFE_WRITE | Source patch, atomic write, explicit stage, local commit, worktree create | Project/path scope, operation approval, idempotency and audit |
| AGENT_RUN | Codex, registered tests/builds/tasks | Managed worktree, explicit profile/network, accepted outer runtime, timeout, job lifecycle |
| HIGH_RISK | Push, install, service/system mutation | Default deny; separate scope and separate supported approval workflow |

## Migration, rollout and rollback

Do not modify running G1 policy, OAuth grants, private keys or services during
source implementation. New tools default disabled. Configure protected worktree
storage and explicit project grants at Broker assembly, then enable READ and
SAFE_WRITE tools in a reviewed signed policy. Enable AGENT_RUN only after the
selected runtime passes physical-host isolation and credential/network tests;
never promote staging evidence by configuration alone. Existing R1 contracts
and grants remain valid. Rollback disables V2 tools first, cancels/drains jobs,
retains dirty worktrees and provenance, then restores the previous service
revision. There is no destructive worktree cleanup during rollback.

## Acceptance and evidence rules

Run focused contract/policy, real Git worktree, secret, job lifecycle and
compatibility tests, then the existing regression suite. Record mock adapter
coverage separately from physical OS isolation. Discover YAP-MCP through the
authorized project surface; use only a synthetic task in its isolated checkout.
No production source edits or push. Compare primary HEAD, index and status
before/after. An unavailable YAP project scope or accepted agent runtime is an
external acceptance dependency, not a passing E2E. Final status must remain
PARTIAL until every Definition of Done item has real evidence.

## Implemented source state (2026-10-01)

The additive modules are `managed-worktrees.ts`, `development-gateway.ts` and
`development-policy.ts`. Existing Broker, Git inspectors, TaskProfileRegistry
and BrokerStore perform authorization, dispatch and job control. The 11 new
contracts remain disabled by default. `mac_task_run` preserves its synchronous
named-profile API and adds strict opt-in asynchronous admission, task/retry IDs
and a narrower runtime. Its operator-registered legacy profiles are preserved;
V2 Codex/test/build tools require managed worktrees.

Managed Git authority now validates canonical metadata, configuration content
identity, reciprocal worktree pointers, the approved task HEAD and exclusive
branch ownership. It rejects metadata symlinks/hardlinks, primary commondir,
external object alternates and worktree-specific configuration. Ordinary source
writes and patches reject `.git` metadata. Provenance and the all-task storage
root cannot overlap ordinary filesystem roots. Native conditional inode deletion
releases stale/dead inventory locks without deleting a replacement; repeated
close cannot release a new instance's lock.

Same-worktree active/unknown jobs prevent another task admission and premature
Git mutation; distinct worktrees can run independently. Removal conservatively
pins the whole original project while related jobs remain unresolved. Audit
records retain the actual scopes, task/worktree identity, bounded changed paths
and commit IDs where observed. Historical rows without recorded scopes report
an empty scope list instead of inventing current authority.

The final evidence and exact acceptance limits are in
[the validation record](../evidence/2026-10-01-v2-gateway-validation.md) and
[the change report](MAC_OPERATOR_V2_CHANGE_REPORT.md). A real production coding
adapter and YAP-MCP E2E remain pending; this is a partial delivery, not a release.

## Later live-deployment distinction

A separate owner-terminal branch deployed O1 later on 2026-10-01. Live capability
readback now exposes its implemented owner-terminal contract (not granted to
this caller), keeps `mac_task_run` policy-disabled, and contains no V2 entries.
This does not repair production task isolation or establish Codex/YAP E2E.
Treat owner-shell access as separate HIGH_RISK authority, never an AGENT_RUN
fallback. See the [verified rollout distinction](MAC_OPERATOR_V2_CHANGE_REPORT.md)
for source references and the unchanged V2 acceptance limits.
