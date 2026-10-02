# Mac Operator V2 — Safe AI Development Gateway

## Production execution architecture (2026-10-02)

The current Mac mini has a native-authenticated Docker Desktop Linux Engine
with cgroup v2. A disposable task container is the least disruptive complete
execution boundary. It adds an explicit `docker-container` mechanism; no
existing staging runner, host executable digest or VM proof is relabelled.

The Broker controls a fixed Unix socket and approved image digest. It creates
one container per job, with readonly rootfs, nonroot UIDs, dropped capabilities,
no-new-privileges, default seccomp, private PID/IPC/cgroup namespaces, resource
limits, no host mounts, no Docker socket and no task network. A trusted deadline
process runs as UID 65533; untrusted commands run as UID 65532 and cannot stop
that timer. Exact Engine/container/image/nonce/job ownership is durable before
start. Completion requires stopped/removed identity readback; restart cleanup
never replays an uncertain task or promotes it to success.

An authorized worktree is represented by a bounded secret-filtered regular-file
snapshot at `/workspace`. Git metadata and credential paths never enter it.
Operator-owned source exclusions prevent copying persistent project data or
generated assets. Readonly snapshots use root-owned readonly files; workspace-write snapshots
belong to the task user. Docker archive APIs do not expose runtime tmpfs safely. Fixed staging and
quiescent guest export programs carry bounded source chunks; the host constructs
and parses a strict USTAR archive without host extraction;
links, special files, traversal, metadata and secrets are rejected. All changed
paths and original hashes are checked before canonical native atomic writes
back to that same managed worktree. The primary repository is never mounted.

Codex is a trusted inference controller with its own private sanitized home and
an opaque reference consumed only by its existing authentication manager. The
gateway does not read or return credential values. Built-in host execution,
patching, MCP servers, hooks, browser and agent tools are disabled; only explicit
Broker dynamic tools operate the task container. This separates inference from
code execution. The controller's private cwd differs from the original
single-process proposal; actual coding commands use `/workspace`, mapped to
one owned worktree, and all host writes require verified import. This preserves
project isolation while keeping authentication outside untrusted code.

The container shares the Docker Desktop guest kernel, so kernel/Engine flaws
remain trusted-platform risks. The Docker daemon is a privileged control-plane
dependency and is never exposed to agent code or MCP arguments. Host operators
may provision a pinned public runtime image; coding approval cannot install
packages, select an arbitrary image/daemon, grant network or authorize push.

Rollout preserves previously explicit O1 grants while ordinary new V2 consent
excludes terminal authority. It adds explicit V2 scopes
and narrow project rules only after physical acceptance, and excludes gateway
provenance/all-task storage from ordinary filesystem access. Existing grants
retain their original scopes. Signed-policy/state backups and immutable source
releases remain the rollback mechanism.

## Audit baseline (completed before implementation)

Source baseline: `0be86f5`, wire/protocol version `0.1`, application `0.1.0`.
Physical host: macOS arm64 Mac mini. Live `mac_health` reported healthy;
`mac_capabilities` reported `mac_task_run` disabled by policy. Codex CLI
`0.153.4` and Docker Engine `29.1.3` are installed. Installation is not isolation
or authentication evidence. This October 1 audit/implementation changed no
live policy or service. The October 2 authorized source rollout preserves the
existing O1 signed policy and leaves V2 tools disabled; see the
[deployment record](../evidence/2026-10-02-v2-o1-personal-rollout.md).

### R1 audit architecture and ownership

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
| Prompt injection / hostile project scripts | Fixed profiles; outer isolation gate; no host command input | Profile/security tests and actual cgroup/UID/deadline validation |
| Traversal, symlink or `.git` pointer escape | Canonical roots, pinned identities, inventory-bound metadata | Filesystem regressions and worktree hostile fixtures |
| Credential exfiltration | Hard-deny zones; credential-free execution; bounded redaction | Secret corpus, actual filtered snapshot and constrained inference controller |
| Arbitrary Git hooks/filters | Pinned config, hooks disabled, transports/lazy fetch disabled | Actual configured hooks and partial-clone helper fixtures |
| Idempotency replay / cross-owner access | Owner+payload+policy binding and managed inventory | Duplicate/conflict tests |
| Cancellation, timeout or restart lies | Existing leases/revisions; UNKNOWN after uncertain interruption | Job regressions plus actual Broker SIGKILL/deadline/recovery |
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

## Historical implementation state (2026-10-01)

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
writes and patches reject `.git` metadata. Provenance and all-task storage
are denied by ordinary filesystem roots, including explicit exclusions on
broad ancestor roots. Native conditional inode deletion
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
[the change report](MAC_OPERATOR_V2_CHANGE_REPORT.md). The October 1 validation is historical source-only evidence. Current production
acceptance is recorded in [production evidence](../evidence/2026-10-02-v2-production-gateway.md).

## Historical live-deployment distinction (before production executor)

A separate owner-terminal branch deployed O1 later on 2026-10-01. Live capability
readback now exposes its implemented owner-terminal contract (not granted to
this caller), keeps `mac_task_run` policy-disabled, and contains no V2 entries.
This does not repair production task isolation or establish Codex/YAP E2E.
Treat owner-shell access as separate HIGH_RISK authority, never an AGENT_RUN
fallback. See the [verified rollout distinction](MAC_OPERATOR_V2_CHANGE_REPORT.md)
for source references and the unchanged V2 acceptance limits.

## Current execution and residual risks

The production adapter reuses Broker policy/approval/jobs, ManagedWorktrees and
canonical native writes. Container identity is persisted in schema 20 before
start; detached descendants are contained by the cgroup and an independent
UID65533 deadline. Export fences exec admission, kills UID65532 descendants,
checks /proc quiescence and pins file inode, nanosecond times and hashes. Every
host mutation gets durable intent and verified-path audit events, including a
partial import that later fails. Revocation/cancellation never reports success;
confirmed cleanup settles cancelled, unverified cleanup remains UNKNOWN.

Docker Desktop/guest kernel, the pinned public image and native Codex binary
remain trusted dependencies. A malicious same-UID host operator is outside this
remote-agent threat model. Secret signature filtering is conservative and
cannot identify every unknown credential format; do not commit credentials to
source, and exclude project data/config requiring special trust. No task receives
host credentials, mounts, socket, sudo, network or unrestricted argv. Inference
network is restricted to the trusted provider manager, outside task code.

Readonly/test-only profiles cannot write source. Tests/build may write ephemeral
container artifacts; their output files are not imported automatically. Source
deletion and dirty worktree force-removal are unsupported and fail closed.
Imports validate the full delta before writing but are not a multi-file
transaction; individually verified partial writes remain visible and audited.
The current YAP image/registry validates its Node isolation test and site build;
other languages/projects require separately reviewed profiles and runtime images.

## Independent owner terminal client compatibility audit

On October 2, the native Codex OAuth manager had an authenticated independent
`/terminal/mcp` registration, but startup failed: its initialize request used
`2025-06-18`, while Edge explicitly rejected all legacy protocols. Previous live
probes used the SDK's pinned `2026-07-28` client and did not cover this consumer.
OAuth credentials and owner consent were valid; transport negotiation was the
blocking contract. No change to the V2 execution boundary is needed.

The existing SDK provides a stateless legacy handler using the same governed
server factory. Reuse it only for the independent owner terminal resource with
its exact issuer and O1 scopes. Accept exactly `2025-06-18` in addition to the
existing modern protocol. Require the negotiated protocol header on subsequent
legacy requests; reject batches, unknown versions and header/body conflicts
before invoking Broker. The primary V2 endpoint continues to reject legacy.

Both protocol paths retain bearer verification, issuer/audience binding, scope
projection, Broker authorization, grant revocation, rate/body/Host/Origin
limits, bounded output and managed jobs. No credentials are forwarded or
rewritten. Stateless operation adds no session authority or persisted state.
The residual risk is the SDK's legacy parsing/SSE implementation, covered by
transport and cross-resource authorization regressions plus a real saved-OAuth
Codex execution. Roll out as an immutable release with stopped-state backup;
rollback restores the previous release and complete protected state.

Git hooks remain configured in user repositories but every adapter forces
`core.hooksPath=/dev/null` and pins repository configuration identity. Filters,
external integration and unsafe Git metadata remain denied. The offline
migration requires a full stopped-state rollback snapshot; an interrupted
cross-file migration cannot be automatically resumed.
