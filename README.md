# Mac-Operator-MCP

Mac-Operator-MCP provides a governed MCP Edge and local macOS Broker for operating a physical Mac mini. The Local Broker performs final authorization. Scoped R1/G1 and V2 interfaces preserve the boundaries in `SECURITY.md`; the separately authorized [personal owner terminal profile (O1)](docs/owner-terminal.md) executes arbitrary commands with the owner's permissions.

## Current status

See `PROGRESS.md` for current Git evidence, implementation and enablement state, verification, blockers, and next work.

O1 owner-terminal execution retains its separate explicit owner authority.
The combined O1/V2 source is deployed on the personal Mac mini as of October 2,
2026, with the existing signed policy preserved and V2 tools disabled.
Public OAuth and existing-tool verification passed. V2 acceptance remains PARTIAL (55%);
O1 shell/CLI checks do not establish V2 isolation or coding E2E. See the
[live rollout evidence](evidence/2026-10-02-v2-o1-personal-rollout.md) and
[remaining acceptance gates](docs/MAC_OPERATOR_V2_CHANGE_REPORT.md).

## Start here

- [Goal](GOAL.md)
- [Current progress](PROGRESS.md)
- [Architecture](DESIGN.md)
- [Specification](SPEC.md)
- [Security baseline](SECURITY.md)
- [Threat model](THREAT_MODEL.md)
- [Filesystem policy](FILESYSTEM_POLICY.md)
- [Scope model](SCOPE_MODEL.md)
- [Persistence model](PERSISTENCE_MODEL.md)
- [Tool catalog](TOOL_CATALOG.md)
- [Tool contract standard](TOOL_CONTRACT_STANDARD.md)
- [Machine-readable tool contracts](tool-contracts/README.md)
- [Versioned ledger record contracts](schemas/ledger-records.schema.json)
- [Epics](EPIC.md)
- [Roadmap](ROADMAP.md)
- [Task ledger](TASK.md)
- [Verification matrix](VERIFICATION.md)
- [SSOT conflict register](CONFLICTS.md)
- [KB-MCP synchronization](KB_SYNC.md)
- [Architecture decisions](docs/adr/README.md)

## Delivery and operations

- [Testing](TESTING.md)
- [Configuration](CONFIGURATION.md)
- [Deployment](DEPLOYMENT.md)
- [Owner OAuth login and local setup](docs/oauth-login-operations.md)
- [Running personal deployment](docs/personal-deployment.md)
- [Browser Computer Use (G1)](docs/gui-computer-use.md)
- [V2 development gateway design and threat model](docs/MAC_OPERATOR_V2_DESIGN.md)
- [V2 development gateway operator runbook](docs/MAC_OPERATOR_V2_RUNBOOK.md)
- [Personal owner terminal (O1)](docs/owner-terminal.md)
- [macOS packaging boundary](packaging/macos/README.md)
- [Operations](OPERATIONS.md)
- [Kill switch](KILL_SWITCH.md)
- [Incident response](INCIDENT_RESPONSE.md)
- [Rollback](ROLLBACK.md)
- [Persistence cutover and migration runbook](PERSISTENCE_CUTOVER.md)
- [Audit archive runbook](AUDIT_ARCHIVE_RUNBOOK.md)
- [Request/Job ledger archive runbook](LEDGER_ARCHIVE_RUNBOOK.md)

The source-level operator control entrypoint is built with `npm run build` and
invoked as `node packages/broker/dist/authority-control-cli.js --help`. It
only reads or changes bounded kill-switch/revocation state through the
authenticated owner-only IPC; it does not install services, expose keys, run
commands, or grant capabilities.

The optional stable operator proxy is built as
`packages/broker/dist/authority-control-service.js`. It is launched only by a
reviewed owner-domain LaunchAgent plan, accepts owner-only CLI traffic on a
separate socket, and forwards authenticated authority commands to the Broker;
it is not installed or enabled by default.

## V2 Safe AI Development Gateway

V2 adds 11 project-scoped contracts for managed Git worktrees, coding-agent
preflight and job admission, registered test/build execution, worktree-based
branch creation, review preparation, and bounded audit retrieval. It reuses the
existing Edge authorization, Local Broker policies, operation approvals, Git
safety controls, and durable job ledger. Protocol version remains `0.1`; existing
R1 and G1 contracts and grants remain compatible.

All 11 new tools are disabled by default. Enabling a policy entry alone cannot
provision the gateway or an execution boundary. Host-owned startup assembly must
provide `DevelopmentGateway`, protected `ManagedWorktrees` storage, and any
approved command registrations. Test/build commands resolve through an existing
`TaskProfileRegistry`; execution requires a production-enabled isolated
`TaskRunner` with accepted process ownership evidence. No production coding
adapter ships in this change, and `mac_git_push` always denies execution.

This is an additive implementation, not a claim that production Codex execution
or the YAP-MCP development E2E has passed. Coding enablement still requires a
verified credential-free agent runtime, enforced execution profiles, and an
explicit inference network route. No live policy, OAuth grant, or service must be
changed merely to try this source-level integration. Follow the
[V2 operator runbook](docs/MAC_OPERATOR_V2_RUNBOOK.md) for staged provisioning,
approval, job recovery, and worktree reconciliation.

## Source-of-truth rules

- Repository code and exact-revision evidence determine implementation truth.
- `PROGRESS.md` owns dynamic Git, implementation, verification, blocker, and next-step status.
- Durable architecture and requirements belong in their named documents.
- KBID `mac-operator-mcp` is the upstream design SSOT for materialized KB artifacts until a reviewed synchronization rule replaces it.
- A documented contract is not an implemented or enabled capability.

## Development

The Edge/Broker baseline uses TypeScript on Node.js 24 or newer with npm workspaces. The optional owner OAuth service requires Node.js 24.7 or newer for native Argon2id. Production tools remain disabled by default.

```sh
npm install
npm run lint
npm run typecheck
npm run verify:docs
npm run verify:completion
npm test
npm run verify:contracts
```

`npm run verify:completion` is a read-only, fail-closed acceptance audit. It
reports the current evidence set and physical-host release/GUI/lifecycle
readiness; a non-zero result means production completion is not proven.

The deployment handoff can be compiled without changing host state with
`npm run plan:macos:launchagents -- --manifest <absolute-path>`. It validates
the owner-only manifest and emits the Edge/Broker LaunchAgent plan, exact plist
hashes, launchd argv, and preflight data. It intentionally has no `--apply`
mode and never calls `launchctl`; use `--development-probe` only for explicit
ad-hoc staging plans.

The root-helper handoff has the same read-only boundary through
`npm run plan:root-helper -- --manifest <absolute-path>`. It validates the
owner-only root-helper manifest and emits the native LaunchDaemon, release,
rollback, protected-path, and four-socket plan with
`apply.available: false`; it never loads key material or changes host state.
The separate host-only apply handoff is
`npm run apply:root-helper -- --manifest <absolute-path> --confirm install`
(use `upgrade`, `rollback`, or `uninstall` for those exact operations); it
requires root, exact operation confirmation, authenticated root-helper
status readback, and fixed rollback behavior. It is never an MCP handler.

The repository also has an owner-managed R1 personal deployment at the public
MCP endpoint. Its service/API read-only boundary is verified, and a separate
owner-approved ChatGPT R1 app is connected with 17 scopes and 30 discovered
read-only tools; an older app still retains its historical three-tool R0 grant.
See `PROGRESS.md` and the verification matrix before treating any capability as
released beyond that personal snapshot.
