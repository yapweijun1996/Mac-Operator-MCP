# Mac-Operator-MCP

Mac-Operator-MCP is a planned governed MCP Edge and local macOS Broker for operating a physical Mac mini with high capability and bounded authority. The Local Broker performs final authorization; secret content, unrestricted shell, unrestricted root, and the interfaces excluded by `SECURITY.md` remain unavailable.

## Current status

See `PROGRESS.md` for current Git evidence, implementation and enablement state, verification, blockers, and next work.

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
- [macOS packaging boundary](packaging/macos/README.md)
- [Operations](OPERATIONS.md)
- [Kill switch](KILL_SWITCH.md)
- [Incident response](INCIDENT_RESPONSE.md)
- [Rollback](ROLLBACK.md)
- [Persistence cutover and migration runbook](PERSISTENCE_CUTOVER.md)

The source-level operator control entrypoint is built with `npm run build` and
invoked as `node packages/broker/dist/authority-control-cli.js --help`. It
only reads or changes bounded kill-switch/revocation state through the
authenticated owner-only IPC; it does not install services, expose keys, run
commands, or grant capabilities.

## Source-of-truth rules

- Repository code and exact-revision evidence determine implementation truth.
- `PROGRESS.md` owns dynamic Git, implementation, verification, blocker, and next-step status.
- Durable architecture and requirements belong in their named documents.
- KBID `mac-operator-mcp` is the upstream design SSOT for materialized KB artifacts until a reviewed synchronization rule replaces it.
- A documented contract is not an implemented or enabled capability.

## Development

The Edge/Broker baseline uses TypeScript on Node.js 24 or newer with npm workspaces. Production tools remain disabled by default.

```sh
npm install
npm run lint
npm run typecheck
npm run verify:docs
npm test
npm run verify:contracts
```

The current code is an authenticated MCP Edge and local Broker foundation, not an installed or remotely reachable deployment. See `PROGRESS.md` and the verification matrix before treating any capability as released.
