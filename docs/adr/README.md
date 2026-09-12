# Architecture Decision Records

ADRs capture decisions that materially affect authority, compatibility, data ownership, deployment, or operations. `Accepted` records are binding until superseded. `Proposed` records document the decision to be made and cannot be treated as implemented behavior.

| ADR | Topic | Status |
|---|---|---|
| [ADR-0001](0001-runtime.md) | Runtime and package structure | Accepted for Edge/Broker baseline |
| [ADR-0002](0002-identity-ipc.md) | Principal identity and Edge-to-Broker IPC | Proposed |
| [ADR-0003](0003-remote-auth.md) | Remote authentication and transport | Proposed |
| [ADR-0004](0004-policy-config.md) | Policy and configuration format | Proposed |
| [ADR-0005](0005-audit-persistence.md) | Audit and operational persistence | Proposed |
| [ADR-0006](0006-sandbox.md) | Child-process sandbox | Proposed |
| [ADR-0007](0007-packaging.md) | macOS packaging and signing | Proposed |
| [ADR-0008](0008-approval-model.md) | Approval model | Proposed |

Each accepted ADR must record evidence, affected tasks, migration or compatibility impact, failure and rollback behavior, and superseded decisions.
