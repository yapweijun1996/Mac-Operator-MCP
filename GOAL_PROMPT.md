# Goal Prompt

Design and implement Mac-Operator-MCP: a governed MCP service and macOS broker for AI clients operating a physical Mac mini. The AI selects tools; the host authenticates the request, authorizes its capability and target, executes within limits, verifies results, and records redacted evidence.

Use: HTTPS MCP Edge -> authenticated local IPC -> unprivileged Local Broker -> adapters and Broker-owned jobs. Put privileged actions behind a separately authenticated allowlisted helper. The Broker is final authority; tool arguments cannot grant permission. Reject replayed requests.

Keep read, write, process, network, GUI, destructive, and privileged scopes independent. Fail closed. Protect credentials, signing keys, and secret zones. Resist traversal, symlink, and target-swap escapes. Treat repository scripts as untrusted. Child processes require explicit cwd, minimal environment, filesystem/network limits, timeout, output cap, cancellation, and credential-isolation proof.

Every tool needs a versioned contract, stable errors, scopes, target type, budgets, secret policy, verification, audit class, and separate planned/implemented/enabled states. Mutations require audit intent, preconditions, idempotency, status lookup, recovery, and postcondition checks. Define revocation and kill-switch behavior for new, queued, and active work.

Deliver in phases: contracts and threat model; local Broker; remote Edge; L0/L1 inspection; isolated L2 tasks and writes; L3/L4 app control; L5 helper; hardening. Exclude unrestricted shell/root commands, raw automation, arbitrary Docker access, credential UI access, Git push, force reset, and destructive disk operations.

Treat repository code as implementation truth. Distinguish decisions, proposals, implementation, enablement, tests, and host evidence. A capability is complete only after code, tests, boundary checks, applicable real-Mac evidence, documentation, rollback, and final readback pass with no unresolved P0/P1 finding.
