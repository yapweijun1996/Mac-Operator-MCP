# Mac-Operator-MCP Design

Status: Draft architecture; no runtime implementation exists
Version: 0.1
Last verified: 2026-09-12

## Source-of-truth statement

Current repository evidence is authoritative for implementation status. At commit `8f8d6b5`, the repository contains only `.gitattributes`. The architecture below records approved direction and design proposals; it does not describe running software.

## System context

```text
ChatGPT / AI Client
        |
        | authenticated HTTPS MCP
        v
Remote MCP Edge
        |
        | authenticated, replay-resistant local IPC
        v
Mac Local Broker -----> Audit Store
        |
        +-----> Capability Adapters -----> macOS resources and apps
        |
        +-----> Job Manager ------------> bounded child processes
        |
        +-----> Privileged Helper ------> allowlisted system operations
```

The AI interprets intent and chooses a structured tool. The host resolves identity, policy, target, and execution constraints. Credentials and host authority do not transit through model-editable tool arguments.

## Component ownership

### Remote MCP Edge

Owns MCP protocol handling, remote authentication, client/session rate limits, tool discovery, request IDs, transport-level validation, and projection of trusted principal claims. It cannot grant host authority by itself and should hold no unrestricted host credentials.

### Mac Local Broker

Owns final authorization, capability enablement, normalized target resolution, policy evaluation, request lifecycle, execution budgets, kill switches, adapter dispatch, result verification, redaction, and audit coordination. It binds to loopback or a protected Unix-domain socket and is never exposed directly to the public network.

### Policy Engine

Runs inside the Broker boundary. Its inputs are trusted principal context, requested tool, normalized target, current policy version, capability switches, and execution constraints. Its output is a stable allow or deny decision with a reason code and effective constraints. Deny rules take precedence.

### Capability Adapters

Implement system, filesystem, project/Git, Docker, service, application, Accessibility, and native automation operations. Adapters consume an already authorized execution plan and cannot broaden scopes or invent authorization rules.

### Job Manager

Owns broker-created child processes, state transitions, bounded logs, cancellation, expiry, and result retrieval. A named task profile limits command, arguments, working directory, environment, filesystem, network, duration, and output. Repository scripts are treated as executable code, not trusted merely because a profile invoked them.

### Privileged Helper

Runs behind a separate local authentication boundary. It accepts only versioned operation schemas and allowlisted actions. It independently validates its caller, operation, preconditions, and policy version. It never accepts arbitrary command strings.

### Audit Store

Stores append-oriented intent, decision, execution, and verification events. Records contain principal reference, request ID, tool, normalized target reference, policy version, timestamps, result class, duration, and bounded redacted evidence. Secret contents and credentials are excluded.

## Authority model

Authorization requires all of the following:

```text
valid principal
AND valid non-replayed request
AND enabled tool
AND required scopes
AND allowed normalized target
AND satisfied execution constraints
AND enabled capability switch
AND valid current policy
```

Capability levels L0-L5 are planning and discovery labels. They are not an inheritance hierarchy. For example, developer execution does not imply network access, secret reads, GUI access, or privileged access.

## Request lifecycle

1. Edge authenticates the caller and derives immutable principal context.
2. Edge validates the tool envelope, assigns a request ID and nonce, and forwards a signed request over local IPC.
3. Broker validates IPC identity, signature, timestamp, nonce, request binding, and current revocation state.
4. Broker normalizes paths, PIDs, repository roots, app identities, service identities, and Docker object identities.
5. Policy Engine returns a decision and effective execution plan.
6. For mutations and privileged work, the Broker persists an audit intent before dispatch.
7. Adapter or Job Manager executes with explicit limits.
8. Broker verifies meaningful postconditions and classifies the result.
9. Broker redacts output, persists completion evidence, and returns the stable result envelope.

If durable audit intent cannot be recorded, mutating and privileged operations fail before execution. Read-only behavior under audit-store failure remains an explicit deployment policy decision.

## Identity and IPC design

The principal must be derived from validated transport credentials and cannot be supplied in tool arguments. The Edge-to-Broker message must bind the principal, session, tool, canonical argument digest, timestamp, nonce, policy audience, and request ID. The Broker tracks a bounded replay window and checks revocation at admission and again immediately before mutation.

Exact remote authentication, IPC credential mechanism, and tunnel provider remain open decisions. The first implementation must support local integration tests without requiring a public deployment.

## Filesystem design

Policy uses canonical allow roots and deny roots, with deny winning. It rejects traversal, invalid encodings, unsupported file types, device nodes, secret zones, and symlink escapes. Authorization must remain bound to the opened filesystem object so a target cannot be swapped after a path check. Writes require an expected state such as content hash or file version, use an atomic replacement where suitable, and report a recoverable final state.

Secret deny zones initially include Keychain-related data, SSH private material, browser credential databases, cloud credentials, API tokens, signing keys, package credentials, shell history where sensitive, and configured project secret patterns. Detection must avoid returning the matching secret bytes.

## Child-process design

Named task profiles are the initial execution model. Each profile fixes the executable or resolver, allowed arguments, cwd rules, environment allowlist, filesystem access, network policy, timeout, output cap, child-process limits, and cancellation behavior. The implementation must prove that task code cannot read Broker or Edge credentials. A generic command runner is deferred until an enforceable sandbox exists and a separate review approves it.

## Mutation and idempotency design

Mutations carry an idempotency key, normalized target, expected precondition, and requested end state. Repeating a completed request returns its recorded result. A conflicting payload under the same key fails. If execution outcome is uncertain, the request enters `UNKNOWN` until reconciliation determines the actual target state. Clients can query status rather than retrying blindly.

## Job state model

```text
QUEUED -> RUNNING -> SUCCEEDED
                  -> FAILED
                  -> TIMED_OUT
                  -> CANCELLED
                  -> UNKNOWN
```

Revocation and kill switches reject new work, cancel queued work, and request termination of active cancellable work. The operation contract declares whether interruption is supported and how post-termination verification determines final state.

## Application and GUI design

Control preference is native API, AppleScript/JXA/Shortcuts adapter, Accessibility tree, then visual coordinates as an exceptional future capability. Authorization is bound to application identity, window or element identity, action family, and freshness token. Sensitive dialogs, password prompts, security settings, credential surfaces, and unapproved applications are denied at observation and action time.

## Privileged design

Initial candidates are approved service control, approved package installation, and reboot or shutdown. Each operation has a strict schema, caller policy, preconditions, postconditions, timeout, audit class, and emergency disable. Privileged work cannot begin until Edge/Broker identity, L0/L1 policy, replay defense, secret isolation, and kill-switch behavior have passed real-host tests.

## Configuration and state ownership

- Edge configuration: remote auth, MCP exposure, rate limits, Broker endpoint.
- Broker configuration: capability switches, policy version, adapter registry, budgets, audit behavior.
- Policy data: scopes, target allowlists/denylists, task profiles, app/service identities.
- Runtime state: replay window, request ledger, jobs, idempotency results, revocations.
- Secrets: host secret store, referenced by runtime components and never copied into policy files, tool arguments, results, or audit records.

Configuration changes that alter authority are versioned, validated, audited, and applied atomically. Unknown or invalid configuration prevents affected capabilities from starting.

## Failure and recovery

- Edge unavailable: no remote requests; Broker remains private.
- Broker unavailable or locked: host execution is unavailable.
- Adapter failure: bounded `EXECUTION_FAILED` response and audit completion event.
- Verification failure: `VERIFICATION_FAILED`; never report success.
- Audit failure: mutations and privileged operations stop before execution.
- Process timeout: terminate the process tree, collect bounded evidence, and verify final state.
- Restart: reconcile requests left in `RUNNING` and mark them with verified terminal state or `UNKNOWN`.

## Deployment sequence

1. Local in-process contract tests.
2. Edge and Broker as separate unprivileged local processes over protected IPC.
3. Real-Mac L0/L1 vertical-slice tests.
4. Authenticated remote Edge connection.
5. L2 named task profiles after child credential-isolation evidence.
6. L3/L4 after macOS permission and sensitive-target tests.
7. L5 helper after independent authority-boundary review.

## Decided and open items

Decided: Broker final authority; separate Edge and Broker; structured tools; deny-first policy; secret deny zones; bounded execution; redacted audit; kill switches; separate privileged helper; no unrestricted shell.

Open: TypeScript/Node runtime confirmation; transport and remote authentication provider; IPC authentication primitive; sandbox implementation; policy file format; audit storage backend; macOS packaging/signing; initial allow/deny roots; read-only behavior during audit failure; generic process execution eligibility.
