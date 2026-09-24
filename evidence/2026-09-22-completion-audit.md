# Mac-Operator-MCP Completion Audit

Status: `PARTIAL` — the repository and staging boundaries are substantially
implemented, but the physical-host release and capability enablement gates are
not closed.

Date: 2026-09-22

This audit checks the owner-only governed-MCP objective against current source,
tests, host probes, and release evidence. It is an acceptance audit, not a
claim that a planned capability is available remotely.

## Evidence baseline

- Full repository regression: 1,151 tests; 1,136 passed, 15 skipped, 0 failed.
- The L5 Broker dispatch integration invokes the actual composed package and
  power adapters through approval, Job lease, signed command issuance, the
  authenticated helper socket with HMAC response verification and durable
  replay guard, fixed command-runner seams, and postcondition mapping; focused
  adapter, composition, dispatch, and recovery coverage passes 29/29. The
  fixed installer/shutdown argv and package/power readback contracts are
  asserted, including unresolved-outcome, Job-cancellation, and
  authority-revocation recovery, plus independently authenticated Job-bound
  helper readback for unresolved privileged Jobs; no privileged host side effect
  was enabled.
- The requirement-to-release matrix contains 29 rows: 2 `PASS`, 23 `OPEN`,
  and 4 `BLOCKED`. The completion auditor now includes this matrix as an
  explicit gate, so evidence-file presence cannot be mistaken for complete
  runtime or host verification.
- The replay boundary was rerun after extending capacity/expiry coverage to
  the policy-signer, authority-control, Broker-status, virtualization-guest,
  Edge-revocation, and approval-issuance ledgers. The focused
  persistence/replay slice passed 74/74, including all nine malformed
  persisted replay-row cases. Production remote-issuer evidence remains open
  for `VT-AUTH-02`; see
  `evidence/2026-09-22-replay-ledger-retention-rerun.md`.
- The Broker now exposes an authenticated, bounded `audit-integrity-v1`
  summary through the existing owner-only status readback. It re-verifies the
  full local chain and keyed tail, returns no raw audit evidence, and fails
  closed after keyed-tail publication outage. Focused readback coverage passes
  70/70 and append-only retention coverage passes 4/4; external immutable
  anchoring, production export/recovery, and installed operator authentication
  remain open. Evidence:
  `evidence/2026-09-22-audit-integrity-readback.md` and
  `evidence/2026-09-22-audit-retention-boundary.md`.
- The host-only `mac-operator-audit` boundary now requires a separate
  configured Keychain archive key, an inactive Broker socket, and the exact
  Broker instance lock before exporting to the fixed owner-only
  `<dataRoot>/audit-exports` directory. Inspection is metadata-only and
  validates the encrypted archive without exposing events. Focused CLI/config
  coverage passes 23/24 with one opt-in Keychain skip; the archive/persistence
  slice remains 64/64. Evidence:
  `evidence/2026-09-23-audit-export-recovery.md` and
  `AUDIT_ARCHIVE_RUNBOOK.md`.
- Typecheck, build, lint, documentation-link, verification-matrix, and diff
  checks pass.
- `npm audit --omit=dev --audit-level=high` reports zero vulnerabilities on
  the current dependency lockfile.
- `npm run verify:contracts` validates all 45 contracts, the versioned ledger
  schemas, and the exact one-to-one contract links in `TOOL_CATALOG.md`.
- The canonical contract schema, build verifier, and Edge registry enforce the
  same cross-field safety invariants: approval policies are closed, read-only
  tools are idempotent, mutations require postcondition verification and
  non-trusted-read approval, and privileged tools require the privileged
  audit/approval pair; the focused Edge registry suite passes 16/16.
- The materialized catalog and contract set contain 45 tools. The catalog,
  scope model, contract schema, and policy parity now include the owner-domain
  `mac_service_control` boundary.
- Production Broker startup now applies explicit public exposure gates to the
  Accessibility-dependent G1 tools, the selected D1 TaskRunner, and the D1
  developer mutation tools. Non-production readiness is rejected before
  listener publication and runtime projection is fail-closed before approval
  consumption. Evidence:
  `evidence/2026-09-22-developer-public-exposure-gate.md`.
- Production GUI/D1 exposure also requires a fresh owner-only
  `macos-host-readiness-v1` record matching the current host and requested
  readiness. Missing, stale, inconsistent, and cross-host evidence fail before
  listener startup; the current host still produces a blocked record.
  Evidence: `evidence/2026-09-22-host-readiness-evidence-gate.md`.
- The production source audit found only three direct child-process entry
  points: the fixed Auth/Edge supervisor children, the bounded process
  supervisor, and the fixed App Sandbox helper. These paths use explicit
  working-directory/environment boundaries and explicitly set `shell: false`,
  and apply the relevant timeout, output, cancellation, identity, or helper
  authentication checks. Connection diagnostics emit only fixed categories,
  bounded protocol values, and a validated Cloudflare request identifier;
  request URLs, query values, authorization headers, cookies, MCP arguments,
  and raw user-agent strings are excluded.
- The process-boundary verifier now checks the reviewed production and probe
  scripts for explicit cwd/minimal-env, timeout, output-cap, and cancellation
  controls in addition to `shell: false`. The fixed Seatbelt probe, standalone
  App-Sandbox helper round-trip, packaged executor round-trip, and hostile
  process-tree probe all pass their bounded physical readbacks. The native
  helper preserves the cwd descriptor across control-descriptor cleanup; this
  closes the previously observed standalone fixture failure without changing
  the production host gates.
- A fresh Darwin host probe confirms the fixed system-published executable
  identities for `/bin/launchctl`, `/usr/bin/sandbox-exec`, and
  `/usr/bin/printf`. This strengthens the reviewed child-process boundary but
  does not substitute for Developer ID, notarization, sandbox-capability, or
  persistent-service evidence.
- The App Sandbox executor now requires a host-owned SHA-256 identity for the
  exact helper artifact before it reports availability, rechecks that identity
  after pathname spawn, and uses an explicit `shell: false` launch boundary.
  This narrows artifact substitution risk but does not replace Developer ID,
  notarization, or Gatekeeper evidence.
- App Sandbox startup now requires an explicit `development-probe` or
  `production` release mode. Production construction requires a complete
  Developer ID/notarization readback for the exact helper bundle, and each
  production run re-reads and compares the bundle tree identity before spawn.
  The physical host has no valid Developer ID identity, so this gate remains
  closed and the ad-hoc helper is probe-only.
- Root-helper startup, runtime, server, task executor, and transport capability
  now require an explicit release mode. Production mode requires exact native
  helper artifact identity plus Developer ID/notarization evidence; a regular
  native executable is accepted as the artifact shape, while missing or
  incomplete evidence fails closed. Evidence:
  `evidence/2026-09-22-root-helper-release-gate.md`.
- A reproducible Root Helper release verifier is available through
  `npm run verify:release:root-helper -- --manifest <canonical-path>`. It
  accepts only an owner-only manifest and regular native artifact, then emits
  the redacted release evidence accepted by production startup.
- A fail-closed release-manifest generator is available through
  `npm run create:release:manifest -- --artifact <canonical-path> --output
  <canonical-path> --identifier <id> --team-identifier <team> --cdhash <hash>`.
  It derives the artifact digest and writes nothing unless the complete
  Developer ID/Gatekeeper preflight succeeds. The current ad-hoc artifact was
  rejected without output; this improves the handoff but does not satisfy the
  missing production identity.
- The completion audit now has a strict owner-only production acceptance-record
  boundary for the final material/rollback/security-review gate. It validates
  current host identity, seven-day freshness, protected file mode, exact
  non-secret assertions, and regular non-symlink evidence references. The
  current record is intentionally absent, so the gate remains incomplete.
- The non-executing Root Helper package plan now requires that same release
  evidence for the exact LaunchDaemon executable, rejects a different
  `Program` path, and freezes the evidence snapshot after validation. Focused
  package-plan and host-observer coverage passes 11/11; this does not perform root-domain writes.
- A helper-specific reproducible release verifier is now available through
  `npm run verify:release:app-sandbox -- --manifest <canonical-path>`. It
  binds the helper executable digest to the exact `.app` bundle and emits only
  the release evidence accepted by the production startup gate.
- `npm run verify:process-boundaries` now performs a source-level production
  audit: only the fixed Auth/Edge supervisor, Broker process supervisor, and
  App Sandbox helper may import direct child-process APIs, and each must state
  `shell: false`. The current audit reports three reviewed files and zero
  unreviewed entries. Evidence: `evidence/2026-09-22-production-process-boundary-audit.md`.
- The live personal deployment remains the R1 read-only snapshot. No live
  mutation or privileged scope was enabled or restarted during this audit.
- Edge startup now has an optional owner-only HMAC service-status channel with
  freshness, replay, socket-identity, and fail-closed lifecycle checks. The
  separate apply entrypoint consumes primary and exact-inverse manifests,
  production-only signature policy, authenticated Edge/Broker status sources,
  and authority-gated uninstall. This is a host-owned handoff boundary only;
  no live R1 state changed. Evidence:
  `evidence/2026-09-22-macos-launchagent-apply-boundary.md`.
- The privileged-helper package independently samples its three root-helper,
  Broker, and Broker-authority sockets twice; the root-helper package now
  samples four endpoints by adding its authenticated status socket. Both bind
  owner/mode and device/inode identity. Focused privileged-helper coverage
  passes 21/21; root-helper package/status coverage passes 14/14 and its
  service/runtime/status integration slice passes 12/12. Root-domain
  installation and production signing remain open. Evidence:
  `evidence/2026-09-22-privileged-helper-three-socket-readback.md`.
- TaskRunner public exposure is now explicit: production startup rejects an
  enabled `mac_task_run` policy when the available selected runner is
  `staging-only`. This prevents physical canary evidence from becoming a
  public task capability; it does not close the underlying production release
  or sandbox gates. Evidence:
  `evidence/2026-09-22-production-task-exposure-gate.md`.
- Accessibility-dependent G1 exposure is now explicit: production startup
  rejects an enabled focus/observe/action/type tool unless host-owned GUI
  readiness is `production`; the default is unavailable and direct staging
  probes remain separate. The current host still reports permission denied.
  Evidence: `evidence/2026-09-22-gui-public-exposure-gate.md`.
- The fixed production Broker entrypoint now reads the strict GUI and D1
  readiness enums from the owner-only startup configuration; missing values
  remain unavailable and invalid values fail before authority restoration.
  The physical D1 mutation, Git, and named-task canaries were rerun and passed
  in disposable state. Evidence:
  `evidence/2026-09-22-d1-physical-canary-rerun.md`.
- The opt-in D1 user-service canary also passed the authenticated Auth -> HTTPS
  Edge -> Broker -> Job -> launchd readback path for a disposable owner-domain
  LaunchAgent, including approval denial, owner-approved start/stop, strict
  output-schema validation, and exact cleanup. Evidence:
  `evidence/2026-09-22-d1-auth-edge-broker-user-service-canary.md`.
- The install-plan lifecycle itself now has a real disposable owner-domain
  LaunchAgent probe covering atomic plist application, fixed bootstrap, exact
  running readback, bootout, uninstall, and post-cleanup absence. It uses an
  ad-hoc artifact and remains staging-only. Evidence:
  `evidence/2026-09-22-install-plan-launchagent-lifecycle.md`.
- The packaged Edge/Broker startup smoke also passes with temporary real
  LaunchAgents, TLS, authenticated Unix IPC, owner-only sockets, Keychain
  audit-anchor ACL delivery, Broker status readback, and exact cleanup. It is
  staging evidence and does not close signed production installation. Evidence:
  `evidence/2026-09-22-packaged-launchagent-smoke.md`.
- The real temporary user-Keychain ACL rerun passes 23/23 focused credential
  and peer/native checks. It verifies executable-bound ACL readback, rejection
  of a different executable identity, wrong-digest retirement rejection,
  exact item retirement, and finally-path cleanup without secret output. This
  strengthens staging evidence only; signed installed identity, production
  helper material, rotation, and public enablement remain open. Evidence:
  `evidence/2026-09-22-keychain-acl-readback.md`.
- The machine-readable `npm run verify:completion` audit now emits a
  fail-closed `mac-operator-completion-audit-v1` record. The current run is
  `partial` at 92% because the host reports zero Developer ID identities,
  Accessibility denial, absent target service labels, and no independent
  production-material/rollback/security-review acceptance. Evidence:
  `evidence/2026-09-22-completion-audit-command.md`.
- The process-boundary audit now covers three production runtime files and
  eleven repository scripts, each with explicit `shell: false`; no unreviewed
  child-process entry remains. Evidence:
  `evidence/2026-09-22-script-process-boundary-audit.md`.
- The macOS deployment handoff now has a strict read-only LaunchAgent plan
  compiler. A positive two-component probe emitted exact Edge/Broker service
  IDs, plist hashes, launchd argv, signature policy, metadata, capabilities,
  and preflight data with `apply.available: false`; negative probes rejected
  unapproved ad-hoc planning, unknown fields, and `--apply`. No plist,
  launchctl state, package, or service state changed. Evidence:
  `evidence/2026-09-22-macos-launchagent-plan-cli.md`.
- The root-helper deployment handoff now has a matching strict read-only plan
  compiler. It emits native release, protected-path, rollback, and four-socket
  metadata with `apply.available: false`; positive and negative manifest probes
  passed without changing host state. Evidence:
  `evidence/2026-09-22-root-helper-snapshot-plan-cli.md`.
- The host-owned LaunchAgent coordinator now binds the two component
  executors into a fixed-order transaction. Install/upgrade/rollback run Edge
  then Broker; uninstall reverses the order after authority shutdown. Focused
  7/7 coverage proves inverse-action recovery, explicit recovery-required
  failure, production rejection of ad-hoc/non-notarized plans, authority-gated
  Broker uninstall, and pre-mutation operation validation. No live R1 state
  changed.
  Evidence: `evidence/2026-09-22-macos-launchagent-coordinator.md`.

## Requirement audit

| Objective requirement | Current evidence | Status |
| --- | --- | --- |
| HTTPS MCP Edge -> authenticated local IPC -> unprivileged Broker -> adapters/jobs | `packages/edge`, `packages/broker`, real HTTPS/Unix IPC tests, and R1 deployment readback | `PASS` for implemented R1 path |
| Privileged work behind a separately authenticated allowlisted helper | Root-helper protocol, native peer/HMAC, authority polling, operation allowlist, and package/startup plans | `PARTIAL`; production root helper is not installed or enabled |
| Broker is final authority; arguments cannot grant permission | Broker request parser, policy/target/approval gates, runtime capability-state tests, forbidden authority input-schema tests | `PASS` for covered boundaries |
| Replay rejection | Durable request, nonce, revocation, approval, helper, and authority ledgers with restart tests | `PASS` for covered protocols |
| Independent read/write/process/network/GUI/destructive/privileged scopes | `SCOPES`, policy kill switches, contract-policy parity, capability projection | `PASS` in source/staging; only R1 is live |
| Fail closed and protect credential/secret zones | Filesystem policy, redaction, secret-shaped environment/output denial, physical sandbox probes | `PARTIAL`; final production sandbox and release identity remain open |
| Traversal/symlink/target-swap resistance | Descriptor-relative filesystem execution, `O_NOFOLLOW`, identity/digest readback, target-swap tests | `PASS` for covered adapters |
| Untrusted child-process limits | Explicit profile cwd/env/args, timeout/output/cancel, fixed system-published profiles, process-tree and App Sandbox evidence | `PARTIAL`; arbitrary executable selection is not proven on this host |
| Production process and diagnostic boundary | Source audit of all direct runtime spawns plus credential-safe connection-diagnostic tests | `PASS` for current bounded entry points; App Sandbox/root-helper publication and signing remain external release gates |
| Versioned tool contracts and stable errors | 45 JSON contracts, functional schemas, stable failure schema, contract/policy parity | `PASS` for contract/document integrity |
| Separate planned/implemented/enabled state | Contract lifecycle remains planned; Broker policy and MCP capability response expose implemented/enabled independently | `PASS` for state separation; remote enablement remains gated |
| Mutations with approval, intent, preconditions, idempotency, status, recovery, postconditions | D1 write/Git/job/service-control candidates and physical boundary tests | `PARTIAL`; no public mutation deployment |
| Revocation and kill switch for new, queued, and active work | Auth direct push, Edge-to-Broker HMAC event, Broker durable revocation, queued cancellation, active authority polling, `UNKNOWN_OUTCOME` recovery | `PASS` in tested source/staging path; live R1 not restarted |
| Phased delivery from contracts through hardening | `ROADMAP.md`, `TASK.md`, `VERIFICATION.md`, and phase evidence | `PARTIAL`; release gates and independent review remain open |
| Explicit exclusions | Security baseline, input-schema authority-field rejection, policy allowlists, and negative tests | `PASS` for documented/enforced exclusions |
| Rollback and final readback | Temporary install-plan rollback, D1 mutation/service rollback probes, personal R1 readback | `PARTIAL`; production signed artifact and installed lifecycle rollback are missing |
| No unresolved P0/P1 findings | No final independent security review or production acceptance record is present | `OPEN` |

## Blocking acceptance gates

The following are current external or production gates, not inferred as
complete from source tests:

1. Developer ID identity, notarized artifacts, Gatekeeper readback, and
   persistent LaunchAgent/root-helper lifecycle, including the root-helper
   production release-evidence gate.
2. Accessibility permission plus permission-granted real-application G1
   observe/action/type evidence.
3. Supported production child-process sandbox/executable selection, final D1
   public enablement evidence, and release evidence for the developer mutation
   exposure gate.
4. Protected production Keychain/helper material, root-domain install,
   privileged rollback/readback, and independent P0/P1 security review.

The reproducible host probe currently reports zero valid signing identities,
Accessibility permission denied, and absent target launchd labels. It exits
non-zero and leaves the system unchanged by design:
`npm run probe:host-readiness`.

## Acceptance decision

The objective is not complete. The current evidence proves a governed,
owner-only R1 read path and substantial fail-closed staging boundaries, but it
does not prove production-wide Mac control. The goal remains active; the next
highest-value work is to close the external release/G1 gates or strengthen the
remaining staging boundary without widening live authority.
