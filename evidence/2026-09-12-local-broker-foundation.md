# Authenticated Edge and Local Broker Foundation Evidence

Status: PASS for the bounded prototype scope; not a release record
Recorded: 2026-09-12 (Asia/Kuala_Lumpur)

## Source identity

- Base commit: `45c2097c41d7a2d3964f06283a88537e9e8e83c6`
- Working tree: clean; implementation and contract changes were committed when tested
- Git status manifest SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Runtime source manifest SHA-256: `1d849902e561b2249b71cefeb400af3fcfb604ce44a1eaa9f8f280b277eee25c`
- Tool-contract manifest SHA-256: `87629571205c16e7bad7ce9df90f4a37a2b87d38af50b33f1c772f96ece1576d`
- Contract version: `0.1`
- Policy version: `policy-0.1`

This evidence applies only to the recorded exact commit. It is prototype evidence and does not by itself close a release gate.

## Host profile

- Hardware: Mac mini `Mac16,10`, Apple M4, 16 GB
- Operating system: macOS 26.2 (build 25C56), arm64
- Node.js: 25.5.0
- npm: 11.8.0

No serial number, username, credential, signing identity, or host secret was collected.

## Automated procedure

Commands:

```sh
npm test
npm run verify:contracts
npm run typecheck
npm audit --audit-level=high
```

Observed results:

- 140 tests passed; 0 failed, skipped, cancelled, or todo.
- 44 unique tool contract envelopes and functional schemas compiled successfully.
- TypeScript project-reference type checking passed and npm reported 0 known vulnerabilities.
- The Unix-domain socket integration tests verified mode `0600`, a signed request round trip, and rejection of a group-writable socket directory.
- A locally compiled macOS N-API adapter verified the accepted connection's UID, GID, and PID through `getpeereid` and `LOCAL_PEERPID`; an unlisted PID and a Broker-level denied peer were rejected before request parsing, with no audit event created.
- The Edge verified a response HMAC bound to the complete request/result and rejected a substituted local Broker socket holding a different key.
- MCP Edge tests verified exact OAuth resource binding, known-scope projection, bearer-token isolation, missing-authentication rejection, and Broker-filtered tool discovery through a fresh per-request MCP SDK v2 server.
- Negative cases covered payload tampering, expired request/session, duplicate nonce across Broker-store restart, missing exact scope, Broker-grant scope expansion, session revocation, global kill switch, and recursive audit-field redaction.
- Success envelopes for the twenty implemented Broker handlers and the common stable failure envelope passed their JSON Schemas.
- A failure after authorization was verified to produce an allowed decision followed by a failed completion event, rather than a contradictory denial event.
- Authentication-key tests verified owner-only raw-key loading and rejection of weak permissions and symlinks.
- Signed-policy tests verified Ed25519 signatures, payload digests, schema strictness, protected policy/public-key files, monotonic revision activation, exact target deny precedence, static global disable, unimplemented-tool rejection, and request binding to the active policy version.
- Policy lifecycle tests verified transactional intent/activation/completion, restart identity matching, mismatch rejection, and explicit rollback to an exact signed historical digest with a current-revision precondition.
- Edge-key tests verified overlapping rotation windows, signed `(edge_id, key_id)` authorization metadata, local and signed-policy expiry, unknown-key rejection, and persisted old-key revocation without disabling the replacement key.
- Key-lifecycle tests verified exclusive `0600` creation, file/directory synchronization, protected loading, digest-bound retirement, and refusal to unlink a key before its exact Edge-key identity is persisted as revoked.
- Persistence tests verified atomic migration of legacy revocations to key-specific Edge revocation and startup rejection after audit event tampering.
- Request Ledger tests verified atomic nonce-plus-request admission, globally unique request IDs, canonical payload binding, revisioned decision/intent/running/completion transitions, terminal denial idempotency, and Broker-visible `SUCCEEDED`/`FAILED` readback.
- Restart reconciliation verified that interrupted admission, authorized reads, and pre-dispatch mutation intent become `FAILED`, while a dispatched mutation with an unproven outcome becomes `UNKNOWN`; no interrupted record was promoted to success.
- Approval Ledger tests verified exact binding to requester, tool/contract, normalized target, canonical arguments digest, policy version, approval class, attended mode and TTL. Missing, substituted, expired, revoked and exhausted approvals failed closed; two competing requests could not consume one approval twice.
- `mac_job_cancel` was denied without approval and left the queued job unchanged. Exact approval consumption, request linkage, mutation intent and redacted audit evidence committed together; revocation after intent prevented the request from reaching `RUNNING`.
- The future `admitApprovedJob` primitive verified one-transaction approval/intent/idempotency/new-job admission, idempotent reuse without a second approval consumption, and full rollback on conflicting idempotency payload/target.
- The disabled `ApprovalAuthority` and separate owner-only `ApprovalIpcServer` prototypes verified issuer/key validity, canonical issuance digest and HMAC proof, bounded preview binding, distinct issuer/requester identities, attended/unattended profile gating, durable issuance nonce replay denial across Broker restart, peer denial before parsing, and decision/completion provenance before approval persistence.
- Approval issuer-key lifecycle tests verified owner-only non-symlink `0600` loading/provisioning, a separate durable `approval_key` revocation identity, fail-closed use after revocation, exact digest preconditions, and revoke-before-retire deletion.
- Versioned approval issuer-key metadata tests verified owner-only `0600` atomic write/reload, canonical payload digest readback across revision rotation, separate key-byte files, and fail-closed rejection of symlink, duplicate, weak-mode, and revoked config entries.
- Approval issuer-key manager tests verified persisted activation history, intent/completion audit pairs, monotonic revision enforcement, exact revision/digest restore after Broker restart, and failed rollback attempts leaving the active identity unchanged.
- Named task profile tests verified fixed Broker-owned executable selection, canonical cwd-root containment, anchored argument allowlists, profile-owned environment, network/filesystem declarations, bounded budgets, disabled-profile rejection, and rejection of extra executable/environment fields. The registry remains disconnected from `mac_task_run` pending real sandbox evidence.
- The versioned internal approval-issuance JSON Schema compiled successfully with the contract verifier and rejects unknown envelope/payload fields in the authority parser.
- The bounded `mac_system_summary` adapter and Broker handler returned sanitized OS/architecture/CPU/memory/uptime facts with optional bounded load, omitted user identity and path data, and passed its versioned output schema.
- A default-off test-only fault injector failed admission after request creation, authorization, approval consumption, and Job insertion in turn; each failure rolled back on disk, remained absent after BrokerStore restart, and could be retried successfully without a phantom approval consumption.
- The disabled Broker `ProcessSupervisor` prototype verified explicit size-bounded environment isolation, secret-shaped environment rejection, canonical executable/cwd checks, bounded output, timeout, process-group cancellation, descendant cleanup, and concurrent capacity. It is not wired to `mac_task_run`.
- Signed filesystem policy tests verified root schema loading, exact root-ID target authorization, default denial when that target grant is absent, and path-aware `mac_policy_explain` behavior without letting a request choose its own authority identity.
- The descriptor-backed `mac_stat_path` slice verified regular-file metadata, canonical path plus device/inode evidence, traversal rejection, internal and escaping symlinks, root-symlink rejection, deny-inside-allow after canonical readback, root `/` handling, same-volume containment, and 2,000 atomic symlink target swaps where every successful observation remained inside the authorized root.
- The bounded `mac_read_file` slice verified independent signed content-root enablement, local-volume and single-link regular-file enforcement, final-symlink denial, offset/length bounds, strict UTF-8 output, contract conformance, canonical audit identity, range hashes, post-read descriptor stability, and 2,000 intermediate-directory symlink swaps where every successful read returned only authorized content.
- The disabled-by-default `mac_hash_file` slice verified independent `mac.files.hash` scope and metadata-root authorization, descriptor-backed SHA-256/SHA-512 hashing without content return, protected secret-path denial, canonical path/device/inode evidence, bounded 1GB size handling, and rejection when the target changes after canonical-path authorization.
- The disabled `mac_write_file_atomic` slice verified an independently enabled write root, exact approval binding to the canonical argument digest and root target, explicit idempotency key and Broker Job Ledger linkage, `mac_job_status` readback, secret path/content denial, descriptor-backed same-volume parent/target identity, atomic same-directory temporary-file rename with `fsync`, create-only exclusion, expected hash preconditions, final/intermediate symlink escape rejection, and readback SHA-256 verification. This is dirty-tree prototype evidence; crash/partial-mutation recovery, create-target race coverage, and release rollback/readback gates remain open.
- Mandatory path tests denied representative SSH, GPG, cloud, Docker, Kubernetes, Keychain, Mail, Messages, Safari, Chrome, Photos, dot-env, and credential zones. Representative private-key/token/credential signatures were denied before result construction without raw secret material in results or audit rows.
- A production-default policy assertion verified that all tools remain disabled and no filesystem root exists unless explicitly supplied by authenticated authority configuration.
- Filesystem adapter calls executed in Broker-owned worker threads with empty environment/arguments, bounded V8 heap/stack settings, a four-worker cap, per-tool deadlines, cancellation polling, termination requests, and runtime message validation. Tests covered normal completion, capacity exhaustion, timeout, active cancellation, and a credential-shaped environment canary that did not cross into the worker.
- Native process inventory executes in its own Broker-owned worker boundary with empty environment/arguments, bounded V8 heap/stack settings, a two-worker cap, deadline/cancellation termination, and strict post-message validation; the Broker dispatch path does not run native enumeration on its event loop.
- `mac_find_files` executes in the Broker-owned filesystem worker with empty environment/arguments, metadata-only descriptor-backed traversal, independent `mac.files.search` scope, authorization for every requested root, a fixed 50,000-entry/32-level budget, protected-entry filtering, active cancellation, and strict result validation. No file contents are read or returned.
- `mac_recent_files` executes in the same Broker-owned worker with empty environment/arguments, metadata-only descriptor-backed traversal, independent `mac.files.search` scope, per-root authorization, a Broker-supplied clock and bounded time window, fixed traversal/result budgets, protected-entry filtering, active cancellation, and strict result validation. No file contents are read or returned.
- `mac_search_text` executes in the same Broker-owned worker with empty environment/arguments, content-read root planning, independent `mac.files.search` scope and per-root authorization, 1 MiB per-file and 64 MiB aggregate scan budgets, UTF-8-only text handling, binary/NUL rejection, 100 matches per file, sanitized snippets, protected-entry/secret-content filtering, active cancellation, and strict result validation. Metadata-only roots are denied before content execution.
- `mac_project_discover` executes in the same Broker-owned worker with empty environment/arguments, metadata-only root planning, independent `mac.project.read` scope and per-root authorization, allowlisted project marker types, fixed 16-level/10,000-directory/50,000-entry/result budgets, dependency-directory pruning, protected-entry filtering, active cancellation, and strict result validation. It does not read project file contents.
- `mac_project_summary` executes in the same Broker-owned worker with empty environment/arguments, metadata-only project-root planning, independent `mac.project.read` scope and root authorization, fixed 4-level/1,000-tree-entry/50,000-entry budgets, safe manifest/language inference, dependency-directory pruning, protected-entry filtering, explicit branch/dirty omission warnings, active cancellation, and strict result validation. It does not read source, credential, or VCS control-file contents.
- `mac_storage_analysis` executes in the same Broker-owned worker with empty environment/arguments, independent `mac.storage.read` scope and per-root metadata authorization, native descriptor-verified `statfs` capacity facts, metadata-only ranked file/directory consumers, fixed 8-level/10,000-directory/50,000-entry budgets, protected-entry and symlink filtering, aggregate-directory sizing, active cancellation, truncation warnings, and strict result validation. It does not read file contents or perform cleanup.
- A Broker integration test revoked the active session during a filesystem read, verified the worker cancellation predicate changed immediately, discarded the otherwise successful result, and recorded `AUTHORIZED` decision followed by `CANCELLED` completion.
- Job Ledger tests verified principal-scoped payload-bound idempotency, conflicting reuse denial, revision-checked and time/result-consistent transitions, bounded secret-output replacement, owner isolation, immediate/idempotent queued cancellation, and startup recovery from queued/running to `cancelled`/`unknown` with hash-linked audit evidence.
- `mac_job_status` and `mac_job_cancel` passed their versioned success schemas. Dynamic job IDs were resolved to Broker-owned ownership before the `job:owned` policy decision; foreign jobs were indistinguishable from missing jobs. Cancellation produced separate decision, payload-digest intent, state mutation, readback verification, and completion audit records.

## Directory-listing slice

- The disabled-by-default `mac_list_directory` slice verified independent `mac.files.read` scope and content-root authorization, descriptor-backed local-volume directory opening, bounded lexicographic pagination, hidden-entry handling, protected `.env`/secret-zone filtering before result construction, canonical path/device/inode identity checks, and rejection of directory identity changes after enumeration.
- The disabled-by-default `mac_directory_tree` slice verified independent `mac.files.read` scope and content-root authorization, depth and entry bounds, descriptor-backed recursion only through real directories, inherited protected-entry filtering, same-volume child filtering, canonical root identity, and explicit truncation reporting.
- The enabled-in-test `mac_process_list` slice verified independent `mac.process.read` scope and `process:all` target authorization, native bounded PID enumeration, executable/name/CPU/resident-memory bounds, numeric owner labels, sort/limit validation, strict worker-result validation, and no argv/environment output.
- The enabled-in-test `mac_find_files` slice verified metadata-only search on a root with `contentRead` disabled, canonical matching paths and safe metadata, nested traversal, protected-entry filtering, result/depth bounds, worker execution, and independent authorization failure when one of multiple requested roots lacked a target grant.
- The enabled-in-test `mac_recent_files` slice verified a Broker-bound 24-hour window, inclusion of a recent file and exclusion of an older file, metadata-only roots with `contentRead` disabled, protected-entry filtering, bounded result validation, worker execution, and absence of content or credential-shaped output.
- The enabled-in-test `mac_search_text` slice verified literal/glob matching, line/column/snippet output, UTF-8/binary handling, protected credential filtering, no secret leakage in result/audit evidence, content-root authorization, metadata-only denial, bounded result validation, and worker execution.
- The enabled-in-test `mac_project_discover` slice verified Git/Node/Python marker detection, metadata-only roots with content reads disabled, protected-directory exclusion, unsupported-type rejection, bounded result validation, worker execution, and absence of credential-shaped output.
- The enabled-in-test `mac_project_summary` slice verified safe Git/manifest/language/structure metadata, metadata-only roots with content reads disabled, protected `.env` exclusion, branch/dirty omission warnings, bounded tree output, bounded result validation, worker execution, and absence of source or credential-shaped output.
- The enabled-in-test `mac_storage_analysis` slice verified metadata-only roots with content reads disabled, descriptor-backed capacity output, ranked nested consumers, fixed `top_n`/depth bounds, protected `.ssh` exclusion, no credential-shaped output, bounded result validation, worker execution, and audit redaction.
- The enabled-in-test `mac_network_status` slice verified bounded local interface metadata, inferred connectivity, empty listener output with an explicit limitation warning, no active probes or packet capture, independent `mac.network.read` authorization, bounded native result validation, and audit evidence without credential-shaped network data. Listener enumeration remains disabled until a version-pinned macOS kernel ABI adapter is available.

## Boundary and limitations

This evidence supports only the in-process authenticated MCP Edge factory, Broker core, local Unix-socket prototype, descriptor-backed filesystem operations, and bounded worker-thread lifecycle. It does not prove a real OAuth issuer, certificate/tunnel deployment, production key storage/rotation, native-module packaging/code identity, stable Node descriptor compatibility, Edge PID lifecycle, rate limiting, removable-volume remount identity, Unicode/case behavior, configurable and split-range secret classification, immediate interruption of a kernel-blocked syscall, process-level credential/filesystem/network isolation, persistent queued jobs, process-tree cancellation, create-target races, GUI safety, privileged helper isolation, packaging/signing, deployment, or whole-service rollback.

Node emitted an experimental-feature warning for `node:sqlite`. The persistence API is acceptable for continued prototyping, but the persistence release decision remains open until compatibility, general migration, backup, corruption, disk-pressure, and packaging tests pass. Approval issuance authentication, UI/preview and signed provenance also remain outside this prototype. The current unkeyed audit hash chain detects stored-content mismatch at startup but is not proof against a database writer who recomputes the full chain.

Manifest procedures:

```sh
git status --porcelain=v1 -uall | LC_ALL=C sort | shasum -a 256
find packages schemas -type f ! -path '*/dist/*' -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256
find tool-contracts -type f -name '*.json' -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256
```

The recorded runtime digest additionally includes `package.json`, `package-lock.json`, and `tsconfig.json`, then sorts and hashes the per-file digest manifest. The contract digest hashes the ordered per-file digest manifest.
