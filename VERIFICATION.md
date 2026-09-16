# Verification Matrix

Status: Contract checks and bounded local Broker prototype evidence exist; no release gate is closed
Version: 0.1

Released helper readback addendum: an explicit host-verified
`mac_priv_service_control` package release is now checked through the
authenticated helper status observer, and a false/empty status projection is
rejected as `SERVICE_MISMATCH`. The focused package suite passes 17/17 and
typecheck passes. This proves the final observer binding only; root install,
descriptor execution, signing provenance, and live privileged enablement
remain open. Evidence:
`evidence/2026-09-16-helper-package-release-readback.md`.

Process descendant fixture addendum: the Darwin persisted-descendant recovery
test no longer relies on a 50ms child lifetime; it records identity first and
then terminates the fixture child. Three isolated runs and the latest 871-test
regression pass with zero failures. Evidence:
`evidence/2026-09-16-process-descendant-fixture-stability.md`.

Helper runtime service-control addendum: authenticated helper runtime dispatch
now reaches the concrete service-control adapter and verifies fixed launchctl
argv, empty environment, state readback, response proof, and matching status
capability projection. The runtime suite passes 8/8 using host-only
command/readback seams; descriptor execution, root
installation, signing, and live mutation remain unproven. Evidence:
`evidence/2026-09-16-helper-service-control-runtime-ipc.md`.

Privileged helper capability-release addendum: root package plans now require
an explicit host-verified capability projection before any non-empty helper
capability list can be represented. Only the implemented
`mac_priv_service_control` name is accepted; final package readback compares
the exact availability boolean and capability list. Focused package and
service-control tests pass 23/23 and typecheck passes. This closes projection
drift only; root installation, signing, descriptor execution, and live
privileged enablement remain open. Evidence:
`evidence/2026-09-16-helper-capability-release.md`.

Privileged service-control adapter addendum: the new allowlisted adapter
accepts only `start`, `stop`, and `restart`, sends fixed `/bin/launchctl`
argv with empty environment and bounded timeout/output, and requires a final
LaunchDaemon readback before success. Focused adapter tests pass 6/6, the latest
full regression passes 857/857 with 14 explicit skips, and typecheck passes. This
proves the bounded adapter contract only; descriptor-exec availability,
root-helper identity, root-domain installation, signing provenance, and live privileged enablement
remain open. Evidence:
`evidence/2026-09-16-privileged-service-control-adapter.md`.

Privileged-helper capability binding addendum: `AllowlistedPrivilegedHelper`
now snapshots and derives its capability projection from the own-handler map, while the
authenticated status endpoint validates canonical capability names and rejects
any adapter/status mismatch as `EXECUTION_FAILED`. Focused helper tests pass
17/17 and typecheck passes. This proves projection consistency only; it does
not prove root-domain installation, signing provenance, or enabled privileged
execution. Evidence:
`evidence/2026-09-16-helper-capability-status-binding.md`.

Immutable-snapshot probe addendum: the physical Darwin 25.2.0 / macOS 26.2
host allows the unprivileged file owner to clear `uchg`, while `chflags schg`
returns `Operation not permitted`. These flags therefore do not provide an
attacker-resistant executable snapshot for the unprivileged Broker. Together
with the descriptor-exec SDK probe, this keeps descriptor-required execution
fail-closed and rejects a pathname snapshot shim. Evidence:
`evidence/2026-09-16-immutable-snapshot-probe.md`.

Binary-private-key secret addendum: content and bounded Base64 scanning now
rejects validated DER PKCS#8/PKCS#1/SEC1 private keys and the OpenSSH binary
private-key envelope while preserving public DER. Secret-policy tests pass
9/9, focused security-fuzz passes 8/8, and the related Broker/ProcessSupervisor/
task-profile/guest/Edge regression passes 209/209 with six explicit skips.
This closes known binary private-key formats only; opaque credentials and
production isolation remain open. Evidence:
`evidence/2026-09-16-binary-private-key-secret-boundary.md`.

Private-root secret-zone addendum: content-path authorization now rejects
arbitrary paths under both `/private/var/root/` and `/var/root/`, while log
redaction removes generic private-root paths. Secret-policy tests pass 8/8 and
the focused security-fuzz path/secret corpus passes 8/8. This closes the
root-home path variant only; opaque credential formats and production
isolation remain open. Evidence:
`evidence/2026-09-16-private-root-secret-zone.md`.

Write-recovery regression addendum: the restart cleanup tests now use a clock
after the persisted Broker restart boundary and close the initial store only
once. Rebuilt native fault fixture plus focused post-rename/recovery tests
pass 3/3. This validates the test fixtures and preserves the production
timestamp and identity fail-closed guards. Evidence:
`evidence/2026-09-16-write-recovery-regression-fix.md`.

Process-detail PID-binding addendum at source revision `a8cec0e`: native
process inspection now binds `detail.pid` to the requested PID after the
native before/after start-time fence, while the Broker retains its own result
check. Focused Broker process-inspection tests pass 2/2 and the adapter suite
passes 7/7; typecheck and build pass. This closes adapter-result mismatch only;
continuous post-read identity, descriptor execution, and production sandbox
evidence remain open. Evidence:
`evidence/2026-09-16-process-detail-pid-binding.md`.

Launchd service-id bound addendum at source revision `c5d48fd`: the
system-domain service-status adapter now uses the strict parser's bounded
128-character service-label grammar and rejects an overlong label before any
`launchctl` invocation. The service-inspector suite passes 6/6; typecheck and
build pass. This closes an input-bound mismatch only; persistent launchd
ownership, signing provenance, descriptor execution, helper installation, and
remote issuer deployment remain open. Evidence:
`evidence/2026-09-16-launchd-service-id-bound.md`.

Privileged-helper launchd bootstrap addendum at source revision `316e303`:
Broker caller capture retries only an exact top-level `xpcproxy` readback while
the service remains within a bounded five-second startup deadline. Missing or
conflicting service type still fails closed before native PID/start-time
binding. The focused launchd/startup/helper suite passes 26/26; typecheck and
build pass. This covers transient bootstrap handling only; persistent launchd
ownership, signing provenance, descriptor execution, root-domain installation,
and remote issuer deployment remain open. Evidence:
`evidence/2026-09-16-helper-launchd-bootstrap-retry.md`.

Launchd status type-binding addendum at source revision `583fa09`: the
system-domain `LaunchdServiceInspector` now requires an explicit
`type = LaunchDaemon` in the strict readback before publishing status. Missing
or conflicting status identity fails as the stable `EXECUTION_FAILED` class;
the public `xpcproxy -> loaded` mapping remains unchanged. Focused launchd,
service-inspector, startup, and helper tests pass 25/25; typecheck and build
pass. Persistent launchd ownership, signing provenance, descriptor execution,
root-domain installation, and remote issuer deployment remain open. Evidence:
`evidence/2026-09-16-launchd-status-type-binding.md`.

Launchd startup type-binding addendum at source revision `bd14cba`: Edge and
privileged-helper Broker-caller capture now requires an explicit
`type = LaunchAgent` in the strict readback after GUI-domain validation.
Missing type readback is rejected as a stable service-unavailable error;
focused launchd/startup/helper tests pass 20/20, with typecheck and build
passing. This narrows startup identity ambiguity only; persistent launchd
ownership, signing provenance, descriptor execution, root-domain installation,
and remote issuer deployment remain open. Evidence:
`evidence/2026-09-16-launchd-startup-type-binding.md`.

Launchd service-inspector parser addendum at source revision `917d479`: the
read-only service-status adapter now reuses the strict launchd readback parser,
rejecting forged headers, duplicate singleton fields, nested-field shadowing,
malformed PIDs, and unsupported states before returning status. Public
`xpcproxy -> loaded` mapping and stable Broker errors remain unchanged. The
combined launchd/install/helper/startup suite passes 60/60; typecheck and build
pass. Persistent launchd ownership, Developer ID provenance, descriptor
execution, root-domain installation, and remote issuer deployment remain open.
Evidence: `evidence/2026-09-16-launchd-service-inspector-parser.md`.

Launchd startup parser reuse addendum at source revision `3fa25e1`: Edge
startup identity capture and privileged-helper Broker-caller capture now reuse
the strict launchd parser, rejecting duplicate/nested fields and malformed PID
readback before native process-identity capture. Stable component error classes
and exact top-level `xpcproxy` retry behavior remain intact. The combined
launchd/startup suite passes 23/23; typecheck and build pass. Persistent
launchd ownership, Developer ID provenance, descriptor execution, root-domain
installation, and remote issuer deployment remain open. Evidence:
`evidence/2026-09-16-launchd-startup-parser-reuse.md`.

Launchd conflicting-field rejection addendum at source revision `1b09cfa`:
the bounded `launchctl print` parser now rejects duplicate service headers,
duplicate top-level singleton fields, and duplicate argument blocks as
`MALFORMED_READBACK`. Nested dictionaries and argument values are excluded
from top-level field extraction, preventing shadowed service state. The
focused launchd suite passes 6/6; install-plan, privileged-helper,
service-startup, and packaged-service suites pass 43/43 with one opt-in smoke
skip. Typecheck and build pass. This closes parser ambiguity only; persistent
launchd ownership, code-signing provenance, helper execution, and remote
deployment remain open. Evidence:
`evidence/2026-09-16-launchd-conflicting-fields.md`.

Packaged LaunchAgent smoke at source revision `2e5d08b`: the opt-in physical
Darwin test bootstraps reviewed Edge and Broker entrypoints as temporary
owner-domain LaunchAgents, verifies exact launchd program/argument/PID
readback, native socket creation and `0600` ownership, and an authenticated
Broker status response showing `running` with zero enabled capabilities. The
test boots out both jobs, verifies absence, retires its synthetic Keychain
item, and removes the disposable root. The smoke passes 1/1. This is
temporary startup/status-channel evidence only; persistent installation,
Developer ID/notarization, remote OAuth, privileged-helper installation, and
release approval remain open. Evidence:
`evidence/2026-09-16-packaged-launchagent-smoke.md`.

Secret-corpus and split-argv verification at source revision `2e5d08b`: the
Broker now rejects and redacts additional synthetic AWS, Google, GitHub,
GitLab, npm, PyPI, Stripe, OpenAI, Cloudflare, and Heroku credential forms.
It also rejects credential labels whose values are split across adjacent argv
entries, including `Bearer <value>` and `-H Authorization: <value>`, before a
child can be spawned. Secret-policy tests pass 6/6 and the related
ProcessSupervisor/task-profile suites pass 47/47; typecheck, lint,
documentation, and matrix checks pass. This is
known-signature and split-label evidence only; binary/base64 encodings, opaque
secrets, complete credential-store coverage, false-positive analysis, and
production isolation remain open. Evidence:
`evidence/2026-09-16-secret-corpus-expansion.md`.

HTTPS Edge new-session revocation verification at source revision `c0fa6f0`:
the Edge now probes Broker capability authority for session-less
`initialize`/`server/discover` requests before the MCP SDK factory runs. A
Broker `REVOKED` response is converted to a stable HTTP 403 envelope
(`error=revoked`, `result_class=REVOKED`) rather than the SDK's generic 500
internal JSON-RPC error; session-bound requests continue through normal
Broker-authorized execution. Focused HTTPS/MCP tests pass 11/11 and the
complete Edge suite passes 66/66; typecheck, lint, documentation, and matrix
checks pass. This is local session-start evidence only, not remote
revocation-distribution, launchd, physical worker-termination, or production
key-rotation evidence. Evidence:
`evidence/2026-09-16-edge-new-session-revocation.md`.

Cross-process Edge revocation verification at source revision `37ab0fc`:
the separately spawned Edge process completes an authenticated HTTPS -> native
peer-checked IPC call, then the parent Broker persists `edge-1` revocation.
The same MCP session's next request remains routable through the bounded
capability projection and receives stable `REVOKED`; the child does not publish
a late success and the bearer token is absent from audit readback. Focused
HTTPS tests pass 2/2 and the complete Edge suite passes 66/66. This proves
local cross-process propagation only; launchd lifecycle, remote distribution,
and physical worker-termination evidence remain open. Evidence:
`evidence/2026-09-16-edge-cross-process-revocation.md`.

HTTPS Edge mutation-authority verification at the current working revision:
the authenticated MCP client now exercises a Broker-enabled atomic write over
HTTPS -> signed local IPC. A controlled executor flips the `mutations`
kill-switch during execution; Broker authority revalidation returns
`CANCELLED`, keeps the write Job `UNKNOWN`, and publishes no file. A queued
write Job is cancelled transactionally by the same kill-switch and its
`cancelled` state is read back through HTTPS. Edge revocation cancels a second
provenance-bound queued Job, and a subsequent request on the same MCP session
returns stable `REVOKED` while duplicate signed requests remain
`REPLAY_DENIED`. Focused HTTPS tests pass 2/2 and the complete Edge suite
passes 66/66. This is controlled boundary evidence, not physical durability,
production launchd, or OS-level worker-termination evidence. Evidence:
`evidence/2026-09-16-edge-https-mutation-authority.md`.

Edge-to-Broker revocation propagation at source revision `8b3e8e2`: the MCP
Edge now retains only a bounded, short-lived capability projection so a fresh
per-request MCP server can still route a previously verified session after
Broker revocation. The tool call itself always crosses Broker IPC and remains
subject to current authority checks. The authenticated HTTPS integration
revokes the Edge and receives a stable `REVOKED` result on the same MCP client
session; focused MCP/revocation suites pass 10/10 and the complete Edge suite
passes 66/66. Evidence:
`evidence/2026-09-16-edge-broker-revocation.md`.

Edge TLS hostname binding verification at source revision `9c647db`: the
protected startup loader now checks the certificate SAN/CN against the
configured resource hostname after public-key pairing and before listener
construction. A real OpenSSL-generated wrong-hostname negative case passes;
the focused TLS suite passes 5/5 and the HTTPS/cross-process/service-startup
suites pass 10/10. This proves startup identity binding only, not complete
chain trust, issuer availability, or launchd deployment. Evidence:
`evidence/2026-09-16-edge-tls-host-binding.md`.

Edge TLS material pairing verification at source revision `3dacdbe`: protected
certificate/private-key loading now derives both public SPKI values and rejects
invalid or mismatched pairs before the HTTPS listener is constructed. The
private-key buffer is cleared on pairing failure. The focused TLS suite passes
4/4 with a real OpenSSL-generated pair and a mismatch negative case; HTTPS
Edge, cross-process Edge/Broker, and service-startup suites pass 10/10.
This closes startup pairing only, not certificate-chain, hostname, issuer, or
launchd deployment evidence. Evidence:
`evidence/2026-09-16-edge-tls-pairing.md`.

Descriptor-launch capability probe at source revision `81a67b1`: the native
peer addon now returns a versioned, host-owned capability record instead of
leaving launcher presence implicit. The physical Mac mini reports
`available=false`, `executableCoverage=unproven`, `immutableSelection=unproven`,
and `closeOnExec=unproven`; descriptor-required execution remains fail-closed
with `POLICY_DENIED`, and older/partial native addons are rejected by the
required-export check. This is an explicit unavailable result, not evidence of
descriptor execution or physical sandbox enforcement. Evidence:
`evidence/2026-09-16-descriptor-launch-capability-probe.md`.

Task sandbox Docker-socket denial verification at source revision `314189c`:
the Broker-owned Seatbelt renderer emits explicit read/write denies for both
`/var/run/docker.sock` and `/private/var/run/docker.sock`, regardless of task
arguments or filesystem-root grants. The deterministic sandbox-profile suite
passes 13/13 with five real-macOS opt-in skips. This is static SBPL evidence
only because the native descriptor launcher is unavailable in the current
runtime; physical kernel enforcement, socket aliases, daemon/VM isolation,
mutation, and production evidence remain open. Evidence:
`evidence/2026-09-16-docker-sandbox-deny.md`.

Docker CLI code-signature verification at source revision `872198b`: the
Broker default requires a fixed `/usr/bin/codesign` strict verification and
bounded details readback before Docker status, inspect, or logs. The readback
must match the Broker-owned Docker Inc identity (`Identifier=docker`,
`TeamIdentifier=9BNSXJN65R`); missing, malformed, duplicate, or mismatched
fields fail closed as `POLICY_DENIED`, and raw codesign output is not returned.
The attested executable content SHA-256 is carried into every Docker child
admission, so a replacement between signature readback and spawn is rejected
by the shared supervisor. Focused Docker tests pass 16/16 with one explicit
opt-in skip; the physical signature/status/inspect readback passes 1/1. This
proves current signature identity and a bounded content handoff only, not
notarization, a kernel-held descriptor, native daemon/socket isolation, VM
isolation, mutation, or production deployment. Evidence:
`evidence/2026-09-16-docker-code-signature.md`.

Docker inspect object-identity verification at source revision `13537e6`:
the fixed adapter and Broker response boundary require exact ID equality or a
one-way bounded hexadecimal prefix match for ID targets, exact normalized
`Name` readback for non-ID names, and matching object type. ID-looking names
are treated as IDs, so a different object cannot be accepted merely because
its name matches; name targets are re-inspected by canonical ID and changes
between observations fail closed. Missing identity is rejected before response
serialization, and the Broker repeats the check for adapter-provided results.
Focused Docker identity/parser tests pass 14/14, the Broker mismatch test passes 1/1; target
validation also rejects CLI-option, absolute-path, and socket/HTTP URL syntax
before invocation; Inspect/Logs JSON contracts encode the same negative
pattern. The physical Docker Desktop status/inspect readback passes
1/1, and typecheck passes. This is an observation/result-binding fence, not a
kernel-held Docker handle or same-name replacement guarantee. Native macOS
daemon isolation, host socket denial, mutation,
and production evidence remain open. Evidence:
`evidence/2026-09-16-docker-object-identity.md`.

Docker CLI executable-boundary verification at source revision `ff4f4d6`:
the shared process supervisor remains root-owned by default, while the fixed
Docker adapter can execute only a Broker-listed canonical user-owned path with
owner-only write permissions and an explicit internal flag. Focused
ProcessSupervisor/Docker tests pass 49/49 with one opt-in skip, and the real
Docker Desktop readback passes 1/1. This narrows executable substitution but
does not prove native macOS daemon isolation, OS-level socket denial, or
production deployment; code-signature provenance is covered by the newer
`872198b` verification above. Evidence:
`evidence/2026-09-16-docker-cli-executable-boundary.md`.

Real Docker readback verification at source revision `a0c753a`: the local
Docker adapter accepts Docker 29's bounded `Platform` field under the strict
record allowlist. On the physical Mac mini's Docker Desktop `desktop-linux`
context, status returned 24 container records with no warnings or truncation,
and a bounded container inspect succeeded. The focused Docker suite passes
9/9; this proves local Docker Desktop compatibility only, not native macOS
daemon, arbitrary socket, container mutation, VM isolation, or production
deployment evidence. Evidence:
`evidence/2026-09-16-real-docker-readback.md`.

Process inspection start-time verification at source revision `f01ddb8`:
the native adapter captures PID plus `startTimeMicros` before and after bounded
metadata collection and rejects changes before returning the result. Focused
process/Broker tests pass 8/8, the physical Darwin L0/L1 readback passes 1/1,
and typecheck, lint, and diff checks pass. This is a before/after observation
fence, not a kernel-held process handle or post-readback liveness proof.
Evidence: `evidence/2026-09-16-process-inspect-start-time.md`.

Process inspection target-binding verification at source revision `93daffb`:
`mac_process_inspect` rejects a worker/native adapter result whose PID differs
from the requested argument before success serialization. The focused Broker
process-inspect suite passes 2/2, including failed request-state and audit
completion assertions for the mismatch; typecheck, lint, and diff checks pass.
This closes only the adapter-result substitution boundary. OS PID-reuse and
start-time identity, installed service identity, remote revocation, and release
evidence remain open. Evidence:
`evidence/2026-09-16-process-inspect-target-binding.md`.

Signed policy schema alignment verification at source revision `3c76604`, with
grammar centralization revalidated at `9a4554e`:
the policy document schema now represents `docker_runtime` and
`docker_object` targets and constrains all target kinds with their canonical
reference forms. `PolicyBundleVerifier.verify()` materializes and validates the
Broker policy before returning a verified bundle, preventing malformed signed
target rules from reaching activation. The policy-loader suite passes 16/16;
the combined policy/loader/target suites pass 30/30 after the shared
target-authority refactor; typecheck, lint, docs,
matrix, and diff checks pass. This closes schema/runtime alignment at that
revision; finite-set parameterized matching is covered by the later `1ea5ab4`
verification below. Live resource readback, native transport, remote issuer,
and release evidence remain open.
Evidence: `evidence/2026-09-16-signed-policy-target-schema.md`.

Parameterized target-constraint verification at source revision `1ea5ab4`:
signed rules may carry a bounded `target_constraint` finite set of canonical
same-kind references. The anchor reference, uniqueness, lexical ordering,
cross-kind grammar, immutable policy cloning, deny-over-allow matching, and
default-deny behavior are covered by schema/loader/runtime tests. The focused
policy, loader, target-authority, and policy-query suites pass 33/33; physical
resource identity readback, native transport, remote issuer, and release
evidence remain open. Evidence:
`evidence/2026-09-16-parameterized-target-constraints.md`.

Real macOS layered Edge/L0-L1 readback at source revision `c82d04a`:
Darwin 25.2.0 arm64 with Node.js 25.5.0 passed the metadata-only bounded host
probe, same-process signed HTTPS-to-Broker path, and separately spawned Edge
process with native UID/GID/PID-start-time peer binding (3/3). Replay and
bearer-token audit isolation checks also passed. This remains prototype host
evidence; installed launchd identity, external issuer/certificate provenance,
remote deployment, and release gates remain open. Evidence:
`evidence/2026-09-16-real-edge-https-l0-l1.md`.

Real read-only adapter verification at source revision `c82d04a`: on the same
Darwin 25.2.0 arm64 host, the app-inventory, launchd-service, log, and Docker
adapter suites pass 21/21. Physical cases are limited to bounded running-app,
`system/com.apple.logd`, and sanitized `system` log readback; Docker coverage
is deterministic and does not claim a live daemon. App control, Accessibility,
live Docker object identity, mutation, helper, and release evidence remain
separate. Evidence:
`evidence/2026-09-16-real-readonly-adapters.md`.

Signed policy target validation verification at source revision `7e92fe9`:
`validateBrokerPolicy` now applies target-kind-specific reference grammars to
every active target rule after generic shape validation. Host/runtime identities,
root IDs, canonical project paths, process/Job/profile IDs, app/window/UI
identities, service/log sources, Docker objects, packages, and power targets are
bounded and traversal-resistant. Focused policy-target tests pass 2/2 (18
canonical/malformed target cases), and the
combined policy/policy-loader regression passes 29/29; typecheck, lint, docs,
matrix, and diff checks pass. Caller-side unknown safe targets retain normal
default-deny behavior. Parameterized grant serialization, live identity
readback, native transport, remote issuer, and release evidence remain open.
Evidence: `evidence/2026-09-16-signed-policy-target-validation.md`.

Policy-query target normalization verification at source revision `81bf9fa`:
`mac_policy_explain` now applies target-kind-specific reference grammars before
policy lookup, including canonical bundle/app-window/UI identities, absolute
filesystem/project paths, bounded service/log/Docker/Job/package/profile
references, and the previously omitted `docker_runtime:local` target. Traversal,
cross-kind, malformed resource, control-character, and unknown-kind inputs fail
with stable `PRECONDITION_FAILED`; omitted input defaults only to
`host:broker`. Focused target-normalizer tests pass 3/3; typecheck, lint, and
diff checks pass. Filesystem paths remain lexical until descriptor-backed root
planning, and signed policy, native transport, remote issuer, resource
readback, and release evidence remain open. Evidence:
`evidence/2026-09-16-policy-query-target-normalization.md`.

Replay-ledger capacity verification at source revision `aec1bc8`: all seven
Broker replay ledgers enforce a 4,096-row transactional admission boundary,
perform expiry cleanup before the check, and reject an over-capacity ledger
with `AUDIT_UNAVAILABLE` without inserting a partial request. Focused capacity
coverage passes 1/1; typecheck, style, and diff checks pass. Startup integrity
rejects a persisted ledger above the same boundary while allowing a full but
bounded ledger to restart and reclaim expired rows. This closes
unbounded local replay-ledger growth only; remote retention, disk exhaustion,
cross-runtime, and installed-service recovery evidence remain open. Evidence:
`evidence/2026-09-16-replay-ledger-capacity.md`.

Broker request-snapshot verification at source revision `0795958`:
`parseBrokerRequest` recursively copies and freezes the complete validated
request envelope, and `Broker.handleForIpc` carries that snapshot through
asynchronous dispatch and response signing. Focused request-boundary tests
pass 3/3; typecheck, style, and diff checks pass. Negative coverage mutates
arguments, nested values, scopes, principal fields, and an own `__proto__`
field after parsing without changing the Broker view; the IPC regression also
mutates the original request during async dispatch and still verifies the
pre-dispatch response binding. This closes same-process request-object
substitution only; native transport, remote issuer, replay, policy, target,
and installed-service evidence remain independent gates.
Evidence: `evidence/2026-09-16-broker-request-snapshot.md`.

Guest identity authority-snapshot verification at source revision `5d1084e`:
the Guest Agent, Broker transport client, VM lifecycle, and composed runtime
copy and freeze expected or published Guest identity objects before retaining
them. Negative coverage proves top-level and caller-object mutations fail at
runtime or leave the bound identity unchanged. Focused Guest
lifecycle/transport/agent/startup tests pass 32/32; the serial physical
regression passes 669/674 with 0 failures and 5 explicit descriptor-capability
skips. The three pre-existing long-running suites were excluded and left
untouched. This closes in-process Guest identity reference substitution only;
native VM boot, descriptor pinning, remount resistance, signed attestation
production, guest isolation, and production enablement remain open. Evidence:
`evidence/2026-09-16-guest-identity-authority-snapshots.md`.

Guest attestation key snapshot verification at source revision `3325376`:
the protected loader and KeyManager copy and recursively freeze config
documents, key entries, active arrays, and public-key material before exposing
them to verifier creation. Negative coverage proves document and key-entry
mutation attempts fail at runtime, while public-key bytes are no longer
exposed as mutable Buffers. Focused keyring tests pass 4/4; the serial physical
regression passes 667/672 with 0 failures and 5 explicit descriptor-capability
skips. The three pre-existing long-running suites were excluded and left
untouched. This closes in-process active-key object substitution only; private
key distribution, signed installation provenance, native attestation
production, VM isolation, and production enablement remain open. Evidence:
`evidence/2026-09-16-guest-attestation-key-snapshot.md`.

Signed Guest attestation snapshot verification at source revision `08770f3`:
the verifier, `VirtualizationGuestTransportExecutor`, and
`VirtualizationTaskRunner` copy and recursively freeze the complete signed
attestation envelope and verification result before long-lived retention.
Negative coverage proves top-level, payload, nested identity, and original
caller-object mutation attempts cannot alter the bound data. Focused
attestation/runner tests pass 20/20; the serial physical regression passes
667/672 with 0 failures and 5 explicit descriptor-capability skips. The three
pre-existing long-running suites were excluded and left untouched. This closes
in-process post-verification object substitution only; native attestation
production, protected private-key distribution, VM boot, guest isolation,
remount resistance, and production enablement remain open. Evidence:
`evidence/2026-09-16-signed-guest-attestation-snapshot.md`.

Guest image binding verification at source revision `e613a5a`:
`VirtualizationTaskRunner` retains a copied, recursively frozen startup image
binding; negative coverage proves path and nested identity mutation attempts
fail at runtime. Focused task-runner tests pass 13/13; the serial physical
regression passes 666/671 with 0 failures and 5 explicit descriptor-capability
skips. The three pre-existing long-running suites were excluded and left
untouched. This closes post-constructor in-process image binding mutation only;
native VM descriptor pinning, remount resistance, signed provenance, and
production virtualization remain open. Evidence:
`evidence/2026-09-16-guest-image-binding-snapshot.md`.

Guest admission evidence verification at source revision `b726d69`:
`VirtualizationGuestTransportExecutor` recursively freezes the bounded guest
request admission snapshot before Broker Job persistence callbacks. Negative
coverage proves request-ID and nested identity mutation attempts fail at
runtime. Focused Guest/Runner/Agent tests pass 17/17; the serial physical
regression passes 666/671 with 0 failures and 5 explicit descriptor-capability
skips. The three pre-existing long-running suites were excluded and left
untouched. This closes callback-side in-process admission-evidence mutation
only; native guest isolation, signed attestation enablement, and production VM
deployment remain open. Evidence:
`evidence/2026-09-16-guest-admission-evidence-snapshot.md`.

Process ownership evidence verification at source revision `17aa71e`:
`ProcessSupervisor` recursively freezes ownership snapshots before invoking
persistence callbacks. Negative coverage proves callback-side PID mutation is
rejected at runtime and cannot alter the recovery evidence graph. Focused
supervisor tests pass 39/39; the serial physical regression passes 666/671
with 0 failures and 5 explicit descriptor-capability skips. The three
pre-existing long-running suites were excluded and left untouched. This
closes callback-side in-process evidence mutation only; kernel process-tree
isolation, descriptor execution, production sandboxing, and task enablement
remain open. Evidence:
`evidence/2026-09-16-process-ownership-evidence-snapshot.md`.

Guest transport provenance-snapshot verification at source revision `6241e24`:
`VirtualizationGuestTransportExecutor` recursively freezes the validated Guest
identity and attestation graph retained for later exchange and recovery.
Negative coverage proves top-level and nested provenance mutation attempts fail
at runtime. Focused Guest/Runner/Agent tests pass 33/33; the serial physical
regression passes 666/671 with 0 failures and 5 explicit descriptor-capability
skips. The three pre-existing long-running suites were excluded and left
untouched. This closes in-process provenance-object mutation only; native VM
isolation, signed-attestation enablement, and production virtualization remain
open. Evidence:
`evidence/2026-09-16-guest-transport-provenance-snapshot.md`.

Filesystem authorization-snapshot verification at source revision `29abdd0`:
normalized root policies and complete filesystem plans are recursively frozen
before asynchronous worker execution. Negative coverage proves target, root
policy, deny-zone, and captured volume identity mutation attempts fail at
runtime. Focused filesystem tests pass 38/38; the serial physical regression
passes 666/671 with 0 failures and 5 explicit descriptor-capability skips. The
three pre-existing long-running suites were excluded and left untouched. This
closes post-authorization in-process plan mutation only; native descriptor
execution, production sandbox enablement, remount resistance, and privileged
capability enablement remain open. Evidence:
`evidence/2026-09-16-filesystem-authorization-snapshot.md`.

Privileged Helper adapter command-boundary verification at source revision
`60fe9ec`: `AllowlistedPrivilegedHelper` validates the strict command envelope
before selecting or invoking an operation handler. Negative coverage proves a
command with an unsupported field is rejected without handler execution.
Focused Helper/Job tests pass 27/27; the serial physical regression passes
665/670 with 0 failures and 5 explicit descriptor-capability skips. The three
pre-existing long-running suites were excluded and left untouched. This
closes the direct adapter command-shape boundary only; authenticated helper
transport, root deployment, and capability enablement remain open. Evidence:
`evidence/2026-09-16-privileged-helper-adapter-command-boundary.md`.

Privileged Helper Job input-boundary verification at source revision
`340eb2c`: `PrivilegedHelperJobExecutor` rejects unknown operations and
malformed Job/Lease identities before BrokerStore access, lease renewal, or
command issuance. Negative coverage proves no command factory or client call
occurs and the running Job remains unchanged. Focused Helper Job executor
tests pass 10/10; the serial physical regression passes 664/669 with 0
failures and 5 explicit descriptor-capability skips. The three pre-existing
long-running suites were excluded and left untouched. This closes the local
helper executor input boundary only; separate helper authentication,
privileged host deployment, and capability enablement remain open. Evidence:
`evidence/2026-09-16-privileged-helper-job-input-boundary.md`.

Guest status-lookup validation verification at source revision `6ad2046`:
`VirtualizationGuestProfileExecutor.lookup()` now snapshots and invokes
`validateUnsignedVirtualizationGuestStatusRequest` before bounded-ledger access
or status readback publication. Negative coverage proves a malformed status
operation is rejected at the executor boundary. Focused Guest
executor/agent/transport tests pass 32/32; the serial physical regression
passes 663/668 with 0 failures and 5 explicit descriptor-capability skips.
The three pre-existing long-running suites were excluded and left untouched.
This closes direct in-process status-envelope bypass only; authenticated
transport admission, native VM isolation, immutable executable selection, and
production enablement remain open. Evidence:
`evidence/2026-09-16-guest-status-lookup-validation.md`.

Guest request-envelope validation verification at source revision `19099e4`:
the executor snapshot and profile registry both call
`validateUnsignedVirtualizationGuestRequest`, closing the direct-invocation
path that could otherwise skip strict version, kind, identifier, guest
identity, operation, and limit checks. Negative coverage proves malformed
operation and schema-version inputs are rejected before adapter execution.
Focused guest-executor tests pass 12/12; the related Guest suite passes 78/78;
the serial physical regression passes 663/668 with 0 failures and 5 explicit
descriptor-capability skips. The three pre-existing long-running suites were
excluded and left untouched. This closes request-envelope validation at the
guest executor boundary only; authenticated transport admission, native VM
isolation, immutable executable selection, and production enablement remain
open. Evidence:
`evidence/2026-09-16-guest-request-envelope-validation.md`.

Resolved task-profile snapshot verification at source revision `45e1472`:
`TaskProfileRegistry.resolve()` recursively freezes the exact Broker-owned
profile snapshot handed to task adapters. Negative coverage proves that
executable/cwd-adjacent process data, environment, and filesystem-root
collections cannot be widened after resolution. Focused
task-profile/task-runner/sandbox tests pass 32/32 with 5 explicit
descriptor-capability skips; the serial physical regression passes 662/667
with 0 failures and 5 skips. The three pre-existing long-running suites were
excluded and left untouched. This closes adapter-side mutation of a resolved
profile only; native descriptor execution, production credential/process
isolation, remount resistance, installed provenance, and task enablement
remain open. Evidence:
`evidence/2026-09-16-resolved-task-profile-snapshot.md`.

Task isolation-proof immutability verification: the validated
`TaskIsolationProof` graph is recursively frozen before a sandbox or
virtualization runner retains or exposes it. Negative coverage proves that
top-level proof fields and nested guest identity cannot be changed after
validation. Focused task-runner/sandbox/guest tests pass 32/32 with 5 explicit
descriptor-capability skips; the serial physical regression passes 662/667
with 0 failures and 5 skips. The three pre-existing long-running suites were
excluded and left untouched. This closes runtime proof-object mutation only;
native descriptor execution, production credential/process isolation,
remount resistance, installed provenance, and task enablement remain open.
Evidence: `evidence/2026-09-16-task-isolation-proof-immutability.md`.

Edge contract immutable-snapshot verification at source revision `1bedb5d`:
the validated contract graph is recursively frozen before the registry shares
it with MCP registration or callers. Mutation attempts against the contract,
required scopes, and nested input-schema properties fail, preserving the
validated authorization snapshot. Focused Edge contract/readback tests pass
19/19; the serial physical regression passes 662/667 with 0 failures and 5
explicit descriptor-capability skips. The three pre-existing long-running
suites were excluded and left untouched. This closes post-validation object
mutation only; installed provenance, signing, native descriptor execution,
production isolation, remote issuer deployment, and capability enablement
remain open. Evidence:
`evidence/2026-09-16-edge-contract-immutable-snapshot.md`.

Filesystem parent-directory identity verification at source revision
`bba64c1`: native write, unlink, and unlink-recovery operations compare the
canonical parent directory device/inode with the opened parent descriptor
before mutating a child name. Focused filesystem tests pass 37/37; the serial
physical regression passes 661/666 with 0 failures and 5 explicit
descriptor-capability skips. The three pre-existing long-running suites were
excluded and left untouched. This closes the implemented same-root parent
replacement check only; kernel-held task execution, remount resistance,
production isolation, installed provenance, and capability enablement remain
open. Evidence:
`evidence/2026-09-16-filesystem-parent-identity.md`.

Edge runtime functional-schema verification at source revision `e1c10a2`: the
contract loader recursively rejects forbidden authority-shaped input fields
and bounds schema depth, node, array, and property structure before MCP SDK
registration. Focused contract/readback tests pass 18/18; the serial physical
regression passes 661/666 with 0 failures and 5 explicit descriptor-capability
skips. The three pre-existing long-running suites were excluded and left
untouched. Evidence: `evidence/2026-09-16-edge-runtime-schema-boundary.md`.

Edge contract canonical-path verification at source revision `a688bfb`:
`ToolContractRegistry.load()` rejects relative paths and parent-directory
symlinks before parsing and rechecks canonicality at final readback. Focused
contract/readback tests pass 17/17; the serial physical regression passes
660/665 with 0 failures and 5 explicit descriptor-capability skips. The three
pre-existing long-running suites were excluded and left untouched. Evidence:
`evidence/2026-09-16-edge-contract-canonical-path.md`.

Edge contract owner readback verification at source revision `32c277e`: final
contract-directory readback rechecks the current Edge UID after parsing, and
direct negative coverage rejects a simulated owner change during loading.
Focused contract/readback tests pass 16/16; the serial physical regression
passes 659/664 with 0 failures and 5 explicit descriptor-capability skips.
The three pre-existing long-running suites were excluded and left untouched.
Evidence: `evidence/2026-09-16-edge-contract-owner-readback.md`.

Edge contract foreign-owner regression verification at source revision
`edd2cff`: direct negative coverage rejects a mismatched Edge UID before
contract parsing, restoring the simulated identity in a `finally` block.
Focused contract/readback tests pass 15/15; the serial physical regression
passes 658/663 with 0 failures and 5 explicit descriptor-capability skips.
The three pre-existing long-running suites were excluded and left untouched.
Evidence: `evidence/2026-09-16-edge-contract-owner-test.md`.

Edge contract ownership verification at source revision `1500196`: the Edge
contract directory and each contract file must be owned by the Edge UID before
parsing or MCP advertisement, in addition to regular, non-symlink, and
non-writable checks. Focused contract/readback tests pass 14/14; the serial
physical regression passes 657/662 with 0 failures and 5 explicit
descriptor-capability skips. The three pre-existing long-running suites were
excluded and left untouched. This closes owner-integrity admission only;
installed provenance, signing, native descriptor execution, remote issuer
deployment, and capability enablement remain open. Evidence:
`evidence/2026-09-16-edge-contract-owner.md`.

Descriptor launcher executable-and-cwd boundary verification at source
revision `d8f0202`: descriptor-required ProcessSupervisor execution opens and
identity-checks both the validated executable and cwd, passing only borrowed
descriptors to the native adapter. Neither pathname is supplied and pathname
spawn is not a fallback. Focused process/capability tests pass 42/42; the
serial physical regression passes 657/662 with 0 failures and 5 explicit
descriptor-capability skips. The three pre-existing long-running suites were
excluded and left untouched. This closes only the executable/cwd pathname
reopen ambiguity; native descriptor execution, close-on-exec, immutable
selection, remount resistance, production isolation, and task enablement
remain open. Evidence:
`evidence/2026-09-16-descriptor-launcher-cwd-boundary.md`.

Descriptor launcher FD-boundary verification at source revision `2c2b10d`:
descriptor-required ProcessSupervisor execution now opens the validated
executable with `O_NOFOLLOW`, rechecks complete descriptor metadata, and passes
only a borrowed descriptor FD to the native adapter. The adapter receives no
pathname, and pathname spawn is not a fallback. Focused process/capability
tests pass 42/42; the serial physical regression passes 657/662 with 0
failures and 5 explicit descriptor-capability skips. The three pre-existing
long-running suites were excluded and left untouched. This closes only the
Broker-to-adapter contract ambiguity; native descriptor execution,
close-on-exec, immutable selection, remount resistance, production isolation,
and task enablement remain open. Evidence:
`evidence/2026-09-16-descriptor-launcher-fd-boundary.md`.

Edge protected descriptor readback verification at source revision `a01f540`:
Edge authentication-key, TLS, startup-config, and tool-contract readers now
perform a complete post-read descriptor metadata check and wipe changed or
oversized bytes; authentication-key temporary source bytes are wiped after
derivation, and Broker readers wipe bytes when post-read stat fails. Focused
Edge/Broker tests pass 32/32. The serial physical regression passes 657/662
with 0 failures and 5 explicit descriptor-capability skips. The three
pre-existing long-running suites were excluded and left untouched. This
closes the Edge protected read-window race only; atomic executable selection,
remount resistance, production isolation, installed signing, and capability
enablement remain open. Evidence:
`evidence/2026-09-16-edge-protected-descriptor-readback.md`.

Protected descriptor readback verification at source revision `ea50824`:
protected policy and key metadata readers now perform a post-read descriptor
identity check covering device, inode, owner, mode, size, mtime, and ctime;
changed or oversized content is wiped and rejected before parsing or key
activation. Focused protected-reader tests pass 38/38, and the serial physical
regression passes 652/657 with 0 failures and 5 explicit
descriptor-capability skips. The three pre-existing long-running suites were
excluded and left untouched. This closes the protected read-window race only;
atomic executable selection, remount resistance, production isolation,
installed signing, and capability enablement remain open. Evidence:
`evidence/2026-09-16-protected-descriptor-readback.md`.

Descriptor child-handle validation verification at source revision `537bb37`:
the Broker validates a future native launcher result as a ChildProcess-like
handle before capture, identity observation, or cleanup. Invalid shapes fail
with bounded `EXECUTION_FAILED`. Focused process-supervisor and capability
tests pass 42/42, and the serial physical regression passes 649/654 with 0
failures and 5 explicit descriptor-capability skips. The three pre-existing
long-running suites were excluded and left untouched. This hardens the native
return boundary only; descriptor execution, immutable selection, remount
resistance, production isolation, and task enablement remain open. Evidence:
`evidence/2026-09-16-descriptor-child-handle.md`.

Descriptor-launcher seam verification at source revision `b228089`:
descriptor-required `ProcessSupervisor` admission now requires a concrete
Broker-owned launcher seam after the host capability check. Missing wiring
returns stable `POLICY_DENIED`; pathname `spawn` is not a fallback. Focused
process-supervisor and capability tests pass 42/42, and the serial physical
regression passes 649/654 with 0 failures and 5 explicit
descriptor-capability skips. The three pre-existing long-running suites were
excluded and left untouched. This closes only the latent fallback condition;
native immutable descriptor execution, remount resistance, production
credential/process isolation, and task enablement remain open. Evidence:
`evidence/2026-09-16-descriptor-launcher-seam.md`.

Serial physical regression verification at source revision `d3ebdf3`: the
installation, sandbox, and Keychain opt-in suite ran serially on Darwin
25.2.0 arm64 and passed 648/653 tests with 0 failures and 5 explicit
descriptor-capability skips. The three existing long-running suites were
excluded and left untouched. This confirms current implemented-boundary
regression behavior only; native immutable descriptor execution, remount
resistance, production credential/process isolation, installed signing/helper
state, and capability enablement remain open. Evidence:
`evidence/2026-09-16-serial-physical-regression.md`.

Edge capability-scope binding verification at source revision `d4c9bbf`: the
contract registry retains each tool's required scopes, and the authenticated
MCP factory requires Broker capability items to provide a non-empty unique
scope list exactly equal to the registered contract before advertising a
tool. Scope drift fails closed before registration. Focused Edge
contract/MCP tests pass 18/18; no runtime capability was enabled. Evidence:
`evidence/2026-09-16-edge-capability-scope-binding.md`.

Contract-policy parity verification at source revision `20b5d9b`: the default
Broker policy now matches all 44 materialized contracts for required scopes,
Broker-normalized target type, timeout, output cap, approval policy, mutation
safety, and tool-set membership. Six pre-existing budget/target drifts were
corrected, including an explicit descriptor-backed `project_root` to `path`
normalization for `mac_project_summary`. The focused parity test passes 1/1;
no runtime capability was enabled. Evidence:
`evidence/2026-09-16-contract-policy-parity.md`.

Contract-schema identity verification at source revision `f7cd4fe`: the
machine-readable tool-contract schema now requires the top-level `$schema`
identity already enforced by the Edge loader. The focused contract-registry
suite passes 10/10 and `npm run verify:contracts` validates 44 unique contracts;
no runtime or host configuration changed. Evidence:
`evidence/2026-09-16-contract-schema-identity.md`.

Task-descriptor persistence verification at source revision `0229fe3`: the
Broker computes a non-secret SHA-256 digest over the complete resolved task
descriptor and stores it with process ownership metadata. Every later
ownership update must carry the same digest, restart parsing validates its
shape, and legacy metadata without the field remains compatible without an
upgrade. Focused descriptor persistence tests pass 2/2. The serial physical
regression with install, sandbox, and Keychain opt-ins passes 643/648 with 0
failures and 5 explicit descriptor-capability skips; the three pre-existing
long-running suites were excluded and left untouched. This verifies metadata
binding only; the versioned ledger schema accepts the matching optional
digest/proof fields. Native descriptor execution, immutable snapshots, remount
resistance, credential/process isolation, and production task enablement
remain open. Evidence:
`evidence/2026-09-16-task-descriptor-persistence.md`.

Descriptor-required process admission verification at source revisions
`a05cce8`, `c23cfb7`, and `495cd6e`: `ProcessSupervisor` now checks the
host-owned descriptor-execution capability after request validation and before
any child spawn when its
Broker-owned option requires that boundary. Missing or malformed native
support returns stable `POLICY_DENIED`; pathname execution is not used as a
fallback. The capability proof must cover `all-child-executables`, not only a
wrapper launcher. The default `SandboxExecTaskRunner` supervisor enables this gate so
the experimental sandbox cannot be mistaken for atomic executable selection.
Focused process-supervisor tests pass 38/38; descriptor-capability,
sandbox, and task-runner tests pass 29/34 with five explicit real-sandbox
skips. Build, typecheck, and lint checks pass. This verifies admission wiring
only; `VT-FS-02`, native descriptor execution, immutable snapshot proof,
remount resistance, and production task enablement remain open. The serial
physical regression passes 641/646 with 0 failures and 5 explicit
descriptor-capability skips; the three pre-existing long-running suites were
excluded and left untouched. Evidence:
`evidence/2026-09-16-descriptor-admission-boundary.md`.

Write-recovery root-identity verification at source revision `cd649e6` stores
the canonical policy-root path/device/inode in new write Job metadata and
requires an exact match before restart cleanup or postcondition inspection.
Legacy rows without the proof are preserved and skipped. The focused
write-recovery suites pass 4/4; the serial physical regression passes 644/644
with no skips or failures. Evidence:
`evidence/2026-09-16-write-recovery-root-identity.md`.

Filesystem-root identity verification at source revision `bed6a75` binds each
plan to both the storage-volume identity and the authorized policy-root
directory device/inode. A same-volume root rename followed by replacement at
the original pathname is rejected before planned readback. Focused filesystem
and security-fuzz suites pass 37/37 and 8/8; the serial physical regression
passes 643/643 with no skips or failures. Evidence:
`evidence/2026-09-16-filesystem-root-identity.md`.

Additional-target authority verification at source revision `b2d3264` passes
all normalized execution targets into the final Broker success gate. A
same-version policy revision removing a second multi-root target during
dispatch is cancelled before result publication; the focused regression passes
1/1 and the serial physical regression passes 642/642 with no skips or
failures. This closes the final multi-root authority readback gap only; remote
revocation propagation, installed recovery, remount races, and production
enablement remain open. Evidence:
`evidence/2026-09-16-additional-target-authority.md`.

Broker status response-schema verification at source revision `d6f704b`
requires exact nested failure fields and bounded, line-safe status error text
before signing. Focused status tests pass 3/3; the serial physical regression
passes 641/641 with no skips or failures. This closes the local status IPC
response boundary only; production installation and privileged capability
gates remain open. Evidence:
`evidence/2026-09-16-broker-status-response-schema.md`.

Privileged-helper response-schema verification at source revision `cd80e0d`
requires exact command-result, success/failure-response, status-response, and
nested verification/error fields. Unknown fields and unbounded failure
messages fail closed after HMAC identity verification. Focused helper tests
pass 15/15; the serial physical regression passes 640/640 with no skips or
failures. This closes response-shape integrity only; helper enablement,
production signing/install, real privileged adapters, and independent review
remain release gates. Evidence:
`evidence/2026-09-16-privileged-helper-response-schema.md`.

Process-path owner-identity verification at source revision `138b6ed` adds
owner UID/GID comparison to the supervised executable/cwd stability check.
Focused process-supervisor tests pass 37/37; the serial physical regression
passes 640/640 with no skips or failures. This closes ownership drift in that
check only; kernel isolation and production task enablement remain separate
gates. Evidence:
`evidence/2026-09-16-process-path-owner-identity.md`.

Passing-evidence enforcement at source revision `168da62` makes the matrix
checker fail closed when a `PASS` row has no repository evidence reference.
The two PASS rows now reference concrete ledger/capability artifacts. Local
matrix, docs, lint, typecheck, and diff checks pass for 28 targets, 24 threats,
30 tasks, and 3 evidence references. This strengthens traceability only and
does not close runtime gates. Evidence:
`evidence/2026-09-16-verification-matrix-pass-evidence.md`.

Sandbox Keychain-canary verification at source revision `bc5ee74` adds one
real ACL-bound credential path to the MOP-086 boundary. An opt-in
physical-Darwin task invokes `/usr/bin/security` against a synthetic
Broker-owned Keychain item bound to the task executable; the lookup is denied
and stdout remains empty. Focused sandbox checks pass 17/17, and the serial
physical regression passes 639/639 with no skips or failures. This remains
partial evidence and does not enable deprecated `sandbox-exec` or
`mac_task_run`. Evidence:
`evidence/2026-09-16-sandbox-keychain-canary.md`.

Verification-matrix enforcement at source revision `64ee61c` adds a CI-backed
`npm run verify:matrix` check. It validates the seven-column matrix shape,
unique targets, known statuses/gates, threat/task references, repository-local
evidence paths, and coverage of every threat-model verification target. The
local check passes for 28 targets, 24 threats, and 30 task references; docs,
lint, typecheck, and diff checks also pass. This is traceability integrity
evidence only and does not change OPEN/BLOCKED runtime gates or provide a
remote CI result. Evidence:
`evidence/2026-09-16-verification-matrix.md`.

Process-group census verification at source revision `ea7b133` supplements
native descendant traversal with a bounded detached-group member census.
Snapshots are merged by PID/start time and malformed, conflicting, or
truncated observations fail closed; runtime and recovery gates require the
new native export. Focused process/peer tests pass 47/47, and the serial
physical regression passes 638/638 with 0 skips and 0 failures. This closes
only the reparented-child observation gap; post-window `setsid`, kernel
termination, credential isolation, and production task enablement remain
release gates. Evidence:
`evidence/2026-09-15-process-group-census.md`.

Native artifact signing-readiness verification at source revision `54d4590`
covers all three Broker native extensions. Strict `/usr/bin/codesign`
verification passes for each, but `security find-identity -v -p codesigning`
reports `0 valid identities found`; all artifacts are ad-hoc with no
TeamIdentifier. Production Developer ID/notarization and installed readback
remain release gates. Evidence:
`evidence/2026-09-15-native-artifact-signing-readiness.md`.

Serial physical-Darwin regression at source revision `54d4590` passes 637/637
non-overlapping tests with 0 skips and 0 failures under the install, sandbox,
and Keychain opt-ins, serializing execution. The run includes the exact native
Node runtime binding and all existing native IPC, filesystem, process,
sandbox, helper, GUI, virtualization, packaged-service, and HTTPS Edge
boundaries. The three existing long-running suites were excluded without
interruption. Evidence:
`evidence/2026-09-15-serial-physical-regression-native-node-runtime.md`.

Native Node runtime-binding verification at source revision `54d4590`: all
three Broker native addons export the build-time Node version and each loader
requires exact equality with the running `process.versions.node` after the
existing N-API checks. The physical Darwin arm64 build and focused native
loader/boundary suite pass 22/22 with 0 failures and 0 skips; typecheck, lint,
runtime export readback, and diff checks pass. Rebuilding remains required
after Node upgrades; Developer ID provenance and installed deployment remain
separate release gates. Evidence:
`evidence/2026-09-15-native-node-runtime-binding.md`.

Edge runtime contract-integrity verification at source revision `d35f1f7`:
the Edge loader requires the complete governance envelope for every contract,
including known scopes, target type, bounded budgets, independent policy
fields, idempotency, postcondition, audit class, delivery wave, lifecycle
state, functional schemas, and source provenance. It rejects incomplete,
unknown, malformed, or unsupported metadata before MCP registration. The Edge
package regression passes 52/52; all repository contracts load successfully;
build, typecheck, lint, contract verification (44/44), and diff checks pass.
This is runtime contract-shape evidence only; Broker authorization and
production signing/deployment remain required. Evidence:
`evidence/2026-09-15-edge-runtime-contract-integrity.md`.

Safe-integer physical regression at source revisions `350ebbc` and `6f6bf2f`
passes 634/634 non-overlapping tests with 0 skips and 0 failures on the
physical Darwin arm64 host under install, sandbox, and Keychain opt-ins.
The existing Broker, persistence, and privileged-helper IPC long-running
suites were excluded without interruption. Evidence:
`evidence/2026-09-15-serial-physical-regression-safe-integer.md`.

Strict numeric-input verification at source revision `350ebbc`: inbound canonical JSON parsing now rejects
plain decimal integer tokens outside JavaScript's safe-integer range before
request, response, or audit-digest verification. Scientific notation remains
governed by the locked ECMAScript `JSON.stringify` profile; field contracts
continue to impose semantic bounds. The focused contracts/authentication
suite passes 10/10, `verify:canonical:native` passes 5/5 fixed vectors,
`verify:contracts` reports 44 unique tool contracts plus the versioned ledger
schema, and lint passes. Evidence:
`evidence/2026-09-15-safe-integer-canonicalization.md`.

Descriptor launch capability-gate verification at source revision `07ba885`
adds a versioned host-owned capability record. The requirement gate accepts
only a native descriptor launcher plus attested immutable executable
selection and close-on-exec properties; missing or malformed support returns
unavailable and stable `POLICY_DENIED`, with no pathname fallback. On the
physical Darwin host the optional native exports are absent, so the focused
suite passes 3/3; typecheck and lint pass. This records and enforces the
fail-closed boundary but does not close `VT-FS-02`, remount resistance, or
production task enablement. Evidence:
`evidence/2026-09-15-descriptor-launch-capability-gate.md`.

Serial physical-Darwin regression at source revision `eaca6c6` passes 633/633
non-overlapping tests with 0 skips and 0 failures under the install, sandbox,
and Keychain opt-ins, serializing execution. The rebuilt native mount-flag
identity boundary and descriptor capability gate are included; the existing
Broker, persistence, and privileged-helper IPC long tests were excluded and
not interrupted. Evidence:
`evidence/2026-09-15-serial-physical-regression-mount-flags.md`.

Filesystem mount-flag identity verification at source revision `eaca6c6`
extends native `SameFilesystem` checks to include `f_flags` and records that
field in storage-volume IDs. Physical Darwin readback shows the new bounded
identity format; the filesystem/native focused regression passes 38/38 and
typecheck/lint pass. This closes only detection of remount changes visible in
the reported flags; it does not prove in-syscall remount resistance or close
the production task gate. Evidence:
`evidence/2026-09-15-filesystem-mount-flags.md`.

Serial physical-Darwin regression at source revision `339d932` passes 630/630
with 0 skips and 0 failures under the install, sandbox, and Keychain opt-ins,
serializing test execution. It covers the root-owned fixed-adapter executable
gate plus the non-overlapping native IPC, filesystem/write recovery, helper,
GUI, virtualization, policy/audit, temporary LaunchAgent, and HTTPS Edge
boundaries. The long-running Broker, persistence, and privileged-helper IPC
suites were excluded without interruption. Descriptor/fexec, remount,
production signing/deployment, and task-runner enablement remain open.
Evidence: `evidence/2026-09-15-serial-physical-regression.md`.

Process executable permission verification at source revision `339d932`
rejects group- or other-writable executable paths before spawning, and the
Broker's fixed-adapter supervisor additionally requires root ownership. The
physical Darwin build and lint checks pass, and the focused
`process-supervisor.test.js` suite passes 36/36, including temporary writable
and current-user-owned executables denied with `POLICY_DENIED`. Owner UID/GID,
canonical path, descriptor digest, and post-spawn identity checks remain in
force. This does not close kernel-held descriptor execution, remount
resistance, or production task enablement. Evidence:
`evidence/2026-09-15-process-executable-permissions.md`.

Packaged-service lifecycle verification at source revision `339d932` passes
1/1 on the physical Darwin host with
`MOPS_REAL_INSTALL=1 node --test
packages/broker/dist/packaged-service-smoke.test.js`. The isolated smoke
bootstraps temporary-user Edge and Broker LaunchAgents, authenticates the
Broker status readback, verifies executable/argument and PID identity, checks
owner-only sockets, then boots both services out and confirms absence. A
preflight skips without mutation if the fixed labels are already loaded. This
is temporary-user lifecycle evidence, not Developer ID/provenance, production
fixed-label ownership, or crash/remount durability. Evidence:
`evidence/2026-09-15-packaged-service-smoke.md`.

Write-cleanup Job-recovery verification at source revision `bfc9a28` persists
the exact temporary device/inode before the unlink boundary and reconnects
restart reconciliation to identity/age-gated native quarantine recovery. The
focused integration suite passes 3/3; combined with the filesystem boundary
suite, 39/39 pass. A fault-test child receives SIGKILL immediately after the
native quarantine rename, then the same inode is aged into a valid stale
artifact and recovered from the persisted Job identity. Recent, ambiguous,
replacement, and unproven artifacts are preserved and completion audit
classes are explicit. Production remount injection and installed-service
readback remain open. Evidence:
`evidence/2026-09-15-write-recovery-journal.md`.

Service-lock and audit-anchor orphan-recovery verification covers timestamped
UUID/basename-fingerprint quarantine names, stable owner-only parent
identity, exact regular single-link device/inode, bounded age, unique
selection, and durable absence readback. Service locks additionally require
stale PID/start-time proof; audit locks require the host stop gate. Build,
lint, diff checks, and the dedicated suites pass 6/6 and 10/10. Production
crash/remount evidence remains open. Evidence:
`evidence/2026-09-15-service-lock-orphan-recovery.md` and
`evidence/2026-09-15-audit-anchor-lock-orphan-recovery.md`.

IPC socket orphan-recovery verification covers timestamped UUID/basename-
fingerprint quarantine names and explicit stale recovery. The recovery path
checks canonical owner-only parent identity before and after scanning, exact
socket device/inode, inactive endpoint state (including macOS detached-socket
`EINVAL`), bounded age, unique selection, and absence readback. Build, lint,
diff checks, and the dedicated Darwin IPC suite pass 11/11. Production
crash/remount evidence remains open. Evidence:
`evidence/2026-09-15-ipc-socket-orphan-recovery.md`.

Filesystem unlink orphan-recovery verification covers the native quarantine
timestamp/basename fingerprint and explicit stale-artifact recovery. Recovery
reopens the same local root and canonical parent, requires a unique regular
single-link artifact with the recorded device/inode, preserves recent or
ambiguous entries, and verifies durable absence after `unlinkat`/`fsync`.
Build, lint, typecheck, diff checks, and the dedicated filesystem suite pass
36/36, including the Darwin physical stale/recent/wrong-target probe.
Production crash/remount evidence remains open; persisted Job integration is
covered by `def8e82` above.
Evidence: `evidence/2026-09-15-filesystem-unlink-orphan-recovery.md`.

Backup-quarantine age-test verification at source revision `4db2d0d` covers
stale completion, recent quarantine preservation, and invalid timestamp
fail-closed behavior. Build, lint, typecheck, and diff checks pass; the
dedicated quarantine suite passes 3/3. Native unlink recovery and production
crash/remount evidence remain open. Evidence:
`evidence/2026-09-15-backup-quarantine-age-tests.md`.

Backup-quarantine age verification at source revision `8119e94` encodes a
bounded creation timestamp in new quarantine names and uses it for stale-age
decisions, avoiding mtime-based interference with active deletion. Build,
lint, typecheck, and diff checks pass; the dedicated regression passes 1/1.
Native unlink recovery and production crash/remount evidence remain open.
Evidence: `evidence/2026-09-15-backup-quarantine-age.md`.

Backup quarantine recovery verification at source revision `38c5381` scans
only bounded, recognized Broker backup quarantine names, leaves recent entries
untouched, and removes stale owner-only regular files through identity-fenced
cleanup. Unexpected type/owner/mode/count fails closed. Build, lint, typecheck,
and diff checks pass; the dedicated regression and physical probe pass. Native
unlink, IPC/lock/anchor orphan recovery and production crash/remount evidence
remain open. Evidence:
`evidence/2026-09-15-backup-quarantine-recovery.md`.

IPC key-copy gate verification at source revision `af68248` moves all
non-secret constructor validation ahead of authentication-key copying across
the Policy Signer, Authority Control, Broker Status, Privileged Helper, and
guest transport boundaries. Build, lint, typecheck, and diff checks pass; the
focused boundary suites pass 41/41. Production cross-process delivery and
signing identity remain open. Evidence:
`evidence/2026-09-15-ipc-key-copy-gate.md`.

Edge-factory disposal verification at source revision `e3ad73d` makes dispose
idempotent and rejects request creation after key wipe; response verification
fails closed with `false`. Build, lint, typecheck, and diff checks pass; the
focused Edge authentication/IPC/TLS/startup suites pass 18/18. Production
lifecycle and installed shutdown readback remain open. Evidence:
`evidence/2026-09-15-edge-factory-disposal.md`.

Credential-loader buffer verification at source revision `43fec85` clears raw
file-read buffers after copying/parsing and wipes native Keychain read/write/
delete argument buffers on success and failure. Build, lint, typecheck, and
diff checks pass; the focused credentials/keyring suite reports 28 total (27
passed, 1 explicit physical-Keychain skip, 0 failed). Production cross-process
Keychain memory evidence remains open. Evidence:
`evidence/2026-09-15-credential-loader-buffers.md`.

Provisioned-key lifetime verification at source revision `5f4bc61` clears the
random file-provisioning key on every return path and removes failed creations
only after a device/inode/owner/mode/size/time identity-fenced quarantine.
Build, lint, typecheck, and diff checks pass; the focused credentials/keyring
suite reports 28 total (27 passed, 1 explicit physical-Keychain skip, 0
failed). Production Keychain distribution and recovery readback remain open.
Evidence: `evidence/2026-09-15-provisioned-key-lifetime.md`.

Audit-anchor lock quarantine verification at source revision `61e6acb` uses a
private same-directory rename and post-rename device/inode/type readback for
normal lock cleanup; replacement identities fail closed. The stopped-service
native recovery boundary remains independently gated. Build, lint, typecheck,
and diff checks pass; the focused audit-anchor/read-only suite passes 9/9.
Orphan quarantine recovery and installed-service readback remain open.
Evidence: `evidence/2026-09-15-audit-anchor-lock-quarantine.md`.

Service-instance-lock verification at source revision `d3ca767` removes exact
lock identities through a private same-directory quarantine rename, validates
device/inode/type after the move, and only then unlinks the quarantine.
Replacement locks fail closed without deletion. Build, lint, typecheck, and
diff checks pass; the focused service-lock suite passes 5/5. Orphan quarantine
recovery and installed-service readback remain open. Evidence:
`evidence/2026-09-15-service-lock-quarantine.md`.

IPC socket quarantine verification at source revision `6e246bf` uses an
identity-fenced same-directory rename before stale/owned Unix-socket removal,
then rechecks device/inode identity in the private quarantine. Replacement
socket identities fail closed without unlinking the newcomer. Build, lint,
typecheck, and diff checks pass; the focused Broker IPC suite passes 10/10.
Orphan quarantine recovery and installed-service readback remain open.
Evidence: `evidence/2026-09-15-ipc-socket-quarantine.md`.

TLS material lifetime verification at source revision `96adc2d` returns the
validated protected-file buffer directly and clears the certificate buffer on
private-key load failure. Build, lint, typecheck, and diff checks pass; the
focused Edge TLS/service-startup suite passes 8/8. Production TLS key
packaging, listener shutdown readback, and full HTTPS Edge regression remain
open. Evidence: `evidence/2026-09-15-tls-material-lifetime.md`.

Edge key handoff verification at source revision `5695db0` clears the
loader-owned protected-file key buffer after defensive constructor copy.
Build, lint, typecheck, diff checks, and the focused Edge key/request-factory
suite pass 5/5. Full HTTPS Edge and production key-storage evidence remain
open. Evidence:
`evidence/2026-09-15-edge-key-handoff-lifetime.md`.

Request-authentication key lifetime verification at source revision `fec6e5b`
clears transient Edge HMAC copies after request verification and authenticated
response signing, including failures. Build, lint, typecheck, diff checks, and
the focused IPC boundary suite pass 18/18. Production key storage and full
Broker regression remain open. Evidence:
`evidence/2026-09-15-request-authentication-key-lifetime.md`.

Authentication-key memory verification at source revision `42766c9` clears
partially loaded Edge/approval buffers on failure and old manager snapshots on
replacement or explicit disposal; native Edge startup clears its raw snapshot
after Broker handoff. Build, lint, typecheck, diff checks, and the focused
Edge/approval keyring suite pass 10/10. Production cross-process delivery,
signing identity, and final shutdown evidence remain open. Evidence:
`evidence/2026-09-15-authentication-key-memory-lifecycle.md`.

Backup-cleanup verification at source revision `f25c900` applies one protected
same-directory quarantine primitive to retention, stale temporary, restore,
publication, and decrypt-failure removals. Expected file identity is checked
before and after quarantine; failures restore without overwriting a newcomer.
Build, lint, typecheck, diff checks, and a physical encrypted-backup prune
probe pass. Fresh full persistence and orphan-quarantine recovery evidence
remain open. Evidence:
`evidence/2026-09-15-backup-cleanup-target-fence.md`.

Filesystem unlink target-swap verification at source revision `a6971fc` uses
exclusive same-directory quarantine rename plus post-rename device/inode/type/
link-count validation; mismatches restore by non-overwriting `linkat`. Build,
lint, typecheck, diff checks, 40 filesystem inspector/patch tests, and a
physical temp-root removal probe pass. Orphan-quarantine crash recovery and
production packaging remain open. Evidence:
`evidence/2026-09-15-filesystem-unlink-quarantine.md`.

Credential-retirement verification at source revision `737ab3a` fences
revoked file-backed key retirement with digest and owner/mode/device/inode/
size/mtime checks before and after quarantine rename, non-overwriting recovery,
and key-buffer clearing. The physical Keychain-enabled credential suite passes
11/11; build, lint, typecheck, documentation-link, and diff checks pass.
Production Keychain distribution, installed helper recovery, and final release
approval remain open. Evidence:
`evidence/2026-09-15-credential-retirement-fence.md`.

UNKNOWN write recovery verification: source revision `2fadf8a` retries only a
prior `TEMPORARY_CLEANUP_SKIPPED` result and reuses the persisted exact target
and temporary name. Existing root, symlink, and device/inode checks remain in
force; no write is replayed or promoted. A physical-host probe and regression
coverage verify skip-then-safe-removal behavior; build, lint, and typecheck
pass. Evidence: `evidence/2026-09-15-write-recovery-retry.md`.

UNKNOWN process recovery verification: source revision `436917d` retries a
restart-reconciled task only when the prior result was
`PROCESS_RECOVERY_UNKNOWN`; the same persisted process identity is used and no
task execution is replayed. Definitive drained, absent, and identity-mismatch
results remain terminal. A physical-host probe and regression coverage verify
unknown-then-drained recovery; build, lint, and typecheck pass. Evidence:
`evidence/2026-09-15-process-recovery-retry.md`.

Persistence backup publication verification: source revision `8e57790` uses
same-directory hard-link publication for encrypted backup creation and fresh
restore, so an existing destination cannot be replaced after an existence
check. Source identity is revalidated at publication and identity comparisons
include device, inode, owner, mode, size, and modification time. The added
restore no-replace regression plus a physical-host probe preserve an existing
destination and return `CONFLICT`; build, lint, typecheck, and diff checks
pass. Evidence:
`evidence/2026-09-15-persistence-backup-publication.md`.

Documentation navigation verification: the new dependency-free
`npm run verify:docs` check rejects README local-link escapes or unavailable
targets and requires eight named testing/configuration/deployment/operations/
incident/rollback/kill-switch/persistence runbooks. The physical host check
passed for 29 local links and all 8 runbooks; this does not promote draft
runbooks to production procedures. Evidence:
`evidence/2026-09-15-documentation-link-check.md`.

Production signing readiness verification: a read-only physical-host probe on
2026-09-15 found `0 valid identities` from `security find-identity -v -p
codesigning`. The rebuilt native adapter passes strict ad-hoc verification but
reports an ad-hoc/linker-signed CodeDirectory with no TeamIdentifier or
Developer ID provenance. This keeps MOP-061 root installation and all
privileged enablement fail-closed; no root LaunchDaemon mutation was attempted.
Evidence: `evidence/2026-09-15-production-signing-readiness.md`.

Keychain trusted-executable ownership verification: source revisions
`7f725bf` and `0c21edb`
binds the ACL executable to the current process owner in both the TypeScript
boundary and macOS native adapter. Missing POSIX identity, foreign ownership,
writable modes, symlinks, and non-canonical paths fail closed before secret
access; the native layer repeats the owner check with `geteuid()` around its
canonical-path double-read and now includes UID/mode in its before/after
identity fence. Focused peer/credentials/helper suites pass 30/30 with
`MOPS_REAL_KEYCHAIN=1`, and the latest physical non-overlapping regression
passes 618/618 with zero skips and zero failures. The existing Broker/Persistence
process was not restarted. Evidence:
`evidence/2026-09-15-keychain-trusted-executable-ownership.md`.

Root-helper Keychain ACL binding verification: source revisions `4bc0308`,
`666a978`, and `711f3e4` keep the BrokerStore-backed factory bound to the
Broker executable while the no-`BrokerStore` root-helper loader requires an
explicit canonical helper executable path for a Keychain-backed helper key
and verifies the item's non-secret ACL/protection metadata before loading key
bytes. Missing or non-canonical binding is rejected with a stable error before
Keychain access. Focused helper keyring/runtime tests pass 10/10; focused
credential tests pass 14/14 with one explicit physical Keychain skip. The
latest physical non-overlapping regression passes 617/617 with zero skips and
zero failures. The existing Broker/Persistence process was not restarted. Evidence:
`evidence/2026-09-15-root-helper-keychain-acl-binding.md`.

Privileged helper runtime disposal verification: source revision `2ce0945`,
with failed-cleanup coverage in test revision `ccb248b`, makes the runtime
dispose its separately authenticated authority poller on startup failure,
failed server cleanup, and close-before-start paths. Disposal is idempotent,
and a runtime whose poller has been disposed cannot be restarted with wiped
authority material. Focused runtime tests pass 6/6, and
the latest physical non-overlapping regression passes 616/616 with zero skips
and zero failures. The existing Broker/Persistence process was not restarted.
Evidence: `evidence/2026-09-15-privileged-helper-runtime-disposal.md`.

Root-helper authority-poller construction verification: source revision
`a79d813` removes injectable authority-poller selection from the no-
`BrokerStore` root-helper factory. When an adapter is enabled, startup must
construct `PrivilegedHelperAuthorityClient` from the fixed authority socket
and native Broker peer policy; a missing socket fails closed. Focused runtime
tests pass 5/5, and the latest physical non-overlapping regression passes
615/615 with zero skips and zero failures. Evidence:
`evidence/2026-09-15-privileged-helper-poller-construction.md`.

Privileged helper authority-socket ACL verification: source revision
`fe9d681` adds an independent Broker-owned socket readback. It requires a
Unix socket at the planned endpoint, expected Broker UID/GID, no group/other
permissions, and stable device/inode/mode/ownership across two reads. The
socket remains outside the root-owned helper filesystem set. Focused package
tests pass 14/14, and the latest physical non-overlapping regression passes
615/615 with zero skips and zero failures. Evidence:
`evidence/2026-09-15-privileged-helper-authority-socket-acl.md`.

Privileged helper package authority-socket verification: source revision
`ee2c934` binds the root-domain package plan and runtime status readback to the
Broker-owned `helperAuthoritySocketPath`. The plan rejects socket reuse and
rejects placing the authority endpoint inside the root-owned helper package;
readback must match all three socket identities. Focused helper/package/status
tests pass 31/31, and the prior physical non-overlapping regression passes
614/614 with zero skips and zero failures. Evidence:
`evidence/2026-09-15-privileged-helper-package-authority-socket.md`.

Privileged helper key-material isolation verification: source revision
`e786002` (building on `2c3e01d`) adds a root-helper startup factory that does
not accept or open `BrokerStore`. It loads only protected local key material,
keeps local validity checks, and requires a separately authenticated Broker
authority poller whenever an adapter is enabled. The prior BrokerStore-backed
factory remains available for Broker-side activation and compatibility paths.
Focused helper/runtime/keyring/authority tests pass 11/11, and the latest
physical non-overlapping regression passes 614/614 with zero skips and zero
failures. Evidence:
`evidence/2026-09-15-privileged-helper-key-material.md`.

Privileged helper authority-polling IPC verification: source revision
`2c3e01d` (building on `b9d038a`, `d717525`, `2660bdf`, `becea16`, and
`1eea5cb`) adds a separately authenticated helper-to-Broker authority channel,
wires the Broker listener into native startup with rollback, wipes copied keys
on setup failure, and strictly validates failure bodies. It also rejects
root-as-Broker and non-root-as-helper peer-role substitutions at production
startup boundaries.
The Broker endpoint uses native/explicit peer authentication, a
direction-specific HMAC envelope, durable replay admission, nested command
authentication, and the Broker-backed Request/Approval/Job authority gate.
The helper client authenticates the Broker peer, fences socket identity,
verifies bounded response proofs, and clears key material. Active helper work
polls before dispatch, during execution, and before success publication;
authority loss after execution begins is reported as retryable
`UNKNOWN_OUTCOME`. Enabled adapters are rejected at runtime construction when
no authority poller is supplied. Focused helper/authority tests pass 18/18,
runtime/keyring tests pass 7/7, native startup assembly tests pass 8/8, and
the prior physical non-overlapping regression passes 613/613 with zero skips
and zero failures. The existing
Broker/Persistence process was not restarted. Evidence:
`evidence/2026-09-15-privileged-authority-polling-ipc.md`.

Broker-backed privileged authority verification: source revision `91806ae`
adds a reusable final authority callback for helper IPC. It reconstructs
Request/Approval/Job identity from durable state and rejects disabled
switches, Edge/key/principal/session revocation, cancelled or non-running
Jobs, expired approvals, and command/intent identity substitution. The
combined helper/executor/dispatch suite passes 26/26. The latest physical
non-overlapping regression passes 607/607 with zero skips and zero failures;
the existing Broker/Persistence process was not restarted. Evidence:
`evidence/2026-09-15-privileged-authority-gate.md`.

Privileged cancellation and lease verification: source revision `6fab84d`
closes the pre-dispatch cancellation race, rechecks cancellation after helper
command signing, preserves `UNKNOWN_OUTCOME` when cancellation occurs after
helper dispatch, and proves bounded lease renewal for long helper calls. The
focused executor/dispatch suite passes 12/12. The latest physical
non-overlapping regression passes 606/606 with zero skips and zero failures
under all three physical gates; the existing Broker/Persistence process was
not restarted. Evidence:
`evidence/2026-09-15-privileged-cancellation-lease-regression.md`.

Privileged Broker dispatch verification: source revision `1f7451b` connects all
three L5 contracts to normalized payload planning, explicit approval intent,
Broker-owned Job lease transitions, and the separately authenticated helper
executor. The default helper and policy remain disabled; a focused fake-helper
integration suite passes 3/3 and confirms no Job is created when the helper
boundary is unavailable. This does not claim helper signing, root-domain
installation, real privileged adapters, or privileged enablement. Evidence:
`evidence/2026-09-15-privileged-broker-dispatch.md`.

Post-dispatch physical regression verification: source revision `1f7451b`
passes 602/602 non-overlapping built tests with zero skips and zero failures
under all three physical gates. This is a regression checkpoint for existing
host boundaries, not real privileged-action, Developer ID, root-domain, or
production-enablement evidence; the long-running Broker/Persistence suites
were not restarted. Evidence:
`evidence/2026-09-15-real-privileged-dispatch-regression.md`.

Physical secret-boundary regression verification: source revision `356ebd4`
passes 598/598 non-overlapping built tests with zero skips and zero failures
under all three physical gates. Real sandbox, temporary Keychain ACL, and
Edge/Broker LaunchAgent bootstrap/bootout checks ran; this does not close
production signing, VM isolation, remote issuer, helper installation, or
`mac_task_run` enablement. Evidence:
`evidence/2026-09-15-real-secret-boundary-regression.md`.

Latest secret-boundary regression verification: source revision `f921714`
passes 598 non-overlapping built tests (592 passed, 6 explicit opt-in skips,
0 failed) after shared local-process and virtualization guest secret checks.
The existing Broker/Persistence process remained undisturbed; production
signing, installation, isolation, and helper release gates remain open.
Evidence: `evidence/2026-09-15-secret-boundary-full-regression.md`.

Process environment secret-value verification: source revision `98b36ac`
rejects known token/credential/authorization signatures in explicitly
allowlisted environment values before local process or virtualization guest
dispatch, and guest task arguments reject protected credential options. The
focused process, task-profile, and guest suites pass 51/51; this does not
close VT-SBX-01/02, production credential isolation, or `mac_task_run`
enablement. Evidence:
`evidence/2026-09-15-process-environment-secret-values.md`.

Broker lifecycle verification: source revision `6297c58` serializes Broker
service startup and shutdown around the native runtime and passes the focused
service-entrypoint suite 3/3. This closes the local lifecycle race boundary
only; installed identity, remote deployment, and release gates remain open.
Evidence: `evidence/2026-09-15-broker-lifecycle-serialization.md`.

Edge lifecycle verification: source revision `04132fe` serializes Edge
startup and shutdown transitions and passes the focused service-startup suite
5/5. This closes the local lifecycle race boundary only; installed launchd
identity, remote deployment, and release gates remain open. Evidence:
`evidence/2026-09-15-edge-lifecycle-serialization.md`.

Latest local regression verification: the serial built test set excluding the
already-running Broker/persistence suites passes 595 total (589 passed, 6
explicitly skipped, 0 failed). The run includes normalized failure-target,
credential-field, and secret-shaped-string redaction coverage. Evidence:
`evidence/2026-09-15-latest-local-regression.md`.

Physical Darwin sandbox verification: with `MOPS_REAL_SANDBOX=1` exported to
the test processes, the non-overlapping built set passes 595 total (593
passed, 2 explicitly skipped, 0 failed) on Darwin arm64/macOS 26.2. Real
sandbox, protected-surface, fork/`setsid`, TCP/UDP allowlist, and active
cancellation checks ran; real Keychain ACL and temporary install remain
explicitly skipped. Evidence:
`evidence/2026-09-15-real-sandbox-regression.md`.

Physical Keychain/install verification: with all three physical gates
exported, the non-overlapping built set passes 595/595 with 0 skips and 0
failures. Real temporary Keychain ACL retirement and per-user Edge/Broker
LaunchAgent bootstrap, authenticated readback, and bootout passed; a post-test
`launchctl print` readback confirmed both fixed labels absent. Evidence:
`evidence/2026-09-15-real-install-keychain-regression.md`.

Audit-evidence redaction verification: the persistence and privileged-helper
response boundaries cover common API/access/refresh token, client/HMAC/
signing/SSH key, bearer/JWT, password/passphrase, cookie, credential, and
private/secret field aliases; persistence also sanitizes secret-shaped string
values under ordinary fields. Focused alias/content and helper tests pass with
safe fields unchanged. This defense-in-depth check does not close VT-SEC-01/02
or prove physical credential isolation. Evidence:
`evidence/2026-09-15-audit-evidence-redaction.md`.

Failure-audit target verification at source revision `3ed2e02` confirms that
post-authorization failures retain the Broker-normalized `host:broker` target
in both decision and completion audit rows, while earlier failures remain
`unresolved`. The existing focused assertion and a built-distribution harness
pass; full Broker/persistence suites were not restarted because an existing
long-running process was active. Evidence:
`evidence/2026-09-15-failure-audit-target.md`.

Schema-startup verification at source revision `183ecd4` confirms malformed
persistence versions, migration registries, runtime fences, replay schemas,
and metadata migrations fail with stable `AUDIT_UNAVAILABLE` errors. Unknown
column injection across every persisted table passes 2/2; the non-overlapping
package regression passes 593 total (587 passed, 6 explicitly skipped, 0
failed). Production crash recovery, signing/Keychain, installed lifecycle,
isolation, disk exhaustion, and independent review remain unverified. Evidence:
`evidence/2026-09-15-core-schema-layout.md`.

Schema-migration readback verification at source revision `a26e6d8` opens
legacy Request and Job SQLite layouts, reads historical rows without
fabricating new authority metadata, and confirms the current complete
post-migration column sets. This is temporary local migration evidence only;
production backup restore, crash recovery, disk exhaustion, and release
upgrade/rollback remain unverified. Evidence:
`evidence/2026-09-15-schema-migration-readback.md`.

Core-schema-layout addendum: commit `a26e6d8` verifies the complete
post-migration column set for every Broker persistence table and rejects
unknown or missing columns as `AUDIT_UNAVAILABLE`. The schema-layout test passes 1/1; the
non-overlapping package regression passes 592 total (586 passed, 6 explicitly
skipped, 0 failed). This is local schema-shape evidence only; physical crash
recovery, production signing/Keychain, installed lifecycle, isolation, disk
exhaustion, and independent review remain unverified. Evidence:
`evidence/2026-09-15-core-schema-layout.md`.

Local-gate checkpoint at source revision `a26e6d8`: native canonical-JSON
vectors pass 5/5, dependency audit reports zero high-severity vulnerabilities,
lint passes for 602 tracked files, and `git diff --check` passes. The
non-overlapping package regression passes 592 total (586 passed, 6 explicitly
skipped, 0 failed); the existing Broker/persistence test processes were not
restarted, so their fresh completion is not claimed. Working tree is clean and
no remote push was performed. Evidence:
`evidence/2026-09-15-final-local-gates.md`.

Persisted Job-output integrity addendum: commit `1cfc62c` revalidates bounded,
secret-free stdout/stderr plus exit-code, cancellation-reason, and metadata
types before startup recovery or status publication. Job-row/state tests pass
7/7 and Request-link tests pass 3/3; the non-overlapping package regression
passes 591 total (585 passed, 6 explicitly skipped, 0 failed). This proves
local persisted-output fencing only; crash recovery, old-worker ownership,
credential rotation, remount durability, installed operation, and independent
security review remain unverified. Evidence:
`evidence/2026-09-15-job-output-integrity.md`.

Request-link integrity addendum: commit `24c0641` validates Request-to-Job
linkage inside the Broker transaction and cross-checks every persisted
Approval/Job reference at startup. Missing references and owner/session/tool/
target/policy/Edge substitutions fail closed with stable errors. Focused link
tests pass 3/3; the non-overlapping package regression passes 590 total (584
passed, 6 explicitly skipped, 0 failed). The envelope digest and
argument-level Approval/Job digests remain independent by contract. This is
local cross-ledger evidence only; crash recovery, credential rotation,
remount durability, installed recovery, and independent security review remain
unverified. Evidence:
`evidence/2026-09-15-request-link-integrity.md`.

Authority-ledger startup-integrity addendum: commit `ba34100` scans every
persisted Approval, Revocation, and Kill-switch row before policy evaluation,
request admission, or recovery. Malformed approval lifecycle fields,
authority identities/targets, revocation subjects, and switch state fail closed
as `AUDIT_UNAVAILABLE`. Focused authority startup tests pass 5/5; the combined
Request/Job/Approval/authority slice passes 15/15; the non-overlapping package
regression passes 587 total (581 passed, 6 explicitly skipped, 0 failed).
This proves local persisted authority fencing only; production Keychain,
external rollback, crash recovery, installed operation, and approval UI remain
unverified. Evidence:
`evidence/2026-09-15-authority-ledger-startup-integrity.md`.

Request-ledger startup-integrity addendum: commit `040284a` scans every
persisted Request before restart reconciliation and rejects malformed identity,
tool, policy, payload-digest, capability-family, lifecycle, and mutation-link
fields as `AUDIT_UNAVAILABLE`. Focused Request-state/startup tests pass 4/4;
the non-overlapping package regression passes 587 total (581 passed, 6
explicitly skipped, 0 failed). This proves local persisted-ledger fencing only;
physical crash recovery, old-worker ownership, credential rotation, remount
durability, and production task enablement remain unverified. Evidence:
`evidence/2026-09-15-request-ledger-startup-integrity.md`.

Filesystem-worker result boundary addendum: commits `5657267` and `86a6792`
enforce operation-specific exact fields, plain-data nested records, dense
bounded arrays, and bounded scalar values before filesystem results reach the
Broker. Storage analysis now strips the internal volume `rootPath` field at
the producer boundary; contract conformance therefore cannot be broken by
internal planning metadata. Focused filesystem and contract-conformance
tests pass 3/3; the non-overlapping package regression passes 521 total
(515 pass, 6 skipped, 0 fail). This proves local result-shape integrity only;
native provenance, remount, sandbox/credential/VM isolation, persistence,
and capability enablement remain unverified.
Evidence: `evidence/2026-09-15-filesystem-worker-result-boundary.md`.

Read-only adapter result-boundary addendum: commits `a9d1b2a` and `e1ae276`
enforce exact public field sets and plain data across native network and
Broker-owned JXA app/Accessibility outputs. Address/listener/node arrays are
dense and bounded; unknown fields and malformed nested records are rejected
before result projection, target identity, or sensitive-label handling.
Focused app/UI/network tests pass 15/15; the non-overlapping package
regression passes 523 total (517 pass, 6 skipped, 0 fail). This proves local
result-shape integrity only; native provenance, permission-granted GUI,
sandbox/credential/VM isolation, persistence, and capability enablement
remain unverified.
Evidence: `evidence/2026-09-15-readonly-adapter-result-boundaries.md`.

Virtualization VM result-boundary addendum: commit `c22fc98` rejects native
guest lifecycle results unless transition/status records are plain data with
the exact declared fields. Guest identity parsing remains digest/runtime
bound, while boot/state readbacks are checked before publication. Focused
native VM lifecycle tests pass 9/9; the non-overlapping package regression
passes 524 total (518 pass, 6 skipped, 0 fail). This proves local VM result
shape integrity only; native attestation production, VM/credential/
persistence isolation, and task enablement remain unverified.
Evidence: `evidence/2026-09-15-virtualization-vm-result-boundary.md`.

Persisted Job readback addendum: commits `2cc1db7`, `937ffcd`, and `5f4980d` validate
stored app-open/app-focus/UI-action/write/patch result envelopes as plain
records with exact nested fields before a completed Job is reused. Invalid
stored records map to `UNKNOWN_OUTCOME`; no malformed payload can become a
verified postcondition. Focused persisted-result tests pass 2/2; the
non-overlapping package regression passes 527 total (521 pass, 6 skipped,
0 fail). This proves stored-result shape integrity only; SQLite corruption,
crash ownership, disk exhaustion, service recovery, and final release gates
remain unverified.
Evidence: `evidence/2026-09-15-persisted-job-readbacks.md`.

Process worker executor addendum: commit `8a9a89c` routes worker inventory and
detail results through the strict native process parsers before Broker use.
Exact fields, plain-data records, dense bounded arrays, and fresh projection
are now shared across both boundaries. Focused process executor/inspector
tests pass 6/6; the non-overlapping package regression passes 528 total
(522 pass, 6 skipped, 0 fail). This proves local process-result integrity
only; native provenance, process ownership, kernel limits, and production
task enablement remain unverified.
Evidence: `evidence/2026-09-15-process-worker-executor-boundary.md`.

Filesystem native-result addendum: commit `645f57b` rejects unknown,
inherited, symbolic, accessor, and sparse fields in native stat/read/hash/
list/write/unlink/storage results before filesystem policy or postcondition
logic. Directory entries and returned buffers are copied into fresh records.
Focused filesystem tests pass 37/37; the non-overlapping package regression
passes 530 total (524 pass, 6 skipped, 0 fail). This proves local native
filesystem result integrity only; physical remount, kernel I/O, provenance,
and production resource limits remain unverified.
Evidence: `evidence/2026-09-15-filesystem-native-result-boundary.md`.

Audit-anchor readback addendum: commit `e54a862` requires exact plain-data
sidecar and native lock-recovery records before MAC/tail verification or
identity-bound unlink. Focused audit-anchor tests pass 8/8; the
non-overlapping package regression passes 530 total (524 pass, 6 skipped,
0 fail). SQLite corruption, key provenance, disk exhaustion, and installed
service recovery remain unverified.
Evidence: `evidence/2026-09-15-audit-anchor-result-boundary.md`.

Process-worker result boundary addendum: commit `a01b62e` requires native
process inventory/detail results to be plain records with exact fields and
bounded uid/child identities. The generic worker envelope accepts only its
declared success or failure fields, rejecting extra result data before it can
be consumed. Focused process-inspector/worker tests pass 14/14; the
non-overlapping package regression passes 520 total (514 pass, 6 skipped,
0 fail). This proves local result-shape integrity only; production native
provenance, sandbox/credential/VM isolation, persistence, and enablement
remain unverified.
Evidence: `evidence/2026-09-15-process-worker-result-boundary.md`.

Task-profile request snapshot addendum: commit `04f77eb` takes a synchronous
copy of the validated TaskProfileRegistry request before cwd/root/executable
readback awaits. Profile selection, argument validation, process arguments,
and output of the resolved process request use only the copy. A hostile test
mutates arguments immediately after `resolve()`; the result retains the
authorized value. Focused task-profile tests pass 6/6; the non-overlapping
package regression passes 518 total (512 pass, 6 skipped, 0 fail). This proves
one local task-request TOCTOU control only; production sandbox, credential,
VM, persistence, and task enablement remain unproven.
Evidence: `evidence/2026-09-15-task-profile-request-snapshot.md`.

Guest-request snapshot addendum: commit `31dc880` snapshots the authenticated
guest task request and nested identity before asynchronous profile target
readback. Adapter input, ledger identity, timeout/output budgets,
cancellation, response digest, and terminal recovery are derived only from
that snapshot. A hostile test mutates request identity, digest, budget, and
nested guest identity immediately after `execute()`; the adapter and response
retain the original values. Focused guest executor tests pass 11/11; the
non-overlapping package regression passes 517 total (511 pass, 6 skipped,
0 fail). This proves one local guest-request TOCTOU control only; it does not
prove native attestation production, VM/credential/persistence isolation, or
task enablement.
Evidence: `evidence/2026-09-15-guest-request-snapshot.md`.

Guest-profile boundary addendum: commit `5f67e18` validates startup-owned
Virtualization guest profiles and unsigned digest-bound requests as plain
records with exact known fields. Dense bounded arrays and plain environment
data are required before digest lookup or asynchronous target readback;
prototype, accessor, hidden/symbolic, sparse, unknown-field, and inherited
authority shapes fail closed. The focused guest executor suite passes 10/10;
the non-overlapping package regression passes 516 total (510 pass, 6 skipped,
0 fail). This proves manifest/request representation integrity only; it does
not prove native attestation production, VM boot/isolation, credential or
persistence isolation, or task enablement.
Evidence: `evidence/2026-09-15-guest-profile-boundary.md`.

Process-request snapshot addendum: commit `aa8040e` takes a synchronous
snapshot of the plain, exact-shape ProcessSupervisor request before any
asynchronous target identity check. Subsequent spawn, capacity, environment,
callback, stability, and cancellation operations read only the snapshot. A
hostile test mutates executable, args, cwd, and environment immediately after
calling `run`; the result still uses the authorized values. Focused
process-supervisor/task-profile/task-runner tests pass 50/50; the
non-overlapping package regression passes 515 total (509 pass, 6 skipped,
0 fail). This proves one local request TOCTOU control only; it does not prove
production sandbox, credential isolation, VM, persistence, or task
enablement.
Evidence: `evidence/2026-09-15-process-request-snapshot.md`.

Process-request boundary addendum: commit `78dd404` validates the
ProcessSupervisor request at the Broker boundary before child admission.
Only plain records with the declared fields are accepted; executable/cwd
paths are canonical absolute paths, argument arrays are dense and bounded,
environment data is plain and non-inherited, resource limits are bounded
safe integers, and control callbacks must be functions. Hostile prototype,
accessor, hidden/symbolic, unknown-field, sparse-array, environment, and
callback shapes fail closed without spawning. Focused
process-supervisor/task-profile/task-runner tests pass 49/49; the
non-overlapping package regression passes 514 total (508 pass, 6 skipped,
0 fail). This proves request-shape integrity only; it is not evidence of
production sandbox, credential isolation, VM, persistence, or task
enablement.
Evidence: `evidence/2026-09-15-process-request-boundary.md`.

Task-profile authority-shape addendum: commit `956e95f` makes named
TaskProfile documents and task-run requests accept only plain records with
known fields. Path, argument, and network arrays must be dense bounded string
arrays; environment data rejects accessors/inherited fields; resolved
arguments are copied before execution. The focused task-profile/task-runner
suite passes 18/18; the non-overlapping package regression passes 513 total
(507 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff checks pass.
This proves local task-profile representation integrity only; sandbox,
credential, VM, and `mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-task-profile-authority-shape.md`.

Task-runner result-boundary addendum: commit `0c486c9` applies plain-data and
exact-field validation to host isolation proofs and runner results. Inherited,
accessor, symbolic, and unknown fields are rejected; result verification keeps
only its declared optional summary, and UTF-8 output/duration bounds are
checked before Broker persistence or audit. The focused task-runner and guest
attestation suite passes 19/19; the non-overlapping package regression passes
512 total (506 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff
checks pass. This proves local result-shape integrity only; production
sandbox, credential isolation, VM, and `mac_task_run` gates remain open.
Evidence: `evidence/2026-09-15-task-runner-result-boundary.md`.

Filesystem mutation rename-race addendum: commit `e83bf1e` adds a
physical-host atomic-write race harness alongside the read harness. It
repeatedly renames an authorized child directory, replaces it with an outside
symlink, and restores it while bounded writes execute. Successful write
readbacks remain under the canonical authorized root, and the outside file is
unchanged. The focused filesystem suite passes 34/34; the non-overlapping
package regression passes 511 total (505 pass, 6 skipped, 0 fail); build,
typecheck, lint, and diff checks pass. Physical remount, broader volume, and
production resource evidence remain open.
Evidence: `evidence/2026-09-15-filesystem-mutation-rename-race.md`.

Filesystem directory-rename race addendum: commit `7fe59fd` adds a
physical-host runtime race harness that repeatedly renames an authorized child
directory, replaces it with an outside symlink, and restores it during bounded
descriptor-relative reads. Successful results contain only authorized bytes;
outside resolution is rejected. The focused filesystem suite passes 33/33; the
non-overlapping package regression passes 510 total (504 pass, 6 skipped,
0 fail); build, typecheck, lint, and diff checks pass. This covers runtime
directory create/rename behavior but physical remount, broader volume, and
production resource evidence remain open.
Evidence: `evidence/2026-09-15-filesystem-directory-rename-race.md`.

Filesystem root-descriptor addendum: commit `6fb5372` makes native filesystem
target opens descriptor-relative to a pinned authorized root, with
traversal-free relative conversion and canonical parent handling for
macOS path aliases. Metadata/list/read/hash and atomic write/unlink boundaries
now use `openat`/`fstatat`/`renameat`/`unlinkat` under that descriptor.
Filesystem focused tests pass 32/32; the non-overlapping package regression
passes 509 total (503 pass, 6 skipped, 0 fail); build, typecheck, lint, and
diff checks pass. Physical remount and broader volume/resource evidence remain
open.
Evidence: `evidence/2026-09-15-filesystem-root-descriptor-binding.md`.

System-published guest-image addendum: commits `e00554c`, `f74e485`, and
`a08d2a5` add a
startup-owned
publication mode and requires the native Virtualization.framework path to
accept only root-owned, canonical, non-symlink images with a non-writable
unprivileged publication boundary. The native C++ preflight repeats the
policy before pathname attachment; every canonical ancestor is checked to
prevent writable-grandparent renames; root Broker execution is rejected.
Focused image/native suites pass 12/12;
the non-overlapping package regression passes 508 total (502 pass, 6 skipped,
0 fail); build, typecheck, lint, and diff checks pass. This mitigates
unprivileged pathname target replacement but does not close root rotation,
atomic descriptor attachment, VM boot, guest isolation, or production task
enablement.
Evidence: `evidence/2026-09-15-system-published-guest-image.md`.

Nested authenticated-data addendum: commit `54fe71a` requires plain-data
records for helper payloads/results/verification/evidence, Broker and Helper
status readbacks, and nested authority/status failures before canonicalization
or redaction. Focused authority-control, Broker-status, and privileged-helper
suites pass 17/17; the non-overlapping package regression passes 506 total
(500 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff checks pass.
This proves local nested parser integrity only and does not close production
peer, packaging, VM, credential, helper, or capability gates.
Evidence: `evidence/2026-09-15-nested-authenticated-data.md`.

Guest attestation data-shape addendum: commit `d276615` applies the shared
plain-data-record check to the signed attestation envelope, payload, and
nested guest identity before digest/signature verification. Inherited,
hidden, symbolic, and accessor-bearing values fail closed as
`POLICY_DENIED`. The focused attestation suite passes 6/6; the
non-overlapping package regression passes 505 total (499 pass, 6 skipped,
0 fail); build, typecheck, lint, and diff checks pass. This proves local
provenance parser integrity only and does not close VM, key-distribution,
native-producer, or capability gates.
Evidence: `evidence/2026-09-15-guest-attestation-data-shapes.md`.

Operator IPC data-shape addendum: commit `8ed6e298` applies the shared
plain-data-record check to policy-signer command and approval issuance
parsers, including the nested approval payload. Inherited, hidden, symbolic,
and accessor-bearing authority fields fail closed before proof/digest
verification or persistence. Focused policy-signer and approval suites pass
14/14; the non-overlapping package regression passes 504 total (498 pass,
6 skipped, 0 fail); build, typecheck, lint, and diff checks pass. This proves
local parser integrity only and does not close protected key, packaging, VM,
helper, or capability gates.
Evidence: `evidence/2026-09-15-operator-ipc-data-shapes.md`.

Real sandbox readback addendum: the physical Mac mini run at source revision
`a8b4660` executes `MOPS_REAL_SANDBOX=1 node --test
packages/broker/dist/sandbox-profile.test.js` with 16/16 passing and no skips.
It provides current-host evidence for deny-default profile behavior,
protected-surface/environment denials, loopback TCP/UDP allowlists,
fork/setsid denial, and cancellation. This remains partial evidence for the
deprecated candidate and does not close VT-SBX-01/02, MOP-043/045, or
production task enablement.
Evidence: `evidence/2026-09-15-real-sandbox-16-tests.md`.

Authenticated IPC data-shape addendum: commit `27e102b` applies a shared
plain-data-record check to Authority Control, Broker Status, Privileged Helper,
and Virtualization Guest authenticated parsers. Accessor, hidden, symbolic,
and prototype-bearing envelopes fail closed before proof verification or
dispatch. Focused IPC tests pass 32/32; the non-overlapping package regression
passes 502 total (496 pass, 6 skipped, 0 fail); build, typecheck, lint, and
diff checks pass. This covers parser integrity only and does not close OS peer,
production packaging, VM, credential, helper, or capability gates.
Evidence: `evidence/2026-09-15-authenticated-ipc-data-shapes.md`.

Signed request data-shape addendum: commit `14d3cc0` validates every request
value before authentication, requiring data-only ordinary/null-prototype
records and dense bounded arrays. Inherited, hidden, accessor, sparse,
cyclic, symbolic, and unsupported values fail closed as `AUTH_INVALID`.
Security-fuzz tests pass 8/8; the non-overlapping package regression passes
498 total (492 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff
checks pass. This covers direct in-process request integrity only and does not
close production transport, VM, credential, helper, or capability gates.
Evidence: `evidence/2026-09-15-request-data-shape.md`.

Request object authority-boundary addendum: commit `8a8f335` makes
`parseBrokerRequest()` reject prototype-bearing envelope, argument, and
principal records before the signed request can reach authentication,
authorization, audit admission, or execution. Security-fuzz tests pass 8/8;
the non-overlapping package regression passes 498 total (492 pass, 6 skipped,
0 fail); build, typecheck, lint, and diff checks pass. This covers direct
in-process request shape integrity only and does not close transport, policy,
VM, credential, helper, or capability gates.
Evidence: `evidence/2026-09-15-request-object-authority-boundary.md`.

Policy prototype authority-boundary addendum: commit `b164da0` makes
`validateBrokerPolicy()` reject prototype-bearing records at every strict
field boundary, including kill switches, key windows, principal grants, and
tool policies. Policy tests pass 4/4; the security-fuzz policy corpus passes
7/7; the non-overlapping package regression passes 497 total (491 pass,
6 skipped, 0 fail); build, typecheck, lint, and diff checks pass. This covers
in-memory policy shape integrity only and does not close production signing,
Keychain distribution, VM isolation, privileged helper, or capability gates.
Evidence: `evidence/2026-09-15-policy-prototype-authority-boundary.md`.

Guest executor close-recovery addendum: commit `3245482` fences new guest
work, aborts active adapters, always waits for active executions, and clears a
rejected cleanup Promise for explicit retry while preserving the fence. Guest
executor tests pass 10/10; the non-overlapping package regression passes 496
total (490 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff checks
pass. This closes only guest executor shutdown recovery and does not provide VM
boot/isolation, native attestation, credential isolation, or production task
enablement. Evidence: `evidence/2026-09-15-guest-executor-close-recovery.md`.

Broker shutdown recovery addendum: commit `505d28a` keeps `closing` asserted
after shutdown starts, rejects new work with `CANCELLED`, and clears only the
rejected aggregate close Promise so an explicit host retry can finish resource
cleanup. Broker close tests pass; the non-overlapping package regression passes
495 total (489 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff checks
pass. This closes local Broker cleanup retry semantics only and does not prove
installed service recovery, VM/guest isolation, credential isolation, helper
operation, or capability enablement. Evidence:
`evidence/2026-09-15-broker-close-recovery.md`.

Virtualization guest attestation key-validity addendum: commit `5aa7d2e`
requires a signed assertion's full issued/expiry interval to be contained by
the trusted Ed25519 key validity window. The focused attestation suite passes
5/5; the non-overlapping package regression passes 495 total (489 pass, 6
skipped, 0 fail); build, typecheck, lint, and diff checks pass. This closes
only signed key-window binding; native attestation production, protected key
distribution, VM boot/isolation, and production task enablement remain open.
Evidence: `evidence/2026-09-15-virtualization-guest-attestation-key-validity.md`.

Virtualization guest runtime close-recovery addendum: commits `d68176b` and
`28007cf` keep `VirtualizationGuestRuntimeImpl` open and retryable after a
failed close, clearing the rejected promise cache, fencing new start/stop work
while a close retry is pending, and requiring a later successful close before
setting the terminal closed state. Virtualization startup tests pass 3/3; the
non-overlapping package regression passes 494 total (488 pass, 6 skipped, 0
fail); build, typecheck, lint, and diff checks pass. This closes only the
local shutdown-recovery boundary and does not provide VM boot, guest isolation,
credential isolation, signing, or `mac_task_run` evidence.
Evidence: `evidence/2026-09-15-virtualization-guest-runtime-close-recovery.md`.

Darwin descriptor-exec boundary addendum: on Darwin 25.2.0 arm64, the
installed SDK exposes no public `fexecve`/`execveat` declaration and no
executable-file-descriptor `posix_spawn` operation. A direct `/dev/fd/N`
execution probe returned status 126 (`Permission denied`). This is recorded as
a host capability limitation; no pathname shim is treated as atomic descriptor
execution. `VT-FS-02` and production task enablement remain open. Evidence:
`evidence/2026-09-15-darwin-descriptor-exec-boundary.md`.

Descriptor-exec SDK follow-up: a compiled macOS 26.2 probe confirmed that
`posix_spawn_file_actions_addfchdir` and descriptor inheritance are available,
but executable selection through `/dev/fd/<fd>` still returns `Permission
denied` for both `posix_spawn` and direct `execve`. Cwd-descriptor support is
therefore not executable-descriptor proof, and the production gate remains
closed. Evidence: `evidence/2026-09-16-descriptor-exec-sdk-probe.md`.

Process argv false-positive addendum: source revision `7231964` restricts
sensitive option-name matching to explicit Unix options and preserves
full-argument concrete token-signature scanning. Real-Darwin sandbox tests pass
16/16 after the canary-script regression was fixed; focused process/secret
tests pass 35/35 and the non-overlapping package regression passes 494 total
(488 pass, 6 skipped, 0 fail). Build, typecheck, lint, and diff checks pass.
This does not prove opaque-secret classification or production credential
isolation. Evidence: `evidence/2026-09-15-secret-argv-script-boundary.md`.

Capability-list integrity addendum: source revision `399a17c` makes the Edge
reject duplicate and unregistered capability names plus malformed name/version
fields before registering MCP tools. The non-overlapping package regression
passes 494 total (488 pass, 6 skipped, 0 fail); Edge tests, contract
validation, build, lint, and diff checks pass. No capability is enabled by
this change, and production host/VM/credential/privileged evidence remains
open. Evidence: `evidence/2026-09-15-capability-list-integrity.md`.

Capability lifecycle-state addendum: source revision `e22f025` adds required
`planned`, `implemented`, and `enabled` fields to each `mac_capabilities` item.
The Broker emits the full state and the Edge rejects an enabled item with an
inconsistent state before tool registration. Focused Broker/Edge tests pass;
the non-overlapping package regression passes 493 total (487 pass, 6 skipped,
0 fail); 44 contracts validate; build, typecheck, lint, and diff checks pass.
This does not enable disabled capabilities or prove production host, VM, credential, or
privileged-helper evidence. Evidence:
`evidence/2026-09-15-capability-lifecycle-states.md`.

Worker startup-failure addendum: `BoundedWorkerExecutor.run` catches a
synchronous worker-factory exception, returns stable `EXECUTION_FAILED`, and
does not consume active capacity. Worker-executor tests pass 8/8; the
non-overlapping package regression passes 492 total (486 pass, 6 skipped,
0 fail); build, typecheck, lint, and diff checks pass. This does not prove worker sandboxing, credential
separation, or production task-runner enablement. Evidence:
`evidence/2026-09-15-worker-startup-failure-boundary.md`.

Edge JWKS response-status addendum: source revision `fc04641` requires a 2xx
remote JWKS response before body handling or `jose` parsing. JWT tests pass
8/8, all Edge tests pass 41/41, and the non-overlapping physical-Darwin
regression passes 491 total (485 pass, 6 skipped, 0 fail). Build, typecheck,
lint, and diff checks pass. External issuer, DNS/TLS, rotation/revocation
propagation, and remote deployment evidence remain open. Evidence:
`evidence/2026-09-15-edge-jwks-status-boundary.md`.

Edge JWKS redirect-boundary addendum: source revision `c97140a` rejects
redirected responses and non-empty final URLs that differ from the configured
JWKS endpoint before `jose` parsing. JWT tests pass 7/7, all Edge tests pass
40/40, and the non-overlapping physical-Darwin regression passes 490/490 with
0 skipped tests. Build, typecheck, lint, and diff checks pass. External issuer,
DNS/TLS, rotation/revocation propagation, and remote deployment evidence
remain open. Evidence:
`evidence/2026-09-15-edge-jwks-redirect-boundary.md`.

Process-argument secret-boundary addendum: source revision `17d10e2` denies
credential-bearing argv option names and known token signatures at fixed
profile load, task argument resolution, and the final child spawn boundary.
Secret-policy tests pass 5/5, task-profile tests pass 4/4,
process-supervisor tests pass 30/30, and the non-overlapping physical-Darwin
regression passes 489/489 with 0 skipped tests. Build, typecheck, lint,
contract, canonical-JSON, audit, and diff checks pass. This closes the known
argv signature boundary only; opaque secrets and production task isolation
remain separate gates. Evidence:
`evidence/2026-09-15-process-argument-secret-boundary.md`.

Edge remote-JWKS response addendum: source revision `3cca22c` bounds remote
JWKS bodies to 256 KiB with a streaming reader and accepts only
`application/json` or `application/jwk-set+json` before handing the response to
`jose`. JWT tests pass 6/6, all Edge tests pass 39/39, and the non-overlapping
physical-Darwin regression passes 488/488 with 0 skipped tests. Build,
typecheck, lint, contract, canonical-JSON, audit, and diff checks pass. This
does not claim external issuer, rotation/revocation propagation, or remote
deployment evidence. Evidence:
`evidence/2026-09-15-edge-jwks-response-boundary.md`.

Virtualization lifecycle timeout-fence addendum: source revision `ea85237`
fences a native lifecycle operation after caller-visible timeout or
cancellation until the underlying promise settles. A delayed-start regression
rejects overlapping status with retryable `UNKNOWN_OUTCOME` and then permits
status recovery after settlement. Lifecycle tests pass 7/7; the focused
guest/transport/lifecycle/startup/native/task-runner suite passes 86/86; and
the non-overlapping physical-Darwin regression passes 486/486 with 0 skipped
tests. Build, typecheck, lint, and diff checks pass. This does not claim VM
boot, guest isolation, remount resistance, or production `mac_task_run`
enablement. Evidence:
`evidence/2026-09-15-virtualization-guest-lifecycle-timeout-fence.md`.

Process-supervisor early-capture addendum: source revision `efb9d5c` records
bounded child output and lifecycle events immediately after spawn so fast
children cannot evade later observer registration. Process-supervisor tests
pass 30/30; the non-overlapping physical-Darwin regression passes 485/485
with 0 skipped tests. Build, typecheck, lint, and diff checks pass. This
addresses an observer race only; descriptor/fexec atomicity, remount
resistance, production isolation, and `mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-process-supervisor-early-capture.md`.

Guest-executor close-drain addendum: source revision `9f772fe` waits for
tracked active adapter executions after cancellation and adapter shutdown,
preventing close from returning while guest work remains live. Guest executor
tests pass 8/8; the combined guest/transport/lifecycle/startup/native suite
passes 53/53 with 0 skipped tests. Build, typecheck, lint, and diff checks
pass. VM boot, guest isolation, and production `mac_task_run` enablement are
not claimed. Evidence:
`evidence/2026-09-15-virtualization-guest-close-drain.md`.

Guest-executor admission-concurrency addendum: source revision `eb9aa47`
reserves guest capacity before asynchronous manifest resolution and checks
active plus pending admissions against `maxConcurrent`. Focused guest executor
tests pass 8/8; the combined guest/transport/lifecycle/startup/native suite
passes 53/53 with 0 skipped tests. Build, typecheck, lint, and diff checks
pass. VM boot, guest isolation, and production `mac_task_run` enablement are
not claimed. Evidence:
`evidence/2026-09-15-virtualization-guest-concurrency.md`.

Guest-bootstrap timeout-cancellation addendum: source revision `9148013`
aborts the per-connection guest controller before stream close on deadline or
transport failure, propagating a stable cancellation signal into the guest
executor. Bootstrap tests pass 6/6; the combined guest/transport/lifecycle/
startup/native focused suite passes 52/52 with 0 skipped tests. Build,
typecheck, lint, and diff checks pass. No VM boot, guest isolation, or
production `mac_task_run` enablement is claimed. Evidence:
`evidence/2026-09-15-virtualization-guest-bootstrap-timeout.md`.

Task-profile startup-wiring addendum: startup now accepts a host-owned
`TaskProfileRegistry` only alongside an explicit sandbox or virtualization
runner, validates its callable surface, and injects it into the Broker. A
runnerless or malformed registry fails closed before startup state is touched;
the packaged default remains an empty registry with the fail-closed runner.
Service-startup tests pass 7/7; a gated physical-Darwin smoke also verifies
one fixed profile through startup, native UDS, approval, sandbox, and Job
readback, while an approved read of the protected Broker database is denied
with `VERIFICATION_FAILED` and a failed Job. Credential/process isolation and
production `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-task-profile-startup-wiring.md`.

Task-profile regex-safety addendum: source revision `c42c7a8` rejects
oversized, nested-group, alternation, backreference-bearing, and unbounded-
range argument patterns before compilation, while preserving the bounded
anchored patterns used by current profiles. Task-profile tests pass 4/4;
production sandbox and descriptor/fexec evidence remain open. Evidence:
`evidence/2026-09-15-task-profile-regex-safety.md`.

Sandbox startup-wiring addendum: source revision `2e605ea` gives service
startup an explicit host-only sandbox runner seam, derives protected
package/data/runtime roots, and rejects competing virtualization and sandbox
runner configuration. Service-startup passes 5/5 and sandbox-profile passes
16/16. Build, lint, contract, native canonical, and diff checks pass. The
packaged default remains fail-closed and `mac_task_run` remains disabled until
real startup, credential, process-tree, and remount evidence exists. Evidence:
`evidence/2026-09-15-sandbox-startup-wiring.md`.

Sandbox UDP addendum: source revision `02fec55` verifies a physical-Darwin
loopback UDP allowlist: the listed port receives the task datagram, while an
unlisted port fails without delivery. Sandbox-profile passes 16/16 and the
complete serial physical-Darwin suite passes 607/607 with 0 skipped tests.
Build, lint, contract, native canonical, and diff checks pass. This does not
close external networking, DNS, process-tree, or production task-runner gates.
Evidence: `evidence/2026-09-15-sandbox-udp.md`.

Sandbox protected-root addendum: source revision `5fb0f3a` adds host-provided
canonical Broker-owned protected roots to the Seatbelt profile and places
read/write deny rules after task allows. The real-Darwin smoke verifies a
synthetic persistence root is denied despite being listed as an allowed task
root; sandbox-profile passes 15/15 and the complete serial physical-Darwin
suite passes 606/606 with 0 skipped tests. Build, lint, contract, native
canonical, and diff checks pass. Startup wiring now exists as an explicit host
seam, but the packaged default remains disabled until real Broker paths and
remount/descriptor, persistence, and credential claims are verified. Evidence:
`evidence/2026-09-15-sandbox-protected-roots.md`.

Executable-content identity addendum: source revision `a0e62e2` binds the
Broker executable target to device/inode/mode, ordinary file metadata, and a
bounded SHA-256 digest read through an `O_NOFOLLOW` descriptor across
validation, startup, ownership persistence, and final readback. A Darwin
regression rewrites the authorized executable at the same path/inode and
receives stable `POLICY_DENIED`; ProcessSupervisor passes 29/29,
sandbox-profile passes 15/15, and the complete serial physical-Darwin suite
passes 606/606 with 0 skipped tests. Build, lint, contract, native canonical,
and diff checks pass. Descriptor/fexec atomicity, remount resistance, and
production task enablement remain open. Evidence:
`evidence/2026-09-15-process-executable-content-identity.md`.

Sandbox-root identity addendum: source revision `f562bc2` captures every
unique task filesystem-root directory's device/inode/mode identity and
rechecks it after startup ownership capture and after execution. A non-cwd
root replacement is rejected with stable `POLICY_DENIED`; the physical-Darwin
suite passes 604/604 with 0 skipped tests. Build, typecheck, lint, contract
verification, native canonical probe, and diff checks pass. This closes the
implemented root-path swap detection boundary, not in-syscall remount or
kernel-held descriptor atomicity. Evidence:
`evidence/2026-09-15-sandbox-root-identity.md`.

Sandbox-task path addendum: source revision `2599502` binds the actual task
executable and cwd carried inside the `sandbox-exec` argument vector to
Broker-captured device/inode/mode identities. The startup callback is awaited
so its identity and filesystem checks complete before active ownership is
persisted; final readback repeats the checks. The target-swap regression and
complete physical-Darwin suite pass 603/603 with 0 skipped tests. Build,
typecheck, lint, contract verification, native canonical probe, and diff
checks pass. This closes inner-task startup swap detection, not an atomic
kernel descriptor/fexec race proof. Evidence:
`evidence/2026-09-15-sandbox-task-path-identity.md`.

Process-path identity addendum: source revision `5efe002` captures canonical
executable and cwd device/inode/mode identities before child creation and
rechecks them after spawn and after startup ownership callbacks. A changed or
missing target aborts the process group and only returns the stable denial
after cleanup is verified; uncertain cleanup maps to `UNKNOWN_OUTCOME`. The
target-swap regression and complete physical-Darwin suite pass 602/602 with
0 skipped tests. Build, typecheck, lint, contract verification, native
canonical probe, and diff checks pass. This closes the observed startup
target-swap boundary, not a kernel-held descriptor/fexec race proof.
Evidence: `evidence/2026-09-15-process-path-identity.md`.

Policy-helper gate addendum: source revision `21559e7` applies full
`BrokerPolicy` validation to every policy authorization/discovery helper, not
only the main ToolPolicy authorization path. The updated 256-iteration policy
mutation corpus uses complete policy objects and confirms projected scopes and
deny-overrides-allow cannot be expanded through a partial or malformed object.
The complete physical-Darwin regression passes 601/601 with 0 skipped tests;
build, typecheck, lint, contract verification, native canonical probe, and
diff checks pass. This closes helper-entry policy validation only; signed
policy provenance, installed-service evidence, and final release acceptance
remain open. Evidence: `evidence/2026-09-15-policy-helper-gate.md`.

Runtime-policy semantic-validation addendum: source revision `83a733e`
validates the full in-memory Broker authority shape before capability use,
including exact top-level/nested fields, key validity windows, principal grant
scope membership, duplicate rule/root identities, normalized filesystem roots,
and target-kind/reference binding. Malformed target or key authority fails
closed with stable `POLICY_DENIED` errors. The complete physical-Darwin
regression passes 601/601 with 0 skipped tests; build, typecheck, lint,
contract verification, native canonical probe, and diff checks pass. This
closes the runtime policy semantic boundary only; signed-policy provenance,
installed-service evidence, and final release acceptance remain open.
Evidence: `evidence/2026-09-15-runtime-policy-semantics.md`.

Runtime-policy snapshot addendum: source revision `0be82c4` isolates active
Broker authority from mutable caller references by deep-copying policy maps,
sets, arrays, and nested entries at plain-policy construction and every
PolicyManager transition/readback. Target rules and kill switches therefore
cannot be expanded or changed through a retained object reference after the
authority handoff. Focused Broker/policy selection passes 82 tests (76 passed,
6 explicit platform skips); the complete physical-Darwin regression passes
601/601 with 0 skipped tests. Build, typecheck, lint, contract verification,
native canonical probe, and diff checks pass. This closes the in-memory
authority-reference boundary only; signed-policy provenance, package signing,
installed-service evidence, and final release acceptance remain open.
Evidence: `evidence/2026-09-15-policy-authority-snapshot.md`.

Runtime-policy validation addendum: source revision `ee994a8` validates the
Broker policy shape at construction, policy-manager transitions, and each
authorization call. The gate rejects malformed metadata and ToolPolicy
authority (unknown tool keys, contract drift, invalid scope/family/target or
approval values, unsafe timeout/output budgets, and enabled unimplemented
tools) before capability discovery or execution. Policy and PolicyManager
tests pass 17/17; the complete physical-Darwin regression passes 600/600 with
0 skipped tests. Build, typecheck, lint, contract verification, native
canonical probe, and diff checks pass. This closes the in-memory policy
shape boundary only; signed-policy supply-chain protection, package signing,
installed-service evidence, and final release acceptance remain open.
Evidence: `evidence/2026-09-15-runtime-policy-validation.md`.

Runtime contract-integrity addendum: source revision `2dedae0` hardens Edge
contract loading with non-symlink directory/file checks, group/other-write
denial, and device/inode/mode readback before and after loading. Focused
contract-registry tests pass 5/5; the complete physical-Darwin regression
passes 598/598 with 0 skipped tests. This protects the runtime MCP contract
surface but does not replace Broker authorization or close package-signing and
installed-service release gates. Evidence:
`evidence/2026-09-15-runtime-contract-integrity.md`.

Idempotency authorization addendum: source revision `d715512` hardens
`BrokerStore.createJob` so idempotent Job reuse requires the same policy
version as the original authorized operation, in addition to principal, tool,
target, and payload digest. A policy-version substitution returns stable
`CONFLICT` before reuse. Focused persistence and full regression tests pass;
the mutation release gate remains open for broader crash, concurrency, and
installed-service evidence. Evidence:
`evidence/2026-09-15-idempotency-policy-binding.md`.

Strict UTF-8 boundary addendum: source revision `1ce5bee` applies fatal
UTF-8 decoding before JSON parsing across implemented local/guest IPC,
protected configuration, persistence, audit, and Edge contract paths.
Malformed bytes are rejected without replay admission or mutation. Focused
boundary tests pass 78/78, the native canonical JSON probe passes 5/5
vectors, and the complete physical-Darwin suite passes 587/587 with 0 skipped
tests. Build, typecheck, lint, contract verification, and diff checks pass.
Broader numeric canonicalization compatibility, duplicate-key handling, and
release evidence remain unproven. Evidence:
`evidence/2026-09-15-strict-utf8-boundary.md`.

Strict JSON parser addendum: source revision `ecc3a98` adds bounded recursive
validation before `JSON.parse` across implemented protocol, protected
configuration, persistence, audit, and Edge contract readers. Duplicate keys
(including escaped equivalents), unpaired UTF-16 surrogates, malformed grammar,
and trailing data are rejected before replay admission or mutation. Focused
trust-boundary tests pass 49/49, the native canonical JSON probe passes 5/5
vectors, and the complete physical-Darwin suite passes 588/588 with 0 skipped
tests. Build, typecheck, lint, contract verification, and diff checks pass.
Broader numeric canonicalization compatibility, runtime fuzzing, and release
evidence remain unproven. Evidence:
`evidence/2026-09-15-strict-json-parser.md`.

Runtime strict-JSON addendum: source revision `0bcb354` applies
`parseJsonStrict` to implemented child-adapter, Authority Control IPC,
stored-result, Job metadata, audit, and encrypted-backup evidence readers
before validation or canonical hashing. Static schema loading and parser
internals remain separate trusted implementation inputs. Targeted runtime-reader
tests pass 79/79 and the complete physical-Darwin suite passes 592/592 with
0 skipped tests. Build, typecheck, lint, contract verification, and diff
checks pass. Broader numeric canonicalization compatibility, runtime fuzzing,
and final release evidence remain unproven. Evidence:
`evidence/2026-09-15-runtime-strict-json-boundaries.md`.

Cross-runtime number addendum: source revision `c31f82a` compares every strict
JSON numeric token with the canonical lexical form emitted by Node's
ECMAScript `JSON.stringify`, rejecting precision-changing integers,
rounding-divergent fractions, underflow, overflow, and oversized exponents
before authentication or persistence. Focused canonical JSON tests pass 5/5;
the complete physical-Darwin suite passes 593/593 with 0 skipped tests.
Build, typecheck, lint, contract verification, native canonical probe, and
diff checks pass. Independent native number-vector expansion and final release
evidence remain unproven. Evidence:
`evidence/2026-09-15-cross-runtime-json-number-canonicalization.md`.

Capability-family capacity addendum: source revisions `db129b3`, `0b7d3b9`, `d7c4689`, and `8ad120b` add schema-v9
request markers and durable BrokerStore admission gates for independent
read/write/process/network/gui/destructive/privileged families. Family
selection comes from the active Broker policy, is persisted before
authorization, and is counted under the same SQLite `BEGIN IMMEDIATE`
transaction across handles. Empty legacy markers count against every requested
family; malformed stored markers fail closed as `AUDIT_UNAVAILABLE`, including
when the new request is family-less. Focused Broker/persistence tests pass
123/123 with 6 explicit skips; the complete physical-Darwin suite passes
597/597 with 0 skipped tests; RequestRecord and the versioned ledger schema
read back the resolved family list while preserving legacy records; malformed
readback is rejected as `AUDIT_UNAVAILABLE`. Build,
typecheck, lint, contract verification, native canonical probe, and diff
checks pass. Adapter-specific semantic quotas, kernel/disk/depth limits,
installed service evidence, and final release acceptance remain unproven.
Evidence: `evidence/2026-09-15-capability-family-capacity.md`.

Durable request-capacity addendum: source revision `31e89f0` enforces global
and principal/session active-request limits inside BrokerStore's
`BEGIN IMMEDIATE` admission transaction. Defaults are global 64 and per
principal/session 8, with hard maxima 256/64; retryable `CONFLICT` is returned
before durable nonce/request state, and terminal/restart reconciliation frees
capacity. Cross-handle persistence and Broker constructor tests pass; full
physical-Darwin suite passes 589/589 with 0 skipped tests. Build, typecheck,
lint, contract verification, and diff checks pass. Process/adapter-specific
quotas, disk/depth budgets, and final release evidence remain unproven.
Evidence: `evidence/2026-09-15-durable-request-capacity.md`.

Process-quota addendum: source revision `a135396` adds a Broker-owned
per-executable admission gate to the shared ProcessSupervisor. Active and
pending starts for one canonical executable share a default cap of 4 while
the Broker-wide pool remains bounded at 16. Focused ProcessSupervisor tests
pass 26/26; the complete physical-Darwin suite passes 592/592 with 0 skipped
tests. Build, typecheck, lint, contract verification, and diff checks pass.
Adapter-specific semantic quotas, disk/depth budgets, kernel-level resource
limits, and final release evidence remain unproven. Evidence:
`evidence/2026-09-15-process-quota-isolation.md`.

Broker session-concurrency addendum: source revisions `d185f12` and `9d92f0d` validate
request-age and clock-skew limits before Broker startup and reserves at most
eight active requests per principal/session by default (hard maximum 64).
Saturated sessions receive retryable `CONFLICT` before durable admission or
audit; release is verified on success and failure paths. Broker focused tests
pass 78/78, the native canonical JSON probe passes 5/5 vectors, and the
complete physical-Darwin suite passes 585/585 with 0 skipped tests. Build,
typecheck, lint, contract verification, and diff checks pass. Cross-process
global quotas, installed service packaging, and final release evidence remain
unproven. Evidence:
`evidence/2026-09-15-broker-session-concurrency.md`.

Approval TTL-gate addendum: source revision `0ab3fc9` checks the signed
Approval TTL against the current Broker clock before Approval or audit
persistence; current-expired nonce and Approval regressions pass without
creating records. Approval Authority/IPC tests pass 10/10 and the complete
physical-Darwin suite passes 583/583 with 0 skipped tests. Build, typecheck,
lint, contract verification, and diff checks pass. Human approval UI,
protected production issuer-key storage, and unattended profile ownership
remain unproven. Evidence: `evidence/2026-09-15-approval-ttl-gate.md`.

Task isolation proof addendum: source revision `7a101d9` requires and
normalizes `persistence: "isolated"` in every `TaskIsolationProof`; strict
validation rejects missing or non-isolated persistence claims before a runner
can be available. Proof/guest-startup tests and the complete physical-Darwin
suite pass (582/582, 0 skipped); build, typecheck, lint, contract verification,
and diff checks pass. This is contract hardening, not real host persistence,
credential, VM isolation, or `mac_task_run` enablement evidence. Evidence:
`evidence/2026-09-15-task-persistence-proof.md`.

Approval issuance expiry-gate addendum: source revision `8552210` checks the
current clock against the signed Approval issuance nonce expiry before
approval persistence or audit. A current-expired signed request leaves no
Approval or audit record. Approval Authority/IPC tests pass 9/9; the complete
physical-Darwin suite passes 582/582 with 0 skipped tests. Build, typecheck,
lint, contract verification, and diff checks pass. This verifies only the
source-level expiry gate; protected production issuer-key storage, human
approval UI, and unattended profile ownership remain unproven. Evidence:
`evidence/2026-09-15-approval-expiry-gate.md`.

IPC expiry-gate addendum: source revision `6947608` checks current nonce and
command expiry for Privileged Helper command/status authentication before
replay admission, authorization, adapter dispatch, or status readback, and
checks current Policy Signer nonce expiry before manager mutation. Structurally
valid stale Helper errors remain response-authenticated; malformed envelopes
use the fallback proof. Focused Helper tests pass 9/9 and Policy Signer tests
pass 2/2; the complete physical-Darwin suite passes 581/581 with 0 skipped
tests. Build, typecheck, lint, contract verification, and diff checks pass.
This verifies only source-level IPC expiry gates; installed launchd/root helper
ownership, production key distribution, and real privileged execution remain
unproven. Evidence: `evidence/2026-09-15-ipc-expiry-gates.md`.

Broker Status IPC error-proof addendum: source revision `ad3adc9` binds
structurally valid status requests to authenticated `AUTH_EXPIRED` and
`REPLAY_DENIED` failure responses before freshness/auth checks. Unknown fields
remain on the invalid-request fallback, and the candidate never reaches replay
admission or status execution. The focused Broker Status IPC test passes 1/1;
the complete physical-Darwin suite passes 581/581 with 0 skipped tests. Build,
typecheck, lint, contract verification, and diff checks pass. Evidence:
`evidence/2026-09-15-broker-status-error-proof.md`.

Authority Control CLI and IPC error-proof addendum: source revisions
`447e4aa`, `f359360`, `5962efc`, and `032bf8f`
provide a bounded
operator entrypoint for switch readback, expected-state switch mutation, and
identity revocation. It restores the exact active key through the Broker key
manager, rejects raw key/command/capability inputs, requires explicit mutation
confirmation, and performs authenticated readback before reporting success.
Focused CLI tests pass 4/4, including a protected-file/authenticated-IPC
round trip; Authority Control IPC tests pass 3/3, including stable
authenticated `AUTH_EXPIRED` readback without admission, audit, or mutation
side effects. The complete physical-Darwin suite passes 581/581 with 0 skipped
tests. Build, typecheck, lint, contract verification, and diff
checks pass. This verifies only the source-level operator boundary; installed
launchd ownership, active process-tree termination, and production key
distribution remain unproven. Evidence:
`evidence/2026-09-15-authority-control-cli.md`.

Privileged helper command-factory disposal addendum: the command factory now
wipes its defensive HMAC-key copy at an idempotent disposal boundary and
rejects later issuance with stable `CANCELLED`. Focused privileged-helper
tests pass 9/9; the complete physical-Darwin suite passes 576/576 with 0
skipped tests. Build, typecheck, lint, contract verification, and diff checks
pass. This verifies Broker-side factory credential lifetime only; production
operator-key distribution, Developer ID/root helper installation, real
privileged adapters, and deployed kill-switch readback remain unproven.
Evidence: `evidence/2026-09-15-privileged-helper-factory-disposal.md`.

Virtualization guest active-I/O drain addendum: Native VM handles track
Broker-owned Virtio connections and close tracked connections before stop or
close, while late callbacks close immediately after the atomic shutdown state
is set. Reference release is fenced by tracking removal. This verifies the
host-side active-I/O cleanup boundary only; VM boot, guest isolation, and
attestation remain unproven. Native lifecycle build, focused VM-native tests
(7/7), typecheck, lint, contract verification, diff check, and the complete
physical-Darwin suite (576/576, 0 skipped) pass. Evidence:
`evidence/2026-09-15-virtualization-native-connection-drain.md`.

Virtualization guest native-handle fencing addendum: the native lifecycle
handle validity marker is atomic, is not reset by retained async transition
completion, and the dispatch queue remains alive until the external handle is
finalized. This closes a native use-after-close resurrection/null-queue race;
it does not claim VM boot or guest isolation evidence. Native lifecycle build,
focused VM-native tests (7/7), typecheck, lint, contract verification, diff
check, and the complete physical-Darwin suite (576/576, 0 skipped) pass.
Evidence: `evidence/2026-09-15-virtualization-native-handle-fencing.md`.

Local IPC shutdown-drain addendum: Broker, Approval, Authority Control,
Broker Status, Policy Signer, and Privileged Helper Node UDS servers track and
destroy accepted sockets before close waits. The idle-peer regression passes;
the cross-channel IPC suite passes 29/29 and the complete physical-Darwin
suite passes 575/575 with 0 skipped tests. Build, typecheck, lint, contract
verification, and diff checks pass. Evidence:
`evidence/2026-09-15-local-ipc-shutdown-drain.md`.

Broker IPC framing addendum: the authenticated Broker server rejects
non-whitespace trailing bytes after its first frame before JSON parsing or
Broker admission. A clean retry succeeds and proves no replay/audit state is
consumed by the rejected frame. Focused Broker IPC tests pass 6/6; the
complete physical-Darwin suite passes 574/574 with 0 skipped tests. Build,
typecheck, lint, contract verification, and diff checks pass. Evidence:
`evidence/2026-09-15-local-ipc-framing-hardening.md`.

Approval IPC framing addendum: the owner-only approval server rejects
non-whitespace trailing bytes after its first authenticated frame, before
issuer verification, replay admission, approval creation, or audit. The
trailing-frame regression and clean retry pass; the complete physical-Darwin
suite passes 574/574 with 0 skipped tests. Build, typecheck, lint, contract
verification, and diff checks pass. Evidence:
`evidence/2026-09-15-local-ipc-framing-hardening.md`.

Approval issuer key lifecycle addendum: `ApprovalAuthority` keeps only
defensive issuer-key copies, wipes and clears them on idempotent disposal,
and returns stable `CANCELLED` failures after disposal. The focused approval
authority/IPC suite passes 8/8; build and diff checks pass. Evidence:
`evidence/2026-09-15-approval-key-lifecycle.md`.

Authority-control key lifecycle addendum: the Authority Control client copies
and explicitly wipes its HMAC key, rejects use after disposal, and leaves the
caller-owned source buffer under its original lifecycle. Authority Control
and Privileged Helper servers wipe their copied keys even when socket
detachment fails. Focused Authority Control tests pass 2/2, Privileged Helper
IPC tests pass 9/9, and the complete physical-Darwin suite passes 573/573
with 0 skipped tests; build, typecheck, lint, contract verification, and diff
checks pass. Evidence:
`evidence/2026-09-15-authority-control-key-lifecycle.md`.

Local IPC framing hardening addendum: Privileged Helper, Policy Signer, and
Broker Status servers and clients now fail closed on non-whitespace trailing
frames after the first authenticated message; Policy Signer key copies are
wiped on close. Framing regressions and the
complete physical-Darwin suite pass 573/573 with 0 skipped tests; typecheck,
lint, contract verification, and diff checks pass. Evidence:
`evidence/2026-09-15-local-ipc-framing-hardening.md`.

Capability kill-switch readback addendum: `mac_capabilities` now checks the
Broker-owned persisted switch and signed policy kill-switch for each enabled
family before reporting it as available. Focused coverage verifies both
process-switch sources. The complete physical-Darwin regression passes
572/572 with 0 skipped tests; typecheck, lint, contract verification, and diff
checks pass. Evidence:
`evidence/2026-09-15-capability-kill-switch-readback.md`.

Authority-control framing addendum: non-whitespace trailing bytes after the
single newline-delimited command are rejected before replay admission or any
authority mutation. Focused tests pass 2/2 and the complete physical-Darwin
suite passes 571/571 with 0 skipped tests. Evidence:
`evidence/2026-09-15-authority-control-framing.md`.

Authority-control restart readback addendum: a fresh authenticated IPC client
now reads persisted switch and revocation state after BrokerStore/server
reopen, while replayed authority mutations remain denied. Focused tests pass
2/2 and the complete physical-Darwin suite passes 571/571 with 0 skipped
tests. Installed operator identity and active-work termination evidence remain
open. Evidence:
`evidence/2026-09-15-authority-control-restart-readback.md`.

Guest transport shutdown hardening addendum: active host exchanges are now
abortable during client close, with closed-state checks before send and result
publication. Focused transport tests pass 15/15 and the complete
physical-Darwin suite passes 571/571 with 0 skipped tests. Evidence:
`evidence/2026-09-15-virtualization-guest-transport-close.md`.

Guest-agent shutdown hardening addendum: `VirtualizationGuestAgent` now
tracks active task/status handlers, propagates caller aborts, aborts all active
handlers during close, and checks authority again before response signing.
Focused tests pass 4/4 and the complete physical-Darwin suite passes 571/571
with 0 skipped tests. This proves only the protocol-service shutdown race is
closed; VM boot, guest isolation, and `mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-virtualization-guest-agent.md`.

Latest guest bootstrap addendum: a bounded guest-side frame service now keeps
the protocol loop independent from the native vsock acceptor. It enforces an
explicit enable gate, one request/response per connection, frame/response and
concurrency caps, one deadline across read/agent/write, trailing-data
rejection, stream cleanup, shutdown cancellation, and guest-agent key disposal.
Focused tests pass 5/5 and the complete physical-Darwin suite passes 560/560
with 0 skipped tests;
typecheck, lint, and diff checks pass. This does not prove a production
AF_VSOCK acceptor, VM boot, guest isolation, or `mac_task_run` enablement.
Evidence: `evidence/2026-09-15-virtualization-guest-bootstrap.md`.

Virtio listener addendum: the native Virtualization.framework artifact now
installs a startup-owned fixed-port listener and exposes bounded asynchronous
accept/read/write/close operations through a TypeScript
`VirtualizationGuestConnectionSource`. Pending connections and external
handles are drained on listener/VM close, and an aborted accept closes a late
connection rather than leaking it. Focused VM/listener tests pass 6/6 and the
complete physical-Darwin suite passes 562/562 with 0 skipped tests; typecheck,
lint, and diff checks pass. This proves only the host-side listener seam, not a
guest AF_VSOCK service, bootable image, guest isolation, attestation production,
or `mac_task_run` enablement. Evidence:
`evidence/2026-09-15-virtualization-guest-vsock-listener.md`.

Guest profile executor addendum: the Guest registry verifies the shared
profile/task digest material, denies shell and unsafe environment manifests,
rechecks canonical executable/cwd/filesystem targets, bounds concurrency and
output, and records terminal results for authenticated status recovery. Error
summaries and streams are redacted before transport, and active work is
cancelled before executor close can publish success. The concrete process
adapter is unavailable without explicit isolation evidence. Focused
guest-executor tests pass 7/7 and the complete physical-Darwin suite passes
569/569 with 0 skipped
tests; typecheck, lint, and diff checks pass. This proves manifest/executor
semantics only, not VM boot or real guest isolation. Evidence:
`evidence/2026-09-15-virtualization-guest-executor.md`.

Latest startup composition addendum: the startup-only
`virtualizationGuest` seam composes image identity verification, native VM
lifecycle, a fixed virtio port, an optional guest-initiated listener source,
authenticated transport, replay admission, and the virtualization runner. If
explicitly enabled, the guest starts before
restart reconciliation and is closed before Broker persistence; with no seam,
the prior fail-closed runner remains in force. Focused startup tests pass 3/3,
the service-startup tests pass 3/3, and the complete physical-Darwin suite
passes 555/555 with 0 skipped tests; typecheck, lint, and diff checks pass. The
host still rejects the synthetic image before VM creation, so this is startup
composition/ordering evidence only and does not prove VM boot, guest serving,
isolation, attestation production, or production `mac_task_run` enablement.
Evidence: `evidence/2026-09-15-virtualization-guest-startup.md`.

Latest virtio connector addendum: commit `b8551d6` adds a native
`VZVirtioSocketDevice.connectToPort` connector and TypeScript channel adapter.
It accepts only an existing Broker VM handle, bounds port/request/response
bytes and one monotonic deadline, rejects truncated or trailing frames, and
releases connections on callback races. Focused lifecycle/native/channel tests
pass 10/10. The complete
`MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
regression passes 552/552 with 0 skipped tests; typecheck and lint pass. The
current host rejects the synthetic VM configuration before creation, so no
guest server, VM boot, or isolation is claimed. Evidence:
`evidence/2026-09-15-virtualization-guest-virtio-connector.md`.

Latest native virtualization lifecycle addendum: commit `40f0461` adds a
separate Objective-C++ N-API artifact linked to `Virtualization.framework` and
loads it through a protected, digest-bound startup path. The native config uses
a read-only guest disk, no host network or directory sharing, and a future
virtio-socket device; asynchronous handle-bound lifecycle methods return and
validate an adapter-owned boot ID. Focused lifecycle/adapter tests pass 9/9;
the complete
`MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
regression passes 551/551 with 0 skipped tests; typecheck and lint pass. The
current host rejects the synthetic configuration before VM creation, so this
does not prove VM boot or guest isolation and no production capability is
enabled. Evidence:
`evidence/2026-09-15-virtualization-guest-native-lifecycle.md`.

Latest Broker virtualization lifecycle addendum: commit `042517a` adds a
disabled-by-default lifecycle controller around a future native VM adapter.
Operations are serialized and bounded; identity and boot ID are validated on
start/stop/status, cancellation and timeout fail closed, and uncertain
operations remain `unknown` until status recovery. Focused lifecycle tests pass
5/5. The complete
`MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
regression passes 547/547 with 0 skipped tests; typecheck and lint pass. This
does not demonstrate VM boot, guest transport serving, or independent guest
isolation, so no production capability is enabled. Evidence:
`evidence/2026-09-15-virtualization-guest-lifecycle.md`.

Latest guest-agent addendum: commit `c8a856e` adds a bounded
`VirtualizationGuestAgent` protocol service. It verifies signed request
freshness, guest/profile binding, and replay identity before invoking a
guest-owned executor, signs request-bound task/status responses, enforces
bounded frames, and exposes no host paths, executable arguments, or
credentials. Focused tests pass 3/3; the complete
`MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
regression passes 542/542 with 0 skipped tests. This does not prove a native
guest server, VM boot, guest isolation, or production `mac_task_run`
enablement. Evidence:
`evidence/2026-09-15-virtualization-guest-agent.md`.

Latest native Virtualization guest-preflight addendum: commit `7de8385` adds a
protected N-API artifact that revalidates a startup-bound canonical image,
constructs a read-only `VZDiskImageStorageDeviceAttachment`, and reports empty
host network/directory-sharing device sets without booting a VM. Focused native
tests pass 2/2; the full
`MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
regression passes 539/539 with 0 skipped tests. This is native
image/configuration readback only. A valid production image, VM boot/lifecycle,
guest channel server, signed attestation producer, isolation evidence, and
production `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-native-virtualization-guest-preflight.md`.

Latest canonical JSON wire-profile addendum: commits `7860a00`, `a26a188`,
`1aa0eea`, and `ae2e9eb`
publish the versioned `jcs-utf8-v1` serialization profile, exact
`canonicalJsonUtf8` byte helper, and an independent bounded native Swift
standard-library probe. Five fixed vectors cover nested values, escaping,
number formatting, Unicode ordering without normalization, and empty values;
focused TypeScript tests pass 2/2, native readback passes 5/5, the full
physical-Darwin regression passes 537/537 with 0 skipped tests, and typecheck
passes. The protected C++ N-API artifact passes the same five digest vectors
plus empty-input and 1 MiB cap checks. Production
Swift/C++ adapter interoperability, VM isolation, and release acceptance
remain open. Evidence:
`evidence/2026-09-15-canonical-json-wire-profile.md`.

Latest guest-attestation keyring addendum: commits `73148a6`, `db83881`, and `c56aa0a` add a startup-only
Broker manager for protected Ed25519 public-key configuration. Owner-only
canonical files are opened with `O_NOFOLLOW`, device/inode and digest bound,
size limited, and rejected on duplicate paths, weak modes, replacement, or
non-Ed25519 content. The schema-version-8 migration persists independent
activation/rollback history and the dedicated `guest_attestation_key`
revocation kind; each verifier checks that revocation dynamically. Focused
persistence/keyring tests pass 50/50 and the physical-Darwin full regression
passes 533/533. Private guest signing keys are never loaded by the host; native
producer, Keychain distribution, VM boot/isolation, and capability enablement
remain open. The policy, policy-signer, and guest verification loaders also
reject private-key material before constructing trusted public keys. Packaged
startup restores an optional dataRoot-bound trust set before listeners or
recovery. Evidence:
`evidence/2026-09-15-virtualization-guest-attestation-keyring.md`.

Latest signed guest-provenance addendum: commit `84da3e0` defines a versioned
Ed25519 envelope covering the guest key ID, algorithm, issue/expiry window,
payload digest, and complete digest-bound attestation claims. Startup-trusted
key validity, revocation, bounded lifetime, and freshness are enforced, and a
configured `VirtualizationTaskRunner` revalidates the signed claims before
dispatch and restart status lookup. Focused attestation/runner tests pass
15/15; the physical-Darwin full regression passes 527/527. This is provenance
verification only; no native attestation producer, Keychain distribution, VM
boot, guest isolation, or production enablement is claimed. Evidence:
`evidence/2026-09-15-virtualization-guest-attestation.md`.

Latest guest-image addendum: commits `846eca5` and `81faff0` require a
startup-owned, protected image preflight for `VirtualizationTaskRunner` and
revalidate its full digest/device/inode/size identity before dispatch and
restart status recovery. Focused runner/image tests pass 15/15; the physical
Darwin full regression passes 527/527. No VM boot or production
enablement is claimed; signed guest provenance is covered by the addendum
above, while guest attestation production and isolation remain open.

Latest guest-channel addendum: commits `521eecc` and `4592cad` add a bounded
Broker-side Unix-socket channel for the future native adapter. Physical Darwin
tests pass 4/4 focused and 527/527 full regression cases, including protected
socket target readback, native peer authorization before response parsing,
single-frame limits, cancellation, trailing-data rejection, and transport-loss
mapping. This is local channel evidence only; native guest serving, VM boot,
attestation, isolation, and production enablement remain open.

Latest authenticated Virtualization guest-transport addendum: commits
`e768a74`, `0dcc3cc`, `a5f053a`, `a872fbc`, `2761bbb`, and `c2a7888` define a versioned domain-separated
HMAC request/response contract, bind guest identity and attestation-related
profile/task digests, persist request ID/nonce admission in BrokerStore schema
version 6 with a 4,096-row bounded ledger and expired-row cleanup, and add a bounded exchange client with hard response framing,
timeout, cancellation, malformed-response handling, and retryable
`UNKNOWN_OUTCOME` transport-loss mapping. The Broker-side
`VirtualizationGuestTransportExecutor` binds resolved profile/task digests,
bounded budgets, response schema, guest identity, and verified-success status
to the `TaskRunner` contract without sending raw host paths or commands.
The authenticated status envelope adds fresh replay admission and original
task ID/nonce/digest binding, and lookup requires a Broker-owned authority
callback before transport. Focused task-runner plus transport tests pass 25/25;
the complete `MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1
npm test` regression passes 506/506. This closes only VT-VZ-01's protocol
boundary; it does not prove VM boot, entitlements, guest filesystem/network or
credential isolation, process ownership, native channel implementation, or
production `mac_task_run` enablement. Evidence:
`evidence/2026-09-14-virtualization-guest-transport.md` and
`evidence/2026-09-14-virtualization-framework-sdk.md`.

Latest guest Job recovery addendum: schema version `7` persists only the
authenticated guest request identity, immutable guest identity, policy/task
digests, and bounded budgets after replay admission. Broker startup now
selects restart-reconciled unknown guest Jobs and invokes an optional
TaskRunner status-recovery boundary with current policy, switch, revocation,
owner, and identity checks. A signed and verified terminal status may close
the Job; unknown, unverified, unavailable, or transport-uncertain results stay
`UNKNOWN`. Broker, persistence, task-runner, and transport recovery tests pass;
the complete real-install/sandbox/Keychain regression passes 509/509. This
still does not prove a native guest status server, VM boot, guest isolation, or
production `mac_task_run` enablement. Evidence:
`evidence/2026-09-14-virtualization-guest-transport.md`.

Latest process-start admission addendum: `ProcessSupervisor` now counts
pending child starts against the shared concurrency budget from spawn through
PID/start-time observation and ownership persistence, and `close()` waits for
those startups to abort and release capacity. The focused Darwin
ProcessSupervisor suite passes 23/23. The complete
`MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
regression passes 488/488, including the temporary Edge/Broker LaunchAgent
bootstrap, authenticated status readback, and cleanup. This closes an
in-process admission/shutdown race only; native root readback also binds the
detached process-group ID and fails closed if it changes. Crashed-process ownership,
post-snapshot descendants for generic process trees, credential isolation, and
production signing remain open. The validated single-process sandbox path now
records a no-fork proof and can distinguish a dead root as absent only after
the original group disappears. Evidence:
`evidence/2026-09-14-process-start-admission.md`.

Latest strict-exit addendum: governed sandbox tasks request a final native
process-tree readback after child close; uncertain, truncated, replaced, or
non-empty descendant state remains `UNKNOWN_OUTCOME`. Focused
process-supervisor/sandbox tests pass 29/32 with three explicit Darwin-boundary
skips. Full `MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test` passes 475/476
with one explicit skip. This is an observation guard only; post-snapshot
detached descendants, remount resistance, credential-store isolation, and
production task enablement remain open. Evidence:
`evidence/2026-09-14-post-snapshot-exit-proof.md`.

Latest exit-event addendum: strict task proof now begins at child `exit`,
records process-group survival before stream `close`, and takes a second native
descendant sample after one bounded poll interval. A Darwin fork-and-detach
fixture that keeps the output pipe open remains `UNKNOWN_OUTCOME`; focused
process-supervisor tests pass 20/20 and the full real sandbox/Keychain
regression passes 477/478 with one explicit skip. This closes the close-event
reparenting race but not post-window descendants, remount resistance, or
credential isolation. Evidence:
`evidence/2026-09-14-exit-observation-window.md`.

Latest packaged-startup addendum: compiled Broker startup now requires the
owner-controlled audit-anchor path and fixed Keychain coordinates, loads the
HMAC source through the executable-bound ACL, and verifies the sidecar before
readiness. Service-startup tests pass 3/3. The real temporary LaunchAgent
smoke with `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1` passes 1/1 and removes
the temporary Keychain item and service labels during cleanup. This is host
startup evidence only; production Developer ID provisioning, persistent
installation, cross-process locking, and external immutable anchoring remain
open. Evidence:
`evidence/2026-09-14-packaged-audit-anchor-startup.md`.

Latest audit-lock addendum: `AuditAnchorManager` now serializes sidecar reads
and publications with an owner-only atomic sibling lock, holds it through
validation/rename/`fsync`, and rechecks device/inode identity before release.
Existing locks are never auto-reclaimed; the boundary fails closed for
authenticated operator recovery. Focused audit-anchor plus persistence tests
pass 44/44. This closes a local cross-process sidecar race but does not prove a
kernel lease or external immutable anchoring. Evidence:
`evidence/2026-09-14-audit-anchor-lock.md`.

Latest audit-lock recovery addendum: host-only `recoverAuditAnchorLock`
requires the exact owner-only lock device/inode and an authenticated
stopped-service callback. On Darwin, descriptor-relative native `unlinkat` plus
parent `fsync` removes only the verified lock and returns exact removal
readback; replacement, symlink, and running-service cases fail closed. The
focused recovery tests pass 3/3, and the full
`MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test` regression passes 483/484
with one explicit skip. This is not external anchoring or proof of an
installed operator channel. Evidence:
`evidence/2026-09-14-audit-anchor-lock-recovery.md`.

Latest controller-secret-zone addendum: Broker-owned sandbox profiles now
deny `.codex` and `.openai` controller-state directories alongside SSH, cloud,
Docker, browser, Mail, Messages, and Keychain zones. The real
`MOPS_REAL_SANDBOX=1` sandbox/task-runner readback passes 21/21 and confirms
those surfaces are denied without opening contents. This strengthens the
credential-surface deny boundary but does not prove real credential-content
isolation or production `sandbox-exec` enablement. Evidence:
`evidence/2026-09-14-sandbox-controller-secret-zones.md`.

Latest keyed-audit addendum: the optional Broker-owned audit anchor binds the
SQLite tail to a separate 0600 sidecar with an explicit HMAC key source; a
dedicated Keychain factory binds that source to the Broker executable ACL. The
Broker publishes only after commit and rejects missing, stale, forged, or
key-mismatched anchors at startup. Persistence tests pass 43/43. This is local
keyed-integrity evidence only; external immutable anchoring, production
Keychain provisioning, cross-process locking, and packaged enablement remain
open. Evidence: `evidence/2026-09-14-keyed-audit-anchor.md`.

Latest encrypted-backup addendum: Broker backups require a configured
Broker-owned key source and are published as authenticated AES-256-GCM
`.sqlite.enc` envelopes. Creation and restore stream through descriptor-backed
files, verify decrypted SQLite/audit content before and after publication, bind
the key identity, and reject missing/mismatched keys, ciphertext tampering, and
legacy plaintext backup names. Focused persistence and credential tests pass
47/47. Evidence: `evidence/2026-09-14-encrypted-backup.md`.

Latest Keychain ACL addendum: the file-based macOS Keychain boundary binds
provisioning to an explicit canonical Broker executable through `SecAccess`,
checks the trusted-application ACL before returning secret bytes, rejects
duplicate identities, and retires only after an exact digest check. A real
physical-host credential/native run passed 16/16, including wrong-executable
denial and final deletion/readback. No secrets appear in the evidence.
Evidence: `evidence/2026-09-14-keychain-acl.md`.

Latest production-signature addendum: Broker and Edge install plans default to
`developer-id`, require exact component identifiers plus TeamIdentifier and
CDHash, and reject capability-bearing ad-hoc development plans. The focused
install-plan suite passes 21/21; no production certificate or persistent
LaunchAgent was available. Evidence:
`evidence/2026-09-14-production-signature-gate.md`.

Latest task credential-proof addendum: `TaskIsolationProof` now requires a
mechanism-bound credential-isolation value and rejects generic or cross-runner
claims before dispatch. The focused runner/sandbox suite passes 18/21 with
three explicit Darwin skips; this strengthens the contract but does not prove
production credential-store isolation. Evidence:
`evidence/2026-09-14-task-credential-isolation-proof.md`.

Latest persistence operations addendum: `PERSISTENCE_CUTOVER.md` defines the
host-only forward migration, encrypted-backup restore, authority freeze,
UNKNOWN-job handling, rollback, and final readback sequence. It does not claim
installed service cutover or automatic down-migration.

Latest persistence-schema addendum: `BrokerStore` enforces SQLite
`user_version` `4`, runs a versioned forward-only migration registry in one
transaction, and rejects future-version or inconsistent-registry databases
before authority or recovery work. Fresh, legacy, future-version, and registry
integrity and failed-migration rollback cases pass 39/39 focused persistence
tests. Rollback is explicitly restore-from-encrypted-backup only; no automatic
down-migration is exposed.
ADR-0005 acceptance remains open.
Evidence: `evidence/2026-09-14-persistence-schema-version.md`.

Latest process-tree identity addendum: ProcessSupervisor treats a changed
start-time for an already tracked descendant PID as a target-swap failure,
stops signalling, and preserves unresolved work as `UNKNOWN`. The deterministic
PID-reuse regression passes; the full real-sandbox regression passes 466/467
with one explicit opt-in skip. Evidence:
`evidence/2026-09-14-process-pid-reuse.md`.

Latest process-identity exit-window addendum: `ProcessSupervisor` continues
the bounded 100ms native PID/start-time retry when a short-lived child closes
before the process table settles, while still refusing synthetic identities or
unowned active registration. Five consecutive real Broker task/crash runs
passed 2/2; the full regression passes 457/458 with one explicit
host-boundary/opt-in skip. Evidence:
`evidence/2026-09-14-process-identity-exit-window.md`.

Latest Virtualization.framework candidate addendum: the active Darwin 26.2
Command Line Tools SDK contains the Virtualization.framework module and
headers; the native Objective-C probe links it, reports host support, and
constructs an intentionally invalid guest-less `VZVirtualMachineConfiguration`
without boot. The new disabled-by-default
`VirtualizationTaskRunner` requires an
external host-evidence gate, a native executor, and a proof-bound guest image
SHA-256/runtime identity; it rechecks that identity before dispatch and fails
closed on a target swap. Focused task-runner tests pass 8/8; the full
`MOPS_REAL_SANDBOX=1 npm test` regression passes 463/464 with one explicit
host-boundary/opt-in skip. No VM boot, guest isolation, or production task
enablement is claimed. Evidence:
`evidence/2026-09-14-virtualization-framework-sdk.md`.

Latest startup-authority addendum: `ProcessSupervisor` rechecks close and
cancellation authority after startup ownership sampling and before active-run
registration. A real `/bin/sleep` closes this window by invoking `close()` from
the startup callback; the child is drained, `CANCELLED` is returned, and no
active capacity remains. Focused process-supervisor tests pass 17/17; the full
real-sandbox suite passes 454/455 with one explicit host-boundary/opt-in skip.
Missing or failed native process-tree observation now returns unresolved
cleanup rather than inferring detached descendants are gone.
Evidence: `evidence/2026-09-14-process-supervisor-startup-authority.md`.

Latest process-identity startup addendum: native PID/start-time capture now
uses a bounded 100ms retry window for transient process-table visibility after
spawn, including short-lived children that exit while the table is settling,
without synthesizing identities or weakening fail-closed cleanup. The
focused process-supervisor/sandbox suite passes 29/29, and two consecutive full
real-sandbox runs each pass 452/453 with one explicit host-boundary/opt-in skip.
Evidence: `evidence/2026-09-14-process-identity-startup-retry.md`.

Latest task-crash mapping addendum: `SandboxExecTaskRunner` maps an observed
`SIGKILL`/signal execution failure to `UNKNOWN_OUTCOME` with unknown
verification, preserving a Broker Job as unresolved when a writes-local task
may have partially changed state before crashing. A real Broker integration
confirms the Request and Job remain unresolved. Focused
Broker/process-supervisor/sandbox/task-runner tests pass 106/106; the full
real-sandbox suite passes 453/454 with one explicit host-boundary/opt-in skip.
Explicit timeout, cancellation, and output-limit classes remain distinct. Evidence:
`evidence/2026-09-14-task-crash-unknown.md`.

Latest process-crash addendum: `ProcessSupervisor` treats a non-null child
termination signal as an abnormal exit, so a real self-`SIGKILL` returns
`EXECUTION_FAILED` rather than `SUCCEEDED` even when `exitCode` is null.
Focused process-supervisor tests pass 16/16; the full real-sandbox suite passes
451/452 with one explicit host-boundary/opt-in skip. This prevents false-success
readback but does not provide mutation actor attribution or production sandbox
evidence. Evidence:
`evidence/2026-09-14-process-supervisor-crash-attribution.md`.

Latest real Broker network addendum: an opt-in Darwin integration exercises a
profile-owned loopback TCP allowlist through the signed Broker task path. The
fixed curl executable, URL, empty environment, and arguments return verified
local readback. Focused Broker tests pass 72/72; the real-sandbox suite passes
449/450 with one explicit host-boundary/opt-in skip. Evidence:
`evidence/2026-09-14-real-broker-task-network.md`.

Latest task-volume identity addendum: the experimental task runner captures
native volume identity twice for every authorized filesystem root before launch,
rechecks it at process start, and rechecks it after completion. Root or volume
changes fail closed before result publication. Focused TaskProfile/runner/sandbox
tests pass 20/20; the real-sandbox suite passes 449/450 with one explicit
host-boundary/opt-in skip. This is a target-swap/remount readback guard, not a
kernel-held mount namespace, so a swap during a child syscall remains open.
Evidence:
`evidence/2026-09-14-task-volume-identity.md`.

Latest startup-abort addendum: `ProcessSupervisor` now force-terminates a
spawned detached process group when startup ownership persistence fails, waits
for the native root and tracked descendants to drain, and returns retryable
`UNKNOWN_OUTCOME` if bounded cleanup cannot be proved. A real Darwin
`/bin/sleep` callback-failure test confirms the PID disappears and capacity is
released; focused process-supervisor/sandbox tests pass 27/27 and the full
real-sandbox suite passes 450/451 with one explicit host-boundary/opt-in skip.
This closes the process-start volume-identity failure path but does not select a
production sandbox or prove in-syscall remount and credential isolation.
Evidence: `evidence/2026-09-14-process-supervisor-startup-abort.md`.

Latest task credential-policy addendum: TaskProfiles now carry an explicit
`credentialPolicy`; only `none` is accepted. Registry resolution, sandbox
rendering, and isolation-proof admission reject any unsupported credential
value before execution. Focused task-profile/runner/sandbox tests pass 17/17;
the real-sandbox suite remains 445/446 with one explicit skip. This proves a
Broker policy boundary, not real credential-store isolation or production
sandbox selection. Evidence:
`evidence/2026-09-14-task-credential-policy.md`.

Latest real process-kill-switch addendum: an opt-in Darwin integration flips
the durable `process` kill switch during a running sandboxed task. The
ProcessSupervisor drains the detached group, Broker returns `CANCELLED`, and
the Job remains `unknown`. `MOPS_REAL_SANDBOX=1 npm test` passes 445/446 with
one explicit host-boundary/opt-in skip; the focused Broker suite passes 71/71.
Evidence: `evidence/2026-09-14-real-broker-task-kill-switch.md`.

Latest real active-revocation addendum: an opt-in Darwin integration revokes
the session while `/bin/sleep` is running inside the experimental sandbox.
The ProcessSupervisor drains the process group, Broker returns `CANCELLED`,
the Job remains `unknown`, and decision/intent/completion audit events remain
present. `MOPS_REAL_SANDBOX=1 npm test` passes 444/445 with one explicit
host-boundary/opt-in skip; the focused Broker suite passes 70/70. Evidence:
`evidence/2026-09-14-real-broker-task-revocation.md`.

Latest real Edge-revocation addendum: an opt-in Darwin integration revokes the
authenticated Edge identity while `/bin/sleep` is running inside the
experimental sandbox. The ProcessSupervisor drains the process group, Broker
returns `CANCELLED`, and the Job remains `unknown` without a late success.
The focused integration passes 1/1. Evidence:
`evidence/2026-09-14-real-broker-task-edge-revocation.md`.

Latest real Broker task-path addendum: an opt-in Darwin integration exercises
the signed `mac_task_run` path through policy admission, single-use approval,
Broker Job linkage, `SandboxExecTaskRunner`, and verified completion/readback.
`MOPS_REAL_SANDBOX=1 npm test` passes 443/444 with one explicit host-boundary/
opt-in skip, and the
focused Broker suite passes 69/69. This is end-to-end experimental evidence;
the default policy remains disabled and MOP-086 still lacks credential,
remount, crash-attribution, and production-boundary proof. Evidence:
`evidence/2026-09-14-real-broker-task-path.md`.

Latest process-supervisor lifecycle addendum: registration now precedes the
initial ownership callback, so synchronous ownership persistence failure cannot
leave an active-run entry after capacity is released. Focused Darwin tests pass
14/14. Evidence:
`evidence/2026-09-14-process-supervisor-registration.md`.

Latest bounded-Git-log addendum: the `mac_git_log` adapter parses complete
records from a supervisor-confirmed bounded prefix, marks truncation, and
fails closed when termination is not observed. Focused Git tests pass 17/17.
Evidence: `evidence/2026-09-14-git-log-output-budget.md`.

Latest bounded-log addendum: the `mac_log_tail` adapter now accepts only a
supervisor-confirmed `OUTPUT_LIMIT` result, parses the already bounded output
prefix, redacts it, and reports truncation explicitly. Unresolved process
outcomes remain stable `UNKNOWN_OUTCOME` failures. Focused log tests pass 5/5;
the latest Darwin real-sandbox suite passes 442/442 with one explicit skip.
Evidence: `evidence/2026-09-14-log-output-budget.md`.

Latest bounded-write addendum: `mac_apply_patch` now has a disabled-by-default
Broker implementation with independent file/project scopes, exact project
target authorization, approval and Job linkage, textual patch bounds,
secret-content denial, expected-base hash checks, descriptor-relative atomic
writes, target identity binding, rollback, and structured post-write hashes.
Focused Broker and filesystem tests pass; evidence is recorded in
`evidence/2026-09-14-bounded-patch.md`. Enablement and physical remount,
crash-attribution, and final release evidence remain open.

Latest live install/readback addendum: the current source makes the macOS
install executor accept
only independent raw launchd, native PID/start-time, plist, Broker-status, and
signature sources, then composes the final `MacOsInstallReadback` internally.
The collector waits through the real launchd `launching` transition and
double-reads mutable identities before readiness. A physical-Mac temporary
package smoke started the real zero-capability Broker assembly under a user
LaunchAgent, verified running readback, and completed exact uninstall. The
focused install-plan suite passes 16/16. Ad-hoc signing, production
authenticated status-channel binding, Developer ID/notarization, remote Edge,
upgrade/rollback, and helper installation remain open. Evidence:
`evidence/2026-09-14-live-install-plan.md`.

Latest separate Edge-process addendum: the compiled Edge package now has a
Darwin-only cross-process HTTPS smoke. A spawned Edge loads protected key/TLS
material and contracts, while the parent native Broker accepts only its exact
UID/GID and PID/start-time identity. Official MCP negotiation and `mac_health`
complete successfully, signed local IPC remains in force, and the bearer token
is absent from the audit ledger. Focused Edge tests pass 2/2. This is temporary
process-boundary evidence; launchd installation/readback, Developer ID,
remote OAuth/JWKS, and production key rotation remain open. Evidence:
`evidence/2026-09-14-separate-edge-process.md`.

Latest packaging-shape addendum: commit `576038e` adds the reviewed Edge
LaunchAgent template next to the Broker template and documents the Edge-first,
Broker-second startup/readback order plus reverse authority-disabled uninstall.
The template regression passes with both agents containing no shell,
environment, user, or privileged launchd fields. This is static packaging
evidence only; persistent install, signing provenance, and remote deployment
remain open.

Latest packaged-service host addendum: the Darwin-only opt-in smoke starts
the compiled Edge and Broker entrypoints as separate real user LaunchAgents,
checks exact launchd arguments, an Edge TLS handshake, owner-only native and
status sockets, HMAC status readback with no enabled capabilities, native PID
identity, and bounded post-bootout absence. It copies dependencies into the
temporary package so workspace symlinks are not mistaken for installed
packaging. `MOPS_REAL_INSTALL=1` is required and existing fixed labels cause a
skip. Persistent installation, Developer ID/notarization, remote OAuth/JWKS,
Keychain ACLs, and helper installation remain open. Evidence:
`evidence/2026-09-14-packaged-edge-broker-launchd.md`.

Latest component-plan addendum: `buildMacOsEdgeInstallPlan` now provides an
Edge-specific reviewed plan with an exact listener binding, and
`composeMacOsEdgeInstallReadback`/`validateMacOsEdgeInstallReadback` require
the independently observed Edge process to be running and listening while
binding launchd, PID/start-time, plist, and signature identity. The separate
Edge executor reuses the bounded atomic plist and launchd recovery flow and
rejects operation-confirmation mismatches before filesystem access. Edge
readback cannot fall back to the Broker status channel. The full suite passes
431 tests (427 passed, 4 explicit opt-in skips); production installer and
signed-release evidence remain open.

Latest repository-quality addendum: `npm run lint` now checks all tracked
source/document files for CRLF, trailing whitespace, final newline, and regular
file invariants without executing repository content. The macOS CI workflow
runs this check before typecheck and tests. Local lint, full tests, contract
verification, dependency audit, and diff checks pass; remote CI execution is
not yet evidenced.

Latest real-sandbox addendum: `MOPS_REAL_SANDBOX=1 npm test` passed 430/430
with one explicit non-sandbox skip on the current Darwin arm64 host. The real
runner checks covered environment and protected-surface denial, single-process
fork/setsid and external-network denial, selected loopback allowlisting, and
active process-group cancellation. This remains experimental host evidence;
deprecated `sandbox-exec`, post-snapshot descendants, remounts, credential
contents, and production task enablement remain open. Evidence:
`evidence/2026-09-14-real-sandbox-regression.md`.

Latest isolation-proof hardening: `TaskIsolationProof` now binds an explicit
`sandboxMechanism` (`sandbox-exec` for the experimental runner) alongside the
profile and process-tree policy. Unknown mechanisms are rejected, preventing
future App Sandbox or Virtualization evidence from being reused by the
deprecated runner. The `TaskRunner` declares the same host mechanism, and
Broker admission/dispatch reject missing or mismatched declarations before
approval consumption or process launch. The runner remains opt-in and
unavailable by default.

Latest exact-arguments readback addendum: source commit `9d90138` parses the
bounded launchd `arguments` block and requires the exact planned Node binary
plus JavaScript entrypoint during Broker service composition. Missing,
malformed, oversized, incomplete, or substituted arguments fail closed; the
generic system-service smoke remains compatible when arguments are omitted.
The full 395-test suite passes. This remains a non-installing boundary; real
LaunchAgent bootstrap/readback remains open. Evidence:
`evidence/2026-09-13-installed-readback-identity.md`.

Latest privileged-helper readback addendum: source commit `8fd5814` carries the
native helper's planned `ProgramArguments` into the root-domain LaunchDaemon
readback contract and rejects any missing, reordered, or substituted argument
vector before helper readiness is accepted. The full 395-test suite passes;
real root-owned installation and launchd readback remain open.
Evidence: `evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Latest privileged-helper identity addendum: source commit `cc103a7` requires a
positive launchd PID and a matching native PID/start-time identity in every
non-uninstall helper readback. Missing, null, mismatched, or non-positive
identity values fail closed; the full 395-test suite passes. Real root-owned
installation and live launchd readback remain open.
Evidence: `evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Latest privileged-helper plist addendum: source commit `d3efae1` requires the
exact root-domain plist path, rendered byte count, SHA-256, and descriptor
device/inode identity in the final helper readback. A descriptor-backed
host-only reader rejects target swaps, truncation, and tampered bytes; the full
395-test suite passes. Root-owned installation and live LaunchDaemon readback
remain open.
Evidence: `evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Latest privileged-helper source-composition addendum: source commit `1405b99`
adds `composePrivilegedHelperPackageReadback`, which accepts only raw launchd,
native process, plist, helper-runtime, and signature sources. It rejects
service-ID, domain, state, type, PID, argv, plist-path, and identity
substitution before final helper validation. The full 395-test suite passes;
real root installation and live LaunchDaemon readback remain open.
Evidence: `evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Latest privileged-helper executor addendum: source commit `56ab0ca` changes the
host-only lifecycle callback to return only raw readback sources; the executor
composes and validates the final package readback internally. This prevents a
plan-shaped readback bypass. The full 395-test suite passes; root-owned
installation and live LaunchDaemon readback remain open.
Evidence: `evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Latest privileged-helper observer addendum: source commit `30b69df` adds a
host-only observer boundary that re-reads launchd, PID/start-time, and plist
identities before composition. A service/process/target replacement between
snapshots fails closed; the full 395-test suite passes. No root service was
installed, and live LaunchDaemon evidence remains open.
Evidence: `evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Latest privileged-helper host-adapter addendum: source commit `a3d7765` wires
bounded `launchctl print`, native PID/start-time capture, descriptor-backed
plist reading, and strict bounded `codesign` verify/details parsing into the
observer factory. Runtime metadata remains explicit helper-owned input. The
full suite passes 397 tests (394 passed, 3 opt-in sandbox tests skipped); no
root service was installed.
Evidence: `evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Latest final-plist-readback addendum: source commit `70ca1e9` requires a
descriptor-backed plist path, device/inode, byte count, and SHA-256 matching
the exact rendered plan. The readback rejects truncation, target changes,
tampering, and non-canonical path substitution; the focused test and full
395-test suite pass. This remains a non-installing boundary; real LaunchAgent
bootstrap/readback remains open. Evidence:
`evidence/2026-09-13-installed-readback-identity.md`.

Latest verified-launchd-readback addendum: source commit `4cb4e1a` adds
`composeMacOsInstallReadback`, which accepts only the bounded launchd service
readback plus native process identity, Broker metadata, and signature sources.
It rejects substituted service IDs, domains, states, types, PIDs, programs, or
plist paths before delegating to the complete install validator. The focused
composition test and full 395-test suite pass. This remains a non-installing
composition boundary; real LaunchAgent bootstrap/readback remains open.
Evidence: `evidence/2026-09-13-installed-readback-identity.md`.

Latest installer-readback addendum: source commit `6da24f6` requires every
non-null post-bootstrap `MacOsInstallReadback` to carry a positive launchd PID
and a matching native Darwin PID/start-time identity. Negative coverage rejects
missing, malformed, mismatched, and non-positive identities before readiness is
reported. `npm run typecheck` and the 394-test suite pass. This is a contract
boundary only; LaunchAgent installation/bootstrap and real installed-service
readback remain open. Evidence:
`evidence/2026-09-13-installed-readback-identity.md`.

Latest startup-serialization addendum: source commit `0c34c65` acquires an
owner-only runtime-root Broker instance lock with PID/start-time identity
before socket preflight, Job Ledger access, and restart recovery. Live duplicate
owners are denied, proven stale locks are reclaimed, and malformed,
observer-uncertain, symlinked, or replaced locks fail closed. The default suite
passes 394 tests (391 passed, 3 opt-in sandbox tests skipped);
`MOPS_REAL_SANDBOX=1 npm test` passes 394/394, contract validation and audit
pass. Normal and failed startup cleanup paths release the lock after resource
disposal. Launchd installation/bootstrap, arbitrary non-cooperating process
locking, and physical crash/remount evidence remain open. Evidence:
`evidence/2026-09-13-service-instance-lock.md`.

Latest IPC ownership-hardening addendum: source commit `44cae6a` rejects live
Unix listeners before stale cleanup, fences generic Node listener close with
device/inode identity and a temporary symlink barrier, limits native cleanup
to the recorded socket identity, and performs Broker startup preflight before
Job Ledger recovery. The default suite passes 390 tests (387 passed, 3
opt-in sandbox tests skipped); `MOPS_REAL_SANDBOX=1 npm test` passes 390/390,
contract validation and dependency audit pass. Installed launchd singleton
enforcement, non-cooperating-process kernel locking, and physical
crash/remount evidence remain open. Evidence:
`evidence/2026-09-13-ipc-socket-ownership.md`.

Latest startup-recovery wiring addendum: source commit `9c96605` runs the
bounded task-process and write-artifact restart reconciliation pass during
Broker service assembly, before native IPC runtime startup, and closes
Broker-owned resources on failed or unstarted assembly disposal. `npm test`
passes 387 tests (384 passed, 3 opt-in sandbox tests skipped), typecheck and
diff checks pass. This is startup ordering evidence only; installed launchd
singleton enforcement, stale-socket ownership fencing, post-snapshot
descendant cleanup, credential isolation, and production task-runner
enablement remain open. Evidence:
`evidence/2026-09-13-startup-recovery-wiring.md`.

## Evidence contract

Each evidence record must identify source commit, dirty-state status, tool contract version, policy version, test command or manual procedure, target macOS/hardware profile, relevant component versions, timestamp, result, and artifact hashes. A later source revision cannot inherit earlier evidence without rerunning affected checks.

Status values are `OPEN`, `BLOCKED`, `PASS`, and `FAIL`. Documentation presence can close a documentation task but cannot produce `PASS` for runtime behavior.

## Requirement-to-release matrix

Privileged-helper response-schema addendum at source revision `cd80e0d`:
command results and success/failure responses now use exact-field envelopes,
including nested verification and error records. Focused helper tests pass
15/15, and the serial physical regression passes 640/640 with no skips or
failures. Evidence: `evidence/2026-09-16-privileged-helper-response-schema.md`.

| Verification target | Requirement | Threat | Task | Test/evidence required | Gate | Status |
|---|---|---|---|---|---|---|
| VT-CON-01 | 44 canonical contract envelopes are schema-complete | T-019, T-020, T-021 | MOP-005, MOP-084, MOP-085 | Exactly 44 files; envelope JSON Schema validation; unique names and KB IDs; catalog parity; non-null audit class and postcondition object; valid delivery wave; required policy/budget fields; no excluded tools | Documentation | PASS — evidence: `evidence/2026-09-13-ledger-record-contracts.md` |
| VT-CON-02 | Per-tool functional input/output schemas are complete | T-019, T-021 | MOP-084 | Every contract has bounded `input_schema` and `output_schema`, functional schema compilation, forbidden-field checks, and catalog parity; runtime compatibility remains a separate gate | Documentation | PASS — evidence: `evidence/2026-09-13-capability-version-binding.md` |
| VT-AUTH-01 | Broker final authority | T-001, T-003 | MOP-011, MOP-013 | Forged scope/principal integration tests | Local/Remote | OPEN — a real RS256-authenticated MCP client now reaches `mac_health` through signed, peer-checked local IPC and Broker-owned capability discovery; separately spawned Broker and Edge package-process fixtures now complete a signed request/response over native UDS under a captured PID/start-time identity and verify the Broker response proof; the fixed Broker service entrypoint restores exact persisted signed Policy/Edge-key authority before native listener construction; exact scope/host target, signed Edge/key metadata, protected owner-only Authority Control key source with digest/revocation/activation binding, startup assembly with separate native-peer Authority channel, key rotation/revocation, macOS UID/GID/PID and optional PID/start-time peer denial, caller-filtered discovery and bearer isolation, bounded remote JWKS status/content-type/redirect/content-length checks pass; bounded launchd readback binds service domain/type and program/argv identity, and composed install readback retains the approved `gui/<uid>` LaunchAgent identity; temporary LaunchAgent startup/status smoke passes 1/1; persistent launchd identity, native code identity, and real remote issuer chain remain |
| VT-AUTH-02 | Replay rejection | T-002 | MOP-012 | Duplicate nonce, stale timestamp, altered payload, restart tests | Local/Remote | OPEN — atomic nonce/request admission, local duplicate/restart and authenticated-denial reservation cases pass; corruption/retention/remote evidence remains |
| VT-VZ-01 | Authenticated Virtualization guest transport | T-023 | MOP-086, MOP-012 | Guest request/response HMAC, durable replay, identity/profile binding, bounded frame, timeout/cancel, malformed/transport-loss tests | L2/L5 | OPEN — versioned HMAC envelopes, request/response digest binding, guest identity checks, schema-6 replay persistence plus schema-7 guest Job metadata, hard frame/timeout/cancel bounds, authenticated status lookup bound to the original task, restart Job reconciliation with verified-terminal-only promotion, malformed-response rejection, retryable unknown-outcome mapping, Broker-side digest-bound executor mapping, physical-Darwin authenticated local Unix-socket channel with protected target readback, optional startup-trusted Ed25519 guest-attestation verification with independent schema-8 key activation/rollback, dynamic revocation, key validity, and freshness rechecks pass; native guest channel/status server, VM isolation evidence, and production enablement remain |
| VT-VZ-02 | Real guest isolation and readback | T-024 | MOP-086, MOP-045 | Signed VM image/runtime identity, VM boot, guest filesystem/network/credential/process escape, cancellation, postcondition and restart evidence | L2 | BLOCKED — host-owned owner-only image preflight now binds digest/runtime/device/inode/size, and signed guest-attestation verification can bind adapter claims to startup-trusted Ed25519 provenance loaded through the schema-8 Broker key manager; the runner rechecks both before dispatch/recovery, while SDK/header availability and an intentionally invalid guest-less configuration probe are recorded. No native attestation producer, protected private-key distribution, approved VM image, boot, entitlement, guest isolation, or production capability evidence exists |
| VT-AUTH-03 | Compromised Edge cannot expand target | T-003 | MOP-013 | Broker policy negative matrix | Local | OPEN — exact host and signed filesystem-root authorization, deny/default-deny, Broker-owned path-to-root mapping, policy-query app/window/UI/service/log/Docker reference normalizers, signed target-rule reference validation, signed-schema/runtime target-vocabulary alignment, finite same-kind target-constraint serialization/matching, process-inspection adapter-result PID binding, and native process PID/start-time before-after fencing pass; physical app/resource target readback and broader live identity evidence remain |
| VT-FS-01 | F0-F5 and precedence | T-004 | MOP-018, MOP-036 | Traversal, symlink, mount, deny-inside-allow real-Mac tests | L0/L1 | OPEN — descriptor metadata/read/hash/list/tree traversal, symlink escape, same-volume/local-volume containment, independent root enablement, protected-entry filtering, deny-after-resolution, single-link inode, plan-captured volume plus policy-root identity, native `f_fsid`/filesystem-type checks, Unix-domain-socket denial, FIFO `O_NONBLOCK` denial, `/dev` pseudo-device volume denial, observed character/block-device denial, bounded listing/tree/search pressure, post-operation stability, lexical case-alias rejection, NFKC-normalized Unicode search identity cases, and physical canonical-project package metadata readback pass; physical remount identity, broader device/pseudo-filesystem coverage, production-scale resource exhaustion, and configurable secret matrix remain |
| VT-FS-02 | Target identity survives race | T-005 | MOP-018, MOP-036 | Symlink swap, create-target, directory-rename, and mutation race harness | L0/L1 | OPEN — 2,000-iteration metadata final-symlink swap, 2,000-iteration content intermediate-symlink swap, 500-iteration create-only concurrent create/symlink replacement, 2,000-iteration directory rename/outside-symlink replacement for reads, 500-iteration directory rename/outside-symlink replacement for atomic writes, same-volume authorized-root rename/replacement rejection, descriptor-relative native target opens, hash post-authorization mutation rejection, plan/native volume and policy-root identity pre/post guards, bounded directory-list pagination/tree depth filtering, and descriptor readback pass; physical remount race and broader volume/resource evidence remain |
| VT-SEC-01 | No secret output | T-006 | MOP-037 | Result/error/audit secret corpus | L0/L1 | OPEN — representative private-key, AWS/Google/cloud/GitHub/GitLab/npm/PyPI/OpenAI/Stripe/Slack token, Bearer/Basic/JWT, credential-assignment, and credential-bearing argv option signatures are denied before result construction or child spawn; split credential labels across adjacent argv entries are denied; the shared ProcessSupervisor applies the same guard to bounded stdin and centrally redacts known signatures from stdout/stderr before adapter consumers receive results; conservative UTF-16LE/BE and bounded Base64 representations are denied/redacted when decoded bytes match a known signature; bounded DER/OpenSSH private-key containers are denied, and opaque signing/credential containers are denied by `.key`, `.p8`, `.p12`, `.pfx`, `.ppk`, `.jks`, `.keystore`, and provisioning-profile path suffixes; protected `.docker`, GitHub CLI, browser, containerized Apple-data, and `/private/var/root` paths are covered, including paths with spaces. Opaque secret values, broader corpus, and false-positive analysis remain |
| VT-SEC-02 | F1 requires dedicated opt-in | T-007 | MOP-037 | Mail/browser/photo/private-data denial tests | L0/L1 | OPEN — mandatory path rules deny representative Mail, Messages, Safari, Chrome profile, Photos, Keychain, SSH, GPG, and cloud credential zones, including canonical alias checks before read; purpose-built opt-in adapters and complete corpus remain |
| VT-SBX-01 | Child cannot access controller secrets | T-008 | MOP-086, MOP-045 | macOS sandbox PoC and credential canary tests | L2 | BLOCKED — the opt-in runner smoke hides controller/`HOME`/SSH-agent/AWS_PROFILE canaries with an explicit empty environment and denies `/private/etc/passwd`, a root-contained `.env`, an outside-file symlink, and existing `.ssh`, `.docker`, Chrome, Safari, Mail, Messages, and Keychains surfaces without opening their contents. Source `bc5ee74` adds a real ACL-bound synthetic Keychain canary: `/usr/bin/security` cannot read the Broker-owned item and returns empty stdout. The shared supervisor also rejects known credential signatures in bounded stdin before spawn. The focused sandbox suite passes 17/17 and the serial physical-Darwin suite passes 639/639; evidence: `evidence/2026-09-16-sandbox-keychain-canary.md`. Fake canaries, explicit empty environment, loader-variable rejection, and Broker descriptor-launch isolation pass, but broader credential-surface isolation, production startup wiring, and full persistence/Docker boundary proof remain incomplete. Broker admission still requires a profile-matched `TaskIsolationProof`; `mac_task_run` rejects missing or incomplete proof |
| VT-SBX-02 | Child obeys network/process limits | T-009 | MOP-086, MOP-045 | Network egress and process escape tests | L2 | BLOCKED — the default profile omits `process-fork`; the smoke allows only its selected loopback `tcp` destination, denies a second loopback port and external curl DNS/network access, maps active `/bin/sleep` cancellation to detached process-group termination, and runs a Perl `fork` + `setsid` + marker-write attempt that returns `fork-denied` and leaves no marker. A real UDP loopback regression now allows one listed destination, receives its datagram, and rejects an unlisted port without delivery; source `bc5ee74` refreshes the focused sandbox suite to 17/17 and the serial physical-Darwin suite to 639/639. Source `138b6ed` also binds process-path owner UID/GID into startup stability checks; evidence: `evidence/2026-09-16-process-path-owner-identity.md`. Controlled ProcessSupervisor tests separately bind root/descendant start-time identities, reject group/other-writable cwd directories, drain hostile detached children, prove live close drains owned work, recover a persisted root identity after BrokerStore reopen, recover a persisted detached child after root exit, and keep both empty and descendant-bearing post-exit snapshots unresolved rather than claiming absence. Owned-group enforcement, descendants created after the last snapshot, post-snapshot `setsid`, timeout/crash cleanup, external allowlisted networking, and production task-runner process ownership remain |
| VT-DKR-01 | No raw Docker authority | T-010 | MOP-042 | Adapter allowlist and raw-socket negative tests | L2 | OPEN — fixed local-only status/object/log adapter tests pass; adapter and Broker response boundaries bind exact IDs, bounded ID prefixes, exact normalized names, and object type, rejecting missing or different identity before success; option-like, absolute-path, and socket/HTTP URL targets are rejected before invocation; the shared supervisor keeps root-owned execution by default and bounds Docker's canonical user-owned app-bundle CLI exception; the Broker default now requires strict `/usr/bin/codesign` readback matching Docker Inc `Identifier=docker` and `TeamIdentifier=9BNSXJN65R`, with focused signature tests and physical signature/status/inspect readback passing; the attested executable SHA-256 is required at each Docker child admission; task sandbox SBPL now explicitly denies read/write access to both Docker socket path spellings, with deterministic renderer coverage; the physical Mac mini's Docker Desktop `desktop-linux` status/inspect readback passes against Docker 29.1.3; same-name replacement races, kernel-held atomic signature-to-exec binding, native macOS daemon, host-level socket negative, VM isolation, and production evidence remain |
| VT-APR-01 | Approval binding and consumption | T-011 | MOP-082 | Payload mutation, expiry, replay, cross-principal tests | Mutation | OPEN — exact principal/tool/contract/target/payload/policy/class/mode binding, expiry, revocation, single-use exhaustion, competing consumption and pre-dispatch invalidation pass; authenticated issuance/UI, signed provenance, unattended profiles, active-work behavior and remote evidence remain |
| VT-REL-01 | Mutation retry and reconciliation | T-012 | MOP-017, MOP-083 | Crash-window and duplicate-request tests | Mutation | OPEN — request lifecycle/revision tests, atomic approval/intent/idempotency/new-job admission, idempotent reuse, conflict rollback, real filesystem-worker pre-commit, post-rename, and post-commit worker-crash failures that preserve an `UNKNOWN` Job, abrupt-worker capacity recovery, Broker.handle stale-completion rejection after a second BrokerStore reopen, persisted runtime-fence rejection of stale BrokerStore writes after takeover, fault-injected rollback/restart readback and startup reconciliation prevent false success; durable non-secret write descriptors with exact temporary names and canonical policy-root path/device/inode identity, legacy recovery rows without root proof preserved and skipped, lease owner/token/expiry heartbeat persistence, stale terminal-commit fencing, deterministic `ENOSPC` cleanup at temporary write/`fsync` boundaries, selected native `SIGKILL` crash boundaries, a non-authoritative `mac_job_status` postcondition probe, explicit exact-artifact restart cleanup, live Broker task-runner close/drain, exact persisted task PID/start-time recovery after a BrokerStore reopen, and conservative restart recovery when all persisted descendants have disappeared now pass; descendants created after the last snapshot, terminal invariants, queued/running recovery, physical disk-full/remount durability, external actor attribution, and broader partial-mutation evidence remain |
| VT-GIT-01 | Governed local Git mutation boundary | T-004, T-005, T-011, T-012, T-014, T-020 | MOP-040, MOP-047 | Explicit-path staging, staged-diff hash binding, commit parent/precondition, target identity, redaction, no-push/no-reset negatives, approval/Job lease, and unknown-outcome tests | Mutation | OPEN — Broker/inspector boundary tests and a real synthetic temporary-repository run pass with fixed `/usr/bin/git` argv, no hooks/fsmonitor/optional locks/signing/network integrations, explicit literal paths, secret/symlink/`.git` rejection, staged/HEAD/index/status readback, and failure mapping; tools remain policy-disabled and crash/concurrency/remount, external-actor, broader redaction, and final readback evidence remain |
| VT-REV-01 | Revocation/kill-switch lifecycle | T-013 | MOP-016 | New, queued, running, pre-mutation and restart cases | Local/Remote | OPEN — new-work denial, transactional queued cancellation for applicable global/mutations/process/network switches and principal/session revocations, dedicated `authority_key` revocation with digest-bound activation rejection, redacted authority intent/completion audit pairs, native-peer/HMAC Authority Control IPC with durable replay denial and expected-state switch checks, authenticated client response/readback, active filesystem-worker session and Edge revocation/cancellation/revalidation, active mutation kill-switch revalidation before Job completion, final-success revalidation of every normalized multi-root target (source `b2d3264`), persisted runtime-fence rejection of stale Broker writes after service takeover, exact persisted task-process recovery after a BrokerStore reopen plus conservative descendant-absence handling, and a 16-seed deterministic authority/job state-machine regression pass; the authenticated HTTPS -> IPC -> Broker Edge regression now covers active write cancellation, queued write cancellation/status readback, Edge-provenance queued cancellation, stable post-revocation `REVOKED`, replay denial, and separately spawned Edge/native-IPC revocation propagation (2/2 focused, 66/66 Edge suite); descendants created after the last snapshot, pre-mutation, remote propagation, installed operator recovery, and restart readback cases remain |
| VT-AUD-01 | Durable intent before mutation | T-014 | MOP-015, MOP-083 | Audit outage and crash injection | Mutation | OPEN — approval consumption, request linkage, `mac_job_cancel` argument-digest intent, future new-job creation, and generic switch/revocation changes commit with their audit evidence atomically before dispatch or authority publication; Authority Control IPC request/nonce admission is durable and request-linked audit evidence omits operator reason text; injected failures across admission phases roll back cleanly, completion state/evidence are atomic, and a keyed audit-anchor publication outage returns retryable `AUDIT_UNAVAILABLE`, freezes further writes in the same BrokerStore, and forces the next startup to reject the stale tail. External mutation/audit outage behavior remains |
| VT-AUD-02 | Audit privacy/integrity | T-015 | MOP-015 | Tamper, access-control, redaction and retention tests | Release | OPEN — recursive redaction, startup hash-chain tamper rejection, keyed-tail publication outage, stale-tail startup rejection, and stopped-service exact lock recovery pass; external immutable anchoring, retention, installed operator authentication, and access-control evidence remain |
| VT-UI-01 | Fresh target and focus | T-016 | MOP-050, MOP-052, MOP-053 | App identity, launch readback, stale ref, window change and focus-race tests | GUI | OPEN — bounded real running-app inventory readback passes; exact bundle identity authorization, fixed launch/focus command wiring, GUI approval/Job leases, active revocation, running-state reobservation, focused-window readback, bounded Accessibility observation/parser/permission-denial tests, and snapshot-bound `mac_ui_action` freshness/identity/revocation tests pass; no real app launch/focus/action or permission-granted UI evidence was run |
| VT-UI-02 | Sensitive UI denied | T-017 | MOP-054 | Password, credential and security-setting tests | GUI | OPEN — conservative sensitive bundle/window deny checks and secure-node masking tests pass; broader credential surfaces, clipboard/cross-app policy, and real-app evidence remain |
| VT-PRIV-01 | Helper exposes no arbitrary root | T-018 | MOP-060, MOP-061 | Schema fuzz, caller spoof, operation bypass tests | L5 | BLOCKED — proposed helper IPC now authenticates the OS peer before parsing, binds HMAC commands/responses to a full command digest, persists helper nonce/request replay admission, rejects raw executable/argument fields, dispatches only three operation names, and bounds/redacts postcondition evidence. A dedicated protected `helper_key` source/loader now binds digest, validity, revocation, monotonic activation, exact restore, and key disposal; independent helper startup restores that activation, requires native peer identity, rejects Broker/control socket reuse, and can derive the caller from an exact Broker LaunchAgent readback bound to PID/start-time identity. A separate non-executing root-domain package plan fixes native-only argv, exact signature identity, protected socket/key paths, Broker peer UID/GID binding, disabled capability advertisement, `system`/`LaunchDaemon` final readback identity, rollback/readback invariants, and a dry-run/gated executor for exact revision preconditions, bounded command order, final readback, and recovery. A real macOS cross-process test accepts the captured Broker PID/start-time identity and drops a spawned caller before parsing; host-only plist apply and the executor additionally verify the real current UID before filesystem/command/readback access. Developer ID provenance, real root-domain readback, separate helper/root installation, real adapters, crash recovery, and independent review remain |
| VT-POL-01 | Policy integrity/versioning | T-019 | MOP-080, MOP-084 | Invalid config, downgrade, atomic reload and rollback tests | Local | OPEN — schema/signature/tamper/downgrade/transactional activation/restart matching/explicit rollback/version-binding, protected signer-file loading with per-key digest binding, bounded overlapping signer validity windows, durable activation/restore/reload/rollback, audited key-specific revocation, protected Authority Control and helper key file/Keychain sources with digest-bound monotonic activation and exact restart restore, replay-bound HMAC operator UDS, separate replay-bound Authority Control IPC with native peer denial and expected-state switch preconditions, and legacy revocation migration pass; installed startup, protected key distribution, native caller/process identity packaging, general migrations, crash injection, and broader numeric canonicalization remain |
| VT-DOS-01 | Resource bounds | T-020 | MOP-017, MOP-070 | Rate, output, disk, depth, timeout and concurrency tests | Release | OPEN — filesystem worker multi-root dispatch, fixed concurrency rejection, pending-start admission, close-time startup cleanup, cancellation-capacity release, V8 memory/stack settings, empty environment, output caps, deadline/cancellation, bounded detached process-group plus root/descendant identity drain/capacity tests pass; local post-auth Edge fixed-window rate limits, durable BrokerStore request admission caps, shared ProcessSupervisor per-executable quotas, and stable HTTPS malformed/oversized JSON responses (400/413) pass; adapter-specific semantic quotas, disk/depth budgets, kernel-level cancellation and general jobs remain |
| VT-FUZZ-01 | Deterministic hostile-input mutation coverage | T-001, T-002, T-004, T-006, T-020, T-021 | MOP-070 | Bounded request/guest-auth mutation, replay, traversal, secret/prompt-injection, output-budget, canonicalization, policy precedence, and strict-field corpus | Local | OPEN — source commit `bccc02d` adds seven deterministic mutation suites and `d0c96be` adds the authority/job state-machine suite; the physical Darwin run passes 533/533 and the focused security-fuzz suite passes 7/7. This is bounded regression coverage, not exhaustive fuzzing, kernel isolation, full policy-state exploration, or independent review. |
| VT-COMP-01 | Version negotiation fails safely | T-021 | MOP-081 | Edge/Broker/helper compatibility matrix | Local/Remote/L5 | OPEN — Broker capability readback, the separately authenticated helper command, and the Authority Control IPC response envelope now bind explicit protocol/contract versions or domains and fail closed on mismatch; installed, remote, helper packaging, upgrade/rollback, and cross-runtime compatibility evidence remains |
| VT-OPS-01 | Disable/uninstall removes authority | T-022 | MOP-071, MOP-087 | Revocation, service removal and readback procedure | Release | OPEN — host-only uninstall coordination now selects the activated protected Authority Control key manager, binds to the owner-only IPC client, requires authenticated global kill-switch disable and exact Edge revocation readback before plist/launchd removal, and rechecks authority afterward; startup assembly now places the separate Authority channel under the fail-closed Broker runtime lifecycle; focused keyring, client, startup, idempotency, migration, and temporary-root tests pass, while installed keychain ACLs, authority-channel packaging, Developer ID/notarization, native identity, live launchd disable/uninstall, key cleanup, and final host readback remain |

## Release gates

Durable capability-family clarification: source revisions `db129b3` and `0b7d3b9` close the
cross-handle BrokerStore quota boundary for read, write, process, network, GUI,
destructive, and privileged families. The remaining resource-bound gate is
adapter-specific semantic enforcement plus kernel/disk/depth limits and
installed-service evidence.

- Documentation gate: locked decisions materialized; open decisions and conflicts explicit.
- Local authority gate: identity, IPC, policy, replay, audit, revocation, and failure behavior pass.
- L0/L1 gate: filesystem and secret tests pass on the supported Mac profile.
- L2 gate: sandbox and credential-isolation evidence pass before `mac_task_run` enablement.
- Write gate: approval, ledger, idempotency, audit intent, recovery, and postconditions pass.
- GUI gate: app/element identity, freshness, focus, privacy, and permission recovery pass.
- L5 gate: helper protocol, caller auth, allowlist, packaging/signing, rollback, and independent review pass.
- Release gate: exact revision has no unresolved P0/P1 or High/Critical threat in affected boundaries.

## Current evidence

Latest Job-ledger startup-integrity addendum: the BrokerStore now validates
every persisted Job row before restart reconciliation. Job identity fields,
lease owner/token formats, heartbeat/expiry ordering, and the bounded lease
window fail closed; mixed local-process and virtualization guest ownership
metadata is rejected before recovery. Focused Job-state/startup tests pass
6/6; the non-overlapping package regression passes 586 total (580 passed, 6
skipped, 0 failed), with build, lint, and diff checks passing. The long-running
Broker and persistence suites were not restarted. This is persisted-ledger and
old-writer fencing evidence only; physical crash process ownership, credential
rotation, remount durability, and production task enablement remain open.
Evidence: `evidence/2026-09-15-job-ledger-startup-integrity.md`.

Latest persistence integrity rerun: source revision `8077a6d` passes 33/33
focused replay, Approval, authority, configuration, Request, Job,
Request-to-Job, and all-table schema-layout invariants with no skips or
failures. The existing `broker.test.js` and `persistence.test.js` process was
left undisturbed. This strengthens local startup/readback evidence only;
physical crash/remount durability, production Keychain, installed recovery,
external rollback, and independent P0/P1 review remain open. Evidence:
`evidence/2026-09-15-ledger-integrity-rerun.md`.

Latest physical-Darwin full regression: after rebuilding source revision
`cd62bbc`, the serial non-overlapping package set passes 595/595 with zero
skips and zero failures under the explicit sandbox, Keychain, and temporary
install gates. The pre-existing Broker/Persistence process was left
undisturbed. This is current host regression evidence only; persistent
production installation, Developer ID provenance, real isolation, VM
isolation, remote issuer/deployment, and independent P0/P1 review remain
open. Evidence: `evidence/2026-09-15-real-full-regression-rerun.md`.

Latest verification-timeout boundary: source revision `7d99b98` adds a fixed
120-second per-test-case timeout to the root `npm test` command. Lint,
typecheck, and the 11-test contracts smoke pass; the existing Broker/
Persistence process was left undisturbed. This bounds test-run hangs only and
does not change production task budgets or close physical crash, installed,
isolation, remote, or independent-review gates. Evidence:
`evidence/2026-09-15-test-timeout-boundary.md`.

Latest release-gate rerun: source revision `7e0cc43` passes 44-contract
verification, 5/5 native canonical vectors, high-level dependency audit with
zero vulnerabilities, lint for 611 tracked files, typecheck, and diff
checks. The old Broker/Persistence process was left undisturbed, so its full
result and the remaining physical production/release gates are not claimed.
Evidence: `evidence/2026-09-15-release-gate-rerun.md`.

Latest audit-outage availability decision: after keyed audit-tail publication
failure, every Broker MCP admission—including a read-only request—fails
closed as `AUDIT_UNAVAILABLE` until restart with a verified tail. The focused
test confirms no Request row is created and host recovery readback remains
available. This closes the previously open read-only audit-failure decision;
external immutable anchoring and production recovery remain open. Evidence:
`evidence/2026-09-15-audit-readonly-fail-closed.md`.

Latest Broker restart-recovery addendum: source commit `a20fed7` persists
bounded non-secret task-process PID/process-group/start-time identities for the
root and observed descendants before task execution proceeds. A new
BrokerStore marks the prior running Job `UNKNOWN`;
`reconcileRestartedTaskProcesses()` then verifies exact Darwin identities before
terminating the root process group and tracked descendants, records a redacted
intent/completion audit pair, and leaves the Job `UNKNOWN`. PID/start-time
substitution is rejected. Cross-Broker live-root, persisted detached-child,
and empty-snapshot fail-closed recovery tests pass; the default suite passes
387 tests (384 passed, 3 opt-in sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 387/387. This proves recovery for
observed identities and conservative unknown handling, not descendants created
after the last snapshot, post-snapshot `setsid`, credential isolation, or
production task-runner enablement. Evidence: `evidence/2026-09-13-task-process-recovery.md`.

Latest Broker OS-process ownership addendum: source commit `1a8b0cc` routes
default launchd, log, Git, Docker, app, and UI adapters through one
Broker-owned `ProcessSupervisor` with bounded aggregate concurrency and an
explicit union of non-secret environment keys. `Broker.close()` drains that
authority alongside worker executors and the task runner. The integration close
test passes; `MOPS_REAL_SANDBOX=1 npm test` passes 381/381, while the default
suite passes 381 tests (378 passed, 3 opt-in sandbox tests skipped). This is
live graceful-shutdown evidence only: crashed-Broker descendant ownership,
post-snapshot `setsid`, credential isolation, and production task-runner
enablement remain open. Evidence:
`evidence/2026-09-13-broker-process-ownership.md`.

Latest OS-process lifecycle addendum: source commit `889ccdf` adds an
explicit `ProcessSupervisor.close()` boundary. It rejects new work, cancels
active owned process groups, waits for tracked process-tree drain, and leaves
unobserved termination as `UNKNOWN_OUTCOME`; `SandboxExecTaskRunner.close()`
forwards the boundary and `Broker.close()` drains it after transport shutdown.
The default task runner and `owned_group` profile remain disabled. The default
full suite passes 380 tests (377 passed, 3 opt-in sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 380/380. This is live graceful-shutdown
evidence only: crashed-Broker descendant ownership, post-snapshot `setsid`,
credential isolation, and production task-runner enablement remain open.
Evidence: `evidence/2026-09-13-process-supervisor-close.md`.

Latest Broker real-worker post-rename addendum: source commit `42268d2` adds a
controlled test-only worker URL and fault native adapter. A real
`WorkerFilesystemExecutor` write injects `ENOSPC` after rename before parent
`fsync`; the target is committed, the worker fails, Broker preserves the Job as
`UNKNOWN`, and `mac_job_status` reads `matches / remains_unknown`. The
production default worker/native paths remain fixed. Focused Broker tests pass
62/62; the full suite passes 372 tests (370 passed, 2 opt-in real-sandbox tests
skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes 372/372. Physical disk-full,
remount, kernel-blocked I/O, and Broker-process restart fencing remain open. Evidence:
`evidence/2026-09-13-broker-worker-post-rename.md`.

Latest sandbox hostile-descendant addendum: source commit `01a26ba` adds an
opt-in real-Mac test that runs a Broker-resolved `/usr/bin/perl` fixture under
the default `single_process` profile. The fixture attempts `fork()`,
`setsid()`, and a marker write; macOS returns `fork-denied`, no marker is
created, and the result is not success. The focused sandbox suite passes 8/8;
the complete `MOPS_REAL_SANDBOX=1 npm test` regression passes 373/373. This is
no-fork evidence only and does not prove owned-group, post-snapshot escape,
crash/restart cleanup, credential contents, persistence, or production task
runner safety. Evidence:
`evidence/2026-09-13-sandbox-hostile-descendant.md`.

Latest worker-crash addendum: source commit `61b0865` adds a test-only
`filesystem-crash-worker.js` that performs a real descriptor-backed atomic write
and then exits by uncaught exception before posting a result. The Broker returns
`EXECUTION_FAILED`, leaves the Job `UNKNOWN`, and a subsequent
`mac_job_status` readback reports `matches / remains_unknown`. A separate
`BoundedWorkerExecutor` test proves an abrupt worker exit releases capacity
after the exit event and allows the next bounded request to complete. Focused
Broker/worker tests pass 69/69; the default full suite passes 375 tests (372
passed, 3 opt-in real-sandbox tests skipped), and `MOPS_REAL_SANDBOX=1 npm test`
passes 375/375. This remains worker-thread crash evidence: it does not prove
Broker-process restart fencing, old-worker OS ownership, or production task
runner enablement. Evidence:
`evidence/2026-09-13-worker-crash-unknown.md`.

Latest Broker worker-lifecycle addendum: source commit `84f4991` gives the
bounded executor explicit ownership of active Worker instances. Shutdown now
rejects new work, terminates owned workers, waits for termination requests, and
keeps capacity reserved until each Worker exit event. `Broker.close()` fences
new requests and checks shutdown authority before publishing active results;
the native runtime closes transport channels before these Broker resources.
Focused lifecycle tests pass 13/13; the default full suite passes 377 tests
(374 passed, 3 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 377/377. This is graceful in-process
worker drain evidence only; crashed-Broker OS-process ownership, restart
fencing, and production task-runner enablement remain open. Evidence:
`evidence/2026-09-13-broker-worker-shutdown.md`.

Latest cross-Broker stale-completion addendum: source commit `f2ce163` adds an
integration test at the `Broker.handle` boundary. A delayed old Broker write
enters `running`; a second `BrokerStore` reopen reconciles the Job to
`UNKNOWN`; releasing the old delayed result cannot publish success, and the
reopened Broker's `mac_job_status` remains `UNKNOWN`. Focused Broker tests pass
64/64; the default full suite passes 378 tests (375 passed, 3 opt-in
real-sandbox tests skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes 378/378.
This is persisted lease/revision fencing evidence only, not OS-process
ownership or proof of old-worker termination after a crashed Broker. Evidence:
`evidence/2026-09-13-stale-broker-completion.md`.

Latest Broker real-worker write-failure addendum: source commit `2371eba` adds
a Broker integration test using a real `WorkerFilesystemExecutor`. A
metadata-readable, write-authorized root becomes mode `0500`; the worker fails
to create its temporary file, Broker returns a stable failure, the mutation Job
persists as `UNKNOWN`, the target remains absent, and `mac_job_status` reads
`unavailable / remains_unknown`. Focused Broker tests pass 61/61; the full suite
passes 371 tests (369 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 371/371. Post-rename failure through the
real worker, physical disk-full, kernel-blocked I/O, Broker-process restart
fencing, and remount evidence remain open. Evidence:
`evidence/2026-09-13-broker-worker-write-failure.md`.

Latest current-revision sandbox readback: source revision `4d18b31` passes the
opt-in `SandboxExecTaskRunner` smoke 7/7 on the Mac mini M4, and
`MOPS_REAL_SANDBOX=1 npm test` passes 370/370. The run is temporary-fixture
evidence only; credential contents, hostile descendants, crash/restart cleanup,
persistence, Docker/privilege isolation, external allowlisted networking, and
remount behavior remain unproven. The default task runner and `mac_task_run`
remain disabled. Evidence:
`evidence/2026-09-13-sandbox-profile-rerun.md`.

Latest macOS volume-inventory addendum: source commit `92137e2` records
read-only `diskutil list`, `mount`, `/Volumes`, and `df -P` output. The host has
only internal APFS surfaces and the system `Macintosh HD -> /` alias; no
removable, network, or secondary user volume is mounted for a remount exercise.
No mount, unmount, erase, repartition, or write operation was performed.
Physical/removable remount evidence remains open because an eligible disposable
target is absent. Evidence:
`evidence/2026-09-13-volume-inventory.md`.

Latest atomic-write post-commit-error addendum: source commit `93eeaf8` adds
fault-test-only `ENOSPC` immediately after atomic rename and before the
parent-directory `fsync`. The target contains the new bytes, the temporary
artifact is absent, and the call fails non-zero, modelling the ambiguous
post-commit window that must remain `UNKNOWN`. Focused filesystem tests pass
31/31; the full suite passes 370 tests (368 passed, 2 opt-in real-sandbox
tests skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes 370/370. Physical
disk-full, remount, kernel-blocked I/O, and restart evidence remain open.
Evidence: `evidence/2026-09-13-write-post-commit-error.md`.

Latest atomic-write storage-error addendum: source commit `0ac3e15` adds
fault-test-only `ENOSPC` injection before temporary-file write and `fsync`.
Create and replace fixtures fail closed, preserve the prior target state, and
remove the exact temporary artifact; production native builds do not expose the
hook. Focused filesystem tests pass 31/31; the full suite passes 370 tests (368
passed, 2 opt-in real-sandbox tests skipped). `MOPS_REAL_SANDBOX=1 npm test`
has the same two environment-gated skips. This is deterministic error-path
evidence, not physical disk-full, remount, kernel-blocked I/O, or restart
recovery evidence. Evidence:
`evidence/2026-09-13-write-storage-error.md`.

Latest filesystem-worker concurrency addendum: source commit `df4ba85` adds a
real `WorkerFilesystemExecutor` fixture that authorizes two independent roots,
returns matches from both roots, rejects overlap at a concurrency cap of one,
and succeeds again after the worker exits. A `BoundedWorkerExecutor` fixture
proves that active cancellation returns `CANCELLED` before capacity is
released, then accepts new work after worker termination. Focused
filesystem/worker tests pass 36/36; the full suite passes 369 tests (367
passed, 2 opt-in real-sandbox tests skipped). `MOPS_REAL_SANDBOX=1 npm test`
has the same two environment-gated skips. Production-scale exhaustion,
kernel-blocked I/O interruption, restart recovery, and process isolation remain
open. Evidence:
`evidence/2026-09-13-filesystem-worker-concurrency.md`.

Latest filesystem pressure-budget addendum: source commit `9d6d6b0` creates
600 synthetic temporary files and proves bounded 500-entry listing pagination,
128-entry tree truncation, 100-result metadata/text search truncation, and
oversized argument rejection. Focused filesystem tests pass 30/30; the full
suite passes 367 tests (365 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 367/367. Production-scale pressure,
disk/error injection, kernel-blocked I/O cancellation, and release evidence
remain open. Evidence:
`evidence/2026-09-13-filesystem-pressure-budgets.md`.

Latest character/block-device addendum: source commit `8fbd148` checks
`/dev/null`, `/dev/tty`, `/dev/random`, and the available `/dev/disk0` block
device as read-only negative targets. All are rejected at the local-volume
boundary without device bytes being read. Focused filesystem tests pass 29/29;
the full suite passes 366 tests (364 passed, 2 opt-in real-sandbox tests
skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes 366/366. Broader device,
pseudo-filesystem, physical-remount, and release evidence remain open.
Evidence: `evidence/2026-09-13-character-block-device-boundary.md`.

Latest special-file hardening addendum: source commit `7a136ef` makes native
metadata/read/hash opens non-blocking for untrusted FIFO targets. A temporary
FIFO is returned only as `other` metadata; generic content, hash, and write
paths fail closed, while `/dev/null` and `/dev` volume crossings are denied.
Focused filesystem tests pass 29/29; the full suite passes 366 tests (364
passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 366/366. Broader special-file and
physical remount evidence remain open. Evidence:
`evidence/2026-09-13-special-file-hardening.md`.

Latest generic special-file addendum: source commit `cd74420` adds a
disposable Unix-domain-socket fixture. Directory metadata returns the entry as
`other`, while generic content read, hash, and atomic write attempts fail
closed. Focused filesystem tests pass 28/28; the full suite passes 365 tests
(363 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 365/365. FIFO/device/pseudo-filesystem
coverage and release evidence remain open. Evidence:
`evidence/2026-09-13-special-file-boundary.md`.

Latest filesystem volume-identity addendum: source commit `1807ebc` binds each
filesystem plan to the native canonical root and volume ID at authorization,
rechecks it before and after metadata/read/hash/list/write/unlink operations,
and adds native `f_fsid`/filesystem-type checks for target and parent
descriptors. Focused filesystem/native tests pass 33/33; the full suite passes
364 tests (362 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 364/364. Typecheck, 44-contract
validation, dependency audit, and diff checks pass. No volume was unmounted or
mounted; physical/removable remount and release evidence remain open. Evidence:
`evidence/2026-09-13-filesystem-volume-identity.md`.

Latest filesystem canonicalization addendum: source commit `a742fbc` adds a
temporary adversarial fixture for lexical case-alias rejection and decomposed
Unicode search against a composed filename. The match is checked against the
native canonical path, including macOS `/private` path canonicalization where
applicable. Focused filesystem tests pass 26/26; the full suite passes 363
tests (361 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 363/363. Typecheck, 44-contract
validation, dependency audit, and diff checks pass. Remount identity,
cross-volume normalization policy, special-file/resource-exhaustion coverage,
and release evidence remain open. Evidence:
`evidence/2026-09-13-filesystem-canonicalization.md`.

Latest secret-zone/redaction addendum: source commit `0bcd893` expands the
Broker deny list to full `.docker` state, GitHub CLI state, browser application
data, and containerized macOS Mail/Messages/Safari paths. Evidence redaction
now handles `/private/var/root`, paths containing spaces, Bearer/Basic
credentials, and JWT-shaped values. Focused policy tests pass 4/4; the full
suite passes 362 tests (360 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 362/362. No credential/private-data
content was opened and no capability was enabled. VT-SEC-01 remains OPEN for
the broader corpus and release gate. Evidence:
`evidence/2026-09-13-secret-zone-redaction.md`.

Latest L0/L1 host-readback addendum: source commit `b7ea5fb` adds a
macOS-only, read-only host probe for bounded system facts, interface state
with active probes and listener enumeration disabled, redacted process
inventory/current-process identity, canonical `/System/Library`
metadata/list/tree output, and a depth-limited APFS volume/capacity readback
with content reads disabled and protected relative zones denied. The probe
performs no mutation, child launch, credential read,
policy change, or service install. Focused host test passes 1/1; the full suite
passes 362 tests (360 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 362/362. Typecheck, 44-contract
validation, dependency audit, and diff checks pass. A one-second JWT expiry
assertion race found during the host run was fixed by binding the expected
expiry second to the signed token input. This remains a narrow L0/L1 slice;
secret corpus, remount/race, special-file, listener ABI, and release evidence
remain open. Evidence: `evidence/2026-09-13-l0-l1-host-readback.md`.

Latest sandbox readback: the opt-in `sandbox-profile.test.js` smoke passes 7/7
and the full `MOPS_REAL_SANDBOX=1 npm test` regression passes 362/362 from
source revision `b7ea5fb`. The probe still proves only partial Seatbelt,
environment, temporary-root, selected loopback, credential-surface existence,
child-launch, and cancellation behavior; it does not prove credential
contents, descendant/`setsid` ownership, remount/crash/restart cleanup,
persistence, Docker, or production isolation. The `mac_task_run` gate remains
BLOCKED. Evidence: `evidence/2026-09-13-sandbox-profile-runner.md`.

Latest governed HTTPS Edge service-entrypoint addendum: source commit
`0e8612d` adds a fixed `service-main.js` and strict owner-only
`edge-service.json` loader. Startup binds canonical package/data/runtime roots,
protected TLS and digest-bound Edge HMAC files, the contract directory, fixed
HTTPS/OAuth/JWKS/IPC/rate-limit budgets, and the existing signed Broker gateway
without accepting MCP arguments or ambient environment authority. Listener
host/port readback is required before readiness; shutdown wipes HMAC/TLS
buffers. Focused startup tests pass 3/3; the full suite passes 361 tests (359
passed, 2 opt-in real-sandbox tests skipped); `MOPS_REAL_SANDBOX=1 npm test`
passes 361/361; typecheck, 44-contract validation, and high-severity dependency
audit pass. This does not prove installed LaunchAgent bootstrap, production
signing, Keychain ACLs, external OAuth issuer rotation, or remote deployment.
Evidence: `evidence/2026-09-13-governed-edge-service-entrypoint.md`.

Latest governed service-entrypoint addendum: source commit `8ac5fe0` adds a
fixed `service-main.js` entrypoint and strict owner-only `broker-service.json`
loader. Startup restores exact persisted signed Policy and Edge-key
activations, checks that the Policy trusts the configured Edge, captures the
launchd Edge PID/start-time identity, and only then constructs native Broker
runtime. Root-bound canonical paths, weak/symlinked config denial, native
start/close, and Edge-key disposal pass; focused startup tests pass 3/3. The
full suite passes 358 tests (356 passed, 2 opt-in real-sandbox tests skipped),
and the opt-in real-host suite passes 358/358. This does not prove installed
LaunchAgent bootstrap, production signing, Keychain ACLs, or live rollback.
Evidence: `evidence/2026-09-13-governed-broker-service-entrypoint.md`.

Latest packaged-process/readback addendum: source commit `018565d5` adds a
bounded read-only `/bin/launchctl print` adapter with exact service identity,
state, PID, canonical path, type, and exit-code parsing; the real Mac smoke
reads `system/com.apple.logd` without changing launchd state. A second native
IPC smoke starts Broker and Edge as separate package processes, captures the
Edge PID/start-time identity before Broker listens, and verifies the signed
`mac_health` response at the Edge process. Focused readback/IPC tests pass
11/11; the full suite passes 354 tests (352 passed, 2 opt-in real-sandbox
tests skipped), and the opt-in real-host suite passes 354/354. This does not
prove installed LaunchAgent bootstrap, production signing, Keychain ACLs, or
live upgrade/rollback. Evidence:
`evidence/2026-09-13-packaged-process-and-launchd-readback.md`.

Latest native Edge process-boundary addendum: source commit `511f8a6` adds a
real separately spawned Node Edge fixture that signs a `mac_health` request,
connects across the native UDS, verifies the complete Broker response proof,
and is accepted only under the captured PID/start-time identity. The fixture
uses an explicit `/` working directory, a minimal environment, and a temporary
owner-only key file. Focused native IPC tests pass 7/7; the full suite passes
350 tests (348 passed, 2 opt-in real-sandbox tests skipped), and the opt-in
real-host suite passes 350/350. This does not prove installed launchd
packaging, signed production binaries, Keychain distribution, or remote
deployment. Evidence:
`evidence/2026-09-13-native-edge-process-boundary.md`.

Latest local Edge/Broker layered addendum: source commit `1fecf5b` adds a
real RS256-authenticated MCP client test that completes pinned `2026-07-28`
HTTPS discovery, receives Broker-filtered `mac_capabilities`, and calls
`mac_health` through the signed, peer-checked local UDS. The full suite passes
350 tests (348 passed, 2 opt-in real-sandbox tests skipped), and the opt-in
real-host suite passes 350/350; no installed service, public endpoint,
mutation, or production credential was used.
Evidence: `evidence/2026-09-13-edge-broker-https-e2e.md`.

Latest privileged-helper key addendum: source commit `d91d406` adds a dedicated
owner-only helper key configuration and `helper_key` revocation path. The
helper key manager requires explicit file/Keychain source, SHA-256 digest,
validity window, audited monotonic activation, and exact restart restore before
constructing either the Broker command factory or helper IPC server. Both
defensively copy and wipe their HMAC key, and constructed paths recheck
key-specific revocation before issuing or authorizing work; the helper adapter remains
fail-closed. The focused helper-key/IPC/persistence suite passes 33/33 and
the full suite passes 335 tests (333 passed, 2 opt-in real-sandbox tests
skipped). No privileged operation was run. Evidence:
`evidence/2026-09-13-privileged-helper-key-activation.md`.

Latest helper-key lifecycle addendum: source commit `72a3284` adds dynamic
active-key fencing to already-constructed helper factories and IPC servers.
Each issue/parse/authorization path rechecks dedicated `helper_key` revocation,
BrokerStore active revision/digest identity, and the configured validity window;
expiry and activation replacement fail closed without restart. The helper
focused suite passes 9/9 and the full suite passes 344 tests (342 passed, 2
opt-in real-sandbox tests skipped). Evidence:
`evidence/2026-09-13-privileged-helper-key-lifecycle.md`.

Latest helper-runtime addendum: source commit `12a1ac3` adds an independent
helper lifecycle that restores the exact active helper-key identity before
constructing the listener, requires an explicit native peer process identity,
rejects Broker/control socket reuse, and rolls back failed start/close in a
serialized state machine. The fail-closed adapter remains the only default;
no root process or privileged action was run. The full suite passes 337 tests
(335 passed, 2 opt-in real-sandbox tests skipped). Evidence:
`evidence/2026-09-13-privileged-helper-runtime.md`.

Latest helper-package addendum: source commit `eb9ee6a` adds a separate
non-executing system LaunchDaemon plan. It fixes the root-domain plist path,
native-only helper argv, exact helper signature identifier, protected helper
root/key/socket paths, Broker peer UID/GID binding, root-owned plist actions,
and exact upgrade/rollback/uninstall commands. Readback rejects adapter
enablement or capability advertisement. No launchd mutation, root process,
signing, or privileged operation was run. A real macOS temporary bundle smoke
test executes the fixed ad-hoc signing/verification command and reads back
the exact helper identifier; this does not prove Developer ID provenance. The
package now also has a double-`lstat` root-owned filesystem preflight with
symlink/type/mode/owner and device/inode checks, including owner-only key/plist
files and an owner-executable helper. The package now also exposes a
host-only, explicitly confirmed descriptor-relative plist apply/upgrade/
rollback/uninstall primitive with exact identity preconditions and restoration
on failed upgrade/uninstall; it rejects non-root callers before filesystem
access, verifies the real current process UID, pins the write to the internal
root filesystem inspector, and never calls launchctl.
Successful root-owned execution remains unverified. A dry-run contract and
gated host executor now validate exact existing-service revisions, run bounded
signature/bootout/plist/bootstrap/readback steps, and recover using fixed
operation-specific actions; non-root callers fail before command or readback
access. The full suite passes 349 tests (347 passed, 2 opt-in real-sandbox
tests skipped); the opt-in real-Mac suite passes 349/349. Evidence:
`evidence/2026-09-13-privileged-helper-package-boundary.md`.

Latest helper-caller addendum: source commit `7af182e` binds helper startup to
the exact per-user `gui/<uid>/com.mac-operator.broker` LaunchAgent readback.
The fixed empty-environment `launchctl print` result is reduced to a PID, then
native peer readback captures PID/start-time identity before helper creation;
service-label smuggling and stopped/malformed services fail closed. The full
suite passes 342 tests (340 passed, 2 opt-in real-sandbox tests skipped). No
launchd mutation or root process was run. Evidence:
`evidence/2026-09-13-privileged-helper-caller-identity.md`.

Latest Authority runtime addendum: source commit `a06eb81` restores both active
key configurations before constructing the native Broker and the separate
owner-only Authority Control channel. The Authority channel has a distinct
socket, requires native peer PID/start-time identity, participates in the same
ordered startup/rollback lifecycle, and owns a defensive key copy that is
wiped on close. The temporary startup suite passes 6/6 and the full suite
passes 333 tests (331 passed, 2 opt-in real-sandbox tests skipped). No
persistent LaunchAgent or production service was installed. Evidence:
`evidence/2026-09-13-authority-runtime-assembly.md`.

Latest Authority Control key addendum: source commit `f47ecc5` adds an
explicit versioned owner-only Authority Control key configuration. Exactly one
active key is selected from a declared file or Keychain source, its secret
bytes are loaded only through protected checks and bound to a configured
SHA-256 digest, and the key is rejected when the dedicated `authority_key`
revocation is present or its validity window has elapsed. BrokerStore persists
audited monotonic activation and requires exact revision/digest matching on
restart restore. The uninstall host assembly takes an activated key manager,
constructs the authenticated IPC client, and never accepts a raw key through
uninstall arguments. Focused keyring/IPC/persistence tests pass; no installed
service or live key rotation/deletion was performed. Evidence:
`evidence/2026-09-13-authority-key-activation.md`.

Latest Authority Control client addendum: source commit `eeebec3` binds the
host-only uninstall coordinator to the real owner-only `AuthorityControlIpcClient`.
Commands are HMAC-bound protocol-`0.1` envelopes with random request/nonce
identity and durable replay admission; responses are HMAC-bound to the exact
request and full response body. The client verifies owner-only socket
directory/target state, rechecks device/inode identity after connect, and
enforces bounded timeout, cancellation, and response bytes. Authenticated read
operations provide switch/revocation pre/post readback, while the uninstall
factory is idempotent and rejects a mismatched Edge identity. The full suite
passes 329 tests (327 passed, 2 opt-in real-sandbox tests skipped), and the
focused authority/install suite passes 14/14. No installed service or live
uninstall was run. Evidence:
`evidence/2026-09-13-authority-control-client.md`.

Latest helper compatibility addendum: source commit `ee6d37b` binds the shared
contract version into the HMAC-protected privileged-helper command envelope.
Parsing rejects missing or mismatched versions before replay admission or
dispatch, while the Broker factory derives the version from the approved
contract binding. The focused helper suite passes 7/7 and the full suite passes
328 tests (326 passed, 2 opt-in real-sandbox tests skipped). Evidence:
`evidence/2026-09-13-helper-contract-version.md`. The helper remains disabled;
installed/remote negotiation, packaging, and L5 review remain open.

Latest uninstall authority addendum: source commit `f24b506` adds a host-only
coordinator that disables the global kill switch and revokes the selected Edge
through separately authenticated callbacks before any uninstall file or
launchd operation. It requires authority readback before and after exact-
revision plist removal, never re-enables authority on failure, and fails closed
without issuing commands when readback is incomplete. Eleven focused tests and
the full 328-test suite pass (326 passed, 2 opt-in real-sandbox tests skipped).
Evidence: `evidence/2026-09-13-uninstall-authority-gate.md`. Live installation,
packaging, key cleanup, and final host readback remain open.

Latest install-plan readback addendum: the focused macOS install-plan suite was
rerun from clean source revision `c1defff` with 10 tests passed and 0 failed.
It covers fixed per-user LaunchAgent argv, owner-only temporary-root preflight,
symlink/writable-path rejection, ad-hoc signature verification, atomic plist
install/upgrade/rollback/uninstall, exact previous-revision preconditions,
explicit host confirmation, final Broker/signature readback, and mismatch
recovery. No live LaunchAgent or installed service was touched. Evidence:
`evidence/2026-09-13-install-plan-executor.md`. Live launchd, Developer ID,
notarization, installed Edge identity, and production rollback gates remain
open.

Latest capability compatibility addendum: source commit `8061254` adds
protocol/contract version fields to Broker capability readback and the
versioned `mac_capabilities` output schema. The MCP Edge validates the shared
protocol and contract versions and requires every enabled capability to match
the local contract registry before registering an MCP tool; missing, malformed,
stale, or mismatched data fails closed. The full suite passes 327 tests (325
passed, 2 opt-in real-sandbox tests skipped), including the versioned contract
conformance case and an enabled-capability mismatch negative test. Evidence:
`evidence/2026-09-13-capability-version-binding.md`. This is local compatibility
evidence only; installed/remote/helper matrices, upgrade/rollback readback, and
broader numeric canonicalization remain open.

Latest app launch addendum: commit `85d1e96` records 264 passing tests and adds the disabled-by-default `mac_app_open` mutation boundary, runtime contract-envelope conformance, and one global deadline across inventory, launch, and reobservation. The Broker requires independent `mac.app.control`, an exact `app:bundle:<bundle_id>` target, `trusted_gui` approval, durable intent, a generic Job lease, and active authority rechecks. The adapter first confirms the stable identity in bounded Broker-owned inventory, invokes only fixed `/usr/bin/open -b <bundle_id>` with `/` cwd, empty environment, and bounded timeout/output, then reobserves the exact app as running before committing the Job and success result. Paths and URLs are rejected until their own filesystem/network policy and target-swap proofs exist; caller scripts, arbitrary executables, process IDs, and app arguments are not accepted. Fake-adapter tests cover command wiring, target absence, already-running state, active deadline expiry, approval/Job/audit linkage, and active session revocation; no user application was launched during verification. Evidence: `evidence/2026-09-13-app-open-boundary.md`. Focus, app/window freshness, Accessibility, sensitive-surface, permission recovery, real-app launch, and GUI release evidence remain open.

Latest app inventory addendum: commit `072cbd4` records 257 passing tests and adds the bounded read-only `mac_app_list` boundary. Broker authorization binds the independent `mac.app.read` scope to the exact `app_set:all` target; the adapter invokes only a fixed Broker-owned `/usr/bin/osascript -l JavaScript` program with `/` cwd, empty environment, a 10-second timeout cap, and a 256 KiB output cap. Results are schema-validated and redacted to stable bundle identity, name, optional version, and running state; bundle paths, PIDs, process arguments, environments, and caller-provided script/code do not cross the boundary. Parser, policy, contract-conformance, Broker integration, fixed-command, and real-host running-app tests pass. Evidence: `evidence/2026-09-13-app-inventory-boundary.md`. Installed-app completeness, launch/focus, app/window freshness, Accessibility, sensitive-surface policy, permission recovery, and GUI release evidence remain open.

Latest Accessibility observation addendum: the current revision adds `mac_ui_observe` as a read-only, GUI-kill-switch-bound Broker handler. Authorization requires independent `mac.ui.observe` scope and an exact `window:bundle:<bundle_id>` target rule. The adapter invokes only fixed Broker-owned `/usr/bin/osascript -l JavaScript` code with `/` cwd, empty environment, 10-second timeout, 512 KiB output, and a 2,000-node cap; it checks `AXIsProcessTrusted`, selects only the requested running bundle/window, omits element values, masks secure/password-like nodes, rejects sensitive applications and security/credential/sign-in window titles, redacts labels, and derives opaque snapshot-bound window/element refs. Parser, fixed-command, policy-schema, Broker integration, contract-envelope, secure-redaction, sensitive-target, malformed-result, and permission-denied tests pass. A real host probe for Finder failed closed with `POLICY_DENIED` because Accessibility permission was not granted; no app launch, focus, typing, clicking, or other mutation was performed. Focus freshness/action reobservation and permission-granted real-app evidence remain open. Evidence: `evidence/2026-09-13-ui-observe-boundary.md`.
Latest Accessibility observation addendum: the current revision adds `mac_ui_observe` as a read-only, GUI-kill-switch-bound Broker handler. Authorization requires independent `mac.ui.observe` scope and an exact `window:bundle:<bundle_id>` target rule. The adapter invokes only fixed Broker-owned `/usr/bin/osascript -l JavaScript` code with `/` cwd, empty environment, 10-second timeout, 512 KiB output, and a 2,000-node cap; it checks `AXIsProcessTrusted`, selects only the requested running bundle/window, omits element values, masks secure/password-like nodes, rejects sensitive applications and security/credential/sign-in window titles, redacts labels, and derives opaque snapshot-bound window/element refs. Parser, fixed-command, policy-schema, Broker integration, contract-envelope, secure-redaction, sensitive-target, malformed-result, and permission-denied tests pass. A real host probe for Finder failed closed with `POLICY_DENIED` because Accessibility permission was not granted; no app launch, focus, typing, clicking, or other mutation was performed. Focus freshness/action reobservation and permission-granted real-app evidence remain open. Evidence: `evidence/2026-09-13-ui-observe-boundary.md`.

Latest App Focus addendum: the current revision adds a disabled-by-default `mac_app_focus` mutation boundary. The Broker requires independent `mac.app.control`, an exact `app_window` target alias `window:bundle:<bundle_id>`, a `trusted_gui` approval, durable intent, a principal/session-bound Job lease, and authority checks before dispatch and terminal success. The adapter invokes only fixed Broker-owned `/usr/bin/osascript -l JavaScript` code with `/` cwd, empty environment, a 10-second timeout, and a 128 KiB output cap; it accepts only a stable bundle ID and bounded optional exact window title, sets frontmost/focus through Accessibility, and reobserves the selected window as focused before completing the Job. Sensitive bundles and credential/security/sign-in window hints or returned titles are denied by the Broker, adapter, and parser. Parser, fixed-command, policy, contract-envelope, Broker approval/Job/readback, active-revocation, and sensitive-target tests pass. No real app was focused during verification; permission-granted real-app, snapshot-bound stale-reference/focus-race, and GUI release evidence remain open. Evidence: `evidence/2026-09-13-app-focus-boundary.md`.

Latest privileged-helper addendum: commit `96acb1a` adds a proposed separately authenticated helper IPC candidate. OS peer authorization occurs before parsing; HMAC commands and responses bind the complete command digest; a separate durable nonce/request ledger rejects helper replay after restart; only `service_control`, `package_install`, and `power` operation names and exact service/package/host targets are representable; raw executables, shell text, arguments, roots, and credentials are not accepted. Results are bounded and secret-redacted, unsupported handler-map keys are rejected, and a mandatory Broker-owned authority callback is checked before dispatch, during active cancellation polling, and before response publication. The Broker-owned command factory signs only a matching explicit-approval, intent-linked running Job and rejects operation, target, payload, policy, principal/session, queued-state, kill-switch, and revocation substitutions. Authority loss or expiry cannot publish success. No root process or privileged action was run, so caller-spoof, packaging/signing, operation adapters, rollback, and independent review remain open. Evidence: `evidence/2026-09-13-privileged-helper-boundary.md`.

Latest controlled-write recovery addendum: the current revision records 247 passing tests and adds durable non-secret write descriptors with exact temporary names, a `mac_job_status` postcondition probe for unresolved writes, and an explicit host-startup cleanup hook for restart-reconciled unknown Jobs. Matching, mismatching, or unavailable target state is reported without exposing content and without changing the Job from `UNKNOWN`; exact cleanup requires root/path/name revalidation, regular non-symlink identity, native `unlinkat`/parent `fsync`/absence readback, and audited intent/completion. A completion-failure simulation, selected native `SIGKILL` crash boundaries, and an active mutations-kill-switch test confirm that a write cannot be published as success after authority is lost. Evidence: `evidence/2026-09-13-write-recovery-postcondition.md` and `evidence/2026-09-13-write-temporary-cleanup.md`. Exhaustive crash coverage, remount durability, prior-worker/process ownership, actor attribution, and release enablement remain open.

Latest Job authority addendum: the current revision transactionally cancels queued Jobs when a global/mutations/process/network switch is disabled, with tool-family matching that leaves unrelated queued capabilities intact; principal/session revocation cancels only jobs with matching persisted ownership, while edge/key/approval/policy-signer revocation conservatively cancels all queued Jobs until upstream provenance is durable. Broker request handling rechecks session, revocations, policy, target, and switch authority immediately before starting a queued Job, so a concurrent authority change cannot dispatch the stale plan. Evidence: `evidence/2026-09-13-job-authority-lifecycle.md`. Durable lease fencing now prevents stale terminal commits, while real process ownership, active process-tree termination, and restart-safe worker recovery remain open.

Latest authority-control addendum: source revision `dd824b4` adds a separate owner-only Authority Control IPC. Native UID/GID/PID peer checks run before parsing; protocol-`0.1` HMAC commands use bounded timestamp/nonce windows and a durable request/nonce replay ledger. Only `set_switch` and `revoke` operations are representable, switch changes require an expected current state, and command request IDs flow into the transactional redacted audit pair (audit evidence stores a reason digest rather than operator reason text). Focused native tests cover success, queued cancellation, wrong-key/denied-peer rejection, stale-state conflict, and replay after restart. Installed key distribution, startup/readback, active process termination, remote propagation, and executable operator recovery remain open. Evidence: `evidence/2026-09-13-job-authority-lifecycle.md`.

Latest Job lease addendum: the current revision persists a per-Broker owner ID, random lease token, bounded expiry, and heartbeat timestamp for Broker-started mutation Jobs. Active polling renews the lease; terminal success/failure/cancelled transitions require the matching lease, and an expired lease may only close as `UNKNOWN`. Restart reconciliation clears lease fields while fencing running work, so a stale worker cannot publish a result after reopen. Evidence: `evidence/2026-09-13-job-lease-fencing.md`. This remains fencing evidence rather than proof of a real macOS process tree, sandbox, credential isolation, or multi-Broker startup exclusion.

Latest ProcessSupervisor addendum: source revisions through `f0f6d1e` extend the disabled child-process boundary beyond the POSIX detached process group. On macOS, a bounded native process-identity snapshot tracks descendant PID/start-time pairs and binds the root PID to its own start-time identity; signalling the group is suppressed unless that root identity is still verified, preventing PID-reuse target swaps. TERM/KILL also targets verified descendants; Darwin execution fails closed when the native observer is unavailable. Normal completion, timeout, cancellation, output overflow, and orphan detection require group and tracked-descendant drain before returning `terminationObserved`; malformed, truncated, or failed observation returns `UNKNOWN_OUTCOME` and retains capacity until reaping proves disappearance. A hostile `fork` + `setsid` fixture passes this controlled boundary. Snapshot races, post-snapshot `setsid`, sandbox enforcement, credential isolation, and production task-runner enablement remain open. Evidence: `evidence/2026-09-13-process-group-drain.md`.

Latest sandbox runner addendum: commit `1e3eb86` records the experimental,
opt-in `SandboxExecTaskRunner` and Broker-owned deny-default Seatbelt profile
renderer. The renderer rejects raw SBPL, broad roots, cwd escapes, and
non-loopback network destinations; loopback allowlists are rendered as exact
`localhost:port` rules. Resolved profiles default to a single-process policy without
`process-fork`; the runner refuses `owned_group` even when an external proof is
supplied. It binds `/usr/bin/sandbox-exec` to a resolved TaskProfile and
passes only explicit cwd/environment/timeout/output/cancellation controls to
`ProcessSupervisor`. On the Mac mini M4/macOS 26.2 host, the 7-test opt-in
smoke allowed temporary-root read/write, denied `/private/etc/passwd`, a
root-contained `.env`, and an outside-file symlink, hid four synthetic parent
environment canaries, denied curl DNS/network access, and mapped active
`/bin/sleep` cancellation to process-group termination, and denies a Bash
child-launch attempt under the default no-fork policy. Loopback allowlists are
rendered as exact `localhost:port` rules; non-loopback destinations are
rejected. The focused real-Mac smoke was rerun from `1e3eb86` with
`MOPS_REAL_SANDBOX=1` and passes 7/7 tests. The host probe also checked only
readability of the current user's existing `.ssh`, `.docker`, Chrome, Safari,
Mail, Messages, and Keychains directories plus `/var/run/docker.sock`; all were
denied without reading contents. This is `PARTIAL`
evidence only: real credential stores, descendants/`setsid`,
crash/restart cleanup, remounts, Docker, persistence, privilege, and
allowlisted networking remain unproven; `sandbox-exec` is deprecated and the
runner is not wired into production capability enablement. Evidence:
`evidence/2026-09-13-sandbox-profile-runner.md`.

Current host readback: source revision `3d5d257` reran the focused opt-in
sandbox test at 7/7 and the complete `MOPS_REAL_SANDBOX=1 npm test` regression
at 348/348 with no skipped tests. This refreshes real-Mac evidence only; it
does not change the `BLOCKED` gate because deprecated `sandbox-exec`, real
credential/persistence isolation, descendant ownership, remount behavior, and
production runner acceptance remain unresolved.

Latest Git mutation addendum: the current revision records 252 passing tests and adds a disabled-by-default Broker-owned `mac_git_stage`/`mac_git_commit` boundary. Admission binds the exact project target, arguments, approval, mutation intent, idempotency key, and generic Job lease. Staging accepts only bounded explicit literal paths after canonical project, symlink, `.git`, and secret checks; commit binds an optional staged-diff hash precondition. Fixed `/usr/bin/git` argv disables hooks, fsmonitor, optional locks, signing, replacement objects, and network integrations, with no push/reset/remote command surface. Staged diff hash, HEAD/parent, index-empty, working-tree, target identity, redaction, and unknown-outcome readbacks are enforced, and an actual `/usr/bin/git` run against a disposable temporary repository verifies stage/commit behavior without touching the project repository. Evidence: `evidence/2026-09-13-git-write-boundary.md`. This remains prototype evidence: the tools stay policy-disabled and crash/concurrency/remount, external-actor attribution, broader redaction, and release-gate closure remain open.

Latest launchd boundary addendum: commit `fde7341` records 225 passing tests and adds canonical launchd plist rendering, no-shell/no-environment/no-root-key constraints, signal-aware service lifecycle, and bounded source/contract/policy readback. Evidence: `evidence/2026-09-13-launchd-service-boundary.md`. This is source-level packaging evidence only; installation, code signing, notarization, live `launchctl` readback, upgrade, uninstall, and rollback remain open.

Latest packaging addendum: commit `58b0b94` adds guarded uninstall evidence, and the subsequent packaging smoke test executes ad-hoc signing plus the fixed `/usr/bin/codesign --verify --strict --deep` command against a synthetic temporary bundle on the real Mac. The non-executing install plan still requires an explicit non-root `gui/<uid>` domain, canonical user-owned package paths, exactly one package-owned JavaScript entrypoint, fixed `/bin/launchctl` argv with empty environment and bounded budgets, exact previous-revision preconditions for upgrade/rollback/uninstall, and launchd/Broker/signature readback matching. This remains host command-wiring evidence only; no production artifact, launchd state, Developer ID identity, or notarization is claimed. Detailed evidence: `evidence/2026-09-13-codesign-verification.md`.

Latest install-execution addendum: commit `c59983e` adds the host-only
`executeMacOsInstallPlan` boundary. It requires exact operation confirmation
and an existing-service precondition, runs fixed bounded signature/launchctl
commands with an empty environment, applies the descriptor-backed atomic
plist, and refuses success until launchd/Broker/signature readback matches the
plan. A mismatched readback boots out the exact service and leaves the plist
and upgrade backup for explicit recovery rather than overwriting an uncertain
target. Ten focused install-plan tests pass; the full regression is 304/306
with two opt-in sandbox tests skipped and the real sandbox smoke is 7/7. No
live LaunchAgent was installed or bootstrapped; Developer ID provenance,
installed Edge identity handshake, and production enablement remain open.
Evidence: `evidence/2026-09-13-install-plan-executor.md`.

Latest filesystem preflight addendum: commit `8fe6663` adds a sixth focused test and a read-only `lstat` preflight for the user-home parent chain, package root, working directory, executable, JavaScript entrypoint, signed artifact, log directory, and optional plist. Each path is checked twice for stable device/inode identity; symlinks, foreign owners, group/other write bits, unexpected types, and owner-domain mismatch fail closed. This remains source-level evidence and does not prove descriptor-relative installation or live launchd state.

Latest atomic plist addendum: commit `b4945c3` adds a seventh focused test and `applyMacOsPlistPlan`. Temporary-root evidence covers install, upgrade backup, rollback restoration, native `openat`/`renameat`/`fsync` commit, target identity preconditions, reopened content/hash readback, and no launchd execution. Uninstall deletion, signed artifacts, live launchd state, and production installer authority remain open.

Latest uninstall addendum: commit `662801b` adds guarded native `unlinkat` and extends the seventh focused test through plist/backup uninstall. The remover accepts only a regular file under the opened authorized root with matching device/inode, fsyncs the parent, verifies absence, and attempts plist restoration if backup removal fails. This is temporary-root evidence only; no live LaunchAgent bootout, signed artifact, or production uninstall authority is claimed.

Latest native operator IPC addendum: commit `6683344` records 221 passing tests and shares one native peer-accept transport across Broker, policy-signer, and approval channels. Native UID/GID/PID policy is enforced before handler parsing; native round trips and denied-peer/no-audit cases pass. Evidence: `evidence/2026-09-13-native-operator-ipc.md`. Legacy private-descriptor verifier mode remains compatibility-only; launchd packaging, code signing, Edge PID lifecycle, protected secret distribution, and production enablement remain open.

Latest native runtime assembly addendum: commit `24f1824` records 221 passing tests and adds `createMacOsNativeBrokerRuntime`, which constructs `MacOsNativeBrokerIpcServer` before optional operator channels and delegates lifecycle rollback/recovery to `LocalBrokerRuntime`. Evidence: `evidence/2026-09-13-native-runtime-assembly.md`. This closes only the in-process transport-selection ambiguity; installed launchd packaging, code signing, Edge PID lifecycle, protected secret distribution, operator-channel native migration, and production capability enablement remain open.

Latest native IPC addendum: commit `0cdb8f0` records 220 passing tests and adds a macOS-native UDS accept boundary. The native adapter owns listener creation, `FD_CLOEXEC`/`SO_NOSIGPIPE`, owner-only mode, non-blocking accept, `getpeereid`, and `LOCAL_PEERPID`; accepted descriptors cross into Node through the public `Socket({ fd })` constructor. Denied peers are dropped before request parsing or audit, and unsafe parent directories fail closed. Evidence: `evidence/2026-09-13-native-ipc-transport.md`. This does not prove installed launchd packaging, code signing, Edge PID lifecycle wiring, Keychain/cross-process secret distribution, or production capability enablement. The legacy private-handle compatibility path remains open.

Latest native adapter-loading addendum: commit `fa96330` adds focused negative coverage for the protected `peer_credentials.node` load boundary. The loader requires canonical regular-file identity, realpath equality, bounded size, current-user ownership, no group/other write bits, stable device/inode/size across `require`, and the complete required peer-IPC export set; symlinked, writable, and non-canonical artifacts are explicitly rejected, and failures map to unavailable and fail closed. Native peer credential/IPC focused tests pass 7/7, while code signing/provenance, runtime ABI pinning, Keychain distribution, installed launchd startup, and production enablement remain open. Evidence: `evidence/2026-09-13-native-adapter-loading.md`.

Latest native consumer-boundary addendum: commit `22881f9` routes filesystem,
process, network, and process-tree production consumers through the protected
loader; a source check reports no production direct `.node` requires. Test-only
native loads remain isolated to fixtures. This removes a consumer-side bypass
of artifact canonicalization and load-identity checks; native code
signing/provenance, runtime ABI pinning, Keychain distribution, installed
launchd startup, and production enablement remain open. Evidence:
`evidence/2026-09-13-native-adapter-loading.md`.

Latest native loader cache addendum: commit `d01cf95` binds the cached native
module to the first loaded artifact's device, inode, size, and SHA-256 digest;
subsequent loads fail closed if the on-disk artifact changes, preventing a
Node-module-cache target swap. Full regression remains 295/297 with two
opt-in sandbox tests skipped. Code signing/provenance, runtime ABI pinning,
Keychain distribution, installed launchd startup, and production enablement
remain open. Evidence: `evidence/2026-09-13-native-adapter-loading.md`.

Latest native export-set addendum: commit `a447cb1` makes the shared loader
require all 17 production native exports used by IPC, filesystem, process,
network, and process-tree adapters. An incomplete artifact therefore fails
closed before any consumer operation. Full regression remains 295/297 with
two opt-in sandbox tests skipped; signing/provenance, ABI pinning, Keychain
distribution, installed startup, and production enablement remain open.
Evidence: `evidence/2026-09-13-native-adapter-loading.md`.

Latest native ABI addendum: commit `f12ab8a` makes the addon expose its
compiled N-API version and requires a supported version 8 or newer that is no
greater than the active Node runtime. The built-addon readback test and full
296/298 regression pass (two opt-in sandbox tests skipped). This is runtime
compatibility evidence only; code signing/provenance, Keychain distribution,
installed launchd startup, and production enablement remain open. Evidence:
`evidence/2026-09-13-native-adapter-loading.md`.

Latest native build-signature addendum: commit `18a418a` makes the macOS native
adapter build run fixed `/usr/bin/codesign --verify --strict` immediately after
compilation. The current Mac mini host build and direct readback pass, while a
temporary unsigned copy is rejected. The observed module is `Signature=adhoc`
with `TeamIdentifier=not set`, so this closes only build-time artifact
verification; Developer ID identity/provenance, notarization, protected
signing-key distribution, installed launchd startup, and production enablement
remain open. Evidence: `evidence/2026-09-13-native-adapter-code-signing.md`.

Latest native peer-identity addendum: commit `f76e8a0` adds an explicit
PID/start-time identity policy to the native Broker and compatibility IPC
boundaries. After native peer credentials are obtained, the server reads the
current process identity and rejects a substituted start time before socket
construction or request parsing; the focused tests also verify the matching
path and an empty audit ledger on denial. This is reusable caller-identity
evidence only. The installed Edge startup must still capture the intended
identity, survive Edge restart by failing closed, and provide signed package
provenance. Evidence: `evidence/2026-09-13-native-peer-process-identity.md`.

Latest native runtime assembly addendum: commit `752f73a` makes
`createMacOsNativeBrokerRuntime` reject a PID-only policy before constructing a
listener. The focused negative test proves the production assembly cannot
silently select the compatibility policy; installed Edge identity capture,
restart handling, signed caller provenance, and launchd readback remain open.
Evidence: `evidence/2026-09-13-native-peer-process-identity.md`.

Latest native cross-process addendum: commit `cd84e37` adds a real macOS test
with a separately spawned Node Edge fixture. The Broker captures the fixture's
PID/start-time identity before opening the listener, accepts its connection and
passes it to the bounded JSON handler, while mismatched identities are still
rejected before parsing. Focused IPC/peer/runtime tests pass 17/17 and the full
regression passes 300/302 with two opt-in sandbox tests skipped. This remains
caller-identity evidence rather than installed launchd, signed provenance, or
Edge restart/revocation evidence. Evidence:
`evidence/2026-09-13-native-peer-process-identity.md`.

Latest native Edge-lifecycle addendum: commit `9c48359` checks the captured
PID/start-time identity before listener creation and on a bounded unref'd
monitor. Identity loss closes the listener and accepted sockets, removes the
socket path, and invokes the production runtime hook that durably revokes the
exact Edge in the Broker; queued/new authority is denied and active polling
cannot publish a late success. A separately spawned `/bin/sleep` fixture proves
the loss path, durable revocation, and `ENOENT` socket removal. Focused
IPC/peer tests pass 13/13; the full regression passes 302/304 with two opt-in
sandbox tests skipped, and the real sandbox smoke remains 7/7. This is local
lifecycle evidence only; installed launchd startup/readback, signed caller
provenance, Keychain distribution, and remote issuer propagation remain open.
Evidence: `evidence/2026-09-13-native-peer-process-identity.md`.

Latest LaunchAgent identity-startup addendum: commit `f3fc18e` adds a
host-only startup assembly that accepts only `gui/<uid>/com.mac-operator.*`,
reads the exact service with bounded empty-environment `launchctl print`,
requires `running` plus a bounded PID, captures native PID/start-time identity,
and passes it into the production native runtime before listening. Wrong
domains, stopped/malformed services, unavailable identity, and missing service
readback fail closed. Ten focused startup/native tests pass; full regression is
307/309 with two opt-in sandbox tests skipped. No Mac-Operator LaunchAgent was
installed or bootstrapped, so signed package provenance and live launchd
restart/readback remain open. Evidence:
`evidence/2026-09-13-launchd-edge-identity-startup.md`.

Latest Keychain addendum: commits `ef5e336`, `44c16ad`, `be02907`, and `26cc667` add a native Security.framework
generic-password read boundary with fixed service/account namespaces,
unique-match enforcement, exact 32-byte output, and authentication-UI failure
mode for background operation. Approval issuer metadata can select the source
only through an explicit `keySource: "keychain"` entry; file-backed entries
remain compatible. Explicit provisioning now generates one random 32-byte item,
rejects duplicates, binds `kSecAttrAccessControl` to
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, disables synchronizable
replication, and returns only a digest. Missing-item, malformed-identity, and
provisioning namespace tests pass; no real secret item was created during
verification. The protected loader now requires 19 native exports. This is a
partial distribution primitive, not live-item ACL/rotation/deletion evidence,
Edge-side Keychain delivery, installed use, or production enablement.
Evidence: `evidence/2026-09-13-keychain-key-read.md`.

Latest Edge-key source addendum: commits `e9dd75e`, `7d91c8f`, `49843cc`,
`a0b31fe`, `ad781c2`, `5d5d2ce`, and `e47137a` add a versioned owner-only Edge
authentication-key config loader and atomic writer. Each entry explicitly
selects a file or Keychain source and binds an expected secret-byte SHA-256
digest; mixed metadata, duplicate identities, unsafe/canonical-path
violations, config target swaps, and invalid validity windows fail closed. A
BrokerStore is required for load-time `edge_key` revocation preflight.
`EdgeAuthenticationKeyManager` persists audited monotonic revision/digest
activation and requires exact restart restore; overlapping file-backed validity
windows prove the rotation path. The Edge request factory also has a
protected-file loader/factory with owner-only, canonical, `O_NOFOLLOW`,
bounded-encoding, and expected-digest checks; it does not fall back to
environment variables or MCP arguments. The Edge IPC client checks the
owner-only socket parent and revalidates socket device/inode identity after
connect before sending request bytes. The request factory copies signing bytes
and validates key IDs. LaunchAgent startup restores the active key config before
PID/start-time capture and native Broker construction, refusing to call
`launchctl` for an unactivated, mismatched, or cross-Edge config. Twelve focused
Edge/Broker key-source/startup tests pass; the full regression is 321/323 with
two opt-in real-sandbox tests skipped. This remains startup configuration
evidence only: Keychain provisioning/ACLs, real-item rotation or deletion,
installed launchd startup, and production capability enablement remain open.
An opt-in native peer-authenticated Edge-side Keychain delivery boundary is
implemented and separately documented, but is not enabled or installed.
Evidence:
`evidence/2026-09-13-edge-key-source-rotation.md`.

Latest Edge TLS addendum: commit `87f3a72` records 217 passing tests and adds a protected TLS material loader. Certificate and private-key files are bounded, canonical absolute owner-only regular files; symlinks, weak permissions, oversized inputs, and device/inode changes are rejected before HTTPS startup receives material. Evidence: `evidence/2026-09-13-edge-tls-material.md`. This does not prove certificate rotation, Keychain storage, remote OAuth deployment, or installed startup.

Latest lifecycle addendum: commit `10ef33a` records 214 passing tests and adds a fail-closed local Broker runtime boundary with ordered Broker-IPC/operator-channel startup, reverse cleanup, explicit recovery after cleanup failure, serialized lifecycle calls, idempotent close, and duplicate-channel rejection. The source evidence is `evidence/2026-09-13-local-runtime-lifecycle.md`; installed launchd startup, code signing, Keychain distribution, native caller identity, policy loading, store ownership, and production capability enablement remain open.

Latest exact-revision addendum: commit `e8112ea` records 209 passing tests, including the preceding signed JWT/JWKS access-token verification, issuer/metadata consistency, unknown-`kid` JWKS rotation refresh, HTTP-level metadata/invalid/expiry/scope/revocation checks, official MCP client HTTPS discovery, bounded HTTPS connection/rate limits, and local Docker daemon status readback. It adds fail-closed named-task admission, exact task-profile target and approval binding, atomic post-decision approval/intent/Job admission with owner, target, payload, and timestamp preconditions, fault-injected rollback proving no partial approval, intent, or Job, restart fail-closed recovery for an authorized request interrupted before intent, Broker Job creation/start/terminal readback, profile timeout/output-budget enforcement, bounded secret-redacted output, verified postcondition enforcement, active session-revocation handling that refuses to publish a late success, unknown-outcome handling, malformed runner-result tests, protected policy signer configuration with per-key public-key digests, monotonic activation/restore/reload, audited revocation, verified-history rollback, revocation-schema migration, a separate HMAC-authenticated owner-only operator UDS with durable replay denial and peer-denial tests, and a persistence regression proving operator-command replay remains denied after reopening the SQLite store. The 208-test paragraph below is the preceding evidence baseline; detailed records are `evidence/2026-09-12-local-broker-foundation.md`, `evidence/2026-09-13-official-mcp-client.md`, `evidence/2026-09-13-jwt-access-token.md`, `evidence/2026-09-13-task-runner.md`, `evidence/2026-09-13-task-revocation.md`, `evidence/2026-09-13-task-budget.md`, `evidence/2026-09-13-task-admission.md`, `evidence/2026-09-13-policy-signer-lifecycle.md`, `evidence/2026-09-13-policy-signer-operator-channel.md`, and `evidence/2026-09-13-policy-signer-replay.md`.

Latest privileged-helper status addendum: commits `2240870` and `86a99ca` add
and harden a
helper-owned read-only status envelope over separately authenticated local
IPC. It uses a distinct HMAC domain, strict fields, bounded timestamps,
durable replay admission, native peer policy, request-bound response proofs,
canonical distinct socket paths, positive Broker UID, bounded source/
contract/policy metadata, disabled adapter, and no enabled capabilities. The
client checks socket device/inode before and after the exchange; runtime
construction exposes the source and Broker authority gate, while the active
key manager fences status reads on expiry, revocation, and activation identity
changes. The full suite is 398 tests (395 passed, 0 failed, 3 opt-in sandbox
tests skipped); typecheck, contract verification, audit, and diff checks pass.
No root helper was installed and no launchd mutation was attempted. Evidence:
`evidence/2026-09-13-privileged-helper-status-ipc.md`.

Latest real-Mac sandbox addendum: on source revision `a8d9007`,
`MOPS_REAL_SANDBOX=1 npm test` passed 398/398 with no skipped tests; the
focused sandbox file passed 9/9. The host run covers empty child environment,
protected-file and symlink denial, selected local network allow/deny behavior,
fork/`setsid` escape denial, and active cancellation. It does not close the
blocked/open sandbox gates: real credential/Docker/persistence isolation,
remount identity, owned-group semantics, post-snapshot descendants, UDP,
external allowlisted networking, and production packaging remain unproven.
Evidence: `evidence/2026-09-13-real-sandbox-regression.md`.

Latest helper signature addendum: commit `46a3167` requires the root-domain
helper plan to bind the exact helper identifier, a ten-character uppercase
Developer ID TeamIdentifier, and a CDHash. Missing identity fields fail with
`INVALID_SIGNATURE` before filesystem or launchd actions; final codesign
readback must match all three. The focused helper package suite passes 12/12
and the default full suite remains 398 tests (395 passed, 3 sandbox tests
skipped). This is a fail-closed package gate, not evidence that a Developer ID
artifact is currently signed/notarized or installed. Evidence:
`evidence/2026-09-13-helper-signature-gate.md`.

Latest helper observer integration addendum: commits `3b24604` and `a1bd63c` wire the
authenticated helper status client into the production-shaped package
observer. Construction now requires either that explicit socket/key client or
a controlled test callback; the observer cannot silently accept a missing
runtime source. A real local signed status exchange passes through the observer
integration test, and an already-created key-manager server rejects status
reads after helper-key revocation. The latest default suite is 400 tests (397
passed, 3 opt-in sandbox tests skipped), with typecheck passing. Evidence:
`evidence/2026-09-13-helper-observer-ipc-integration.md`.

Latest helper command-client addendum: commit `6d6087d` adds the Broker-side
bounded client for already-signed helper commands. It authenticates complete
responses, caps bytes/time, fences socket device/inode identity, preserves
stable helper failures, and maps transport loss to retryable
`UNKNOWN_OUTCOME`. The latest default suite remains 400 tests (397 passed,
3 opt-in sandbox tests skipped), with typecheck passing. Evidence:
`evidence/2026-09-13-helper-command-client.md`.

Latest helper Job-executor addendum: the disabled-by-default Broker executor
renews a persisted Job lease, binds command operation/target/payload/policy to
the Job, rechecks authority before and after helper dispatch, and persists
verified completion or conservative `UNKNOWN_OUTCOME`. Its command-client
binding clears short-lived helper key buffers. The focused executor suite
passes 5/5; the default suite passes 404/407 with 3 opt-in sandbox tests
skipped. No privileged tool, adapter, root helper, or launchd service is
enabled. Evidence: `evidence/2026-09-13-helper-job-executor.md`.

The Broker integration seam is covered by a regression asserting that the
default constructor rejects privileged execution without changing a Job.

The follow-on payload-boundary slice persists an allowlisted typed descriptor
for privileged Jobs, restores it after BrokerStore restart, and validates the
same descriptor in the signed helper envelope. Extra fields, secret-shaped
values, unbounded strings, target/operation mismatches, and canonical digest
mismatches fail closed. The default policy contains no privileged entries and
the helper adapter remains disabled; this evidence does not claim helper
installation or real privileged execution.

The persistence boundary now also has a versioned `ledger-records.schema.json`
covering Request, Approval, Job, and Audit envelopes. AJV positive/negative
tests reject malformed lifecycle values and raw helper authority fields, and
`verify:contracts` compiles the schema alongside all 44 MCP contracts. Runtime
cross-field checks remain in BrokerStore. Host-only Broker backup/restore/
retention primitives now provide owner-only atomic encrypted snapshots, SQLite
quick check and audit-chain verification, fresh-target restore, numeric
retention, migration registry/rollback policy, and symlink/ownership/mode/
size/target-swap refusal. Disk exhaustion, production migration cutover, and
stronger audit anchoring remain open.
Evidence: `evidence/2026-09-13-ledger-record-contracts.md`.

The ledger-contract revision reran the full suite at 409 tests (406 passed,
3 opt-in sandbox tests skipped). Typecheck, dependency audit, and diff checks
also pass; contract verification reports the 44 MCP contracts plus the
versioned ledger-record schema.

The persistence recovery revision reran the full suite at 412 tests (409
passed, 3 opt-in sandbox tests skipped). The focused Broker persistence suite
passes 29/29, including owner-only backup/restore readback, numeric retention,
symlink refusal, and modified-audit-chain rejection. Typecheck, contract
verification, dependency audit, and diff checks are part of the local commit
verification. Evidence:
`evidence/2026-09-14-persistence-backup-restore.md`.

The persistence crash/concurrency addendum adds a hard-killed child-process
backup test with stale temporary and SQLite WAL/SHM/journal sidecar cleanup, a
five-second SQLite busy timeout, a simulated ENOSPC retryable-failure test,
an insufficient-capacity preflight, and two independent Broker writers whose
final audit chain verifies after reopen. The focused persistence suite now
passes 33/33; real kernel/disk-quota exhaustion and explicit single-owner
service evidence remain open. Evidence:
`evidence/2026-09-14-persistence-backup-restore.md`.

The crash/concurrency addendum reran the full suite at 416 tests (413 passed,
3 opt-in sandbox tests skipped), with no failures.

Physical macOS host verification then ran `MOPS_REAL_SANDBOX=1 npm test` on
Darwin arm64: 416 tests passed, 0 failed, and 0 skipped. The run includes the
real macOS sandbox, process-group cancellation, service-lock, launchd
read-only, and authenticated Edge/Broker integration checks. It does not
claim kernel-level quota exhaustion or an installed production launchd service.

The live launchd readback boundary was additionally exercised with a unique,
temporary user-domain `/bin/sleep` LaunchAgent. The production adapter parsed
the observed `xpcproxy` bootstrap state as `launching` (without treating it as
running), then the service was booted out and confirmed absent. The focused
launchd readback/service-inspector suites pass 7/7, including the regression.
No persistent service or
capability was installed. Evidence:
`evidence/2026-09-14-live-launchd-readback.md`. The updated default suite is
420 tests (417 passed, 3 opt-in sandbox tests skipped); the real-sandbox suite
is 420 passed with 0 skips.

The live smoke also exercised `captureLaunchdEdgeProcessIdentity` against a
temporary user LaunchAgent. It captured a positive PID/start-time identity
after the `xpcproxy` transition, retrying only that explicit transient under a
five-second global deadline, then booted the service out and confirmed
absence. Native startup focused tests pass 7/7; malformed, stopped, and
identity-failure paths remain fail-closed.

The Broker instance-lock boundary also has a real non-cooperating-process
test: a child holds the owner-only lock, the parent receives `ALREADY_ACTIVE`,
and reclamation succeeds only after the child's PID/start-time identity is
proven stale. Focused lock tests pass 5/5. This does not claim launchd
singleton enforcement or remount durability. Evidence:
`evidence/2026-09-14-service-instance-lock-process.md`.

The host-only macOS install plan also has a physical-Mac package smoke:
ad-hoc signature verification, owner-only package layout, atomic plist
publication, fixed `launchctl bootstrap`, real zero-capability Broker startup,
independent double-read launchd/native/plist/Broker/signature verification,
exact uninstall, and final service/plist absence all passed. The package smoke
used its historical owner-only fixture; the current startup assembly now
provides a separate HMAC-authenticated Broker status socket with native peer
credentials and durable replay rejection, exercised by the focused physical
host startup test. Developer ID, upgrade/rollback, and helper gates remain
open.
Evidence: `evidence/2026-09-14-live-install-plan.md` and
`evidence/2026-09-14-broker-status-ipc.md`.

The live startup-assembly smoke then called
`createBrokerServiceFromStartupConfig` with the real launchd command path. A
temporary user LaunchAgent supplied the positive PID/start-time identity;
temporary signed policy and Edge-key activations restored before native Broker
listener construction; the service reached `running` with zero enabled
capabilities and a mode-`0600` socket, then closed and removed that socket.
This is physical-host startup evidence only, not installed-package,
installed Edge request packaging, Developer ID, or privileged-helper evidence.
The separate native HTTPS Edge smoke now covers local request exchange;
installed deployment remains open. Evidence:
`evidence/2026-09-14-live-broker-startup.md`.

Latest native HTTPS Edge addendum: the physical Darwin test now selects
`MacOsNativeBrokerIpcServer` for the HTTPS Edge/Broker end-to-end path,
captures the peer PID/start-time identity, verifies signed `mac_health`
responses, rejects request replay, and confirms bearer-token redaction from
Broker audit rows. Evidence:
`evidence/2026-09-14-native-https-edge.md`.

The documentation evidence for `VT-CON-01` and `VT-CON-02` includes JSON validity and envelope-schema validation, functional input/output schema compilation for all 44 contracts, exactly 44 contracts, catalog/contract parity, field/taxonomy checks, unique tool/provenance IDs, bounded-field checks, forbidden-authority-field checks, output/verification compatibility checks, excluded-interface checks, and full documentation diff review. These PASS results prove contract-document integrity and functional schema completeness only; they do not prove runtime implementation, API compatibility in a running server, postcondition behavior, authorization enforcement, or host safety. Runtime rows remain `OPEN` or `BLOCKED` because the 44 tools are still planned and no 44-tool runtime evidence exists.

`evidence/2026-09-12-local-broker-foundation.md` records 180 passing tests on a Mac mini M4/macOS 26.2 for the bounded Edge/Broker/IPC/policy, sanitized system/process/network/service/log/Git/package/Docker inspection, descriptor-backed metadata/content/hash/list/tree/find/recent/search-text/project-discover/project-summary/storage-analysis/write worker, atomic-write, and Request/Approval/Job Ledger prototypes. The Edge factory uses MCP SDK v2 modern protocol handling, Broker-filtered tool discovery, and stable redacted mapping for Broker and transport failures; it never forwards bearer tokens to IPC. It adds bounded single-PID process inspection with independent process scope, redacted owner identity, bounded executable/name/state/resource metadata, parent/child PID identities, and no argv/environment output, plus allowlisted system launchd status via fixed `/bin/launchctl` execution with empty environment, bounded output, timeout/cancellation, safe state/exit/PID parsing, and no mutation. It also adds allowlisted `system`/`process/<name>` log tails via fixed `/usr/bin/log` execution with empty environment, bounded compact-format parsing, 24-hour effective window cap, line/output budgets, malformed-record warnings, and mandatory secret/path redaction before result or audit. Git status, branch listing, log, and diff use an exact authorized project root, fixed `/usr/bin/git`, porcelain-v2/ref/log/diff parsing, a fixed non-secret environment, disabled hooks/fsmonitor/optional locks and external diff/textconv/rename behavior, bounded status/branch/commit/diff output, literal path and revision validation, secret-pattern redaction, sanitized diff hashing, repository-config executable-integration rejection, and root/metadata identity readback. Package inspection uses independent `mac.package.read` scope, exact project target authorization, descriptor-backed non-symlink manifest/lock checks, bounded npm/pnpm/yarn/pip/uv/poetry/Brewfile parsing, protected-content denial, cancellation, no script execution, and explicit disabled outdated-registry behavior. Docker inspection uses independent `mac.docker.read` scope, exact runtime/object targets, fixed local Unix-socket environment and CLI arguments, bounded status/object/log parsing, environment omission, mount/log redaction, and cancellation/timeout mapping without raw socket proxying; storage facts and host daemon compatibility remain open. It also adds local interface metadata and inferred connectivity without active probes or packet capture; optional listener metadata remains unavailable until a version-pinned native ABI is available. Native process inventory/detail, service, log, Git, package, and Docker inspection run behind Broker-controlled bounded execution with strict result validation and active authority checks, alongside metadata-only file discovery, recent-file metadata, content-authorized text search, metadata-only project discovery, metadata-only project summary, and metadata-only storage analysis with independent scopes, per-root authorization, fixed traversal/text/project/storage budgets, descriptor-verified volume capacity, ranked consumers, UTF-8/binary handling, protected-entry and secret-content filtering, sanitized snippets, safe allowlisted project markers, safe manifest/language inference, bounded structure metadata, explicit VCS branch/dirty omission warnings, dependency-directory pruning, and worker cancellation, alongside descriptor-backed SHA-256/SHA-512 hashing without content return and target-change rejection, bounded directory metadata pagination with protected-entry filtering and directory identity checks, depth/entry-bounded tree traversal with truncation and inherited volume filtering, exact single-use approval binding and atomic intent consumption, descriptor-backed create/replace with hash/readback and create-only preconditions, durable write-job idempotency/status/restart recovery, future-job admission with idempotent reuse and conflict rollback, injected admission rollback/restart readback, replay admission, restart-safe request recovery, payload-bound job idempotency, owner-bound status/cancel, and terminal recovery evidence. It is exact-revision prototype evidence and cannot close a release gate. Authenticated approval issuance, outdated registry reads, real OAuth/remote transport, process-owned jobs, sandbox, write crash recovery/partial-mutation, GUI, helper, packaging, release-runbook, and release-gate rows remain open or blocked.

Docker result-boundary verification at source revision `50fd2fb` adds plain
known-field container/image records, conflicting-ID rejection, bounded nested
inspection data, and capped Docker log line count/bytes before redaction.
Focused Docker tests pass 9/9; the non-overlapping package regression passes
533 total (527 passed, 6 skipped, 0 failed). This is local CLI result-shape
evidence only; daemon compatibility, storage, isolation, raw-socket negatives,
packaging, and capability enablement remain open. Evidence:
`evidence/2026-09-15-docker-result-boundary.md`.

Install-plan readback verification at source revision `61e7357` adds
data-only guards for service, component, existing-service, and signature
observations. The focused install-plan suite passes 22/22 with hostile
inherited/accessor fixtures rejected. This remains local representation
evidence and does not close Developer ID, persistent install, production
upgrade/rollback, helper, or capability gates. Evidence:
`evidence/2026-09-15-install-readback-boundary.md`.

Edge IPC response verification at source revision `adddedd` adds exact
data-only envelope/result validation before MCP publication. The focused Edge
IPC suite passes 4/4, including valid signed round-trip and hostile
unknown/accessor fixtures. This is Edge representation evidence only and does
not close Broker correctness, remote deployment, production key lifecycle,
installed provenance, or capability gates. Evidence:
`evidence/2026-09-15-edge-ipc-response-boundary.md`.

Persisted process ownership verification at source revision `7ad478c` adds
exact data-only identity/snapshot checks and dense descendant validation before
native recovery. The focused supervisor suite passes 33/33 with hostile
accessor/inherited/unknown fixtures rejected. This remains representation
evidence only and does not close descendant escape, kernel termination,
credential isolation, production task, or installed recovery gates. Evidence:
`evidence/2026-09-15-process-ownership-readback.md`.

Post-hardening release verification reran the non-overlapping package suite:
536 total, 530 passed, 6 skipped, 0 failed. Typecheck, style, versioned
contract validation, native canonical-JSON vectors, and `git diff --check`
passed. The two pre-existing long-lived Broker/persistence test processes
were excluded and left untouched.

Audit evidence verification at source revision `fbb197b` confirms recursive
redaction traverses only plain records and dense arrays. The focused audit
evidence tests pass 2/2, including accessor/inherited/symbolic fixtures. This
does not close SQLite corruption/disk exhaustion, external anchoring,
production Keychain, installed recovery, or release acceptance. Evidence:
`evidence/2026-09-15-audit-evidence-boundary.md`.

Privileged-helper status request verification at source revision `026a83f`
confirms status envelope classification, candidate recovery, and unsigned
validation reject accessor and inherited fields before authority-sensitive
reads. The focused boundary test passes 1/1. The non-overlapping package
regression passes 537 total (531 passed, 6 skipped, 0 failed). This remains
representation evidence only and does not close helper provenance, production
Keychain, root-domain installation, real privileged execution, crash recovery,
or capability enablement. Evidence:
`evidence/2026-09-15-helper-status-boundary.md`.

Helper status readback verification at source revision `e9d67e6` confirms the
readback validator checks plain-data shape before key enumeration or state
access. Focused request/readback tests pass 2/2; the complete non-overlapping
package regression passes 538 total (532 passed, 6 skipped, 0 failed). This
remains representation evidence only and does not close helper provenance,
production Keychain, root-domain installation, real privileged execution,
crash recovery, or capability enablement. Evidence:
`evidence/2026-09-15-helper-status-boundary.md`.

Broker status request verification at source revision `240ee88` confirms the
unsigned validator rejects accessor and inherited fields before key enumeration
or authority-sensitive reads. The focused parser test passes 1/1; the
non-overlapping package regression passes 538 total (532 passed, 6 skipped,
0 failed). This remains representation evidence only and does not close
production deployment, Keychain, remote transport, privileged operations, or
capability enablement. Evidence:
`evidence/2026-09-15-broker-status-boundary.md`.

Status-array verification at source revision `987cadc` confirms Broker and
privileged-helper readbacks reject extra enumerable/accessor, symbolic, and
sparse capability-list shapes before publication. Focused status readback tests
pass 2/2; the non-overlapping package regression passes 538 total (532 passed,
6 skipped, 0 failed). This remains representation evidence only and does not
close production deployment, Keychain, remote transport, privileged
operations, or capability enablement. Evidence:
`evidence/2026-09-15-status-array-boundary.md`.

Startup-config verification at source revision `345b329` confirms the Broker
startup validator rejects accessor and inherited configuration objects before
key enumeration, path normalization, or authority checks. The focused test
passes 1/1; the non-overlapping package regression passes 538 total (532
passed, 6 skipped, 0 failed). This remains representation evidence only and
does not close Developer ID, installed lifecycle, Keychain, remote deployment,
helper, or release gates. Evidence:
`evidence/2026-09-15-startup-config-boundary.md`.

Schema migration verification at source revision `7ce59c1` confirms startup
reads back the exact schema marker and ordered migration registry before
recovery. Three focused migration tests pass (3/3), including tampered
registry rejection; the non-overlapping package regression passes 538 total
(532 passed, 6 skipped, 0 failed). This does not close physical disk recovery,
production backups, Keychain deployment, installed recovery, or release
acceptance. Evidence:
`evidence/2026-09-15-schema-migration-readback.md`.

Runtime policy-array verification at source revision `d1f96f2` confirms
principal scopes, target rules, filesystem roots, deny paths, tool scopes, and
capability families reject sparse, symbolic, accessor, and extra-property
arrays before authority use. Focused tests pass 2/2; the non-overlapping
package regression passes 539 total (533 passed, 6 skipped, 0 failed). This
does not close ADR-0004, production signer/Keychain, installed reload, or
capability enablement. Evidence:
`evidence/2026-09-15-policy-array-boundary.md`.

Broker family-limit verification at source revision `0a97e3f` confirms the
constructor rejects inherited and accessor-shaped `maxActiveRequestsByFamily`
overrides before merging or reading values. Focused constructor tests pass
2/2; the non-overlapping package regression passes 539 total (533 passed, 6
skipped, 0 failed). This is configuration-shape evidence only and does not
close process-wide/adapter quotas, kernel or disk limits, production
packaging, or capability enablement. Evidence:
`evidence/2026-09-15-broker-family-limit-boundary.md`.

Durable admission-limit verification at source revision `999435d` confirms
`BrokerStore` rejects inherited and accessor-shaped global/session/family
limit records before key enumeration, value reads, or request insertion. The
focused persistence test passes 1/1; the non-overlapping package regression
passes 539 total (533 passed, 6 skipped, 0 failed). This remains local
configuration-shape evidence and does not close kernel/process quotas, disk
exhaustion, or production service evidence. Evidence:
`evidence/2026-09-15-admission-limit-boundary.md`.

Active approval verification at source revision `b4cac00` confirms Broker
revalidates consumed mutation approvals during pre-dispatch, active control,
and final readback. Revocation cancels the request, keeps a started Job
`unknown`, and prevents a success response. The focused Broker test passes
1/1; the non-overlapping package regression passes 539 total (533 passed, 6
skipped, 0 failed). Human approval UI/channel, protected Keychain,
unattended ownership, and production service evidence remain open. Evidence:
`evidence/2026-09-15-active-approval-revalidation.md`.

Edge configuration verification at source revision `04fcffc` confirms startup
documents are plain data records and Host/Origin lists are dense bounded
arrays before URL/path validation or listener setup. Inherited, accessor,
symbolic, and sparse fixtures are rejected. Focused Edge tests pass 2/2; the
non-overlapping package regression passes 540 total (534 passed, 6 skipped,
0 failed). This does not close TLS/key lifecycle, remote deployment, launchd
installation, or capability enablement. Evidence:
`evidence/2026-09-15-edge-config-shape-boundary.md`.

Contract-registry verification at source revision `fa0dc50` confirms Edge
contract records are plain data and reject unknown top-level fields before
exposure to MCP construction. Focused registry tests pass 2/2; the
non-overlapping package regression passes 541 total (535 passed, 6 skipped,
0 failed). This does not close handler completeness, signing provenance,
remote deployment, or capability enablement. Evidence:
`evidence/2026-09-15-contract-registry-boundary.md`.

MCP capability-readback verification at source revisions `0b8c7e2`, `3f65dc8`
confirms plain response data, dense bounded arrays, governed fields, and
optional `scopes`/`reason` metadata are validated before tool registration.
Unknown, accessor, symbolic, and sparse fixtures are rejected. Focused Edge
tests pass 2/2; the non-overlapping package regression passes 542 total (536
passed, 6 skipped, 0 failed). This does not close Broker handler completeness,
remote deployment, or capability enablement. Evidence:
`evidence/2026-09-15-mcp-capability-boundary.md`.

Principal-projection verification at source revision `ce198e1` confirms Edge
rejects inherited/accessor identity metadata and accessor/sparse/symbolic scope
arrays before scope filtering or request creation. The focused projection suite
passes 3/3; the non-overlapping package regression passes 543 total (537
passed, 6 skipped, 0 failed). This does not close OAuth provider correctness,
key rotation, remote deployment, or capability enablement. Evidence:
`evidence/2026-09-15-principal-projection-boundary.md`.

Direct policy-input verification at source revision `88d9179` confirms exported
authorization helpers reject malformed projected scopes and targets before
matching or grant lookup. Focused policy tests pass 2/2; the non-overlapping
package regression passes 544 total (538 passed, 6 skipped, 0 failed). This
does not close production signer/Keychain distribution, installed reload, or
capability enablement. Evidence:
`evidence/2026-09-15-policy-input-boundary.md`.

Scope-boundary verification confirms request parsing and direct `authorizeTool`
calls reject duplicate, unknown, sparse, or oversized principal scope arrays
with `AUTH_INVALID` before authority lookup. The focused policy/security-fuzz
suite passes 15/15. This remains local representation evidence and does not
close production token issuance, cross-process identity packaging, or
capability enablement. Evidence:
`evidence/2026-09-15-scope-boundary.md`.

Target-grant verification at source revision `d785eb0` confirms direct target
authorization rejects disabled principal grants and requested scopes outside
the enabled grant before rule matching. Focused policy/security-fuzz tests pass
16/16; the non-overlapping package regression passes 546 total (540 passed, 6
skipped, 0 failed). Production policy distribution and capability enablement
remain open. Evidence:
`evidence/2026-09-15-target-grant-boundary.md`.

Kill-switch scope verification at source revision `6bf29d4` confirms the
`mutations` switch cancels queued mutation Jobs without cancelling a queued
`mac_health` read Job. A temporary BrokerStore smoke passes after build; the
non-overlapping package regression remains 546 total (540 passed, 6 skipped,
0 failed). This does not close physical process ownership or production
service evidence. Evidence:
`evidence/2026-09-15-kill-switch-scope-isolation.md`.

Fail-closed kill-switch verification at source revision `fe6a187` confirms
`mutations` preserves only known read-only queued Jobs and cancels both known
mutation and unknown future-tool Jobs. Build and a temporary BrokerStore smoke
pass; the non-overlapping package regression remains 546 total (540 passed, 6
skipped, 0 failed). Physical process ownership and production service evidence
remain open. Evidence:
`evidence/2026-09-15-kill-switch-fail-closed.md`.

Job Edge-provenance verification at source revisions `e0b9db8`, `66688ec`,
`9a52c59`, `8dbbd67`, `08c8100`, and `b31cf4c` confirms schema versions `10` and `11` add nullable
`owner_edge_id` and `owner_edge_key_id` columns with forward-only migration for
legacy ledgers. Broker-created mutation Jobs bind the authenticated Edge and
Edge-key, idempotent reuse checks both identities, and Edge/Edge-key revocation
cancels only matching queued Jobs; legacy/null and malformed provenance remain
conservative or fail closed. Restarted guest recovery rechecks persisted Edge
provenance and Edge-key revocation before a status lookup. `npm run build`, typecheck,
lint, and a temporary SQLite schema/readback/revocation smoke pass. The
non-overlapping package regression remains 546 total (540 passed, 6 skipped,
0 failed). The new persistence tests are recorded but were not run separately
because the long-lived persistence test process was already active; physical
Edge lifecycle and production service evidence remain open. Evidence:
`evidence/2026-09-15-job-edge-provenance.md`.

Edge-keyring identity-boundary verification at source revision `a2580e0`
confirms direct keyring construction rejects malformed, traversal-shaped, and
overlong Edge/key IDs before inserting authentication authority. The same
bounded Edge identity predicate is reused by Edge config loading, persisted Job
provenance readback/creation, and `Broker.revokeEdge`; focused keyring/config
tests pass 9/9. Build, typecheck, lint, contract verification, and diff checks
pass; the non-overlapping package regression passes 547 total (541 passed, 6
skipped, 0 failed). This is local constructor/loader consistency evidence only; production
key distribution, signing provenance, and installed-service evidence remain
open. Evidence:
`evidence/2026-09-15-edge-keyring-identity-boundary.md`.

Edge-key identity length verification at source revision `6fdc725` confirms
the full bounded composite identity is accepted consistently: maximum 128
character Edge and key components produce a 257-character revocation subject,
which passes keyring, Authority Control parser, Job provenance, and persistence
subject validation. The non-overlapping package regression passes 549 total
(543 passed, 6 skipped, 0 failed). This does not close production key
distribution, signing provenance, or installed-service evidence. Evidence:
`evidence/2026-09-15-edge-key-identity-length.md`.

`mac_ui_type` boundary verification confirms bounded text and nine allowlisted
keys stay off argv through ProcessSupervisor stdin, secret-like text is denied,
secure/redacted snapshots and non-text controls fail closed, and the exact
snapshot is reobserved with focus and input postconditions before success.
Focused UI, policy-loader, and ProcessSupervisor tests pass; the
non-overlapping package regression passes 553 total (547 passed, 6 skipped,
0 failed). The feature remains disabled by default and real permission-granted
Accessibility evidence is still required. Evidence:
`evidence/2026-09-15-ui-type-boundary.md`.

Job-state verification confirms BrokerStore rejects corrupted state/result
combinations and invalid lifecycle timestamps, leases, or cancellation markers
before exposing a Job. A cancellation request increments the Job revision and
fences a late success; only an explicit unknown recovery can close the active
Job safely. Focused invariant/corruption tests pass 2/2, and the existing
persistence suite passes 56/56. This does not close physical disk exhaustion,
production identity, or ADR acceptance. Evidence:
`evidence/2026-09-15-job-state-invariants.md`.

Request-state verification confirms BrokerStore rejects corrupted request
state/result combinations and timestamp rollback before request readback or
recovery. Mutation approval and Job identifiers are also bounded and cannot be
attached to a non-mutation request. Focused request invariant tests pass 3/3;
the non-overlapping package regression passes 558 total (552 passed, 6
skipped, 0 failed). Production identity, disk-exhaustion behavior, and ADR
acceptance remain open. Evidence:
`evidence/2026-09-15-request-state-invariants.md`.

Audit-row verification confirms malformed persisted sequence, identity/text,
event, timestamp, hash, and evidence JSON fields fail closed as
`AUDIT_UNAVAILABLE` before audit readback. Focused audit-row corruption tests
pass 1/1; the non-overlapping package regression passes 559 total (553
passed, 6 skipped, 0 failed). External rollback-resistant anchoring,
production identity, and final ADR acceptance remain open. Evidence:
`evidence/2026-09-15-audit-row-invariants.md`.

Audit write-boundary verification confirms malformed events are rejected before
SQLite insertion and leave no partial audit row. Combined audit write/read
tests pass 2/2; the non-overlapping package regression passes 560 total (554
passed, 6 skipped, 0 failed). Evidence:
`evidence/2026-09-15-audit-row-invariants.md`.

Accessibility permission-denial verification confirms the real Finder probe
returns stable `POLICY_DENIED` and no UI nodes or labels when host permission
is absent. Permission-granted real-app evidence and GUI mutation readback
remain open. Evidence:
`evidence/2026-09-15-ui-permission-denial-host-readback.md`.

Dependency verification reports zero high-severity-or-greater npm advisories
from `npm audit --omit=dev --audit-level=high`. This point-in-time check does
not replace native artifact provenance, macOS signing, runtime isolation, or
independent release review. Evidence:
`evidence/2026-09-15-dependency-audit.md`.

Privileged-helper verification passes 38/38 boundary tests for independent
peer/HMAC authentication, replay denial, allowlists, typed payloads,
helper-owned status, trailing-frame rejection, denied peers, Job binding, and
active revocation. No real privileged mutation was performed. Production
installation, signing, Keychain, and enablement remain open. Evidence:
`evidence/2026-09-15-helper-boundary-38-tests.md`.

The helper/install-plan focused suite passes 47/47 on the physical macOS host
at source revision `3d9e326`. Install plans, signature/readback composition,
socket and native peer boundaries, revision preconditions, host confirmation,
non-root rejection, and recovery ordering remain fail-closed. No root command,
launchd bootstrap, package installation, reboot, shutdown, Keychain
provisioning, or privileged mutation was executed. Developer ID provenance,
real root-domain lifecycle, protected production Keychain material, and
independent release review remain open. Evidence:
`evidence/2026-09-15-helper-install-plan-47-tests.md`.

The local CI-equivalent native canonical-JSON check passes 5/5 vectors and
`npm audit --audit-level=high` reports zero vulnerabilities at source revision
`48d5b12`. This confirms the repository-local gates only; no remote GitHub
Actions execution is claimed, and packaging, signing, runtime isolation, and
release review remain open. Evidence:
`evidence/2026-09-15-ci-local-equivalent.md`.

Approval readback verification at source revision `28b26db` enforces bounded
identity/target/digest fields, expiry and timestamp ordering, single-use
consumption state, revocation pairing, and revision monotonicity before a
persisted Approval can influence authority. Focused approval authority and
corruption tests pass 14/14 with stable `AUDIT_UNAVAILABLE` on malformed rows.
Protected production Keychain/cross-process storage, human approval UI,
unattended ownership, and ADR acceptance remain open. Evidence:
`evidence/2026-09-15-approval-row-invariants.md`.

The non-overlapping package regression after the Approval readback change
reports 563 tests total (557 passed, 6 explicitly skipped, 0 failed). The
already-running `broker.test.js` and `persistence.test.js` processes were
excluded, so this is a bounded regression result rather than a claim about a
fresh full-suite run. Evidence:
`evidence/2026-09-15-approval-row-invariants.md`.

Authority-row verification at source revision `e11127e` validates revocation
and kill-switch query identities and persisted fields before authority use.
Malformed queries return `PRECONDITION_FAILED`; corrupted rows return stable
`AUDIT_UNAVAILABLE`. Focused Authority Control IPC, Policy, and corruption
tests pass 15/15. Production Keychain distribution, installed operator
recovery, external rollback detection, and ADR acceptance remain open.
Evidence: `evidence/2026-09-15-authority-row-invariants.md`.

The non-overlapping package regression after the authority-row change reports
565 tests total (559 passed, 6 explicitly skipped, 0 failed). The existing
`broker.test.js` and `persistence.test.js` processes were excluded because
they were already running, so this is bounded local evidence rather than a
fresh full-suite run. Evidence:
`evidence/2026-09-15-authority-row-invariants.md`.

Replay-ledger verification at source revision `100133e` scans all seven
Broker-owned nonce tables after migration and fails closed on malformed
identities, nonce formats, timestamp ordering, or guest-ledger over-capacity.
Focused replay corruption tests pass 7/7; the combined replay/Approval/
Authority slice passes 12/12. The non-overlapping package regression passes
572 total (566 passed, 6 explicitly skipped, 0 failed). Broader
canonicalization, retention, protected Keychain, installed recovery, external
rollback detection, and ADR acceptance remain open. Evidence:
`evidence/2026-09-15-replay-row-invariants.md`.

Configuration-ledger verification at source revision `7a34191` validates all
Policy/configuration history rows and active singletons after migration, binds
active identities to matching history, and repeats the checks in identity
getters. Malformed revisions, digests, timestamps, Policy metadata, or
active/history mismatches fail closed as `AUDIT_UNAVAILABLE`. Focused
configuration plus Policy and policy-signer tests pass 26/26; the
non-overlapping package regression passes 579 total (573 passed, 6 explicitly
skipped, 0 failed). Production Keychain distribution, installed recovery,
external rollback detection, and ADR acceptance remain open. Evidence:
`evidence/2026-09-15-configuration-row-invariants.md`.

Restart-reconciliation clock-order verification at source revision `5148a8b`
rejects a recovery timestamp earlier than persisted Request received/updated
or Job created/start/heartbeat timestamps before any transition. Focused
Request, Job, and runtime tests pass 9/9; the non-overlapping package
regression passes 582 total (576 passed, 6 explicitly skipped, 0 failed).
Crash ownership, real clock/rollback behavior, production Keychain, installed
recovery, external rollback detection, and ADR acceptance remain open.
Evidence: `evidence/2026-09-15-reconciliation-clock-order.md`.
