# Mac-Operator-MCP Progress

Status: Phase 1 Broker and authenticated MCP Edge foundation in progress
Version: 0.1
Last verified: 2026-09-15

Process executable permission addendum: source revision `339d932` rejects
group- or other-writable executable files before child admission and lets the
Broker's fixed-adapter supervisor require root ownership. Owner UID/GID now
participate in identity readback; canonical path, non-symlink, descriptor-backed
digest, and post-spawn checks remain. Build, lint, and the focused
ProcessSupervisor suite pass 36/36 on the physical Darwin host. This hardens
fixed adapter preflight but does not provide kernel-held descriptor execution or
remount resistance; those remain open with production task enablement. Evidence:
`evidence/2026-09-15-process-executable-permissions.md`.

Packaged-service host addendum: source revision `339d932` passes the physical
Darwin `MOPS_REAL_INSTALL=1 node --test
packages/broker/dist/packaged-service-smoke.test.js` smoke (1/1). The test
bootstraps temporary-user Edge and Broker LaunchAgents, verifies executable and
argument readback, PID/start-time identity, owner-only IPC sockets, authenticated
Broker status, then boots both out and confirms label absence with temporary
Keychain/data cleanup. It skips without mutation when fixed labels are already
loaded. This closes the temporary packaged lifecycle slice only; Developer ID,
production fixed-label ownership, deployment/rotation, and crash/remount
durability remain open. Evidence:
`evidence/2026-09-15-packaged-service-smoke.md`.

Write-cleanup Job-recovery addendum: source revision `bfc9a28` persists the
temporary device/inode before unlink and reconnects restart reconciliation to
the explicit native quarantine recovery boundary. Recovery derives the exact
temporary basename from the Job record, removes only a unique stale
identity-bound quarantine, and preserves recent, ambiguous, replacement, or
unproven artifacts. Completion audit classes distinguish removed, recovered,
absent, and skipped outcomes. Build, lint, and the focused filesystem plus
Job-recovery suites pass 39/39, including a child-process SIGKILL immediately
after native quarantine rename. Production remount injection and
installed-service evidence remain open. Evidence:
`evidence/2026-09-15-write-recovery-journal.md`.

Service-lock and audit-anchor orphan-recovery addendum: source revision
`3ddc056` adds timestamped UUID/basename-fingerprint quarantine
names plus explicit recovery. Service locks require stale PID/start-time
proof; audit locks require the host stop gate. Both paths require stable
owner-only parents, exact regular single-link identity, bounded age, unique
selection, and post-removal readback; active, unknown, recent, malformed, or
ambiguous candidates remain untouched. Build, lint, diff checks, and the
dedicated 6-test service-lock and 10-test audit-anchor/read-only suites pass.
Production crash/remount evidence remains open. Evidence:
`evidence/2026-09-15-service-lock-orphan-recovery.md` and
`evidence/2026-09-15-audit-anchor-lock-orphan-recovery.md`.

IPC socket orphan-recovery addendum: source revision `49b575a` adds
timestamped UUID/basename-fingerprint quarantine names and explicit recovery
requiring canonical owner-only parent identity, matching socket device/inode,
inactive liveness, bounded age, and a unique stale candidate. Recent, active,
mixed-age, and ambiguous entries remain untouched; removal has absence
readback. Build, lint, diff checks, and the dedicated 11-test Darwin IPC suite
pass. Production crash/remount evidence remains open. Evidence:
`evidence/2026-09-15-ipc-socket-orphan-recovery.md`.

Filesystem unlink orphan-recovery addendum: the native unlink boundary now
records a timestamped, nonce-bearing basename fingerprint in its private
quarantine name and exposes explicit recovery that requires the original
device/inode, bounded age, same-root canonical parent, and a unique regular
single-link match. Recent or ambiguous artifacts remain untouched. Build,
lint, typecheck, diff checks, and the dedicated 36-test filesystem suite pass;
the Darwin physical probe covers stale, recent, and wrong-target cases.
Production crash/remount evidence remains open; persisted Job integration is
covered by `def8e82` above.
Evidence: `evidence/2026-09-15-filesystem-unlink-orphan-recovery.md`.

Backup-quarantine age-test addendum: source revision `4db2d0d` adds dedicated
coverage for stale cleanup, recent-entry preservation, and invalid timestamp
fail-closed behavior. Build, lint, typecheck, diff checks, and the 3-test
quarantine suite pass; native unlink recovery and production crash/remount
evidence remain open. Evidence:
`evidence/2026-09-15-backup-quarantine-age-tests.md`.

Backup-quarantine age addendum: source revision `8119e94` adds a bounded
creation timestamp to quarantine names and bases stale recovery on that value,
not the original file mtime. This prevents an active deletion of an old file
from being mistaken for an orphan. Build, lint, typecheck, diff checks, and the
dedicated regression pass; native unlink recovery and production crash/remount
evidence remain open. Evidence:
`evidence/2026-09-15-backup-quarantine-age.md`.

Backup quarantine recovery addendum: source revision `38c5381` adds a bounded
strict-name scan for stale Broker backup cleanup quarantines. Recent entries
remain untouched; stale owner-only regular files are identity-checked and
removed, while unexpected entries fail closed. Build, lint, typecheck, diff
checks, the dedicated regression, and a physical probe pass. Native unlink,
IPC/lock/anchor orphan recovery and production crash/remount evidence remain
open. Evidence: `evidence/2026-09-15-backup-quarantine-recovery.md`.

IPC key-copy gate addendum: source revision `af68248` validates non-secret
constructor limits and bindings before copying authentication keys for Policy
Signer, Authority Control, Broker Status, Privileged Helper, and guest
transport channels. Build, lint, typecheck, diff checks, and the focused
41-test boundary suite pass; production cross-process delivery and signing
identity remain open. Evidence: `evidence/2026-09-15-ipc-key-copy-gate.md`.

Edge-factory disposal addendum: source revision `e3ad73d` makes request-factory
shutdown terminal and idempotent; post-disposal request creation fails closed
and response verification returns false instead of using a wiped key. Build,
lint, typecheck, diff checks, and the focused 18-test Edge auth/IPC/TLS/startup
suite pass; production lifecycle and installed shutdown readback remain open.
Evidence: `evidence/2026-09-15-edge-factory-disposal.md`.

Credential-loader buffer addendum: source revision `43fec85` wipes raw
file-read buffers after defensive key copies and clears native Keychain read,
write, and delete argument buffers on all paths. Build, lint, typecheck, diff
checks, and the focused 28-test credentials/keyring suite pass (27 pass, 1
explicit physical-Keychain skip); production cross-process Keychain memory
evidence remains open. Evidence:
`evidence/2026-09-15-credential-loader-buffers.md`.

Provisioned-key lifetime addendum: source revision `5f4bc61` clears the random
file-provisioning key after digest use and replaces failure-path direct unlink
with identity-fenced quarantine cleanup. Build, lint, typecheck, diff checks,
and the focused 28-test credentials/keyring suite pass (27 pass, 1 explicit
physical-Keychain skip); production Keychain distribution and recovery remain
open. Evidence: `evidence/2026-09-15-provisioned-key-lifetime.md`.

Audit-anchor lock quarantine addendum: source revision `61e6acb` replaces
normal direct lock unlink with a private same-directory quarantine rename,
device/inode/type recheck, and post-check deletion. Replacement locks fail
closed; stopped-service native recovery remains separately gated. Build, lint,
typecheck, diff checks, and the focused 9-test audit-anchor/read-only suite
pass; orphan quarantine recovery and installed-service evidence remain open.
Evidence: `evidence/2026-09-15-audit-anchor-lock-quarantine.md`.

Service-lock quarantine addendum: source revision `d3ca767` replaces direct
owner-lock unlink with an identity-fenced same-directory quarantine rename and
post-rename recheck before deletion. Replacement lock identities fail closed
and are not removed. Build, lint, typecheck, diff checks, and the focused
5-test service-lock suite pass; orphan quarantine recovery and installed
service evidence remain open. Evidence:
`evidence/2026-09-15-service-lock-quarantine.md`.

IPC socket quarantine addendum: source revision `6e246bf` atomically moves
stale and owned Unix sockets to private same-directory quarantine names,
rechecks device/inode identity, and only then unlinks the quarantine. Identity
mismatch fails closed without deleting a replacement socket. Build, lint,
typecheck, diff checks, and the focused 10-test Broker IPC suite pass; orphan
quarantine recovery and installed-service evidence remain open. Evidence:
`evidence/2026-09-15-ipc-socket-quarantine.md`.

TLS material lifetime addendum: source revision `96adc2d` returns the validated
protected-file buffer without an unnecessary duplicate and wipes the loaded
certificate if private-key loading fails. Build, lint, typecheck, diff checks,
and the focused 8-test Edge TLS/service-startup suite pass; production TLS key
packaging and full HTTPS Edge evidence remain open. Evidence:
`evidence/2026-09-15-tls-material-lifetime.md`.

Edge key handoff lifetime addendum: source revision `5695db0` clears the
protected-file loader buffer after `EdgeRequestFactory` copies it, matching the
Keychain delivery lifecycle. Build, lint, typecheck, diff checks, and the
focused 5-test Edge key/request-factory suite pass; full HTTPS Edge and
production key-storage evidence remain open. Evidence:
`evidence/2026-09-15-edge-key-handoff-lifetime.md`.

Request-authentication key lifetime addendum: source revision `fec6e5b` clears
per-request Edge HMAC copies after verification and response signing on both
success and failure paths. Build, lint, typecheck, diff checks, and the focused
18-test IPC boundary suite pass; production key storage and full Broker
regression remain open. Evidence:
`evidence/2026-09-15-request-authentication-key-lifetime.md`.

Authentication-key memory lifecycle addendum: source revision `42766c9` wipes
partially loaded Edge and approval issuer key buffers on failure, clears old
manager snapshots on replacement, and adds explicit disposal. Native Edge
startup clears its raw snapshot after handing defensive copies to the Broker.
Build, lint, typecheck, diff checks, and the focused 10-test keyring suite pass;
production cross-process delivery and signing gates remain open. Evidence:
`evidence/2026-09-15-authentication-key-memory-lifecycle.md`.

Backup-cleanup target-fence addendum: source revision `f25c900` routes backup
retention, stale temporary, restore, publication, and decrypt-failure cleanup
through a same-directory quarantine and identity recheck before deletion.
Non-overwriting hard-link restoration is attempted on failure. Build, lint,
typecheck, diff checks, and a physical encrypted-backup prune probe pass; fresh
full persistence and orphan-quarantine recovery evidence remain open. Evidence:
`evidence/2026-09-15-backup-cleanup-target-fence.md`.

Filesystem unlink target-swap addendum: source revision `a6971fc` changes
descriptor-relative deletion to quarantine the pathname with an exclusive
same-directory rename, recheck device/inode/type/link-count identity, and
delete only the verified quarantine inode. Identity mismatch restores through
non-overwriting `linkat`; failed restoration leaves an explicit recovery
artifact. Build, lint, typecheck, 40 filesystem tests, and a physical temp-root
probe pass. Orphan-quarantine crash recovery and production packaging remain
open. Evidence:
`evidence/2026-09-15-filesystem-unlink-quarantine.md`.

Credential retirement identity-fence addendum: source revision `737ab3a`
checks the exact owner/mode/device/inode/size/mtime before and after moving a
revoked file-backed authentication or approval key to quarantine. Failed
retirement restores only through a non-overwriting hard link, and all loaded
key buffers are cleared in `finally`. The physical Keychain-enabled credential
suite passes 11/11; production Keychain distribution, installed recovery, and
release enablement remain open. Evidence:
`evidence/2026-09-15-credential-retirement-fence.md`.

UNKNOWN write recovery addendum: source revision `2fadf8a` retries a prior
`TEMPORARY_CLEANUP_SKIPPED` observation using only the persisted root, target,
and exact temporary name. Filesystem root, symlink, and device/inode checks
still gate unlinking; no write is replayed or promoted. A physical-host probe
and regression coverage verify skip-then-safe-removal behavior.
Evidence: `evidence/2026-09-15-write-recovery-retry.md`.

UNKNOWN process recovery addendum: source revision `436917d` treats
`PROCESS_RECOVERY_UNKNOWN` as retryable observer uncertainty. Later startup
reconciliation retries the exact persisted PID/start-time/process-group
identity without replaying task execution or promoting the Job; definitive
drained, absent, and identity-mismatch outcomes remain terminal. A physical
host probe and regression coverage verify unknown-then-drained recovery.
Evidence: `evidence/2026-09-15-process-recovery-retry.md`.

Persistence backup publication addendum: source revision `8e57790` replaces
backup/restore `rename` publication with same-directory hard-link publication
that cannot overwrite an existing destination. The source temporary identity
is checked before and after linking, and file identity checks include device,
inode, owner, mode, size, and modification time. The new no-replace restore
regression and a physical-host probe preserve an existing destination and
return `CONFLICT`; build, lint, typecheck, and diff checks pass. Evidence:
`evidence/2026-09-15-persistence-backup-publication.md`.

Documentation navigation addendum: `npm run verify:docs` now rejects README
local-link escapes/unavailable targets and requires the eight named operator
runbooks. The physical host check passed for 29 README local links and all 8
runbooks; runbook content remains draft where production signing, installed
launchd ownership, remote deployment, or operator approval evidence is absent.
Evidence: `evidence/2026-09-15-documentation-link-check.md`.

Production signing readiness addendum: a read-only physical-host probe found
`0 valid identities` from `security find-identity -v -p codesigning`. The
rebuilt native adapter passes strict ad-hoc verification but has no
TeamIdentifier or Developer ID provenance. MOP-061 root installation and
privileged enablement therefore remain fail-closed; no root LaunchDaemon
mutation was attempted. Evidence:
`evidence/2026-09-15-production-signing-readiness.md`.

Keychain trusted-executable ownership addendum: source revisions `7f725bf`
and `0c21edb`
binds the ACL executable to the current process owner in both TypeScript and
the macOS native adapter. Missing POSIX identity, foreign ownership, writable
modes, symlinks, and non-canonical paths fail closed before secret access; the
native layer repeats the owner check with `geteuid()` around its canonical
path double-read and now includes UID/mode in its before/after identity fence.
Focused peer/credentials/helper suites pass 30/30 with `MOPS_REAL_KEYCHAIN=1`;
the latest physical non-overlapping suite passes 618/618 with zero skips and
zero failures. The existing Broker/Persistence process was left undisturbed.
Evidence:
`evidence/2026-09-15-keychain-trusted-executable-ownership.md`.

Root-helper Keychain ACL binding addendum: source revisions `4bc0308`,
`666a978`, and `711f3e4` keep the BrokerStore-backed key loader bound to the
Broker executable and make the no-`BrokerStore` root-helper loader require an
explicit canonical helper executable path for Keychain-backed keys. It now
verifies non-secret ACL/protection metadata before loading key bytes, and
missing or non-canonical binding fails with a stable error before Keychain
access. Focused helper keyring/runtime tests pass 10/10; focused credential
tests pass 14/14 with one explicit physical Keychain skip. The latest physical
non-overlapping suite passes 617/617 with zero skips and zero failures; the
existing Broker/Persistence process was left undisturbed. Evidence:
`evidence/2026-09-15-root-helper-keychain-acl-binding.md`.

Privileged helper runtime disposal addendum: source revision `2ce0945`, with
failed-cleanup coverage in test revision `ccb248b`, makes authority poller
cleanup idempotent across startup failure, failed listener cleanup,
close-before-start, and ordinary close. A runtime cannot restart after its
poller has been disposed, preventing reuse after authentication key material
has been wiped. Focused runtime tests pass 6/6 and the latest
physical non-overlapping suite passes 616/616 with zero skips and zero
failures; the existing Broker/Persistence process was left undisturbed.
Evidence: `evidence/2026-09-15-privileged-helper-runtime-disposal.md`.

Root-helper authority-poller construction addendum: source revision `a79d813`
removes injectable poller selection from the no-`BrokerStore` root-helper
factory. Enabled adapters now require a fixed authority socket and native
Broker peer policy so the factory itself constructs the authenticated
`PrivilegedHelperAuthorityClient`; missing authority configuration fails
closed. Focused runtime tests pass 5/5 and the latest physical
non-overlapping suite passes 615/615 with zero skips and zero failures.
Evidence: `evidence/2026-09-15-privileged-helper-poller-construction.md`.

Privileged helper authority-socket ACL addendum: source revision `fe9d681`
adds an independent Broker-owned Unix-socket readback. It checks expected
Broker UID/GID, owner-only permissions, socket type, and stable
device/inode/mode/ownership across two reads, while keeping the endpoint out
of the root-owned helper filesystem set. Focused package tests pass 14/14 and
the latest physical non-overlapping suite passes 615/615 with zero skips and
zero failures. Evidence:
`evidence/2026-09-15-privileged-helper-authority-socket-acl.md`.

Privileged helper package authority-socket addendum: source revision
`ee2c934` binds the root-domain package plan and helper status readback to the
Broker-owned `helperAuthoritySocketPath`. The plan rejects reuse with the
helper or Broker sockets and rejects an authority endpoint inside the
root-owned helper package; readback checks the exact path. Focused
helper/package/status tests pass 31/31, and the prior physical
non-overlapping suite passes 614/614 with zero skips and zero failures.
Evidence: `evidence/2026-09-15-privileged-helper-package-authority-socket.md`.

Privileged helper key-material isolation addendum: source revision
`e786002` adds `createPrivilegedHelperRuntimeFromKeyMaterial`, a root-helper
startup path with no `BrokerStore` dependency. It reads only protected local
key material, performs local validity checks, and requires the separately
authenticated Broker authority poller when an adapter is enabled. The
BrokerStore-backed activation factory remains for Broker-side compatibility;
the root-helper path does not create or open Broker SQLite state. Focused
helper/runtime/keyring/authority tests pass 11/11, and the latest physical
non-overlapping suite passes 614/614 with zero skips and zero failures.
Evidence: `evidence/2026-09-15-privileged-helper-key-material.md`.

Privileged helper authority-polling IPC addendum: source revision `2c3e01d`
(building on `b9d038a`, `d717525`, `2660bdf`, `becea16`, and `1eea5cb`) adds an independent
helper-to-Broker Unix socket, wires it into native Broker startup with
rollback, wipes copied keys on setup failure, and strictly validates failure
bodies and enforces the root-helper/non-root-Broker peer roles at production
startup. Both peers are explicitly
authenticated, request/response HMAC domains are direction-separated, replay
IDs/nonces use durable admission, and the Broker endpoint invokes the final
Request/Approval/Job authority gate. The helper client fences socket identity,
bounds transport, verifies response proofs, and clears key material. Active
operations poll before dispatch, during execution, and before publishing
success; a post-dispatch authority change becomes retryable
`UNKNOWN_OUTCOME`. Runtime startup rejects enabled adapters without the
poller. Focused helper/authority tests pass 18/18, runtime/keyring tests pass
7/7, native startup assembly tests pass 8/8, and the prior physical
non-overlapping suite passes 613/613 with zero skips and zero failures. The
default helper/policy remain disabled and the
existing Broker/Persistence process was left undisturbed. Evidence:
`evidence/2026-09-15-privileged-authority-polling-ipc.md`.

Broker-backed privileged authority addendum: source revision `91806ae` adds
`assertPrivilegedHelperCommandAuthority`, a reusable final Broker gate for
helper IPC. It reconstructs Request/Approval/Job identity from durable state,
checks deterministic command/intent proofs, and fails closed on disabled
switches, Edge/key/principal/session revocation, expired approval, cancelled
or non-running Jobs, and identity substitution. The combined
helper/executor/dispatch suite passes 26/26. The latest physical
non-overlapping suite passes 607/607 with zero skips and zero failures; the
default helper/policy remain disabled and the existing Broker/Persistence
process remained undisturbed. Evidence:
`evidence/2026-09-15-privileged-authority-gate.md`.

Privileged cancellation/lease addendum: source revision `6fab84d` closes the
running-Job cancellation race before helper IPC, rechecks cancellation after
command signing, retains `UNKNOWN_OUTCOME` after a command may have crossed
the helper boundary, and renews long helper leases at a bounded interval. The
focused executor/dispatch suite passes 12/12. The latest physical
non-overlapping suite passes 606/606 with zero skips and zero failures under
the install, Keychain, and sandbox gates; the existing Broker/Persistence
process remained undisturbed. This remains fail-closed candidate behavior:
the default helper/policy are disabled and no privileged operation was run.
Evidence: `evidence/2026-09-15-privileged-cancellation-lease-regression.md`.

Privileged Broker dispatch addendum: source revision `1f7451b` wires all three
L5 contracts through Broker planning, normalized payload validation, approval
intent, Broker-owned Job creation/lease, and the separately authenticated
`PrivilegedHelperJobExecutor`. The helper boundary remains explicitly
disabled by default, while the default policy now records the tools as
`implemented=true` and `enabled=false`; no root operation is enabled by this
change. A fake authenticated helper integration test passes 3/3, including a
fail-closed no-helper admission check. The helper factory now keeps the signed
Edge-envelope digest separate from the normalized privileged-argument digest.
Physical helper signing, root-domain installation, real adapters, and
production enablement remain open. Evidence:
`evidence/2026-09-15-privileged-broker-dispatch.md`.

Post-dispatch physical regression addendum: source revision `1f7451b` runs the
non-overlapping built suite at 602/602 with zero skips and zero failures under
`MOPS_REAL_INSTALL=1`, `MOPS_REAL_KEYCHAIN=1`, and `MOPS_REAL_SANDBOX=1`.
This confirms the privileged dispatch wiring did not regress the existing
physical sandbox, Keychain ACL, install, IPC, filesystem, Edge, guest, or
adapter boundary tests. It is not evidence that a real privileged operation
was executed. The long-running Broker/Persistence suites remained
undisturbed. Evidence:
`evidence/2026-09-15-real-privileged-dispatch-regression.md`.

Physical secret-boundary regression addendum: source revision `356ebd4`
passes the non-overlapping built suite 598/598 with zero skips and zero
failures under `MOPS_REAL_SANDBOX=1`, `MOPS_REAL_KEYCHAIN=1`, and
`MOPS_REAL_INSTALL=1`. Real sandbox, Keychain ACL, and temporary
Edge/Broker LaunchAgent gates ran successfully; process ownership tests now
use bounded snapshot handshakes and explicit shutdown-cancellation assertions.
The existing Broker/Persistence process was left undisturbed. Evidence:
`evidence/2026-09-15-real-secret-boundary-regression.md`.

Latest secret-boundary regression addendum: after source revision `f921714`,
the non-overlapping built suite passes 598 total (592 passed, 6 explicit
opt-in skips, 0 failed) after the shared process, TaskProfile, and guest
argument/environment secret checks. The existing Broker/Persistence process
was left undisturbed. Evidence:
`evidence/2026-09-15-secret-boundary-full-regression.md`.

Process environment secret-value addendum: source revision `98b36ac` extends
the shared policy across ProcessSupervisor, TaskProfile, and virtualization
guest validation so explicitly allowlisted environment values are rejected
when they match known token, credential, or authorization signatures; guest
task arguments also reject protected credential options. The focused process,
task-profile, and guest suites pass 51/51, with typecheck, lint, and diff
checks passing. This is defense-in-depth and does not close production sandbox
credential isolation or `mac_task_run` enablement. Evidence:
`evidence/2026-09-15-process-environment-secret-values.md`.

Broker lifecycle serialization addendum: source revision `6297c58` serializes
Broker service `start()` and `stop()` transitions around the native runtime;
the focused service-entrypoint suite passes 3/3, with typecheck, lint, and
diff checks passing. Evidence:
`evidence/2026-09-15-broker-lifecycle-serialization.md`.

Edge lifecycle serialization addendum: source revision `04132fe` serializes
Edge `start()` and `stop()` transitions through one lifecycle queue, so a
stop requested during listener startup cannot be followed by a stale
`running` publication. The focused Edge startup suite passes 5/5, with
typecheck, lint, and diff checks passing. Evidence:
`evidence/2026-09-15-edge-lifecycle-serialization.md`.

Latest local regression addendum: the non-overlapping built test set now
passes 595 total (589 pass, 6 explicit skips, 0 fail), including the new
audit credential-field and secret-shaped-string redaction tests. Broker/persistence suites were not
restarted because their existing long-running process remained active.
Evidence: `evidence/2026-09-15-latest-local-regression.md`.

Persistence integrity rerun addendum: source revision `8077a6d` passes 33/33
focused replay, Approval, authority, configuration, Request, Job,
Request-to-Job, and complete schema-layout invariants with no skips or
failures. The existing Broker/persistence process remains undisturbed. This
does not close physical crash/remount durability, production Keychain,
installed recovery, external rollback, or independent P0/P1 review. Evidence:
`evidence/2026-09-15-ledger-integrity-rerun.md`.

Physical Darwin full-regression addendum: after rebuilding source revision
`cd62bbc`, the serial non-overlapping package set passes 595/595 with zero
skips and zero failures under `MOPS_REAL_INSTALL=1`, `MOPS_REAL_KEYCHAIN=1`,
and `MOPS_REAL_SANDBOX=1`. The old Broker/persistence process remains
undisturbed. This is a host regression checkpoint, not production signing,
persistent installation, isolation, VM, remote issuer, or independent-review
acceptance. Evidence: `evidence/2026-09-15-real-full-regression-rerun.md`.

Test-timeout boundary addendum: source revision `7d99b98` makes the root
`npm test` command enforce a fixed 120-second per-test-case timeout. Lint,
typecheck, and the 11-test contracts smoke pass; the existing Broker/
persistence process remains undisturbed. This bounds verification hangs only
and does not change production task budgets or close release gates. Evidence:
`evidence/2026-09-15-test-timeout-boundary.md`.

Release-gate rerun addendum: source revision `7e0cc43` passes contract
verification (44 unique contracts), native canonical JSON (5/5), high-level
dependency audit (0 vulnerabilities), lint (611 tracked files), typecheck,
and diff checks. The old Broker/persistence process remains undisturbed, so
their complete result and the physical production/release gates are not
claimed. Evidence: `evidence/2026-09-15-release-gate-rerun.md`.

Audit-outage availability decision addendum: BrokerStore now explicitly
documents and tests the fail-closed policy that an unavailable keyed audit
tail blocks all MCP request admissions, including read-only requests, until
restart with a verified tail. The focused audit-anchor read-only test proves
no Request row is created after publication failure; direct host recovery
readback remains available. Evidence: `evidence/2026-09-15-audit-readonly-fail-closed.md`.

Physical Darwin sandbox addendum: with `MOPS_REAL_SANDBOX=1` correctly
exported to the test processes, the same non-overlapping built set passes 595
total (593 pass, 2 explicit skips, 0 fail) on Darwin arm64/macOS 26.2. The
real sandbox, credential-canary, fork/`setsid`, TCP/UDP allowlist, and active
cancellation checks ran; only real Keychain ACL and temporary install gates
skipped. Evidence: `evidence/2026-09-15-real-sandbox-regression.md`.

Physical Keychain/install addendum: with `MOPS_REAL_INSTALL=1`,
`MOPS_REAL_KEYCHAIN=1`, and `MOPS_REAL_SANDBOX=1` exported to the test
processes, the same non-overlapping built set passes 595/595 with 0 skips and
0 failures. Temporary Keychain ACL retirement and per-user Edge/Broker
LaunchAgent bootstrap/readback/bootout passed; post-test launchd readback
confirmed both fixed labels absent. Evidence:
`evidence/2026-09-15-real-install-keychain-regression.md`.

Audit-evidence redaction addendum: source revision `42ca30c` expands both the
recursive persistence redactor and the separately authenticated privileged
helper response redactor to cover common API/access/refresh token,
client/HMAC/signing/SSH key, bearer/JWT, password/passphrase, cookie,
credential, and private/secret field aliases, and sanitizes secret-shaped
string values under ordinary fields. Focused alias/content/helper tests, build,
and diff checks pass. This is defense-in-depth and does not close the broader
secret corpus or physical isolation gates. Evidence:
`evidence/2026-09-15-audit-evidence-redaction.md`.

Failure-audit target addendum: source revision `3ed2e02` carries the
Broker-normalized target into post-authorization failure audit rows while
preserving `unresolved` for earlier parse/auth/authorization failures. The
existing post-authorization test now asserts `host:broker` readback, and a
built-distribution harness reproduces the same bounded target pair. Build,
lint, contract verification, and diff checks pass; the already-running full
Broker/persistence suites were not restarted. Evidence:
`evidence/2026-09-15-failure-audit-target.md`.

Schema-startup error and coverage addendum: source revision `183ecd4` maps
malformed persistence versions, migration registries, runtime fences, replay
schemas, and metadata migrations to stable `AUDIT_UNAVAILABLE` failures. The
schema-layout regression now injects an unknown column into every persisted
table and passes 2/2; the non-overlapping package regression passes 593 total
(587 pass, 6 skipped, 0 fail). Production crash recovery, signing/Keychain,
installed lifecycle, isolation, disk exhaustion, and independent review remain
open. Evidence: `evidence/2026-09-15-core-schema-layout.md`.

Schema-migration readback addendum: the current BrokerStore successfully opens
legacy Request and Job layouts, preserves historical records, and accepts the
post-migration complete column sets at source revision `a26e6d8`. Temporary
physical-host checks confirmed nullable Request linkage and absence of
fabricated Job metadata, while the schema-layout guard remained fail-closed for
unknown columns. Production backup restore, crash recovery, disk exhaustion,
and release upgrade/rollback evidence remain open. Evidence:
`evidence/2026-09-15-schema-migration-readback.md`.

Core-schema-layout addendum: commit `a26e6d8` extends the complete
post-migration column-set check to every Broker persistence table, including
nonce ledgers, runtime fence, active/history configuration, Request/Approval/
Job ledgers, audit events, revocations, and kill-switches; unknown or missing
columns fail closed as `AUDIT_UNAVAILABLE`. The schema-layout test passes 1/1
and the non-overlapping package regression passes 592 total (586 pass, 6
skipped, 0 fail). Build, lint, and diff checks pass. Physical crash recovery,
production signing/Keychain, installed lifecycle, isolation, disk exhaustion,
and independent review remain open. Evidence:
`evidence/2026-09-15-core-schema-layout.md`.

Local-gate checkpoint addendum: source revision `a26e6d8` passes 5/5 native
canonical-JSON vectors, `npm audit --audit-level=high` reports zero
vulnerabilities, lint passes for 602 tracked files, and `git diff --check`
passes. The non-overlapping package regression remains 592 total (586 pass,
6 skipped, 0 fail); the already-running Broker/persistence suites were not
restarted. The working tree is clean and no remote push was performed.
Evidence: `evidence/2026-09-15-final-local-gates.md`.

Persisted Job-output integrity addendum: commit `1cfc62c` revalidates Job
stdout/stderr bounds and secret policy at startup, along with exit-code,
cancellation-reason, and metadata-column types. Job-row/state tests pass 7/7;
Request-link tests pass 3/3; the non-overlapping package regression passes 591
total (585 pass, 6 skipped, 0 fail). Build, lint (599 tracked files), and diff checks pass.
Physical crash/old-worker ownership, credential rotation, remount durability,
installed recovery, and independent review remain open. Evidence:
`evidence/2026-09-15-job-output-integrity.md`.

Request-link integrity addendum: commit `24c0641` binds Request-to-Job linkage
to an existing Job whose owner, session, tool, target, policy, and Edge
provenance match; missing or substituted Jobs fail with stable errors. Broker
startup now cross-checks persisted Request Approval/Job references before
recovery. Focused link tests pass 3/3; the non-overlapping package regression
passes 590 total (584 pass, 6 skipped, 0 fail). Build, lint, and diff checks
pass. Physical crash/old-worker ownership, credential rotation, remount
durability, installed recovery, and independent review remain open.
Evidence: `evidence/2026-09-15-request-link-integrity.md`.

Authority-ledger startup-integrity addendum: commit `ba34100` makes BrokerStore
scan every persisted Approval, Revocation, and Kill-switch row before policy
evaluation and recovery. Approval lifecycle pairing, bounded authority
identities/targets, revocation subjects, and switch state now fail closed as
`AUDIT_UNAVAILABLE` when malformed. Focused authority startup tests pass 5/5;
the combined Request/Job/Approval/authority slice passes 15/15, and the
non-overlapping package regression remains 587 total (581 pass, 6 skipped, 0
fail). Build, lint, and diff checks pass. Production Keychain distribution,
external rollback detection, physical crash recovery, and approval UI remain
open. Evidence: `evidence/2026-09-15-authority-ledger-startup-integrity.md`.

Request-ledger startup-integrity addendum: commit `040284a` makes BrokerStore
scan every persisted Request before restart reconciliation. Request identity,
tool, policy, payload digest, capability-family storage, lifecycle state, and
mutation linkage now fail closed as `AUDIT_UNAVAILABLE` when malformed. The
focused Request-state/startup tests pass 4/4; the non-overlapping package
regression passes 587 total (581 pass, 6 skipped, 0 fail). Build, lint, and
diff checks pass. Physical crash recovery, old-worker ownership, credential
rotation, remount durability, and production task enablement remain open.
Evidence: `evidence/2026-09-15-request-ledger-startup-integrity.md`.

Job-ledger startup-integrity addendum: the BrokerStore now validates every
persisted Job row before restart reconciliation. Job identity fields, lease
owner/token formats, heartbeat/expiry ordering, and the bounded lease window
fail closed, while mixed local-process and virtualization guest ownership
metadata is rejected. Focused Job-state/startup tests pass 6/6; the
non-overlapping package regression passes 586 total (580 pass, 6 skipped, 0
fail). Build, lint, and diff checks pass. Physical crash/old-worker process
ownership, credential rotation, remount durability, and production task
enablement remain open.
Evidence: `evidence/2026-09-15-job-ledger-startup-integrity.md`.

Filesystem-worker result boundary addendum: commits `5657267` and `86a6792`
apply exact-field, plain-data, dense-array, and bounded nested-record checks
to all filesystem worker operations. Storage volume results are explicitly
projected to their public fields, removing the internal `rootPath` authority
before result validation. Focused filesystem/contract tests pass 3/3; the
non-overlapping package regression passes 521 total (515 pass, 6 skipped,
0 fail). Native provenance, remount, sandbox, credential, VM, persistence,
and capability enablement evidence remains open.
Evidence: `evidence/2026-09-15-filesystem-worker-result-boundary.md`.

Read-only adapter result-boundary addendum: commits `a9d1b2a` and `e1ae276`
apply plain-data, exact-field, and dense-array validation to native network,
JSON app inventory, and Accessibility observation/action results. Unknown
fields or unstable nested records fail closed before Broker consumers use
identity or UI metadata. Focused app/UI/network tests pass 15/15; the
non-overlapping package regression passes 523 total (517 pass, 6 skipped,
0 fail). Native provenance, permission-granted GUI, sandbox, credential, VM,
persistence, and capability enablement evidence remains open.
Evidence: `evidence/2026-09-15-readonly-adapter-result-boundaries.md`.

Virtualization VM result-boundary addendum: commit `c22fc98` applies exact
plain-data checks to native guest lifecycle start/stop/status results before
boot and guest identities are compared. Focused native VM lifecycle tests
pass 9/9; the non-overlapping package regression passes 524 total (518 pass,
6 skipped, 0 fail). Native attestation, VM isolation, credential/persistence
isolation, and `mac_task_run` enablement evidence remains open.
Evidence: `evidence/2026-09-15-virtualization-vm-result-boundary.md`.

Persisted Job readback addendum: commits `2cc1db7`, `937ffcd`, and `5f4980d`
require exact plain-data shapes for stored app, UI, write, and patch results plus
nested target/precondition/file records. Unknown or malformed persisted
fields fail closed as `UNKNOWN_OUTCOME` before idempotent reuse or readback
publication. Focused persisted-result tests pass 2/2; the non-overlapping
package regression passes 527 total (521 pass, 6 skipped, 0 fail). SQLite
corruption, crash ownership, disk exhaustion, service recovery, and release
evidence remain open.
Evidence: `evidence/2026-09-15-persisted-job-readbacks.md`.

Process worker executor addendum: commit `8a9a89c` unifies WorkerProcessExecutor
validation with the strict native process parsers and rejects sparse
inventory arrays or unknown/accessor result fields. Focused process
executor/inspector tests pass 6/6; the non-overlapping package regression
passes 528 total (522 pass, 6 skipped, 0 fail). Native provenance, process
ownership, kernel limits, and production task enablement evidence remain open.
Evidence: `evidence/2026-09-15-process-worker-executor-boundary.md`.

Filesystem native-result addendum: commit `645f57b` applies exact plain-data
and dense-array validation to native filesystem stat/read/hash/list/write/
unlink/storage records, with fresh buffer and entry projection. Focused
filesystem tests pass 37/37; the non-overlapping package regression passes
530 total (524 pass, 6 skipped, 0 fail). Physical remount, kernel I/O,
native provenance, and production resource evidence remain open.
Evidence: `evidence/2026-09-15-filesystem-native-result-boundary.md`.

Audit-anchor readback addendum: commit `e54a862` validates the audit sidecar
and native lock-recovery readback as exact plain records before MAC/tail or
unlink decisions. Focused audit-anchor tests pass 8/8; the non-overlapping
package regression passes 530 total (524 pass, 6 skipped, 0 fail). SQLite
corruption, key provenance, disk exhaustion, and service recovery evidence
remain open.
Evidence: `evidence/2026-09-15-audit-anchor-result-boundary.md`.

Process-worker result boundary addendum: commit `a01b62e` applies plain-data
and exact-field validation to native process inventory/detail results and
worker envelopes. Owner identities and child PID arrays receive bounded,
ordered checks; extra worker fields cannot turn a malformed result into a
success. Focused process-inspector/worker tests pass 14/14; the
non-overlapping package regression passes 520 total (514 pass, 6 skipped,
0 fail). Native provenance, sandbox, credential, VM, persistence, and
capability enablement evidence remains open.
Evidence: `evidence/2026-09-15-process-worker-result-boundary.md`.

Task-profile request snapshot addendum: commit `04f77eb` copies the validated
TaskProfileRegistry request before asynchronous filesystem readback. All
profile argument matching and process construction use that snapshot, so
caller changes cannot substitute arguments or cwd after admission. Focused
task-profile tests pass 6/6; the non-overlapping package regression passes 518
total (512 pass, 6 skipped, 0 fail). Sandbox, credential, VM, persistence,
and `mac_task_run` enablement evidence remains open.
Evidence: `evidence/2026-09-15-task-profile-request-snapshot.md`.

Guest-request snapshot addendum: commit `31dc880` copies the authenticated
guest task request and nested identity before asynchronous profile target
readback. All ledger, adapter, budget, cancellation, response, and recovery
paths use the snapshot; a caller mutation cannot substitute task identity or
execution limits after admission. Focused guest executor tests pass 11/11;
the non-overlapping package regression passes 517 total (511 pass, 6 skipped,
0 fail). This closes one local guest-request TOCTOU window only; native
attestation, VM, credential, persistence, and `mac_task_run` evidence remains
open.
Evidence: `evidence/2026-09-15-guest-request-snapshot.md`.

Guest-profile boundary addendum: commit `5f67e18` applies strict plain-record,
known-field, dense-array, and bounded-collection checks to startup-owned guest
profiles and digest-bound guest task requests. Inherited/accessor/symbolic,
sparse, unknown, and malformed environment data fails closed before profile
resolution or target readback. Focused guest executor tests pass 10/10; the
non-overlapping package regression passes 516 total (510 pass, 6 skipped,
0 fail). Native attestation, VM, credential, persistence, and
`mac_task_run` enablement evidence remains open.
Evidence: `evidence/2026-09-15-guest-profile-boundary.md`.

Process-request snapshot addendum: commit `aa8040e` copies the complete
validated ProcessSupervisor request before asynchronous path identity checks.
All spawn, budget, environment, callback, stability, and cancellation logic
uses the immutable snapshot; a caller mutation during validation cannot change
what is admitted. Focused process-supervisor/task-profile/task-runner tests
pass 50/50; the non-overlapping package regression passes 515 total (509
pass, 6 skipped, 0 fail). This closes one local request TOCTOU window only;
sandbox, credential, VM, persistence, and `mac_task_run` evidence remains
open.
Evidence: `evidence/2026-09-15-process-request-snapshot.md`.

Process-request boundary addendum: commit `78dd404` makes ProcessSupervisor
admit only plain, exact-shape requests before spawning. Canonical executable
and cwd paths, dense bounded string arguments, plain environment data,
bounded integer limits, and callable control callbacks are validated; unknown,
inherited, accessor, symbolic, sparse, malformed, and callback-substitution
inputs fail closed. Focused process-supervisor/task-profile/task-runner tests
pass 49/49; the non-overlapping package regression passes 514 total (508
pass, 6 skipped, 0 fail). This closes local process-request representation
integrity only; sandbox, credential, VM, persistence, and `mac_task_run`
enablement evidence remains open.
Evidence: `evidence/2026-09-15-process-request-boundary.md`.

Task-profile authority-shape addendum: commit `956e95f` makes named
TaskProfile documents and task-run requests accept only plain records with
known fields. Path, argument, and network arrays are dense bounded string
arrays; environment values cannot be accessor/inherited authority; resolved
arguments are copied before execution. The focused task-profile/task-runner
suite passes 18/18; the non-overlapping package regression passes 513 total
(507 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff checks pass.
This closes local task-profile representation integrity only; sandbox,
credential, VM, and `mac_task_run` evidence remains open.
Evidence: `evidence/2026-09-15-task-profile-authority-shape.md`.

Task-runner result-boundary addendum: commit `0c486c9` applies the shared
plain-data check and exact field set to host isolation proofs and runner
results. Accessors, inherited/symbolic fields, unknown keys, oversized UTF-8
output, and overlong durations fail closed before Broker persistence/audit;
guest verification summaries remain explicitly optional. The focused
task-runner/guest-attestation suite passes 19/19; the non-overlapping package
regression passes 512 total (506 pass, 6 skipped, 0 fail); build, typecheck,
lint, and diff checks pass. This closes local parser/result integrity only;
production sandbox, credential, VM, and `mac_task_run` evidence remain open.
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
physical-host runtime race harness that renames an authorized child directory,
briefly replaces it with an outside symlink, and restores it during bounded
descriptor-relative reads. Only authorized bytes are accepted; outside
resolution is rejected. The focused filesystem suite passes 33/33; the
non-overlapping package regression passes 510 total (504 pass, 6 skipped,
0 fail); build, typecheck, lint, and diff checks pass. Runtime directory
create/rename evidence is now covered, while physical remount, broader volume,
and production resource evidence remain open.
Evidence: `evidence/2026-09-15-filesystem-directory-rename-race.md`.

Filesystem root-descriptor addendum: commit `6fb5372` makes native
metadata/list/read/hash and atomic write/unlink operations descriptor-relative
to the authorized root. A traversal-free relative-path helper rejects
`.`/`..`/empty components, while target-parent canonicalization preserves
final-symlink semantics and handles macOS `/var` aliases. Filesystem focused
tests pass 32/32; the non-overlapping package regression passes 509 total
(503 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff checks pass.
This reduces root-directory rename/target-swap exposure but leaves physical
remount and production-scale resource evidence open.
Evidence: `evidence/2026-09-15-filesystem-root-descriptor-binding.md`.

System-published guest-image addendum: commits `e00554c`, `f74e485`, and `a08d2a5` make image
publication explicit and requires the enabled native VM path to consume only
root-owned, canonical, non-symlink images and every canonical ancestor without
group/other write bits; both TypeScript and native paths reject a root Broker.
The native C++ boundary repeats the check before
`initWithURL:` because Virtualization.framework accepts a pathname, while
descriptor/inode/digest readback remains in place. Focused image/native tests
pass 12/12; the non-overlapping package regression passes 508 total (502
pass, 6 skipped, 0 fail); build, typecheck, lint, and diff checks pass. This
is a compensating control against unprivileged target replacement, not proof
of atomic descriptor attachment, VM boot, guest isolation, or capability
enablement.
Evidence: `evidence/2026-09-15-system-published-guest-image.md`.

Nested authenticated-data addendum: source revision `54fe71a` applies
plain-data checks to helper payloads/results/verification/evidence, Broker and
Helper status readbacks, and nested authority/status failures. Malformed
accessor, hidden, symbolic, and prototype-bearing values fail closed before
canonicalization, redaction, or postcondition checks. Focused suites pass
17/17; the non-overlapping package regression passes 506 total (500 pass,
6 skipped, 0 fail); build, typecheck, lint, and diff checks pass. This closes
local nested representation integrity only; production peer, packaging, VM,
credential, helper, and capability evidence remain open.
Evidence: `evidence/2026-09-15-nested-authenticated-data.md`.

Guest attestation data-shape addendum: source revision `d276615` makes the
signed guest attestation envelope, payload, and nested identity accept only
plain data records before canonicalization or signature verification.
Inherited, accessor, hidden, and symbolic values fail closed. Focused
attestation tests pass 6/6; the non-overlapping package regression passes 505
total (499 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff checks
pass. This closes local provenance representation integrity only; native
attestation production, private-key distribution, VM isolation, and
enablement evidence remain open.
Evidence: `evidence/2026-09-15-guest-attestation-data-shapes.md`.

Operator IPC data-shape addendum: source revision `8ed6e298` makes the
policy-signer and approval issuance parsers accept only plain data records,
including the nested signed approval payload. Inherited, accessor, hidden,
and symbolic fields are rejected before authority verification or persistence.
Focused suites pass 14/14; the non-overlapping package regression passes 504
total (498 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff checks
pass. This closes local operator parser integrity only; protected key
distribution, production packaging, VM, helper, and capability enablement
evidence remain open.
Evidence: `evidence/2026-09-15-operator-ipc-data-shapes.md`.

Real sandbox readback addendum: on the physical Mac mini (macOS 26.2,
Darwin 25.2.0, arm64), `MOPS_REAL_SANDBOX=1 node --test
packages/broker/dist/sandbox-profile.test.js` passes 16/16 with no skips.
The run covers the current deny-default profile, environment and protected
surface denials, TCP/UDP loopback allowlists, fork/setsid escape denial, and
owned cancellation. This remains partial evidence for deprecated
`sandbox-exec`; real credential-content, remount, crash/restart, Docker,
production packaging, and task-runner enablement gates remain open.
Evidence: `evidence/2026-09-15-real-sandbox-16-tests.md`.

Authenticated IPC data-shape addendum: source revision `27e102b` applies the
shared plain-data-record guard to Authority Control, Broker Status, Privileged
Helper, and Virtualization Guest transport parsers. Accessors, hidden fields,
symbols, and prototype-bearing envelopes fail closed before proof verification
or dispatch. Focused IPC tests pass 32/32; the non-overlapping package
regression passes 502 total (496 pass, 6 skipped, 0 fail); build, typecheck,
lint, and diff checks pass. This closes local parser integrity only; OS peer,
production packaging, VM, credential, helper, and enablement evidence remain
open. Evidence: `evidence/2026-09-15-authenticated-ipc-data-shapes.md`.

Signed request data-shape addendum: source revision `14d3cc0` applies a shared
plain-data-record check and bounded recursive validation to the complete Broker
request value. Inherited, hidden, accessor, sparse-array, cyclic, symbolic, and
unsupported nested values now fail closed before authentication. Security-fuzz
tests pass 8/8; the non-overlapping package regression passes 498 total
(492 pass, 6 skipped, 0 fail); build, typecheck, lint, and diff checks pass.
This closes local request representation integrity only; production transport,
VM, credential, helper, and enablement evidence remain open.
Evidence: `evidence/2026-09-15-request-data-shape.md`.

Request object authority-boundary addendum: source revision `8a8f335` makes
request parsing reject prototype-bearing envelope, arguments, and principal
objects before authentication or execution. The security-fuzz suite passes
8/8; the non-overlapping package regression passes 498 total (492 pass,
6 skipped, 0 fail); build, typecheck, lint, and diff checks pass. This closes
local request object-shape integrity only; transport, policy signing, VM,
credential, helper, and production enablement evidence remain open.
Evidence: `evidence/2026-09-15-request-object-authority-boundary.md`.

Policy prototype authority-boundary addendum: source revision `b164da0` makes
runtime policy validation reject prototype-bearing authority records instead
of accepting inherited kill-switch, key-window, principal, or tool fields.
Policy tests pass 4/4; the security-fuzz policy corpus passes 7/7; the
non-overlapping package regression passes 497 total (491 pass, 6 skipped,
0 fail); build, typecheck, lint, and diff checks pass. This closes policy
object-shape integrity only; production signing, Keychain distribution, VM
isolation, helper installation, and capability enablement remain open.
Evidence: `evidence/2026-09-15-policy-prototype-authority-boundary.md`.

Guest executor close-recovery addendum: source revision `3245482` makes
`VirtualizationGuestProfileExecutor.close()` abort and fully drain active work
even when adapter cleanup fails. The rejected close Promise is cleared for an
explicit retry, while the executor remains permanently fenced against new
tasks; successful close remains idempotent. Guest executor tests pass 10/10,
the non-overlapping package regression passes 496 total (490 pass, 6 skipped,
0 fail), and build, typecheck, lint, and diff checks pass. This is shutdown
semantics only; VM boot/isolation, native attestation, credential isolation,
and `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-guest-executor-close-recovery.md`.

Broker shutdown recovery addendum: source revision `505d28a` keeps the Broker
shutdown fence active while clearing a rejected aggregate close Promise for an
explicit retry. New requests remain denied with `CANCELLED`; only a fully
successful resource cleanup becomes idempotently complete. Broker close tests,
the non-overlapping package regression (495 total, 489 pass, 6 skipped, 0
fail), build, typecheck, lint, and diff checks pass. This closes local cleanup
retry semantics only; installed service recovery, VM/guest isolation,
credential isolation, helper operation, and production enablement remain open.
Evidence: `evidence/2026-09-15-broker-close-recovery.md`.

Virtualization guest attestation key-validity addendum: source revision
`5aa7d2e` requires each signed guest attestation lifetime to fit completely
inside the trusted Ed25519 key's validity window, in addition to current-time,
freshness, revocation, digest, and signature checks. Attestation tests pass
5/5; the non-overlapping package regression passes 495 total (489 pass, 6
skipped, 0 fail); build, typecheck, lint, and diff checks pass. This closes
key-window binding only; native attestation production, protected key
distribution, VM boot/isolation, and `mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-virtualization-guest-attestation-key-validity.md`.

Virtualization guest runtime close-recovery addendum: source revisions
`d68176b` and `28007cf` keep `VirtualizationGuestRuntimeImpl` retryable when
connection, task-runner, or lifecycle shutdown fails. A failed close no longer
caches a rejected promise or permanently marks the runtime closed; while the
explicit close retry is pending, new start/stop operations are fenced and only
lifecycle status recovery remains available. Only a fully successful shutdown
marks the runtime closed. Virtualization startup tests pass 3/3, the
non-overlapping package regression passes 494 total (488 pass, 6 skipped, 0
fail), and build, typecheck, lint, and diff checks pass. This is a lifecycle
recovery boundary only; VM boot, guest isolation, production signing,
credential isolation, and `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-runtime-close-recovery.md`.

Darwin descriptor-exec boundary addendum: a physical Darwin 25.2.0 probe found
no public `fexecve`/`execveat` SDK declaration, no executable-fd API in
`spawn.h`, and `/dev/fd/N` execution returned permission denied (status 126).
The Broker therefore does not claim descriptor/fexec atomicity; the existing
canonical path, no-follow, digest, and startup revalidation remain compensating
controls. `VT-FS-02`, immutable snapshot alternatives, and production
`mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-darwin-descriptor-exec-boundary.md`.

Process argv false-positive addendum: source revision `7231964` limits
sensitive option-name matching to explicit Unix options while retaining
full-argument token-signature scanning. A real-Darwin sandbox run now passes
16/16 after exposing and fixing the canary-script false positive; the focused
process/secret suite passes 35/35 and the non-overlapping package regression
passes 494 total (488 pass, 6 skipped, 0 fail). Build, typecheck, lint, and
diff checks pass. This closes one false-positive boundary only; opaque secret
classification and production credential isolation remain open. Evidence:
`evidence/2026-09-15-secret-argv-script-boundary.md`.

Capability-list integrity addendum: source revision `399a17c` makes the Edge
reject duplicate or unregistered capability names and malformed name/version
fields before MCP registration. The non-overlapping package regression passes
494 total (488 pass, 6 skipped, 0 fail); Edge tests, contract validation,
build, lint, and diff checks pass. This is a response-integrity guard only and
does not enable capabilities or close production host/VM/credential/privileged
evidence gates. Evidence:
`evidence/2026-09-15-capability-list-integrity.md`.

Capability lifecycle-state addendum: source revision `e22f025` carries
`planned`, `implemented`, and `enabled` for every `mac_capabilities` item,
requires those fields in the versioned output schema, and makes the Edge reject
an enabled item with an inconsistent lifecycle state. Broker capability and
kill-switch tests plus Edge MCP/HTTPS tests pass; the non-overlapping package
regression passes 493 total (487 pass, 6 skipped, 0 fail); 44 contracts
validate, and build, typecheck, lint, and diff checks pass. This changes representation and
fail-closed admission only; it does not enable disabled capabilities or close
production host/VM/credential/privileged evidence gates. Evidence:
`evidence/2026-09-15-capability-lifecycle-states.md`.

Worker startup-failure addendum: `BoundedWorkerExecutor` now maps synchronous
worker-factory exceptions to stable `EXECUTION_FAILED` without incrementing
active capacity or exposing raw startup text. Worker-executor tests pass 8/8;
the non-overlapping package regression passes 492 total (486 pass, 6 skipped,
0 fail); build, typecheck, lint, and diff checks pass. This closes error
normalization only; worker sandboxing, credential separation, and production
task-runner enablement remain open. Evidence:
`evidence/2026-09-15-worker-startup-failure-boundary.md`.

Edge JWKS response-status addendum: source revision `fc04641` requires the
Edge-owned remote JWKS fetch to return a 2xx response before body handling or
`jose` parsing. JWT tests pass 8/8, all Edge tests pass 41/41, and the
non-overlapping physical-Darwin regression passes 491 total (485 pass, 6
skipped, 0 fail). Build, typecheck, lint, and diff checks pass. External OAuth
issuer, DNS/TLS, and remote deployment evidence remain unproven. Evidence:
`evidence/2026-09-15-edge-jwks-status-boundary.md`.

Edge JWKS redirect-boundary addendum: source revision `c97140a` rejects
redirected responses and non-empty final URLs that differ from the configured
JWKS endpoint before key parsing. JWT tests pass 7/7, all Edge tests pass
40/40, and the non-overlapping physical-Darwin regression passes 490/490 with
0 skipped tests. Build, typecheck, lint, and diff checks pass. External OAuth
issuer, DNS/TLS, and remote deployment evidence remain unproven. Evidence:
`evidence/2026-09-15-edge-jwks-redirect-boundary.md`.

Process-argument secret-boundary addendum: source revision `17d10e2` adds a
shared Broker policy that rejects credential-bearing argv option names and
known token signatures when fixed profiles load, task arguments resolve, and
immediately before child spawn. Secret-policy tests pass 5/5, task-profile
tests pass 4/4, process-supervisor tests pass 30/30, and the non-overlapping
physical-Darwin regression passes 489/489 with 0 skipped tests. Build,
typecheck, lint, contract, canonical-JSON, audit, and diff checks pass.
Evidence: `evidence/2026-09-15-process-argument-secret-boundary.md`.

Edge remote-JWKS response addendum: source revision `3cca22c` installs a
bounded streaming fetch wrapper before `jose` JSON parsing. Only JSON JWKS MIME
types are accepted and responses over 256 KiB or with invalid length metadata
fail closed. JWT tests pass 6/6, all Edge tests pass 39/39, and the
non-overlapping physical-Darwin regression passes 488/488 with 0 skipped
tests. Build, typecheck, lint, contract, canonical-JSON, audit, and diff
checks pass. External OAuth issuer and remote deployment evidence remain
unproven. Evidence: `evidence/2026-09-15-edge-jwks-response-boundary.md`.

Virtualization lifecycle timeout-fence addendum: source revision `ea85237`
keeps a timed-out or cancelled native lifecycle promise fenced until it
settles, so a later status or transition cannot overlap an unknown VM
mutation. Lifecycle tests pass 7/7; the focused guest/transport/lifecycle/
startup/native/task-runner suite passes 86/86; and the non-overlapping
physical-Darwin regression passes 486/486 with 0 skipped tests. Build,
typecheck, lint, and diff checks pass. VM boot, guest isolation, and
production `mac_task_run` enablement remain disabled. Evidence:
`evidence/2026-09-15-virtualization-guest-lifecycle-timeout-fence.md`.

Process-supervisor early-capture addendum: source revision `efb9d5c` fixes the
spawn-to-observer race by capturing bounded child output and exit/close state
immediately after spawn, then handing that state to the later path/process
observer. The fast-child regression and cancellation/capacity path now pass;
process-supervisor tests pass 30/30 and the non-overlapping physical-Darwin
regression passes 485/485 with 0 skipped tests. Build, typecheck, lint, and
diff checks pass. Descriptor/fexec, remount, production isolation, and
`mac_task_run` enablement remain disabled. Evidence:
`evidence/2026-09-15-process-supervisor-early-capture.md`.

Guest-executor close-drain addendum: source revision `9f772fe` now waits for
all tracked adapter promises after aborting active controllers and invoking
the adapter close hook. The close regression stays pending until the adapter
settles; guest executor tests pass 8/8 and the combined guest/transport/
lifecycle/startup/native focused suite passes 53/53 with 0 skipped tests.
Build, typecheck, lint, and diff checks pass. VM boot, guest isolation, and
production `mac_task_run` enablement remain disabled. Evidence:
`evidence/2026-09-15-virtualization-guest-close-drain.md`.

Guest-executor admission-concurrency addendum: source revision `eb9aa47`
counts pending manifest admission as in-flight work, reserving the bounded
slot synchronously before filesystem identity readback. A `maxConcurrent: 1`
regression rejects the competing request and permits the first to complete;
guest executor tests pass 8/8 and the combined guest/transport/lifecycle/
startup/native focused suite passes 53/53 with 0 skipped tests. Build,
typecheck, lint, and diff checks pass. VM boot, guest isolation, and
production `mac_task_run` enablement remain disabled. Evidence:
`evidence/2026-09-15-virtualization-guest-concurrency.md`.

Guest-bootstrap timeout-cancellation addendum: source revision `9148013`
changes each connection handler to retain its abort controller and abort
guest work before closing the stream on deadline, transport, or normal
teardown. A focused deadline regression observes callback cancellation and
prevents a completed response. Bootstrap tests pass 6/6 and the combined
guest/transport/lifecycle/startup/native focused suite passes 52/52 with 0
skipped tests; build, typecheck, lint, and diff checks pass. This remains a
guest protocol boundary only—VM boot, guest isolation, and production
`mac_task_run` enablement are still disabled. Evidence:
`evidence/2026-09-15-virtualization-guest-bootstrap-timeout.md`.

Task-profile startup-wiring addendum: the explicit host startup seam now
requires a validated `TaskProfileRegistry` whenever sandbox or virtualization
task execution is configured, injects that registry into the Broker, and
rejects a registry without an isolated runner or a malformed registry. This
keeps the packaged empty-registry/fail-closed default unchanged. Service-startup
tests pass 7/7, and a gated physical-Darwin smoke executes one fixed profile
through startup, native UDS, approval, sandbox, and Job readback. The same
startup path denies an approved read of the protected Broker database with
`VERIFICATION_FAILED` and a failed Job. Production profile enablement still
requires independent host evidence. Evidence:
`evidence/2026-09-15-task-profile-startup-wiring.md`.

Task-profile regex-safety addendum: source revision `c42c7a8` restricts
host-owned argument patterns to a bounded anchored fragment without groups,
alternation, or backreferences before JavaScript compilation. Nested,
unbounded-range, and oversized patterns fail closed; task-profile tests pass
4/4. This closes only the profile-configuration regex DoS boundary, not
production task enablement.
Evidence: `evidence/2026-09-15-task-profile-regex-safety.md`.

Sandbox startup-wiring addendum: source revision `2e605ea` connects the
explicit host sandbox runner seam to Broker service assembly and always merges
validated package/data/runtime roots into its protected set. Competing
virtualization and sandbox runners fail closed; the default service remains
unchanged and disabled. Service-startup tests pass 5/5 and sandbox tests pass
16/16. Evidence:
`evidence/2026-09-15-sandbox-startup-wiring.md`.

Sandbox UDP addendum: source revision `02fec55` verifies the existing
loopback-UDP allowlist on physical Darwin using a fixed Perl Socket task. The
listed destination receives a datagram; an unlisted port fails and receives
none. Sandbox tests pass 16/16 and the complete serial physical-Darwin suite
passes 607/607 with 0 skipped tests. External networking and production task
enablement remain disabled. Evidence:
`evidence/2026-09-15-sandbox-udp.md`.

Sandbox protected-root addendum: source revision `5fb0f3a` threads an explicit,
bounded Broker-owned protected-root set into the sandbox renderer. Deny rules
follow task allow rules and are validated as canonical absolute paths; the
physical-Darwin smoke allows the synthetic root but rejects its ledger file.
The complete serial physical-Darwin suite passes 606/606 with 0 skipped tests.
This advances persistence-surface policy and is now reachable through the
explicit startup seam, but the packaged runner remains disabled and remount,
descriptor, credential, and Docker isolation are not proven. Evidence:
`evidence/2026-09-15-sandbox-protected-roots.md`.

Executable-content identity addendum: source revision `a0e62e2` makes the
ProcessSupervisor executable snapshot include device/inode/mode, ordinary
metadata, and a bounded SHA-256 digest read through an `O_NOFOLLOW`
descriptor. Startup and final readbacks now reject an executable rewrite even
when the path and inode are unchanged; cwd directories intentionally retain
identity-only checks because task writes change directory timestamps. The
same-inode Darwin regression and complete serial physical-Darwin suite pass
606/606 with 0 skipped tests. This narrows the startup target-swap window but
is not a kernel-held descriptor/fexec proof. Evidence:
`evidence/2026-09-15-process-executable-content-identity.md`.

Sandbox-root identity addendum: source revision `f562bc2` extends the task
boundary from volume identity to each unique Broker-owned filesystem-root
directory. Device/inode/mode snapshots are captured before dispatch and
rechecked through awaited startup ownership and final execution readback;
volume identity checks remain in place. A Darwin regression swaps a non-cwd
allowed root and proves the runner rejects it. The complete physical-Darwin
regression passes 604/604 with 0 skipped tests. This detects root-path swaps in
the implemented windows but is not an in-syscall remount or kernel descriptor
proof. Evidence: `evidence/2026-09-15-sandbox-root-identity.md`.

Sandbox-task path addendum: source revision `2599502` reuses the Broker-owned
process path identity gate for the executable and cwd embedded inside a
`sandbox-exec` task profile. The runner captures device/inode/mode before
dispatch, awaits asynchronous startup ownership checks, rechecks those paths
after startup and after execution, and leaves the Job unresolved when the
target changes. A physical-Darwin regression replaces the inner task
executable after authorization and proves rejection; the complete suite passes
603/603 with 0 skipped tests. The checks detect startup-window swaps but do
not claim a kernel-held descriptor/fexec guarantee. Evidence:
`evidence/2026-09-15-sandbox-task-path-identity.md`.

Process-path identity addendum: source revision `5efe002` makes
`ProcessSupervisor` retain the device/inode/mode identity of the canonical
executable and cwd during request validation, recheck both immediately after
spawn and after the startup ownership callback, and abort with a stable
fail-closed error when either target changes. A real physical-Darwin test
replaces the executable after authorization and proves the swap is rejected;
the complete physical-Darwin regression passes 602/602 with 0 skipped tests.
This detects startup target swaps but does not yet provide a kernel-held
descriptor/fexec guarantee for all post-check filesystem changes. Evidence:
`evidence/2026-09-15-process-path-identity.md`.

Policy-helper gate addendum: source revision `21559e7` makes principal
projection, target authorization, capability-family kill-switch evaluation,
and capability discovery invoke the same complete Broker policy validator
before acting. Partial or malformed policy objects can no longer use a helper
entrypoint to bypass the authority gate. The security-fuzz policy corpus and
full physical-Darwin regression pass; the latter is 601/601 with 0 skipped
tests. Evidence:
`evidence/2026-09-15-policy-helper-gate.md`.

Runtime-policy semantic-validation addendum: source revision `83a733e`
extends the Broker policy gate beyond ToolPolicy fields to validate exact
policy keys, trusted-key windows, principal grants, target-rule identity and
scope binding, filesystem-root identifiers and normalized deny paths, and
target-kind/reference constraints. Malformed in-memory authority now fails
closed before authorization while planned-but-unimplemented tools remain
supported. The complete physical-Darwin regression passes 601/601 with
0 skipped tests. Evidence:
`evidence/2026-09-15-runtime-policy-semantics.md`.

Runtime-policy snapshot addendum: source revision `0be82c4` deep-copies
Broker policy authority at the plain-policy Broker boundary and inside
PolicyManager transitions/readback. Mutable caller references to target rules,
principal grants, kill switches, filesystem roots, ToolPolicy scopes, and
capability families can no longer alter active authorization or capability
state. The focused Broker/policy selection passes 82 tests (76 passed, 6
explicit platform skips); the complete physical-Darwin regression passes
601/601 with 0 skipped tests. Evidence:
`evidence/2026-09-15-policy-authority-snapshot.md`.

Runtime-policy validation addendum: source revision `ee994a8` adds a
Broker-owned validation gate for in-memory and signed `BrokerPolicy` values.
Construction, activation, restore, rollback, and every tool authorization now
fail closed on malformed policy metadata or ToolPolicy fields, including
unknown tools, contract-version drift, invalid scopes/capability families,
invalid target or approval types, unsafe budgets, and an enabled-but-not-
implemented state. This prevents a mutable caller-owned policy map from
advertising or authorizing an unsafe contract. Policy and PolicyManager tests
pass 17/17; the complete physical-Darwin regression passes 600/600 with
0 skipped tests. Evidence:
`evidence/2026-09-15-runtime-policy-validation.md`.

Runtime contract-integrity addendum: source revision `2dedae0` makes the Edge
contract loader reject group/other-writable contract directories and files,
rejects symlinked paths, and rechecks device/inode/mode before and after each
read plus the directory-wide load. This protects the MCP schema/purpose
surface from an untrusted package replacement while Broker authorization
remains authoritative. Focused contract-registry tests pass 5/5 and the full
physical-Darwin regression passes 598/598 with 0 skipped tests. Evidence:
`evidence/2026-09-15-runtime-contract-integrity.md`.

Idempotency authorization addendum: source revision `d715512` makes the
BrokerStore Job reuse path bind
the existing Job's policy version in addition to principal, tool, target, and
payload digest. A repeated idempotency key under a different policy revision
returns `CONFLICT` and cannot reuse the prior Job. Focused persistence and
full regression tests pass. Evidence:
`evidence/2026-09-15-idempotency-policy-binding.md`.

Strict UTF-8 boundary addendum: source revision `1ce5bee` adds a shared fatal
UTF-8 decoder and applies it to implemented Broker/Edge IPC, approval,
policy-signer, authority-control, status, helper, Keychain, virtualization
guest, contract, persistence, audit, lock, and protected configuration JSON
paths. Malformed frames fail closed before parsing or replay admission. Focused
boundary tests pass 78/78, the native canonical JSON probe passes 5/5 vectors,
and the complete physical-Darwin regression passes 587/587 with 0 skipped
tests. Evidence: `evidence/2026-09-15-strict-utf8-boundary.md`.

Strict JSON parser addendum: source revision `ecc3a98` adds a bounded recursive
wire scanner before `JSON.parse`. Implemented protocol, protected
configuration, persistence, audit, and Edge contract readers now reject
duplicate object keys (including escaped equivalents), unpaired UTF-16
surrogates, malformed grammar, and trailing data while preserving strict
UTF-8 decoding. Focused trust-boundary tests pass 49/49, the native canonical
JSON probe passes 5/5 vectors, and the complete physical-Darwin regression
passes 588/588 with 0 skipped tests. Evidence:
`evidence/2026-09-15-strict-json-parser.md`.

Runtime strict-JSON addendum: source revision `0bcb354` routes implemented
child-adapter, Authority Control IPC, stored-result, Job metadata, audit, and
encrypted-backup evidence readers through `parseJsonStrict` before validation
or canonical hashing. Static schema loading and parser internals remain
separate trusted implementation inputs. Targeted runtime-reader tests pass
79/79; the complete physical-Darwin regression passes 592/592 with 0 skipped
tests. Evidence:
`evidence/2026-09-15-runtime-strict-json-boundaries.md`.

Cross-runtime number addendum: source revision `c31f82a` makes the strict JSON
scanner compare every numeric token's lexical canonical form with Node's
ECMAScript `JSON.stringify` representation. Precision-changing integers,
floating-point spellings that round differently, underflow, overflow, and
oversized exponents now fail closed before authentication or persistence.
Focused canonical JSON tests pass 5/5 and the complete physical-Darwin
regression passes 593/593 with 0 skipped tests. Evidence:
`evidence/2026-09-15-cross-runtime-json-number-canonicalization.md`.

Capability-family capacity addendum: source revisions `db129b3`, `0b7d3b9`, `d7c4689`, and `8ad120b` add a schema-v9
request-ledger marker and BrokerStore admission gates for independent
`read`/`write`/`process`/`network`/`gui`/`destructive`/`privileged` families.
Broker-resolved families are persisted before authorization and counted inside
the same SQLite `BEGIN IMMEDIATE` transaction across Broker handles. Unknown
legacy markers conservatively consume every requested family, while malformed
markers fail closed as `AUDIT_UNAVAILABLE`; every admission validates existing
markers even when the new request has no family. Focused Broker/persistence
tests pass 123/123 with 6 explicit skips; RequestRecord and the versioned
ledger schema expose the resolved family list while preserving legacy records;
malformed readback is covered directly;
the complete physical-Darwin
regression passes 597/597 with 0 skipped tests. Evidence:
`evidence/2026-09-15-capability-family-capacity.md`.

Durable request-capacity addendum: source revision `31e89f0` moves active
request admission limits into the BrokerStore `BEGIN IMMEDIATE` transaction.
The Broker now supplies a default global cap of 64 and principal/session cap
of 8 (hard maxima 256 and 64); saturation returns retryable `CONFLICT` before
nonce/request persistence, and terminal/restart reconciliation releases
capacity. Two SQLite handles prove session and global conflicts, no durable
record for rejected requests, and release after terminal failure. Focused
Broker/persistence tests pass 125 cases with 119 pass and 6 explicit
non-Darwin/real-sandbox skips; full physical-Darwin regression passes 589/589
with 0 skipped tests. Evidence:
`evidence/2026-09-15-durable-request-capacity.md`.

Process-quota addendum: source revision `a135396` adds a Broker-owned
per-executable admission gate to the shared ProcessSupervisor. Active and
pending starts for the same canonical executable share a default cap of 4,
bounded by the existing global cap of 16 in the Broker runtime; cancellation,
startup abort, unknown-outcome drain, and close release both counters. Focused
ProcessSupervisor tests pass 26/26, and the complete physical-Darwin suite
passes 592/592 with 0 skipped tests. Evidence:
`evidence/2026-09-15-process-quota-isolation.md`.

Broker session-concurrency addendum: source revisions `d185f12` and `9d92f0d` validate
request-age and clock-skew limits at Broker startup and bounds active work per
authenticated principal/session (default 8, maximum 64). Capacity rejection
returns retryable `CONFLICT` before durable request admission or audit, and
reservations release on every completion path. Broker focused tests pass 78/78,
the native canonical JSON probe passes 5/5 vectors, and the complete
physical-Darwin regression passes 585/585 with 0 skipped tests. Evidence:
`evidence/2026-09-15-broker-session-concurrency.md`.

Approval TTL-gate addendum: source revision `0ab3fc9` rejects a signed Approval
whose own TTL has elapsed at the current Broker clock before persistence or
audit. Approval Authority/IPC tests pass 10/10, including current-expired
nonce and Approval cases with no records created; the complete physical-Darwin
regression passes 583/583 with 0 skipped tests. Evidence:
`evidence/2026-09-15-approval-ttl-gate.md`.

Task isolation proof addendum: source revision `7a101d9` requires an explicit
`persistence: "isolated"` claim alongside filesystem, network, credentials,
and process-tree guarantees. Strict validation rejects missing or non-isolated
persistence claims before runner availability; all proof fixtures and guest
startup paths preserve the new field. The complete physical-Darwin regression
passes 582/582 with 0 skipped tests. Evidence:
`evidence/2026-09-15-task-persistence-proof.md`.

Approval issuance expiry-gate addendum: source revision `8552210` makes the
Broker-owned Approval Authority reject a current-expired signed issuance nonce
before approval persistence or audit. The regression leaves both the Approval
record and audit ledger unchanged; Approval Authority/IPC tests pass 9/9 and
the complete physical-Darwin regression passes 582/582 with 0 skipped tests.
Evidence: `evidence/2026-09-15-approval-expiry-gate.md`.

IPC expiry-gate addendum: source revision `6947608` makes Privileged Helper
command/status authentication reject current-expired nonce/command windows
before replay admission, authorization, adapter dispatch, or status readback;
Policy Signer applies the current nonce-expiry gate before manager mutation.
Structurally valid stale Helper requests retain authenticated `AUTH_EXPIRED`
proofs, while malformed envelopes use the fallback proof. Focused Helper tests
pass 9/9 and Policy Signer tests pass 2/2; the complete physical-Darwin
regression passes 581/581 with 0 skipped tests. Evidence:
`evidence/2026-09-15-ipc-expiry-gates.md`.

Broker Status IPC error-proof addendum: source revision `ad3adc9` binds
structurally valid status requests to authenticated `AUTH_EXPIRED` and
`REPLAY_DENIED` failure responses before freshness/auth checks, while unknown
fields remain on the invalid-request fallback and no candidate reaches replay
admission or status execution. The focused Broker Status IPC test passes 1/1;
the complete physical-Darwin regression passes 581/581 with 0 skipped tests.
Evidence: `evidence/2026-09-15-broker-status-error-proof.md`.

Authority Control CLI and IPC error-proof addendum: source revisions
`447e4aa`, `f359360`, `5962efc`, and `032bf8f` add
the bounded
`mac-operator-authority` operator entrypoint. It accepts only switch readback,
expected-state switch changes, and identity revocation; restores the exact
active key through the Broker key manager, requires explicit confirmation for
mutations, verifies each mutation with authenticated readback, and exposes no
raw key, command, executable, or capability grant. The revocation allowlist
includes guest-attestation keys. Focused CLI tests pass 4/4, including a
protected file/authenticated-IPC round trip; Authority Control IPC tests pass
3/3, including stable authenticated `AUTH_EXPIRED` readback without
admission, audit, or mutation side effects. The complete physical-Darwin
regression passes 581/581 with 0 skipped tests. Evidence:
`evidence/2026-09-15-authority-control-cli.md`.

Privileged helper command-factory disposal addendum: the Broker-owned helper
command factory now wipes its defensive authentication-key copy at an
idempotent disposal boundary and rejects all later issuance with stable
`CANCELLED`, preventing stale factories from signing with cleared material.
Focused privileged-helper tests pass 9/9; the complete physical-Darwin
regression passes 576/576 with 0 skipped tests. Evidence:
`evidence/2026-09-15-privileged-helper-factory-disposal.md`.

Virtualization guest active-I/O drain addendum: the Native VM handle now
tracks every Broker-owned Virtio exchange, closes tracked connections before a
VM stop or close, and closes a late connection immediately after shutdown is
marked. Retained Objective-C references are released only after tracking is
removed, so cancellation cannot race an invalid pointer. Native build,
focused VM-native tests (7/7), and the complete physical-Darwin regression
(576/576, 0 skipped) pass. Evidence:
`evidence/2026-09-15-virtualization-native-connection-drain.md`.

Virtualization guest native-handle fencing addendum: the native VM lifecycle
adapter now uses an atomic handle-validity marker, never restores that marker
after a retained async transition completes, and keeps the serial dispatch
queue alive until the external handle finalizer. This prevents a closed handle
from being resurrected and lets in-flight callbacks observe the closed state
instead of dispatching through a null queue. Native build, focused VM-native
tests (7/7), and the complete physical-Darwin regression (576/576, 0 skipped)
pass. Evidence: `evidence/2026-09-15-virtualization-native-handle-fencing.md`.

Local IPC shutdown-drain addendum: Node UDS servers for Broker, Approval,
Authority Control, Broker Status, Policy Signer, and Privileged Helper now
track and destroy accepted sockets before close waits. The cross-channel IPC
suite passes 29/29, including an idle Broker peer, and the full physical-
Darwin regression passes 575/575 with 0 skipped tests. Evidence:
`evidence/2026-09-15-local-ipc-shutdown-drain.md`.

Broker IPC framing addendum: the authenticated Broker socket now rejects
non-whitespace bytes after its first newline frame before JSON parsing or
Broker admission. The signed request can be retried cleanly, proving the
rejection does not consume replay state or write audit. Focused Broker IPC
tests pass 6/6 and the full physical-Darwin regression remains 574/574 with
0 skipped tests. Evidence:
`evidence/2026-09-15-local-ipc-framing-hardening.md`.

Approval IPC framing addendum: the owner-only approval channel now rejects
non-whitespace bytes after its authenticated newline frame before issuer
verification, durable replay, approval creation, or audit. The regression
proves the same signed issuance can be retried cleanly after a trailing-frame
rejection; focused approval tests pass 8/8 and the full physical-Darwin
regression remains 574/574 with 0 skipped tests. Evidence:
`evidence/2026-09-15-local-ipc-framing-hardening.md`.

Approval issuer key lifecycle addendum: `ApprovalAuthority` now owns
defensive issuer-key copies, wipes and clears them through an idempotent
`dispose()` boundary, and rejects later issuance or key addition with
`CANCELLED`. Approval authority and owner-only IPC tests pass 8/8; the
implementation build and diff checks pass. Evidence:
`evidence/2026-09-15-approval-key-lifecycle.md`.

Authority-control key lifecycle addendum: `AuthorityControlIpcClient` now
copies its HMAC key, wipes it on explicit `dispose()`, and rejects further
requests with `CANCELLED`. Authority Control and Privileged Helper servers
also wipe copied keys when socket detachment or close cleanup fails. Focused
Authority Control tests pass 2/2, Privileged Helper IPC tests pass 9/9, and
the complete physical-Darwin regression passes 573/573 with 0 skipped tests.
Evidence: `evidence/2026-09-15-authority-control-key-lifecycle.md`.

Local IPC framing hardening addendum: the Privileged Helper, Policy Signer,
and Broker Status owner-only channels now reject non-whitespace bytes after
their authenticated first frame before replay admission, status readback, or
mutation. Their clients reject appended response frames as well, and the
Policy Signer wipes its copied HMAC key on every close path. The complete
physical-Darwin regression passes 573/573 with 0 skipped tests. Evidence:
`evidence/2026-09-15-local-ipc-framing-hardening.md`.

Capability kill-switch readback addendum: `mac_capabilities` now evaluates
both persisted runtime switches and signed-policy family kill-switches before
advertising an enabled capability. Disabled families return the stable
`disabled_by_kill_switch` reason, keeping Edge discovery consistent with the
Broker's final execution authority. The focused regression covers persisted
and policy `process` switches; the full physical-Darwin regression passes
572/572 with 0 skipped tests. Evidence:
`evidence/2026-09-15-capability-kill-switch-readback.md`.

Authority-control framing addendum: the owner-only IPC now rejects non-
whitespace bytes after the single newline-delimited command. It authenticates
the command but skips replay admission, authority mutation, and audit when
trailing data is present. Focused IPC tests pass 2/2 and the full
physical-Darwin regression passes 571/571 with 0 skipped tests. Evidence:
`evidence/2026-09-15-authority-control-framing.md`.

Authority-control restart readback addendum: after closing and reopening the
BrokerStore and Authority Control IPC server, a fresh authenticated client now
reads back persisted global/process switches and session/Edge revocations;
replayed mutation commands remain denied. Focused IPC tests pass 2/2 and the
full physical-Darwin regression passes 571/571 with 0 skipped tests. Installed
operator identity, active process termination, and safe re-enable procedures
remain open. Evidence:
`evidence/2026-09-15-authority-control-restart-readback.md`.

Guest transport shutdown hardening addendum: the host transport client now
tracks active exchanges, aborts them on close, rejects a stable `CANCELLED`
outcome, and blocks a post-admission frame send or response success after
shutdown. Focused transport tests pass 15/15 and the full physical-Darwin
regression passes 571/571 with 0 skipped tests. Evidence:
`evidence/2026-09-15-virtualization-guest-transport-close.md`.

Guest-agent shutdown hardening addendum: `VirtualizationGuestAgent` now owns
an abort controller for every admitted task/status request, propagates caller
cancellation, aborts all active work on close, and checks the close state
before signing or publishing a response. Focused guest-agent tests pass 4/4
and the full physical-Darwin regression passes 571/571 with 0 skipped tests.
This closes only the protocol-service shutdown race; VM boot, guest
isolation, and `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-agent.md`.

Latest guest bootstrap addendum: `VirtualizationGuestBootstrap` now serves one
bounded length-prefixed authenticated frame per startup-owned connection. It
keeps vsock acceptance transport-specific, enforces frame/response,
connection-time, and concurrency budgets, rejects trailing request data, and
propagates shutdown cancellation into the guest executor before wiping the
guest-agent key. Focused bootstrap tests pass 5/5 and the full physical-Darwin
regression passes 560/560 with 0 skipped tests. This does
not claim a production AF_VSOCK acceptor, bootable image, VM boot, guest
isolation, or `mac_task_run` enablement. Evidence:
`evidence/2026-09-15-virtualization-guest-bootstrap.md`.

Virtualization listener addendum: the protected native lifecycle artifact now
exposes a fixed-port `VZVirtioSocketListener` boundary with bounded pending
connections, finite accept/read/write deadlines, external connection-handle
lifetime fencing, and listener/VM close draining. The TypeScript adapter wraps
it as a `VirtualizationGuestConnectionSource` for the bootstrap protocol;
accept cancellation closes a connection that arrives after the caller stops
waiting. Focused VM/listener tests pass 6/6 and the full physical-Darwin
regression passes 562/562 with 0 skipped tests. This closes only the host-side
virtio-socket acceptor seam; it does not claim a guest AF_VSOCK service,
bootable image, guest execution/isolation, attestation production, or
`mac_task_run` enablement. Evidence:
`evidence/2026-09-15-virtualization-guest-vsock-listener.md`.

Guest profile executor addendum: the guest-side manifest registry now
recomputes the shared profile/task digests, rejects shell and unsafe
environment entries, rechecks canonical executable/cwd/root targets at
admission, and dispatches only fixed startup-owned process material. A
bounded terminal ledger serves status recovery, maps timeout/cancellation/
output failures to stable redacted results, and keeps the process adapter
behind an explicit isolation-evidence gate. The host Broker also redacts task
verification summaries before publishing the final success envelope. Focused guest-executor tests pass
7/7 and the full physical-Darwin regression passes 569/569 with 0 skipped
tests. This proves manifest binding and executor semantics only; it does not
claim a bootable guest, guest filesystem/network/credential isolation, or
`mac_task_run` enablement. Evidence:
`evidence/2026-09-15-virtualization-guest-executor.md`.

Latest startup composition addendum: the optional
`virtualizationGuest` startup seam now composes the protected image, native VM
lifecycle, fixed virtio channel, optional guest-initiated listener source,
authenticated guest transport, and virtualization task runner. Enabled startup
boots the guest before Job Ledger
recovery and closes transport/VM resources before the Broker store; absent
startup input leaves the existing fail-closed runner unchanged. Focused startup
tests pass 3/3 and the full physical-Darwin regression passes 555/555 with 0
skipped tests. The host still rejects the synthetic image before VM creation,
so no production VM boot, guest handshake, isolation, attestation production,
or `mac_task_run` enablement is claimed. Evidence:
`evidence/2026-09-15-virtualization-guest-startup.md`.

Latest virtio connector addendum: commit `b8551d6` adds a bounded native
`exchangeGuestFrame` over `VZVirtioSocketDevice.connectToPort` and a
`NativeVirtualizationGuestChannel` adapter for the existing authenticated guest
transport. The connector is handle-only, uses a monotonic connect/write/read
deadline, enforces port/frame/response caps, rejects truncation and trailing
data, protects SIGPIPE, and releases connections across callback races. Focused
lifecycle/native/channel tests pass 10/10 and the full physical-Darwin
regression passes 552/552 with 0 skipped tests. The host still rejects the
synthetic VM configuration before creation, so this is connector/framing
evidence only; no guest server, VM boot, isolation, or `mac_task_run`
enablement is claimed. Evidence:
`evidence/2026-09-15-virtualization-guest-virtio-connector.md`.

Latest native virtualization lifecycle addendum: commit `40f0461` connects the
Broker-owned lifecycle controller to a separate Objective-C++ N-API artifact
linked against `Virtualization.framework`. The startup constructor revalidates
the protected image identity, creates a read-only block attachment with no
host network or directory sharing and one future virtio-socket device, and
exposes asynchronous handle-bound start/stop/status/close operations with
random boot IDs and unknown-state mapping. The TypeScript adapter rechecks the
image before every operation and never accepts MCP paths. Focused lifecycle/
adapter tests pass 9/9 and the full physical-Darwin regression passes 551/551
with 0 skipped tests. The current host rejects the synthetic configuration
before VM creation, so no VM boot or guest isolation is claimed; production
entitlement, bootable image, guest serving, attestation production, and
`mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-native-lifecycle.md`.

Latest Broker virtualization lifecycle addendum: commit `042517a` adds a
disabled-by-default, Broker-owned `VirtualizationGuestVmLifecycle` state
machine. Start, stop, status, cancellation, timeout, close, and recovery are
serialized and bounded; every adapter result is checked against the immutable
guest identity and boot ID, while failures remain `unknown` until fresh status
readback. Focused lifecycle tests pass 5/5 and the full physical-Darwin
regression passes 547/547 with 0 skipped tests. This is a native-adapter
lifecycle seam only: it does not boot a VM or prove guest isolation, virtio
serving, attestation production, or `mac_task_run` enablement. Evidence:
`evidence/2026-09-15-virtualization-guest-lifecycle.md`.

Latest guest-agent addendum: commit `c8a856e` adds `VirtualizationGuestAgent`,
a bounded guest-side protocol service for the future native virtio channel. It
verifies HMAC, freshness, guest/profile digest binding, and replay identity
before invoking a guest-owned executor; it signs request-bound task/status
responses, enforces frame limits, excludes host paths/commands/credentials from
the executor API, and clears its guest-only key on close. Focused guest-agent
tests pass 3/3 and the full physical-Darwin regression passes 542/542 with 0
skipped tests. This is protocol-serving code only: native VM lifecycle,
bootable image deployment, guest isolation evidence, and `mac_task_run`
enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-agent.md`.

Latest native Virtualization guest-preflight addendum: commit `7de8385` adds a
protected `virtualization_guest.node` N-API artifact and startup-only wrapper.
The artifact accepts only a canonical owner-only image whose device/inode/size
and SHA-256 are supplied by the host preflight, opens it with `O_NOFOLLOW`,
constructs a read-only `VZDiskImageStorageDeviceAttachment`, and reports that
network and directory-sharing devices are absent. It never boots a VM. Focused
native tests pass 2/2 and the full physical-Darwin regression passes 539/539
with 0 skipped tests. This is a real native image/configuration boundary, not
guest execution or isolation evidence: a bootable production image, VM
lifecycle, guest channel serving, signed attestation production, independent
credential/filesystem/network/process isolation, and `mac_task_run`
enablement remain open. Evidence:
`evidence/2026-09-15-native-virtualization-guest-preflight.md`.

Latest canonical JSON wire-profile addendum: commits `7860a00`, `a26a188`,
`1aa0eea`, and `ae2e9eb`
publish the versioned `jcs-utf8-v1` profile, exact UTF-8 byte helper, and a
bounded read-only native Swift standard-library probe over five fixed SHA-256
vectors. Focused TypeScript tests pass 2/2, the native probe passes 5/5, the
full physical-Darwin regression passes 537/537 with 0 skipped tests, and
typecheck passes. The protected C++ N-API artifact additionally reproduces all
five native digest vectors and enforces a 1 MiB input cap. This establishes
repository and independent native serialization readback without
changing existing digest bytes; the production Swift/C++ adapter, VM
isolation, and cross-runtime release evidence remain open. Evidence:
`evidence/2026-09-15-canonical-json-wire-profile.md`.

Latest guest-attestation keyring addendum: commits `73148a6`, `db83881`, and
`c56aa0a` add a Broker
startup/operator key manager for signed guest provenance. It loads only
owner-only canonical public-key files with `O_NOFOLLOW`, device/inode and
digest binding, bounded sizes, and Ed25519 validation. BrokerStore schema
version `8` persists this configuration independently with monotonic
activation, exact restart restore, audited rollback, and a dedicated
`guest_attestation_key` revocation kind checked dynamically by each verifier.
Focused persistence/keyring tests pass 50/50 and the full physical-Darwin
regression passes 533/533. Host private signing keys are never loaded; native
guest signing, protected key distribution, VM boot, guest isolation, and
capability enablement remain open. Commit `db83881` also makes the policy,
policy-signer, and guest verification loaders reject private-key material
instead of deriving a public key from it; `c56aa0a` restores an optional
dataRoot-bound guest trust set before packaged startup proceeds. Evidence:
`evidence/2026-09-15-virtualization-guest-attestation-keyring.md`.

Latest signed guest-provenance addendum: commit `84da3e0` extracts the
Virtualization guest attestation contract into a dedicated module and adds a
versioned Ed25519 envelope. The verifier binds key ID, algorithm, issue/expiry
window, payload digest, and complete claims; it enforces startup-trusted key
validity, revocation, bounded lifetime, and fail-closed freshness. When
configured, `VirtualizationTaskRunner` requires a matching signed attestation
at construction and revalidates it before dispatch and restart status lookup.
Focused attestation/runner tests pass 15/15 and the full physical-Darwin
regression passes 527/527. This is signed provenance verification only;
Keychain-backed key distribution, native attestation production, VM boot,
guest isolation, and capability enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-attestation.md`.

Latest authority-lifecycle addendum: commit `d0c96be` adds a bounded
deterministic BrokerStore state-machine regression. Sixteen reproducible seeds
run 72 actions each across independent kill switches, principal/session and
upstream revocation, expected-state conflicts, queued/running cancellation,
terminal completion, and restart reconciliation. Invariants prove blocked
queued Jobs are cancelled without cross-principal impact, revisions never
regress, terminal Jobs do not change state, and no queued/running Job survives
restart reconciliation. The focused persistence suite passes 46/46 and the
full physical-Darwin regression passes 527/527. This advances MOP-070 coverage
but remains bounded model-based testing; exhaustive fuzzing, active
process-tree proof, remote propagation, and installed-service evidence remain
open. Evidence:
`evidence/2026-09-15-authority-state-machine.md`.

Latest guest-image binding addendum: commits `846eca5` and `81faff0` add a
startup-owned, owner-only image preflight and require its immutable identity
for `VirtualizationTaskRunner` availability. The Broker re-hashes and checks
device/inode/size before every dispatch and restart status recovery, rejecting
content replacement before the executor is called. Focused runner/image tests
pass 15/15 and the full physical-Darwin regression remains 527/527. This is
host image provenance and target-swap evidence only; native signed-attestation
production, VM boot, guest isolation, and capability enablement remain open.
Evidence: `evidence/2026-09-15-virtualization-guest-image-preflight.md`.

Latest virtualization channel addendum: commits `521eecc` and `4592cad` add a
Broker-side, disabled-by-default Unix-socket channel for the future native
guest adapter. The startup-owned socket target is owner-only and bound to
device/inode identity before and after connect; the connected peer is checked
through native UID/GID/PID credentials and optional PID/start-time identity
before any response frame is accepted. One bounded length-prefixed frame is
allowed per connection, with cancellation, timeout, output, trailing-data,
symlink, and transport-loss handling. The physical Darwin regression passes
527/527 and the focused channel tests pass 4/4. This closes only the local
Broker-to-adapter transport seam; native guest serving, VM boot, guest
isolation evidence, and `mac_task_run` enablement remain open.
Evidence: `evidence/2026-09-15-virtualization-guest-channel.md`.

Latest Virtualization.framework host probe: source revision `75c8fd7` links the
active macOS 26.2 SDK on the physical Darwin arm64 host and reports framework
support. The intentionally guest-less configuration remains invalid, and no
VM boot, image fetch, guest channel, or capability enablement was attempted.
This refreshes SDK evidence only; guest image provenance, attestation, VM
isolation, credential/process/network proof, and production signing remain
open. Evidence:
`evidence/2026-09-15-virtualization-framework-probe.md`.

Latest hardening addendum: commit `bccc02d` adds deterministic bounded security
fuzz regression suites for Broker and guest authentication mutation, replay,
strict envelopes, traversal/protected zones, secret and prompt-injection-shaped
content, canonicalization, policy precedence, and output/resource budgets. On the physical Darwin
arm64 host, `MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm
test` passes 527/527, including the focused security-fuzz suite at 7/7 and the
authority state-machine regression. This advances MOP-070 coverage; exhaustive
fuzzing, kernel-level resource/isolation evidence, and independent review
remain open. Evidence:
`evidence/2026-09-15-security-fuzz-regression.md`.

Latest strict-exit addendum: governed sandbox tasks now request a final native
process-tree readback after child close. Missing observation, truncation, PID
replacement, or unresolved descendants returns `UNKNOWN_OUTCOME`; ordinary
fixed adapters retain their bounded exit behavior. Focused process-supervisor/
sandbox tests pass 29/32 with three explicit Darwin-boundary skips, and the
full real sandbox/Keychain regression passes 475/476 with one explicit skip.
This is an observation guard, not kernel-held process or remount isolation;
post-snapshot detached descendants, in-syscall remounts, credential contents,
and task enablement remain open. Evidence:
`evidence/2026-09-14-post-snapshot-exit-proof.md`.

Latest exit-event addendum: strict task proof now begins at the native child
`exit` event, records process-group survival before Node stream `close`, and
performs a second descendant observation after one bounded poll interval. A
Darwin fork-and-detach fixture that keeps the output pipe open is rejected as
`UNKNOWN_OUTCOME`; the focused process-supervisor suite passes 20/20 and the
full real sandbox/Keychain regression passes 477/478 with one explicit skip.
This reduces the close-event reparenting race but does not prove descendants
created after the final window, remount resistance, or credential isolation.
Evidence: `evidence/2026-09-14-exit-observation-window.md`.

Latest restart-recovery addendum: a persisted task snapshot is not a complete
post-exit process census. When the root and all previously observed
descendants are gone, recovery therefore remains `UNKNOWN_OUTCOME` with no
termination claim instead of reporting `PROCESS_ABSENT`; a descendant could
have been created after the final persisted observation and escaped into
another process group. The Darwin regression passes 21/21 focused
process-supervisor tests, and the full real sandbox/Keychain run passes
478/479 with one explicit install skip. Evidence:
`evidence/2026-09-14-restart-descendant-absence.md`.

Latest audit-outage addendum: a held audit-anchor sidecar lock now has a
physical regression proving that SQLite commit and keyed-tail publication are
separate failure boundaries. A post-commit publication outage returns the
retryable `AUDIT_UNAVAILABLE` error, leaves the database ahead of the sidecar,
freezes further writes in the same BrokerStore, and makes the next BrokerStore
startup reject the mismatch. The focused persistence suite passes 41/41.
Evidence:
`evidence/2026-09-14-audit-anchor-publication-outage.md`.

Latest packaged-startup addendum: the compiled Broker service entrypoint now
requires an owner-controlled audit-anchor path plus fixed Keychain
service/account/key-id configuration, constructs `BrokerStore` with the
executable-bound Keychain HMAC source, and fails closed before readiness when
the item or sidecar cannot be verified. The service-startup suite passes 3/3.
The opt-in real temporary LaunchAgent smoke
(`MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 node --test
packages/broker/dist/packaged-service-smoke.test.js`) passes 1/1 and cleans up
the exact temporary Keychain item and both labels. This is startup wiring and
host evidence only; Developer ID/persistent production installation,
cross-process sidecar locking, and external rollback-resistant anchoring remain
open. Evidence:
`evidence/2026-09-14-packaged-audit-anchor-startup.md`.

Latest audit-lock addendum: `AuditAnchorManager` now takes an owner-only
atomically-created sibling lock across sidecar read, validation, atomic
publication, and directory `fsync`. Release rechecks device/inode identity;
an existing lock is never auto-reclaimed and causes fail-closed recovery. The
focused audit-anchor plus persistence suite passes 44/44. This closes the
same-target sidecar race but is not a kernel lease or external immutable log;
stale-lock operator recovery, production Keychain rotation, Developer ID
installation, and rollback-resistant external anchoring remain open. Evidence:
`evidence/2026-09-14-audit-anchor-lock.md`.

Latest audit-lock recovery addendum: a host-only `recoverAuditAnchorLock`
boundary now requires an authenticated stopped-service callback and the exact
owner-only lock device/inode captured by operator readback. On Darwin it uses
the existing native descriptor-relative `unlinkat` + parent `fsync` boundary,
validates the removal readback, and refuses replacement or symlink targets;
startup and normal publication never invoke it automatically. Focused recovery
tests pass 3/3, and the full `MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm
test` regression passes 483/484 with one explicit skip. This is an explicit
stopped-service recovery primitive, not proof of external immutable anchoring
or production operator authentication. Evidence:
`evidence/2026-09-14-audit-anchor-lock-recovery.md`.

Latest Broker runtime-fence addendum: packaged Broker startup now enables a
persisted singleton runtime fence in SQLite. Each service instance claims the
next monotonic generation and a fresh token before restart reconciliation;
every subsequent write transaction verifies that generation/token pair while
holding the SQLite write lock. A later instance therefore invalidates stale
`BrokerStore` writers, which fail closed with stable `CONFLICT` instead of
publishing an old terminal Job, audit, or authority write. The focused
persistence suite passes 42/42; the complete real sandbox/Keychain regression
passes 484/485 with one explicit install skip. This is persistence-level Broker
fencing, not kernel process ownership: generic fixture stores may leave the
option off, and crashed-process, detached-worker, launchd, and installed-service
evidence remain open. Evidence:
`evidence/2026-09-14-broker-runtime-fence.md`.

Latest process-start admission addendum: `ProcessSupervisor` now counts a
child from validated spawn through PID/start-time observation and ownership
persistence, so pending starts consume shared concurrency capacity. Broker
shutdown also waits for those pending starts to abort and release their
capacity; it cannot return while an untracked startup is still proving
ownership. The focused Darwin ProcessSupervisor suite passes 23/23, and the
full `MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
regression passes 488/488, including the temporary LaunchAgent smoke. This is
an in-process admission and shutdown race fix; native Darwin root checks also
bind the observed process-group ID to the detached PID. It is not kernel
quotas or generic proof of crashed-Broker descendant ownership. A validated
single-process sandbox snapshot now carries a no-fork proof and can report
`PROCESS_ABSENT` only when its original process group is gone; observed-
descendant snapshots remain unresolved after root exit. Evidence:
`evidence/2026-09-14-process-start-admission.md`.

Latest controller-secret-zone addendum: Broker-owned sandbox profiles now
deny `.codex` and `.openai` controller-state directories in addition to the
existing SSH, cloud, Docker, browser, Mail, Messages, and Keychain zones. The
real `MOPS_REAL_SANDBOX=1` sandbox/task-runner readback passes 21/21 and
confirms those surfaces are denied without opening contents. This is stronger
deny-list evidence, not real credential-content isolation or production
`sandbox-exec` enablement. Evidence:
`evidence/2026-09-14-sandbox-controller-secret-zones.md`.

Latest Virtualization seam addendum: the disabled runner now requires a
digest-bound native guest attestation tied to the immutable guest identity,
resolved profile, external evidence reference, guest-private filesystem,
profile-bound network, unavailable host credentials, and guest-owned process
tree/policy. Construction and dispatch both revalidate the attestation. This is a
fail-closed adapter contract, not VM boot, entitlement, credential-isolation,
or production enablement evidence. Evidence:
`evidence/2026-09-14-virtualization-framework-sdk.md`.

Latest authenticated guest-transport addendum: `virtualization-guest-transport.ts`
adds a versioned, domain-separated HMAC protocol seam for a future native
Virtualization guest bridge. Request proofs bind guest identity, profile/task
digests, nonce, freshness, process policy, and bounded budgets; response proofs
bind the complete request digest, guest identity, result, verification, and
Broker-redacted output. Strict envelope validation rejects unknown fields,
wrong keys, stale requests, oversized output, and replayed request IDs/nonces.
Schema version 6 now adds a Broker-owned SQLite replay ledger and an adapter
that rejects the same request after Broker restart; the live ledger is capped
at 4,096 rows and cleans expired entries before admission; the in-memory guard
remains test-only. The bounded `VirtualizationGuestTransportClient` now admits before
exchange, enforces response framing/timeout/cancellation, and maps transport
loss to `UNKNOWN_OUTCOME`. Focused transport tests pass 10/10 and the
persistence plus transport run passes 54/54. Evidence:
`evidence/2026-09-14-virtualization-guest-transport.md`.

Latest guest-executor addendum: commit `2761bbb` adds
`VirtualizationGuestTransportExecutor`, which adapts the authenticated
transport to the Broker `TaskRunner` contract. It derives separate SHA-256
policy and exact-task digests from the resolved Broker-owned profile, sends
only those digests plus the guest identity and bounded budgets, revalidates the
response envelope and guest identity, and refuses to publish a guest success
without verified postcondition status. Focused task-runner plus guest-transport
tests pass 21/21, and the complete
`MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
regression passes 502/502. This is Broker-side adapter wiring only; the native
Virtualization channel, VM boot, signed attestation source, guest isolation,
and production `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-14-virtualization-guest-transport.md`.

Latest guest-recovery addendum: commit `c2a7888` adds a separate authenticated
guest status envelope. A lookup uses a fresh replay-protected request ID and
nonce, binds the original task request ID/nonce/digest and immutable guest
identity, applies bounded timeout/output limits, and verifies a signed status
response. The client requires an explicit Broker-owned authority callback
before sending any lookup, so status queries cannot become a new execution
authority. Focused task-runner plus guest-transport tests pass 25/25, and the
complete `MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm
test` regression passes 506/506. This is a recovery protocol boundary only;
Broker Job reconciliation, native guest status serving, VM boot, and production
enablement remain open. Evidence:
`evidence/2026-09-14-virtualization-guest-transport.md`.

Latest guest Job reconciliation addendum: the Broker now persists a bounded,
non-secret guest request descriptor (`guest_metadata_json`) immediately after
authenticated replay admission and before a native guest frame is sent. The
schema is version `7`; it records only request ID/nonce/digest, immutable guest
identity, profile/task digests, and timeout/output budgets. On restart,
`reconcileRestartedGuestTasks()` selects only `mac_task_run` Jobs that are
already `UNKNOWN`, marked `BROKER_RESTART`, and retain that descriptor. It
performs a fresh status lookup through the TaskRunner recovery boundary with
current policy, kill-switch, revocation, owner, and identity checks. Only a
verified terminal result can close the Job; unavailable, cancelled, malformed,
unverified, or transport-uncertain results remain `UNKNOWN` and are audited.
Focused Broker, persistence, task-runner, and guest-transport tests pass, and
the complete `MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1
npm test` regression passes 509/509. Native guest status serving, VM boot,
guest isolation evidence, and production enablement remain open. Evidence:
`evidence/2026-09-14-virtualization-guest-transport.md`.

Latest keyed-audit addendum: optional `BrokerStore` startup configuration now
binds the SQLite audit tail to a separate Broker-owned 0600 sidecar using an
explicit memory-only HMAC key source; a dedicated Keychain source factory now
loads that key through the Broker executable ACL. Every committed audit transaction
publishes the latest sequence/event hash after commit; startup rejects a
missing, stale, forged, or key-mismatched anchor, and a publication failure
cannot be mistaken for verified persistence. The focused persistence suite
passes 43/43, including restart and forged-sidecar readback; the full real
sandbox/Keychain regression passes 474/475 with one explicit skip. This is a local
keyed-integrity boundary, not an external immutable log; packaged startup,
production Keychain anchor provisioning, cross-process locking, and rollback
detection remain open. Evidence:
`evidence/2026-09-14-keyed-audit-anchor.md`.

Latest encrypted-backup addendum: Broker persistence backups now require an
explicit Broker-owned 32-byte key source and publish only authenticated
AES-256-GCM `.sqlite.enc` files. Creation and restore use descriptor-backed
streaming, decrypt-and-verify SQLite/audit readback, identity checks before
rename, and owner-only temporary cleanup; missing or mismatched keys,
ciphertext tampering, and legacy plaintext names fail closed. The dedicated
Keychain source factory keeps the key out of files, logs, and MCP arguments.
Focused persistence and credential tests pass 47/47. Evidence:
`evidence/2026-09-14-encrypted-backup.md`.

Persistence-schema addendum (v5): `BrokerStore` now reads SQLite
`user_version` before initialization, rejects a database marked newer than the
runtime, and applies a versioned forward-only migration registry transactionally
before publishing schema version `5`. Each known migration is shape-checked and
recorded in `schema_migrations`; registry gaps, identity changes, malformed
timestamps, and future markers fail closed. Fresh initialization, legacy data
preservation, future-version refusal, registry-integrity refusal, failed
migration rollback, and persisted runtime-fence takeover pass 42/42 focused
persistence tests. Rollback is explicitly
restore-from-encrypted-backup only; no automatic down-migration is exposed.
ADR-0005 acceptance remains open.
Evidence:
`evidence/2026-09-14-persistence-schema-version.md`.

Latest persistence replay-ledger addendum: schema version `6` adds the
owner-controlled `virtualization_guest_nonces` table and a strict
`BrokerStore.admitVirtualizationGuestRequest()` boundary. The
`BrokerStoreVirtualizationGuestReplayGuard` binds Guest transport admission to
that ledger, so request IDs and nonces remain rejected after Broker restart;
duplicate and persistence failures map to stable `REPLAY_DENIED` and
`AUDIT_UNAVAILABLE` errors. Migration identity/shape checks remain
transactional and future schema markers remain refused. The focused
persistence plus Guest transport run passes 50/50. Evidence:
`evidence/2026-09-14-virtualization-guest-transport.md`.

Schema version `7` extends the Job Ledger with the bounded guest task request
descriptor used by restart reconciliation. The descriptor contains no host
paths, executable text, arguments, environment, credentials, or raw output;
terminal recovery clears it after verified readback, while unresolved Jobs
retain it for a later bounded lookup. Migration is forward-only and future
schema markers remain refused.

Schema version `8` adds independently persisted guest-attestation key
configuration history and active identity, plus the dedicated
`guest_attestation_key` revocation kind. Activation and rollback are monotonic,
revision/precondition bound, and audited; restart restore requires an exact
payload digest. The key manager loads only protected Ed25519 public keys and
never handles guest private signing material. Evidence:
`evidence/2026-09-15-virtualization-guest-attestation-keyring.md`.

Latest process-tree identity addendum: ProcessSupervisor now rejects a
descendant PID whose start-time changes between observations, marks native
observation failed, and stops descendant signalling instead of targeting a
replacement process. The deterministic PID-reuse regression passes; unresolved
work remains `UNKNOWN`; the full real-sandbox regression now passes 466/467
with one explicit opt-in skip. Evidence:
`evidence/2026-09-14-process-pid-reuse.md`.

Latest Keychain ACL addendum: the macOS credential boundary now targets the
file-based Keychain model required for launchd daemons. Provisioning accepts an
explicit canonical protected Broker executable and creates a `SecAccess` ACL
bound to its trusted-application requirement; native readback checks that ACL
before touching secret bytes. Native search rejects duplicate service/account
identities, and retirement requires the exact 32-byte value plus a bound item
reference. A real physical-host run provisioned a random item, verified
`file-based-acl` metadata, rejected a different executable identity, and
retired the item; focused credential/native tests pass 16/16. The previous
data-protection `SecAccessControl` attempt correctly failed with missing
entitlement on the unsigned development host and is not used as a daemon
fallback. Production Developer ID/provisioning, installed executable identity,
cross-process rotation, and final ADR acceptance remain open. Evidence:
`evidence/2026-09-14-keychain-acl.md`.

Latest production-signature addendum: Broker and Edge LaunchAgent install plans
now default to a strict `developer-id` signature policy requiring the exact
component identifier, Developer ID Team Identifier, and CDHash before any plan
can render launchd mutation actions. An explicit `development-ad-hoc` mode is
limited to zero-capability temporary fixtures. The focused install-plan suite
passes 21/21; no Developer ID artifact or persistent service was available on
the host. Evidence: `evidence/2026-09-14-production-signature-gate.md`.

Latest task credential-proof addendum: `TaskIsolationProof` now binds an
explicit credential-isolation statement to the selected `sandbox-exec` or
virtualization mechanism. The host sandbox proof names empty inherited
environment plus secret-zone denial; a future guest proof names no host
credentials. Mechanism mismatch fails closed before dispatch. Focused
runner/sandbox tests pass 18/21 with three explicit Darwin skips. Evidence:
`evidence/2026-09-14-task-credential-isolation-proof.md`.

Latest persistence operations addendum: `PERSISTENCE_CUTOVER.md` defines the
forward migration, encrypted-backup restore, authority freeze, UNKNOWN-job
handling, rollback, and final readback order without inventing an installer or
in-place down-migration. This is a host/operator procedure; production service
cutover and external audit anchoring remain open.

Latest process-identity exit-window addendum: `ProcessSupervisor` now keeps
the bounded 100ms native PID/start-time retry alive even when a short-lived
child closes first, without inventing an identity or registering unowned work.
Five consecutive real Broker task/crash runs passed 2/2; the full regression
passes 457/458 with one explicit host-boundary/opt-in skip. Evidence:
`evidence/2026-09-14-process-identity-exit-window.md`.

Latest Virtualization.framework candidate addendum: the active Darwin 26.2
SDK exposes Virtualization.framework headers/modules, and the checked-in native
Objective-C probe links the framework, reports host support, and constructs an
intentionally invalid guest-less `VZVirtualMachineConfiguration`; Xcode is
absent, Swift compiler/SDK versions do not match, and no VM image or guest boot
was attempted. A disabled-by-default
`VirtualizationTaskRunner` seam now requires an externally reviewed guest
image SHA-256/runtime identity, a native-adapter executor, and a matching
identity recheck immediately before dispatch; missing or changed identity
fails closed, and adapter failures remain retryable `UNKNOWN_OUTCOME`. New
proof-validation, target-swap, and adapter-failure tests pass 8/8; the full
real-sandbox regression passes 463/464 with one explicit host-boundary/opt-in
skip. This is SDK and
boundary evidence only, not VM isolation or `mac_task_run` enablement.
Evidence: `evidence/2026-09-14-virtualization-framework-sdk.md`.

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

Latest real Broker network addendum: an opt-in Darwin integration sends a
signed `mac_task_run` request through a profile-owned loopback TCP allowlist.
The Broker fixes `/usr/bin/curl`, URL, empty environment, and no extra args;
the experimental sandbox reaches only the selected local fixture and returns
verified readback. Focused Broker tests pass 72/72, and the full
`MOPS_REAL_SANDBOX=1 npm test` suite passes 449/450 with one explicit
host-boundary/opt-in skip. Evidence:
`evidence/2026-09-14-real-broker-task-network.md`.

Latest task-volume identity addendum: the experimental task runner reads each
authorized filesystem root's native volume identity twice before launch, again
at process start, and after completion. A changed canonical root or volume ID
fails closed with `POLICY_DENIED` instead of publishing the child result.
Focused TaskProfile/runner/sandbox tests pass 20/20, and the real-sandbox suite
passes 449/450 with one explicit host-boundary/opt-in skip. This catches
remount or target replacement at the Broker execution boundary but does not
yet provide a kernel-held mount namespace or prevent a swap during child
syscalls. Evidence:
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

Latest task credential-policy addendum: versioned TaskProfiles now carry an
explicit `credentialPolicy`, and the only supported value is `none`. Registry
resolution, sandbox profile rendering, and isolation-proof admission all fail
closed on any future credential-bearing value, while process environments stay
explicit and allowlisted. Focused task-profile/runner/sandbox tests pass 17/17;
the current real-sandbox suite remains 445/446 with one explicit skip. This is
an enforceable Broker policy boundary, not proof of real credential-store
contents or production sandbox selection. Evidence:
`evidence/2026-09-14-task-credential-policy.md`.

Latest real process-kill-switch addendum: an opt-in Darwin Broker integration
flips the durable `process` kill switch while a real sandboxed task is active.
The control callback observes the switch, the ProcessSupervisor drains the
detached group, and Broker returns `CANCELLED` with an `unknown` Job. The full
`MOPS_REAL_SANDBOX=1 npm test` suite passes 445/446 with one explicit
host-boundary/opt-in skip; focused Broker tests pass 71/71. Evidence:
`evidence/2026-09-14-real-broker-task-kill-switch.md`.

Latest real active-revocation addendum: an opt-in Darwin Broker integration
revokes the session while a real sandboxed `/bin/sleep` task is running. The
ProcessSupervisor observes the authority loss, drains the detached process
group, returns `CANCELLED`, and the Broker keeps the Job `unknown` rather than
publishing success. The run records decision/intent/completion audit events.
The full `MOPS_REAL_SANDBOX=1 npm test` suite passes 444/445 with one explicit
host-boundary/opt-in skip; focused Broker tests pass 70/70. Evidence:
`evidence/2026-09-14-real-broker-task-revocation.md`.

Latest real Edge-revocation addendum: an opt-in Darwin Broker integration
revokes the authenticated Edge identity while a real sandboxed `/bin/sleep`
task is running. The active authority check observes the revocation,
ProcessSupervisor drains the detached process group, and Broker returns
`CANCELLED` while keeping the Job `unknown`; no late success is published.
The focused integration passes 1/1. Evidence:
`evidence/2026-09-14-real-broker-task-edge-revocation.md`.

Latest real Broker task-path addendum: an opt-in Darwin integration now
exercises the signed `mac_task_run` request through Broker policy admission,
single-use approval, Job creation, `SandboxExecTaskRunner`, and verified
completion/readback. `MOPS_REAL_SANDBOX=1 npm test` passes 443/444 with one
explicit host-boundary/opt-in skip; the focused Broker suite passes 69/69. The
default policy and production task capability remain disabled while MOP-086
still lacks the required credential, remount, crash-attribution, and
production-boundary evidence. Evidence:
`evidence/2026-09-14-real-broker-task-path.md`.

Latest process-supervisor lifecycle addendum: active runs are now registered
before the first ownership observation. A synchronous persistence failure can
therefore terminate and remove its run without leaving a close-time ghost
entry. The focused Darwin process-supervisor suite passes 14/14, including
capacity release and close idempotency. Evidence:
`evidence/2026-09-14-process-supervisor-registration.md`.

Latest bounded-Git-log addendum: `mac_git_log` now preserves complete commit
records from a supervisor-confirmed output prefix, marks the result truncated,
and rejects output-limit reports without observed termination as retryable
`UNKNOWN_OUTCOME`. Focused Git tests pass 17/17. Evidence:
`evidence/2026-09-14-git-log-output-budget.md`.

Latest bounded-log addendum: `mac_log_tail` now preserves a safe, redacted
prefix when the Broker-owned process supervisor reaches its fixed 512 KiB
output cap. The adapter exposes `truncated: true` and an explicit warning only
after process termination has been observed; an unresolved supervisor outcome
still fails closed as `UNKNOWN_OUTCOME`. Focused log tests pass 5/5, and the
latest Darwin real-sandbox suite passes 442/442 with one explicit skip.
Evidence: `evidence/2026-09-14-log-output-budget.md`.

Latest bounded-write addendum: `mac_apply_patch` is now implemented behind a
disabled-by-default `mac.files.write` + `mac.project.write` policy gate. The
Broker owns a textual patch parser with project-relative path checks, fixed
file/count/byte limits, secret-content denial, expected-base hashing,
descriptor-relative atomic writes, identity preconditions, rollback, and
conservative UNKNOWN outcomes. The worker protocol, Broker Job lifecycle,
approval/audit binding, and readback result validation are wired end to end;
focused Broker and filesystem tests pass. Evidence:
`evidence/2026-09-14-bounded-patch.md`. Contract enablement, remount and
crash attribution evidence, and production release gates remain open.

## Current situation

Latest transport addendum: commit `18e9103` adds a Darwin-only cross-process
HTTPS smoke. A separately spawned Edge process loads the compiled Edge package,
protected authentication key, contracts, TLS material, and local JWT verifier;
the parent native Broker binds the child by exact UID/GID and PID/start-time.
The official MCP client completes version negotiation and `mac_health`, while
the Broker audit ledger excludes the bearer token. This extends the earlier
same-process HTTPS/native-UDS evidence but remains a temporary process fixture;
launchd installation/readback, Developer ID/notarization, remote OAuth/JWKS,
and production key rotation remain open. Evidence:
`evidence/2026-09-14-separate-edge-process.md`.

Latest packaging-shape addendum: commit `576038e` adds a reviewable
`com.mac-operator.edge.plist.in` to the macOS packaging boundary alongside the
Broker template. The
documented order is Edge launchd identity/readback first, Broker startup second,
and reverse order for authority-disabled uninstall. A template regression test
keeps both agents free of shell, environment, user, and privileged launchd
fields. This is a packaging artifact and static boundary check; it does not
claim persistent installation, signing provenance, or remote deployment.

Latest packaged-service host addendum: the opt-in Darwin smoke now copies the
compiled Edge/Broker packages and runtime dependencies into an isolated
temporary root, bootstraps the real Edge LaunchAgent before Broker, verifies
the exact launchd argument vectors, Edge TLS listener, native/status socket
ownership and mode, HMAC Broker status, native PID identity, and empty
capability readback, then bootouts both labels and verifies absence. The smoke
is gated by `MOPS_REAL_INSTALL=1` and refuses to run when either fixed label is
already loaded. This is temporary host evidence, not production signing or
persistent installation. Evidence:
`evidence/2026-09-14-packaged-edge-broker-launchd.md`.

Latest component-plan addendum: the packaging boundary now exposes separate
`buildMacOsEdgeInstallPlan` and `buildMacOsInstallPlan` contracts. Edge plans
bind the exact Edge label and expected listener, while Edge readback is
composed from independently sampled launchd, PID/start-time, plist, signature,
and process-owned listener sources; Broker plans retain their native transport
and capability checks. Both host-only executors require exact operation
confirmation and existing-service preconditions before atomic plist mutation,
and Edge has no Broker-status fallback. Focused and full tests cover listener
substitution, target swaps, and pre-confirmation rejection. Production signed
artifacts, unattended installer authorization, and upgrade/rollback evidence
remain open.

Latest repository-quality addendum: the current change adds `npm run lint`, a
dependency-free checker over the tracked source/document surface for CRLF,
trailing whitespace, missing final newlines, and non-regular tracked inputs.
CI runs it before typecheck and test; it does not execute repository scripts or
inspect ignored build artifacts. Local style, typecheck, contract, audit, and
full-test checks pass; first remote CI execution remains unverified.

Latest real-sandbox addendum: `MOPS_REAL_SANDBOX=1 npm test` passed 430/430
with one explicit non-sandbox skip on the current Darwin arm64 host. The three
real sandbox runner checks exercised environment/credential-surface denial,
single-process fork/setsid and external-network denial, selected loopback
allowlisting, and active process-group cancellation. This strengthens host
evidence but does not select deprecated `sandbox-exec`; credential contents,
post-snapshot descendants, remounts, and production task enablement remain
open. Evidence: `evidence/2026-09-14-real-sandbox-regression.md`.

Latest isolation-proof hardening: `TaskIsolationProof` now binds an explicit
`sandboxMechanism` (`sandbox-exec` for the experimental runner) in addition to
the profile and process-tree policy. Validation rejects unknown mechanisms, so
future App Sandbox or Virtualization evidence cannot be reused accidentally by
the deprecated runner. The `TaskRunner` also declares its host mechanism, and
Broker admission/dispatch reject missing or mismatched declarations before
approval consumption or process launch. The runner remains opt-in and
unavailable by default.

Current committed implementation baseline: install-plan raw-readback hardening.

The current install-plan readback hardening adds a raw-source observer boundary:
`executeMacOsInstallPlan` no longer accepts a caller-preassembled final
`MacOsInstallReadback`. A production-shaped host observer reads bounded
launchd/codesign data, native PID/start-time identity, descriptor-backed plist
identity, and a Broker-owned status source; collection waits through transient
`launching`, double-reads mutable identities, and composes the final readback
inside the executor. A physical-Mac temporary package smoke starts the real
zero-capability Broker assembly under LaunchAgent, verifies running readback,
and completes exact uninstall. Ad-hoc signing, production status-channel
binding, Developer ID/notarization, remote Edge, upgrade/rollback, and helper
installation remain open. Evidence:
`evidence/2026-09-14-live-install-plan.md`.

The latest privileged-helper host-adapter addendum is `a3d7765`: the
production-shaped observer now wires bounded `launchctl print`, native
PID/start-time capture, descriptor-backed plist readback, and strict bounded
`codesign` verification/details parsing. Helper runtime metadata remains an
explicit helper-owned source; no root service is installed. The full suite
passes 397 tests (394 passed, 3 opt-in sandbox tests skipped). Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

The latest privileged-helper observer addendum is `30b69df`: the host-only
observer reads launchd, PID/start-time, and plist identities twice and rejects
service/process/target replacement during collection before composing helper
readback. The injected observer fixture passes stable success and PID-swap
failure cases; no root service is installed. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

The latest privileged-helper executor addendum is `56ab0ca`: the host-only
lifecycle executor now accepts only raw readback sources and invokes
`composePrivilegedHelperPackageReadback` internally. A caller cannot bypass
independent launchd/process/plist/signature checks by supplying a preassembled
package readback. Root-owned installation and live LaunchDaemon evidence remain
open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

The latest privileged-helper source-composition addendum is `1405b99`:
`composePrivilegedHelperPackageReadback` accepts only independently observed
launchd, native process, plist, helper-runtime, and code-signature sources. It
requires the exact `system/com.mac-operator.privileged-helper` service ID,
LaunchDaemon type, running state, PID, native argv, plist path, and
process-identity binding before constructing the final readback. Caller-built
plan fields are not treated as raw launchd evidence. Real root installation
and live LaunchDaemon evidence remain open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

The latest privileged-helper plist addendum is `d3efae1`: final helper
readback now requires the exact root-domain plist path, rendered byte count,
SHA-256, and descriptor device/inode identity. The host-only reader uses the
Broker filesystem inspector with no caller-supplied path or inspector, and
tampered/truncated content fails closed. Root-owned installation and live
LaunchDaemon readback remain open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

The latest privileged-helper identity addendum is `cc103a7`: an installed
helper readback must now provide a positive launchd PID plus a matching native
PID/start-time identity. Missing, null, reused, or zero start-time identities
fail closed before helper readiness is reported. This remains a non-installing
boundary; root-owned launchd installation and final helper evidence remain
open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

The latest privileged-helper readback addendum is `8fd5814`: the root-domain
LaunchDaemon readback now carries and exactly matches the planned
`ProgramArguments` array, so an otherwise matching helper cannot substitute a
different executable argument vector. The negative readback test rejects an
attacker-supplied extra argument. This remains a non-installing boundary; real
root-owned launchd installation and final helper readback remain open.
Evidence: `evidence/2026-09-13-privileged-helper-readback-arguments.md`.

The latest exact-arguments readback addendum is `9d90138`: bounded launchd
readback now parses an optional `arguments` block, and Broker installation
composition requires the exact planned Node binary plus JavaScript entrypoint.
Missing, malformed, oversized, incomplete, or substituted arguments fail
closed, while generic system-service readback remains compatible when launchd
omits arguments. The final plist identity/digest check remains in force. This
is still a non-installing boundary; real LaunchAgent bootstrap and final host
evidence remain open. Evidence:
`evidence/2026-09-13-installed-readback-identity.md`.

The latest final-plist-readback addendum is `70ca1e9`: the installed-service
readback now requires a descriptor-backed plist path, device/inode identity,
byte count, and SHA-256 matching the exact rendered plan. The protected
filesystem reader rejects truncation, target changes, and tampered content,
including macOS `/var` to `/private/var` canonicalization. This remains a
non-installing boundary; real LaunchAgent bootstrap and final host evidence
remain open. Evidence:
`evidence/2026-09-13-installed-readback-identity.md`.

The latest verified-launchd-readback addendum is `4cb4e1a`: the installer now
has a composition function that binds the bounded `launchctl print` service ID,
per-user domain, LaunchAgent type, running state, PID, program, and plist path
to the same native PID/start-time identity before validating Broker metadata and
code-signature readback. The composition layer never installs or bootstraps a
service; real LaunchAgent installation and final host readback remain open.
Evidence: `evidence/2026-09-13-installed-readback-identity.md`.

The latest installer-readback addendum is `6da24f6`: post-bootstrap Broker
readback now requires a positive launchd PID bound to the same native Darwin
PID/start-time identity. Missing, malformed, mismatched, or non-positive
process identities fail closed before install/upgrade/rollback readiness is
reported. This strengthens the planned installer boundary but does not claim a
real LaunchAgent installation or bootstrap; that host evidence remains open.
Evidence: `evidence/2026-09-13-installed-readback-identity.md`.

The latest Broker startup-serialization addendum is `0c34c65`: packaged
service startup now holds an owner-only runtime-root instance lock containing
the exact PID/start-time identity before socket preflight, BrokerStore open, or
restart recovery. Duplicate live owners are rejected; stale locks are
reclaimed only after exact identity observation proves the owner is gone, and
observer uncertainty or target replacement fails closed. Normal and failed
startup cleanup paths release the lock after Broker/store disposal. The default
suite passes 394 tests (391 passed, 3 opt-in sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 394/394. Launchd installation/bootstrap,
non-cooperating-process kernel locking, and physical crash/remount evidence
remain open. Evidence:
`evidence/2026-09-13-service-instance-lock.md`.

The latest IPC ownership-hardening addendum is `44cae6a`: all local Unix IPC
servers now probe existing socket paths before stale cleanup, bind close to a
recorded device/inode identity, and use a temporary symlink barrier around
generic Node listener shutdown. Broker service assembly performs the active
socket preflight before opening the Job Ledger or reconciling restart-unknown
work. Active-listener refusal, startup preflight, replacement-listener close
fencing, native IPC, and authenticated operator-channel tests pass; the
default suite passes 390 tests (387 passed, 3 opt-in sandbox tests skipped),
and `MOPS_REAL_SANDBOX=1 npm test` passes 390/390. This does not prove
installed launchd singleton enforcement, a kernel lock against arbitrary
non-cooperating processes, or physical crash/remount behavior. Evidence:
`evidence/2026-09-13-ipc-socket-ownership.md`.

The latest Broker startup-recovery wiring addendum is `9c96605`: the packaged
service assembly now reconciles restart-unknown task processes and write
artifacts before native IPC runtime startup, so no listener is exposed while
the bounded recovery pass is pending. Failed assembly and disposal-before-
start paths close Broker-owned resources before key and store disposal. The
default suite remains 387 tests (384 passed, 3 opt-in sandbox tests skipped),
and the native service-startup boundary remains covered on the supported Mac
profile. This does not prove installed launchd singleton enforcement,
stale-socket ownership fencing, post-snapshot descendant cleanup, credential
isolation, or production task-runner enablement. Evidence:
`evidence/2026-09-13-startup-recovery-wiring.md`.

The latest Broker restart-recovery addendum is `a20fed7`: task Jobs now retain
bounded non-secret PID/process-group/start-time identities for the root and
observed descendants after process start. The host-startup hook
`reconcileRestartedTaskProcesses()` selects only restart-reconciled `UNKNOWN`
Jobs. A new Broker verifies exact Darwin identities before terminating the
process tree; PID/start-time substitution is rejected, observed detached
descendants can be recovered after root exit, an empty post-exit snapshot stays
unresolved rather than claiming absence, recovery is audited, and the Job
never becomes success. The cross-Broker real-process fixture and process-tree
fail-closed fixtures pass, the default suite passes 387 tests (384 passed, 3
opt-in sandbox tests skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes
387/387. This proves controlled
restart recovery for observed identities, not recovery of descendants created
after the last snapshot, post-snapshot `setsid` resistance, credential
isolation, or production task-runner enablement. Evidence:
`evidence/2026-09-13-task-process-recovery.md`.

The latest child-process environment addendum is `e9d8570`: a shared
environment-key policy rejects secret-shaped, interpreter-loader, command
resolution, temporary-directory, and Git/Docker configuration injection keys
for task profiles. The lower-level Supervisor permits only the exact fixed
Git/Docker adapter keys, preserving those adapters without allowing arbitrary
`GIT_*` or `DOCKER_*` names. Negative tests cover `PATH` and `NODE_OPTIONS`,
and the full real-Mac suite remains 387/387. This closes environment
construction and injection control, not real Keychain/credential-content
isolation or production task-runner enablement. Evidence:
`evidence/2026-09-13-process-environment-boundary.md`.

The latest Broker OS-process ownership addendum is `1a8b0cc`: default
launchd, log, Git, Docker, app, and UI adapters now receive one Broker-owned
`ProcessSupervisor` with a union of explicit non-secret environment keys and a
bounded shared concurrency limit. `Broker.close()` drains this supervisor in
addition to worker executors and the task runner. The integration close test
passes; the opt-in host regression passes 381/381. This closes live Broker
shutdown ownership for these adapter processes, not ownership after a crashed
Broker or evidence for production task-runner enablement. Evidence:
`evidence/2026-09-13-broker-process-ownership.md`.

The latest OS-process lifecycle addendum is `889ccdf`: `ProcessSupervisor`
now owns an explicit close boundary that stops new admissions, cancels every
active process group, waits for tracked process-tree drain, and preserves
`UNKNOWN_OUTCOME` when termination cannot be observed. `SandboxExecTaskRunner`
forwards that boundary and `Broker.close()` drains it after transport shutdown.
The default task runner remains disabled, and the `owned_group` profile remains
unavailable. The focused close tests pass; the default suite passes 381 tests
(378 passed, 3 opt-in sandbox tests skipped), while
`MOPS_REAL_SANDBOX=1 npm test` passes 381/381. This proves graceful shutdown of
live Broker-owned OS task processes, not ownership after a crashed Broker,
post-snapshot `setsid` escape resistance, credential isolation, or production
task-runner enablement. Evidence:
`evidence/2026-09-13-process-supervisor-close.md`.

The latest cross-Broker stale-completion addendum is `f2ce163`: an actual
`Broker.handle` write is held in `running`, a second `BrokerStore` reopen
reconciles it to `UNKNOWN`, and the prior Broker's delayed worker result is
rejected rather than published as success. The restarted Broker reads the Job
as `UNKNOWN`. Focused Broker tests pass 64/64; the full suite passes 378 tests
(375 passed, 3 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 378/378. This proves persisted Job
lease/revision fencing across BrokerStore reopen, not OS-process ownership or
proof that a crashed Broker's old worker has exited. Evidence:
`evidence/2026-09-13-stale-broker-completion.md`.

The latest Broker worker-lifecycle addendum is `84f4991`: `BoundedWorkerExecutor`
now owns its active Worker set, rejects new work after close, terminates and
waits for owned workers, and releases capacity from the Worker exit event.
`WorkerFilesystemExecutor` and `WorkerProcessExecutor` expose that close
boundary; `Broker.close()` fences new requests and active completion checks;
`LocalBrokerRuntime` closes transport channels before Broker resources. The
focused lifecycle tests pass, and the real-Mac full suite passes 377/377.
This proves graceful in-process worker drain, not OS-process ownership after a
crashed Broker or complete restart fencing. Evidence:
`evidence/2026-09-13-broker-worker-shutdown.md`.

The latest worker-crash addendum is `61b0865`: a test-only filesystem worker
performs a real atomic write and then exits without returning a result. The
Broker maps the abrupt worker exit to `EXECUTION_FAILED`, preserves the Job as
`UNKNOWN`, and `mac_job_status` reports `matches / remains_unknown`; a separate
executor test proves the capacity slot is released only after the worker exits
and the next request can run. Production construction remains fixed to
`filesystem-worker.js`. This proves worker-thread crash ambiguity and capacity
recovery, not Broker-process restart fencing or OS-process ownership. Evidence:
`evidence/2026-09-13-worker-crash-unknown.md`.

The latest sandbox hostile-descendant addendum is `01a26ba`: the opt-in
real-Mac `single_process` profile runs a Broker-resolved `/usr/bin/perl`
fixture that attempts `fork()` followed by `setsid()` and a marker write. The
host returns `fork-denied` with a non-success result and leaves no marker in
the temporary root. The focused sandbox suite passes 8/8; the complete
`MOPS_REAL_SANDBOX=1 npm test` regression passes 373/373. This strengthens
no-fork evidence only; owned-group enforcement, post-snapshot session escape,
crash/restart cleanup, credential contents, persistence, and production task
runner enablement remain open. Evidence:
`evidence/2026-09-13-sandbox-hostile-descendant.md`.

The latest Broker real-worker post-rename addendum is `42268d2`: a controlled
test-only worker URL and fault native adapter drive a real descriptor-relative
write through `WorkerFilesystemExecutor`, inject `ENOSPC` after rename before
parent `fsync`, and verify the target is committed while the worker fails.
Broker preserves the mutation Job as `UNKNOWN`; `mac_job_status` reads
`matches / remains_unknown`. The production default worker/native paths remain
fixed. Focused Broker tests pass 62/62; the full suite passes 372 tests (370
passed, 2 opt-in real-sandbox tests skipped). `MOPS_REAL_SANDBOX=1 npm test`
passes 372/372. Physical disk-full, remount, kernel-blocked I/O, and
Broker-process restart fencing remain open. Evidence:
`evidence/2026-09-13-broker-worker-post-rename.md`.

The latest Broker real-worker write-failure addendum is `2371eba`: a real
`WorkerFilesystemExecutor` fails to create a temporary file under a
read-only parent after policy authorization and plan capture. Broker returns a
stable failure, persists the mutation Job as `UNKNOWN`, leaves the target
absent, and `mac_job_status` reads `unavailable / remains_unknown`. Focused
Broker tests pass 61/61; the full suite passes 371 tests (369 passed, 2
opt-in real-sandbox tests skipped). `MOPS_REAL_SANDBOX=1 npm test` passes
371/371. Post-rename failure through the real worker, physical disk-full,
kernel-blocked I/O, Broker-process restart fencing, and remount evidence remain open.
Evidence: `evidence/2026-09-13-broker-worker-write-failure.md`.

The latest current-revision sandbox readback is `4d18b31`: the opt-in
`SandboxExecTaskRunner` smoke passes 7/7 on the Mac mini M4, and the complete
`MOPS_REAL_SANDBOX=1 npm test` regression passes 370/370. The run remains
temporary-fixture evidence only; credential contents, hostile descendants,
crash/restart cleanup, persistence, Docker/privilege isolation, external
allowlisted networking, and remount behavior remain unproven. The default task
runner and `mac_task_run` remain disabled. Evidence:
`evidence/2026-09-13-sandbox-profile-rerun.md`.

The latest macOS volume-inventory addendum is `92137e2`: read-only `diskutil
list`, `mount`, `/Volumes`, and `df -P` readback shows only the internal APFS
layout and the system `Macintosh HD -> /` alias; no removable, network, or
secondary user volume is mounted for a remount exercise. No mount, unmount,
erase, repartition, or write operation was performed. Physical/removable
remount evidence remains open because the required disposable target is absent.
Evidence: `evidence/2026-09-13-volume-inventory.md`.

The latest atomic-write post-commit-error addendum is `93eeaf8`: the
fault-test-only native module injects `ENOSPC` after atomic rename and before
parent-directory `fsync`. The target contains the new bytes, the temporary
artifact is absent, and the call fails non-zero, modelling the ambiguous
post-commit window that must remain `UNKNOWN`. Focused filesystem tests pass
31/31; the full suite passes 370 tests (368 passed, 2 opt-in real-sandbox
tests skipped). `MOPS_REAL_SANDBOX=1 npm test` passes 370/370. Physical
disk-full, remount, kernel-blocked I/O, and restart evidence remain open.
Evidence: `evidence/2026-09-13-write-post-commit-error.md`.

The latest atomic-write storage-error addendum is `0ac3e15`: the fault-test
native module can deterministically inject `ENOSPC` at temporary-file write and
`fsync` boundaries. Create and replace fixtures fail non-zero, preserve the
prior target state, and remove the exact temporary artifact; the production
native module does not expose the injection hook. Focused filesystem tests pass
31/31; the full suite passes 370 tests (368 passed, 2 opt-in real-sandbox
tests skipped). `MOPS_REAL_SANDBOX=1 npm test` has the same two
environment-gated skips. This is error-path evidence, not physical disk-full,
remount, kernel-blocked I/O, or restart-recovery evidence. Evidence:
`evidence/2026-09-13-write-storage-error.md`.

The latest filesystem-worker concurrency addendum is `df4ba85`: a real
`WorkerFilesystemExecutor` fixture authorizes two independent roots, performs
a bounded multi-root search, rejects an overlapping request at the fixed
concurrency cap, and verifies capacity recovery after worker exit. A separate
worker-executor test proves active cancellation returns `CANCELLED` before the
slot is released and that a later request succeeds only after termination.
Focused filesystem/worker tests pass 36/36; the full suite passes 369 tests
(367 passed, 2 opt-in real-sandbox tests skipped). `MOPS_REAL_SANDBOX=1 npm
test` has the same two environment-gated skips. Production-scale exhaustion,
kernel-blocked I/O interruption, restart recovery, and process isolation
remain open. Evidence:
`evidence/2026-09-13-filesystem-worker-concurrency.md`.

The latest filesystem pressure-budget addendum is `9d6d6b0`: a bounded fixture
creates 600 temporary files and verifies 500-entry listing pagination,
128-entry tree truncation, 100-result metadata/text search truncation, and
oversized argument rejection. Focused filesystem tests pass 30/30; the full
suite passes 367 tests (365 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 367/367. Evidence:
`evidence/2026-09-13-filesystem-pressure-budgets.md`.

The latest character/block-device addendum is `8fbd148`: the real-host
negative fixture rejects `/dev/null`, `/dev/tty`, `/dev/random`, and the
available `/dev/disk0` block device at the local-volume boundary without
reading device bytes. Focused filesystem tests remain 29/29; the full suite
passes 366 tests (364 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 366/366. Evidence:
`evidence/2026-09-13-character-block-device-boundary.md`.

The latest special-file hardening addendum is `7a136ef`: native metadata,
content-read, and hash opens use `O_NONBLOCK`, so an untrusted FIFO cannot
stall the Broker; FIFO metadata is `other`, generic content/hash/write fail
closed, and `/dev/null`/`/dev` volume crossings are denied. Focused filesystem
tests pass 29/29; the full suite passes 366 tests (364 passed, 2 opt-in
real-sandbox tests skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes 366/366.
Evidence: `evidence/2026-09-13-special-file-hardening.md`.

The latest special-file boundary addendum is `cd74420`: a disposable
Unix-domain socket is returned only as bounded `other` metadata and generic
content-read, hash, and atomic-write attempts fail closed. Focused filesystem
tests pass 28/28; the full suite passes 365 tests (363 passed, 2 opt-in
real-sandbox tests skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes 365/365.
FIFO/device/pseudo-filesystem coverage remains open and no production adapter
was enabled. Evidence:
`evidence/2026-09-13-special-file-boundary.md`.

The latest filesystem volume-identity addendum is `1807ebc`: every
`FilesystemPathPlan` now binds the native canonical root and volume identity at
authorization, checks it before and after metadata/read/hash/list/write/unlink
operations, and the native adapter compares target/parent `f_fsid` and
filesystem type in addition to `st_dev`. Focused filesystem/native tests pass
33/33; the full suite passes 364 tests (362 passed, 2 opt-in real-sandbox tests
skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes 364/364. No volume was
unmounted or mounted and no capability was enabled. Evidence:
`evidence/2026-09-13-filesystem-volume-identity.md`.

The latest filesystem canonicalization addendum is `a742fbc`: a temporary
adversarial fixture proves that lexical containment rejects case-altered root
aliases, while metadata search matches decomposed Unicode queries against
composed filenames using the existing NFKC/lowercase key and verifies the
native canonical return path. Focused filesystem tests pass 26/26; the full
suite passes 363 tests (361 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 363/363. No protected content, service,
policy, or capability state was changed. Evidence:
`evidence/2026-09-13-filesystem-canonicalization.md`.

The latest secret-zone/redaction addendum is `0bcd893`: Broker content policy
now denies full `.docker` state, GitHub CLI state, browser application data,
and containerized macOS Mail/Messages/Safari paths, while evidence redaction
handles `/private/var/root`, paths containing spaces, Bearer/Basic credentials,
and JWT-shaped values. Focused policy tests pass 4/4; the full suite passes 362
tests (360 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 362/362. No credential/private-data
content was opened and no capability was enabled. Evidence:
`evidence/2026-09-13-secret-zone-redaction.md`.

The latest L0/L1 host-readback addendum is `b7ea5fb`: a macOS-only,
read-only test now observes bounded system facts, interface state without
active probes or listener enumeration, redacted process metadata/current
process identity, canonical `/System/Library` metadata/list/tree output, and
depth-limited APFS volume/capacity readback with content reads disabled and
protected relative zones denied. It performs
no mutation, child launch, credential read, policy change, or service install.
The focused host test passes 1/1; the full suite passes 362 tests (360 passed,
2 opt-in real-sandbox tests skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes
362/362. A one-second JWT test assertion race found during the real-host run
was fixed by binding the expected expiry second to the signed token input.
Evidence: `evidence/2026-09-13-l0-l1-host-readback.md`.

The experimental sandbox boundary was rerun from source `b7ea5fb`: the
focused opt-in real-Mac smoke passes 7/7 and `MOPS_REAL_SANDBOX=1 npm test`
passes 362/362. This refresh confirms the existing partial environment,
temporary-root, selected-loopback, credential-surface, child-launch, and
cancellation observations but does not prove credential contents,
descendant/`setsid` ownership, remount/crash/restart cleanup, persistence,
Docker, or production isolation; `mac_task_run` remains blocked. Evidence:
`evidence/2026-09-13-sandbox-profile-runner.md`.

The latest governed HTTPS Edge service-entrypoint addendum is `0e8612d`:
the packaged Edge now has a fixed `service-main.js` and strict owner-only
`edge-service.json` loader. Startup binds canonical package/data/runtime roots,
protected TLS and digest-bound Edge HMAC files, the contract directory, fixed
HTTPS/OAuth/JWKS/IPC/rate-limit budgets, and a Broker gateway without accepting
MCP arguments or ambient environment authority. Listener host/port readback is
required before readiness; shutdown wipes HMAC/TLS buffers. Focused startup
tests pass 3/3, the full suite passes 361 tests (359 passed, 2 opt-in
real-sandbox tests skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes 361/361.
No LaunchAgent, public listener, production credential, or Keychain item was
used. Evidence: `evidence/2026-09-13-governed-edge-service-entrypoint.md`.

The latest governed service-entrypoint addendum is `8ac5fe0`: the packaged
Broker now has a fixed `service-main.js` entrypoint and strict owner-only
`broker-service.json` loader. Startup restores the exact persisted signed
Policy and Edge-key activations, checks that policy trusts the configured Edge,
captures the launchd Edge PID/start-time identity, and only then constructs the
native Broker runtime. Package/data/runtime roots and every state path are
canonical and root-bound; startup closes by wiping loaded Edge keys. Focused
startup tests pass 3/3, the full suite passes 358 tests (356 passed, 2 opt-in
real-sandbox tests skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes 358/358.
No live LaunchAgent state was changed. Evidence:
`evidence/2026-09-13-governed-broker-service-entrypoint.md`.

The latest packaged-process/readback addendum is `018565d`: a bounded,
read-only `/bin/launchctl print` adapter now validates service identity, state,
PID, canonical paths, type, and exit code, with a real Mac smoke against
`system/com.apple.logd`. A second native IPC smoke starts Broker and Edge as
separate package processes; the Broker captures the Edge PID/start-time before
listening, while the Edge signs and verifies a complete `mac_health` round
trip. The focused readback/IPC suite passes 11/11, the full suite passes 354
tests (352 passed, 2 opt-in real-sandbox tests skipped), and
`MOPS_REAL_SANDBOX=1 npm test` passes 354/354. This remains local evidence;
launchd installation, production signing, Keychain ACLs, and live upgrade or
rollback are not proven. Evidence:
`evidence/2026-09-13-packaged-process-and-launchd-readback.md`.

The latest native process-boundary addendum is `511f8a6`: a real separately
spawned Node Edge fixture now signs a `mac_health` request, connects across the
native Unix-domain socket, verifies the complete Broker response proof, and is
accepted only under the captured macOS PID/start-time identity. The fixture
uses an explicit `/` working directory, a minimal environment, and a temporary
owner-only key file; the peer-loss case remains covered. The focused native IPC
suite passes 7/7, the full suite passes 350 tests (348 passed, 2 opt-in
real-sandbox tests skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes 350/350.
This remains local process-boundary evidence: installed launchd packaging,
signed production binaries, Keychain distribution, and remote deployment are
not proven. Evidence: `evidence/2026-09-13-native-edge-process-boundary.md`.

The latest local layered Edge/Broker addendum is `1fecf5b`: a real RS256
JWT-authenticated MCP client now reaches the Broker through the signed,
peer-checked local UDS, discovers only the scope- and policy-enabled
`mac_capabilities`/`mac_health` tools, and receives a verified `mac_health`
success response. The full suite passes 350 tests (348 passed, 2 opt-in
real-sandbox tests skipped), and `MOPS_REAL_SANDBOX=1 npm test` passes 350/350
on the current host. This remains temporary local evidence; no
installed service, public endpoint, mutation, or production credential was
used. Evidence:
`evidence/2026-09-13-edge-broker-https-e2e.md`.

The latest helper package execution addendum is `eb9ee6a`: the host-only
executor now consumes the fixed lifecycle plan, defaults to the bounded
`ProcessSupervisor`, requires the real current UID to be root before any
command/filesystem/readback access, and runs operation-specific recovery when
bootstrap or final readback fails. Root-domain success remains unverified;
the default suite passes 349 tests (347 passed, 2 opt-in real-sandbox tests
skipped), and the opt-in real-Mac suite passes 349/349. Evidence:
`evidence/2026-09-13-privileged-helper-package-boundary.md`.

The latest helper lifecycle addendum is `3d5d257`: a host-only dry-run
execution contract now validates the exact existing service revision and fixes
the install/upgrade/rollback/uninstall step order, including signature
verification, bootout/bootstrap, plist action, final readback, and recovery
steps. It is a plan-only boundary; no launchctl command or root mutation is
executed. The default full suite passes 348 tests (346 passed, 2 opt-in
real-sandbox tests skipped). Evidence:
`evidence/2026-09-13-privileged-helper-package-boundary.md`.

The latest helper apply hardening is `c8dcb2c`: host-only plist mutation now
checks the real current process UID in addition to the caller-supplied root
identity, so a non-root process cannot forge `ownerUid: 0`. The rejection is
tested before any helper filesystem preflight, and the writer is pinned to the
internal root filesystem inspector rather than caller-injected state. The
default full suite passes
347 tests (345 passed, 2 opt-in real-sandbox tests skipped); the real-Mac
opt-in suite passes 347/347. Evidence:
`evidence/2026-09-13-privileged-helper-package-boundary.md`.

The latest real-Mac sandbox readback was rerun from `eb9ee6a` with
`MOPS_REAL_SANDBOX=1`: both opt-in sandbox tests passed, and the full suite
passed 349/349 with no skipped tests. The smoke remains synthetic and
disabled-by-default; it does not establish real credential/persistence
isolation, descendant/`setsid` ownership, remount safety, or a production
replacement for deprecated `sandbox-exec`. `mac_task_run` remains disabled.
Evidence: `evidence/2026-09-13-sandbox-profile-runner.md`.

The latest helper caller-boundary addendum is `7a4a788`: a real macOS
cross-process test starts a separately spawned Broker fixture, captures its
native PID/start-time identity before helper construction, proves the bound
caller reaches the helper parser, and proves a second spawned caller is
dropped before parsing. The test uses a temporary socket only; it installs no
launchd service and starts no root process. The full suite passes 346 tests
(344 passed, 2 opt-in real-sandbox tests skipped). Evidence:
`evidence/2026-09-13-privileged-helper-native-caller.md`.

The latest helper-plist apply addendum is `4afbe75`: the root-domain package
now exposes a host-only, explicitly confirmed descriptor-relative plist
apply/upgrade/rollback/uninstall primitive backed by the native filesystem
writer, exact device/inode preconditions, and restoration on failed upgrade or
uninstall. It rejects non-root callers before filesystem access and never runs
launchctl. Successful root-owned host execution remains unverified. The full
suite passes 345 tests (343 passed, 2 opt-in real-sandbox tests skipped).
Evidence: `evidence/2026-09-13-privileged-helper-package-boundary.md`.

The latest helper-key lifecycle addendum is `72a3284`: already-constructed
helper factories and IPC servers now recheck helper-key revocation, active
revision/digest identity, and validity windows before issue, parse, or
authorization. Expiry and activation replacement fence old key owners without
relying on a restart. The full suite remains 344 tests (342 passed, 2 opt-in
real-sandbox tests skipped). Evidence:
`evidence/2026-09-13-privileged-helper-key-lifecycle.md`.

The latest helper-filesystem addendum is `7f8f285`: the package boundary now
has a read-only root-owned preflight with double `lstat`, symlink/type/mode/
owner checks, device/inode stability, owner-only helper-key/plist files, and
owner-executable native helper validation. This remains preflight evidence;
descriptor-relative installation and real root-owned package readback remain
open. The full suite passes 344 tests (342 passed, 2 opt-in real-sandbox tests
skipped). Evidence: `evidence/2026-09-13-privileged-helper-package-boundary.md`.

The latest helper-signature addendum is `4bdcf94`: on the real macOS host,
the package test now builds a temporary helper bundle, runs the fixed
`/usr/bin/codesign` ad-hoc signing command, verifies the exact plan command,
and reads back `com.mac-operator.privileged-helper`. This is temporary
ad-hoc evidence only; Developer ID provenance, notarization, installation,
and root-domain readback remain open. The full suite passes 343 tests (341
passed, 2 opt-in real-sandbox tests skipped). Evidence:
`evidence/2026-09-13-privileged-helper-package-boundary.md`.

The latest helper-caller addendum is `7af182e`: helper startup can now derive
the caller from the exact per-user `gui/<uid>/com.mac-operator.broker`
LaunchAgent readback, use fixed empty-environment `launchctl print`, and bind
the returned PID to native start-time identity before constructing the helper.
Service-label smuggling and non-running readbacks fail closed. The full suite
passes 342 tests (340 passed, 2 opt-in real-sandbox tests skipped). No launchd
mutation or root process was run. Evidence:
`evidence/2026-09-13-privileged-helper-caller-identity.md`.

The latest helper-package addendum is `e0c1e17`: a separate non-executing
system LaunchDaemon plan now fixes the helper label/domain, native-only argv,
root-owned plist actions, exact helper signature identity, protected helper
root/key/socket paths, Broker peer UID/GID binding, and exact upgrade/rollback/
uninstall commands. Readback rejects an enabled adapter or any capability
advertisement. This is packaging-boundary evidence only; no launchd mutation,
root process, signing, or privileged action was performed. The full suite
passes 341 tests (339 passed, 2 opt-in real-sandbox tests skipped). Evidence:
`evidence/2026-09-13-privileged-helper-package-boundary.md`.

The latest helper-runtime addendum is `12a1ac3`: an independent helper
runtime now restores the exact active `helper_key` configuration before
constructing the separately authenticated listener, requires a native peer
process identity, rejects socket reuse with the Broker/control channels, and
owns serialized start/close rollback. The default adapter remains
fail-closed; no root process or privileged operation is started. The full
suite passes 337 tests (335 passed, 2 opt-in real-sandbox tests skipped).
Evidence: `evidence/2026-09-13-privileged-helper-runtime.md`.

The latest helper-key addendum is `d91d406`: helper factories now recheck
key-specific `helper_key` revocation at issue/authorization time, so revoking
an activated key fences already-constructed helper command paths. The full
suite remains green; no privileged operation is enabled.

The latest privileged-helper key addendum is `afe73c4`: the separately
authenticated L5 helper now has a dedicated protected file/Keychain key
configuration, `helper_key` revocation kind, digest-bound secret loading,
audited monotonic activation, exact restart restore, validity-window checks,
and defensive key disposal. The helper command factory and IPC server copy and
wipe their HMAC keys; helper construction requires an activated manager while
the adapter remains fail-closed. The full suite passes 335 tests (333 passed,
2 opt-in real-sandbox tests skipped), with 33 focused helper-key/IPC/persistence
tests passing. Caller identity packaging, root/helper separation, signed
artifacts, real adapters, and privileged host evidence remain open. Evidence:
`evidence/2026-09-13-privileged-helper-key-activation.md`.

The latest startup-assembly addendum is `a06eb81`: the launchd Edge startup
factory now restores both the active Edge key configuration and the active
Authority Control key configuration before constructing the native Broker and
separate owner-only Authority channel. The Authority channel has its own
socket, requires an explicit native peer PID/start-time identity, joins the
same fail-closed LocalBrokerRuntime lifecycle, and wipes its defensive key copy
on close. Partial startup closes the new channel and releases the source key
without misclassifying Edge failures. The full suite passes 333 tests (331
passed, 2 opt-in real-sandbox tests skipped), with six native startup tests
passing. No persistent service was installed. Evidence:
`evidence/2026-09-13-authority-runtime-assembly.md`.

The latest authority-key addendum is `f47ecc5`: owner-only Authority Control
key metadata now has an explicit versioned file/Keychain source, digest-bound
secret loading, a dedicated `authority_key` revocation kind, monotonic audited
activation, exact restart restore, validity-window enforcement, and explicit
secret disposal. The host-only uninstall assembly selects the activated key
manager before constructing the authenticated Authority Control IPC client;
raw uninstall arguments cannot supply a key. The full suite passes 332 tests
(330 passed, 2 opt-in real-sandbox tests skipped), with focused keyring, IPC,
and persistence coverage passing. Installed keychain ACLs, launchd startup,
live rotation/deletion, and final real-Mac evidence remain open. Evidence:
`evidence/2026-09-13-authority-key-activation.md`.

The latest authority-control addendum is `eeebec3`: the host-only uninstall
coordinator can now bind to the real owner-only `AuthorityControlIpcClient`
rather than a test callback. The client signs complete protocol-`0.1`
commands, authenticates complete response bodies, rejects replayed requests
through the durable server ledger, validates owner-only socket and stable
device/inode identity before and after connect, and enforces timeout,
cancellation, and response-size limits. Authenticated switch/revocation
readback is available for pre/post uninstall fencing, and the uninstall action
factory is idempotent while binding revocation to the selected Edge ID. The
full suite passes 329 tests (327 passed, 2 opt-in real-sandbox tests skipped),
with 14 focused authority/install tests passing. This remains a host-only
library boundary; protected key delivery, installed startup, live uninstall,
active-process termination, remote propagation, and final real-Mac readback
remain open. Evidence: `evidence/2026-09-13-authority-control-client.md`.

The latest compatibility addendum is `ee6d37b`: separately authenticated
privileged-helper commands now carry and validate the shared contract version;
the value is included in the complete HMAC proof and must match before replay
admission or dispatch. The helper remains disabled and no privileged action was
run. Evidence: `evidence/2026-09-13-helper-contract-version.md`.

The latest security addendum is `f24b506`: host-only uninstall coordination now
requires global kill-switch disable and selected Edge revocation through the
separately authenticated authority channel before exact-revision plist/launchd
removal, then verifies service absence and authority state again. It never
re-enables authority after a failed removal. Callback, temporary-root, and
full-regression tests pass; installed packaging, key cleanup, and live
launchd/readback evidence remain open. Evidence:
`evidence/2026-09-13-uninstall-authority-gate.md`.

The current revision also reruns the host-only macOS install-plan boundary:
10 focused tests pass for fixed LaunchAgent planning, owner-only temporary-root
preflight, signature readback, atomic plist install/upgrade/rollback/uninstall,
explicit confirmation, exact revision preconditions, and mismatch recovery.
No live LaunchAgent or installed service was touched. Evidence:
`evidence/2026-09-13-install-plan-executor.md`; live launchd, signing,
installed identity, and production rollback gates remain open.

The latest implementation addendum is `8061254`: Broker capability discovery
now returns shared protocol/contract versions and per-tool contract versions;
the versioned `mac_capabilities` schema requires those fields. The MCP Edge
fails closed unless the top-level versions match shared constants and every
enabled capability matches the local contract registry. This binds local
Broker-to-Edge capability exposure without granting Edge authority. Installed,
remote, helper, upgrade/rollback, and cross-runtime compatibility evidence
remain open. Evidence: `evidence/2026-09-13-capability-version-binding.md`.

The following paragraph records the preceding `e8112ea` baseline for evidence continuity:

The accepted documentation baseline is commit `2e389b8`; the current committed implementation baseline is `e8112ea`, which adds a separate owner-only policy signer UDS with HMAC-authenticated, replay-bound reload/rollback/revoke commands on top of the versioned owner-only policy signer metadata file, per-key public-key digests, monotonic activation and restore, local operator reload/rollback, durable audited signer revocation, bounded policy signer-key rotation, and a restart-persistent operator-command replay regression on top of the post-decision approval/intent/Job fault-injected rollback and restart fail-closed recovery to the atomic task admission boundary with target, payload, timestamp, and owner binding on the profile timeout/output-budget-enforced, active-revocation-checked, fail-closed named-task boundary on top of startup OAuth issuer/metadata consistency checks and bounded unknown-`kid` JWKS rotation evidence, HTTP-level metadata, malformed-token, scope-reduction, expiry, and post-revocation boundary checks, internal issuer-ID projection and fail-closed revocation, local certificate/key ignore rules, bounded HTTPS request, header, keep-alive, and per-socket request budgets, fail-closed HTTPS Edge configuration validation and adversarial transport-policy tests, bounded Edge contract loading with regular-file and `O_NOFOLLOW` checks, size/file-count limits, strict tool/version identifiers, canonical Docker Desktop executable resolution, bounded post-authentication Edge rate limiting, stable governed MCP Edge failure mapping, governed L2 Docker status, object inspection, and bounded container logs plus Git status, branch-list, log, and diff inspection and bounded package-manifest inspection alongside L0 log tail and launchd service status, process-detail inspection, network inspection, storage analysis, and the L1 project summary, project discovery, bounded text search, recent-file metadata, file discovery, process listing, file hashing, directory listing, and depth/entry-bounded directory trees with same-volume entry filtering. Shared contracts, a Broker core, authenticated Unix-socket transport, an authenticated MCP 2026-07-28 HTTPS Edge factory, SQLite prototype persistence, tests, and developer commands are present. No public deployment, installed service, deployment artifact, privileged helper, or production-enabled tool exists.

The implementation baseline above is superseded by `10ef33a`, which adds a fail-closed `LocalBrokerRuntime` lifecycle boundary: Broker IPC starts before separate operator channels, partial startup rolls back in reverse order, failed cleanup is retained for explicit recovery, lifecycle operations are serialized, and duplicate channel ownership is rejected. This remains an in-process library primitive; no installed launchd service or production capability is implied.

The latest implementation addendum is `87f3a72`: Edge TLS material can now be loaded only from bounded owner-only regular files opened with `O_NOFOLLOW` and checked for canonical path, ownership, permissions, and stable device/inode identity. This protects the HTTPS private key at the file boundary but does not establish remote deployment, certificate rotation, or Keychain storage.

The latest implementation addendum is `0cdb8f0`: a macOS-native Broker IPC transport now owns Unix listener creation, accept, UID/GID/PID peer lookup, and descriptor lifecycle before handing accepted descriptors to Node through the public `Socket({ fd })` API. The legacy compatibility verifier remains private-handle based; installed startup must select and package the native transport before that path can be treated as production-ready.

The latest implementation addendum is `ebe5a62`: the native peer adapter loader
now checks canonical realpath, regular-file and symlink state, bounded size,
current-user ownership, no group/other write bits, stable device/inode/size
across loading, and the required export set before returning an adapter. A
failure is treated as unavailable and fails closed. This is packaging/runtime
boundary evidence only; code signing/provenance, ABI pinning, Keychain
distribution, installed startup, and production enablement remain open.

The latest test addendum is `fa96330`: native adapter path validation now has
focused negative coverage for symlinked, writable, and non-canonical artifacts.
The validator is exercised with a canonical temporary path so the test matches
macOS `/var` to `/private/var` behavior. This strengthens local artifact
boundary evidence but does not close native signing/provenance or runtime ABI
gates.

The latest implementation addendum is `22881f9`: filesystem, process, network,
and process-tree native consumers now load through the protected peer-adapter
loader. A source boundary check finds no production direct `.node` requires,
closing the consumer-side bypass of canonical path, ownership, permission, and
load-identity checks. Native signing/provenance, ABI pinning, Keychain
distribution, installed startup, and production enablement remain open.

The latest implementation addendum is `d01cf95`: the protected native loader
binds Node's cached module to the first artifact's device, inode, size, and
SHA-256 digest, rejecting later path replacement or in-place content changes
before returning the cached adapter. This closes the loader's cache target-swap
gap; code signing/provenance, ABI pinning, Keychain distribution, installed
startup, and production enablement remain open.

The latest implementation addendum is `a447cb1`: the shared loader now
requires all 17 production native exports before any consumer receives the
module, so incomplete or capability-truncated artifacts fail closed at load
time instead of failing later during an operation. Native signing/provenance,
ABI pinning, Keychain distribution, installed startup, and production
enablement remain open.

The latest implementation addendum is `f12ab8a`: the native addon exposes its
compiled N-API version and the protected loader requires version 8 or newer,
compatible with the active Node runtime. A real built-addon readback test
passes; this narrows runtime ABI compatibility but does not prove code
signing/provenance or package trust.

The latest implementation addendum is `18a418a`: the macOS native adapter
build invokes fixed `/usr/bin/codesign --verify --strict` immediately after
compilation and fails closed if the emitted artifact cannot be verified. The
current host readback is a valid ad-hoc linker-signed arm64 module with no Team
ID; this is build-integrity evidence only and does not establish Developer ID
provenance, notarization, Keychain distribution, installed startup, or
production enablement. Evidence: `evidence/2026-09-13-native-adapter-code-signing.md`.

The latest implementation addendum is `f76e8a0`: native Broker and
compatibility IPC peer policies can bind the accepted UID/GID/PID to a captured
native `startTimeMicros`, rejecting PID reuse before socket construction or
request parsing. The stronger identity policy is explicit and preserves a
PID-only compatibility mode; installed Edge startup still must capture and
configure the intended caller identity. Evidence:
`evidence/2026-09-13-native-peer-process-identity.md`.

The latest implementation addendum is `752f73a`: the production
`createMacOsNativeBrokerRuntime` assembly rejects a PID-only peer policy before
constructing the native listener. The lower-level compatibility server remains
available for migration/tests, but the documented production assembly cannot
silently fall back to numeric-PID authorization.

The latest test addendum is `cd84e37`: a separately spawned Node Edge fixture
connects over the native UDS after the Broker captures its PID/start-time
identity. The fixture is accepted and reaches the bounded JSON handler, while
the same boundary rejects substituted identities before parsing. Full
regression is 300/302 with two opt-in sandbox tests skipped; the real sandbox
smoke is 7/7. Evidence: `evidence/2026-09-13-native-peer-process-identity.md`.

The latest lifecycle addendum is `9c48359`: the native peer server now checks
the captured PID/start-time identity before listener creation and on a bounded
unref'd monitor. If the Edge exits or the PID is replaced, the listener and
accepted sockets are closed, the socket path is removed, and the explicit
production runtime callback durably revokes that Edge in the Broker. New work
is rejected and active authority polling cannot publish a late success. A
separately spawned `/bin/sleep` fixture proves identity-loss detection and
socket removal; the Broker test proves the redacted revocation audit pair and
stable `REVOKED` response. Full regression is 302/304 with two opt-in sandbox
tests skipped; the real sandbox smoke is 7/7. This remains local lifecycle
evidence, not installed launchd restart/readback or signed caller provenance.
Evidence: `evidence/2026-09-13-native-peer-process-identity.md`.

The latest packaging addendum is `c59983e`: `executeMacOsInstallPlan` now
provides the host-only execution boundary for the existing install plan. It
requires an exact operation confirmation and existing-service precondition,
runs fixed bounded signature/launchctl commands with an empty environment,
applies the descriptor-backed atomic plist, requires final launchd/Broker/
signature readback, and boots out a mismatched service without attempting an
uncertain target overwrite. Temporary-root tests cover no-command confirmation
denial, successful install orchestration, and readback failure with an
upgrade backup left for explicit recovery. This remains non-live evidence:
no LaunchAgent was installed or bootstrapped on the host. Evidence:
`evidence/2026-09-13-install-plan-executor.md`.

The latest startup addendum is `f3fc18e`: the native Broker startup assembly
can capture an Edge PID from an exact per-user LaunchAgent `launchctl print`,
require the running state and bounded PID, read its native start time, and pass
that identity into the production runtime before it listens. Wrong domains,
stopped/malformed services, and unavailable native identity fail closed. The
focused tests also start and close a real native listener with the captured
identity. This is startup assembly evidence only; no Mac-Operator LaunchAgent
was installed or bootstrapped on the host. Evidence:
`evidence/2026-09-13-launchd-edge-identity-startup.md`.

The latest credential addendum is `ef5e336`, `44c16ad`, `be02907`, plus
`26cc667`: the native adapter now provides a
non-interactive Security.framework generic-password read for one exact
`com.mac-operator.*` service/account pair. It requires a unique 32-byte item,
fails instead of presenting a Keychain UI, and exposes no secret in logs or
files. A TypeScript loader and read-only missing-item/namespace tests are
implemented; Approval issuer configuration can select this source only with an
explicit `keySource: "keychain"` entry, while file-backed entries remain
compatible. Explicit provisioning now generates one random 32-byte item,
rejects duplicates, binds `kSecAttrAccessControl` to
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, disables synchronizable
replication, and returns only a digest. No MCP tool exposes provisioning, and
live-item ACL/rotation/deletion remain open. An opt-in native peer-authenticated
Edge-side Keychain delivery channel is now implemented with a fresh challenge,
strict bounded messages, replay rejection, fixed service/account startup
binding, Edge digest verification, and launchd startup gating; it is not
enabled or installed. Evidence:
`evidence/2026-09-13-keychain-key-read.md`.

The latest Edge-key addendum is `e9dd75e`, `7d91c8f`, `49843cc`, `a0b31fe`,
`ad781c2`, `5d5d2ce`, plus `e47137a`:
versioned owner-only
Edge key metadata now requires an explicit `file` or `keychain` source per
entry, binds an expected secret-byte SHA-256 digest, rejects mixed or unsafe
metadata, rechecks config device/inode identity, and requires BrokerStore
revocation preflight before constructing the EdgeKeyring. A BrokerStore-backed
manager persists monotonic revision/digest activation with audited intent and
completion and restores only an exact matching config after restart.
The Edge request factory now has a protected-file loader/factory with the same
owner-only, `O_NOFOLLOW`, canonical-path, bounded-encoding, and expected-digest
checks; it never falls back to environment variables or MCP arguments.
The Edge IPC client also checks the owner-only socket parent and revalidates
socket device/inode identity after connect before sending request bytes.
The request factory copies key bytes at construction and validates the key ID,
so callers cannot mutate the signing secret through an aliased Buffer or inject
an unbounded key identity.
The LaunchAgent startup assembly now restores the exact active Edge-key config
before launchd PID/start-time capture and native runtime construction, injecting
the restored keyring through a Broker factory; unactivated or mismatched config
or a config containing another Edge identity fails before `launchctl` is
called.
Overlapping validity windows provide a tested rotation path while the Broker
continues to enforce signed-policy validity and key-specific revocation on each
request. This is still a startup/configuration primitive, not installed
launchd or production enablement; the implemented delivery boundary is
documented separately. Evidence:
`evidence/2026-09-13-edge-key-source-rotation.md`.

The latest implementation addendum is `24f1824`: `createMacOsNativeBrokerRuntime` is now the explicit macOS startup assembly boundary. It constructs the native Broker channel before optional operator channels and delegates ordering, rollback, and recovery to `LocalBrokerRuntime`; no installed launchd entrypoint or production enablement is implied.

The latest implementation addendum is `6683344`: Broker, policy-signer, and approval IPC now share a native peer-accept transport. Supplying `peerPolicy` performs UID/GID/PID authorization before handler parsing; the legacy private-descriptor verifier remains compatibility-only.

The latest implementation addendum is `fde7341`: the source-level launchd boundary now validates and renders an unprivileged no-shell plist, exposes a signal-aware Broker service entrypoint with bounded readback, and includes a reviewable LaunchAgent template. No service installation or signing is implied.

The latest implementation addendum is `5804f04`: the packaging boundary now exposes a non-executing `buildMacOsInstallPlan` with explicit non-root user domain, package-owned JavaScript entrypoint, signed-artifact path, fixed `/usr/bin/codesign` and `/bin/launchctl` argv, bounded command budgets, exact previous-revision preconditions, rollback/uninstall file actions, and post-bootstrap launchd/Broker/signature readback validation. This remains source-level evidence; no signing, filesystem installation, `launchctl` mutation, or live host readback is implied.

The latest implementation addendum is `8fe6663`: `inspectMacOsInstallFilesystem` now performs read-only double-`lstat` checks over the user-home parent chain and package-owned executable, entrypoint, artifact, logs, and plist paths. It fails closed on symlinks, foreign owners, group/other write bits, unexpected types, and device/inode changes. This still does not perform descriptor-relative writes or launchd mutation.

The latest implementation addendum is `b4945c3`: `applyMacOsPlistPlan` now binds target device/inode preconditions and uses the existing native `openat`/`renameat`/`fsync` writer for temporary-root-tested install, upgrade backup, and rollback. It verifies reopened bytes/identity and attempts restoration on upgrade failure; uninstall deletion and launchd mutation remain disabled.

The latest implementation addendum is `662801b`: the native filesystem boundary now exposes exact-target `unlinkat` with root, regular-file, owner-domain, and device/inode preconditions. `applyMacOsPlistPlan` uses it for temporary-root-tested plist/backup uninstall and restores the plist if backup deletion fails; recursive deletion and launchd mutation remain unavailable.

The latest implementation addendum is `53a6550`: the disabled-by-default `mac_app_focus` boundary now binds independent `mac.app.control` authority to an exact `app_window` target, `trusted_gui` approval, durable mutation intent, a principal/session-bound Job lease, and active authority checks before dispatch and terminal success. A fixed Broker-owned JXA adapter uses `/usr/bin/osascript`, `/` cwd, an empty environment, a 10-second timeout, and a 128 KiB output cap to resolve and focus only an allowlisted running bundle/window, then verifies focused state. Sensitive system/security applications and credential/password/sign-in/verification-code targets are denied at Broker, adapter, and parser layers. This remains implemented but disabled by default. Evidence: `evidence/2026-09-13-app-focus-boundary.md`.

The current implementation addendum is `9bba3cd`: disabled-by-default `mac_ui_action` binds an exact observed Accessibility element to an owner/session-scoped 30-second snapshot, parent app-window authority, `trusted_gui` approval, a Broker Job ID, fixed Broker-owned JXA, and exact before/after window/index/role/label reobservation. The fixed action allowlist is `press`, `select`, `increment`, `decrement`, `show_menu`, and `focus`; secure, redacted, sensitive, stale, mismatched, cancelled, and permission-denied paths fail closed. Credential typing, real permission-granted GUI evidence, structured automation, and capability enablement remain open. Evidence: `evidence/2026-09-13-ui-action-boundary.md`.

The current implementation addendum is `96acb1a`: the proposed L5 helper boundary now has a separately authenticated owner-only IPC server, HMAC command/response binding, durable BrokerStore nonce/request replay admission, strict target/operation and handler-map validation, no raw executable or argument fields, bounded redacted evidence, and a mandatory Broker-owned authority callback checked before dispatch, during active cancellation polling, and before response publication. A Broker-owned command factory derives helper operations only from the three `mac_priv_*` tools and requires a matching explicit approval, intent-linked running Job, payload/policy/target identity, principal/session ownership, active kill switches, and revocation checks before signing. Authority loss or expiry yields `UNKNOWN_OUTCOME`; no root process or privileged operation is enabled. Evidence: `evidence/2026-09-13-privileged-helper-boundary.md`.

The current implementation addendum is `2e6cd57`: an experimental,
disabled-by-default `SandboxExecTaskRunner` now renders a Broker-owned
deny-default macOS Seatbelt profile from the resolved named TaskProfile and
invokes only `/usr/bin/sandbox-exec` through the bounded ProcessSupervisor.
The renderer rejects raw SBPL, broad roots, cwd escapes, and non-loopback
network destinations; loopback allowlists are rendered as exact
`localhost:port` rules. The runner requires a profile-matched `TaskIsolationProof`, an
explicit opt-in, and an external host-evidence gate. On the Mac mini M4/macOS
26.2 host, the opt-in smoke passed allowed-root read/write, denied
`/private/etc/passwd`, a root-contained `.env`, and an outside-file symlink, hid
four synthetic inherited environment canaries, allowed the selected loopback
destination while denying an unlisted loopback port and external curl
DNS/network access,
and mapped active `/bin/sleep` cancellation to process-group termination; a
Bash child-launch attempt was rejected by the default no-fork policy. The
resolved profile defaults to `single_process` without `process-fork`; explicit
`owned_group` remains a separate unevidenced extension. `TaskIsolationProof`
now binds this selected process-tree policy, preventing proof reuse across
variants.
Evidence is partial and does not select the
deprecated `sandbox-exec` boundary for production or unblock `mac_task_run`:
real credential stores, descendants/`setsid`, crash/restart cleanup, remounts,
Docker, persistence, privilege, and allowlisted networking remain open.
Evidence: `evidence/2026-09-13-sandbox-profile-runner.md`.

The latest implementation addendum is `f0f6d1e`: the disabled
`ProcessSupervisor` now binds macOS descendant termination to bounded native
PID/start-time identities in addition to the detached process group. It binds
the root process group to its own start-time identity before signalling,
signals only identities that still match their observed start time, refuses
Darwin execution when the native observer is unavailable, and returns
`UNKNOWN_OUTCOME` while retaining capacity when descendant observation is
malformed, truncated, or failed. A hostile fork-plus-`setsid` fixture now
terminates within the bounded timeout. Snapshot races, post-snapshot `setsid`,
crash/restart cleanup, sandbox enforcement, credential isolation, and
production task-runner enablement remain open. Evidence:
`evidence/2026-09-13-process-group-drain.md`.

The latest implementation addendum is `dd824b4`: the Broker now exposes a
separate owner-only Authority Control IPC with native UID/GID/PID peer checks,
HMAC-authenticated protocol-`0.1` commands, bounded timestamps/nonces, durable
replay admission across restart, strict `set_switch`/`revoke` allowlists, and
expected-state switch preconditions. Authority request IDs flow into the
transactional intent/completion audit pair, while audit evidence stores only a
SHA-256 reason digest. This remains a source-level control boundary and does
not prove protected key distribution, installed startup/readback, active
process termination, remote propagation, or an executable operator recovery
procedure. Evidence: `evidence/2026-09-13-job-authority-lifecycle.md`.

The latest implementation addendum is `1e3eb86`: the experimental
`SandboxExecTaskRunner` now refuses the unevidenced `owned_group` process-tree
policy even when an external isolation proof is supplied. The only executable
task policy remains the no-fork `single_process` variant. The real Mac opt-in
smoke was rerun at 7/7 tests and checked only readability of the current
user's existing `.ssh`, `.docker`, Chrome, Safari, Mail, Messages, and Keychains
directories plus `/var/run/docker.sock`, all denied without reading contents.
This is an enablement guard and partial host evidence, not a production
selection of deprecated `sandbox-exec`.
Evidence: `evidence/2026-09-13-sandbox-profile-runner.md`.

## Completed work

- Created the Git repository and initial commit.
- Established LF text normalization through `.gitattributes`.
- Created the initial KB planning set for goal, design, specification, security, Epics, roadmap, tasks, progress, tool contracts, and the 44-tool catalog.
- Selected the high-level topology: Remote MCP Edge to authenticated local IPC to Mac Local Broker to adapters, with separate audit and privileged boundaries.
- Selected the governing security direction: Broker final authority, default deny, secret deny zones, bounded execution, redacted audit, kill switches, and no unrestricted shell or root interface.
- Completed an architecture deep dive identifying identity-chain, path-race, child-process isolation, active revocation, mutation recovery, GUI target, and tool-lifecycle requirements.
- Materialized, reviewed, verified, and committed the repository documentation baseline through `MOP-002`.
- Added a protected Edge TLS material loader with owner-only permissions, non-symlink opening, bounded file size, canonical-path validation, and device/inode readback checks; the loader is explicit and does not enable HTTPS deployment by itself.
- Added a macOS-native Broker IPC transport with bounded owner-only UDS creation, CLOEXEC/SIGPIPE controls, native `getpeereid`/`LOCAL_PEERPID` acceptance, public Node descriptor handoff, denied-peer pre-parse behavior, and fail-closed listener cleanup; the transport is explicit and does not enable installed service packaging or production capability enablement by itself.
- Added an explicit `createMacOsNativeBrokerRuntime` factory so a future macOS packaging entrypoint selects the native Broker IPC channel and cannot accidentally wire the legacy private-handle server; startup/rollback/close semantics remain owned by `LocalBrokerRuntime`.
- Added a shared `MacOsNativePeerIpcServer` and native peer-policy mode for policy-signer and approval channels, keeping their HMAC/signed-command semantics after pre-parse OS identity authorization; compatibility verifier mode remains explicit and non-production.
- Added a launchd packaging boundary with canonical path/argv validation, no shell or environment injection, bounded restart settings, a signal-aware service lifecycle, component/policy/source readback, and an unprivileged LaunchAgent template; installation, signing, and live launchd readback remain disabled.
- Added a non-executing macOS install preflight plan with fixed signature/service command argv, empty environments, bounded timeout/output, per-user/root denial, package-owned entrypoint/path checks, exact upgrade/rollback/uninstall preconditions, rollback/uninstall actions, and exact post-bootstrap identity validation; live installation and signature/launchd host evidence remain disabled.
- Added a read-only macOS install filesystem preflight with double-`lstat` identity checks across package paths and parent directories; symlink, owner, mode, type, and target-swap boundaries fail closed, while descriptor-relative atomic installation remains future work.
- Added a bounded plist apply primitive that reuses the native descriptor-relative atomic writer, binds external identity preconditions, verifies content/identity readback, and restores upgrade content on failure in temporary-root tests; it never invokes launchd and intentionally does not delete uninstall targets.
- Added exact-target native `unlinkat` with postcondition verification and recovery around plist/backup uninstall; no recursive or arbitrary deletion surface is exposed, and real service removal remains unverified.
- Started documentation-only remediation against the newer KB SSOT: repaired stale dynamic-state ownership; materialized locked Security, Filesystem Policy, Tool Contract Standard, and Tool Catalog documents; added threat, scope, persistence, verification, ADR, sandbox-research, navigation, testing, configuration, deployment, operations, incident, rollback, and kill-switch documents.
- Resolved the two representation conflicts: every contract now has deterministic `audit_class` and structured `postcondition_verification`, and the legacy contract `phase` field is now canonical `tool_delivery_wave`.
- Completed MOP-084 functional API schema materialization: all 44 planned tools now have explicit bounded `input_schema` and tool-specific `output_schema` objects integrated with the common result envelope. Envelope validation, functional schema compilation, semantic review, authority-surface review, and catalog parity pass; runtime compatibility remains a separate gate.
- Prepared the KB writeback manifest without changing KB-MCP; orchestration review is still required before upstream synchronization.
- Accepted TypeScript/Node 24+ for the Edge/Broker baseline under ADR-0001 and created npm workspaces for shared contracts and Broker code.
- Implemented signed payload binding, strict request parsing, timestamp/session expiry, persistent nonce/request replay denial, exact scope authorization, revocation, independent kill-switch primitives, bounded structured outputs, recursive audit redaction, and hash-linked audit records.
- Implemented local handlers for `mac_health`, `mac_capabilities`, `mac_policy_explain`, `mac_stat_path`, bounded `mac_read_file`, descriptor-backed `mac_hash_file`, bounded descriptor-backed `mac_list_directory`, and bounded `mac_directory_tree`; production defaults keep the filesystem handlers disabled.
- Implemented bounded `mac_system_summary`, `mac_process_list`, `mac_process_inspect`, `mac_service_status`, `mac_log_tail`, `mac_git_status`, `mac_git_branch_list`, `mac_git_log`, `mac_git_diff`, and `mac_package_inspect` Broker handlers and adapters. Host summary returns sanitized OS version, architecture, CPU, memory, uptime, and optional load facts; process inventory/detail inspection use native metadata, bounded output, numeric owner labels, parent/child identity, and no argv/environment exposure; service status uses an allowlisted system launchd identifier and fixed `/bin/launchctl` execution with bounded output; log tail uses allowlisted sources, fixed `/usr/bin/log`, bounded compact-format parsing, and mandatory redaction; Git status, branch listing, log, and diff use exact project-root authorization, fixed `/usr/bin/git`, bounded porcelain/ref/log/diff parsing, literal path and revision validation, repository-script rejection, secret-pattern redaction, and post-execution identity readback; package inspection uses independent `mac.package.read` scope, descriptor-backed manifest/lock probing, npm/pnpm/yarn/pip/uv/poetry/Brewfile parsing, no script execution, and explicit disabled-outdated warnings.
- Implemented bounded `mac_docker_status`, `mac_docker_inspect`, and `mac_docker_logs` through an exact `mac.docker.read` scope and Broker-authorized local runtime/object targets. The adapter uses a fixed canonical Docker Desktop/Homebrew executable allowlist, `/` cwd, a fixed local Unix socket, an empty synthetic HOME/config path, fixed non-mutating CLI arguments, bounded JSON/line parsing, omission of environment fields, mount/log redaction, cancellation/timeout mapping, and no raw socket proxy or arbitrary command surface. A real Mac daemon status readback observed local Docker version `29.1.3` without enumerating containers/images; storage facts, object/log compatibility, and host-level socket negative evidence remain open.
- The MCP Edge factory uses SDK v2 modern protocol handling, discovers only tools returned as enabled by the Broker, and maps `BrokerError` or unknown gateway failures to a stable redacted failure envelope without exposing transport internals. External OAuth issuer issuance/discovery, revocation propagation, and HTTPS deployment evidence remain open.
- `EdgeRequestFactory` binds the protocol/contract versions, tool arguments, immutable projected principal, policy audience/version, timestamp, single-use nonce, and `(edge_id, key_id)` identity into the signed request; `BrokerIpcClient` verifies a response proof bound to the complete request/result and rejects a replaced or mismatched socket. Cross-runtime canonicalization and protected production key distribution remain open.
- The HTTPS Edge applies a fixed-window, bounded in-memory rate limiter after Bearer verification, keyed only by verifier-provided client/principal identity, with fixed request/window/key budgets and `Retry-After` responses. Shared multi-instance counters, durable rate-limit state, and load evidence remain open.
- The Edge contract registry rejects symlinked/non-regular contract files, symlinked directories, invalid tool/version identifiers, and oversized file/count/aggregate inputs before parsing; regular files are opened with `O_NOFOLLOW` and read under fixed byte budgets. Adversarial loader tests cover regular-file success, symlink denial, directory denial, size denial, and invalid schema versions.
- The HTTPS Edge validates non-empty TLS material, dedicated HTTPS resource URLs, canonical host/origin hostname lists, resource-host inclusion, and duplicate normalization before constructing the server. Tests reject insecure URLs, scheme/port/path smuggling, empty TLS material, and host-list mismatches.
- The HTTPS Edge sets fixed request, header, keep-alive, and per-socket request limits (`30s`, `10s`, `5s`, and `100` respectively) in addition to the 1 MiB JSON body limit. These are local transport controls; shared multi-instance admission and load evidence remain open.
- A real local HTTPS probe with an ephemeral certificate verified protected-resource metadata (`200`), bearer challenge (`401`), Host/Origin rejection (`403`), MCP route reachability (`405` for unsupported GET), fixed-window `429` with `Retry-After`, TLS 1.2 rejection, and readback of the connection budgets. Real OAuth issuer/client interoperability and deployment remain open.
- The official `@modelcontextprotocol/client` SDK completed a pinned `2026-07-28` `server/discover` and `tools/list` exchange against the local HTTPS Edge, and received exactly the Broker-enabled `mac_health` tool. The test uses a temporary self-signed certificate and loopback fetch adapter; real OAuth issuer, certificate-chain, and remote deployment evidence remain open.
- The Edge now verifies the same probe's RS256 JWT signature against a configured JWKS, checks issuer/resource/audience/expiry/iat/jti, maps the external issuer URL to the bounded internal issuer ID, filters scopes, and supports a fail-closed revocation callback. Startup binds OAuth metadata to the configured issuer and endpoint scheme; local and bounded remote-JWKS cache/rotation tests cover valid, malformed, expired, wrong-audience, missing-identity, revoked, and rotated-key tokens.
- Implemented bounded `mac_find_files` over explicitly authorized filesystem roots. Search runs in Broker-owned filesystem workers, uses metadata-only descriptor-backed traversal, filters protected entries before result construction, caps roots/results/visited entries/depth, and authorizes every requested root independently.
- Implemented bounded `mac_recent_files` over explicitly authorized metadata roots. Recent-file results use a Broker-owned worker, a Broker-bound time window, fixed traversal/result budgets, protected-entry filtering, independent per-root authorization, and no content reads.
- Implemented bounded `mac_search_text` over explicitly content-authorized filesystem roots. Search runs in a Broker-owned worker, accepts only bounded literal/glob queries, scans UTF-8 text within fixed per-file and aggregate byte budgets, caps matches per file/results, filters protected paths and secret-shaped content, and authorizes every requested root independently.
- Implemented bounded `mac_project_discover` over explicitly metadata-authorized filesystem roots. Discovery runs in a Broker-owned worker, reports only safe project-marker types and indicator names, bounds roots/depth/directories/entries/results, skips symlinked and dependency directories, filters protected entries, and authorizes every requested root independently without reading file contents.
- Implemented bounded `mac_project_summary` for one explicitly metadata-authorized project root. Summary runs in a Broker-owned worker, returns only safe VCS type, root manifests, inferred languages, bounded structure metadata, and explicit warnings when branch/dirty state is omitted; it never reads source, credential, or VCS control-file content.
- Implemented bounded `mac_storage_analysis` over explicitly metadata-authorized filesystem roots. Storage analysis runs in a Broker-owned worker, reads volume capacity through a descriptor-verified native `statfs` adapter, ranks bounded file/directory metadata without content reads, aggregates directory consumers within fixed depth/entry/directory budgets, excludes protected paths and symlinks, and returns truncation warnings without exposing secret content.
- Implemented bounded `mac_network_status` for local interface metadata and inferred connectivity. The native adapter uses `getifaddrs` only, performs no active probe or packet capture, bounds interface/address output, and fails closed with an explicit warning when optional listener metadata is requested because the version-neutral adapter does not yet expose a pinned listener ABI.
- Implemented bounded `mac_service_status` for allowlisted `system/<label>` launchd identifiers. The Broker authorizes the exact service target before a fixed `/bin/launchctl print` call; the adapter uses `/` cwd, an empty environment, detached process-group timeout/cancellation, a 128 KiB output cap, safe state/exit/PID parsing, and stable not-found/timeout/error mapping without mutation.
- Implemented bounded `mac_log_tail` for exact `system` or `process/<name>` sources. The Broker authorizes the exact log-source target before a fixed `/usr/bin/log show --style compact` call; the adapter uses `/` cwd, an empty environment, detached process-group timeout/cancellation, a 512 KiB output cap, a 24-hour effective window cap, bounded line output, malformed-record warnings, and secret/path redaction before return or audit.
- Implemented bounded `mac_git_status` for one exact authorized project root. The Broker authorizes the canonical project target before a fixed `/usr/bin/git status --porcelain=v2 -z --branch` call; the adapter uses a non-symlink project and `.git` directory, rejects executable Git integrations in repository config, supplies only fixed non-secret Git environment settings, disables hooks/fsmonitor/optional locks, enforces a 256 KiB output cap and 10-second timeout/cancellation, parses branch/head and bounded status paths, redacts sensitive text, and verifies project identity after execution.
- Implemented bounded `mac_git_branch_list` for one exact authorized project root. The Broker authorizes the same canonical project target before a fixed `/usr/bin/git for-each-ref` call; the adapter optionally lists local and already-known remote refs without fetch, uses the same non-secret environment and repository-config checks, bounds branches to 500 and output to 256 KiB, parses current/upstream/ahead/behind metadata, redacts branch text, and verifies project identity after execution.
- Implemented bounded `mac_git_log` for one exact authorized project root. The Broker authorizes the same canonical project target before a fixed `/usr/bin/git log` call; the adapter accepts only a bounded ref name and limit, uses fixed NUL-delimited commit metadata, disables external diff/textconv/rename behavior and hooks/fsmonitor/optional locks, uses the same non-secret environment and repository-config checks, bounds output to 256 KiB and commits to 200, normalizes timestamps, redacts author/subject text, and verifies project identity after execution.
- Implemented a mode-`0600` Unix-domain socket prototype with application-layer HMAC authentication and a 1 MiB request cap.
- Added functional input/output schemas for all 44 planned tools, a common stable failure schema, automated compilation/uniqueness checks, and implemented-handler conformance tests.
- Added an owner/mode/symlink/identity-checked authentication-key loader and a least-privilege macOS CI workflow; neither installs or enables a service.
- Implemented the signed-policy candidate: JSON Schema 2020-12, Ed25519 verification with a protected pinned public key, monotonic revisions, Broker-owned grants, exact typed target rules, deny-over-allow, static kill switches, atomic in-memory activation, and request-to-policy-version binding.
- Extended policy verification to support up to 32 protected Ed25519 signer entries with overlapping validity windows, bounded key IDs, revocation callbacks, and fail-closed unknown/expired/revoked-key handling. This is a verifier primitive; durable signer metadata, operator rotation/reload, and revocation persistence remain open.
- Added a versioned owner-only policy signer configuration manager. Atomic metadata writes bind each key path to a SHA-256 public-key digest; BrokerStore persists monotonic activation/restore identities, audited revocation, and verified-history rollback. The manager exposes reload/rollback only as a local Broker API and is not wired to the remote MCP Edge or installed startup path.
- Added a separate owner-only policy signer UDS. Commands use a distinct HMAC key, OS peer verification, strict operation schemas, timestamp/nonce bounds, durable replay admission, and no MCP Edge route; successful reload, rollback, and revocation remain Broker-audited.
- Implemented Edge key IDs and overlapping HMAC-key rotation windows. Signed policy authorizes exact Edge/key validity metadata, protected local files provide secret bytes, and persisted key-specific revocation overrides both.
- Implemented an MCP SDK v2 Edge candidate for the 2026-07-28 protocol: OAuth bearer verification is injected, token resources are checked, bearer secrets never cross IPC, capability discovery is caller-filtered, a fresh MCP server is built per request, legacy protocol traffic is rejected, and HTTPS requires TLS 1.3 plus Host/Origin allowlists.
- Added bidirectional request/response HMAC domain separation. Edge verifies the socket owner/mode and a response proof bound to the exact request and complete Broker result, so a replaced socket cannot forge success.
- Added startup verification for the redacted audit hash chain and an atomic migration from the legacy revocation table to key-specific Edge revocation support.
- Added a macOS N-API peer-credential adapter using `getpeereid` and `LOCAL_PEERPID`. Broker IPC now requires an injected UID/GID/PID policy and drops the connection before parsing when OS identity is denied or unavailable.
- Added Broker-owned HMAC key provisioning and retirement primitives: protected parent directories, exclusive `0600` creation, file/directory fsync, digest preconditions, mandatory persisted key revocation, quarantine rename, and unlink. No physical overwrite guarantee is claimed for APFS/SSD storage.
- Added signed filesystem metadata roots and a descriptor-backed macOS `mac_stat_path` handler. The native adapter opens and identifies the configured root and target, enforces same-volume canonical containment, reapplies deny zones after descriptor readback, and records canonical path plus device/inode evidence.
- Added adversarial metadata tests for traversal, root and target symlinks, deny-inside-allow aliases, root `/` containment, and a 2,000-iteration atomic symlink target-swap race. These are bounded dirty-tree prototype results, not closure of the L0/L1 filesystem gate.
- Added an independently enabled signed content-read root flag and a descriptor-backed `mac_read_file` prototype for regular files. It rejects final symlinks and special files, bounds byte ranges, validates UTF-8 strictly, caps base64 expansion, and records the opened device/inode; an intermediate-directory symlink race confirms successful reads never escape the root.
- Hardened content reads with Broker-mandatory secret path/signature rules that signed policy cannot disable, canonical-path authorization before descriptor I/O, single-link inode enforcement, local-volume enforcement, and post-read inode/link/size/mtime/ctime stability checks. Successful ranges carry a SHA-256 readback hash and consistent truncation state.
- Implemented a disabled `mac_write_file_atomic` L2 filesystem handler. Broker-owned policy roots must opt into `write`, exact approvals bind the canonical arguments and root target, content/path secret rules run before mutation, and the macOS native adapter uses same-volume descriptor identity, `openat` temporary files, `fsync`, atomic rename, create-only exclusion, expected identity/hash preconditions, and readback hash verification. Each write now requires an explicit idempotency key, creates a Broker-owned Job Ledger record, exposes its durable `job_id` for `mac_job_status`, and marks unresolved running outcomes `UNKNOWN` on restart. The handler is not enabled by default and its contract remains planned until controlled-write rollback, crash, and final readback gates are complete.
- Moved filesystem stat/read execution into Broker-owned worker threads with an empty environment, empty argv/execArgv, V8 memory/stack limits, a four-worker admission cap, per-tool deadlines, 25 ms active-authority polling, termination requests, and post-result authority revalidation. Timed-out workers retain capacity until actual exit, preventing unbounded timeout-driven thread creation.
- Moved process inventory/detail execution into a separate Broker-owned worker boundary with empty environment/arguments, bounded V8 memory/stack settings, a two-worker admission cap, per-tool deadlines, active-authority polling, termination requests, and strict result validation. This keeps native process inspection off the Broker event loop; it is still not a process-memory or OS sandbox boundary.
- Added bounded `mac_find_files` traversal to the same worker boundary with empty environment/arguments, a fixed 50,000-entry/32-level search budget, output validation, deadline/cancellation handling, and metadata-only root planning. It does not read file contents and protected paths are excluded before output or audit evidence.
- Added bounded `mac_recent_files` traversal to the filesystem worker with empty environment/arguments, metadata-only output validation, Broker-supplied clock binding, deadline/cancellation handling, and the same fixed traversal budget. It returns only canonical path, type, size, and modified time.
- Added bounded `mac_search_text` traversal to the filesystem worker with empty environment/arguments, content-read root planning, 1 MiB per-file and 64 MiB aggregate scan budgets, 100 matches per file, strict UTF-8 decoding, sanitized snippets, protected-entry/secret filtering, deadline/cancellation handling, and strict result validation.
- Added bounded `mac_project_discover` traversal to the filesystem worker with empty environment/arguments, metadata-only root planning, fixed 16-level/10,000-directory/50,000-entry budgets, allowlisted project marker types, dependency-directory pruning, protected-entry filtering, deadline/cancellation handling, and strict result validation.
- Added bounded `mac_project_summary` traversal to the filesystem worker with empty environment/arguments, metadata-only project-root planning, fixed 4-level/1,000-tree-entry/50,000-entry budgets, dependency-directory pruning, protected-entry filtering, safe manifest/language inference, deadline/cancellation handling, and strict result validation.
- Added runtime validation for worker success/error messages and tests for completion, capacity exhaustion, timeout, cancellation, environment canary isolation, and session revocation during execution. Worker threads protect the Broker event loop but are not a filesystem/network sandbox or process-memory isolation boundary.
- Started MOP-086 real-Mac sandbox research. A redacted host record proves partial canonical filesystem/symlink, executable-allowlist, network-deny, and fake credential-canary behavior with deprecated `sandbox-exec`; it also proves inherited environment visibility and that a child can survive parent termination, leaving process-tree, real credential, Docker, persistence, cleanup, and allowlisted-network guarantees unresolved. `mac_task_run` remains disabled.
- Added a disabled `ProcessSupervisor` prototype for the future Broker-owned task boundary. It requires a Broker-resolved canonical executable/cwd, no shell string, explicit allowlisted and size-bounded environment, detached process group, fixed stdio, bounded arguments/output, timeout, cancellation, TERM/KILL escalation, descendant cleanup, and capacity accounting; it remains unavailable until sandbox/credential-isolation evidence is accepted.
- Added a host-side descriptor canary fixture proving the current `ProcessSupervisor` launch does not inherit a non-stdio parent descriptor on the tested POSIX host. This is partial launch-boundary evidence only; it does not prove OS sandbox descriptor policy, credential isolation, or production task-runner safety.
- Hardened the disabled `ProcessSupervisor` termination boundary to verify detached process-group disappearance with bounded `kill(-pgid, 0)` polling for normal completion, timeout, cancellation, output overflow, and orphan detection. Unresolved groups return `UNKNOWN_OUTCOME` and retain the capacity slot until an unref'd reaper observes group disappearance; `setsid` escape resistance, sandbox enforcement, credential isolation, and production enablement remain open.
- Added a real macOS packaging smoke test that creates and ad-hoc signs a synthetic temporary app bundle, then verifies it through the install plan's fixed `/usr/bin/codesign --verify --strict --deep` boundary. It is host command-wiring evidence only; production Developer ID identity, notarization, and installed-service readback remain open.
- Added a 500-iteration hostile create-only write fixture that races a temporary target against attacker-created regular files and symlinks. Native `renameatx_np(RENAME_EXCL)` plus descriptor identity checks either commit the Broker's own file or fail closed; the outside canary remains unchanged. Controlled-write recovery and release evidence remain open.
- Added durable, non-secret write-job descriptors (root/path/size/digests/preconditions and exact generated temporary name) with schema migration and restart readback. `mac_job_status` now probes an unresolved write's current postcondition as `matches`, `mismatch`, or `unavailable` while retaining `UNKNOWN`; a matching digest is evidence only and cannot be promoted to success without actor attribution. The host-startup recovery pass now selects only restart-reconciled unknown write Jobs and cleans one recorded temporary artifact with descriptor-relative identity checks, audited intent/completion, no prefix scan, and kill-switch skip behavior; service assembly invokes it before native IPC startup, while the explicit Broker hook remains available to controlled hosts. Legacy descriptors without a temporary name remain untouched. Synthetic restart/readback/cleanup tests and a test-only native `SIGKILL` fixture at selected syscall boundaries for create/replace writes pass; remount durability, prior-worker/process ownership proof, and broader partial-mutation evidence remain open.
- Added final authority revalidation before a filesystem write Job is marked completed. If the mutations kill switch trips while the adapter is active, the request fails closed as `CANCELLED` and the Job remains `UNKNOWN`; an integration test covers this active-work boundary.
- Added a Broker-owned `TaskProfileRegistry` boundary for named L2 tasks and connected it to a disabled-by-default `mac_task_run` handler. The handler requires a profile-owned canonical executable/cwd/args/environment/network declaration, exact `mac.task.run` target authorization, a single-use `trusted_profile` approval, Broker Job creation/status linkage, bounded redacted output, verified postconditions, and fail-closed unknown outcomes. The default `FailClosedTaskRunner` rejects execution until a separately evidenced sandbox runner is supplied.
- Added a versioned `TaskIsolationProof` gate: an available runner must attest to the selected sandbox profile plus enforced filesystem/network boundaries, isolated credentials, and owned process-tree cleanup before Broker admission can consume approval or create a task Job. Missing, malformed, extra-field, or profile-mismatched proof fails closed; test-only proof fixtures remain explicitly non-production evidence.
- Added a SQLite Job Ledger with principal-scoped payload-bound idempotency, revision-checked transitions, owner/session/tool/target/policy identity, bounded secret-sanitized output, cancellation state, and terminal outcome invariants. Startup recovery maps abandoned queued jobs to `cancelled` and running jobs to `unknown`, with hash-linked recovery audit events.
- Added durable execution leases to the Job Ledger. A Broker instance claims a queued Job with a random owner/token and bounded expiry, renews the lease during cancellable work, and must present the matching unexpired lease before publishing a terminal success/failure/cancelled state. Lease fields are cleared on terminal transition or restart fencing; stale owners can only close an expired lease as `UNKNOWN`, never as success. Process-tree identity/termination and lease-backed recovery remain open.
- Added transactional queued-job authority reconciliation: disabling global/mutations/process/network switches cancels the applicable queued tool families before commit, principal/session revocation cancels matching queued ownership, and upstream edge/key revocation conservatively cancels all queued jobs because their provenance is not yet persisted. Broker request handling revalidates authority immediately before starting a queued job, closing the stale-plan dispatch window while active process-tree ownership and restart-safe worker leases remain open.
- Implemented local `mac_job_status` and `mac_job_cancel` handlers against Broker-owned job identity. Dynamic job IDs resolve to the Broker-owned `job:owned` policy target; foreign jobs return `TARGET_NOT_FOUND`. Cancellation writes a payload-digest audit intent before state mutation, is idempotent for terminal jobs, and reports termination as pending for running jobs until an executor confirms it.
- Added a SQLite Request Ledger with atomic nonce/request admission, canonical payload binding, revisioned lifecycle states, and state-plus-audit transactions for decisions, mutation intent, and completion. Startup recovery fails interrupted reads/pre-dispatch mutations and marks dispatched mutations `UNKNOWN`; authenticated denials remain replay-reserved and no recovery path infers success.
- Added a Broker-owned Approval Ledger prototype. Single-use records bind both principals, tool/contract, normalized target, canonical arguments digest, policy version, approval class, attended mode and TTL. `mac_job_cancel` now fails closed without an exact approval; consumption, request linkage, mutation intent, and redacted audit evidence commit in one transaction, while revocation before `RUNNING` prevents dispatch.
- Added a separately authenticated `ApprovalAuthority` plus dedicated owner-only `ApprovalIpcServer` prototype for operator-issued approvals. Issuer/key identity, validity window, signed canonical payload, bounded preview digest, attended/unattended policy, durable issuance nonce, and approval decision/completion provenance are verified before one transaction persists the approval and audit evidence. Approval issuer key files reuse owner-only non-symlink `0600` loading/provisioning and revoke-before-retire deletion, with a separate durable `approval_key` revocation kind. A versioned owner-only key metadata document now atomically writes and reloads non-secret paths, revision, validity, and unattended flags with canonical payload digest readback; a BrokerStore-backed manager persists activation history, audits intent/completion, rejects revision rollback, and restores only an exact revision/digest after restart. Key bytes remain in separate protected files. It is not exposed through the remote MCP Edge and does not claim protected Keychain storage or a production UI.
- Materialized and compiled the versioned internal approval-issuance envelope at `schemas/approval-issuance.schema.json`; it rejects unknown fields and binds the approval payload, preview digest, issuance digest, and proof fields.
- Added `BrokerStore.admitApprovedJob`, an atomic future-task admission primitive that links nonce/request admission, authorized decision, exact approval consumption, mutation intent, principal-scoped idempotency reservation and queued Job creation. Added `admitApprovedJobAfterDecision` for the active task path so approval consumption, intent audit, queued Job creation, and request linkage commit together with owner/target/payload/timestamp preconditions. Idempotent retries return the original Job without consuming approval again; conflicting reuse and injected post-decision failures roll back without exposing a partial approval, intent, or Job. Restart reconciliation fails an authorized-but-not-intented request closed without consuming approval.
- Added a default-off, test-only fault-injection hook for the atomic admission phases. Reopening the SQLite store after failures at request, authorization, approval-consumption, and Job-insert boundaries verified that no request, audit event, approval consumption, or Job half-commits.

## Implementation status

- Runtime implementation: local foundation only; no meaningful whole-program percentage is claimed.
- Released tools: 0 of 44 planned.
- Implemented local Broker dispatch paths: 44 of 44 planned. The three
  privileged helper paths remain disabled in the default policy until
  independent root-domain signing, installation, live readback, and real
  adapter evidence is accepted.
- Enabled tools: 0 of 44 planned.
- Automated tests: the latest non-overlapping built regression passes 602
  total (596 passed, 6 explicit opt-in skips, 0 failed); the existing
  Broker/Persistence test process remains separately undisturbed.
- Real-Mac execution evidence: bounded local foundation, a synthetic temporary-repository Git staging/commit run, a real-host running-app inventory query, a real-host Finder Accessibility probe that failed closed without permission, and partial sandbox research records on Mac mini M4/macOS 26.2; UI action remains fixed-command/fake-adapter prototype evidence with no real app mutation or permission-granted release evidence.
- Remote MCP deployment: none.
- Privileged helper: protocol/IPC plus Broker Job dispatch candidate; no
  privileged process, real adapter, signing, or enablement.
- Machine-readable tool contracts: 44 of 44 materialized with unique KB
  provenance; all remain planned, the Broker dispatch paths are implemented,
  and enabled delivery remains 0 of 44.

Percentages beyond these objective counts are intentionally omitted because the delivery scope and estimates are not yet baselined.

## Contract schema status

- Contract envelope schema: complete and validated for all 44 materialized contracts. This covers identity, capability, policy, budgets, lifecycle, audit, delivery wave, provenance, and summary fields.
- Per-tool functional input/output schema objects exist and compile for all 44 contracts. Success schemas use `SUCCEEDED`; failures use the shared stable-error schema.
- Schema presence is complete. Semantic review, compatibility fixtures, and
  runtime conformance currently cover all forty-four Broker dispatch paths;
  separately authenticated root-domain helper release gates remain open.

## Current phase

Phase 1 — Broker and Edge foundation with initial L0/L1 inspection slices. Runtime/package selection, signed-policy activation/rollback, HMAC plus macOS UID/GID/PID-authenticated local IPC, authenticated MCP introspection, sanitized system/process/network inspection, descriptor-backed path metadata, bounded regular-file reads, directory listing, depth/entry-bounded trees, metadata-only file discovery, recent-file metadata, bounded secret-filtered text search, bounded project discovery, bounded project summaries, and bounded storage/capacity analysis run in tests. Network listener enumeration remains explicitly limited until a version-pinned native ABI is available. Production key distribution, native-adapter packaging/runtime compatibility, remote issuer integration, operational policy tooling, audit reliability, packaging, configurable secret classification, physical/remount evidence, and enforceable I/O deadlines remain open.

## Decisions recorded

- Keep Edge, Broker, adapters, Job Manager, Audit Store, and Privileged Helper responsibilities explicit.
- Treat the Broker as the sole final host authorization point.
- Keep L0-L5 as planning labels rather than inherited permission levels.
- Distinguish planned, implemented, and enabled tool states.
- Require durable audit intent before mutations and privileged actions.
- Bind filesystem authority to the resolved/opened target, not only a path string check.
- Treat repository task scripts as untrusted child code.
- Add idempotency, status lookup, and unknown-outcome reconciliation for mutations.
- Define revocation and kill-switch effects for queued and active work.
- Defer generic shell, GUI action, and privileged execution until their boundary evidence passes.

## Pending decisions

- Remote OAuth issuer and tunnel/provider deployment choice.
- Native peer-adapter packaging, Node socket-descriptor compatibility, Edge process-ID lifecycle, cross-process/keychain distribution, storage-level erasure limits, cross-process/global session quotas, and broader numeric canonicalization compatibility.
- Child-process sandbox technology on the target macOS version.
- Installed startup wiring, native caller/process identity packaging, Keychain distribution, general schema-version framework, crash-window recovery, and rollback runbook.
- Audit backend, integrity, retention, and read-only outage behavior.
- Production filesystem allow roots, operator-configurable secret classifications, physical/removable-volume remount evidence, and cross-volume Unicode/case policy remain open; plan/native volume-identity guards plus bounded lexical case-alias and NFKC search behavior are covered by adversarial fixtures.
- macOS packaging, signing, launch, update, and rollback strategy.
- Runtime compatibility fixtures and host conformance for unimplemented tools.
- KB-MCP writeback review for the resolved contract and progress changes.

## Blockers

There is no blocker to continued local implementation. Production enablement is blocked by protected Keychain/cross-process secret distribution, native peer-adapter packaging/compatibility, real OAuth issuer and remote transport integration, audit crash/disk/backup behavior, operational policy tooling, packaging, and clean-revision evidence. `node:sqlite` is prototype-only pending ADR-0005 evidence. Named task execution remains blocked by sandbox and credential-isolation proof. Controlled writes, GUI actions, public access, and the privileged helper remain closed behind their documented gates.

## Verification performed

- Confirmed accepted documentation baseline `2e389b8` and implementation baseline `10ef33a`; the exact-revision evidence record is refreshed after the governed HTTPS Edge configuration, contract-loader, rate-limit/failure, Docker, process, hash, directory-listing, directory-tree, file-discovery, recent-file, text-search, project-discovery, project-summary, storage-analysis, network-status, process-inspect, service-status, log-tail, Git-status, Git-branch-list, Git-log, Git-diff, package-inspect, signed JWT/JWKS verifier, OAuth metadata consistency, rotated-key refresh, official MCP client HTTPS discovery, HTTP-level OAuth failure-boundary, fail-closed task-runner Job/approval, active-revocation, profile-budget, atomic post-decision task-admission, policy signer lifecycle, authenticated operator-channel, restart-persistent operator-command replay, and fail-closed local Broker runtime lifecycle slices.
- Confirmed all 44 catalog tools have one valid JSON materialization, a unique tool name, a unique KB item ID, preserved source text, and a catalog link.
- Confirmed the runtime catalog reports all 44 tools separately; forty-one
  have local handlers and the three privileged helper tools remain planned in
  the default policy. The production default enables none, and the read-
  enabled test policy enables only bounded read tools including
  `mac_app_list` and `mac_ui_observe` (the latter still fails closed when
  host Accessibility permission is absent).
- Confirmed all 44 contracts have one taxonomy-valid `audit_class` and one structured `postcondition_verification`; all remain `planned`.
- Confirmed canonical contracts contain `tool_delivery_wave` and no top-level legacy `phase` field; roadmap lifecycle phases remain separate.
- Validated all 44 contract envelopes and compiled all 44 functional input/output schemas; checked unique tool and provenance IDs, bounded fields, forbidden authority-field absence, and output/verification compatibility.
- Ran the full suite at 247 passing tests after adding durable Job execution leases and stale-terminal-commit fencing, alongside transactional queued-job cancellation for authority changes and a pre-start Broker authority recheck, durable write-descriptor migration, exact temporary-name persistence, the explicit fail-closed restart cleanup hook, the unknown-write postcondition probe, a Broker completion-failure simulation, a test-only native syscall crash-boundary fixture, and active mutations-kill-switch revalidation; `npm run typecheck`, `npm run verify:contracts`, and `git diff --check` also pass. Evidence: `evidence/2026-09-13-write-recovery-postcondition.md`, `evidence/2026-09-13-write-temporary-cleanup.md`, `evidence/2026-09-13-job-authority-lifecycle.md`, and `evidence/2026-09-13-job-lease-fencing.md`.
- Reran the full suite at 247 passing tests after adding bounded ProcessSupervisor process-group drain/readback and unresolved-group capacity retention; `npm run typecheck` also passes. Evidence: `evidence/2026-09-13-process-group-drain.md`.
- Reran the full suite at 252 passing tests after adding the disabled-by-default controlled Git staging/local-commit boundary and a real temporary-repository integration run through `/usr/bin/git`, including explicit-path validation, staged-diff hash and HEAD/index/status readback, fixed no-hook/no-network/no-push/no-reset command wiring, Broker approval/intent/Job lease integration, and unknown-outcome mapping; `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev --audit-level=high`, and `git diff --check` also pass. Evidence: `evidence/2026-09-13-git-write-boundary.md`.
- Reran the full suite at 257 passing tests after adding the governed `mac_app_list` inventory boundary. The Broker binds an `app_set:all` target and independent `mac.app.read` scope, while a fixed `/usr/bin/osascript -l JavaScript` adapter returns only bounded bundle identities, names, versions, and running state with path, PID, argument, and environment omission. Parser, policy, contract-conformance, Broker integration, fixed-command, and real-host running-app tests pass; `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev --audit-level=high`, and `git diff --check` also pass. Evidence: `evidence/2026-09-13-app-inventory-boundary.md`.
- Reran the full suite at 264 passing tests after adding the disabled-by-default `mac_app_open` boundary, runtime contract-conformance coverage, and one global launch deadline at commit `85d1e96`. App launch binds `mac.app.control`, an exact `app:bundle:<id>` target, `trusted_gui` approval, a Broker Job lease, fixed `/usr/bin/open -b`, bounded inventory/open/reobservation time, and running-state reobservation; active revocation maps to cancellation/unknown Job state. Document and URL arguments remain explicitly rejected until independent filesystem/network target policy exists. App-control, policy-schema, policy-loader, GUI kill-switch, contract-envelope, deadline, and existing regression tests pass; `npm run typecheck`, `npm run verify:contracts`, `npm audit --omit=dev --audit-level=high`, and `git diff --check` also pass. Evidence: `evidence/2026-09-13-app-open-boundary.md`.
- Reran the full suite at 270 passing tests after adding the read-only `mac_ui_observe` Accessibility boundary and conservative sensitive-target denial. The Broker binds the independent `mac.ui.observe` scope to an exact `window:bundle:<id>` target, applies the GUI kill switch, denies known security/credential/sign-in targets, and emits only bounded secure-masked nodes with opaque snapshot-derived refs. The fixed JXA adapter checks host Accessibility trust and maps permission denial, missing app/window, cancellation, timeout, output overflow, and malformed results to stable fail-closed classes. Policy-schema, policy-loader, contract-envelope, Broker integration, redaction, sensitive-target, fixed-command, and permission-denial tests pass; a real Finder probe correctly returned `POLICY_DENIED` without permission. Evidence: `evidence/2026-09-13-ui-observe-boundary.md`.
- Ran 214 automated tests covering the identity, IPC, authenticated policy-signer operator UDS with HMAC, peer denial and replay persistence across a store reopen, HTTPS Edge configuration/contract loading/discovery/error mapping/rate limiting, signed JWT/JWKS verification, issuer/metadata consistency, rotated-key refresh, official MCP client HTTPS discovery, policy, protected policy signer-file loading with per-key digest binding, durable signer activation/restore/reload/rollback/revocation and revocation-schema migration, fail-closed local Broker runtime startup ordering/partial-start rollback/failed-cleanup recovery/concurrent lifecycle/duplicate-channel rejection, filesystem metadata/content/hash/list/tree/find/recent/search-text/project-discover/project-summary/storage-analysis/write adapters, local network interface inspection, bounded process inventory/detail inspection, fixed launchd service status inspection, bounded allowlisted log tail inspection with secret redaction, exact-target Git status/branch-list/log/diff inspection with literal path/revision validation, sanitized diff hashing, repository integration rejection, bounded package manifest/lock inspection for Node/Python/Brewfile formats, fixed local-only Docker status/object/log inspection with raw-socket and secret-output boundaries, package symlink/cancellation boundaries, disabled outdated lookup, and bounded UTF-8 redaction, system/process-summary adapters, native process inventory, worker, secret, audit, contract, Request/Approval/Job Ledgers, authenticated approval issuance, protected issuer-key lifecycle, named task profile resolution, fail-closed task-runner validation and Broker Job/approval integration, active session-revocation handling, profile timeout/output-budget rejection, atomic post-decision approval/intent/Job admission, post-decision fault-injected rollback and restart fail-closed recovery, disabled process supervisor, including bounded recent-file windows/results/visited entries/depth, bounded search roots/results/visited entries/depth, content-authorized text roots, UTF-8/binary handling, fixed per-file/aggregate text search budgets, sanitized snippets, secret filtering, metadata-only project marker discovery, project type validation, fixed project depth/directory/entry budgets, dependency-directory pruning, metadata-only project summaries, safe manifest/language inference, bounded project tree output, branch/dirty omission warnings, bounded storage depth/entry/directory traversal, descriptor-verified volume capacity, ranked directory aggregation, independent multi-root authorization, protected-entry filtering, bounded process output and numeric owner redaction, parent/child PID bounds, bounded service output/state/exit/PID parsing, log compact-format parsing/malformed-record handling/redaction, Git porcelain-v2/ref/log/diff parsing/head/revision/path/commit/diff budgets/config checks, bounded directory pagination/tree depth and protected-entry filtering, exact write-approval binding, durable write-job idempotency/status/restart recovery, descriptor-backed create/replace, expected hash and create-only preconditions, atomic rename/readback, descriptor-backed SHA-256/SHA-512 hashing without content return, hash target-change rejection, symlink/intermediate escape rejection, issuer/key authentication, preview binding, issuance replay denial, attended/unattended profile gating, durable approval-key revocation, revoke-before-retire deletion, versioned key metadata atomic write/reload and digest readback, persisted monotonic activation, exact restart restore, activation audit, rollback rejection, fixed executable/cwd/environment selection, anchored argument allowlists, symlink/duplicate/revoked config rejection, expiry/revocation/exhaustion, competing consumption, pre-dispatch invalidation, atomic future-job admission, idempotent reuse, conflict rollback, fault-injected admission rollback and restart readback, atomic replay admission, revisioned request lifecycle, fail-closed restart reconciliation, owner isolation, cancellation, explicit environment/argument/cwd validation, bounded output, process-group timeout/cancellation, descendant cleanup, capacity accounting, and schema conformance.
- A later source revision `87f3a72` reran the full suite at 217 passing tests and added the protected Edge TLS material boundary; the exact addendum is recorded separately in `VERIFICATION.md` and `evidence/2026-09-13-edge-tls-material.md`.
- A later source revision `0cdb8f0` reran the full suite at 220 passing tests and added the native Broker IPC transport boundary; the exact addendum is recorded separately in `VERIFICATION.md` and `evidence/2026-09-13-native-ipc-transport.md`.
- A later source revision `24f1824` reran the full suite at 221 passing tests and added the explicit native runtime assembly boundary; the exact addendum is recorded separately in `VERIFICATION.md` and `evidence/2026-09-13-native-runtime-assembly.md`.
- A later source revision `6683344` reran the full suite at 221 passing tests and moved operator-channel peer checks onto the shared native transport; the exact addendum is recorded separately in `VERIFICATION.md` and `evidence/2026-09-13-native-operator-ipc.md`.
- A later source revision `fde7341` reran the full suite at 225 passing tests and added the launchd/service-entrypoint boundary; the exact addendum is recorded separately in `VERIFICATION.md` and `evidence/2026-09-13-launchd-service-boundary.md`.
- Recorded initial real-Mac sandbox evidence in `SANDBOX_RESEARCH.md` and `evidence/2026-09-12-sandbox-research.json`; the result is explicitly partial and does not unblock `mac_task_run`.
- Reran the full suite at 291 tests (289 passed, two default opt-in real-host tests skipped) on clean source commit `41e83c0`; `MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js` passed 6/6 on the Mac mini M4/macOS 26.2 host. The experimental runner smoke proves only Broker-rendered deny-default profile construction, default single-process/no-fork policy, explicit empty-environment filtering for four canaries, allowed temporary-root read/write, `/private/etc/passwd`/`.env`/symlink denial, curl DNS/network denial, child-launch denial, active sleep cancellation, and profile-matched process-tree proof validation. It does not prove real credential, descendant/`setsid`, crash/restart, remount, Docker, persistence, privilege, or allowlisted-network isolation. Evidence: `evidence/2026-09-13-sandbox-profile-runner.md`.
- Recorded bounded host evidence in `evidence/2026-09-12-local-broker-foundation.md`.
- Added atomic audit coverage for generic switch and revocation changes; focused persistence, Broker, and approval tests pass with the authority audit pair present.
- On source revisions through `f12ab8a`, the ProcessSupervisor focused suite passes 8/8, including a detached `setsid` descendant fixture and root-PID identity binding; native peer credential/IPC focused tests pass 8/8, including native adapter artifact rejection, complete-export loading, and runtime N-API compatibility. The full suite passes 296 of 298 tests with two opt-in real-sandbox tests skipped by default. The focused real-Mac sandbox run passes 7/7 with `MOPS_REAL_SANDBOX=1`; `npm run typecheck`, `npm run verify:contracts` (44 unique contracts), `npm audit --omit=dev --audit-level=high`, `git diff --check`, and the production native-loader bypass check also pass.

The passing tests prove only the local foundation, bounded filesystem workers/search, and initial persistent Request/Approval/Job Ledgers on the recorded clean revision. They do not satisfy a release gate or prove protected Keychain-backed secret storage, installed cross-process code identity, a human approval UI/channel, production unattended profiles, remote deployment, removable-volume remount identity, process-tree ownership/termination, credential isolation, sandbox, GUI, helper, packaging, or whole-service rollback.

## Next steps

1. Close native peer-adapter packaging/runtime compatibility and cross-process/keychain distribution under `MOP-081`.
2. Integrate a real OAuth issuer and test MCP metadata, expiry, revocation, scope reduction, rate limits, and Broker outage without exposing the Broker publicly.
3. Use `LocalBrokerRuntime` in an installed startup/packaging entrypoint and complete the policy-signer rollback runbook, only after ADR-0007 and native caller identity are accepted.
4. Supply a real sandboxed `TaskRunner` only after MOP-086 isolation evidence passes, then connect running-job cancellation to verified process-tree ownership.
5. Keep task execution, writes, GUI, public deployment, and helper capabilities disabled until their gates pass.

## Related documents

See `README.md`, `TASK.md`, `VERIFICATION.md`, and `docs/adr/README.md`.

## Latest helper status addendum

Source revisions `2240870` and `86a99ca` add and harden a helper-owned,
read-only status boundary. The
status request uses a distinct HMAC domain, bounded timestamp/expiry, strict
envelope fields, durable replay admission, and the same native peer policy as
the command channel. The response is HMAC-bound to the request and accepts
only the fixed runtime readback shape: native transport required, adapter
disabled, canonical distinct helper/Broker sockets, Broker UID/GID, source,
contract, policy, and an empty enabled-capability set. The status source and
Broker authority gate are explicit runtime inputs; launchd state and request
arguments cannot fabricate them. The client rechecks the socket device/inode
after the read to reject a replacement endpoint. Key-manager-created servers
apply the active-key validity/revocation fence to status reads as well.

No helper operation, root service, launchd mutation, or remote deployment is
enabled. The full suite now reports 398 tests (395 passed, 3 opt-in sandbox
tests skipped), with typecheck, contract verification, audit, and diff checks
passing.

## Latest real-Mac sandbox addendum

On source revision `a8d9007`, `MOPS_REAL_SANDBOX=1 npm test` passed 398/398 on
the Mac mini host, including the focused sandbox suite at 9/9. The run covers
empty child environment, protected-file and symlink denial, selected local
network allow/deny behavior, fork/`setsid` escape denial, and active
cancellation. It is host evidence only: real credential/Docker/persistence
isolation, remount identity, owned-group semantics, post-snapshot descendants,
UDP, external allowlisted networking, and production packaging remain open.
Evidence: `evidence/2026-09-13-real-sandbox-regression.md`.

## Latest helper signature addendum

Source revision `46a3167` makes the root-domain helper package reject any
signature expectation without the exact helper identifier, a ten-character
Developer ID TeamIdentifier, and a CDHash. Codesign readback must match all
three values before package readiness can be accepted. This closes the
incomplete/ad-hoc identity path but does not claim a Developer ID-signed or
notarized artifact, installed root helper, or live launchd evidence.
Evidence: `evidence/2026-09-13-helper-signature-gate.md`.

## Latest helper observer integration addendum

Source revision `3b24604` wires the authenticated helper status client into the
production-shaped package observer. Callers must select either the explicit
helper socket/key client or a controlled test callback; no runtime source means
observer construction fails closed. The observer integration test completes a
real local signed status exchange and feeds the result through package
readback. The latest default suite reports 399 tests, 396 passed, 3 opt-in
sandbox tests skipped. An already-created key-manager server also rejects status
reads immediately after helper-key revocation. The latest suite is now 400
tests, 397 passed, 3 opt-in sandbox tests skipped. Evidence:
`evidence/2026-09-13-helper-observer-ipc-integration.md`.

## Latest helper command client addendum

Source revision `6d6087d` adds the Broker-side bounded client for already-signed
helper commands. It authenticates the complete response, caps bytes and time,
fences socket device/inode identity, returns stable helper failures, and maps
transport loss to retryable `UNKNOWN_OUTCOME` without inferring privileged
success. Evidence: `evidence/2026-09-13-helper-command-client.md`.

## Latest helper Job executor addendum

The disabled-by-default `PrivilegedHelperJobExecutor` now binds the existing
Broker command factory/client to a running Job lease. It rechecks authority
before and after dispatch, validates command identity against the persisted
Job, accepts success only for a verified completed helper result, and records
transport/timeout/accepted-but-incomplete/post-revocation uncertainty as
retryable `UNKNOWN_OUTCOME`. The short-lived command key buffer is cleared by
the client binding. The default policy and MCP dispatch still expose no
privileged operation; helper installation, adapters, and root launchd remain
disabled. The latest default suite is 407 tests (404 passed, 3 opt-in sandbox
tests skipped). Evidence: `evidence/2026-09-13-helper-job-executor.md`.

The Broker now owns the executor through an explicit optional dependency and a
host-only `executePrivilegedHelperJob()` seam. The seam performs an initial
authority check, while the executor repeats it around helper IPC; the default
constructor remains fail-closed and disabled.

The helper envelope now carries a persisted typed payload descriptor as well as
its digest. Strict service-control, package-install, and power shapes reject
unknown fields, secret-shaped content, unbounded text, target mismatches, and
digest mismatches. No MCP route accepts these descriptors and privileged policy
and adapters remain disabled. Persistence/restart and command-binding tests
cover the new boundary.

MOP-004 now has a versioned machine-readable ledger contract at
`schemas/ledger-records.schema.json` for Request, Approval, Job, and Audit
envelopes. The contract is compiled by `verify:contracts` and has positive and
negative AJV coverage, including raw helper-authority rejection. It documents
the persistence boundary without weakening the runtime Broker validators. A
host-only SQLite recovery slice now adds owner-only atomic backup publication,
SQLite quick-check and audit-chain verification, fresh-target restore,
numeric timestamp retention, and fail-closed symlink/ownership/mode/size/
target-swap checks. Encrypted backup storage, disk exhaustion, general
migrations, and stronger audit anchoring remain open.
Evidence: `evidence/2026-09-13-ledger-record-contracts.md`.

The ledger-contract revision reran the full suite at 409 tests (406 passed,
3 opt-in sandbox tests skipped), with typecheck, contract verification,
dependency audit, and diff checks passing. `verify:contracts` now reports both
the 44 MCP contracts and the versioned ledger-record schema.

The persistence recovery revision reran the full suite at 412 tests (409
passed, 3 opt-in sandbox tests skipped). The focused Broker persistence suite
passes 29/29, including owner-only backup/restore readback, numeric retention,
symlink refusal, and modified-audit-chain rejection. Typecheck, contract
verification, dependency audit, and diff checks are recorded after the local
commit. Evidence: `evidence/2026-09-14-persistence-backup-restore.md`.

The persistence crash/concurrency addendum adds stale temporary-artifact and
SQLite WAL/SHM/journal sidecar cleanup after a hard-killed backup child, a
five-second SQLite busy timeout, a simulated ENOSPC retryable-failure test,
an insufficient-capacity preflight, and a two-process audit-writer test that
preserves the hash chain. The focused Broker persistence suite now passes
33/33; real kernel/disk-quota exhaustion and explicit single-owner service
policy remain open. Evidence:
`evidence/2026-09-14-persistence-backup-restore.md`.

The crash/concurrency addendum reran the full suite at 416 tests (413 passed,
3 opt-in sandbox tests skipped), with no failures.

The physical macOS host evidence reran the same suite with
`MOPS_REAL_SANDBOX=1`: 416 tests passed, 0 failed, and 0 skipped. This closes
the opt-in host sandbox, process-group cancellation, service-lock, launchd
read-only, and authenticated Edge/Broker integration checks for the current
revision. Kernel-level disk-quota exhaustion, installed production launchd
readback, encrypted/Keychain backup storage, external audit anchoring, and
rollback/runbook decisions remain open.

Live launchd smoke evidence then exposed and fixed a transient-state parser
gap: macOS reports `state = xpcproxy` immediately after a user LaunchAgent is
bootstrapped. The bounded readback adapter now maps that state to `launching`
without claiming `running`; strict Edge/helper startup paths still require
`running` plus native PID/start-time identity. A unique temporary `/bin/sleep`
LaunchAgent was bootstrapped, read through the production adapter, booted out,
and confirmed absent. Focused launchd readback and service-inspector tests pass
7/7. Evidence:
`evidence/2026-09-14-live-launchd-readback.md`. The updated default suite is
420 tests (417 passed, 3 opt-in sandbox tests skipped), and the
`MOPS_REAL_SANDBOX=1` suite is 420/420 with no skips.

The same live smoke then exercised `captureLaunchdEdgeProcessIdentity` against
a temporary user LaunchAgent. It captured the positive PID/start-time identity
after the `xpcproxy` transition, with retry limited to that state and a
five-second global deadline, then booted the service out and confirmed absence.
The native startup focused suite passes 7/7; malformed, stopped, and identity
failure paths remain fail-closed.

The Broker instance-lock boundary now also has a real non-cooperating-process
test: a child holds the owner-only lock, the parent receives `ALREADY_ACTIVE`,
and reclamation succeeds only after the child's PID/start-time identity is
proven stale. Focused lock tests pass 5/5. This does not claim launchd
singleton enforcement or remount durability. Evidence:
`evidence/2026-09-14-service-instance-lock-process.md`.

The host-only macOS install plan now has a physical-Mac package smoke:
ad-hoc signature verification, owner-only package layout, atomic plist
publication, fixed `launchctl bootstrap`, real zero-capability Broker startup,
independent double-read launchd/native/plist/Broker/signature verification,
exact uninstall, and final service/plist absence all passed. The package smoke
used its historical owner-only fixture, while the current Broker startup
assembly now exposes a separate HMAC-authenticated status socket with native
peer credentials and durable replay rejection. Production package provenance,
upgrade/rollback, and helper gates remain open.
Evidence: `evidence/2026-09-14-live-install-plan.md` and
`evidence/2026-09-14-broker-status-ipc.md`.

The physical host now also exercises `createBrokerServiceFromStartupConfig`
against a real temporary per-user LaunchAgent without a synthetic launchd
executor. Signed policy and Edge-key activations restore before native
PID/start-time capture; the Broker starts its native socket with zero enabled
capabilities and mode `0600`, then closes cleanly and leaves no temporary
service or socket. This closes only the live startup-assembly slice; Edge
request exchange is now covered by a native HTTPS-to-UDS smoke, while
installed production packaging, Developer ID signing, upgrade/rollback, and
helper installation remain open. Evidence:
`evidence/2026-09-14-live-broker-startup.md` and
`evidence/2026-09-14-native-https-edge.md`.

Docker result-boundary hardening (source revision `50fd2fb`) now requires
plain known-field container/image records and unambiguous object identities;
inspection nested data is bounded and Docker logs cap both line count and line
bytes before redaction. Focused Docker tests pass 9/9. The non-overlapping
package regression passes 533 total (527 pass, 6 skipped, 0 fail). Daemon
compatibility, storage readback, isolation, raw-socket negatives, packaging,
and capability enablement remain open. Evidence:
`evidence/2026-09-15-docker-result-boundary.md`.

Install-plan readback hardening (source revision `61e7357`) now routes
service, component, existing-service, and signature observations through a
plain-data record boundary. Inherited and accessor-shaped readbacks fail
closed before identity or capability validation. Focused install-plan tests
pass 22/22; Developer ID provenance, persistent installed lifecycle,
production upgrade/rollback, helper execution, and final capability
enablement remain open. Evidence:
`evidence/2026-09-15-install-readback-boundary.md`.

Edge IPC response hardening (source revision `adddedd`) now validates a plain
exact response envelope plus stable Broker success/failure fields before MCP
publication. Unknown fields, invalid error classes, oversized warnings or
duration, and accessor-shaped observations fail closed. Focused Edge IPC tests
pass 4/4; production key lifecycle, remote deployment, installed provenance,
and capability enablement remain open. Evidence:
`evidence/2026-09-15-edge-ipc-response-boundary.md`.

Persisted process ownership recovery hardening (source revision `7ad478c`)
now validates exact plain root identities, dense bounded descendants, and the
Broker-owned no-fork marker before native signalling. Focused supervisor tests
pass 33/33; descendant escape resistance, kernel termination, credential
isolation, production task enablement, and installed recovery remain open.
Evidence: `evidence/2026-09-15-process-ownership-readback.md`.

The post-hardening non-overlapping package regression passes 536 total tests
(530 passed, 6 skipped, 0 failed). Release-style typecheck, style, contract,
canonical-JSON, and diff checks also pass; the two pre-existing long-lived
Broker/persistence test processes remain intentionally excluded and untouched.

Audit evidence hardening (source revision `fbb197b`) now projects and redacts
only plain records and dense arrays; non-data values become a fixed marker
before canonical hashing or persistence. Focused audit evidence tests pass
2/2. SQLite corruption/disk exhaustion, external anchoring, production
Keychain, installed recovery, and release acceptance remain open. Evidence:
`evidence/2026-09-15-audit-evidence-boundary.md`.

Privileged-helper status request hardening (source revision `026a83f`) now
applies a shared plain-data boundary before status classification, candidate
recovery, key enumeration, or field access. Focused hostile accessor/inherited
status tests pass 1/1; the non-overlapping package regression passes 537 total
(531 passed, 6 skipped, 0 failed). This does not close helper provenance,
production Keychain, root-domain installation, real privileged execution,
crash recovery, or enablement gates. Evidence:
`evidence/2026-09-15-helper-status-boundary.md`.

The helper status readback validator now shares the same plain-data boundary
before key enumeration or helper-owned state access (source revision `e9d67e6`).
Focused request/readback tests pass 2/2; the complete non-overlapping package
regression passes 538 total (532 passed, 6 skipped, 0 failed). Helper
provenance, production Keychain, root-domain installation, real privileged
execution, crash recovery, and enablement remain open. Evidence:
`evidence/2026-09-15-helper-status-boundary.md`.

Broker status request validation now checks plain-data shape before key
enumeration or field access (source revision `240ee88`). The focused parser
test passes 1/1 with accessor/inherited fixtures, and the non-overlapping
package regression passes 538 total (532 passed, 6 skipped, 0 failed).
Production deployment, Keychain, remote transport, privileged operations, and
capability enablement remain open. Evidence:
`evidence/2026-09-15-broker-status-boundary.md`.

Status readback capability arrays are now dense and bounded on both Broker and
privileged-helper paths (source revision `987cadc`). Focused hostile-array
tests pass 2/2; the non-overlapping package regression passes 538 total (532
passed, 6 skipped, 0 failed). Production deployment, Keychain, remote
transport, privileged operations, and capability enablement remain open.
Evidence: `evidence/2026-09-15-status-array-boundary.md`.

Broker startup configuration now enforces the shared plain-data boundary before
key enumeration, path normalization, or authority checks (source revision
`345b329`). Focused accessor/inherited fixtures pass 1/1; the non-overlapping
package regression passes 538 total (532 passed, 6 skipped, 0 failed).
Developer ID, installed lifecycle, Keychain, remote deployment, helper, and
release gates remain open. Evidence:
`evidence/2026-09-15-startup-config-boundary.md`.

Broker persistence migration now performs an in-transaction final readback of
the schema marker and complete ordered registry (source revision `7ce59c1`).
Focused migration tests pass 3/3; the non-overlapping package regression passes
538 total (532 passed, 6 skipped, 0 failed). Physical disk recovery,
production backups, Keychain deployment, installed recovery, and release
acceptance remain open. Evidence:
`evidence/2026-09-15-schema-migration-readback.md`.

Runtime policy authority arrays now require dense bounded data-only shapes
before authorization or capability discovery (source revision `d1f96f2`).
Focused hostile-array tests pass 2/2; the non-overlapping package regression
passes 539 total (533 passed, 6 skipped, 0 failed). ADR-0004, production
signer/Keychain, installed reload, and capability enablement remain open.
Evidence: `evidence/2026-09-15-policy-array-boundary.md`.

Broker capability-family limit configuration now requires a plain data record
before default-limit merging (source revision `0a97e3f`). Inherited and
accessor-shaped overrides fail closed without reading a limit. Focused Broker
constructor tests pass 2/2; the non-overlapping package regression passes 539
total (533 passed, 6 skipped, 0 failed). Process-wide/adapter quotas, kernel
and disk limits, production packaging, and capability enablement remain open.
Evidence: `evidence/2026-09-15-broker-family-limit-boundary.md`.

Durable request-admission limit validation now applies the same plain-data
boundary inside `BrokerStore` (source revision `999435d`). Inherited and
accessor-shaped global/session/family limit records fail closed before any
value read or request-row insertion. Focused persistence validation passes 1/1;
the non-overlapping package regression remains 539 total (533 passed, 6
skipped, 0 failed). Kernel/process quotas, disk exhaustion, and production
service evidence remain open. Evidence:
`evidence/2026-09-15-admission-limit-boundary.md`.

Active mutation approval revalidation now runs during Broker pre-dispatch,
control callbacks, and final readback (source revision `b4cac00`). A revoked
or expired consumed approval cancels active work and prevents success
publication; started Jobs remain `unknown`. Focused Broker verification passes
1/1 and the non-overlapping package regression remains 539 total (533 passed,
6 skipped, 0 failed). Human approval UI/channel, protected Keychain,
unattended ownership, and production evidence remain open. Evidence:
`evidence/2026-09-15-active-approval-revalidation.md`.

Edge startup and HTTPS allowlist configuration now require plain records and
dense bounded data-only host/origin arrays (source revision `04fcffc`).
Inherited, accessor, symbolic, and sparse authority data fail closed before
URL/path validation or listener setup. Focused Edge tests pass 2/2; the
non-overlapping package regression passes 540 total (534 passed, 6 skipped, 0
failed). TLS/key lifecycle, remote deployment, launchd installation, and
capability enablement remain open. Evidence:
`evidence/2026-09-15-edge-config-shape-boundary.md`.

Edge contract loading now rejects non-data records and unknown top-level
contract fields (source revision `fa0dc50`) before MCP tool construction.
Focused registry tests pass 2/2; the non-overlapping package regression passes
541 total (535 passed, 6 skipped, 0 failed). Handler completeness, signing
provenance, remote deployment, and capability enablement remain open. Evidence:
`evidence/2026-09-15-contract-registry-boundary.md`.

MCP capability readback now validates plain response data, dense bounded
capability arrays, governed item fields, and optional Broker `scopes`/`reason`
metadata (source revisions `0b8c7e2`, `3f65dc8`). Unknown, accessor, symbolic,
and sparse structures fail closed before tool registration. Focused Edge tests
pass 2/2; the non-overlapping package regression passes 542 total (536 passed,
6 skipped, 0 failed). Broker handler completeness, remote deployment, and
capability enablement remain open. Evidence:
`evidence/2026-09-15-mcp-capability-boundary.md`.

Edge principal projection now rejects non-data identity metadata and
accessor/sparse/symbolic scope arrays before governed identity creation (source
revision `ce198e1`). Focused projection tests pass 3/3; the non-overlapping
package regression passes 543 total (537 passed, 6 skipped, 0 failed). OAuth
provider behavior, key rotation, remote deployment, and capability enablement
remain open. Evidence:
`evidence/2026-09-15-principal-projection-boundary.md`.

Direct policy authorization now rejects malformed projected scopes and target
records before policy matching (source revision `88d9179`). Dense known-scope
arrays and canonical policy targets are required even for exported helper
calls. Focused policy tests pass 2/2; the non-overlapping package regression
passes 544 total (538 passed, 6 skipped, 0 failed). Production signer/Keychain,
installed reload, and capability enablement remain open. Evidence:
`evidence/2026-09-15-policy-input-boundary.md`.

Scope authority is now consistent at both request parsing and direct tool
authorization boundaries (source revision `cb704af`). Principal
scope arrays must be dense, known, unique, and bounded by the registered scope
set; malformed lists fail with `AUTH_INVALID` before policy lookup. Focused
policy/security-fuzz verification passes 15/15; the non-overlapping package
regression passes 545 total (539 passed, 6 skipped, 0 failed). Production token issuance,
cross-process identity packaging, and capability enablement remain open.
Evidence: `evidence/2026-09-15-scope-boundary.md`.

Target authorization now independently requires an enabled principal grant and
checks every requested scope against that grant (source revision `d785eb0`).
Disabled grants fail with `POLICY_DENIED`; out-of-grant scopes fail with
`SCOPE_DENIED` before target-rule matching. Focused policy/security-fuzz
verification passes 16/16; the non-overlapping package regression passes 546
total (540 passed, 6 skipped, 0 failed). Production policy distribution and
capability enablement remain open. Evidence:
`evidence/2026-09-15-target-grant-boundary.md`.

Queued-job kill-switch reconciliation now preserves read-only Jobs when the
`mutations` switch is disabled and cancels only the explicit mutation tool
allowlist (source revision `6bf29d4`). The `global` switch remains an
all-capability stop; process, GUI, destructive, and privileged mappings remain
independent. Build and a temporary BrokerStore smoke pass; the non-overlapping
package regression remains 546 total (540 passed, 6 skipped, 0 failed).
Evidence: `evidence/2026-09-15-kill-switch-scope-isolation.md`.

The mutation kill-switch mapping is now fail-closed for future tools (source
revision `fe6a187`): known read-only tools are the only queued Jobs preserved;
unknown or newly introduced tools are cancelled until explicitly classified as
read-only. Build and a temporary BrokerStore smoke pass; the non-overlapping
package regression remains 546 total (540 passed, 6 skipped, 0 failed).
Evidence: `evidence/2026-09-15-kill-switch-fail-closed.md`.

Broker-owned Job records now persist the admitting Edge identity in schema
version `11` (source revisions `e0b9db8`, `66688ec`, `9a52c59`, `8dbbd67`, `08c8100`, `b31cf4c`). All Broker mutation Job
paths bind the authenticated request Edge; idempotent reuse rejects a different
Edge, and legacy Jobs migrate with null provenance. Edge revocation now cancels
only matching queued Jobs while null or malformed provenance fails closed
conservatively. Edge-key revocation now has the same precision through persisted
key identity. Restarted guest recovery also rechecks a persisted Job Edge before
status lookup, including Edge-key revocation checks. Build, typecheck, lint, and a temporary schema/readback and
revocation smoke pass; the non-overlapping package regression remains 546
total (540 passed, 6 skipped, 0 failed). Evidence:
`evidence/2026-09-15-job-edge-provenance.md`.

Edge authentication identity validation is now owned by the keyring itself
(source revision `a2580e0`). Direct `EdgeKeyring` construction rejects malformed
or traversal-shaped Edge/key IDs before authority is loaded, and config,
persisted Job provenance, and `Broker.revokeEdge` reuse the same bounded Edge
identity predicate. Focused keyring/config tests pass 9/9; build, typecheck,
lint, contract verification, and diff checks pass; the non-overlapping package
regression now passes 547 total (541 passed, 6 skipped, 0 failed). This closes a constructor
versus loader validation drift but does not close production key distribution,
Developer ID provenance, or installed-service evidence. Evidence:
`evidence/2026-09-15-edge-keyring-identity-boundary.md`.

Maximum Edge/key identity length is now consistent across admission, persisted
Job provenance, and operator revocation (source revision `6fdc725`). A 128
character Edge plus 128 character key yields the supported 257-character
composite identity; keyring and Authority Control boundary tests accept it,
while malformed identities remain rejected. The non-overlapping package
regression passes 549 total (543 passed, 6 skipped, 0 failed). This remains
local bounded-identity evidence; production key distribution and installation
evidence remain open. Evidence:
`evidence/2026-09-15-edge-key-identity-length.md`.

The disabled-by-default `mac_ui_type` slice is now implemented behind the same
snapshot, approval, Job, revocation, and readback boundary as `mac_ui_action`.
(source revision `adf9fd8`).
Bounded text and nine allowlisted keys are delivered through a bounded
ProcessSupervisor stdin channel, so input never appears in argv or persisted
Job output; secret-like input, secure or redacted snapshots, non-text controls,
stale targets, and focus/readback drift fail closed. Focused UI, policy-loader,
and process-supervisor tests pass; the non-overlapping package regression
passes 553 total (547 passed, 6 skipped, 0 failed). Real Accessibility-
permission, focus-race, and adversarial application evidence remains open.
Evidence: `evidence/2026-09-15-ui-type-boundary.md`.

BrokerStore Job state invariants are now enforced at the persistence readback
boundary (source revision `9f8a927`). Stored state/result
class combinations, lifecycle timestamps, lease fields, and cancellation
markers must agree or the row fails closed as `AUDIT_UNAVAILABLE`. A durable
running-Job cancellation revision also prevents a late `completed/success`
transition; recovery must retain `UNKNOWN`. Focused invariant and corruption
tests pass; persistence regression remains green. Disk-exhaustion, production
Keychain/code-signing identity, and ADR acceptance remain open. Evidence:
`evidence/2026-09-15-job-state-invariants.md`.

BrokerStore Request state invariants are now enforced at the persistence
readback boundary (source revision `f607f41`). `RECEIVED`, authorization,
intent, running, and terminal result classes are cross-checked with mutation
approval and Job linkage; timestamp rollback and malformed identifiers fail
closed as `AUDIT_UNAVAILABLE`. Focused request corruption tests pass 3/3; the
non-overlapping package regression passes 558 total (552 passed, 6 skipped, 0
failed). Evidence: `evidence/2026-09-15-request-state-invariants.md`.

Audit-event readback invariants are now enforced at the persistence boundary
(source revision `ed22f71`). Audit sequence ordering, bounded identity/text
fields, event/decision enums, timestamp, hash shape, and strict evidence JSON
are validated before audit verification or caller readback. Focused audit-row
corruption tests pass 1/1; the non-overlapping package regression passes 559
total (553 passed, 6 skipped, 0 failed). Evidence:
`evidence/2026-09-15-audit-row-invariants.md`.

Audit events are now validated before persistence as well as on readback
(source revision `3cc9c80`): malformed identity/text, event, decision,
timestamp, or evidence budgets fail closed before an SQLite row is written.
Focused audit write/read tests pass 2/2; the non-overlapping package
regression passes 560 total (554 passed, 6 skipped, 0 failed). Evidence:
`evidence/2026-09-15-audit-row-invariants.md`.

The current physical-host `mac_app_list` readback passes 4/4 at source revision
`c4bf986`, including the real running-app inventory case and fixed-command,
bounded-result, redaction, and malformed-result checks. This remains read-only
host evidence; GUI mutation, Accessibility permission, packaging, and final
readback gates remain open. Evidence:
`evidence/2026-09-15-app-inventory-host-readback.md`.

The current physical-host Accessibility probe for Finder fails closed with
stable `POLICY_DENIED` when Accessibility permission is absent, without
returning UI content. Permission-granted observation, focus races, GUI
mutation, packaging, and final readback remain open. Evidence:
`evidence/2026-09-15-ui-permission-denial-host-readback.md`.

The current production dependency audit reports zero high-severity-or-greater
npm advisories with `npm audit --omit=dev --audit-level=high`. This is
point-in-time dependency evidence only and does not close native signing,
runtime isolation, or release review gates. Evidence:
`evidence/2026-09-15-dependency-audit.md`.

The L5 privileged-helper boundary suite passes 38/38, covering independent
peer/HMAC authentication, replay rejection, fixed operation allowlists, typed
payloads, helper-owned status, trailing frames, denied peers, Job binding, and
active revocation. No root command or real privileged mutation was executed;
production signing, installation, Keychain, approval UI, and enablement remain
gated. Evidence: `evidence/2026-09-15-helper-boundary-38-tests.md`.

The helper/install-plan focused boundary suite passes 47/47 on the physical
macOS host at source revision `3d9e326`. It covers fixed per-user and
root-domain package plans, signature/readback binding, socket separation,
native peer identity, exact revision preconditions, host-only confirmation,
non-root rejection, and operation recovery. No root command, launchd
bootstrap, package install, reboot, shutdown, or privileged mutation was
executed. Developer ID provenance, protected production Keychain material,
real root-domain lifecycle, and independent release review remain open.
Evidence: `evidence/2026-09-15-helper-install-plan-47-tests.md`.

The local CI-equivalent canonical-JSON native check passes all 5/5 vectors and
`npm audit --audit-level=high` reports zero vulnerabilities at source revision
`48d5b12`. This is local, point-in-time evidence; it does not claim a remote
GitHub Actions run or close packaging, signing, runtime-isolation, or release
review gates. Evidence: `evidence/2026-09-15-ci-local-equivalent.md`.

BrokerStore Approval readback now enforces single-use lifecycle invariants at
source revision `28b26db`. Corrupted consumption counters, expiry ordering,
revocation pairing, identity/target/digest fields, and revision values fail
closed as `AUDIT_UNAVAILABLE` before approval authority is used. Focused
approval authority and corruption tests pass 14/14; protected production
Keychain/cross-process storage, human approval UI, unattended ownership, and
ADR acceptance remain open. Evidence:
`evidence/2026-09-15-approval-row-invariants.md`.

The non-overlapping package regression after the Approval readback change
reports 563 tests total (557 passed, 6 explicitly skipped, 0 failed). The
existing `broker.test.js` and `persistence.test.js` processes were excluded
because they were already running; no test was restarted or killed. Evidence:
`evidence/2026-09-15-approval-row-invariants.md`.

BrokerStore revocation and kill-switch readback now validates authority rows at
source revision `e11127e`. Malformed query identities fail with
`PRECONDITION_FAILED`; corrupted persisted rows fail closed as
`AUDIT_UNAVAILABLE` before policy, Job cancellation, or capability evaluation.
Focused Authority Control IPC, Policy, and corruption tests pass 15/15.
Production Keychain distribution, installed operator recovery, external
rollback detection, and ADR acceptance remain open. Evidence:
`evidence/2026-09-15-authority-row-invariants.md`.

The non-overlapping package regression after the authority-row change reports
565 tests total (559 passed, 6 explicitly skipped, 0 failed). The existing
`broker.test.js` and `persistence.test.js` processes were excluded because
they were already running; this remains bounded local evidence rather than a
fresh full-suite run. Evidence:
`evidence/2026-09-15-authority-row-invariants.md`.

Broker startup now scans all seven persisted replay ledgers after migration
and rejects malformed identities, nonce formats, timestamp ordering, or guest
ledger over-capacity as `AUDIT_UNAVAILABLE` before runtime or admission
decisions (source revision `100133e`). Focused replay corruption tests pass
7/7; the combined replay/Approval/Authority slice passes 12/12, and the
non-overlapping package regression passes 572 total (566 passed, 6 explicitly
skipped, 0 failed). Broader canonicalization, retention, protected Keychain,
installed recovery, external rollback detection, and ADR acceptance remain
open. Evidence: `evidence/2026-09-15-replay-row-invariants.md`.

Broker startup now validates every Policy/configuration history row and active
singleton after migration, binds active identities to matching history, and
repeats the checks in identity getters (source revision `7a34191`). Malformed
revisions, digests, timestamps, Policy metadata, or active/history mismatches
fail closed as `AUDIT_UNAVAILABLE`. Focused configuration plus Policy and
policy-signer tests pass 26/26; the non-overlapping package regression passes
579 total (573 passed, 6 explicitly skipped, 0 failed). Production Keychain
distribution, installed recovery, external rollback detection, and ADR
acceptance remain open. Evidence:
`evidence/2026-09-15-configuration-row-invariants.md`.

Restart reconciliation now rejects a recovery timestamp earlier than a
persisted Request received/updated time or Job created/start/heartbeat time
before any state transition (source revision `5148a8b`). Focused Request, Job,
and runtime tests pass 9/9; the non-overlapping package regression passes 582
total (576 passed, 6 explicitly skipped, 0 failed). Crash ownership, real
clock/rollback behavior, production Keychain, installed recovery, external
rollback detection, and ADR acceptance remain open. Evidence:
`evidence/2026-09-15-reconciliation-clock-order.md`.
