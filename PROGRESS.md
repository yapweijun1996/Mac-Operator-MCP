# Mac-Operator-MCP Progress

Status: Phase 1 Broker and authenticated MCP Edge foundation in progress
Version: 0.1
Last verified: 2026-09-14

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
- Implemented local Broker handlers: 39 of 44 planned.
- Enabled tools: 0 of 44 planned.
- Automated tests: 365 passing (two opt-in real-sandbox tests skipped by default).
- Real-Mac execution evidence: bounded local foundation, a synthetic temporary-repository Git staging/commit run, a real-host running-app inventory query, a real-host Finder Accessibility probe that failed closed without permission, and partial sandbox research records on Mac mini M4/macOS 26.2; UI action remains fixed-command/fake-adapter prototype evidence with no real app mutation or permission-granted release evidence.
- Remote MCP deployment: none.
- Privileged helper: protocol/IPC candidate only; no privileged process, adapter, signing, or enablement.
- Machine-readable tool contracts: 44 of 44 materialized with unique KB provenance; all remain planned, not implemented or enabled.

Percentages beyond these objective counts are intentionally omitted because the delivery scope and estimates are not yet baselined.

## Contract schema status

- Contract envelope schema: complete and validated for all 44 materialized contracts. This covers identity, capability, policy, budgets, lifecycle, audit, delivery wave, provenance, and summary fields.
- Per-tool functional input/output schema objects exist and compile for all 44 contracts. Success schemas use `SUCCEEDED`; failures use the shared stable-error schema.
- Schema presence is complete. Semantic review, compatibility fixtures, and runtime conformance remain limited to the thirty-six implemented handlers, so this is not a 44-tool implementation claim.

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
- Native peer-adapter packaging, Node socket-descriptor compatibility, Edge process-ID lifecycle, cross-process/keychain distribution, storage-level erasure limits, session concurrency, and canonicalization compatibility.
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
- Confirmed the runtime catalog reports all 44 tools separately; thirty-seven have local handlers, the production default enables none, and the read-enabled test policy enables only bounded read tools including `mac_app_list` and `mac_ui_observe` (the latter still fails closed when host Accessibility permission is absent).
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
