import { BrokerError, canonicalJson, sha256, type BrokerRequest } from "@mac-operator/contracts";
import type { BrokerJob, BrokerStore, JobLease } from "./persistence.js";
import type { ProcessOwnershipSnapshot } from "./process-supervisor.js";
import type { OwnerTerminalControl, OwnerTerminalExecutor, OwnerTerminalRequest } from "./owner-terminal.js";
import { redactBoundedText } from "./secret-policy.js";

export async function dispatchOwnerTerminal(options: {
  store: BrokerStore; executor: OwnerTerminalExecutor; request: BrokerRequest;
  terminal: OwnerTerminalRequest; job: BrokerJob; lease?: JobLease;
  control: OwnerTerminalControl; assertAuthority: () => void; now: () => number;
}) {
  const { store, request, terminal, executor, now } = options;
  let job = options.job;
  const makeResult = (reused: boolean) => ({
    data: { cwd: terminal.cwd, job_id: job.jobId, state: job.state, exit_code: job.exitCode,
      stdout: job.stdout, stderr: job.stderr, truncated: job.truncated, reused,
      execution_mode: "personal_owner_terminal" },
    verification: { required: true, status: "verified" as const, strategy: "exit_status_and_declared_task_verification",
      evidence: { summary: "The command exit and bounded output were observed; this is owner-account execution without sandbox isolation" } },
    warnings: ["Uses the macOS owner's permissions; command side effects are not isolated or automatically rolled back"],
    truncated: job.truncated, auditTarget: "host:owner-terminal",
    auditEvidence: { jobId: job.jobId, exitCode: job.exitCode, state: job.state, reused, mode: "personal_owner_terminal" }
  });
  if (job.state === "completed" || job.state === "failed") return makeResult(true);
  if (job.state === "unknown") throw new BrokerError("UNKNOWN_OUTCOME", `Terminal outcome is unresolved; inspect ${job.jobId}`);
  if (job.state === "cancelled") throw new BrokerError("CANCELLED", `Terminal command was cancelled; inspect ${job.jobId}`);
  if (job.state !== "running" || options.lease === undefined) throw new BrokerError("CONFLICT", `Terminal command is already queued or running; inspect ${job.jobId}`);
  const persist = (snapshot: ProcessOwnershipSnapshot, initial: boolean): void => {
    const metadata = { pid: snapshot.identity.pid, processGroupId: snapshot.identity.processGroupId,
      startTimeMicros: snapshot.identity.startTimeMicros, recordedAtMs: now(),
      taskDescriptorDigest: sha256(canonicalJson(request.arguments)), descendants: [...snapshot.descendants] };
    const current = store.ownedJob(job.jobId, request.principal.principalId);
    if (!current) throw new BrokerError("AUDIT_UNAVAILABLE", "Terminal Job disappeared during process observation");
    job = current;
    job = initial
      ? store.recordJobProcessOwnership(job.jobId, request.principal.principalId, job.revision, metadata, options.lease!, now())
      : store.updateJobProcessOwnership(job.jobId, request.principal.principalId, job.revision, metadata, options.lease!, now());
  };
  let persisted = false;
  try {
    options.assertAuthority();
    const result = await executor.run(terminal, { ...options.control,
      onProcessStarted: snapshot => persist(snapshot, true), onProcessOwnershipChanged: snapshot => persist(snapshot, false) });
    const stdout = redactBoundedText(result.stdout, 65_536);
    const stderr = redactBoundedText(result.stderr, 65_536);
    let current = store.ownedJob(job.jobId, request.principal.principalId);
    if (!current) throw new BrokerError("AUDIT_UNAVAILABLE", "Terminal Job disappeared before exit readback");
    if (result.state === "cancelled") {
      if (!result.terminationObserved) throw new BrokerError("UNKNOWN_OUTCOME", "Terminal cancellation could not be observed");
      if (!current.cancelRequested) {
        if (!options.control.shouldCancel()) throw new BrokerError("UNKNOWN_OUTCOME", "Terminal cancellation authority could not be confirmed");
        current = store.requestJobCancellation(job.jobId, request.principal.principalId, "OWNER_TERMINAL_AUTHORITY_CANCELLED", now()).job;
      }
    }
    job = store.finishJob(job.jobId, request.principal.principalId, current.revision, {
      state: result.state === "unknown" ? "unknown" : result.state === "cancelled" ? "cancelled" : result.state === "completed" ? "completed" : "failed",
      resultClass: result.state === "unknown" ? "unknown" : result.state === "cancelled" ? "denied" : result.state === "completed" ? "success" : "failed",
      finishedAtMs: now(), exitCode: result.exitCode, stdout: stdout.text, stderr: stderr.text,
      truncated: result.truncated || stdout.truncated || stderr.truncated
    }, options.lease, now());
    persisted = true;
    if (result.state === "unknown") throw new BrokerError("UNKNOWN_OUTCOME", `Terminal termination is uncertain; inspect ${job.jobId}`);
    if (result.state === "cancelled") throw new BrokerError("CANCELLED", `Terminal command was cancelled; inspect ${job.jobId}`);
    if (result.state === "timed_out") throw new BrokerError("TIMEOUT", `Terminal command timed out; inspect ${job.jobId}`);
    options.assertAuthority();
    return makeResult(false);
  } catch (error) {
    if (!persisted) {
      const current = store.ownedJob(job.jobId, request.principal.principalId);
      if (current?.state === "running") store.finishJob(job.jobId, request.principal.principalId, current.revision,
        { state: "unknown", resultClass: "unknown", finishedAtMs: now() }, options.lease, now());
    }
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("UNKNOWN_OUTCOME", `Terminal outcome could not be recorded; inspect ${job.jobId}`);
  }
}
