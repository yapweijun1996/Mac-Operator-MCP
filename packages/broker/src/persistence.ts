import { DatabaseSync } from "node:sqlite";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { assertContentDoesNotContainSecrets } from "./secret-policy.js";

export type SwitchName = "global" | "mutations" | "process" | "network" | "gui" | "destructive" | "privileged";
export type RevocationKind = "principal" | "session" | "edge" | "edge_key" | "approval_key" | "policy_signer";

export interface AuditEvent {
  requestId: string;
  principalId: string;
  tool: string;
  eventType: "decision" | "intent" | "completion";
  decision: "allow" | "deny";
  resultClass: string;
  targetRef: string;
  policyVersion: string;
  evidence: unknown;
  timestampMs: number;
}

export interface PolicyActivationIdentity {
  revision: number;
  version: string;
  payloadDigest: string;
  keyId: string;
  activatedAtMs: number;
}

export interface ApprovalKeyConfigActivationIdentity {
  revision: number;
  payloadDigest: string;
  activatedAtMs: number;
}

export interface PolicySignerConfigActivationIdentity {
  revision: number;
  payloadDigest: string;
  activatedAtMs: number;
}

export type JobState = "queued" | "running" | "completed" | "failed" | "cancelled" | "unknown";
export type JobResultClass = "success" | "denied" | "failed" | "verification_failed" | "queued" | "accepted" | "unknown";

export interface BrokerJob {
  jobId: string;
  ownerPrincipalId: string;
  ownerSessionId: string;
  tool: string;
  targetRef: string;
  policyVersion: string;
  payloadDigest: string;
  idempotencyKey: string;
  state: JobState;
  resultClass: JobResultClass;
  createdAtMs: number;
  startedAtMs: number | null;
  finishedAtMs: number | null;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  cancelRequested: boolean;
  revision: number;
}

export interface CreateJobInput {
  jobId: string;
  ownerPrincipalId: string;
  ownerSessionId: string;
  tool: string;
  targetRef: string;
  policyVersion: string;
  payloadDigest: string;
  idempotencyKey: string;
  createdAtMs: number;
}

export type RequestState =
  | "RECEIVED" | "AUTHORIZED" | "DENIED" | "INTENT_RECORDED" | "RUNNING"
  | "SUCCEEDED" | "FAILED" | "CANCELLED" | "TIMED_OUT" | "VERIFICATION_FAILED" | "UNKNOWN";

export interface RequestRecord {
  requestId: string;
  edgeId: string;
  principalId: string;
  sessionId: string;
  tool: string;
  policyVersion: string;
  payloadDigest: string;
  mutation: boolean;
  state: RequestState;
  resultClass: string | null;
  targetRef: string | null;
  approvalId: string | null;
  jobId: string | null;
  receivedAtMs: number;
  updatedAtMs: number;
  revision: number;
}

export interface AdmitRequestInput {
  requestId: string;
  edgeId: string;
  nonce: string;
  nonceExpiresAtMs: number;
  principalId: string;
  sessionId: string;
  tool: string;
  policyVersion: string;
  payloadDigest: string;
  mutation: boolean;
  receivedAtMs: number;
}

export type ApprovalClass = "trusted_write" | "trusted_gui" | "trusted_profile" | "explicit_privileged_policy";

export interface ApprovalRecord {
  approvalId: string;
  approverPrincipalId: string;
  requestingPrincipalId: string;
  tool: string;
  contractVersion: string;
  targetKind: string;
  targetRef: string;
  payloadDigest: string;
  policyVersion: string;
  approvalClass: ApprovalClass;
  unattended: boolean;
  issuedAtMs: number;
  expiresAtMs: number;
  useLimit: number;
  usedCount: number;
  lastConsumedAtMs: number | null;
  lastRequestId: string | null;
  revokedAtMs: number | null;
  revocationReason: string | null;
  revision: number;
}

export interface IssueApprovalInput {
  approvalId: string;
  approverPrincipalId: string;
  requestingPrincipalId: string;
  tool: string;
  contractVersion: string;
  targetKind: string;
  targetRef: string;
  payloadDigest: string;
  policyVersion: string;
  approvalClass: ApprovalClass;
  unattended: boolean;
  issuedAtMs: number;
  expiresAtMs: number;
  useLimit?: number;
}

export interface AuthenticatedApprovalIssuance {
  protocolVersion: "0.1";
  requestId: string;
  nonce: string;
  nonceExpiresAtMs: number;
  issuerId: string;
  keyId: string;
  timestampMs: number;
  issuanceDigest: string;
  previewDigest: string;
  approval: IssueApprovalInput;
}

export interface ApprovalConsumptionBinding {
  contractVersion: string;
  targetKind: string;
  targetRef: string;
  payloadDigest: string;
  approvalClass: ApprovalClass;
  unattended: boolean;
}

export interface AtomicJobAdmissionInput {
  request: AdmitRequestInput;
  decision: AuditEvent;
  intent: AuditEvent;
  approval: ApprovalConsumptionBinding;
  job: CreateJobInput;
}

export interface ApprovedJobAdmissionInput {
  intent: AuditEvent;
  approval: ApprovalConsumptionBinding;
  job: CreateJobInput;
}

/**
 * Test-only failure points for proving that atomic admission never exposes a
 * partially committed request, approval, audit event, or job. Production code
 * must leave this hook unset.
 */
export type PersistenceFaultPoint =
  | "admit_approved_job.after_request"
  | "admit_approved_job.after_authorization"
  | "admit_approved_job.after_approval"
  | "admit_approved_job.after_job"
  | "admit_approved_job_after_decision.after_approval"
  | "admit_approved_job_after_decision.after_job";

export interface BrokerStoreOptions {
  /** @internal Test-only; never configure this in a production Broker. */
  faultInjector?: (point: PersistenceFaultPoint) => void;
}

export class BrokerStore {
  private readonly database: DatabaseSync;
  private readonly faultInjector: ((point: PersistenceFaultPoint) => void) | undefined;

  constructor(path: string, options: BrokerStoreOptions = {}) {
    this.faultInjector = options.faultInjector;
    this.database = new DatabaseSync(path);
    this.database.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;");
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS nonces (
        edge_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        request_id TEXT NOT NULL,
        accepted_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        PRIMARY KEY (edge_id, nonce),
        UNIQUE (request_id)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS approval_nonces (
        issuer_id TEXT NOT NULL,
        key_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        request_id TEXT NOT NULL,
        accepted_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        PRIMARY KEY (issuer_id, key_id, nonce),
        UNIQUE (request_id)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS policy_signer_nonces (
        nonce TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        accepted_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS revocations (
        kind TEXT NOT NULL CHECK (kind IN ('principal', 'session', 'edge', 'edge_key', 'approval_key', 'policy_signer')),
        subject_id TEXT NOT NULL,
        revoked_at_ms INTEGER NOT NULL,
        reason TEXT NOT NULL,
        PRIMARY KEY (kind, subject_id)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS switches (
        name TEXT PRIMARY KEY,
        disabled INTEGER NOT NULL CHECK (disabled IN (0, 1)),
        changed_at_ms INTEGER NOT NULL,
        reason TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS audit_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        tool TEXT NOT NULL,
        event_type TEXT NOT NULL,
        decision TEXT NOT NULL,
        result_class TEXT NOT NULL,
        target_ref TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        timestamp_ms INTEGER NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE
      ) STRICT;
      CREATE TABLE IF NOT EXISTS policy_history (
        revision INTEGER PRIMARY KEY,
        version TEXT NOT NULL UNIQUE,
        payload_digest TEXT NOT NULL UNIQUE,
        key_id TEXT NOT NULL,
        activated_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS active_policy (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        revision INTEGER NOT NULL,
        version TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        key_id TEXT NOT NULL,
        activated_at_ms INTEGER NOT NULL,
        FOREIGN KEY (revision) REFERENCES policy_history(revision)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS approval_key_config_history (
        revision INTEGER PRIMARY KEY,
        payload_digest TEXT NOT NULL UNIQUE,
        activated_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS active_approval_key_config (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        revision INTEGER NOT NULL,
        payload_digest TEXT NOT NULL,
        activated_at_ms INTEGER NOT NULL,
        FOREIGN KEY (revision) REFERENCES approval_key_config_history(revision)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS policy_signer_config_history (
        revision INTEGER PRIMARY KEY,
        payload_digest TEXT NOT NULL UNIQUE,
        activated_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS active_policy_signer_config (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        revision INTEGER NOT NULL,
        payload_digest TEXT NOT NULL,
        activated_at_ms INTEGER NOT NULL,
        FOREIGN KEY (revision) REFERENCES policy_signer_config_history(revision)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY,
        owner_principal_id TEXT NOT NULL,
        owner_session_id TEXT NOT NULL,
        tool TEXT NOT NULL,
        target_ref TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'unknown')),
        result_class TEXT NOT NULL CHECK (result_class IN ('success', 'denied', 'failed', 'verification_failed', 'queued', 'accepted', 'unknown')),
        created_at_ms INTEGER NOT NULL,
        started_at_ms INTEGER,
        finished_at_ms INTEGER,
        exit_code INTEGER,
        stdout_text TEXT NOT NULL,
        stderr_text TEXT NOT NULL,
        output_truncated INTEGER NOT NULL CHECK (output_truncated IN (0, 1)),
        cancel_requested INTEGER NOT NULL CHECK (cancel_requested IN (0, 1)),
        cancel_reason TEXT,
        revision INTEGER NOT NULL,
        UNIQUE (owner_principal_id, idempotency_key)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS requests (
        request_id TEXT PRIMARY KEY,
        edge_id TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        tool TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        mutation INTEGER NOT NULL CHECK (mutation IN (0, 1)),
        state TEXT NOT NULL CHECK (state IN (
          'RECEIVED', 'AUTHORIZED', 'DENIED', 'INTENT_RECORDED', 'RUNNING',
          'SUCCEEDED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'VERIFICATION_FAILED', 'UNKNOWN'
        )),
        result_class TEXT,
        target_ref TEXT,
        approval_id TEXT,
        job_id TEXT,
        received_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        revision INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS approvals (
        approval_id TEXT PRIMARY KEY,
        approver_principal_id TEXT NOT NULL,
        requesting_principal_id TEXT NOT NULL,
        tool TEXT NOT NULL,
        contract_version TEXT NOT NULL,
        target_kind TEXT NOT NULL,
        target_ref TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        approval_class TEXT NOT NULL CHECK (approval_class IN (
          'trusted_write', 'trusted_gui', 'trusted_profile', 'explicit_privileged_policy'
        )),
        unattended INTEGER NOT NULL CHECK (unattended IN (0, 1)),
        issued_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        use_limit INTEGER NOT NULL CHECK (use_limit = 1),
        used_count INTEGER NOT NULL CHECK (used_count IN (0, 1)),
        last_consumed_at_ms INTEGER,
        last_request_id TEXT,
        revoked_at_ms INTEGER,
        revocation_reason TEXT,
        revision INTEGER NOT NULL
      ) STRICT;
      CREATE INDEX IF NOT EXISTS approvals_match_idx ON approvals(
        requesting_principal_id, tool, contract_version, target_kind, target_ref,
        payload_digest, policy_version, approval_class, issued_at_ms, approval_id
      );
    `);
    this.migrateRevocationsSchema();
    this.migrateRequestsSchema();
    this.verifyAuditIntegrity();
    this.reconcileInterruptedRequests(Date.now());
    this.reconcileInterruptedJobs(Date.now());
  }

  close(): void {
    this.database.close();
  }

  admitRequest(input: AdmitRequestInput): RequestRecord {
    validateRequestAdmission(input);
    try {
      return this.runTransaction(() => {
        this.database.prepare("DELETE FROM nonces WHERE expires_at_ms < ?").run(input.receivedAtMs);
        this.database.prepare(
          "INSERT INTO nonces(edge_id, nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?)"
        ).run(input.edgeId, input.nonce, input.requestId, input.receivedAtMs, input.nonceExpiresAtMs);
        this.database.prepare(`
          INSERT INTO requests(
            request_id, edge_id, principal_id, session_id, tool, policy_version, payload_digest,
            mutation, state, result_class, target_ref, received_at_ms, updated_at_ms, revision
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'RECEIVED', NULL, NULL, ?, ?, 0)
        `).run(
          input.requestId, input.edgeId, input.principalId, input.sessionId, input.tool,
          input.policyVersion, input.payloadDigest, input.mutation ? 1 : 0,
          input.receivedAtMs, input.receivedAtMs
        );
        return this.requireRequest(input.requestId);
      });
    } catch (error) {
      if (String(error).includes("UNIQUE constraint failed")) {
        throw new BrokerError("REPLAY_DENIED", "Request nonce or request ID was already accepted");
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Request admission could not be persisted");
    }
  }

  requestRecord(requestId: string): RequestRecord | undefined {
    const row = this.database.prepare("SELECT * FROM requests WHERE request_id = ?").get(requestId) as RequestRow | undefined;
    return row ? mapRequest(row) : undefined;
  }

  admitApprovedJob(input: AtomicJobAdmissionInput): { request: RequestRecord; job: BrokerJob; reused: boolean } {
    validateRequestAdmission(input.request);
    validateApprovalBinding(input.approval);
    validateJobCreation(input.job);
    if (!input.request.mutation || input.decision.eventType !== "decision" || input.decision.decision !== "allow" ||
        input.decision.resultClass !== "AUTHORIZED" || input.intent.eventType !== "intent" ||
        input.intent.decision !== "allow" || input.intent.resultClass !== "INTENT_RECORDED" ||
        input.decision.requestId !== input.request.requestId || input.intent.requestId !== input.request.requestId ||
        input.job.ownerPrincipalId !== input.request.principalId || input.job.ownerSessionId !== input.request.sessionId ||
        input.job.tool !== input.request.tool || input.job.policyVersion !== input.request.policyVersion ||
        input.intent.targetRef !== input.decision.targetRef || input.approval.targetRef !== input.decision.targetRef ||
        input.intent.timestampMs < input.decision.timestampMs || input.job.createdAtMs < input.intent.timestampMs ||
        !validAuditTimestamp(input.decision.timestampMs) || !validAuditTimestamp(input.intent.timestampMs) ||
        !validAuditTarget(input.decision.targetRef) || !validAuditTarget(input.intent.targetRef)) {
      throw malformedRequest();
    }
    try {
      return this.runTransaction(() => {
        this.database.prepare("DELETE FROM nonces WHERE expires_at_ms < ?").run(input.request.receivedAtMs);
        this.database.prepare(
          "INSERT INTO nonces(edge_id, nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?)"
        ).run(
          input.request.edgeId, input.request.nonce, input.request.requestId,
          input.request.receivedAtMs, input.request.nonceExpiresAtMs
        );
        this.database.prepare(`
          INSERT INTO requests(
            request_id, edge_id, principal_id, session_id, tool, policy_version, payload_digest,
            mutation, state, result_class, target_ref, approval_id, job_id, received_at_ms, updated_at_ms, revision
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'RECEIVED', NULL, NULL, NULL, NULL, ?, ?, 0)
        `).run(
          input.request.requestId, input.request.edgeId, input.request.principalId, input.request.sessionId,
          input.request.tool, input.request.policyVersion, input.request.payloadDigest,
          input.request.receivedAtMs, input.request.receivedAtMs
        );
        this.injectFault("admit_approved_job.after_request");
        const received = this.requireRequest(input.request.requestId);
        assertAuditMatchesRequest(input.decision, received);
        this.insertAudit(input.decision);
        this.database.prepare(`
          UPDATE requests SET state = 'AUTHORIZED', result_class = 'AUTHORIZED', target_ref = ?,
            updated_at_ms = ?, revision = revision + 1 WHERE request_id = ? AND revision = 0
        `).run(input.decision.targetRef, input.decision.timestampMs, input.request.requestId);
        this.injectFault("admit_approved_job.after_authorization");

        const existing = this.database.prepare(
          "SELECT * FROM jobs WHERE owner_principal_id = ? AND idempotency_key = ?"
        ).get(input.job.ownerPrincipalId, input.job.idempotencyKey) as JobRow | undefined;
        if (existing) {
          if (existing.payload_digest !== input.job.payloadDigest || existing.tool !== input.job.tool ||
              existing.target_ref !== input.job.targetRef || existing.policy_version !== input.job.policyVersion) {
            throw new BrokerError("CONFLICT", "Idempotency key was already used for a different job payload");
          }
          const reused = mapJob(existing);
          const completion: AuditEvent = {
            requestId: input.request.requestId,
            principalId: input.request.principalId,
            tool: input.request.tool,
            eventType: "completion",
            decision: "allow",
            resultClass: "IDEMPOTENT_REUSE",
            targetRef: input.decision.targetRef,
            policyVersion: input.request.policyVersion,
            evidence: { jobId: reused.jobId, reused: true },
            timestampMs: input.intent.timestampMs
          };
          this.insertAudit(completion);
          this.database.prepare(`
            UPDATE requests SET state = 'SUCCEEDED', result_class = ?, target_ref = ?, job_id = ?,
              updated_at_ms = ?, revision = revision + 1 WHERE request_id = ? AND revision = 1
          `).run(completion.resultClass, completion.targetRef, reused.jobId, completion.timestampMs, input.request.requestId);
          return { request: this.requireRequest(input.request.requestId), job: reused, reused: true };
        }

        const approvalRow = this.findConsumableApproval(input.request.principalId, input.request.tool,
          input.request.policyVersion, input.approval, input.intent.timestampMs);
        if (!approvalRow) throw new BrokerError("POLICY_DENIED", "No valid approval matches this mutation");
        const approval = mapApproval(approvalRow);
        const consumed = this.database.prepare(`
          UPDATE approvals SET used_count = used_count + 1, last_consumed_at_ms = ?, last_request_id = ?, revision = revision + 1
          WHERE approval_id = ? AND revision = ? AND revoked_at_ms IS NULL AND used_count < use_limit
        `).run(input.intent.timestampMs, input.request.requestId, approval.approvalId, approval.revision);
        if (consumed.changes !== 1) throw new BrokerError("CONFLICT", "Approval changed concurrently");
        this.injectFault("admit_approved_job.after_approval");
        this.insertAudit({
          ...input.intent,
          evidence: { ...asEvidenceRecord(input.intent.evidence), approvalId: approval.approvalId, approvalClass: approval.approvalClass, jobId: input.job.jobId }
        });
        this.database.prepare(`
          INSERT INTO jobs(
            job_id, owner_principal_id, owner_session_id, tool, target_ref, policy_version,
            payload_digest, idempotency_key, state, result_class, created_at_ms, started_at_ms,
            finished_at_ms, exit_code, stdout_text, stderr_text, output_truncated,
            cancel_requested, cancel_reason, revision
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'queued', ?, NULL, NULL, NULL, '', '', 0, 0, NULL, 0)
        `).run(
          input.job.jobId, input.job.ownerPrincipalId, input.job.ownerSessionId, input.job.tool,
          input.job.targetRef, input.job.policyVersion, input.job.payloadDigest, input.job.idempotencyKey,
          input.job.createdAtMs
        );
        this.injectFault("admit_approved_job.after_job");
        const transitioned = this.database.prepare(`
          UPDATE requests SET state = 'INTENT_RECORDED', result_class = 'INTENT_RECORDED',
            target_ref = ?, approval_id = ?, job_id = ?, updated_at_ms = ?, revision = revision + 1
          WHERE request_id = ? AND revision = 1
        `).run(input.intent.targetRef, approval.approvalId, input.job.jobId, input.intent.timestampMs, input.request.requestId);
        if (transitioned.changes !== 1) throw new BrokerError("CONFLICT", "Request revision changed concurrently");
        return {
          request: this.requireRequest(input.request.requestId),
          job: this.requireOwnedJob(input.job.jobId, input.job.ownerPrincipalId),
          reused: false
        };
      });
    } catch (error) {
      if (String(error).includes("UNIQUE constraint failed")) {
        throw new BrokerError(
          String(error).includes("jobs.job_id") ? "CONFLICT" : "REPLAY_DENIED",
          String(error).includes("jobs.job_id") ? "Job ID was already used" : "Request identity was already accepted"
        );
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Atomic job admission could not be persisted");
    }
  }

  issueApproval(input: IssueApprovalInput): ApprovalRecord {
    validateApprovalIssue(input);
    try {
      return this.runTransaction(() => {
        this.database.prepare(`
          INSERT INTO approvals(
            approval_id, approver_principal_id, requesting_principal_id, tool, contract_version,
            target_kind, target_ref, payload_digest, policy_version, approval_class, unattended,
            issued_at_ms, expires_at_ms, use_limit, used_count, last_consumed_at_ms,
            last_request_id, revoked_at_ms, revocation_reason, revision
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, NULL, 0)
        `).run(
          input.approvalId, input.approverPrincipalId, input.requestingPrincipalId, input.tool,
          input.contractVersion, input.targetKind, input.targetRef, input.payloadDigest,
          input.policyVersion, input.approvalClass, input.unattended ? 1 : 0,
          input.issuedAtMs, input.expiresAtMs, input.useLimit ?? 1
        );
        this.insertAudit({
          requestId: `approval-issue:${input.approvalId}`,
          principalId: input.approverPrincipalId,
          tool: "internal_approval_issue",
          eventType: "completion",
          decision: "allow",
          resultClass: "SUCCEEDED",
          targetRef: `approval:${input.approvalId}`,
          policyVersion: input.policyVersion,
          evidence: {
            requestingPrincipalId: input.requestingPrincipalId,
            tool: input.tool,
            contractVersion: input.contractVersion,
            targetKind: input.targetKind,
            targetRef: input.targetRef,
            payloadDigest: input.payloadDigest,
            approvalClass: input.approvalClass,
            unattended: input.unattended,
            expiresAtMs: input.expiresAtMs,
            useLimit: input.useLimit ?? 1
          },
          timestampMs: input.issuedAtMs
        });
        return this.requireApproval(input.approvalId);
      });
    } catch (error) {
      if (String(error).includes("UNIQUE constraint failed")) {
        throw new BrokerError("CONFLICT", "Approval ID was already issued");
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Approval issuance could not be persisted");
    }
  }

  issueAuthenticatedApproval(input: AuthenticatedApprovalIssuance): ApprovalRecord {
    validateAuthenticatedApprovalIssuance(input);
    try {
      return this.runTransaction(() => {
        this.database.prepare("DELETE FROM approval_nonces WHERE expires_at_ms < ?").run(input.timestampMs);
        this.database.prepare(`
          INSERT INTO approval_nonces(issuer_id, key_id, nonce, request_id, accepted_at_ms, expires_at_ms)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(
          input.issuerId, input.keyId, input.nonce, input.requestId,
          input.timestampMs, input.nonceExpiresAtMs
        );
        this.database.prepare(`
          INSERT INTO approvals(
            approval_id, approver_principal_id, requesting_principal_id, tool, contract_version,
            target_kind, target_ref, payload_digest, policy_version, approval_class, unattended,
            issued_at_ms, expires_at_ms, use_limit, used_count, last_consumed_at_ms,
            last_request_id, revoked_at_ms, revocation_reason, revision
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, NULL, 0)
        `).run(
          input.approval.approvalId, input.approval.approverPrincipalId, input.approval.requestingPrincipalId,
          input.approval.tool, input.approval.contractVersion, input.approval.targetKind, input.approval.targetRef,
          input.approval.payloadDigest, input.approval.policyVersion, input.approval.approvalClass,
          input.approval.unattended ? 1 : 0, input.approval.issuedAtMs, input.approval.expiresAtMs,
          input.approval.useLimit ?? 1
        );
        const targetRef = `approval:${input.approval.approvalId}`;
        const evidence = {
          approvalId: input.approval.approvalId,
          issuerId: input.issuerId,
          issuerKeyId: input.keyId,
          issuanceDigest: input.issuanceDigest,
          previewDigest: input.previewDigest,
          nonce: input.nonce,
          requestingPrincipalId: input.approval.requestingPrincipalId,
          tool: input.approval.tool,
          contractVersion: input.approval.contractVersion,
          targetKind: input.approval.targetKind,
          targetRef: input.approval.targetRef,
          payloadDigest: input.approval.payloadDigest,
          policyVersion: input.approval.policyVersion,
          approvalClass: input.approval.approvalClass,
          unattended: input.approval.unattended,
          expiresAtMs: input.approval.expiresAtMs,
          useLimit: input.approval.useLimit ?? 1
        };
        this.insertAudit({
          requestId: input.requestId,
          principalId: input.issuerId,
          tool: "internal_approval_issue",
          eventType: "decision",
          decision: "allow",
          resultClass: "AUTHORIZED",
          targetRef,
          policyVersion: input.approval.policyVersion,
          evidence,
          timestampMs: input.timestampMs
        });
        this.insertAudit({
          requestId: input.requestId,
          principalId: input.issuerId,
          tool: "internal_approval_issue",
          eventType: "completion",
          decision: "allow",
          resultClass: "SUCCEEDED",
          targetRef,
          policyVersion: input.approval.policyVersion,
          evidence: { ...evidence, persisted: true },
          timestampMs: input.timestampMs
        });
        return this.requireApproval(input.approval.approvalId);
      });
    } catch (error) {
      if (String(error).includes("approval_nonces")) {
        throw new BrokerError("REPLAY_DENIED", "Approval issuance nonce or request ID was already accepted");
      }
      if (String(error).includes("approvals.approval_id")) {
        throw new BrokerError("CONFLICT", "Approval ID was already issued");
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Authenticated approval issuance could not be persisted");
    }
  }

  approvalRecord(approvalId: string): ApprovalRecord | undefined {
    const row = this.database.prepare("SELECT * FROM approvals WHERE approval_id = ?").get(approvalId) as ApprovalRow | undefined;
    return row ? mapApproval(row) : undefined;
  }

  revokeApproval(approvalId: string, reason: string, nowMs: number): ApprovalRecord {
    if (!validApprovalId(approvalId) || !/^[A-Z0-9_:-]{1,64}$/u.test(reason) ||
        !Number.isSafeInteger(nowMs) || nowMs < 0) throw malformedApproval();
    try {
      return this.runTransaction(() => {
        const current = this.requireApproval(approvalId);
        if (current.revokedAtMs !== null) return current;
        if (nowMs < current.issuedAtMs) throw malformedApproval();
        this.database.prepare(`
          UPDATE approvals SET revoked_at_ms = ?, revocation_reason = ?, revision = revision + 1
          WHERE approval_id = ? AND revision = ?
        `).run(nowMs, reason, approvalId, current.revision);
        this.insertAudit({
          requestId: `approval-revoke:${approvalId}:${current.revision + 1}`,
          principalId: current.approverPrincipalId,
          tool: "internal_approval_revoke",
          eventType: "completion",
          decision: "allow",
          resultClass: "REVOKED",
          targetRef: `approval:${approvalId}`,
          policyVersion: current.policyVersion,
          evidence: { reason, revision: current.revision + 1 },
          timestampMs: nowMs
        });
        return this.requireApproval(approvalId);
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Approval revocation could not be persisted");
    }
  }

  recordRequestDecision(event: AuditEvent): RequestRecord {
    if (event.eventType !== "decision" || (event.decision === "allow") !== (event.resultClass === "AUTHORIZED")) {
      throw malformedRequest();
    }
    const nextState: RequestState = event.decision === "allow" ? "AUTHORIZED" : "DENIED";
    return this.persistRequestAudit(() => this.transitionRequest(
      event.requestId,
      ["RECEIVED"],
      nextState,
      event.resultClass,
      event.targetRef,
      event.timestampMs,
      (current) => {
        assertAuditMatchesRequest(event, current);
        this.insertAudit(event);
      }
    ));
  }

  recordRequestIntent(event: AuditEvent, binding: ApprovalConsumptionBinding): RequestRecord {
    if (event.eventType !== "intent" || event.decision !== "allow" || event.resultClass !== "INTENT_RECORDED") {
      throw malformedRequest();
    }
    validateApprovalBinding(binding);
    return this.persistRequestAudit(() => this.runTransaction(() => {
      const current = this.requireRequest(event.requestId);
      if (!current.mutation || current.state !== "AUTHORIZED" || event.timestampMs < current.updatedAtMs ||
          current.targetRef !== binding.targetRef || event.targetRef !== binding.targetRef) {
        throw new BrokerError("CONFLICT", "Request state changed or approval target does not match authorization");
      }
      assertAuditMatchesRequest(event, current);
      const row = this.findConsumableApproval(current.principalId, current.tool, current.policyVersion, binding, event.timestampMs);
      if (!row) throw new BrokerError("POLICY_DENIED", "No valid approval matches this mutation");
      const approval = mapApproval(row);
      const consumed = this.database.prepare(`
        UPDATE approvals SET used_count = used_count + 1, last_consumed_at_ms = ?, last_request_id = ?, revision = revision + 1
        WHERE approval_id = ? AND revision = ? AND revoked_at_ms IS NULL AND used_count < use_limit
      `).run(event.timestampMs, current.requestId, approval.approvalId, approval.revision);
      if (consumed.changes !== 1) throw new BrokerError("CONFLICT", "Approval changed concurrently");
      this.insertAudit({
        ...event,
        evidence: { ...asEvidenceRecord(event.evidence), approvalId: approval.approvalId, approvalClass: approval.approvalClass }
      });
      const transitioned = this.database.prepare(`
        UPDATE requests SET state = 'INTENT_RECORDED', result_class = ?, target_ref = ?, approval_id = ?,
          updated_at_ms = ?, revision = revision + 1 WHERE request_id = ? AND revision = ?
      `).run(event.resultClass, event.targetRef, approval.approvalId, event.timestampMs, current.requestId, current.revision);
      if (transitioned.changes !== 1) throw new BrokerError("CONFLICT", "Request revision changed concurrently");
      return this.requireRequest(current.requestId);
    }));
  }

  admitApprovedJobAfterDecision(input: ApprovedJobAdmissionInput): { request: RequestRecord; job: BrokerJob } {
    if (input.intent.eventType !== "intent" || input.intent.decision !== "allow" || input.intent.resultClass !== "INTENT_RECORDED" ||
        !validAuditTimestamp(input.intent.timestampMs) || !validAuditTarget(input.intent.targetRef) ||
        input.approval.targetRef !== input.intent.targetRef || input.job.payloadDigest !== input.approval.payloadDigest ||
        input.job.createdAtMs < input.intent.timestampMs) {
      throw malformedRequest();
    }
    validateApprovalBinding(input.approval);
    validateJobCreation(input.job);
    try {
      return this.runTransaction(() => {
        const current = this.requireRequest(input.intent.requestId);
        if (!current.mutation || current.state !== "AUTHORIZED" || input.intent.timestampMs < current.updatedAtMs ||
            current.targetRef !== input.intent.targetRef || input.job.ownerPrincipalId !== current.principalId ||
            input.job.ownerSessionId !== current.sessionId || input.job.tool !== current.tool ||
            input.job.policyVersion !== current.policyVersion || input.job.targetRef !== input.intent.targetRef) {
          throw new BrokerError("CONFLICT", "Request state or approved Job identity changed");
        }
        assertAuditMatchesRequest(input.intent, current);
        const row = this.findConsumableApproval(current.principalId, current.tool, current.policyVersion, input.approval, input.intent.timestampMs);
        if (!row) throw new BrokerError("POLICY_DENIED", "No valid approval matches this mutation");
        const approval = mapApproval(row);
        const consumed = this.database.prepare(`
          UPDATE approvals SET used_count = used_count + 1, last_consumed_at_ms = ?, last_request_id = ?, revision = revision + 1
          WHERE approval_id = ? AND revision = ? AND revoked_at_ms IS NULL AND used_count < use_limit
        `).run(input.intent.timestampMs, current.requestId, approval.approvalId, approval.revision);
        if (consumed.changes !== 1) throw new BrokerError("CONFLICT", "Approval changed concurrently");
        this.injectFault("admit_approved_job_after_decision.after_approval");
        this.insertAudit({
          ...input.intent,
          evidence: {
            ...asEvidenceRecord(input.intent.evidence),
            approvalId: approval.approvalId,
            approvalClass: approval.approvalClass,
            jobId: input.job.jobId
          }
        });
        this.database.prepare(`
          INSERT INTO jobs(
            job_id, owner_principal_id, owner_session_id, tool, target_ref, policy_version,
            payload_digest, idempotency_key, state, result_class, created_at_ms, started_at_ms,
            finished_at_ms, exit_code, stdout_text, stderr_text, output_truncated,
            cancel_requested, cancel_reason, revision
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'queued', ?, NULL, NULL, NULL, '', '', 0, 0, NULL, 0)
        `).run(
          input.job.jobId, input.job.ownerPrincipalId, input.job.ownerSessionId, input.job.tool,
          input.job.targetRef, input.job.policyVersion, input.job.payloadDigest, input.job.idempotencyKey,
          input.job.createdAtMs
        );
        this.injectFault("admit_approved_job_after_decision.after_job");
        const transitioned = this.database.prepare(`
          UPDATE requests SET state = 'INTENT_RECORDED', result_class = 'INTENT_RECORDED',
            target_ref = ?, approval_id = ?, job_id = ?, updated_at_ms = ?, revision = revision + 1
          WHERE request_id = ? AND revision = ?
        `).run(input.intent.targetRef, approval.approvalId, input.job.jobId, input.intent.timestampMs, current.requestId, current.revision);
        if (transitioned.changes !== 1) throw new BrokerError("CONFLICT", "Request revision changed concurrently");
        return {
          request: this.requireRequest(current.requestId),
          job: this.requireOwnedJob(input.job.jobId, input.job.ownerPrincipalId)
        };
      });
    } catch (error) {
      if (String(error).includes("UNIQUE constraint failed")) {
        throw new BrokerError("CONFLICT", "Approved Job identity was already used");
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Approved Job admission could not be persisted");
    }
  }

  markRequestRunning(requestId: string, nowMs: number): RequestRecord {
    const current = this.requireRequest(requestId);
    const expected: RequestState = current.mutation ? "INTENT_RECORDED" : "AUTHORIZED";
    return this.transitionRequest(
      requestId,
      [expected],
      "RUNNING",
      "RUNNING",
      current.targetRef,
      nowMs,
      (transitioning) => {
        if (transitioning.mutation) this.assertRequestApprovalActive(transitioning, nowMs);
      }
    );
  }

  completeRequest(event: AuditEvent): RequestRecord {
    if (event.eventType !== "completion" || event.decision !== "allow" || event.resultClass !== "SUCCEEDED") {
      throw malformedRequest();
    }
    return this.persistRequestAudit(() => this.transitionRequest(event.requestId, ["RUNNING"], "SUCCEEDED", event.resultClass, event.targetRef, event.timestampMs, (current) => {
      assertAuditMatchesRequest(event, current);
      this.insertAudit(event);
    }));
  }

  failRequest(event: AuditEvent): RequestRecord {
    if (["AUTHORIZED", "INTENT_RECORDED", "RUNNING", "SUCCEEDED"].includes(event.resultClass)) {
      throw malformedRequest();
    }
    const current = this.requireRequest(event.requestId);
    if (isTerminalRequestState(current.state)) return current;
    const beforeDecision = current.state === "RECEIVED";
    const terminalState = beforeDecision ? "DENIED" : failureRequestState(event.resultClass);
    const normalizedEvent: AuditEvent = {
      ...event,
      eventType: beforeDecision ? "decision" : "completion",
      decision: beforeDecision ? "deny" : "allow"
    };
    return this.persistRequestAudit(() => this.transitionRequest(
      event.requestId,
      [current.state],
      terminalState,
      event.resultClass,
      event.targetRef,
      event.timestampMs,
      (transitioning) => {
        assertAuditMatchesRequest(normalizedEvent, transitioning);
        this.insertAudit(normalizedEvent);
      }
    ));
  }

  reconcileInterruptedRequests(nowMs: number): { failed: number; unknown: number } {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw malformedRequest();
    return this.runTransaction(() => {
      const rows = this.database.prepare(`
        SELECT * FROM requests WHERE state IN ('RECEIVED', 'AUTHORIZED', 'INTENT_RECORDED', 'RUNNING')
        ORDER BY received_at_ms, request_id
      `).all() as unknown as RequestRow[];
      let failed = 0;
      let unknown = 0;
      for (const row of rows) {
        const current = mapRequest(row);
        const nextState: RequestState = current.state === "RUNNING" && current.mutation ? "UNKNOWN" : "FAILED";
        const resultClass = nextState === "UNKNOWN" ? "UNKNOWN_OUTCOME" : "EXECUTION_FAILED";
        this.database.prepare(`
          UPDATE requests SET state = ?, result_class = ?, updated_at_ms = ?, revision = revision + 1
          WHERE request_id = ? AND revision = ?
        `).run(nextState, resultClass, nowMs, current.requestId, current.revision);
        if (nextState === "UNKNOWN") unknown += 1;
        else failed += 1;
        this.insertAudit({
          requestId: current.requestId,
          principalId: current.principalId,
          tool: "internal_request_reconcile",
          eventType: current.state === "RECEIVED" ? "decision" : "completion",
          decision: current.state === "RECEIVED" ? "deny" : "allow",
          resultClass,
          targetRef: current.targetRef ?? "unresolved",
          policyVersion: current.policyVersion,
          evidence: { priorState: current.state, nextState, revision: current.revision + 1 },
          timestampMs: nowMs
        });
      }
      return { failed, unknown };
    });
  }

  revoke(kind: RevocationKind, subjectId: string, reason: string, nowMs = Date.now()): void {
    this.database.prepare(
      "INSERT INTO revocations(kind, subject_id, revoked_at_ms, reason) VALUES (?, ?, ?, ?) ON CONFLICT(kind, subject_id) DO UPDATE SET revoked_at_ms=excluded.revoked_at_ms, reason=excluded.reason"
    ).run(kind, subjectId, nowMs, reason);
  }

  isRevoked(kind: RevocationKind, subjectId: string): boolean {
    return this.database.prepare("SELECT 1 FROM revocations WHERE kind = ? AND subject_id = ?").get(kind, subjectId) !== undefined;
  }

  admitPolicySignerCommand(input: {
    requestId: string;
    nonce: string;
    acceptedAtMs: number;
    expiresAtMs: number;
  }): void {
    if (!/^[A-Za-z0-9._:-]{1,128}$/u.test(input.requestId) ||
        !/^[A-Za-z0-9._:-]{16,128}$/u.test(input.nonce) ||
        !Number.isSafeInteger(input.acceptedAtMs) || input.acceptedAtMs < 0 ||
        !Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= input.acceptedAtMs) {
      throw new BrokerError("PRECONDITION_FAILED", "Policy signer command admission is malformed");
    }
    try {
      this.runTransaction(() => {
        this.database.prepare("DELETE FROM policy_signer_nonces WHERE expires_at_ms < ?").run(input.acceptedAtMs);
        this.database.prepare(
          "INSERT INTO policy_signer_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
        ).run(input.nonce, input.requestId, input.acceptedAtMs, input.expiresAtMs);
      });
    } catch (error) {
      if (String(error).includes("UNIQUE constraint failed")) {
        throw new BrokerError("REPLAY_DENIED", "Policy signer command nonce or request ID was already accepted");
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Policy signer command admission could not be persisted");
    }
  }

  revokePolicySigner(keyId: string, reason: string, nowMs = Date.now()): void {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(keyId) ||
        typeof reason !== "string" || reason.length < 1 || reason.length > 128 ||
        !Number.isSafeInteger(nowMs) || nowMs < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Policy signer revocation is malformed");
    }
    try {
      this.runTransaction(() => {
        const requestId = `policy-signer-revoke-${keyId}-${sha256(canonicalJson({ keyId, reason, nowMs })).slice(0, 16)}`;
        const auditBase = {
          requestId,
          principalId: "local-policy-signer-operator",
          tool: "internal_policy_signer_revoke",
          decision: "allow" as const,
          targetRef: `policy-signer:${keyId}`,
          policyVersion: "internal-policy-signer-config-0.1",
          evidence: { keyId, reason },
          timestampMs: nowMs
        };
        this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
        this.database.prepare(
          "INSERT INTO revocations(kind, subject_id, revoked_at_ms, reason) VALUES ('policy_signer', ?, ?, ?) ON CONFLICT(kind, subject_id) DO UPDATE SET revoked_at_ms=excluded.revoked_at_ms, reason=excluded.reason"
        ).run(keyId, nowMs, reason);
        this.insertAudit({ ...auditBase, eventType: "completion", resultClass: "SUCCEEDED" });
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Policy signer revocation could not be persisted");
    }
  }

  setSwitch(name: SwitchName, disabled: boolean, reason: string, nowMs = Date.now()): void {
    this.database.prepare(
      "INSERT INTO switches(name, disabled, changed_at_ms, reason) VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET disabled=excluded.disabled, changed_at_ms=excluded.changed_at_ms, reason=excluded.reason"
    ).run(name, disabled ? 1 : 0, nowMs, reason);
  }

  isSwitchDisabled(name: SwitchName): boolean {
    const row = this.database.prepare("SELECT disabled FROM switches WHERE name = ?").get(name) as { disabled: number } | undefined;
    return row?.disabled === 1;
  }

  createJob(input: CreateJobInput): { job: BrokerJob; reused: boolean } {
    validateJobCreation(input);
    return this.runTransaction(() => {
      const existing = this.database.prepare(
        "SELECT * FROM jobs WHERE owner_principal_id = ? AND idempotency_key = ?"
      ).get(input.ownerPrincipalId, input.idempotencyKey) as JobRow | undefined;
      if (existing) {
        if (existing.payload_digest !== input.payloadDigest || existing.tool !== input.tool || existing.target_ref !== input.targetRef) {
          throw new BrokerError("CONFLICT", "Idempotency key was already used for a different job payload");
        }
        return { job: mapJob(existing), reused: true };
      }
      this.database.prepare(`
        INSERT INTO jobs(
          job_id, owner_principal_id, owner_session_id, tool, target_ref, policy_version,
          payload_digest, idempotency_key, state, result_class, created_at_ms, started_at_ms,
          finished_at_ms, exit_code, stdout_text, stderr_text, output_truncated,
          cancel_requested, cancel_reason, revision
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'queued', ?, NULL, NULL, NULL, '', '', 0, 0, NULL, 0)
      `).run(
        input.jobId, input.ownerPrincipalId, input.ownerSessionId, input.tool, input.targetRef,
        input.policyVersion, input.payloadDigest, input.idempotencyKey, input.createdAtMs
      );
      return { job: this.requireOwnedJob(input.jobId, input.ownerPrincipalId), reused: false };
    });
  }

  ownedJob(jobId: string, principalId: string): BrokerJob | undefined {
    const row = this.database.prepare(
      "SELECT * FROM jobs WHERE job_id = ? AND owner_principal_id = ?"
    ).get(jobId, principalId) as JobRow | undefined;
    return row ? mapJob(row) : undefined;
  }

  ownedJobByIdempotencyKey(idempotencyKey: string, principalId: string): BrokerJob | undefined {
    if (!/^[A-Za-z0-9._:-]{1,128}$/u.test(idempotencyKey) || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(principalId)) {
      throw malformedJob();
    }
    const row = this.database.prepare(
      "SELECT * FROM jobs WHERE idempotency_key = ? AND owner_principal_id = ?"
    ).get(idempotencyKey, principalId) as JobRow | undefined;
    return row ? mapJob(row) : undefined;
  }

  linkRequestJob(requestId: string, jobId: string, nowMs: number): RequestRecord {
    if (!/^job:[A-Za-z0-9._-]{1,240}$/u.test(jobId) || !Number.isSafeInteger(nowMs) || nowMs < 0) {
      throw malformedRequest();
    }
    return this.runTransaction(() => {
      const current = this.requireRequest(requestId);
      if (current.state !== "INTENT_RECORDED" || (current.jobId !== null && current.jobId !== jobId) || nowMs < current.updatedAtMs) {
        throw new BrokerError("CONFLICT", "Request job linkage changed concurrently");
      }
      this.database.prepare(`
        UPDATE requests SET job_id = ?, updated_at_ms = ?, revision = revision + 1
        WHERE request_id = ? AND revision = ?
      `).run(jobId, nowMs, requestId, current.revision);
      return this.requireRequest(requestId);
    });
  }

  startJob(jobId: string, principalId: string, expectedRevision: number, startedAtMs: number): BrokerJob {
    if (!Number.isSafeInteger(startedAtMs) || startedAtMs < 0) throw malformedJob();
    return this.transitionJob(jobId, principalId, expectedRevision, ["queued"], (current) => {
      if (startedAtMs < current.createdAtMs) throw malformedJob();
      this.database.prepare(`
        UPDATE jobs SET state = 'running', result_class = 'accepted', started_at_ms = ?, revision = revision + 1
        WHERE job_id = ? AND owner_principal_id = ?
      `).run(startedAtMs, jobId, principalId);
    });
  }

  finishJob(
    jobId: string,
    principalId: string,
    expectedRevision: number,
    outcome: {
      state: "completed" | "failed" | "cancelled" | "unknown";
      resultClass: Exclude<JobResultClass, "queued" | "accepted">;
      finishedAtMs: number;
      exitCode?: number | null;
      stdout?: string;
      stderr?: string;
    }
  ): BrokerJob {
    if (!Number.isSafeInteger(outcome.finishedAtMs) || outcome.finishedAtMs < 0) throw malformedJob();
    if (!validTerminalOutcome(outcome.state, outcome.resultClass)) throw malformedJob();
    const stdout = sanitizeJobOutput(outcome.stdout ?? "");
    const stderr = sanitizeJobOutput(outcome.stderr ?? "");
    const exitCode = outcome.exitCode ?? null;
    if (exitCode !== null && (!Number.isInteger(exitCode) || exitCode < -2_147_483_648 || exitCode > 2_147_483_647)) {
      throw malformedJob();
    }
    return this.transitionJob(jobId, principalId, expectedRevision, ["running"], (current) => {
      if (current.startedAtMs === null || outcome.finishedAtMs < current.startedAtMs) throw malformedJob();
      this.database.prepare(`
        UPDATE jobs SET state = ?, result_class = ?, finished_at_ms = ?, exit_code = ?,
          stdout_text = ?, stderr_text = ?, output_truncated = ?, revision = revision + 1
        WHERE job_id = ? AND owner_principal_id = ?
      `).run(
        outcome.state, outcome.resultClass, outcome.finishedAtMs, exitCode,
        stdout.value, stderr.value, stdout.truncated || stderr.truncated ? 1 : 0, jobId, principalId
      );
    });
  }

  requestJobCancellation(jobId: string, principalId: string, reason: string, nowMs: number): {
    job: BrokerJob;
    priorState: JobState;
    terminationObserved: boolean;
  } {
    if (reason.length > 200 || reason.includes("\0") || !Number.isSafeInteger(nowMs) || nowMs < 0) throw malformedJob();
    return this.runTransaction(() => {
      const current = this.requireOwnedJob(jobId, principalId);
      if (nowMs < current.createdAtMs) throw malformedJob();
      if (current.state === "queued") {
        this.database.prepare(`
          UPDATE jobs SET state = 'cancelled', result_class = 'denied', finished_at_ms = ?,
            cancel_requested = 1, cancel_reason = ?, revision = revision + 1
          WHERE job_id = ? AND owner_principal_id = ? AND revision = ?
        `).run(nowMs, reason, jobId, principalId, current.revision);
      } else if (current.state === "running" && !current.cancelRequested) {
        this.database.prepare(`
          UPDATE jobs SET cancel_requested = 1, cancel_reason = ?, revision = revision + 1
          WHERE job_id = ? AND owner_principal_id = ? AND revision = ?
        `).run(reason, jobId, principalId, current.revision);
      }
      const job = this.requireOwnedJob(jobId, principalId);
      return {
        job,
        priorState: current.state,
        terminationObserved: job.state === "cancelled" || job.state === "completed" || job.state === "failed" || job.state === "unknown"
      };
    });
  }

  reconcileInterruptedJobs(nowMs: number): { queuedCancelled: number; runningUnknown: number } {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw malformedJob();
    return this.runTransaction(() => {
      const interrupted = this.database.prepare(
        "SELECT * FROM jobs WHERE state IN ('queued', 'running') ORDER BY created_at_ms, job_id"
      ).all() as unknown as JobRow[];
      let queuedCancelled = 0;
      let runningUnknown = 0;
      for (const row of interrupted) {
        const priorState = row.state;
        const nextState: JobState = priorState === "queued" ? "cancelled" : "unknown";
        const resultClass: JobResultClass = priorState === "queued" ? "denied" : "unknown";
        this.database.prepare(`
          UPDATE jobs SET state = ?, result_class = ?, finished_at_ms = ?, cancel_requested = 1,
            cancel_reason = 'BROKER_RESTART', revision = revision + 1 WHERE job_id = ? AND revision = ?
        `).run(nextState, resultClass, nowMs, row.job_id, row.revision);
        if (priorState === "queued") queuedCancelled += 1;
        else runningUnknown += 1;
        this.insertAudit({
          requestId: `job-reconcile-${row.job_id}-${row.revision + 1}`,
          principalId: row.owner_principal_id,
          tool: "internal_job_reconcile",
          eventType: "completion",
          decision: "allow",
          resultClass: nextState === "unknown" ? "UNKNOWN_OUTCOME" : "CANCELLED",
          targetRef: `job:${row.job_id}`,
          policyVersion: row.policy_version,
          evidence: { priorState, nextState, revision: row.revision + 1 },
          timestampMs: nowMs
        });
      }
      return { queuedCancelled, runningUnknown };
    });
  }

  appendAudit(event: AuditEvent): string {
    try {
      return this.runTransaction(() => this.insertAudit(event));
    } catch {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Required audit event could not be persisted");
    }
  }

  activatePolicy(identity: PolicyActivationIdentity, expectedPreviousRevision: number): void {
    try {
      this.runTransaction(() => {
        const current = this.activePolicyIdentity();
        if ((current?.revision ?? 0) !== expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Persisted policy revision changed concurrently");
        }
        if (identity.revision <= expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Policy revision must increase");
        }
        const highest = this.database.prepare("SELECT MAX(revision) AS revision FROM policy_history").get() as { revision: number | null };
        if (identity.revision <= (highest.revision ?? 0)) {
          throw new BrokerError("CONFLICT", "Policy revision was already used or is below history");
        }
        const requestId = `policy-${identity.revision}-${identity.payloadDigest.slice(0, 16)}`;
        const auditBase = {
          requestId,
          principalId: "local-policy-loader",
          tool: "internal_policy_activate",
          decision: "allow" as const,
          targetRef: `policy:${identity.version}`,
          policyVersion: identity.version,
          evidence: { payloadDigest: identity.payloadDigest, keyId: identity.keyId },
          timestampMs: identity.activatedAtMs
        };
        this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
        this.database.prepare(
          "INSERT INTO policy_history(revision, version, payload_digest, key_id, activated_at_ms) VALUES (?, ?, ?, ?, ?)"
        ).run(identity.revision, identity.version, identity.payloadDigest, identity.keyId, identity.activatedAtMs);
        this.database.prepare(`
          INSERT INTO active_policy(singleton, revision, version, payload_digest, key_id, activated_at_ms)
          VALUES (1, ?, ?, ?, ?, ?)
          ON CONFLICT(singleton) DO UPDATE SET
            revision=excluded.revision,
            version=excluded.version,
            payload_digest=excluded.payload_digest,
            key_id=excluded.key_id,
            activated_at_ms=excluded.activated_at_ms
        `).run(identity.revision, identity.version, identity.payloadDigest, identity.keyId, identity.activatedAtMs);
        this.insertAudit({ ...auditBase, eventType: "completion", resultClass: "SUCCEEDED" });
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Policy activation could not be persisted");
    }
  }

  rollbackPolicy(
    identity: Omit<PolicyActivationIdentity, "activatedAtMs">,
    expectedCurrentRevision: number,
    reasonCode: string,
    rolledBackAtMs: number
  ): void {
    if (!/^[A-Z0-9_:-]{1,64}$/u.test(reasonCode)) {
      throw new BrokerError("PRECONDITION_FAILED", "Policy rollback reason code is malformed");
    }
    try {
      this.runTransaction(() => {
        const current = this.activePolicyIdentity();
        if (!current || current.revision !== expectedCurrentRevision) {
          throw new BrokerError("CONFLICT", "Persisted active policy does not match rollback precondition");
        }
        if (identity.revision >= current.revision) {
          throw new BrokerError("PRECONDITION_FAILED", "Rollback target must be an older policy revision");
        }
        const historical = this.database.prepare(`
          SELECT version, payload_digest, key_id FROM policy_history WHERE revision = ?
        `).get(identity.revision) as { version: string; payload_digest: string; key_id: string } | undefined;
        if (
          !historical ||
          historical.version !== identity.version ||
          historical.payload_digest !== identity.payloadDigest ||
          historical.key_id !== identity.keyId
        ) {
          throw new BrokerError("PRECONDITION_FAILED", "Rollback target does not match verified policy history");
        }
        const requestId = `policy-rollback-${current.revision}-to-${identity.revision}`;
        const auditBase = {
          requestId,
          principalId: "local-policy-loader",
          tool: "internal_policy_rollback",
          decision: "allow" as const,
          targetRef: `policy:${identity.version}`,
          policyVersion: identity.version,
          evidence: {
            fromRevision: current.revision,
            toRevision: identity.revision,
            payloadDigest: identity.payloadDigest,
            keyId: identity.keyId,
            reasonCode
          },
          timestampMs: rolledBackAtMs
        };
        this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
        this.database.prepare(`
          UPDATE active_policy SET revision = ?, version = ?, payload_digest = ?, key_id = ?, activated_at_ms = ?
          WHERE singleton = 1
        `).run(identity.revision, identity.version, identity.payloadDigest, identity.keyId, rolledBackAtMs);
        this.insertAudit({ ...auditBase, eventType: "completion", resultClass: "SUCCEEDED" });
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Policy rollback could not be persisted");
    }
  }

  activePolicyIdentity(): PolicyActivationIdentity | undefined {
    const row = this.database.prepare(`
      SELECT revision, version, payload_digest, key_id, activated_at_ms FROM active_policy WHERE singleton = 1
    `).get() as {
      revision: number;
      version: string;
      payload_digest: string;
      key_id: string;
      activated_at_ms: number;
    } | undefined;
    return row ? {
      revision: row.revision,
      version: row.version,
      payloadDigest: row.payload_digest,
      keyId: row.key_id,
      activatedAtMs: row.activated_at_ms
    } : undefined;
  }

  activateApprovalKeyConfig(
    identity: ApprovalKeyConfigActivationIdentity,
    expectedPreviousRevision: number
  ): void {
    if (!Number.isSafeInteger(identity.revision) || identity.revision < 1 ||
        !/^[a-f0-9]{64}$/u.test(identity.payloadDigest) ||
        !Number.isSafeInteger(identity.activatedAtMs) || identity.activatedAtMs < 0 ||
        !Number.isSafeInteger(expectedPreviousRevision) || expectedPreviousRevision < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Approval key configuration identity is malformed");
    }
    try {
      this.runTransaction(() => {
        const current = this.activeApprovalKeyConfigIdentity();
        if ((current?.revision ?? 0) !== expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Persisted approval key configuration revision changed concurrently");
        }
        if (identity.revision <= expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Approval key configuration revision must increase");
        }
        const highest = this.database.prepare(
          "SELECT MAX(revision) AS revision FROM approval_key_config_history"
        ).get() as { revision: number | null };
        if (identity.revision <= (highest.revision ?? 0)) {
          throw new BrokerError("CONFLICT", "Approval key configuration revision was already used or is below history");
        }
        const requestId = `approval-key-config-${identity.revision}-${identity.payloadDigest.slice(0, 16)}`;
        const auditBase = {
          requestId,
          principalId: "local-approval-key-loader",
          tool: "internal_approval_key_config_activate",
          decision: "allow" as const,
          targetRef: `approval_key_config:${identity.revision}`,
          policyVersion: "internal-approval-key-config-0.1",
          evidence: { payloadDigest: identity.payloadDigest, revision: identity.revision },
          timestampMs: identity.activatedAtMs
        };
        this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
        this.database.prepare(
          "INSERT INTO approval_key_config_history(revision, payload_digest, activated_at_ms) VALUES (?, ?, ?)"
        ).run(identity.revision, identity.payloadDigest, identity.activatedAtMs);
        this.database.prepare(`
          INSERT INTO active_approval_key_config(singleton, revision, payload_digest, activated_at_ms)
          VALUES (1, ?, ?, ?)
          ON CONFLICT(singleton) DO UPDATE SET
            revision=excluded.revision,
            payload_digest=excluded.payload_digest,
            activated_at_ms=excluded.activated_at_ms
        `).run(identity.revision, identity.payloadDigest, identity.activatedAtMs);
        this.insertAudit({ ...auditBase, eventType: "completion", resultClass: "SUCCEEDED" });
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Approval key configuration activation could not be persisted");
    }
  }

  activeApprovalKeyConfigIdentity(): ApprovalKeyConfigActivationIdentity | undefined {
    const row = this.database.prepare(`
      SELECT revision, payload_digest, activated_at_ms
      FROM active_approval_key_config WHERE singleton = 1
    `).get() as {
      revision: number;
      payload_digest: string;
      activated_at_ms: number;
    } | undefined;
    return row ? {
      revision: row.revision,
      payloadDigest: row.payload_digest,
      activatedAtMs: row.activated_at_ms
    } : undefined;
  }

  activatePolicySignerConfig(
    identity: PolicySignerConfigActivationIdentity,
    expectedPreviousRevision: number
  ): void {
    validateConfigActivationIdentity(identity, "Policy signer configuration");
    if (!Number.isSafeInteger(expectedPreviousRevision) || expectedPreviousRevision < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Policy signer configuration revision precondition is malformed");
    }
    try {
      this.runTransaction(() => {
        const current = this.activePolicySignerConfigIdentity();
        if ((current?.revision ?? 0) !== expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Persisted policy signer configuration revision changed concurrently");
        }
        if (identity.revision <= expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Policy signer configuration revision must increase");
        }
        const highest = this.database.prepare(
          "SELECT MAX(revision) AS revision FROM policy_signer_config_history"
        ).get() as { revision: number | null };
        if (identity.revision <= (highest.revision ?? 0)) {
          throw new BrokerError("CONFLICT", "Policy signer configuration revision was already used or is below history");
        }
        const requestId = `policy-signer-config-${identity.revision}-${identity.payloadDigest.slice(0, 16)}`;
        const auditBase = {
          requestId,
          principalId: "local-policy-signer-operator",
          tool: "internal_policy_signer_config_activate",
          decision: "allow" as const,
          targetRef: `policy_signer_config:${identity.revision}`,
          policyVersion: "internal-policy-signer-config-0.1",
          evidence: { payloadDigest: identity.payloadDigest, revision: identity.revision },
          timestampMs: identity.activatedAtMs
        };
        this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
        this.database.prepare(
          "INSERT INTO policy_signer_config_history(revision, payload_digest, activated_at_ms) VALUES (?, ?, ?)"
        ).run(identity.revision, identity.payloadDigest, identity.activatedAtMs);
        this.database.prepare(`
          INSERT INTO active_policy_signer_config(singleton, revision, payload_digest, activated_at_ms)
          VALUES (1, ?, ?, ?)
          ON CONFLICT(singleton) DO UPDATE SET
            revision=excluded.revision,
            payload_digest=excluded.payload_digest,
            activated_at_ms=excluded.activated_at_ms
        `).run(identity.revision, identity.payloadDigest, identity.activatedAtMs);
        this.insertAudit({ ...auditBase, eventType: "completion", resultClass: "SUCCEEDED" });
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Policy signer configuration activation could not be persisted");
    }
  }

  rollbackPolicySignerConfig(
    identity: PolicySignerConfigActivationIdentity,
    expectedCurrentRevision: number,
    reasonCode: string,
    rolledBackAtMs: number
  ): void {
    validateConfigActivationIdentity(identity, "Policy signer configuration");
    if (!Number.isSafeInteger(expectedCurrentRevision) || expectedCurrentRevision < 1 ||
        !/^[A-Z0-9_:-]{1,64}$/u.test(reasonCode) ||
        !Number.isSafeInteger(rolledBackAtMs) || rolledBackAtMs < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Policy signer rollback precondition is malformed");
    }
    try {
      this.runTransaction(() => {
        const current = this.activePolicySignerConfigIdentity();
        if (!current || current.revision !== expectedCurrentRevision) {
          throw new BrokerError("CONFLICT", "Persisted policy signer configuration does not match rollback precondition");
        }
        if (identity.revision >= current.revision) {
          throw new BrokerError("PRECONDITION_FAILED", "Policy signer rollback target must be an older revision");
        }
        const historical = this.database.prepare(`
          SELECT payload_digest, activated_at_ms FROM policy_signer_config_history WHERE revision = ?
        `).get(identity.revision) as { payload_digest: string; activated_at_ms: number } | undefined;
        if (!historical || historical.payload_digest !== identity.payloadDigest) {
          throw new BrokerError("PRECONDITION_FAILED", "Policy signer rollback target does not match verified history");
        }
        const requestId = `policy-signer-rollback-${current.revision}-to-${identity.revision}`;
        const auditBase = {
          requestId,
          principalId: "local-policy-signer-operator",
          tool: "internal_policy_signer_config_rollback",
          decision: "allow" as const,
          targetRef: `policy_signer_config:${identity.revision}`,
          policyVersion: "internal-policy-signer-config-0.1",
          evidence: {
            fromRevision: current.revision,
            toRevision: identity.revision,
            payloadDigest: identity.payloadDigest,
            reasonCode
          },
          timestampMs: rolledBackAtMs
        };
        this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
        this.database.prepare(`
          UPDATE active_policy_signer_config SET revision = ?, payload_digest = ?, activated_at_ms = ?
          WHERE singleton = 1
        `).run(identity.revision, identity.payloadDigest, rolledBackAtMs);
        this.insertAudit({ ...auditBase, eventType: "completion", resultClass: "SUCCEEDED" });
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Policy signer configuration rollback could not be persisted");
    }
  }

  policySignerConfigHistoryIdentity(revision: number): PolicySignerConfigActivationIdentity | undefined {
    if (!Number.isSafeInteger(revision) || revision < 1) return undefined;
    const row = this.database.prepare(`
      SELECT revision, payload_digest, activated_at_ms
      FROM policy_signer_config_history WHERE revision = ?
    `).get(revision) as {
      revision: number;
      payload_digest: string;
      activated_at_ms: number;
    } | undefined;
    return row ? { revision: row.revision, payloadDigest: row.payload_digest, activatedAtMs: row.activated_at_ms } : undefined;
  }

  activePolicySignerConfigIdentity(): PolicySignerConfigActivationIdentity | undefined {
    const row = this.database.prepare(`
      SELECT revision, payload_digest, activated_at_ms
      FROM active_policy_signer_config WHERE singleton = 1
    `).get() as {
      revision: number;
      payload_digest: string;
      activated_at_ms: number;
    } | undefined;
    return row ? { revision: row.revision, payloadDigest: row.payload_digest, activatedAtMs: row.activated_at_ms } : undefined;
  }

  auditRows(): Array<Record<string, unknown>> {
    return this.database.prepare("SELECT * FROM audit_events ORDER BY sequence").all() as Array<Record<string, unknown>>;
  }

  verifyAuditIntegrity(): void {
    const rows = this.auditRows();
    let previousHash = "0".repeat(64);
    for (const row of rows) {
      if (row.previous_hash !== previousHash || typeof row.evidence_json !== "string") {
        throw new BrokerError("AUDIT_UNAVAILABLE", "Audit evidence chain failed integrity verification");
      }
      let evidence: unknown;
      try {
        evidence = JSON.parse(row.evidence_json);
      } catch {
        throw new BrokerError("AUDIT_UNAVAILABLE", "Audit evidence chain failed integrity verification");
      }
      const expectedHash = sha256(canonicalJson({
        requestId: row.request_id,
        principalId: row.principal_id,
        tool: row.tool,
        eventType: row.event_type,
        decision: row.decision,
        resultClass: row.result_class,
        targetRef: row.target_ref,
        policyVersion: row.policy_version,
        evidence,
        timestampMs: row.timestamp_ms,
        previousHash
      }));
      if (row.event_hash !== expectedHash) {
        throw new BrokerError("AUDIT_UNAVAILABLE", "Audit evidence chain failed integrity verification");
      }
      previousHash = expectedHash;
    }
  }

  private transitionJob(
    jobId: string,
    principalId: string,
    expectedRevision: number,
    allowedStates: readonly JobState[],
    update: (current: BrokerJob) => void
  ): BrokerJob {
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) throw malformedJob();
    return this.runTransaction(() => {
      const current = this.requireOwnedJob(jobId, principalId);
      if (current.revision !== expectedRevision || !allowedStates.includes(current.state)) {
        throw new BrokerError("CONFLICT", "Job state or revision changed concurrently");
      }
      update(current);
      return this.requireOwnedJob(jobId, principalId);
    });
  }

  private transitionRequest(
    requestId: string,
    allowedStates: readonly RequestState[],
    nextState: RequestState,
    resultClass: string,
    targetRef: string | null,
    updatedAtMs: number,
    sideEffect?: (current: RequestRecord) => void
  ): RequestRecord {
    if (!Number.isSafeInteger(updatedAtMs) || updatedAtMs < 0 || resultClass.length < 1 || resultClass.length > 128 ||
        (targetRef !== null && (targetRef.length < 1 || targetRef.length > 4096 || targetRef.includes("\0")))) {
      throw malformedRequest();
    }
    return this.runTransaction(() => {
      const current = this.requireRequest(requestId);
      if (!allowedStates.includes(current.state) || updatedAtMs < current.updatedAtMs) {
        throw new BrokerError("CONFLICT", "Request state changed concurrently or time moved backwards");
      }
      sideEffect?.(current);
      const result = this.database.prepare(`
        UPDATE requests SET state = ?, result_class = ?, target_ref = ?, updated_at_ms = ?, revision = revision + 1
        WHERE request_id = ? AND revision = ?
      `).run(nextState, resultClass, targetRef, updatedAtMs, requestId, current.revision);
      if (result.changes !== 1) throw new BrokerError("CONFLICT", "Request revision changed concurrently");
      return this.requireRequest(requestId);
    });
  }

  private persistRequestAudit(operation: () => RequestRecord): RequestRecord {
    try {
      return operation();
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Required request audit event could not be persisted");
    }
  }

  private assertRequestApprovalActive(request: RequestRecord, nowMs: number): void {
    if (!request.mutation || !request.approvalId || !Number.isSafeInteger(nowMs) || nowMs < request.updatedAtMs) {
      throw new BrokerError("POLICY_DENIED", "Mutation approval is not active");
    }
    const approval = this.approvalRecord(request.approvalId);
    if (!approval || approval.revokedAtMs !== null || approval.lastRequestId !== request.requestId ||
        approval.lastConsumedAtMs === null || approval.lastConsumedAtMs > nowMs || approval.expiresAtMs <= nowMs) {
      throw new BrokerError("POLICY_DENIED", "Mutation approval is not active");
    }
  }

  private findConsumableApproval(
    requestingPrincipalId: string,
    tool: string,
    policyVersion: string,
    binding: ApprovalConsumptionBinding,
    timestampMs: number
  ): ApprovalRow | undefined {
    return this.database.prepare(`
      SELECT * FROM approvals
      WHERE requesting_principal_id = ? AND tool = ? AND contract_version = ?
        AND target_kind = ? AND target_ref = ? AND payload_digest = ? AND policy_version = ?
        AND approval_class = ? AND issued_at_ms <= ? AND expires_at_ms > ?
        AND unattended = ?
        AND revoked_at_ms IS NULL AND used_count < use_limit
      ORDER BY issued_at_ms, approval_id LIMIT 1
    `).get(
      requestingPrincipalId, tool, binding.contractVersion, binding.targetKind,
      binding.targetRef, binding.payloadDigest, policyVersion, binding.approvalClass,
      timestampMs, timestampMs, binding.unattended ? 1 : 0
    ) as ApprovalRow | undefined;
  }

  private requireRequest(requestId: string): RequestRecord {
    const request = this.requestRecord(requestId);
    if (!request) throw new BrokerError("TARGET_NOT_FOUND", "Request record was not found");
    return request;
  }

  private requireApproval(approvalId: string): ApprovalRecord {
    const approval = this.approvalRecord(approvalId);
    if (!approval) throw new BrokerError("TARGET_NOT_FOUND", "Approval record was not found");
    return approval;
  }

  private requireOwnedJob(jobId: string, principalId: string): BrokerJob {
    const job = this.ownedJob(jobId, principalId);
    if (!job) throw new BrokerError("TARGET_NOT_FOUND", "Broker-owned job was not found");
    return job;
  }

  private insertAudit(event: AuditEvent): string {
    const evidenceJson = canonicalJson(redactEvidence(event.evidence));
    const previous = this.database.prepare("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").get() as { event_hash: string } | undefined;
    const previousHash = previous?.event_hash ?? "0".repeat(64);
    const eventHash = sha256(canonicalJson({ ...event, evidence: JSON.parse(evidenceJson), previousHash }));
    this.database.prepare(`
      INSERT INTO audit_events(request_id, principal_id, tool, event_type, decision, result_class, target_ref, policy_version, evidence_json, timestamp_ms, previous_hash, event_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(event.requestId, event.principalId, event.tool, event.eventType, event.decision, event.resultClass, event.targetRef, event.policyVersion, evidenceJson, event.timestampMs, previousHash, eventHash);
    return eventHash;
  }

  private runTransaction<T>(operation: () => T): T {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private injectFault(point: PersistenceFaultPoint): void {
    this.faultInjector?.(point);
  }

  private migrateRevocationsSchema(): void {
    const row = this.database.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'revocations'").get() as { sql: string };
    if (row.sql.includes("'approval_key'") && row.sql.includes("'policy_signer'")) return;
    this.runTransaction(() => {
      this.database.exec(`
        ALTER TABLE revocations RENAME TO revocations_v0;
        CREATE TABLE revocations (
          kind TEXT NOT NULL CHECK (kind IN ('principal', 'session', 'edge', 'edge_key', 'approval_key', 'policy_signer')),
          subject_id TEXT NOT NULL,
          revoked_at_ms INTEGER NOT NULL,
          reason TEXT NOT NULL,
          PRIMARY KEY (kind, subject_id)
        ) STRICT;
        INSERT INTO revocations(kind, subject_id, revoked_at_ms, reason)
          SELECT kind, subject_id, revoked_at_ms, reason FROM revocations_v0;
        DROP TABLE revocations_v0;
      `);
    });
  }

  private migrateRequestsSchema(): void {
    const columns = this.database.prepare("PRAGMA table_info(requests)").all() as Array<{ name: string }>;
    const names = new Set(columns.map((column) => column.name));
    if (!names.has("approval_id")) this.database.exec("ALTER TABLE requests ADD COLUMN approval_id TEXT");
    if (!names.has("job_id")) this.database.exec("ALTER TABLE requests ADD COLUMN job_id TEXT");
  }
}

function validateConfigActivationIdentity(identity: PolicySignerConfigActivationIdentity, label: string): void {
  if (!Number.isSafeInteger(identity.revision) || identity.revision < 1 ||
      !/^[a-f0-9]{64}$/u.test(identity.payloadDigest) ||
      !Number.isSafeInteger(identity.activatedAtMs) || identity.activatedAtMs < 0) {
    throw new BrokerError("PRECONDITION_FAILED", `${label} identity is malformed`);
  }
}

interface JobRow {
  job_id: string;
  owner_principal_id: string;
  owner_session_id: string;
  tool: string;
  target_ref: string;
  policy_version: string;
  payload_digest: string;
  idempotency_key: string;
  state: JobState;
  result_class: JobResultClass;
  created_at_ms: number;
  started_at_ms: number | null;
  finished_at_ms: number | null;
  exit_code: number | null;
  stdout_text: string;
  stderr_text: string;
  output_truncated: number;
  cancel_requested: number;
  revision: number;
}

interface RequestRow {
  request_id: string;
  edge_id: string;
  principal_id: string;
  session_id: string;
  tool: string;
  policy_version: string;
  payload_digest: string;
  mutation: number;
  state: RequestState;
  result_class: string | null;
  target_ref: string | null;
  approval_id: string | null;
  job_id: string | null;
  received_at_ms: number;
  updated_at_ms: number;
  revision: number;
}

interface ApprovalRow {
  approval_id: string;
  approver_principal_id: string;
  requesting_principal_id: string;
  tool: string;
  contract_version: string;
  target_kind: string;
  target_ref: string;
  payload_digest: string;
  policy_version: string;
  approval_class: ApprovalClass;
  unattended: number;
  issued_at_ms: number;
  expires_at_ms: number;
  use_limit: number;
  used_count: number;
  last_consumed_at_ms: number | null;
  last_request_id: string | null;
  revoked_at_ms: number | null;
  revocation_reason: string | null;
  revision: number;
}

function mapRequest(row: RequestRow): RequestRecord {
  return {
    requestId: row.request_id,
    edgeId: row.edge_id,
    principalId: row.principal_id,
    sessionId: row.session_id,
    tool: row.tool,
    policyVersion: row.policy_version,
    payloadDigest: row.payload_digest,
    mutation: row.mutation === 1,
    state: row.state,
    resultClass: row.result_class,
    targetRef: row.target_ref,
    approvalId: row.approval_id,
    jobId: row.job_id,
    receivedAtMs: row.received_at_ms,
    updatedAtMs: row.updated_at_ms,
    revision: row.revision
  };
}

function mapApproval(row: ApprovalRow): ApprovalRecord {
  return {
    approvalId: row.approval_id,
    approverPrincipalId: row.approver_principal_id,
    requestingPrincipalId: row.requesting_principal_id,
    tool: row.tool,
    contractVersion: row.contract_version,
    targetKind: row.target_kind,
    targetRef: row.target_ref,
    payloadDigest: row.payload_digest,
    policyVersion: row.policy_version,
    approvalClass: row.approval_class,
    unattended: row.unattended === 1,
    issuedAtMs: row.issued_at_ms,
    expiresAtMs: row.expires_at_ms,
    useLimit: row.use_limit,
    usedCount: row.used_count,
    lastConsumedAtMs: row.last_consumed_at_ms,
    lastRequestId: row.last_request_id,
    revokedAtMs: row.revoked_at_ms,
    revocationReason: row.revocation_reason,
    revision: row.revision
  };
}

function mapJob(row: JobRow): BrokerJob {
  return {
    jobId: row.job_id,
    ownerPrincipalId: row.owner_principal_id,
    ownerSessionId: row.owner_session_id,
    tool: row.tool,
    targetRef: row.target_ref,
    policyVersion: row.policy_version,
    payloadDigest: row.payload_digest,
    idempotencyKey: row.idempotency_key,
    state: row.state,
    resultClass: row.result_class,
    createdAtMs: row.created_at_ms,
    startedAtMs: row.started_at_ms,
    finishedAtMs: row.finished_at_ms,
    exitCode: row.exit_code,
    stdout: row.stdout_text,
    stderr: row.stderr_text,
    truncated: row.output_truncated === 1,
    cancelRequested: row.cancel_requested === 1,
    revision: row.revision
  };
}

function validateJobCreation(input: CreateJobInput): void {
  if (!/^job:[A-Za-z0-9._-]{1,240}$/u.test(input.jobId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.ownerPrincipalId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.ownerSessionId) ||
      !/^mac_[a-z0-9_]{1,123}$/u.test(input.tool) ||
      input.targetRef.length < 1 || input.targetRef.length > 4096 || input.targetRef.includes("\0") ||
      !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(input.policyVersion) ||
      !/^[a-f0-9]{64}$/u.test(input.payloadDigest) ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(input.idempotencyKey) ||
      !Number.isSafeInteger(input.createdAtMs) || input.createdAtMs < 0) {
    throw malformedJob();
  }
}

function validateRequestAdmission(input: AdmitRequestInput): void {
  if (!/^[A-Za-z0-9._:@/+-]{1,128}$/u.test(input.requestId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.edgeId) ||
      !/^[A-Za-z0-9._:@/+-]{1,256}$/u.test(input.nonce) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.principalId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.sessionId) ||
      !/^mac_[a-z0-9_]{1,123}$/u.test(input.tool) ||
      !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(input.policyVersion) ||
      !/^[a-f0-9]{64}$/u.test(input.payloadDigest) ||
      !Number.isSafeInteger(input.receivedAtMs) || input.receivedAtMs < 0 ||
      !Number.isSafeInteger(input.nonceExpiresAtMs) || input.nonceExpiresAtMs <= input.receivedAtMs) {
    throw malformedRequest();
  }
}

function validateApprovalIssue(input: IssueApprovalInput): void {
  const useLimit = input.useLimit ?? 1;
  if (!validApprovalId(input.approvalId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.approverPrincipalId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.requestingPrincipalId) ||
      !/^mac_[a-z0-9_]{1,123}$/u.test(input.tool) ||
      !/^\d+\.\d+$/u.test(input.contractVersion) ||
      !validApprovalTarget(input.targetKind, input.targetRef) ||
      !/^[a-f0-9]{64}$/u.test(input.payloadDigest) ||
      !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(input.policyVersion) ||
      !["trusted_write", "trusted_gui", "trusted_profile", "explicit_privileged_policy"].includes(input.approvalClass) ||
      typeof input.unattended !== "boolean" ||
      !Number.isSafeInteger(input.issuedAtMs) || input.issuedAtMs < 0 ||
      !Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= input.issuedAtMs ||
      useLimit !== 1) {
    throw malformedApproval();
  }
}

function validateAuthenticatedApprovalIssuance(input: AuthenticatedApprovalIssuance): void {
  if (input.protocolVersion !== "0.1" ||
      !/^approval-issue:[A-Za-z0-9._:-]{1,240}$/u.test(input.requestId) ||
      !/^approval-nonce:[A-Za-z0-9._:-]{1,240}$/u.test(input.nonce) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.issuerId) ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(input.keyId) ||
      !/^[a-f0-9]{64}$/u.test(input.issuanceDigest) ||
      !/^[a-f0-9]{64}$/u.test(input.previewDigest) ||
      !Number.isSafeInteger(input.timestampMs) || input.timestampMs < 0 ||
      !Number.isSafeInteger(input.nonceExpiresAtMs) || input.nonceExpiresAtMs <= input.timestampMs ||
      input.approval.issuedAtMs !== input.timestampMs ||
      input.issuerId !== input.approval.approverPrincipalId ||
      input.issuerId === input.approval.requestingPrincipalId) {
    throw new BrokerError("PRECONDITION_FAILED", "Authenticated approval issuance is malformed");
  }
  validateApprovalIssue(input.approval);
  const expectedDigest = sha256(canonicalJson({
    protocolVersion: input.protocolVersion,
    requestId: input.requestId,
    nonce: input.nonce,
    nonceExpiresAtMs: input.nonceExpiresAtMs,
    issuerId: input.issuerId,
    keyId: input.keyId,
    timestampMs: input.timestampMs,
    approval: input.approval,
    previewDigest: input.previewDigest
  }));
  if (expectedDigest !== input.issuanceDigest) {
    throw new BrokerError("AUTH_INVALID", "Authenticated approval issuance digest is invalid");
  }
}

function validateApprovalBinding(binding: ApprovalConsumptionBinding): void {
  if (!/^\d+\.\d+$/u.test(binding.contractVersion) ||
      !validApprovalTarget(binding.targetKind, binding.targetRef) ||
      !/^[a-f0-9]{64}$/u.test(binding.payloadDigest) ||
      !["trusted_write", "trusted_gui", "trusted_profile", "explicit_privileged_policy"].includes(binding.approvalClass) ||
      typeof binding.unattended !== "boolean") {
    throw malformedApproval();
  }
}

function validApprovalId(value: string): boolean {
  return /^approval:[A-Za-z0-9._:-]{1,240}$/u.test(value);
}

function validApprovalTarget(kind: string, reference: string): boolean {
  return ["host", "path", "project", "process", "job", "task_profile", "app", "app_window", "ui_element", "service", "package", "power"]
    .includes(kind) && reference.startsWith(`${kind}:`) && reference.length <= 4096 && !reference.includes("\0");
}

function asEvidenceRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function validAuditTimestamp(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function validAuditTarget(value: string): boolean {
  return typeof value === "string" && value.length >= 1 && value.length <= 4096 && !value.includes("\0");
}

function assertAuditMatchesRequest(event: AuditEvent, request: RequestRecord): void {
  if (event.requestId !== request.requestId || event.principalId !== request.principalId ||
      event.tool !== request.tool || event.policyVersion !== request.policyVersion) {
    throw malformedRequest();
  }
}

function failureRequestState(resultClass: string): RequestState {
  if (resultClass === "CANCELLED") return "CANCELLED";
  if (resultClass === "TIMEOUT") return "TIMED_OUT";
  if (resultClass === "VERIFICATION_FAILED") return "VERIFICATION_FAILED";
  if (resultClass === "UNKNOWN_OUTCOME") return "UNKNOWN";
  return "FAILED";
}

function isTerminalRequestState(state: RequestState): boolean {
  return ["SUCCEEDED", "FAILED", "DENIED", "CANCELLED", "TIMED_OUT", "VERIFICATION_FAILED", "UNKNOWN"].includes(state);
}

function sanitizeJobOutput(value: string): { value: string; truncated: boolean } {
  const bytes = Buffer.from(value, "utf8");
  try {
    assertContentDoesNotContainSecrets(bytes);
  } catch {
    return { value: "[REDACTED: SECRET CONTENT]", truncated: true };
  }
  const maxBytes = 262_144;
  if (bytes.length <= maxBytes) return { value, truncated: false };
  return { value: bytes.subarray(bytes.length - maxBytes).toString("utf8"), truncated: true };
}

function validTerminalOutcome(
  state: "completed" | "failed" | "cancelled" | "unknown",
  resultClass: Exclude<JobResultClass, "queued" | "accepted">
): boolean {
  if (state === "completed") return resultClass === "success";
  if (state === "failed") return resultClass === "failed" || resultClass === "denied" || resultClass === "verification_failed";
  if (state === "cancelled") return resultClass === "denied";
  return resultClass === "unknown";
}

function malformedJob(): BrokerError {
  return new BrokerError("PRECONDITION_FAILED", "Job record is malformed");
}

function malformedRequest(): BrokerError {
  return new BrokerError("PRECONDITION_FAILED", "Request record is malformed");
}

function malformedApproval(): BrokerError {
  return new BrokerError("PRECONDITION_FAILED", "Approval record is malformed");
}

const SECRET_KEY_PATTERN = /(?:authorization|cookie|credential|password|private[_-]?key|secret|token)/iu;

export function redactEvidence(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactEvidence);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [
      key,
      SECRET_KEY_PATTERN.test(key) ? "[REDACTED]" : redactEvidence(item)
    ]));
  }
  return value;
}
