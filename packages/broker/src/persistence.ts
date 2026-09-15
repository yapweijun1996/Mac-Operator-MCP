import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { isAbsolute, resolve } from "node:path";
import { BrokerError, CAPABILITY_FAMILIES, canonicalJson, parseJsonStrict, sha256, type CapabilityFamily } from "@mac-operator/contracts";
import { assertContentDoesNotContainSecrets } from "./secret-policy.js";
import { isPlainDataRecord } from "./plain-record.js";
import { AuditAnchorManager, type AuditAnchorOptions } from "./audit-anchor.js";
import {
  createBrokerBackup,
  pruneBrokerBackups,
  restoreBrokerBackup,
  type BrokerBackupKeySource,
  type BrokerBackupManifest,
  type BrokerBackupOptions,
  type BrokerBackupPruneResult
} from "./persistence-backup.js";
import { EDGE_KEY_IDENTITY_PATTERN, isValidEdgeId } from "./edge-keyring.js";

export type SwitchName = "global" | "mutations" | "process" | "network" | "gui" | "destructive" | "privileged";
const SWITCH_NAMES: readonly SwitchName[] = ["global", "mutations", "process", "network", "gui", "destructive", "privileged"];
export type RevocationKind = "principal" | "session" | "edge" | "edge_key" | "approval_key" | "policy_signer" | "authority_key" | "helper_key" | "guest_attestation_key";
const REVOCATION_KINDS: readonly RevocationKind[] = ["principal", "session", "edge", "edge_key", "approval_key", "policy_signer", "authority_key", "helper_key", "guest_attestation_key"];

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

export interface EdgeKeyConfigActivationIdentity {
  revision: number;
  payloadDigest: string;
  activatedAtMs: number;
}

export interface PolicySignerConfigActivationIdentity {
  revision: number;
  payloadDigest: string;
  activatedAtMs: number;
}

export interface AuthorityKeyConfigActivationIdentity {
  revision: number;
  payloadDigest: string;
  activatedAtMs: number;
}

export interface HelperKeyConfigActivationIdentity {
  revision: number;
  payloadDigest: string;
  activatedAtMs: number;
}

export interface GuestAttestationKeyConfigActivationIdentity {
  revision: number;
  payloadDigest: string;
  activatedAtMs: number;
}

export type JobState = "queued" | "running" | "completed" | "failed" | "cancelled" | "unknown";
export type JobResultClass = "success" | "denied" | "failed" | "verification_failed" | "queued" | "accepted" | "unknown";

export interface JobLease {
  ownerId: string;
  token: string;
  expiresAtMs: number;
}

const JOB_LEASE_OWNER_PATTERN = /^[A-Za-z0-9._:@/-]{1,128}$/u;
const JOB_LEASE_TOKEN_PATTERN = /^lease:[A-Za-z0-9._:-]{16,128}$/u;
const EDGE_KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const MAX_JOB_LEASE_MS = 120_000;
const MAX_ACTIVE_REQUESTS_GLOBAL = 256;
const MAX_ACTIVE_REQUESTS_PER_SESSION = 64;
/**
 * SQLite schema revisions are monotonic. A Broker must never open a database
 * written by a newer runtime because unknown columns or invariants could make
 * authority and recovery decisions unsafe.
 */
export const BROKER_SCHEMA_VERSION = 11;
const MAX_VIRTUALIZATION_GUEST_REPLAY_ROWS = 4096;

/**
 * Non-secret write facts retained so an unresolved mutation can be inspected
 * after restart without persisting the requested bytes.
 */
export interface WriteJobMetadata {
  rootId: string;
  path: string;
  bytes: number;
  desiredSha256: string;
  expectedSha256: string | null;
  createOnly: boolean;
  /**
   * Exact same-directory temporary name allocated for this write. Older
   * ledger rows may omit it and therefore cannot participate in cleanup.
   */
  temporaryName?: string;
}

/** Non-secret OS identity needed to recover an interrupted task process. */
export interface ProcessJobMetadata {
  pid: number;
  processGroupId: number;
  startTimeMicros: number;
  recordedAtMs: number;
  descendants: readonly ProcessDescendantMetadata[];
  /** Host-owned proof that a dead root has no post-snapshot descendants. */
  ownershipProof?: "sandbox-exec-no-fork-v1";
}

export interface ProcessDescendantMetadata {
  pid: number;
  startTimeMicros: number;
}

/**
 * Non-secret identity and budget facts for an admitted Virtualization guest
 * task. This is deliberately limited to the signed request identity and
 * Broker-owned digests so recovery never needs host paths, commands, or
 * credentials.
 */
export interface GuestTaskJobMetadata {
  requestId: string;
  nonce: string;
  requestDigest: string;
  guestIdentity: {
    imageSha256: string;
    runtimeVersion: string;
  };
  profileDigest: string;
  taskDigest: string;
  timeoutMs: number;
  outputCapBytes: number;
  recordedAtMs: number;
}

/**
 * Non-secret, allowlisted arguments that may cross the helper boundary.
 * Generic shell text, executable paths, and arbitrary maps are intentionally
 * not representable here.
 */
export type PrivilegedHelperPayload =
  | {
      operation: "service_control";
      service_id: string;
      action: "start" | "stop" | "restart" | "enable" | "disable";
      expected_state?: "running" | "stopped" | "enabled" | "disabled";
    }
  | {
      operation: "package_install";
      package_id: string;
      version?: string;
      source_profile?: string;
    }
  | {
      operation: "power";
      action: "reboot" | "shutdown";
      reason?: string;
      not_before?: string;
    };

export interface BrokerJob {
  jobId: string;
  /** Internal authority correlation; never serialized in tool results. */
  ownerEdgeId: string | null;
  /** Internal authentication-key correlation; never serialized in tool results. */
  ownerEdgeKeyId: string | null;
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
  writeMetadata?: WriteJobMetadata;
  processMetadata?: ProcessJobMetadata;
  guestMetadata?: GuestTaskJobMetadata;
  privilegedPayload?: PrivilegedHelperPayload;
}

export interface CreateJobInput {
  jobId: string;
  /** Edge identity that admitted this Job; omitted only for legacy/local fixtures. */
  edgeId?: string;
  /** Edge/key identity that authenticated this Job; requires edgeId. */
  edgeKeyId?: string;
  ownerPrincipalId: string;
  ownerSessionId: string;
  tool: string;
  targetRef: string;
  policyVersion: string;
  payloadDigest: string;
  idempotencyKey: string;
  createdAtMs: number;
  writeMetadata?: WriteJobMetadata;
  privilegedPayload?: PrivilegedHelperPayload;
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
  /** Broker-resolved capability families; legacy records expose an empty list. */
  capabilityFamilies: readonly CapabilityFamily[];
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
  /** Broker-resolved capability families used for durable independent quotas. */
  capabilityFamilies?: readonly CapabilityFamily[];
  receivedAtMs: number;
}

/** Durable request-capacity limits enforced inside the BrokerStore transaction. */
export interface RequestAdmissionLimits {
  /** Maximum number of non-terminal requests across all principals/sessions. */
  maxActiveRequestsGlobal?: number;
  /** Maximum number of non-terminal requests for one principal/session pair. */
  maxActiveRequestsPerSession?: number;
  /** Maximum number of non-terminal requests for each Broker capability family. */
  maxActiveRequestsByFamily?: Partial<Record<CapabilityFamily, number>>;
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
  /**
   * Claim a persisted Broker runtime fence. Packaged Broker startup enables
   * this so a later service instance invalidates every stale writer from the
   * prior instance; generic persistence fixtures may leave it disabled.
   */
  runtimeFence?: boolean;
  /**
   * Optional keyed audit-tail anchor. Production startup must load its key
   * from a protected source (normally Keychain) and use a single Broker owner
   * until cross-process sidecar locking is separately accepted.
   */
  auditAnchor?: AuditAnchorOptions;
}

export class BrokerStore {
  private readonly database: DatabaseSync;
  private readonly faultInjector: ((point: PersistenceFaultPoint) => void) | undefined;
  private readonly auditAnchor: AuditAnchorManager | undefined;
  private readonly runtimeFenceEnabled: boolean;
  /** Unique process-instance token used to fence stale Broker writers after restart. */
  private readonly runtimeFenceToken = `fence:${randomUUID()}`;
  private runtimeFenceGeneration = 0;
  private runtimeFenceAcquired = false;
  private pendingAuditAnchor: { sequence: number; eventHash: string } | undefined;
  private auditAnchorUnavailable = false;

  constructor(path: string, options: BrokerStoreOptions = {}) {
    this.faultInjector = options.faultInjector;
    this.auditAnchor = options.auditAnchor ? new AuditAnchorManager(options.auditAnchor) : undefined;
    this.runtimeFenceEnabled = options.runtimeFence === true;
    this.database = new DatabaseSync(path);
    this.database.exec("PRAGMA busy_timeout = 5000;");
    this.database.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;");
    let schemaVersion: number;
    try {
      schemaVersion = this.readSchemaVersion();
    } catch (error) {
      this.database.close();
      throw error;
    }
    if (schemaVersion > BROKER_SCHEMA_VERSION) {
      this.database.close();
      throw new Error("Broker persistence schema version is newer than this runtime");
    }
    try {
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
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        applied_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS broker_runtime_fence (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        generation INTEGER NOT NULL,
        token TEXT NOT NULL,
        acquired_at_ms INTEGER NOT NULL
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
      CREATE TABLE IF NOT EXISTS authority_control_nonces (
        nonce TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        accepted_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS privileged_helper_nonces (
        nonce TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        accepted_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS broker_status_nonces (
        nonce TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        accepted_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS virtualization_guest_nonces (
        nonce TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        accepted_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS revocations (
        kind TEXT NOT NULL CHECK (kind IN ('principal', 'session', 'edge', 'edge_key', 'approval_key', 'policy_signer', 'authority_key', 'helper_key', 'guest_attestation_key')),
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
      CREATE TABLE IF NOT EXISTS edge_key_config_history (
        revision INTEGER PRIMARY KEY,
        payload_digest TEXT NOT NULL UNIQUE,
        activated_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS active_edge_key_config (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        revision INTEGER NOT NULL,
        payload_digest TEXT NOT NULL,
        activated_at_ms INTEGER NOT NULL,
        FOREIGN KEY (revision) REFERENCES edge_key_config_history(revision)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS authority_key_config_history (
        revision INTEGER PRIMARY KEY,
        payload_digest TEXT NOT NULL UNIQUE,
        activated_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS active_authority_key_config (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        revision INTEGER NOT NULL,
        payload_digest TEXT NOT NULL,
        activated_at_ms INTEGER NOT NULL,
        FOREIGN KEY (revision) REFERENCES authority_key_config_history(revision)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS helper_key_config_history (
        revision INTEGER PRIMARY KEY,
        payload_digest TEXT NOT NULL UNIQUE,
        activated_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS active_helper_key_config (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        revision INTEGER NOT NULL,
        payload_digest TEXT NOT NULL,
        activated_at_ms INTEGER NOT NULL,
        FOREIGN KEY (revision) REFERENCES helper_key_config_history(revision)
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
      CREATE TABLE IF NOT EXISTS guest_attestation_key_config_history (
        revision INTEGER PRIMARY KEY,
        payload_digest TEXT NOT NULL UNIQUE,
        activated_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS active_guest_attestation_key_config (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        revision INTEGER NOT NULL,
        payload_digest TEXT NOT NULL,
        activated_at_ms INTEGER NOT NULL,
        FOREIGN KEY (revision) REFERENCES guest_attestation_key_config_history(revision)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY,
        owner_edge_id TEXT,
        owner_edge_key_id TEXT,
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
        lease_owner_id TEXT,
        lease_token TEXT,
        lease_acquired_at_ms INTEGER,
        lease_heartbeat_at_ms INTEGER,
        lease_expires_at_ms INTEGER,
        write_metadata_json TEXT NOT NULL DEFAULT '',
        process_metadata_json TEXT NOT NULL DEFAULT '',
        guest_metadata_json TEXT NOT NULL DEFAULT '',
        privileged_payload_json TEXT NOT NULL DEFAULT '',
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
        capability_families TEXT NOT NULL DEFAULT '',
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
      this.migrateSchema(schemaVersion);
      this.verifyReplayLedgerIntegrity();
      this.verifyConfigurationLedgerIntegrity();
      this.verifyRequestLedgerIntegrity();
      this.verifyAuthorityLedgerIntegrity();
      this.verifyJobLedgerIntegrity();
      this.verifyAuditIntegrity();
      this.verifyExternalAuditAnchor();
      if (this.runtimeFenceEnabled) this.acquireRuntimeFence(Date.now());
      this.reconcileInterruptedRequests(Date.now());
      this.reconcileInterruptedJobs(Date.now());
    } catch (error) {
      this.database.close();
      this.auditAnchor?.close();
      throw error;
    }
  }

  close(): void {
    this.runtimeFenceAcquired = false;
    this.database.close();
    this.auditAnchor?.close();
  }

  /**
   * Replay ledgers are authority inputs: a forged nonce row must never become
   * a valid admission record merely because SQLite accepted its scalar types.
   */
  private verifyReplayLedgerIntegrity(): void {
    try {
      const requestRows = this.database.prepare(
        "SELECT edge_id, nonce, request_id, accepted_at_ms, expires_at_ms FROM nonces"
      ).all() as unknown[];
      for (const row of requestRows) validateStoredReplayRow("request", row);

      const approvalRows = this.database.prepare(
        "SELECT issuer_id, key_id, nonce, request_id, accepted_at_ms, expires_at_ms FROM approval_nonces"
      ).all() as unknown[];
      for (const row of approvalRows) validateStoredReplayRow("approval", row);

      const policySignerRows = this.database.prepare(
        "SELECT nonce, request_id, accepted_at_ms, expires_at_ms FROM policy_signer_nonces"
      ).all() as unknown[];
      for (const row of policySignerRows) validateStoredReplayRow("policy_signer", row);

      const authorityRows = this.database.prepare(
        "SELECT nonce, request_id, accepted_at_ms, expires_at_ms FROM authority_control_nonces"
      ).all() as unknown[];
      for (const row of authorityRows) validateStoredReplayRow("authority_control", row);

      const helperRows = this.database.prepare(
        "SELECT nonce, request_id, accepted_at_ms, expires_at_ms FROM privileged_helper_nonces"
      ).all() as unknown[];
      for (const row of helperRows) validateStoredReplayRow("privileged_helper", row);

      const statusRows = this.database.prepare(
        "SELECT nonce, request_id, accepted_at_ms, expires_at_ms FROM broker_status_nonces"
      ).all() as unknown[];
      for (const row of statusRows) validateStoredReplayRow("broker_status", row);

      const guestRows = this.database.prepare(
        "SELECT nonce, request_id, accepted_at_ms, expires_at_ms FROM virtualization_guest_nonces"
      ).all() as unknown[];
      if (guestRows.length > MAX_VIRTUALIZATION_GUEST_REPLAY_ROWS) {
        throw new BrokerError("AUDIT_UNAVAILABLE", "Virtualization guest replay ledger is at capacity");
      }
      for (const row of guestRows) validateStoredReplayRow("virtualization_guest", row);
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Replay ledger integrity could not be verified");
    }
  }

  /**
   * Active policy/key configuration is authority state. Verify both the
   * singleton and its history before startup can restore or roll back it.
   */
  private verifyConfigurationLedgerIntegrity(): void {
    try {
      const policyHistory = this.database.prepare(
        "SELECT revision, version, payload_digest, key_id, activated_at_ms FROM policy_history"
      ).all() as unknown[];
      for (const row of policyHistory) validateStoredPolicyHistoryRow(row);
      const activePolicy = this.database.prepare(
        "SELECT revision, version, payload_digest, key_id, activated_at_ms FROM active_policy WHERE singleton = 1"
      ).get() as unknown;
      if (activePolicy !== undefined) {
        validateStoredPolicyHistoryRow(activePolicy);
        assertStoredPolicyMatchesHistory(this.database, activePolicy);
      }

      const ledgers = [
        ["approval key", "approval_key_config_history", "active_approval_key_config"],
        ["Edge key", "edge_key_config_history", "active_edge_key_config"],
        ["authority key", "authority_key_config_history", "active_authority_key_config"],
        ["helper key", "helper_key_config_history", "active_helper_key_config"],
        ["guest attestation key", "guest_attestation_key_config_history", "active_guest_attestation_key_config"],
        ["policy signer", "policy_signer_config_history", "active_policy_signer_config"]
      ] as const;
      for (const [label, historyTable, activeTable] of ledgers) {
        const historyRows = this.database.prepare(
          `SELECT revision, payload_digest, activated_at_ms FROM ${historyTable}`
        ).all() as unknown[];
        for (const row of historyRows) validateStoredConfigIdentityRow(row, label);
        const active = this.database.prepare(
          `SELECT revision, payload_digest, activated_at_ms FROM ${activeTable} WHERE singleton = 1`
        ).get() as unknown;
        if (active !== undefined) {
          validateStoredConfigIdentityRow(active, label);
          assertStoredConfigMatchesHistory(this.database, historyTable, active, label);
        }
      }
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Configuration ledger integrity could not be verified");
    }
  }

  /**
   * Requests are durable authority and recovery inputs. Validate every
   * persisted row before startup reconciliation can inspect or mutate it;
   * otherwise a forged identity or state could remain dormant until a later
   * status or mutation request.
   */
  private verifyRequestLedgerIntegrity(): void {
    try {
      const rows = this.database.prepare(
        "SELECT * FROM requests ORDER BY received_at_ms, request_id"
      ).all() as unknown as RequestRow[];
      for (const row of rows) mapRequest(row);
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Request ledger integrity could not be verified");
    }
  }

  /**
   * Approvals, revocations, and kill-switches are durable authority inputs.
   * Validate every row before startup can evaluate policy or recover work;
   * malformed authority state must never be deferred to a later lookup.
   */
  private verifyAuthorityLedgerIntegrity(): void {
    try {
      const approvalRows = this.database.prepare(
        "SELECT * FROM approvals ORDER BY issued_at_ms, approval_id"
      ).all() as unknown as ApprovalRow[];
      for (const row of approvalRows) mapApproval(row);

      const revocationRows = this.database.prepare(
        "SELECT kind, subject_id, revoked_at_ms, reason FROM revocations ORDER BY kind, subject_id"
      ).all() as unknown as RevocationRow[];
      for (const row of revocationRows) validateStoredRevocation(row);

      const switchRows = this.database.prepare(
        "SELECT name, disabled, changed_at_ms, reason FROM switches ORDER BY name"
      ).all() as unknown as SwitchRow[];
      for (const row of switchRows) validateStoredSwitch(row);
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Authority ledger integrity could not be verified");
    }
  }

  /**
   * Jobs are durable authority and recovery inputs. Validate every persisted
   * row before startup reconciliation can inspect or mutate it; otherwise a
   * malformed terminal row or ownership descriptor could remain dormant until
   * a later status/recovery request.
   */
  private verifyJobLedgerIntegrity(): void {
    try {
      const rows = this.database.prepare(
        "SELECT * FROM jobs ORDER BY created_at_ms, job_id"
      ).all() as unknown as JobRow[];
      for (const row of rows) mapJob(row);
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Job ledger integrity could not be verified");
    }
  }

  /** Creates a verified, owner-only encrypted backup without exposing the live database handle. */
  backupTo(directory: string, options: BrokerBackupOptions = {}): Promise<BrokerBackupManifest> {
    return createBrokerBackup(this.database, directory, options);
  }

  /** Prunes only exact Broker backup names in a protected directory. */
  pruneBackups(directory: string, retainCount?: number): Promise<BrokerBackupPruneResult> {
    return pruneBrokerBackups(directory, retainCount);
  }

  /** Restores a verified encrypted backup into a fresh destination without replacing an existing database. */
  static restoreBackup(backupPath: string, destinationPath: string, keySource?: BrokerBackupKeySource): Promise<BrokerBackupManifest> {
    return restoreBrokerBackup(backupPath, destinationPath, keySource);
  }

  admitRequest(input: AdmitRequestInput, limits?: RequestAdmissionLimits): RequestRecord {
    validateRequestAdmission(input);
    validateRequestAdmissionLimits(limits);
    try {
      return this.runTransaction(() => {
        this.database.prepare("DELETE FROM nonces WHERE expires_at_ms < ?").run(input.receivedAtMs);
        enforceRequestAdmissionLimits(this.database, input, limits);
        this.database.prepare(
          "INSERT INTO nonces(edge_id, nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?)"
        ).run(input.edgeId, input.nonce, input.requestId, input.receivedAtMs, input.nonceExpiresAtMs);
        this.database.prepare(`
          INSERT INTO requests(
            request_id, edge_id, principal_id, session_id, tool, policy_version, payload_digest,
            mutation, capability_families, state, result_class, target_ref, received_at_ms, updated_at_ms, revision
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'RECEIVED', NULL, NULL, ?, ?, 0)
        `).run(
          input.requestId, input.edgeId, input.principalId, input.sessionId, input.tool,
          input.policyVersion, input.payloadDigest, input.mutation ? 1 : 0,
          encodeCapabilityFamilies(input.capabilityFamilies), input.receivedAtMs, input.receivedAtMs
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
        (input.job.edgeId !== undefined && input.job.edgeId !== input.request.edgeId) ||
        (input.job.edgeKeyId !== undefined && !validEdgeKeyIdentity(input.job.edgeKeyId, input.request.edgeId)) ||
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
            mutation, capability_families, state, result_class, target_ref, approval_id, job_id, received_at_ms, updated_at_ms, revision
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 'RECEIVED', NULL, NULL, NULL, NULL, ?, ?, 0)
        `).run(
          input.request.requestId, input.request.edgeId, input.request.principalId, input.request.sessionId,
          input.request.tool, input.request.policyVersion, input.request.payloadDigest,
          encodeCapabilityFamilies(input.request.capabilityFamilies), input.request.receivedAtMs, input.request.receivedAtMs
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
              existing.target_ref !== input.job.targetRef || existing.policy_version !== input.job.policyVersion ||
              existing.owner_edge_id !== input.request.edgeId ||
              existing.owner_edge_key_id !== (input.job.edgeKeyId ?? null)) {
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
            job_id, owner_edge_id, owner_edge_key_id, owner_principal_id, owner_session_id, tool, target_ref, policy_version,
            payload_digest, idempotency_key, state, result_class, created_at_ms, started_at_ms,
            finished_at_ms, exit_code, stdout_text, stderr_text, output_truncated,
            cancel_requested, cancel_reason, write_metadata_json, privileged_payload_json, revision
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'queued', ?, NULL, NULL, NULL, '', '', 0, 0, NULL, ?, ?, 0)
        `).run(
          input.job.jobId, input.request.edgeId, input.job.edgeKeyId ?? null, input.job.ownerPrincipalId, input.job.ownerSessionId, input.job.tool,
          input.job.targetRef, input.job.policyVersion, input.job.payloadDigest, input.job.idempotencyKey,
          input.job.createdAtMs, serializeWriteJobMetadata(input.job.writeMetadata), serializePrivilegedHelperPayload(input.job.privilegedPayload)
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
            input.job.policyVersion !== current.policyVersion || input.job.targetRef !== input.intent.targetRef ||
            (input.job.edgeId !== undefined && input.job.edgeId !== current.edgeId) ||
            (input.job.edgeKeyId !== undefined && !validEdgeKeyIdentity(input.job.edgeKeyId, current.edgeId))) {
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
            job_id, owner_edge_id, owner_edge_key_id, owner_principal_id, owner_session_id, tool, target_ref, policy_version,
            payload_digest, idempotency_key, state, result_class, created_at_ms, started_at_ms,
            finished_at_ms, exit_code, stdout_text, stderr_text, output_truncated,
            cancel_requested, cancel_reason, privileged_payload_json, revision
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'queued', ?, NULL, NULL, NULL, '', '', 0, 0, NULL, ?, 0)
        `).run(
          input.job.jobId, current.edgeId, input.job.edgeKeyId ?? null, input.job.ownerPrincipalId, input.job.ownerSessionId, input.job.tool,
          input.job.targetRef, input.job.policyVersion, input.job.payloadDigest, input.job.idempotencyKey,
          input.job.createdAtMs, serializePrivilegedHelperPayload(input.job.privilegedPayload)
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
        if (transitioning.mutation) this.assertRequestApprovalActiveRecord(transitioning, nowMs);
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
        if (nowMs < current.receivedAtMs || nowMs < current.updatedAtMs) {
          throw malformedRequest();
        }
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

  revoke(kind: RevocationKind, subjectId: string, reason: string, nowMs = Date.now(), auditRequestId?: string): void {
    if (!REVOCATION_KINDS.includes(kind) || !/^[A-Za-z0-9._:@/-]{1,257}$/u.test(subjectId) || typeof reason !== "string" || reason.length > 200 || reason.includes("\0") ||
        !Number.isSafeInteger(nowMs) || nowMs < 0 ||
        (auditRequestId !== undefined && !/^[A-Za-z0-9._:@/-]{1,256}$/u.test(auditRequestId))) throw malformedJob();
    this.runTransaction(() => {
      const requestId = auditRequestId ?? `authority-revoke-${kind}-${sha256(canonicalJson({ kind, subjectId, reason, nowMs })).slice(0, 32)}`;
      const reasonDigest = sha256(reason);
      const auditBase = {
        requestId,
        principalId: "local-authority-operator",
        tool: "internal_authority_revoke",
        decision: "allow" as const,
        targetRef: `revocation:${kind}:${subjectId}`,
        policyVersion: "internal-authority-0.1",
        evidence: { kind, subjectId, reasonDigest },
        timestampMs: nowMs
      };
      this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
      this.database.prepare(
        "INSERT INTO revocations(kind, subject_id, revoked_at_ms, reason) VALUES (?, ?, ?, ?) ON CONFLICT(kind, subject_id) DO UPDATE SET revoked_at_ms=excluded.revoked_at_ms, reason=excluded.reason"
      ).run(kind, subjectId, nowMs, reason);
      const cancelled = this.cancelQueuedJobsInTransaction(
        `REVOCATION_${kind.toUpperCase()}`,
        nowMs,
        (row) => queuedJobAffectedByRevocation(kind, subjectId, row)
      );
      this.insertAudit({
        ...auditBase,
        eventType: "completion",
        resultClass: "SUCCEEDED",
        evidence: { ...auditBase.evidence, persisted: true, cancelledQueuedJobs: cancelled }
      });
    });
  }

  isRevoked(kind: RevocationKind, subjectId: string): boolean {
    if (!REVOCATION_KINDS.includes(kind) || !/^[A-Za-z0-9._:@/-]{1,257}$/u.test(subjectId)) {
      throw new BrokerError("PRECONDITION_FAILED", "Revocation query is malformed");
    }
    const row = this.database.prepare("SELECT kind, subject_id, revoked_at_ms, reason FROM revocations WHERE kind = ? AND subject_id = ?")
      .get(kind, subjectId) as RevocationRow | undefined;
    if (row === undefined) return false;
    validateStoredRevocation(row);
    return true;
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

  admitAuthorityControlCommand(input: {
    requestId: string;
    nonce: string;
    acceptedAtMs: number;
    expiresAtMs: number;
  }): void {
    if (!/^[A-Za-z0-9._:-]{1,128}$/u.test(input.requestId) ||
        !/^[A-Za-z0-9._:-]{16,128}$/u.test(input.nonce) ||
        !Number.isSafeInteger(input.acceptedAtMs) || input.acceptedAtMs < 0 ||
        !Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= input.acceptedAtMs) {
      throw new BrokerError("PRECONDITION_FAILED", "Authority control command admission is malformed");
    }
    try {
      this.runTransaction(() => {
        this.database.prepare("DELETE FROM authority_control_nonces WHERE expires_at_ms < ?").run(input.acceptedAtMs);
        this.database.prepare(
          "INSERT INTO authority_control_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
        ).run(input.nonce, input.requestId, input.acceptedAtMs, input.expiresAtMs);
      });
    } catch (error) {
      if (String(error).includes("UNIQUE constraint failed")) {
        throw new BrokerError("REPLAY_DENIED", "Authority control command nonce or request ID was already accepted");
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Authority control command admission could not be persisted");
    }
  }

  admitPrivilegedHelperCommand(input: {
    requestId: string;
    nonce: string;
    acceptedAtMs: number;
    expiresAtMs: number;
  }): void {
    if (!/^request:[A-Za-z0-9._:-]{1,240}$/u.test(input.requestId) ||
        !/^[A-Za-z0-9._:@/-]{16,128}$/u.test(input.nonce) ||
        !Number.isSafeInteger(input.acceptedAtMs) || input.acceptedAtMs < 0 ||
        !Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= input.acceptedAtMs) {
      throw new BrokerError("PRECONDITION_FAILED", "Privileged helper command admission is malformed");
    }
    try {
      this.runTransaction(() => {
        this.database.prepare("DELETE FROM privileged_helper_nonces WHERE expires_at_ms < ?").run(input.acceptedAtMs);
        this.database.prepare(
          "INSERT INTO privileged_helper_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
        ).run(input.nonce, input.requestId, input.acceptedAtMs, input.expiresAtMs);
      });
    } catch (error) {
      if (String(error).includes("UNIQUE constraint failed")) {
        throw new BrokerError("REPLAY_DENIED", "Privileged helper command nonce or request ID was already accepted");
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Privileged helper command admission could not be persisted");
    }
  }

  admitBrokerStatusRequest(input: {
    requestId: string;
    nonce: string;
    timestampMs: number;
    expiresAtMs: number;
  }): void {
    if (!/^request:broker-status-[A-Za-z0-9._:-]{16,128}$/u.test(input.requestId) ||
        !/^broker-status-nonce-[A-Za-z0-9._:-]{16,128}$/u.test(input.nonce) ||
        !Number.isSafeInteger(input.timestampMs) || input.timestampMs < 0 ||
        !Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= input.timestampMs) {
      throw new BrokerError("PRECONDITION_FAILED", "Broker status request admission is malformed");
    }
    try {
      this.runTransaction(() => {
        this.database.prepare("DELETE FROM broker_status_nonces WHERE expires_at_ms < ?").run(input.timestampMs);
        this.database.prepare(
          "INSERT INTO broker_status_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
        ).run(input.nonce, input.requestId, input.timestampMs, input.expiresAtMs);
      });
    } catch (error) {
      if (String(error).includes("UNIQUE constraint failed")) {
        throw new BrokerError("REPLAY_DENIED", "Broker status nonce or request ID was already accepted");
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Broker status request admission could not be persisted");
    }
  }

  admitVirtualizationGuestRequest(input: {
    requestId: string;
    nonce: string;
    acceptedAtMs: number;
    expiresAtMs: number;
  }): void {
    if (!/^request:guest-[A-Za-z0-9._:-]{16,128}$/u.test(input.requestId) ||
        !/^guest-nonce-[A-Za-z0-9._:-]{16,128}$/u.test(input.nonce) ||
        !Number.isSafeInteger(input.acceptedAtMs) || input.acceptedAtMs < 0 ||
        !Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= input.acceptedAtMs) {
      throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest request admission is malformed");
    }
    try {
      this.runTransaction(() => {
        this.database.prepare("DELETE FROM virtualization_guest_nonces WHERE expires_at_ms < ?").run(input.acceptedAtMs);
        const row = this.database.prepare("SELECT COUNT(*) AS count FROM virtualization_guest_nonces").get() as { count?: unknown } | undefined;
        if (!Number.isSafeInteger(row?.count) || (row?.count as number) < 0 || (row?.count as number) >= MAX_VIRTUALIZATION_GUEST_REPLAY_ROWS) {
          throw new BrokerError("AUDIT_UNAVAILABLE", "Virtualization guest replay ledger is at capacity");
        }
        this.database.prepare(
          "INSERT INTO virtualization_guest_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
        ).run(input.nonce, input.requestId, input.acceptedAtMs, input.expiresAtMs);
      });
    } catch (error) {
      if (String(error).includes("UNIQUE constraint failed")) {
        throw new BrokerError("REPLAY_DENIED", "Virtualization guest request nonce or request ID was already accepted");
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Virtualization guest request admission could not be persisted");
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

  private cancelQueuedJobsInTransaction(
    authority: string,
    nowMs: number,
    affected: (row: JobRow) => boolean
  ): number {
    const rows = this.database.prepare(
      "SELECT * FROM jobs WHERE state = 'queued' ORDER BY created_at_ms, job_id"
    ).all() as unknown as JobRow[];
    let cancelled = 0;
    for (const row of rows) {
      if (!affected(row)) continue;
      this.database.prepare(`
        UPDATE jobs SET state = 'cancelled', result_class = 'denied', finished_at_ms = ?,
          cancel_requested = 1, cancel_reason = ?, revision = revision + 1
        WHERE job_id = ? AND state = 'queued' AND revision = ?
      `).run(nowMs, authority, row.job_id, row.revision);
      this.insertAudit({
        requestId: `job-authority-${sha256(row.job_id).slice(0, 32)}-${row.revision + 1}`,
        principalId: row.owner_principal_id,
        tool: "internal_job_authority_reconcile",
        eventType: "completion",
        decision: "allow",
        resultClass: "CANCELLED",
        targetRef: `job:${row.job_id}`,
        policyVersion: row.policy_version,
        evidence: { priorState: "queued", nextState: "cancelled", authority },
        timestampMs: nowMs
      });
      cancelled += 1;
    }
    return cancelled;
  }

  setSwitch(name: SwitchName, disabled: boolean, reason: string, nowMs = Date.now(), expectedDisabled?: boolean, auditRequestId?: string): void {
    if (!SWITCH_NAMES.includes(name) || typeof reason !== "string" || reason.length > 200 || reason.includes("\0") ||
        !Number.isSafeInteger(nowMs) || nowMs < 0 ||
        (expectedDisabled !== undefined && typeof expectedDisabled !== "boolean") ||
        (auditRequestId !== undefined && !/^[A-Za-z0-9._:@/-]{1,256}$/u.test(auditRequestId))) throw malformedJob();
    this.runTransaction(() => {
      const existing = this.database.prepare("SELECT disabled FROM switches WHERE name = ?").get(name) as { disabled: number } | undefined;
      const currentDisabled = existing?.disabled === 1;
      if (expectedDisabled !== undefined && currentDisabled !== expectedDisabled) {
        throw new BrokerError("CONFLICT", "Kill-switch state changed since the authority command was issued");
      }
      const requestId = auditRequestId ?? `authority-switch-${name}-${sha256(canonicalJson({ name, disabled, reason, nowMs })).slice(0, 32)}`;
      const reasonDigest = sha256(reason);
      const auditBase = {
        requestId,
        principalId: "local-authority-operator",
        tool: "internal_authority_switch",
        decision: "allow" as const,
        targetRef: `switch:${name}`,
        policyVersion: "internal-authority-0.1",
        evidence: { name, disabled, reasonDigest },
        timestampMs: nowMs
      };
      this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
      this.database.prepare(
        "INSERT INTO switches(name, disabled, changed_at_ms, reason) VALUES (?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET disabled=excluded.disabled, changed_at_ms=excluded.changed_at_ms, reason=excluded.reason"
      ).run(name, disabled ? 1 : 0, nowMs, reason);
      const cancelled = disabled
        ? this.cancelQueuedJobsInTransaction(`SWITCH_${name.toUpperCase()}`, nowMs, (row) => queuedJobAffectedBySwitch(name, row.tool))
        : 0;
      this.insertAudit({
        ...auditBase,
        eventType: "completion",
        resultClass: "SUCCEEDED",
        evidence: { ...auditBase.evidence, persisted: true, cancelledQueuedJobs: cancelled }
      });
    });
  }

  isSwitchDisabled(name: SwitchName): boolean {
    if (!SWITCH_NAMES.includes(name)) throw new BrokerError("PRECONDITION_FAILED", "Kill-switch query is malformed");
    const row = this.database.prepare("SELECT name, disabled, changed_at_ms, reason FROM switches WHERE name = ?")
      .get(name) as SwitchRow | undefined;
    if (row !== undefined) validateStoredSwitch(row);
    return row?.disabled === 1;
  }

  createJob(input: CreateJobInput): { job: BrokerJob; reused: boolean } {
    validateJobCreation(input);
    return this.runTransaction(() => {
      const existing = this.database.prepare(
        "SELECT * FROM jobs WHERE owner_principal_id = ? AND idempotency_key = ?"
      ).get(input.ownerPrincipalId, input.idempotencyKey) as JobRow | undefined;
      if (existing) {
        if (existing.payload_digest !== input.payloadDigest || existing.tool !== input.tool ||
            existing.target_ref !== input.targetRef || existing.policy_version !== input.policyVersion ||
            existing.owner_edge_id !== (input.edgeId ?? null) ||
            existing.owner_edge_key_id !== (input.edgeKeyId ?? null)) {
          throw new BrokerError("CONFLICT", "Idempotency key was already used for a different authorized job");
        }
        return { job: mapJob(existing), reused: true };
      }
      this.database.prepare(`
        INSERT INTO jobs(
          job_id, owner_edge_id, owner_edge_key_id, owner_principal_id, owner_session_id, tool, target_ref, policy_version,
          payload_digest, idempotency_key, state, result_class, created_at_ms, started_at_ms,
          finished_at_ms, exit_code, stdout_text, stderr_text, output_truncated,
          cancel_requested, cancel_reason, write_metadata_json, process_metadata_json, guest_metadata_json, privileged_payload_json, revision
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'queued', ?, NULL, NULL, NULL, '', '', 0, 0, NULL, ?, '', '', ?, 0)
      `).run(
        input.jobId, input.edgeId ?? null, input.edgeKeyId ?? null, input.ownerPrincipalId, input.ownerSessionId, input.tool, input.targetRef,
        input.policyVersion, input.payloadDigest, input.idempotencyKey, input.createdAtMs,
        serializeWriteJobMetadata(input.writeMetadata), serializePrivilegedHelperPayload(input.privilegedPayload)
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

  /**
   * Return only restart-reconciled unknown write jobs with persisted
   * descriptors. This is intentionally narrower than a prefix scan: callers
   * must prove the Broker restart boundary before attempting artifact cleanup.
   */
  restartUnknownWriteJobs(limit = 100): BrokerJob[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw malformedJob();
    const rows = this.database.prepare(`
      SELECT * FROM jobs
      WHERE tool = 'mac_write_file_atomic'
        AND state = 'unknown'
        AND cancel_reason = 'BROKER_RESTART'
        AND write_metadata_json <> ''
      ORDER BY created_at_ms, job_id
      LIMIT ?
    `).all(limit) as unknown as JobRow[];
    return rows.map(mapJob);
  }

  /** Return restart-reconciled task Jobs that retain a verified process identity. */
  restartUnknownProcessJobs(limit = 100): BrokerJob[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw malformedJob();
    const rows = this.database.prepare(`
      SELECT * FROM jobs
      WHERE tool = 'mac_task_run'
        AND state = 'unknown'
        AND cancel_reason = 'BROKER_RESTART'
        AND process_metadata_json <> ''
      ORDER BY created_at_ms, job_id
      LIMIT ?
    `).all(limit) as unknown as JobRow[];
    return rows.map(mapJob);
  }

  /** Return restart-reconciled Virtualization tasks with an admitted request identity. */
  restartUnknownGuestJobs(limit = 100): BrokerJob[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw malformedJob();
    const rows = this.database.prepare(`
      SELECT * FROM jobs
      WHERE tool = 'mac_task_run'
        AND state = 'unknown'
        AND cancel_reason = 'BROKER_RESTART'
        AND guest_metadata_json <> ''
      ORDER BY created_at_ms, job_id
      LIMIT ?
    `).all(limit) as unknown as JobRow[];
    return rows.map(mapJob);
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

  startJob(jobId: string, principalId: string, expectedRevision: number, startedAtMs: number, lease?: JobLease): BrokerJob {
    if (!Number.isSafeInteger(startedAtMs) || startedAtMs < 0) throw malformedJob();
    if (lease !== undefined) validateJobLease(lease, startedAtMs, false);
    return this.transitionJob(jobId, principalId, expectedRevision, ["queued"], (current) => {
      if (startedAtMs < current.createdAtMs) throw malformedJob();
      this.database.prepare(`
        UPDATE jobs SET state = 'running', result_class = 'accepted', started_at_ms = ?,
          lease_owner_id = ?, lease_token = ?, lease_acquired_at_ms = ?,
          lease_heartbeat_at_ms = ?, lease_expires_at_ms = ?, revision = revision + 1
        WHERE job_id = ? AND owner_principal_id = ?
      `).run(
        startedAtMs,
        lease?.ownerId ?? null,
        lease?.token ?? null,
        lease ? startedAtMs : null,
        lease ? startedAtMs : null,
        lease?.expiresAtMs ?? null,
        jobId,
        principalId
      );
    }, undefined, startedAtMs);
  }

  recordJobProcessOwnership(
    jobId: string,
    principalId: string,
    expectedRevision: number,
    metadata: ProcessJobMetadata,
    lease: JobLease,
    nowMs: number
  ): BrokerJob {
    validateProcessJobMetadata(metadata);
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw malformedJob();
    validateJobLease(lease, nowMs, false);
    return this.transitionJob(jobId, principalId, expectedRevision, ["running"], (current) => {
      if (current.tool !== "mac_task_run" || current.startedAtMs === null ||
          metadata.recordedAtMs < current.startedAtMs || metadata.recordedAtMs > nowMs) {
        throw new BrokerError("PRECONDITION_FAILED", "Task process ownership metadata is outside the active Job window");
      }
      if (current.processMetadata !== undefined) throw new BrokerError("CONFLICT", "Process ownership was already recorded");
      this.database.prepare(`
        UPDATE jobs SET process_metadata_json = ?, revision = revision + 1
        WHERE job_id = ? AND owner_principal_id = ?
      `).run(serializeProcessJobMetadata(metadata), jobId, principalId);
    }, lease, nowMs);
  }

  updateJobProcessOwnership(
    jobId: string,
    principalId: string,
    expectedRevision: number,
    metadata: ProcessJobMetadata,
    lease: JobLease,
    nowMs: number
  ): BrokerJob {
    validateProcessJobMetadata(metadata);
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw malformedJob();
    validateJobLease(lease, nowMs, false);
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) throw malformedJob();
    return this.runTransaction(() => {
      const currentRow = this.requireOwnedJobRow(jobId, principalId);
      const current = mapJob(currentRow);
      if (current.revision !== expectedRevision || current.state !== "running") {
        throw new BrokerError("CONFLICT", "Job state or revision changed concurrently");
      }
      assertActiveJobLease(currentRow, lease, nowMs);
      if (current.tool !== "mac_task_run" || current.startedAtMs === null ||
          current.processMetadata === undefined ||
          metadata.recordedAtMs < current.startedAtMs || metadata.recordedAtMs > nowMs ||
          metadata.pid !== current.processMetadata.pid ||
          metadata.processGroupId !== current.processMetadata.processGroupId ||
          metadata.startTimeMicros !== current.processMetadata.startTimeMicros ||
          metadata.ownershipProof !== current.processMetadata.ownershipProof ||
          metadata.recordedAtMs < current.processMetadata.recordedAtMs) {
        throw new BrokerError("PRECONDITION_FAILED", "Task process ownership metadata is outside the active Job window");
      }
      const nextDescendants = new Set(metadata.descendants.map((descendant) => `${descendant.pid}:${descendant.startTimeMicros}`));
      for (const descendant of current.processMetadata.descendants) {
        if (!nextDescendants.has(`${descendant.pid}:${descendant.startTimeMicros}`)) {
          throw new BrokerError("CONFLICT", "Task process ownership snapshot regressed");
        }
      }
      if (metadata.descendants.length < current.processMetadata.descendants.length) {
        throw new BrokerError("CONFLICT", "Task process ownership snapshot regressed");
      }
      const updated = this.database.prepare(`
        UPDATE jobs SET process_metadata_json = ?
        WHERE job_id = ? AND owner_principal_id = ? AND state = 'running'
          AND revision = ? AND lease_owner_id = ? AND lease_token = ?
          AND lease_expires_at_ms > ?
      `).run(
        serializeProcessJobMetadata(metadata), jobId, principalId, expectedRevision,
        lease.ownerId, lease.token, nowMs
      );
      if (updated.changes !== 1) throw new BrokerError("CONFLICT", "Job process ownership changed concurrently");
      return this.requireOwnedJob(jobId, principalId);
    });
  }

  recordJobGuestRequest(
    jobId: string,
    principalId: string,
    expectedRevision: number,
    metadata: GuestTaskJobMetadata,
    lease: JobLease,
    nowMs: number
  ): BrokerJob {
    validateGuestTaskJobMetadata(metadata);
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw malformedJob();
    validateJobLease(lease, nowMs, false);
    return this.transitionJob(jobId, principalId, expectedRevision, ["running"], (current) => {
      if (current.tool !== "mac_task_run" || current.startedAtMs === null ||
          metadata.recordedAtMs < current.startedAtMs || metadata.recordedAtMs > nowMs) {
        throw new BrokerError("PRECONDITION_FAILED", "Guest request metadata is outside the active Job window");
      }
      if (current.guestMetadata !== undefined) {
        throw new BrokerError("CONFLICT", "Guest request metadata was already recorded");
      }
      this.database.prepare(`
        UPDATE jobs SET guest_metadata_json = ?, revision = revision + 1
        WHERE job_id = ? AND owner_principal_id = ?
      `).run(serializeGuestTaskJobMetadata(metadata), jobId, principalId);
    }, lease, nowMs);
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
    },
    lease?: JobLease,
    leaseNowMs = Date.now()
  ): BrokerJob {
    if (!Number.isSafeInteger(outcome.finishedAtMs) || outcome.finishedAtMs < 0) throw malformedJob();
    if (!validTerminalOutcome(outcome.state, outcome.resultClass)) throw malformedJob();
    if (!Number.isSafeInteger(leaseNowMs) || leaseNowMs < 0) throw malformedJob();
    if (lease !== undefined) validateJobLease(lease, leaseNowMs, true);
    const stdout = sanitizeJobOutput(outcome.stdout ?? "");
    const stderr = sanitizeJobOutput(outcome.stderr ?? "");
    const exitCode = outcome.exitCode ?? null;
    if (exitCode !== null && (!Number.isInteger(exitCode) || exitCode < -2_147_483_648 || exitCode > 2_147_483_647)) {
      throw malformedJob();
    }
    return this.transitionJob(jobId, principalId, expectedRevision, ["running"], (current) => {
      if (current.startedAtMs === null || outcome.finishedAtMs < current.startedAtMs) throw malformedJob();
      // A cancellation request is a durable authority change. If it wins the
      // revision race before completion, never persist a late success; the
      // caller must recover the running Job as unknown instead.
      if (current.cancelRequested && outcome.state === "completed") {
        throw new BrokerError("CANCELLED", "Job cancellation was requested before completion");
      }
      this.database.prepare(`
        UPDATE jobs SET state = ?, result_class = ?, finished_at_ms = ?, exit_code = ?,
          stdout_text = ?, stderr_text = ?, output_truncated = ?, process_metadata_json = CASE WHEN ? = 'unknown' THEN process_metadata_json ELSE '' END,
          guest_metadata_json = CASE WHEN ? = 'unknown' THEN guest_metadata_json ELSE '' END,
          lease_owner_id = NULL, lease_token = NULL, lease_acquired_at_ms = NULL,
          lease_heartbeat_at_ms = NULL, lease_expires_at_ms = NULL, revision = revision + 1
        WHERE job_id = ? AND owner_principal_id = ?
      `).run(
        outcome.state, outcome.resultClass, outcome.finishedAtMs, exitCode,
        stdout.value, stderr.value, stdout.truncated || stderr.truncated ? 1 : 0, outcome.state, outcome.state, jobId, principalId
      );
    }, lease, leaseNowMs, outcome.state === "unknown");
  }

  /**
   * Promote one restart-unknown guest task only after a verified, authenticated
   * status response. No active lease is accepted and the persisted guest
   * identity is cleared once a terminal readback is recorded.
   */
  reconcileUnknownGuestTask(
    jobId: string,
    principalId: string,
    expectedRevision: number,
    outcome: {
      state: Exclude<JobState, "queued" | "running" | "unknown">;
      resultClass: Exclude<JobResultClass, "queued" | "accepted" | "unknown">;
      finishedAtMs: number;
      exitCode?: number | null;
      stdout?: string;
      stderr?: string;
      verificationStatus: "verified";
    }
  ): BrokerJob {
    if (!Number.isSafeInteger(outcome.finishedAtMs) || outcome.finishedAtMs < 0 || outcome.verificationStatus !== "verified") {
      throw malformedJob();
    }
    if (!validTerminalOutcome(outcome.state, outcome.resultClass)) throw malformedJob();
    const stdout = sanitizeJobOutput(outcome.stdout ?? "");
    const stderr = sanitizeJobOutput(outcome.stderr ?? "");
    const exitCode = outcome.exitCode ?? null;
    if (exitCode !== null && (!Number.isInteger(exitCode) || exitCode < -2_147_483_648 || exitCode > 2_147_483_647)) {
      throw malformedJob();
    }
    return this.runTransaction(() => {
      const currentRow = this.requireOwnedJobRow(jobId, principalId);
      const current = mapJob(currentRow);
      if (current.revision !== expectedRevision || current.state !== "unknown" ||
          current.tool !== "mac_task_run" || current.guestMetadata === undefined ||
          currentRow.cancel_requested !== 1 || currentRow.cancel_reason !== "BROKER_RESTART" ||
          currentRow.lease_token !== null || current.startedAtMs === null ||
          outcome.finishedAtMs < current.startedAtMs) {
        throw new BrokerError("CONFLICT", "Guest Job recovery precondition changed concurrently");
      }
      const updated = this.database.prepare(`
        UPDATE jobs SET state = ?, result_class = ?, finished_at_ms = ?, exit_code = ?,
          stdout_text = ?, stderr_text = ?, output_truncated = ?, guest_metadata_json = '',
          revision = revision + 1
        WHERE job_id = ? AND owner_principal_id = ? AND state = 'unknown'
          AND revision = ? AND lease_token IS NULL AND guest_metadata_json <> ''
      `).run(
        outcome.state, outcome.resultClass, outcome.finishedAtMs, exitCode,
        stdout.value, stderr.value, stdout.truncated || stderr.truncated ? 1 : 0,
        jobId, principalId, expectedRevision
      );
      if (updated.changes !== 1) throw new BrokerError("CONFLICT", "Guest Job recovery changed concurrently");
      return this.requireOwnedJob(jobId, principalId);
    });
  }

  renewJobLease(jobId: string, principalId: string, lease: JobLease, nowMs: number, leaseDurationMs = 30_000): JobLease {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0 || !Number.isSafeInteger(leaseDurationMs) ||
        leaseDurationMs < 1_000 || leaseDurationMs > MAX_JOB_LEASE_MS) {
      throw malformedJob();
    }
    validateJobLease(lease, nowMs, false);
    return this.runTransaction(() => {
      const row = this.requireOwnedJobRow(jobId, principalId);
      assertActiveJobLease(row, lease, nowMs);
      const expiresAtMs = nowMs + leaseDurationMs;
      if (!Number.isSafeInteger(expiresAtMs)) throw malformedJob();
      const updated = this.database.prepare(`
        UPDATE jobs SET lease_heartbeat_at_ms = ?, lease_expires_at_ms = ?
        WHERE job_id = ? AND owner_principal_id = ? AND state = 'running'
          AND cancel_requested = 0 AND lease_owner_id = ? AND lease_token = ?
          AND lease_expires_at_ms > ?
      `).run(nowMs, expiresAtMs, jobId, principalId, lease.ownerId, lease.token, nowMs);
      if (updated.changes !== 1) throw new BrokerError("CANCELLED", "Job lease is no longer active");
      lease.expiresAtMs = expiresAtMs;
      return lease;
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
        const current = mapJob(row);
        if (nowMs < current.createdAtMs ||
            (current.startedAtMs !== null && nowMs < current.startedAtMs) ||
            (row.lease_heartbeat_at_ms !== null && nowMs < row.lease_heartbeat_at_ms)) {
          throw malformedJob();
        }
        const priorState = current.state;
        const nextState: JobState = priorState === "queued" ? "cancelled" : "unknown";
        const resultClass: JobResultClass = priorState === "queued" ? "denied" : "unknown";
        this.database.prepare(`
          UPDATE jobs SET state = ?, result_class = ?, finished_at_ms = ?, cancel_requested = 1,
            cancel_reason = 'BROKER_RESTART', lease_owner_id = NULL, lease_token = NULL,
            lease_acquired_at_ms = NULL, lease_heartbeat_at_ms = NULL, lease_expires_at_ms = NULL,
            revision = revision + 1 WHERE job_id = ? AND revision = ?
        `).run(nextState, resultClass, nowMs, current.jobId, current.revision);
        if (priorState === "queued") queuedCancelled += 1;
        else runningUnknown += 1;
        this.insertAudit({
          requestId: `job-reconcile-${current.jobId}-${current.revision + 1}`,
          principalId: current.ownerPrincipalId,
          tool: "internal_job_reconcile",
          eventType: "completion",
          decision: "allow",
          resultClass: nextState === "unknown" ? "UNKNOWN_OUTCOME" : "CANCELLED",
          targetRef: `job:${current.jobId}`,
          policyVersion: current.policyVersion,
          evidence: { priorState, nextState, revision: current.revision + 1 },
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
    if (row !== undefined) {
      validateStoredPolicyHistoryRow(row);
      assertStoredPolicyMatchesHistory(this.database, row);
    }
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
    if (row !== undefined) {
      validateStoredConfigIdentityRow(row, "Approval key");
      assertStoredConfigMatchesHistory(this.database, "approval_key_config_history", row, "Approval key");
    }
    return row ? {
      revision: row.revision,
      payloadDigest: row.payload_digest,
      activatedAtMs: row.activated_at_ms
    } : undefined;
  }

  activateEdgeKeyConfig(
    identity: EdgeKeyConfigActivationIdentity,
    expectedPreviousRevision: number
  ): void {
    if (!Number.isSafeInteger(identity.revision) || identity.revision < 1 ||
        !/^[a-f0-9]{64}$/u.test(identity.payloadDigest) ||
        !Number.isSafeInteger(identity.activatedAtMs) || identity.activatedAtMs < 0 ||
        !Number.isSafeInteger(expectedPreviousRevision) || expectedPreviousRevision < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Edge key configuration identity is malformed");
    }
    try {
      this.runTransaction(() => {
        const current = this.activeEdgeKeyConfigIdentity();
        if ((current?.revision ?? 0) !== expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Persisted Edge key configuration revision changed concurrently");
        }
        if (identity.revision <= expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Edge key configuration revision must increase");
        }
        const highest = this.database.prepare(
          "SELECT MAX(revision) AS revision FROM edge_key_config_history"
        ).get() as { revision: number | null };
        if (identity.revision <= (highest.revision ?? 0)) {
          throw new BrokerError("CONFLICT", "Edge key configuration revision was already used or is below history");
        }
        const requestId = `edge-key-config-${identity.revision}-${identity.payloadDigest.slice(0, 16)}`;
        const auditBase = {
          requestId,
          principalId: "local-edge-key-loader",
          tool: "internal_edge_key_config_activate",
          decision: "allow" as const,
          targetRef: `edge_key_config:${identity.revision}`,
          policyVersion: "internal-edge-key-config-0.1",
          evidence: { payloadDigest: identity.payloadDigest, revision: identity.revision },
          timestampMs: identity.activatedAtMs
        };
        this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
        this.database.prepare(
          "INSERT INTO edge_key_config_history(revision, payload_digest, activated_at_ms) VALUES (?, ?, ?)"
        ).run(identity.revision, identity.payloadDigest, identity.activatedAtMs);
        this.database.prepare(`
          INSERT INTO active_edge_key_config(singleton, revision, payload_digest, activated_at_ms)
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
      throw new BrokerError("AUDIT_UNAVAILABLE", "Edge key configuration activation could not be persisted");
    }
  }

  activeEdgeKeyConfigIdentity(): EdgeKeyConfigActivationIdentity | undefined {
    const row = this.database.prepare(`
      SELECT revision, payload_digest, activated_at_ms
      FROM active_edge_key_config WHERE singleton = 1
    `).get() as {
      revision: number;
      payload_digest: string;
      activated_at_ms: number;
    } | undefined;
    if (row !== undefined) {
      validateStoredConfigIdentityRow(row, "Edge key");
      assertStoredConfigMatchesHistory(this.database, "edge_key_config_history", row, "Edge key");
    }
    return row ? {
      revision: row.revision,
      payloadDigest: row.payload_digest,
      activatedAtMs: row.activated_at_ms
    } : undefined;
  }

  activateAuthorityKeyConfig(
    identity: AuthorityKeyConfigActivationIdentity,
    expectedPreviousRevision: number
  ): void {
    if (!Number.isSafeInteger(identity.revision) || identity.revision < 1 ||
        !/^[a-f0-9]{64}$/u.test(identity.payloadDigest) ||
        !Number.isSafeInteger(identity.activatedAtMs) || identity.activatedAtMs < 0 ||
        !Number.isSafeInteger(expectedPreviousRevision) || expectedPreviousRevision < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Authority key configuration identity is malformed");
    }
    try {
      this.runTransaction(() => {
        const current = this.activeAuthorityKeyConfigIdentity();
        if ((current?.revision ?? 0) !== expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Persisted authority key configuration revision changed concurrently");
        }
        if (identity.revision <= expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Authority key configuration revision must increase");
        }
        const highest = this.database.prepare(
          "SELECT MAX(revision) AS revision FROM authority_key_config_history"
        ).get() as { revision: number | null };
        if (identity.revision <= (highest.revision ?? 0)) {
          throw new BrokerError("CONFLICT", "Authority key configuration revision was already used or is below history");
        }
        const requestId = `authority-key-config-${identity.revision}-${identity.payloadDigest.slice(0, 16)}`;
        const auditBase = {
          requestId,
          principalId: "local-authority-key-loader",
          tool: "internal_authority_key_config_activate",
          decision: "allow" as const,
          targetRef: `authority_key_config:${identity.revision}`,
          policyVersion: "internal-authority-key-config-0.1",
          evidence: { payloadDigest: identity.payloadDigest, revision: identity.revision },
          timestampMs: identity.activatedAtMs
        };
        this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
        this.database.prepare(
          "INSERT INTO authority_key_config_history(revision, payload_digest, activated_at_ms) VALUES (?, ?, ?)"
        ).run(identity.revision, identity.payloadDigest, identity.activatedAtMs);
        this.database.prepare(`
          INSERT INTO active_authority_key_config(singleton, revision, payload_digest, activated_at_ms)
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
      throw new BrokerError("AUDIT_UNAVAILABLE", "Authority key configuration activation could not be persisted");
    }
  }

  activeAuthorityKeyConfigIdentity(): AuthorityKeyConfigActivationIdentity | undefined {
    const row = this.database.prepare(`
      SELECT revision, payload_digest, activated_at_ms
      FROM active_authority_key_config WHERE singleton = 1
    `).get() as {
      revision: number;
      payload_digest: string;
      activated_at_ms: number;
    } | undefined;
    if (row !== undefined) {
      validateStoredConfigIdentityRow(row, "Authority key");
      assertStoredConfigMatchesHistory(this.database, "authority_key_config_history", row, "Authority key");
    }
    return row ? {
      revision: row.revision,
      payloadDigest: row.payload_digest,
      activatedAtMs: row.activated_at_ms
    } : undefined;
  }

  activateHelperKeyConfig(
    identity: HelperKeyConfigActivationIdentity,
    expectedPreviousRevision: number
  ): void {
    if (!Number.isSafeInteger(identity.revision) || identity.revision < 1 ||
        !/^[a-f0-9]{64}$/u.test(identity.payloadDigest) ||
        !Number.isSafeInteger(identity.activatedAtMs) || identity.activatedAtMs < 0 ||
        !Number.isSafeInteger(expectedPreviousRevision) || expectedPreviousRevision < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Helper key configuration identity is malformed");
    }
    try {
      this.runTransaction(() => {
        const current = this.activeHelperKeyConfigIdentity();
        if ((current?.revision ?? 0) !== expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Persisted helper key configuration revision changed concurrently");
        }
        if (identity.revision <= expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Helper key configuration revision must increase");
        }
        const highest = this.database.prepare(
          "SELECT MAX(revision) AS revision FROM helper_key_config_history"
        ).get() as { revision: number | null };
        if (identity.revision <= (highest.revision ?? 0)) {
          throw new BrokerError("CONFLICT", "Helper key configuration revision was already used or is below history");
        }
        const requestId = `helper-key-config-${identity.revision}-${identity.payloadDigest.slice(0, 16)}`;
        const auditBase = {
          requestId,
          principalId: "local-helper-key-loader",
          tool: "internal_helper_key_config_activate",
          decision: "allow" as const,
          targetRef: `helper_key_config:${identity.revision}`,
          policyVersion: "internal-helper-key-config-0.1",
          evidence: { payloadDigest: identity.payloadDigest, revision: identity.revision },
          timestampMs: identity.activatedAtMs
        };
        this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
        this.database.prepare(
          "INSERT INTO helper_key_config_history(revision, payload_digest, activated_at_ms) VALUES (?, ?, ?)"
        ).run(identity.revision, identity.payloadDigest, identity.activatedAtMs);
        this.database.prepare(`
          INSERT INTO active_helper_key_config(singleton, revision, payload_digest, activated_at_ms)
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
      throw new BrokerError("AUDIT_UNAVAILABLE", "Helper key configuration activation could not be persisted");
    }
  }

  activeHelperKeyConfigIdentity(): HelperKeyConfigActivationIdentity | undefined {
    const row = this.database.prepare(`
      SELECT revision, payload_digest, activated_at_ms
      FROM active_helper_key_config WHERE singleton = 1
    `).get() as {
      revision: number;
      payload_digest: string;
      activated_at_ms: number;
    } | undefined;
    if (row !== undefined) {
      validateStoredConfigIdentityRow(row, "Helper key");
      assertStoredConfigMatchesHistory(this.database, "helper_key_config_history", row, "Helper key");
    }
    return row ? {
      revision: row.revision,
      payloadDigest: row.payload_digest,
      activatedAtMs: row.activated_at_ms
    } : undefined;
  }

  activateGuestAttestationKeyConfig(
    identity: GuestAttestationKeyConfigActivationIdentity,
    expectedPreviousRevision: number
  ): void {
    validateConfigActivationIdentity(identity, "Guest attestation key configuration");
    if (!Number.isSafeInteger(expectedPreviousRevision) || expectedPreviousRevision < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Guest attestation key configuration revision precondition is malformed");
    }
    try {
      this.runTransaction(() => {
        const current = this.activeGuestAttestationKeyConfigIdentity();
        if ((current?.revision ?? 0) !== expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Persisted guest attestation key configuration revision changed concurrently");
        }
        if (identity.revision <= expectedPreviousRevision) {
          throw new BrokerError("CONFLICT", "Guest attestation key configuration revision must increase");
        }
        const highest = this.database.prepare(
          "SELECT MAX(revision) AS revision FROM guest_attestation_key_config_history"
        ).get() as { revision: number | null };
        if (identity.revision <= (highest.revision ?? 0)) {
          throw new BrokerError("CONFLICT", "Guest attestation key configuration revision was already used or is below history");
        }
        const requestId = `guest-attestation-key-config-${identity.revision}-${identity.payloadDigest.slice(0, 16)}`;
        const auditBase = {
          requestId,
          principalId: "local-guest-attestation-key-loader",
          tool: "internal_guest_attestation_key_config_activate",
          decision: "allow" as const,
          targetRef: `guest_attestation_key_config:${identity.revision}`,
          policyVersion: "internal-guest-attestation-key-config-0.1",
          evidence: { payloadDigest: identity.payloadDigest, revision: identity.revision },
          timestampMs: identity.activatedAtMs
        };
        this.insertAudit({ ...auditBase, eventType: "intent", resultClass: "INTENT_RECORDED" });
        this.database.prepare(
          "INSERT INTO guest_attestation_key_config_history(revision, payload_digest, activated_at_ms) VALUES (?, ?, ?)"
        ).run(identity.revision, identity.payloadDigest, identity.activatedAtMs);
        this.database.prepare(`
          INSERT INTO active_guest_attestation_key_config(singleton, revision, payload_digest, activated_at_ms)
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
      throw new BrokerError("AUDIT_UNAVAILABLE", "Guest attestation key configuration activation could not be persisted");
    }
  }

  rollbackGuestAttestationKeyConfig(
    identity: GuestAttestationKeyConfigActivationIdentity,
    expectedCurrentRevision: number,
    reasonCode: string,
    rolledBackAtMs: number
  ): void {
    validateConfigActivationIdentity(identity, "Guest attestation key configuration");
    if (!Number.isSafeInteger(expectedCurrentRevision) || expectedCurrentRevision < 1 ||
        !/^[A-Z0-9_:-]{1,64}$/u.test(reasonCode) ||
        !Number.isSafeInteger(rolledBackAtMs) || rolledBackAtMs < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Guest attestation key rollback precondition is malformed");
    }
    try {
      this.runTransaction(() => {
        const current = this.activeGuestAttestationKeyConfigIdentity();
        if (!current || current.revision !== expectedCurrentRevision) {
          throw new BrokerError("CONFLICT", "Persisted guest attestation key configuration does not match rollback precondition");
        }
        if (identity.revision >= current.revision) {
          throw new BrokerError("PRECONDITION_FAILED", "Guest attestation key rollback target must be an older revision");
        }
        const historical = this.database.prepare(`
          SELECT payload_digest, activated_at_ms FROM guest_attestation_key_config_history WHERE revision = ?
        `).get(identity.revision) as { payload_digest: string; activated_at_ms: number } | undefined;
        if (!historical || historical.payload_digest !== identity.payloadDigest) {
          throw new BrokerError("PRECONDITION_FAILED", "Guest attestation key rollback target does not match verified history");
        }
        const requestId = `guest-attestation-key-rollback-${current.revision}-to-${identity.revision}`;
        const auditBase = {
          requestId,
          principalId: "local-guest-attestation-key-loader",
          tool: "internal_guest_attestation_key_config_rollback",
          decision: "allow" as const,
          targetRef: `guest_attestation_key_config:${identity.revision}`,
          policyVersion: "internal-guest-attestation-key-config-0.1",
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
          UPDATE active_guest_attestation_key_config SET revision = ?, payload_digest = ?, activated_at_ms = ?
          WHERE singleton = 1
        `).run(identity.revision, identity.payloadDigest, rolledBackAtMs);
        this.insertAudit({ ...auditBase, eventType: "completion", resultClass: "SUCCEEDED" });
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Guest attestation key configuration rollback could not be persisted");
    }
  }

  guestAttestationKeyConfigHistoryIdentity(revision: number): GuestAttestationKeyConfigActivationIdentity | undefined {
    if (!Number.isSafeInteger(revision) || revision < 1) return undefined;
    const row = this.database.prepare(`
      SELECT revision, payload_digest, activated_at_ms
      FROM guest_attestation_key_config_history WHERE revision = ?
    `).get(revision) as {
      revision: number;
      payload_digest: string;
      activated_at_ms: number;
    } | undefined;
    if (row !== undefined) validateStoredConfigIdentityRow(row, "Guest attestation key");
    return row ? { revision: row.revision, payloadDigest: row.payload_digest, activatedAtMs: row.activated_at_ms } : undefined;
  }

  activeGuestAttestationKeyConfigIdentity(): GuestAttestationKeyConfigActivationIdentity | undefined {
    const row = this.database.prepare(`
      SELECT revision, payload_digest, activated_at_ms
      FROM active_guest_attestation_key_config WHERE singleton = 1
    `).get() as {
      revision: number;
      payload_digest: string;
      activated_at_ms: number;
    } | undefined;
    if (row !== undefined) {
      validateStoredConfigIdentityRow(row, "Guest attestation key");
      assertStoredConfigMatchesHistory(this.database, "guest_attestation_key_config_history", row, "Guest attestation key");
    }
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
    if (row !== undefined) validateStoredConfigIdentityRow(row, "Policy signer");
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
    if (row !== undefined) {
      validateStoredConfigIdentityRow(row, "Policy signer");
      assertStoredConfigMatchesHistory(this.database, "policy_signer_config_history", row, "Policy signer");
    }
    return row ? { revision: row.revision, payloadDigest: row.payload_digest, activatedAtMs: row.activated_at_ms } : undefined;
  }

  auditRows(): Array<Record<string, unknown>> {
    const rows = this.database.prepare("SELECT * FROM audit_events ORDER BY sequence").all() as unknown as AuditRow[];
    let previousSequence = 0;
    for (const row of rows) {
      validateStoredAuditRow(row);
      if (row.sequence <= previousSequence) {
        throw new BrokerError("AUDIT_UNAVAILABLE", "Audit sequence ordering is malformed");
      }
      previousSequence = row.sequence;
    }
    return rows as unknown as Array<Record<string, unknown>>;
  }

  auditEventExists(requestId: string, eventType: AuditEvent["eventType"]): boolean {
    if (!/^[A-Za-z0-9._:@/-]{1,256}$/u.test(requestId)) throw new BrokerError("PRECONDITION_FAILED", "Audit request identity is malformed");
    return this.database.prepare(
      "SELECT 1 FROM audit_events WHERE request_id = ? AND event_type = ? LIMIT 1"
    ).get(requestId, eventType) !== undefined;
  }

  auditEventResult(requestId: string, eventType: AuditEvent["eventType"]): string | undefined {
    if (!/^[A-Za-z0-9._:@/-]{1,256}$/u.test(requestId)) throw new BrokerError("PRECONDITION_FAILED", "Audit request identity is malformed");
    const row = this.database.prepare(
      "SELECT result_class FROM audit_events WHERE request_id = ? AND event_type = ? ORDER BY sequence DESC LIMIT 1"
    ).get(requestId, eventType) as { result_class: string } | undefined;
    return row?.result_class;
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
        evidence = parseJsonStrict(row.evidence_json);
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

  private verifyExternalAuditAnchor(): void {
    if (this.auditAnchor === undefined) return;
    const tail = this.database.prepare("SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").get() as {
      sequence: number;
      event_hash: string;
    } | undefined;
    this.auditAnchor.verify(tail ? { sequence: tail.sequence, eventHash: tail.event_hash } : undefined);
  }

  private transitionJob(
    jobId: string,
    principalId: string,
    expectedRevision: number,
    allowedStates: readonly JobState[],
    update: (current: BrokerJob) => void,
    lease?: JobLease,
    leaseNowMs = Date.now(),
    allowExpiredLease = false
  ): BrokerJob {
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0 ||
        !Number.isSafeInteger(leaseNowMs) || leaseNowMs < 0) throw malformedJob();
    return this.runTransaction(() => {
      const currentRow = this.requireOwnedJobRow(jobId, principalId);
      const current = mapJob(currentRow);
      if (current.revision !== expectedRevision || !allowedStates.includes(current.state)) {
        throw new BrokerError("CONFLICT", "Job state or revision changed concurrently");
      }
      if (lease !== undefined) {
        assertActiveJobLease(currentRow, lease, leaseNowMs, allowExpiredLease);
      } else if (currentRow.lease_token !== null) {
        throw new BrokerError("CONFLICT", "Job lease is required for this transition");
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

  /**
   * Revalidate the approval consumed by an admitted mutation before dispatch
   * and completion. The principal binding prevents one caller from probing
   * another owner's request state.
   */
  assertRequestApprovalActive(requestId: string, principalId: string, nowMs: number): void {
    const request = this.requestRecord(requestId);
    if (!request || request.principalId !== principalId) {
      throw new BrokerError("POLICY_DENIED", "Mutation approval is not active");
    }
    this.assertRequestApprovalActiveRecord(request, nowMs);
  }

  private assertRequestApprovalActiveRecord(request: RequestRecord, nowMs: number): void {
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
    return mapJob(this.requireOwnedJobRow(jobId, principalId));
  }

  private requireOwnedJobRow(jobId: string, principalId: string): JobRow {
    const row = this.database.prepare(
      "SELECT * FROM jobs WHERE job_id = ? AND owner_principal_id = ?"
    ).get(jobId, principalId) as JobRow | undefined;
    if (!row) throw new BrokerError("TARGET_NOT_FOUND", "Broker-owned job was not found");
    return row;
  }

  private insertAudit(event: AuditEvent): string {
    validateAuditEventForPersistence(event);
    let evidenceJson: string;
    try {
      evidenceJson = canonicalJson(redactEvidence(event.evidence));
    } catch {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Audit evidence could not be canonicalized");
    }
    if (Buffer.byteLength(evidenceJson, "utf8") > 1_048_576) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Audit evidence exceeds its persistence budget");
    }
    const previous = this.database.prepare("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").get() as { event_hash: string } | undefined;
    const previousHash = previous?.event_hash ?? "0".repeat(64);
    const eventHash = sha256(canonicalJson({ ...event, evidence: parseJsonStrict(evidenceJson), previousHash }));
    this.database.prepare(`
      INSERT INTO audit_events(request_id, principal_id, tool, event_type, decision, result_class, target_ref, policy_version, evidence_json, timestamp_ms, previous_hash, event_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(event.requestId, event.principalId, event.tool, event.eventType, event.decision, event.resultClass, event.targetRef, event.policyVersion, evidenceJson, event.timestampMs, previousHash, eventHash);
    const row = this.database.prepare("SELECT sequence FROM audit_events WHERE event_hash = ?").get(eventHash) as { sequence: number } | undefined;
    if (this.auditAnchor !== undefined) {
      if (row === undefined || !Number.isSafeInteger(row.sequence) || row.sequence < 1) {
        throw new BrokerError("AUDIT_UNAVAILABLE", "Audit sequence could not be read back");
      }
      this.pendingAuditAnchor = { sequence: row.sequence, eventHash };
    }
    return eventHash;
  }

  private runTransaction<T>(operation: () => T): T {
    if (this.auditAnchorUnavailable) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Audit anchor publication is unavailable; Broker restart is required");
    }
    this.pendingAuditAnchor = undefined;
    this.database.exec("BEGIN IMMEDIATE");
    let committed = false;
    try {
      this.assertRuntimeFence();
      const result = operation();
      const pendingAnchor = this.pendingAuditAnchor;
      this.database.exec("COMMIT");
      committed = true;
      this.pendingAuditAnchor = undefined;
      this.publishPendingAuditAnchor(pendingAnchor);
      return result;
    } catch (error) {
      if (!committed) this.database.exec("ROLLBACK");
      this.pendingAuditAnchor = undefined;
      throw error;
    }
  }

  private injectFault(point: PersistenceFaultPoint): void {
    this.faultInjector?.(point);
  }

  private publishPendingAuditAnchor(anchor: { sequence: number; eventHash: string } | undefined): void {
    if (anchor === undefined || this.auditAnchor === undefined) return;
    try {
      this.auditAnchor.publish(anchor.sequence, anchor.eventHash);
    } catch {
      // SQLite is already committed and cannot be rolled back here. Freeze
      // further writes until the operator repairs the sidecar and restarts the
      // Broker, so no later mutation can run with an unanchored audit tail.
      this.auditAnchorUnavailable = true;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Audit anchor publication is unavailable; Broker restart is required");
    }
  }

  private readSchemaVersion(): number {
    const row = this.database.prepare("PRAGMA user_version").get() as { user_version?: unknown } | undefined;
    if (!Number.isSafeInteger(row?.user_version) || (row?.user_version as number) < 0) {
      throw new Error("Broker persistence schema version is malformed");
    }
    return row?.user_version as number;
  }

  private migrateSchema(previousVersion: number): void {
    this.runTransaction(() => {
      this.validateSchemaMigrationsTable(previousVersion);
      const migrations = [
        { version: 1, name: "baseline", apply: () => undefined },
        { version: 2, name: "revocations-edge-and-operator-key-kinds", apply: () => this.migrateRevocationsSchema() },
        { version: 3, name: "request-approval-and-job-linkage", apply: () => this.migrateRequestsSchema() },
        { version: 4, name: "job-lease-process-and-helper-metadata", apply: () => this.migrateJobsSchema() },
        { version: 5, name: "broker-runtime-fence", apply: () => this.migrateRuntimeFenceSchema() },
        { version: 6, name: "virtualization-guest-replay-ledger", apply: () => this.migrateVirtualizationGuestReplaySchema() },
        { version: 7, name: "virtualization-guest-task-metadata", apply: () => this.migrateVirtualizationGuestTaskMetadataSchema() },
        { version: 8, name: "virtualization-guest-attestation-key-config", apply: () => this.migrateVirtualizationGuestAttestationKeyConfigSchema() },
        { version: 9, name: "request-capability-family-capacity", apply: () => this.migrateRequestCapabilityFamilySchema() },
        { version: 10, name: "job-edge-provenance", apply: () => this.migrateJobEdgeProvenanceSchema() },
        { version: 11, name: "job-edge-key-provenance", apply: () => this.migrateJobEdgeKeyProvenanceSchema() }
      ] as const;
      const recorded = new Map<number, string>();
      const rows = this.database.prepare("SELECT version, name, applied_at_ms FROM schema_migrations ORDER BY version").all() as Array<{ version?: unknown; name?: unknown; applied_at_ms?: unknown }>;
      for (const row of rows) {
        if (!Number.isSafeInteger(row.version) || (row.version as number) < 1 || (row.version as number) > BROKER_SCHEMA_VERSION ||
            typeof row.name !== "string" || row.name.length < 1 || row.name.length > 128 ||
            !Number.isSafeInteger(row.applied_at_ms) || (row.applied_at_ms as number) < 0) {
          throw new Error("Broker schema migration registry is malformed");
        }
        const version = row.version as number;
        if (version > previousVersion || recorded.has(version)) {
          throw new Error("Broker schema migration registry is inconsistent");
        }
        recorded.set(version, row.name as string);
      }
      const maxRecorded = Math.max(0, ...recorded.keys());
      for (let version = 1; version <= maxRecorded; version += 1) {
        if (!recorded.has(version)) throw new Error("Broker schema migration registry is incomplete");
      }
      for (const migration of migrations) {
        const existingName = recorded.get(migration.version);
        if (existingName !== undefined && existingName !== migration.name) {
          throw new Error("Broker schema migration identity changed");
        }
        // Migration bodies are intentionally idempotent and are re-run for
        // every known version. This turns the registry into a shape check even
        // when a database's user_version marker was edited out of band.
        migration.apply();
        if (existingName === undefined) {
          this.database.prepare(
            "INSERT INTO schema_migrations(version, name, applied_at_ms) VALUES (?, ?, ?)"
          ).run(migration.version, migration.name, Date.now());
        }
      }
      this.database.exec(`PRAGMA user_version = ${BROKER_SCHEMA_VERSION}`);
      const finalVersion = this.readSchemaVersion();
      if (finalVersion !== BROKER_SCHEMA_VERSION) {
        throw new Error("Broker persistence schema marker readback is inconsistent");
      }
      const finalRows = this.database.prepare(
        "SELECT version, name FROM schema_migrations ORDER BY version"
      ).all() as Array<{ version?: unknown; name?: unknown }>;
      if (finalRows.length !== migrations.length || finalRows.some((row, index) =>
        row.version !== migrations[index]?.version || row.name !== migrations[index]?.name)) {
        throw new Error("Broker schema migration registry readback is inconsistent");
      }
    });
  }

  private validateSchemaMigrationsTable(previousVersion: number): void {
    const columns = this.database.prepare("PRAGMA table_info(schema_migrations)").all() as Array<{ name?: unknown }>;
    const names = new Set(columns.map((column) => column.name));
    if (!names.has("version") || !names.has("name") || !names.has("applied_at_ms")) {
      throw new Error("Broker schema migration registry is unavailable");
    }
    if (!Number.isSafeInteger(previousVersion) || previousVersion < 0 || previousVersion > BROKER_SCHEMA_VERSION) {
      throw new Error("Broker persistence schema version is malformed");
    }
  }

  private migrateRevocationsSchema(): void {
    const row = this.database.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'revocations'").get() as { sql: string };
    if (row.sql.includes("'approval_key'") && row.sql.includes("'policy_signer'") && row.sql.includes("'authority_key'") && row.sql.includes("'helper_key'") && row.sql.includes("'guest_attestation_key'")) return;
    this.database.exec(`
      ALTER TABLE revocations RENAME TO revocations_v0;
      CREATE TABLE revocations (
        kind TEXT NOT NULL CHECK (kind IN ('principal', 'session', 'edge', 'edge_key', 'approval_key', 'policy_signer', 'authority_key', 'helper_key', 'guest_attestation_key')),
        subject_id TEXT NOT NULL,
        revoked_at_ms INTEGER NOT NULL,
        reason TEXT NOT NULL,
        PRIMARY KEY (kind, subject_id)
      ) STRICT;
      INSERT INTO revocations(kind, subject_id, revoked_at_ms, reason)
        SELECT kind, subject_id, revoked_at_ms, reason FROM revocations_v0;
      DROP TABLE revocations_v0;
    `);
  }

  private migrateRequestsSchema(): void {
    const columns = this.database.prepare("PRAGMA table_info(requests)").all() as Array<{ name: string }>;
    const names = new Set(columns.map((column) => column.name));
    if (!names.has("approval_id")) this.database.exec("ALTER TABLE requests ADD COLUMN approval_id TEXT");
    if (!names.has("job_id")) this.database.exec("ALTER TABLE requests ADD COLUMN job_id TEXT");
  }

  private migrateJobsSchema(): void {
    const columns = this.database.prepare("PRAGMA table_info(jobs)").all() as Array<{ name: string }>;
    const names = new Set(columns.map((column) => column.name));
    if (!names.has("write_metadata_json")) {
      this.database.exec("ALTER TABLE jobs ADD COLUMN write_metadata_json TEXT NOT NULL DEFAULT ''");
    }
    if (!names.has("lease_owner_id")) {
      this.database.exec("ALTER TABLE jobs ADD COLUMN lease_owner_id TEXT");
    }
    if (!names.has("lease_token")) {
      this.database.exec("ALTER TABLE jobs ADD COLUMN lease_token TEXT");
    }
    if (!names.has("lease_acquired_at_ms")) {
      this.database.exec("ALTER TABLE jobs ADD COLUMN lease_acquired_at_ms INTEGER");
    }
    if (!names.has("lease_heartbeat_at_ms")) {
      this.database.exec("ALTER TABLE jobs ADD COLUMN lease_heartbeat_at_ms INTEGER");
    }
    if (!names.has("lease_expires_at_ms")) {
      this.database.exec("ALTER TABLE jobs ADD COLUMN lease_expires_at_ms INTEGER");
    }
    if (!names.has("process_metadata_json")) {
      this.database.exec("ALTER TABLE jobs ADD COLUMN process_metadata_json TEXT NOT NULL DEFAULT ''");
    }
    if (!names.has("guest_metadata_json")) {
      this.database.exec("ALTER TABLE jobs ADD COLUMN guest_metadata_json TEXT NOT NULL DEFAULT ''");
    }
    if (!names.has("privileged_payload_json")) {
      this.database.exec("ALTER TABLE jobs ADD COLUMN privileged_payload_json TEXT NOT NULL DEFAULT ''");
    }
  }

  private migrateRuntimeFenceSchema(): void {
    const table = this.database.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'broker_runtime_fence'"
    ).get() as { sql?: unknown } | undefined;
    if (typeof table?.sql !== "string" || !table.sql.includes("singleton") || !table.sql.includes("generation") ||
        !table.sql.includes("token") || !table.sql.includes("acquired_at_ms") || !table.sql.includes("STRICT")) {
      throw new Error("Broker runtime fence schema is unavailable");
    }
    const columns = this.database.prepare("PRAGMA table_info(broker_runtime_fence)").all() as Array<{ name?: unknown }>;
    const names = new Set(columns.map((column) => column.name));
    if (names.size !== 4 || !names.has("singleton") || !names.has("generation") || !names.has("token") || !names.has("acquired_at_ms")) {
      throw new Error("Broker runtime fence schema is malformed");
    }
  }

  private migrateVirtualizationGuestReplaySchema(): void {
    const table = this.database.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'virtualization_guest_nonces'"
    ).get() as { sql?: unknown } | undefined;
    if (typeof table?.sql !== "string" || !table.sql.includes("nonce") || !table.sql.includes("request_id") ||
        !table.sql.includes("accepted_at_ms") || !table.sql.includes("expires_at_ms") || !table.sql.includes("STRICT")) {
      throw new Error("Virtualization guest replay schema is unavailable");
    }
    const columns = this.database.prepare("PRAGMA table_info(virtualization_guest_nonces)").all() as Array<{ name?: unknown }>;
    const names = new Set(columns.map((column) => column.name));
    if (names.size !== 4 || !names.has("nonce") || !names.has("request_id") || !names.has("accepted_at_ms") || !names.has("expires_at_ms")) {
      throw new Error("Virtualization guest replay schema is malformed");
    }
  }

  private migrateVirtualizationGuestTaskMetadataSchema(): void {
    const columns = this.database.prepare("PRAGMA table_info(jobs)").all() as Array<{ name?: unknown }>;
    const names = new Set(columns.map((column) => column.name));
    if (!names.has("guest_metadata_json")) {
      throw new Error("Virtualization guest task metadata schema is unavailable");
    }
  }

  private migrateVirtualizationGuestAttestationKeyConfigSchema(): void {
    const createTable = (name: string, sql: string, requiredColumns: readonly string[]): void => {
      this.database.exec(sql);
      const table = this.database.prepare(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?"
      ).get(name) as { sql?: unknown } | undefined;
      if (typeof table?.sql !== "string" || !table.sql.includes("STRICT")) {
        throw new Error("Virtualization guest attestation key configuration schema is unavailable");
      }
      const columns = this.database.prepare(`PRAGMA table_info(${name})`).all() as Array<{ name?: unknown }>;
      const names = new Set(columns.map((column) => column.name));
      if (names.size !== requiredColumns.length || requiredColumns.some((column) => !names.has(column))) {
        throw new Error("Virtualization guest attestation key configuration schema is malformed");
      }
    };
    createTable(
      "guest_attestation_key_config_history",
      `CREATE TABLE IF NOT EXISTS guest_attestation_key_config_history (
        revision INTEGER PRIMARY KEY,
        payload_digest TEXT NOT NULL UNIQUE,
        activated_at_ms INTEGER NOT NULL
      ) STRICT`,
      ["revision", "payload_digest", "activated_at_ms"]
    );
    createTable(
      "active_guest_attestation_key_config",
      `CREATE TABLE IF NOT EXISTS active_guest_attestation_key_config (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        revision INTEGER NOT NULL,
        payload_digest TEXT NOT NULL,
        activated_at_ms INTEGER NOT NULL,
        FOREIGN KEY (revision) REFERENCES guest_attestation_key_config_history(revision)
      ) STRICT`,
      ["singleton", "revision", "payload_digest", "activated_at_ms"]
    );
    const revocations = this.database.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'revocations'"
    ).get() as { sql?: unknown } | undefined;
    if (typeof revocations?.sql !== "string" || !revocations.sql.includes("'guest_attestation_key'")) {
      this.database.exec(`
        ALTER TABLE revocations RENAME TO revocations_v7;
        CREATE TABLE revocations (
          kind TEXT NOT NULL CHECK (kind IN ('principal', 'session', 'edge', 'edge_key', 'approval_key', 'policy_signer', 'authority_key', 'helper_key', 'guest_attestation_key')),
          subject_id TEXT NOT NULL,
          revoked_at_ms INTEGER NOT NULL,
          reason TEXT NOT NULL,
          PRIMARY KEY (kind, subject_id)
        ) STRICT;
        INSERT INTO revocations(kind, subject_id, revoked_at_ms, reason)
          SELECT kind, subject_id, revoked_at_ms, reason FROM revocations_v7;
        DROP TABLE revocations_v7;
      `);
    }
  }

  private migrateRequestCapabilityFamilySchema(): void {
    const columns = this.database.prepare("PRAGMA table_info(requests)").all() as Array<{ name?: unknown }>;
    const names = new Set(columns.map((column) => column.name));
    if (!names.has("capability_families")) {
      this.database.exec("ALTER TABLE requests ADD COLUMN capability_families TEXT NOT NULL DEFAULT ''");
    }
    const migratedColumns = this.database.prepare("PRAGMA table_info(requests)").all() as Array<{ name?: unknown }>;
    if (!migratedColumns.some((column) => column.name === "capability_families")) {
      throw new Error("Broker request capability-family schema is unavailable");
    }
  }

  private migrateJobEdgeProvenanceSchema(): void {
    const columns = this.database.prepare("PRAGMA table_info(jobs)").all() as Array<{ name?: unknown }>;
    const names = new Set(columns.map((column) => column.name));
    if (!names.has("owner_edge_id")) {
      // Legacy Jobs have no trustworthy Edge provenance. They remain null and
      // are treated conservatively during upstream Edge revocation.
      this.database.exec("ALTER TABLE jobs ADD COLUMN owner_edge_id TEXT");
    }
    const migratedColumns = this.database.prepare("PRAGMA table_info(jobs)").all() as Array<{ name?: unknown; type?: unknown; notnull?: unknown }>;
    const ownerEdgeColumn = migratedColumns.find((column) => column.name === "owner_edge_id");
    if (ownerEdgeColumn?.type !== "TEXT" || ownerEdgeColumn.notnull !== 0) {
      throw new Error("Broker Job Edge provenance schema is unavailable");
    }
  }

  private migrateJobEdgeKeyProvenanceSchema(): void {
    const columns = this.database.prepare("PRAGMA table_info(jobs)").all() as Array<{ name?: unknown }>;
    const names = new Set(columns.map((column) => column.name));
    if (!names.has("owner_edge_key_id")) {
      // Legacy Jobs have no trustworthy Edge-key provenance. They remain null
      // and are treated conservatively during upstream key revocation.
      this.database.exec("ALTER TABLE jobs ADD COLUMN owner_edge_key_id TEXT");
    }
    const migratedColumns = this.database.prepare("PRAGMA table_info(jobs)").all() as Array<{ name?: unknown; type?: unknown; notnull?: unknown }>;
    const ownerEdgeKeyColumn = migratedColumns.find((column) => column.name === "owner_edge_key_id");
    if (ownerEdgeKeyColumn?.type !== "TEXT" || ownerEdgeKeyColumn.notnull !== 0) {
      throw new Error("Broker Job Edge-key provenance schema is unavailable");
    }
  }

  private acquireRuntimeFence(nowMs: number): void {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new Error("Broker runtime fence timestamp is malformed");
    this.database.exec("BEGIN IMMEDIATE");
    let committed = false;
    try {
      const current = this.database.prepare(
        "SELECT generation FROM broker_runtime_fence WHERE singleton = 1"
      ).get() as { generation?: unknown } | undefined;
      const previousGeneration = current?.generation ?? 0;
      if (!Number.isSafeInteger(previousGeneration) || (previousGeneration as number) < 0 ||
          (previousGeneration as number) >= Number.MAX_SAFE_INTEGER) {
        throw new Error("Broker runtime fence generation is malformed");
      }
      const generation = (previousGeneration as number) + 1;
      this.database.prepare(`
        INSERT INTO broker_runtime_fence(singleton, generation, token, acquired_at_ms)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(singleton) DO UPDATE SET generation = excluded.generation,
          token = excluded.token, acquired_at_ms = excluded.acquired_at_ms
      `).run(generation, this.runtimeFenceToken, nowMs);
      this.database.exec("COMMIT");
      committed = true;
      this.runtimeFenceGeneration = generation;
      this.runtimeFenceAcquired = true;
    } catch (error) {
      if (!committed) this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private assertRuntimeFence(): void {
    if (!this.runtimeFenceEnabled || !this.runtimeFenceAcquired) return;
    const current = this.database.prepare(
      "SELECT generation, token FROM broker_runtime_fence WHERE singleton = 1"
    ).get() as { generation?: unknown; token?: unknown } | undefined;
    if (current === undefined || current.generation !== this.runtimeFenceGeneration || current.token !== this.runtimeFenceToken) {
      throw new BrokerError("CONFLICT", "Broker runtime fence is no longer active; restart is required");
    }
  }
}

function validateConfigActivationIdentity(identity: {
  revision: number;
  payloadDigest: string;
  activatedAtMs: number;
}, label: string): void {
  if (!Number.isSafeInteger(identity.revision) || identity.revision < 1 ||
      !/^[a-f0-9]{64}$/u.test(identity.payloadDigest) ||
      !Number.isSafeInteger(identity.activatedAtMs) || identity.activatedAtMs < 0) {
    throw new BrokerError("PRECONDITION_FAILED", `${label} identity is malformed`);
  }
}

function validateStoredConfigIdentityRow(value: unknown, label: string): void {
  const fail = (): never => {
    throw new BrokerError("AUDIT_UNAVAILABLE", `Stored ${label} configuration state is malformed`);
  };
  const row = isPlainDataRecord(value) ? value : undefined;
  if (row === undefined || !Number.isSafeInteger(row.revision) || (row.revision as number) < 1 ||
      typeof row.payload_digest !== "string" || !/^[a-f0-9]{64}$/u.test(row.payload_digest as string) ||
      !Number.isSafeInteger(row.activated_at_ms) || (row.activated_at_ms as number) < 0) {
    fail();
  }
}

function validateStoredPolicyHistoryRow(value: unknown): void {
  const fail = (): never => {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored policy configuration state is malformed");
  };
  const row = isPlainDataRecord(value) ? value : undefined;
  if (row === undefined || !Number.isSafeInteger(row.revision) || (row.revision as number) < 1 ||
      typeof row.version !== "string" || !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(row.version as string) ||
      typeof row.payload_digest !== "string" || !/^[a-f0-9]{64}$/u.test(row.payload_digest as string) ||
      typeof row.key_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(row.key_id as string) ||
      !Number.isSafeInteger(row.activated_at_ms) || (row.activated_at_ms as number) < 0) {
    fail();
  }
}

function assertStoredConfigMatchesHistory(
  database: DatabaseSync,
  historyTable: string,
  active: unknown,
  label: string
): void {
  const activeRow = isPlainDataRecord(active) ? active : undefined;
  if (activeRow === undefined) {
    throw new BrokerError("AUDIT_UNAVAILABLE", `Stored ${label} configuration state is malformed`);
  }
  const revision = activeRow.revision as number;
  if (!Number.isSafeInteger(revision)) {
    throw new BrokerError("AUDIT_UNAVAILABLE", `Stored ${label} configuration state is malformed`);
  }
  const historical = database.prepare(
    `SELECT revision, payload_digest, activated_at_ms FROM ${historyTable} WHERE revision = ?`
  ).get(revision) as unknown;
  if (!isPlainDataRecord(historical) ||
      historical.revision !== activeRow.revision ||
      historical.payload_digest !== activeRow.payload_digest ||
      (historical.activated_at_ms as number) > (activeRow.activated_at_ms as number)) {
    throw new BrokerError("AUDIT_UNAVAILABLE", `Stored ${label} configuration history does not match active state`);
  }
}

function assertStoredPolicyMatchesHistory(database: DatabaseSync, active: unknown): void {
  const activeRow = isPlainDataRecord(active) ? active : undefined;
  if (activeRow === undefined) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored policy configuration state is malformed");
  }
  const revision = activeRow.revision as number;
  if (!Number.isSafeInteger(revision)) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored policy configuration state is malformed");
  }
  const historical = database.prepare(
    "SELECT revision, version, payload_digest, key_id, activated_at_ms FROM policy_history WHERE revision = ?"
  ).get(revision) as unknown;
  if (!isPlainDataRecord(historical) ||
      historical.revision !== activeRow.revision ||
      historical.version !== activeRow.version ||
      historical.payload_digest !== activeRow.payload_digest ||
      historical.key_id !== activeRow.key_id ||
      (historical.activated_at_ms as number) > (activeRow.activated_at_ms as number)) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored policy history does not match active state");
  }
}

interface JobRow {
  job_id: string;
  owner_edge_id: string | null;
  owner_edge_key_id: string | null;
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
  cancel_reason: string | null;
  lease_owner_id: string | null;
  lease_token: string | null;
  lease_acquired_at_ms: number | null;
  lease_heartbeat_at_ms: number | null;
  lease_expires_at_ms: number | null;
  write_metadata_json: string;
  process_metadata_json: string;
  guest_metadata_json: string;
  privileged_payload_json: string;
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
  capability_families: unknown;
  state: RequestState;
  result_class: string | null;
  target_ref: string | null;
  approval_id: string | null;
  job_id: string | null;
  received_at_ms: number;
  updated_at_ms: number;
  revision: number;
}

interface AuditRow {
  sequence: number;
  request_id: string;
  principal_id: string;
  tool: string;
  event_type: string;
  decision: string;
  result_class: string;
  target_ref: string;
  policy_version: string;
  evidence_json: string;
  timestamp_ms: number;
  previous_hash: string;
  event_hash: string;
}

function validateStoredAuditRow(row: AuditRow): void {
  const fail = (): never => {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored audit record is malformed");
  };
  const bounded = (value: unknown, maxLength: number): value is string =>
    typeof value === "string" && value.length >= 1 && value.length <= maxLength && !value.includes("\0");
  if (!Number.isSafeInteger(row.sequence) || row.sequence < 1 ||
      !bounded(row.request_id, 256) || !bounded(row.principal_id, 128) ||
      !bounded(row.tool, 160) || !/^(?:mac_[a-z0-9_]{1,123}|internal_[A-Za-z0-9._:-]{1,140})$/u.test(row.tool) ||
      !["decision", "intent", "completion"].includes(row.event_type) ||
      !["allow", "deny"].includes(row.decision) ||
      !bounded(row.result_class, 128) || !bounded(row.target_ref, 4096) ||
      !bounded(row.policy_version, 160) || !bounded(row.evidence_json, 1_048_576) ||
      !Number.isSafeInteger(row.timestamp_ms) || row.timestamp_ms < 0 ||
      !/^[a-f0-9]{64}$/u.test(row.previous_hash) ||
      !/^[a-f0-9]{64}$/u.test(row.event_hash)) {
    fail();
  }
  try {
    parseJsonStrict(row.evidence_json);
  } catch {
    fail();
  }
}

function validateAuditEventForPersistence(event: AuditEvent): void {
  const fail = (): never => {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit event is malformed");
  };
  const bounded = (value: unknown, maxLength: number): value is string =>
    typeof value === "string" && value.length >= 1 && value.length <= maxLength && !value.includes("\0");
  if (!bounded(event.requestId, 256) || !bounded(event.principalId, 128) ||
      !bounded(event.tool, 160) || !/^(?:mac_[a-z0-9_]{1,123}|internal_[A-Za-z0-9._:-]{1,140})$/u.test(event.tool) ||
      !["decision", "intent", "completion"].includes(event.eventType) ||
      !["allow", "deny"].includes(event.decision) || !bounded(event.resultClass, 128) ||
      !bounded(event.targetRef, 4096) || !bounded(event.policyVersion, 160) ||
      !Number.isSafeInteger(event.timestampMs) || event.timestampMs < 0) {
    fail();
  }
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

interface RevocationRow {
  kind: string;
  subject_id: string;
  revoked_at_ms: number;
  reason: string;
}

interface SwitchRow {
  name: string;
  disabled: number;
  changed_at_ms: number;
  reason: string;
}

type ReplayLedgerKind =
  | "request"
  | "approval"
  | "policy_signer"
  | "authority_control"
  | "privileged_helper"
  | "broker_status"
  | "virtualization_guest";

/** Validate one persisted replay row before it can participate in admission. */
function validateStoredReplayRow(kind: ReplayLedgerKind, value: unknown): void {
  const fail = (): never => {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored replay ledger state is malformed");
  };
  if (!isPlainDataRecord(value)) fail();
  const row = value as Record<string, unknown>;
  const stringField = (name: string, pattern: RegExp): boolean =>
    typeof row[name] === "string" && pattern.test(row[name] as string);
  const timestamp = (name: string): boolean =>
    typeof row[name] === "number" && Number.isSafeInteger(row[name]) && (row[name] as number) >= 0;
  if (!timestamp("accepted_at_ms") || !timestamp("expires_at_ms") ||
      (row.expires_at_ms as number) <= (row.accepted_at_ms as number)) {
    fail();
  }

  switch (kind) {
    case "request":
      if (!stringField("edge_id", /^[A-Za-z0-9._:@/-]{1,128}$/u) ||
          !stringField("nonce", /^[A-Za-z0-9._:@/-]{1,256}$/u) ||
          !stringField("request_id", /^[A-Za-z0-9._:@/+-]{1,128}$/u)) fail();
      return;
    case "approval":
      if (!stringField("issuer_id", /^[A-Za-z0-9._:@/-]{1,128}$/u) ||
          !stringField("key_id", /^[A-Za-z0-9._:-]{1,128}$/u) ||
          !stringField("nonce", /^approval-nonce:[A-Za-z0-9._:-]{1,240}$/u) ||
          !stringField("request_id", /^approval-issue:[A-Za-z0-9._:-]{1,240}$/u)) fail();
      return;
    case "policy_signer":
    case "authority_control":
      if (!stringField("nonce", /^[A-Za-z0-9._:-]{16,128}$/u) ||
          !stringField("request_id", /^[A-Za-z0-9._:-]{1,128}$/u)) fail();
      return;
    case "privileged_helper":
      if (!stringField("nonce", /^[A-Za-z0-9._:@/-]{16,128}$/u) ||
          !stringField("request_id", /^request:[A-Za-z0-9._:-]{1,240}$/u)) fail();
      return;
    case "broker_status":
      if (!stringField("nonce", /^broker-status-nonce-[A-Za-z0-9._:-]{16,128}$/u) ||
          !stringField("request_id", /^request:broker-status-[A-Za-z0-9._:-]{16,128}$/u)) fail();
      return;
    case "virtualization_guest":
      if (!stringField("nonce", /^guest-nonce-[A-Za-z0-9._:-]{16,128}$/u) ||
          !stringField("request_id", /^request:guest-[A-Za-z0-9._:-]{16,128}$/u)) fail();
      return;
    default:
      fail();
  }
}

function mapRequest(row: RequestRow): RequestRecord {
  validateStoredRequestState(row);
  const capabilityFamilies = decodeCapabilityFamilies(row.capability_families);
  if (capabilityFamilies === null) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored request capability families are malformed");
  }
  return {
    requestId: row.request_id,
    edgeId: row.edge_id,
    principalId: row.principal_id,
    sessionId: row.session_id,
    tool: row.tool,
    policyVersion: row.policy_version,
    payloadDigest: row.payload_digest,
    mutation: row.mutation === 1,
    capabilityFamilies: capabilityFamilies ?? [],
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

/**
 * Validate the durable Request state machine before exposing a row to Broker
 * logic. SQLite protects enum values and scalar nullability, but it cannot
 * prove that result classes, timestamps, mutation approvals, and Job links
 * still describe one coherent request after a crash, migration, or tampering.
 */
function validateStoredRequestState(row: RequestRow): void {
  const fail = (): never => {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored Request state invariants are malformed");
  };
  const timestamp = (value: number): boolean => Number.isSafeInteger(value) && value >= 0;
  const identifier = (value: string | null, pattern: RegExp): boolean => value === null || pattern.test(value);
  const boundedText = (value: string | null, maxLength: number): boolean =>
    value === null || (value.length >= 1 && value.length <= maxLength && !value.includes("\0"));
  const activeResultClasses = new Set(["AUTHORIZED", "INTENT_RECORDED", "RUNNING", "SUCCEEDED"]);

  if (typeof row.request_id !== "string" || !/^[A-Za-z0-9._:@/+-]{1,128}$/u.test(row.request_id) ||
      typeof row.edge_id !== "string" || !isValidEdgeId(row.edge_id) ||
      typeof row.principal_id !== "string" || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(row.principal_id) ||
      typeof row.session_id !== "string" || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(row.session_id) ||
      typeof row.tool !== "string" || !/^mac_[a-z0-9_]{1,123}$/u.test(row.tool) ||
      typeof row.policy_version !== "string" || !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(row.policy_version) ||
      typeof row.payload_digest !== "string" || !/^[a-f0-9]{64}$/u.test(row.payload_digest) ||
      row.mutation !== 0 && row.mutation !== 1 ||
      !timestamp(row.received_at_ms) || !timestamp(row.updated_at_ms) ||
      row.updated_at_ms < row.received_at_ms ||
      !Number.isSafeInteger(row.revision) || row.revision < 0 ||
      !boundedText(row.result_class, 128) || !boundedText(row.target_ref, 4096) ||
      !identifier(row.approval_id, /^approval:[A-Za-z0-9._:-]{1,240}$/u) ||
      !identifier(row.job_id, /^job:[A-Za-z0-9._-]{1,240}$/u)) {
    fail();
  }

  if (row.state === "RECEIVED") {
    if (row.result_class !== null || row.target_ref !== null || row.approval_id !== null || row.job_id !== null) fail();
  } else if (row.state === "AUTHORIZED") {
    if (row.result_class !== "AUTHORIZED" || row.target_ref === null || row.approval_id !== null || row.job_id !== null) fail();
  } else if (row.state === "DENIED") {
    if (row.result_class === null || activeResultClasses.has(row.result_class) || row.approval_id !== null || row.job_id !== null) fail();
  } else if (row.state === "INTENT_RECORDED") {
    if (row.result_class !== "INTENT_RECORDED" || row.mutation !== 1 || row.target_ref === null || row.approval_id === null) fail();
  } else if (row.state === "RUNNING") {
    if (row.result_class !== "RUNNING" || row.target_ref === null) fail();
  } else if (row.state === "SUCCEEDED") {
    if (row.result_class !== "SUCCEEDED" && row.result_class !== "IDEMPOTENT_REUSE") fail();
  } else if (row.state === "FAILED") {
    if (row.result_class === null || activeResultClasses.has(row.result_class)) fail();
  } else if (row.state === "CANCELLED") {
    if (row.result_class !== "CANCELLED") fail();
  } else if (row.state === "TIMED_OUT") {
    if (row.result_class !== "TIMEOUT") fail();
  } else if (row.state === "VERIFICATION_FAILED") {
    if (row.result_class !== "VERIFICATION_FAILED") fail();
  } else if (row.state === "UNKNOWN") {
    if (row.result_class !== "UNKNOWN_OUTCOME") fail();
  } else {
    fail();
  }

  if (row.approval_id !== null && row.mutation !== 1) fail();
  if (row.job_id !== null && row.mutation !== 1) fail();
}

function mapApproval(row: ApprovalRow): ApprovalRecord {
  validateStoredApproval(row);
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

/**
 * Validate a durable Approval before it can influence intent admission or
 * revocation. SQLite CHECK constraints cover only a few scalar fields; the
 * lifecycle counters, timestamps, and nullable consumption/revocation fields
 * must still describe one coherent single-use approval after a crash,
 * migration, or direct database tampering.
 */
function validateStoredApproval(row: ApprovalRow): void {
  const fail = (): never => {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored Approval state invariants are malformed");
  };
  const bounded = (value: unknown, maxLength: number): value is string =>
    typeof value === "string" && value.length >= 1 && value.length <= maxLength && !value.includes("\0");
  const timestamp = (value: number | null): boolean =>
    value === null || (Number.isSafeInteger(value) && value >= 0);
  const requestId = (value: string | null): boolean =>
    value === null || /^[A-Za-z0-9._:@/+-]{1,256}$/u.test(value);
  const approvalClass = ["trusted_write", "trusted_gui", "trusted_profile", "explicit_privileged_policy"];

  if (!validApprovalId(row.approval_id) ||
      !bounded(row.approver_principal_id, 128) || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(row.approver_principal_id) ||
      !bounded(row.requesting_principal_id, 128) || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(row.requesting_principal_id) ||
      !/^mac_[a-z0-9_]{1,123}$/u.test(row.tool) ||
      !bounded(row.contract_version, 128) || !/^\d+\.\d+$/u.test(row.contract_version) ||
      !bounded(row.target_kind, 64) || typeof row.target_ref !== "string" || !validApprovalTarget(row.target_kind, row.target_ref) ||
      !/^[a-f0-9]{64}$/u.test(row.payload_digest) ||
      !bounded(row.policy_version, 128) || !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(row.policy_version) ||
      !approvalClass.includes(row.approval_class) ||
      (row.unattended !== 0 && row.unattended !== 1) ||
      !Number.isSafeInteger(row.issued_at_ms) || row.issued_at_ms < 0 ||
      !Number.isSafeInteger(row.expires_at_ms) || row.expires_at_ms <= row.issued_at_ms ||
      row.use_limit !== 1 || (row.used_count !== 0 && row.used_count !== 1) ||
      !timestamp(row.last_consumed_at_ms) || !requestId(row.last_request_id) ||
      !timestamp(row.revoked_at_ms) ||
      (row.revocation_reason !== null && (!/^[A-Z0-9_:-]{1,64}$/u.test(row.revocation_reason))) ||
      !Number.isSafeInteger(row.revision) || row.revision < 0) {
    fail();
  }

  if (row.used_count === 0) {
    if (row.last_consumed_at_ms !== null || row.last_request_id !== null) fail();
  } else if (row.last_consumed_at_ms === null || row.last_request_id === null ||
             row.last_consumed_at_ms < row.issued_at_ms || row.last_consumed_at_ms >= row.expires_at_ms) {
    fail();
  }

  if (row.revoked_at_ms === null) {
    if (row.revocation_reason !== null) fail();
  } else if (row.revoked_at_ms < row.issued_at_ms || row.revocation_reason === null) {
    fail();
  }

  const expectedRevision = row.used_count + (row.revoked_at_ms === null ? 0 : 1);
  if (row.revision !== expectedRevision) fail();
}

function validateStoredRevocation(row: RevocationRow): void {
  if (!REVOCATION_KINDS.includes(row.kind as RevocationKind) ||
      !/^[A-Za-z0-9._:@/-]{1,257}$/u.test(row.subject_id) ||
      !Number.isSafeInteger(row.revoked_at_ms) || row.revoked_at_ms < 0 ||
      typeof row.reason !== "string" || row.reason.length < 1 || row.reason.length > 200 || row.reason.includes("\0")) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored revocation state is malformed");
  }
}

function validateStoredSwitch(row: SwitchRow): void {
  if (!SWITCH_NAMES.includes(row.name as SwitchName) ||
      (row.disabled !== 0 && row.disabled !== 1) ||
      !Number.isSafeInteger(row.changed_at_ms) || row.changed_at_ms < 0 ||
      typeof row.reason !== "string" || row.reason.length < 1 || row.reason.length > 200 || row.reason.includes("\0")) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored kill-switch state is malformed");
  }
}

function mapJob(row: JobRow): BrokerJob {
  validateStoredJobState(row);
  if (row.owner_edge_id !== null &&
      (typeof row.owner_edge_id !== "string" || !isValidEdgeId(row.owner_edge_id))) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored Job Edge provenance is malformed");
  }
  if (row.owner_edge_key_id !== null &&
      !validEdgeKeyIdentity(row.owner_edge_key_id, row.owner_edge_id)) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored Job Edge-key provenance is malformed");
  }
  return {
    jobId: row.job_id,
    ownerEdgeId: row.owner_edge_id,
    ownerEdgeKeyId: row.owner_edge_key_id,
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
    revision: row.revision,
    ...(row.write_metadata_json ? { writeMetadata: parseWriteJobMetadata(row.write_metadata_json) } : {}),
    ...(row.process_metadata_json ? { processMetadata: parseProcessJobMetadata(row.process_metadata_json) } : {}),
    ...(row.guest_metadata_json ? { guestMetadata: parseGuestTaskJobMetadata(row.guest_metadata_json) } : {}),
    ...(row.privileged_payload_json ? { privilegedPayload: parsePrivilegedHelperPayload(row.privileged_payload_json) } : {})
  };
}

/**
 * Validate the durable Job state machine before exposing a row to Broker
 * logic. SQLite CHECK constraints protect enum values, but they do not prove
 * that timestamps, result classes, cancellation markers, and leases agree.
 * A forged or partially migrated row must become AUDIT_UNAVAILABLE rather
 * than influence an authorization or recovery decision.
 */
function validateStoredJobState(row: JobRow): void {
  const fail = (): never => { throw new BrokerError("AUDIT_UNAVAILABLE", "Stored Job state invariants are malformed"); };
  const timestamp = (value: number | null): boolean => value === null || (Number.isSafeInteger(value) && value >= 0);
  if (!/^job:[A-Za-z0-9._-]{1,240}$/u.test(row.job_id) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(row.owner_principal_id) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(row.owner_session_id) ||
      !/^mac_[a-z0-9_]{1,123}$/u.test(row.tool) ||
      typeof row.target_ref !== "string" || row.target_ref.length < 1 || row.target_ref.length > 4096 || row.target_ref.includes("\0") ||
      !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(row.policy_version) ||
      !/^[a-f0-9]{64}$/u.test(row.payload_digest) ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(row.idempotency_key)) fail();
  if (!Number.isSafeInteger(row.revision) || row.revision < 0 || !timestamp(row.created_at_ms) || !timestamp(row.started_at_ms) ||
      !timestamp(row.finished_at_ms) || !timestamp(row.lease_acquired_at_ms) || !timestamp(row.lease_heartbeat_at_ms) ||
      !timestamp(row.lease_expires_at_ms) || row.cancel_requested !== 0 && row.cancel_requested !== 1 ||
      row.output_truncated !== 0 && row.output_truncated !== 1) fail();
  if (row.created_at_ms < 0 || row.started_at_ms !== null && row.started_at_ms < row.created_at_ms ||
      row.finished_at_ms !== null && row.started_at_ms !== null && row.finished_at_ms < row.started_at_ms) fail();
  if (row.state === "queued") {
    if (row.result_class !== "queued" || row.started_at_ms !== null || row.finished_at_ms !== null || row.cancel_requested !== 0) fail();
  } else if (row.state === "running") {
    if (row.result_class !== "accepted" || row.started_at_ms === null || row.finished_at_ms !== null) fail();
  } else if (row.state === "completed") {
    if (row.result_class !== "success" || row.started_at_ms === null || row.finished_at_ms === null) fail();
  } else if (row.state === "failed") {
    if (!["failed", "denied", "verification_failed"].includes(row.result_class) || row.started_at_ms === null || row.finished_at_ms === null) fail();
  } else if (row.state === "cancelled") {
    if (row.result_class !== "denied" || row.finished_at_ms === null) fail();
  } else if (row.state === "unknown") {
    if (row.result_class !== "unknown" || row.finished_at_ms === null) fail();
  } else {
    fail();
  }
  const leaseFields = [row.lease_owner_id, row.lease_token, row.lease_acquired_at_ms, row.lease_heartbeat_at_ms, row.lease_expires_at_ms];
  const leasePresent = leaseFields.some((value) => value !== null);
  if (leasePresent && leaseFields.some((value) => value === null)) fail();
  if (row.state !== "running" && leasePresent) fail();
  if (leasePresent &&
      (typeof row.lease_owner_id !== "string" || !JOB_LEASE_OWNER_PATTERN.test(row.lease_owner_id) ||
       typeof row.lease_token !== "string" || !JOB_LEASE_TOKEN_PATTERN.test(row.lease_token))) fail();
  if (row.lease_acquired_at_ms !== null && (row.started_at_ms === null || row.lease_acquired_at_ms < row.started_at_ms)) fail();
  if (row.lease_heartbeat_at_ms !== null && row.lease_heartbeat_at_ms < row.lease_acquired_at_ms!) fail();
  if (row.lease_expires_at_ms !== null && row.lease_expires_at_ms <= row.lease_acquired_at_ms!) fail();
  if (row.lease_expires_at_ms !== null && row.lease_heartbeat_at_ms !== null &&
      row.lease_heartbeat_at_ms > row.lease_expires_at_ms) fail();
  if (row.lease_acquired_at_ms !== null && row.lease_expires_at_ms !== null &&
      row.lease_expires_at_ms - row.lease_acquired_at_ms > MAX_JOB_LEASE_MS) fail();
  if (row.cancel_requested === 0 && row.cancel_reason !== null) fail();
  if (row.cancel_requested === 1 && (row.cancel_reason === null || row.cancel_reason.length < 1 || row.cancel_reason.length > 200 || row.cancel_reason.includes("\0"))) fail();

  const hasWriteMetadata = row.write_metadata_json.length > 0;
  const hasProcessMetadata = row.process_metadata_json.length > 0;
  const hasGuestMetadata = row.guest_metadata_json.length > 0;
  if (hasWriteMetadata && row.tool !== "mac_write_file_atomic") fail();
  if ((hasProcessMetadata || hasGuestMetadata) && row.tool !== "mac_task_run") fail();
  if (hasProcessMetadata && hasGuestMetadata) fail();
  if ((hasProcessMetadata || hasGuestMetadata) && row.state !== "running" && row.state !== "unknown") fail();
}

function validateJobCreation(input: CreateJobInput): void {
  if (!/^job:[A-Za-z0-9._-]{1,240}$/u.test(input.jobId) ||
      (input.edgeId !== undefined && !isValidEdgeId(input.edgeId)) ||
      (input.edgeKeyId !== undefined && !validEdgeKeyIdentity(input.edgeKeyId, input.edgeId)) ||
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
  if (input.writeMetadata !== undefined) validateWriteJobMetadata(input.writeMetadata);
  const privilegedTool = input.tool === "mac_priv_service_control" || input.tool === "mac_priv_package_install" || input.tool === "mac_priv_power";
  if (privilegedTool) {
    if (input.privilegedPayload === undefined || privilegedHelperPayloadTarget(input.privilegedPayload) !== input.targetRef ||
        sha256(canonicalJson(input.privilegedPayload)) !== input.payloadDigest) {
      throw malformedJob();
    }
  } else if (input.privilegedPayload !== undefined) {
    throw malformedJob();
  }
}

function validEdgeKeyIdentity(value: unknown, edgeId: string | null | undefined): value is string {
  if (typeof value !== "string" || !isValidEdgeId(edgeId) ||
      !EDGE_KEY_IDENTITY_PATTERN.test(value) || !value.startsWith(`${edgeId}:`)) return false;
  return EDGE_KEY_ID_PATTERN.test(value.slice(edgeId.length + 1));
}

function validateJobLease(lease: JobLease, nowMs: number, allowExpired: boolean): void {
  if (lease === null || typeof lease !== "object" ||
      !JOB_LEASE_OWNER_PATTERN.test(lease.ownerId) ||
      !JOB_LEASE_TOKEN_PATTERN.test(lease.token) ||
      !Number.isSafeInteger(lease.expiresAtMs) || lease.expiresAtMs < 0 ||
      (!allowExpired && lease.expiresAtMs <= nowMs) ||
      lease.expiresAtMs - nowMs > MAX_JOB_LEASE_MS) {
    throw malformedJob();
  }
}

function assertActiveJobLease(row: JobRow, lease: JobLease, nowMs: number, allowExpired = false): void {
  if (row.lease_owner_id !== lease.ownerId || row.lease_token !== lease.token ||
      row.lease_acquired_at_ms === null || row.lease_heartbeat_at_ms === null ||
      row.lease_expires_at_ms === null ||
      (!allowExpired && row.lease_expires_at_ms <= nowMs)) {
    throw new BrokerError("CONFLICT", "Job lease is no longer active");
  }
}

function serializeWriteJobMetadata(metadata: WriteJobMetadata | undefined): string {
  if (metadata === undefined) return "";
  validateWriteJobMetadata(metadata);
  return canonicalJson(metadata);
}

export function serializePrivilegedHelperPayload(payload: PrivilegedHelperPayload | undefined): string {
  if (payload === undefined) return "";
  validatePrivilegedHelperPayload(payload);
  return canonicalJson(payload);
}

function parsePrivilegedHelperPayload(value: string): PrivilegedHelperPayload {
  if (value.length < 1 || value.length > 4_096) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker privileged payload is malformed");
  let parsed: unknown;
  try {
    parsed = parseJsonStrict(value);
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker privileged payload is malformed");
  }
  try {
    validatePrivilegedHelperPayload(parsed as PrivilegedHelperPayload);
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker privileged payload is malformed");
  }
  return parsed as PrivilegedHelperPayload;
}

export function validatePrivilegedHelperPayload(payload: PrivilegedHelperPayload): void {
  if (!isPlainDataRecord(payload)) throw malformedJob();
  const record = payload as unknown as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(",");
  const isBoundedToken = (value: unknown, pattern: RegExp, maxLength = 255): value is string =>
    typeof value === "string" && value.length >= 1 && value.length <= maxLength && !value.includes("\0") && pattern.test(value);
  if (payload.operation === "service_control") {
    if (keys !== "action,operation,service_id" && keys !== "action,expected_state,operation,service_id" ||
        !isBoundedToken(payload.service_id, /^[A-Za-z0-9._:@/+\-]+$/u) ||
        !["start", "stop", "restart", "enable", "disable"].includes(payload.action) ||
        (payload.expected_state !== undefined && !["running", "stopped", "enabled", "disabled"].includes(payload.expected_state))) {
      throw malformedJob();
    }
  } else if (payload.operation === "package_install") {
    if (keys !== "operation,package_id" && keys !== "operation,package_id,source_profile" && keys !== "operation,package_id,version" && keys !== "operation,package_id,source_profile,version" ||
        !isBoundedToken(payload.package_id, /^[A-Za-z0-9._:@/+\-]+$/u) ||
        (payload.version !== undefined && !isBoundedToken(payload.version, /^[A-Za-z0-9._:+\-]+$/u, 128)) ||
        (payload.source_profile !== undefined && !isBoundedToken(payload.source_profile, /^[A-Za-z0-9._:-]+$/u, 128))) {
      throw malformedJob();
    }
  } else if (payload.operation === "power") {
    if (keys !== "action,operation" && keys !== "action,operation,reason" && keys !== "action,not_before,operation" && keys !== "action,not_before,operation,reason" ||
        !["reboot", "shutdown"].includes(payload.action) ||
        (payload.reason !== undefined && (typeof payload.reason !== "string" || payload.reason.length > 200 || payload.reason.includes("\0") || /[\r\n]/u.test(payload.reason))) ||
        (payload.not_before !== undefined && (typeof payload.not_before !== "string" || payload.not_before.length > 64 || payload.not_before.includes("\0") || /[\r\n]/u.test(payload.not_before)))) {
      throw malformedJob();
    }
  } else {
    throw malformedJob();
  }
  try {
    assertContentDoesNotContainSecrets(Buffer.from(canonicalJson(payload), "utf8"));
  } catch {
    throw malformedJob();
  }
}

export function privilegedHelperPayloadTarget(payload: PrivilegedHelperPayload): string {
  validatePrivilegedHelperPayload(payload);
  if (payload.operation === "service_control") return `service:${payload.service_id}`;
  if (payload.operation === "package_install") return `package:${payload.package_id}`;
  return "host:local";
}

function validateProcessJobMetadata(metadata: ProcessJobMetadata): void {
  if (metadata === null || typeof metadata !== "object" ||
      !Number.isSafeInteger(metadata.pid) || metadata.pid < 1 || metadata.pid > 99_999_999 ||
      !Number.isSafeInteger(metadata.processGroupId) || metadata.processGroupId !== metadata.pid ||
      !Number.isSafeInteger(metadata.startTimeMicros) || metadata.startTimeMicros < 1 ||
      !Number.isSafeInteger(metadata.recordedAtMs) || metadata.recordedAtMs < 0 ||
      !Array.isArray(metadata.descendants) || metadata.descendants.length > 256) {
    throw malformedJob();
  }
  if (metadata.ownershipProof !== undefined && metadata.ownershipProof !== "sandbox-exec-no-fork-v1") {
    throw malformedJob();
  }
  if (metadata.ownershipProof === "sandbox-exec-no-fork-v1" && metadata.descendants.length > 0) {
    throw malformedJob();
  }
  let previousPid = 0;
  for (const descendant of metadata.descendants) {
    if (descendant === null || typeof descendant !== "object" ||
        !Number.isSafeInteger(descendant.pid) || descendant.pid < 1 || descendant.pid > 99_999_999 ||
        descendant.pid === metadata.pid || descendant.pid <= previousPid ||
        !Number.isSafeInteger(descendant.startTimeMicros) || descendant.startTimeMicros < 1) {
      throw malformedJob();
    }
    previousPid = descendant.pid;
  }
}

function serializeProcessJobMetadata(metadata: ProcessJobMetadata): string {
  validateProcessJobMetadata(metadata);
  return canonicalJson(metadata);
}

function serializeGuestTaskJobMetadata(metadata: GuestTaskJobMetadata): string {
  validateGuestTaskJobMetadata(metadata);
  return canonicalJson(metadata);
}

function parseGuestTaskJobMetadata(value: string): GuestTaskJobMetadata {
  if (value.length < 1 || value.length > 2_000) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker guest task metadata is malformed");
  }
  let parsed: unknown;
  try { parsed = parseJsonStrict(value); }
  catch { throw new BrokerError("AUDIT_UNAVAILABLE", "Broker guest task metadata is malformed"); }
  try { validateGuestTaskJobMetadata(parsed as GuestTaskJobMetadata); }
  catch { throw new BrokerError("AUDIT_UNAVAILABLE", "Broker guest task metadata is malformed"); }
  return parsed as GuestTaskJobMetadata;
}

function validateGuestTaskJobMetadata(metadata: GuestTaskJobMetadata): void {
  if (metadata === null || typeof metadata !== "object" ||
      !/^request:guest-[A-Za-z0-9._:-]{16,128}$/u.test(metadata.requestId) ||
      !/^guest-nonce-[A-Za-z0-9._:-]{16,128}$/u.test(metadata.nonce) ||
      !/^[a-f0-9]{64}$/u.test(metadata.requestDigest) ||
      metadata.guestIdentity === null || typeof metadata.guestIdentity !== "object" ||
      !/^[a-f0-9]{64}$/u.test(metadata.guestIdentity.imageSha256) ||
      typeof metadata.guestIdentity.runtimeVersion !== "string" ||
      !/^[A-Za-z0-9._:+/-]{1,128}$/u.test(metadata.guestIdentity.runtimeVersion) ||
      !/^[a-f0-9]{64}$/u.test(metadata.profileDigest) ||
      !/^[a-f0-9]{64}$/u.test(metadata.taskDigest) ||
      !Number.isSafeInteger(metadata.timeoutMs) || metadata.timeoutMs < 1 || metadata.timeoutMs > 900_000 ||
      !Number.isSafeInteger(metadata.outputCapBytes) || metadata.outputCapBytes < 1 || metadata.outputCapBytes > 4 * 1024 * 1024 ||
      !Number.isSafeInteger(metadata.recordedAtMs) || metadata.recordedAtMs < 0) {
    throw malformedJob();
  }
  const keys = Object.keys(metadata).sort().join(",");
  if (keys !== "guestIdentity,nonce,outputCapBytes,profileDigest,recordedAtMs,requestDigest,requestId,taskDigest,timeoutMs") {
    throw malformedJob();
  }
  const identityKeys = Object.keys(metadata.guestIdentity).sort().join(",");
  if (identityKeys !== "imageSha256,runtimeVersion") throw malformedJob();
}

function parseProcessJobMetadata(value: string): ProcessJobMetadata {
  if (value.length < 1 || value.length > 2_000) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker process metadata is malformed");
  let parsed: unknown;
  try { parsed = parseJsonStrict(value); }
  catch { throw new BrokerError("AUDIT_UNAVAILABLE", "Broker process metadata is malformed"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker process metadata is malformed");
  }
  const keys = Object.keys(parsed).sort();
  const legacyKeys = "pid,processGroupId,recordedAtMs,startTimeMicros";
  const currentKeys = "descendants,pid,processGroupId,recordedAtMs,startTimeMicros";
  const proofKeys = "descendants,ownershipProof,pid,processGroupId,recordedAtMs,startTimeMicros";
  if (keys.join(",") !== legacyKeys && keys.join(",") !== currentKeys && keys.join(",") !== proofKeys) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker process metadata is malformed");
  }
  const metadata = parsed as Partial<ProcessJobMetadata>;
  const normalized = {
    pid: metadata.pid,
    processGroupId: metadata.processGroupId,
    startTimeMicros: metadata.startTimeMicros,
    recordedAtMs: metadata.recordedAtMs,
    descendants: metadata.descendants ?? [],
    ...(metadata.ownershipProof === undefined ? {} : { ownershipProof: metadata.ownershipProof })
  } as ProcessJobMetadata;
  validateProcessJobMetadata(normalized);
  return normalized;
}

function parseWriteJobMetadata(value: string): WriteJobMetadata {
  if (value.length < 1 || value.length > 20_000) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker write-job metadata is malformed");
  let parsed: unknown;
  try {
    parsed = parseJsonStrict(value);
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker write-job metadata is malformed");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker write-job metadata is malformed");
  const keys = Object.keys(parsed).sort();
  const legacyKeys = "bytes,createOnly,desiredSha256,expectedSha256,path,rootId";
  const currentKeys = "bytes,createOnly,desiredSha256,expectedSha256,path,rootId,temporaryName";
  if (keys.length !== 6 && keys.length !== 7) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker write-job metadata is malformed");
  }
  if (keys.join(",") !== (keys.length === 6 ? legacyKeys : currentKeys)) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker write-job metadata is malformed");
  }
  const metadata = parsed as Partial<WriteJobMetadata>;
  if (
    typeof metadata.rootId !== "string" ||
    typeof metadata.path !== "string" ||
    !isAbsolute(metadata.path) ||
    typeof metadata.bytes !== "number" ||
    typeof metadata.desiredSha256 !== "string" ||
    (typeof metadata.expectedSha256 !== "string" && metadata.expectedSha256 !== null) ||
    typeof metadata.createOnly !== "boolean" ||
    (metadata.temporaryName !== undefined && typeof metadata.temporaryName !== "string")
  ) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker write-job metadata is malformed");
  if (metadata.expectedSha256 === undefined) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker write-job metadata is malformed");
  const normalized: WriteJobMetadata = {
    rootId: metadata.rootId,
    path: metadata.path,
    bytes: metadata.bytes,
    desiredSha256: metadata.desiredSha256,
    expectedSha256: metadata.expectedSha256,
    createOnly: metadata.createOnly,
    ...(metadata.temporaryName !== undefined ? { temporaryName: metadata.temporaryName } : {})
  };
  validateWriteJobMetadata(normalized);
  return normalized;
}

function validateWriteJobMetadata(metadata: WriteJobMetadata): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(metadata.rootId) ||
      !isAbsolute(metadata.path) || resolve(metadata.path) !== metadata.path || metadata.path.length > 4096 || metadata.path.includes("\0") ||
      !Number.isSafeInteger(metadata.bytes) || metadata.bytes < 0 || metadata.bytes > 1_048_576 ||
      !/^[a-f0-9]{64}$/u.test(metadata.desiredSha256) ||
      (metadata.expectedSha256 !== null && !/^[a-f0-9]{64}$/u.test(metadata.expectedSha256)) ||
      typeof metadata.createOnly !== "boolean" ||
      (metadata.temporaryName !== undefined && !/^\.mac-operator-write-[A-Za-z0-9._-]{1,96}$/u.test(metadata.temporaryName))) {
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
  normalizeCapabilityFamilies(input.capabilityFamilies);
}

function validateRequestAdmissionLimits(limits: RequestAdmissionLimits | undefined): void {
  if (limits === undefined) return;
  if (!isPlainDataRecord(limits) ||
      Object.keys(limits).some((key) => key !== "maxActiveRequestsGlobal" && key !== "maxActiveRequestsPerSession" && key !== "maxActiveRequestsByFamily")) {
    throw malformedRequest();
  }
  const validatedLimits = limits as RequestAdmissionLimits;
  for (const value of [validatedLimits.maxActiveRequestsGlobal, validatedLimits.maxActiveRequestsPerSession]) {
    if (value !== undefined && (!Number.isSafeInteger(value) || value < 1 || value > MAX_ACTIVE_REQUESTS_GLOBAL)) {
      throw malformedRequest();
    }
  }
  if (validatedLimits.maxActiveRequestsPerSession !== undefined && validatedLimits.maxActiveRequestsPerSession > MAX_ACTIVE_REQUESTS_PER_SESSION) {
    throw malformedRequest();
  }
  if (validatedLimits.maxActiveRequestsByFamily !== undefined) {
    if (!isPlainDataRecord(validatedLimits.maxActiveRequestsByFamily)) {
      throw malformedRequest();
    }
    for (const [family, value] of Object.entries(validatedLimits.maxActiveRequestsByFamily)) {
      if (!(CAPABILITY_FAMILIES as readonly string[]).includes(family) ||
          !Number.isSafeInteger(value) || value < 1 || value > MAX_ACTIVE_REQUESTS_GLOBAL) {
        throw malformedRequest();
      }
    }
  }
}

function enforceRequestAdmissionLimits(
  database: DatabaseSync,
  input: AdmitRequestInput,
  limits: RequestAdmissionLimits | undefined
): void {
  if (limits === undefined) return;
  const activeStates = "'RECEIVED', 'AUTHORIZED', 'INTENT_RECORDED', 'RUNNING'";
  if (limits.maxActiveRequestsGlobal !== undefined) {
    const row = database.prepare(`SELECT COUNT(*) AS count FROM requests WHERE state IN (${activeStates})`).get() as { count?: unknown } | undefined;
    const count = row?.count;
    if (!Number.isSafeInteger(count) || (count as number) < 0) throw new BrokerError("AUDIT_UNAVAILABLE", "Active request count is malformed");
    if ((count as number) >= limits.maxActiveRequestsGlobal) {
      throw new BrokerError("CONFLICT", "Global request capacity is exhausted", true);
    }
  }
  if (limits.maxActiveRequestsPerSession !== undefined) {
    const row = database.prepare(`
      SELECT COUNT(*) AS count FROM requests
      WHERE principal_id = ? AND session_id = ? AND state IN (${activeStates})
    `).get(input.principalId, input.sessionId) as { count?: unknown } | undefined;
    const count = row?.count;
    if (!Number.isSafeInteger(count) || (count as number) < 0) throw new BrokerError("AUDIT_UNAVAILABLE", "Session request count is malformed");
    if ((count as number) >= limits.maxActiveRequestsPerSession) {
      throw new BrokerError("CONFLICT", "Session request capacity is exhausted", true);
    }
  }
  const requestedFamilies = new Set(normalizeCapabilityFamilies(input.capabilityFamilies));
  const familyCounts = new Map<CapabilityFamily, number>();
  if (Object.keys(limits.maxActiveRequestsByFamily ?? {}).length > 0) {
    const rows = database.prepare(`
      SELECT capability_families FROM requests WHERE state IN (${activeStates})
    `).all() as Array<{ capability_families?: unknown }>;
    for (const row of rows) {
      const storedFamilies = decodeCapabilityFamilies(row.capability_families);
      if (storedFamilies === null) {
        throw new BrokerError("AUDIT_UNAVAILABLE", "Stored request capability families are malformed");
      }
      const countedFamilies = storedFamilies ?? CAPABILITY_FAMILIES;
      for (const family of countedFamilies) {
        familyCounts.set(family, (familyCounts.get(family) ?? 0) + 1);
      }
    }
  }
  for (const [family, limit] of Object.entries(limits.maxActiveRequestsByFamily ?? {})) {
    if (!requestedFamilies.has(family as CapabilityFamily)) continue;
    const count = familyCounts.get(family as CapabilityFamily) ?? 0;
    if (!Number.isSafeInteger(count) || (count as number) < 0) {
      throw new BrokerError("AUDIT_UNAVAILABLE", `${family} request count is malformed`);
    }
    if ((count as number) >= limit) {
      throw new BrokerError("CONFLICT", `${family} request capacity is exhausted`, true);
    }
  }
}

function normalizeCapabilityFamilies(families: readonly CapabilityFamily[] | undefined): CapabilityFamily[] {
  if (families === undefined) return [];
  if (!Array.isArray(families) || families.length > CAPABILITY_FAMILIES.length) throw malformedRequest();
  const known = new Set<CapabilityFamily>();
  for (const family of families) {
    if (!(CAPABILITY_FAMILIES as readonly string[]).includes(family) || known.has(family)) throw malformedRequest();
    known.add(family);
  }
  return [...known].sort();
}

function encodeCapabilityFamilies(families: readonly CapabilityFamily[] | undefined): string {
  const normalized = normalizeCapabilityFamilies(families);
  return normalized.length === 0 ? "" : `|${normalized.join("|")}|`;
}

/** Decode and validate the exact storage spelling used by the request ledger. */
function decodeCapabilityFamilies(value: unknown): readonly CapabilityFamily[] | undefined | null {
  if (value === "") return undefined;
  if (typeof value !== "string" || !value.startsWith("|") || !value.endsWith("|")) return null;
  const parts = value.slice(1, -1).split("|");
  if (parts.length < 1 || parts.length > CAPABILITY_FAMILIES.length) return null;
  const families: CapabilityFamily[] = [];
  for (const part of parts) {
    if (!(CAPABILITY_FAMILIES as readonly string[]).includes(part)) return null;
    families.push(part as CapabilityFamily);
  }
  try {
    return encodeCapabilityFamilies(families) === value ? families : null;
  } catch {
    return null;
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
  return ["host", "path", "project", "process", "job", "task_profile", "app_set", "app", "app_window", "ui_element", "service", "package", "power"]
    .includes(kind) && reference.startsWith(`${kind}:`) && reference.length <= 4096 && !reference.includes("\0");
}

function asEvidenceRecord(value: unknown): Record<string, unknown> {
  return isPlainDataRecord(value) ? value : {};
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

function queuedJobAffectedBySwitch(name: SwitchName, tool: string): boolean {
  if (name === "global") return true;
  if (name === "mutations") return !READ_ONLY_JOB_TOOLS.has(tool);
  if (name === "process" || name === "network") return tool === "mac_task_run";
  if (name === "gui") return tool === "mac_app_open" || tool === "mac_app_focus" || tool.startsWith("mac_ui_");
  if (name === "destructive") return tool === "mac_apply_patch";
  if (name === "privileged") return tool.startsWith("mac_priv_");
  return false;
}

const READ_ONLY_JOB_TOOLS = new Set([
  "mac_health",
  "mac_capabilities",
  "mac_app_list",
  "mac_ui_observe",
  "mac_system_summary",
  "mac_network_status",
  "mac_service_status",
  "mac_log_tail",
  "mac_process_list",
  "mac_process_inspect",
  "mac_policy_explain",
  "mac_stat_path",
  "mac_read_file",
  "mac_hash_file",
  "mac_list_directory",
  "mac_directory_tree",
  "mac_find_files",
  "mac_recent_files",
  "mac_search_text",
  "mac_project_discover",
  "mac_project_summary",
  "mac_git_status",
  "mac_git_branch_list",
  "mac_git_log",
  "mac_git_diff",
  "mac_package_inspect",
  "mac_docker_status",
  "mac_docker_inspect",
  "mac_docker_logs",
  "mac_storage_analysis",
  "mac_job_status"
]);

function queuedJobAffectedByRevocation(kind: RevocationKind, subjectId: string, row: JobRow): boolean {
  if (kind === "principal") return row.owner_principal_id === subjectId;
  if (kind === "session") return row.owner_session_id === subjectId;
  // Legacy Jobs have null provenance and are cancelled conservatively. New
  // Jobs are isolated to the revoked Edge identity.
  if (kind === "edge") {
    if (row.owner_edge_id === null) return true;
    if (typeof row.owner_edge_id !== "string" || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(row.owner_edge_id)) return true;
    return row.owner_edge_id === subjectId;
  }
  if (kind === "edge_key") {
    if (row.owner_edge_key_id === null) return true;
    if (!validEdgeKeyIdentity(row.owner_edge_key_id, row.owner_edge_id)) return true;
    return row.owner_edge_key_id === subjectId;
  }
  // Other upstream identities are not persisted on Jobs yet; revoking one
  // therefore conservatively cancels every queued Job.
  return true;
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
  if (Array.isArray(value)) {
    if (!isPlainDataArray(value)) return "[REDACTED: NON_DATA]";
    return value.map((item) => redactEvidence(item));
  }
  if (isPlainDataRecord(value)) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [
      key,
      SECRET_KEY_PATTERN.test(key) ? "[REDACTED]" : redactEvidence(item)
    ]));
  }
  if (value !== null && typeof value === "object") return "[REDACTED: NON_DATA]";
  return value;
}

function isPlainDataArray(value: readonly unknown[]): boolean {
  try {
    if (Object.getOwnPropertySymbols(value).length > 0 || Object.keys(value).length !== value.length) return false;
    const names = Object.getOwnPropertyNames(value);
    if (names.length !== value.length + 1 || !names.includes("length")) return false;
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (descriptor === undefined || !("value" in descriptor)) return false;
      if (name !== "length" && (!/^(?:0|[1-9][0-9]*)$/u.test(name) || Number(name) >= value.length)) return false;
    }
    return true;
  } catch {
    return false;
  }
}
