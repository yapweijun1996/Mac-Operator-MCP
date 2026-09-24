import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { constants, fchmodSync, fchownSync, fstatSync, fsyncSync, lstatSync, openSync, readSync, writeSync, closeSync } from "node:fs";
import { connect, Socket } from "node:net";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { rm, rename } from "node:fs/promises";
import { BrokerError, canonicalJson, parseJsonUtf8Strict, sha256 } from "@mac-operator/contracts";
import { snapshotSignedDescriptorSnapshotAttestation, type DescriptorSnapshotAttestationVerifier, type SignedDescriptorSnapshotAttestation } from "./descriptor-snapshot-attestation.js";
import {
  receiveAuthenticatedDescriptorHandoff,
  type DescriptorHandoffFrame
} from "./descriptor-handoff-receiver.js";
import { verifyDescriptorSnapshotHandoff } from "./descriptor-handoff-helper.js";
import { MacOsNativePeerIpcServer, type NativePeerPolicy } from "./native-peer-ipc-server.js";
import {
  authorizePeerCredentials,
  getDescriptorPath,
  loadNativePeerAdapter,
  parsePeerCredentials,
  type PeerCredentialPolicy
} from "./peer-credentials.js";
import { isPlainDataRecord } from "./plain-record.js";
import {
  validateRootHelperSnapshotReleaseEvidence,
  type RootHelperSnapshotReleaseEvidence
} from "./root-helper-snapshot-release.js";
import type { CodeSignatureExpectation } from "./macos-install-plan.js";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import type {
  RootHelperSnapshotAuthorityPoller,
  RootHelperSnapshotRequestAuthority
} from "./root-helper-snapshot-authority.js";
import { renderTaskSandboxProfile, type TaskSandboxProfileOptions } from "./sandbox-profile.js";
import {
  validateRootHelperSnapshotProcessResult,
  validateRootHelperSnapshotProcessOwnershipSnapshot,
  validateRootHelperSnapshotTaskRequest,
  type RootHelperSnapshotCapability,
  type RootHelperSnapshotExecutionControl,
  type RootHelperSnapshotRequestAdmission,
  type RootHelperSnapshotTaskRequest,
  type RootHelperSnapshotTransport
} from "./root-helper-snapshot.js";
import type { ProcessOwnershipSnapshot } from "./process-supervisor.js";
import type { ResolvedTaskProfile, TaskNetworkPolicy, TaskProcessTreePolicy } from "./task-profile.js";

const ROOT_HELPER_SNAPSHOT_DOMAIN = "mac-operator-root-helper-snapshot-v0.1\0";
const ROOT_HELPER_SNAPSHOT_RESPONSE_DOMAIN = "mac-operator-root-helper-snapshot-response-v0.1\0";
const ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION = "0.1" as const;
const ROOT_HELPER_SNAPSHOT_MECHANISM = "darwin-root-helper-snapshot-v1" as const;
const MAX_FRAME_BYTES = 256 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024 + 64 * 1024;
const MAX_TIMEOUT_MS = 600_000;
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024;
const REQUEST_ID_PATTERN = /^snapshot-request:[A-Za-z0-9._:-]{16,128}$/u;

export interface UnsignedRootHelperSnapshotEnvelope {
  schemaVersion: typeof ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION;
  mechanism: typeof ROOT_HELPER_SNAPSHOT_MECHANISM;
  requestId: string;
  timestampMs: number;
  expiresAtMs: number;
  signedAttestation: SignedDescriptorSnapshotAttestation;
  args: readonly string[];
  environment: Readonly<Record<string, string>>;
  timeoutMs: number;
  outputCapBytes: number;
}

export interface SignedRootHelperSnapshotEnvelope extends UnsignedRootHelperSnapshotEnvelope {
  authenticationProof: string;
}

export interface RootHelperSnapshotSuccessResponse {
  ok: true;
  requestId: string;
  result: ProcessExecutionResult;
  responseProof: string;
}

export interface RootHelperSnapshotFailureResponse {
  ok: false;
  requestId: string;
  resultClass: BrokerError["errorClass"];
  error: { message: string; retryable: boolean };
  responseProof: string;
}

export type RootHelperSnapshotResponse = RootHelperSnapshotSuccessResponse | RootHelperSnapshotFailureResponse;

interface RootHelperSnapshotProcessEvent {
  kind: "process_started" | "process_ownership_changed";
  requestId: string;
  snapshot: ProcessOwnershipSnapshot;
  eventProof: string;
}

export interface NativeRootHelperSnapshotTransportOptions {
  socketPath: string;
  authenticationKey: Buffer;
  capability: RootHelperSnapshotCapability;
  /** The expected peer is normally uid 0 and a launchd-bound PID identity. */
  peerPolicy: PeerCredentialPolicy;
  now?: () => number;
  timeoutMs?: number;
  /** Broker-owned active digest gate shared with the helper authority server. */
  authorityRegistry?: RootHelperSnapshotRequestAuthority;
}

/**
 * Broker-side SCM_RIGHTS client for the separately authenticated root helper.
 * The caller supplies already-open descriptors; this class never accepts a
 * pathname executable or cwd and never falls back to pathname spawning.
 */
export class NativeRootHelperSnapshotTransport implements RootHelperSnapshotTransport {
  readonly capability: RootHelperSnapshotCapability;
  private readonly socketPath: string;
  private readonly peerPolicy: PeerCredentialPolicy;
  private readonly now: () => number;
  private readonly timeoutMs: number;
  private readonly authenticationKey: Buffer;
  private readonly authorityRegistry: RootHelperSnapshotRequestAuthority | undefined;
  private readonly activeSockets = new Set<Socket>();
  private closed = false;

  constructor(options: NativeRootHelperSnapshotTransportOptions) {
    validateTransportOptions(options);
    this.socketPath = options.socketPath;
    this.peerPolicy = options.peerPolicy;
    this.now = options.now ?? Date.now;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.capability = options.capability;
    this.authorityRegistry = options.authorityRegistry;
  }

  async execute(
    request: RootHelperSnapshotTaskRequest,
    control: RootHelperSnapshotExecutionControl
  ): Promise<ProcessExecutionResult> {
    if (this.closed) throw new BrokerError("CANCELLED", "Root helper snapshot transport is closed");
    const safeRequest = validateRootHelperSnapshotTaskRequest(request);
    if (!Number.isSafeInteger(control?.timeoutMs) || control.timeoutMs < 25 || control.timeoutMs > MAX_TIMEOUT_MS ||
        typeof control.shouldCancel !== "function" ||
        (control.requestAuthority !== undefined &&
         (typeof control.requestAuthority.admit !== "function" || typeof control.requestAuthority.release !== "function")) ||
        (control.onProcessStarted !== undefined && typeof control.onProcessStarted !== "function") ||
        (control.onProcessOwnershipChanged !== undefined && typeof control.onProcessOwnershipChanged !== "function")) {
      throw new BrokerError("PRECONDITION_FAILED", "Root helper snapshot transport control is invalid");
    }
    if (control.shouldCancel()) throw new BrokerError("CANCELLED", "Root helper snapshot transport was cancelled");
    const timestampMs = this.now();
    if (!Number.isSafeInteger(timestampMs) || timestampMs < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Root helper snapshot transport clock is invalid");
    }
    const unsigned: UnsignedRootHelperSnapshotEnvelope = {
      schemaVersion: ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION,
      mechanism: ROOT_HELPER_SNAPSHOT_MECHANISM,
      requestId: `snapshot-request:${randomBytes(24).toString("hex")}`,
      timestampMs,
      expiresAtMs: timestampMs + Math.min(control.timeoutMs, this.timeoutMs),
      signedAttestation: safeRequest.signedAttestation,
      args: safeRequest.args,
      environment: safeRequest.environment,
      timeoutMs: safeRequest.timeoutMs,
      outputCapBytes: safeRequest.outputCapBytes
    };
    const signed: SignedRootHelperSnapshotEnvelope = {
      ...unsigned,
      authenticationProof: rootHelperSnapshotProof(unsigned, this.authenticationKey)
    };
    const requestDigest = sha256(canonicalJson(signed));
    const requestAuthority: RootHelperSnapshotRequestAdmission | undefined = control.requestAuthority ?? this.authorityRegistry;
    requestAuthority?.admit(requestDigest, unsigned.expiresAtMs);
    let response: unknown;
    try {
      response = await exchangeRootHelperSnapshotSocket({
        socketPath: this.socketPath,
        peerPolicy: this.peerPolicy,
        signed,
        executableFd: safeRequest.executableFd,
        cwdFd: safeRequest.cwdFd,
        timeoutMs: Math.min(control.timeoutMs, this.timeoutMs),
        shouldCancel: control.shouldCancel,
        request: unsigned,
        authenticationKey: this.authenticationKey,
        ...(control.onProcessStarted === undefined ? {} : { onProcessStarted: control.onProcessStarted }),
        ...(control.onProcessOwnershipChanged === undefined ? {} : { onProcessOwnershipChanged: control.onProcessOwnershipChanged }),
        registerSocket: (socket) => this.activeSockets.add(socket),
        unregisterSocket: (socket) => this.activeSockets.delete(socket)
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", "Root helper snapshot transport outcome could not be established", true);
    } finally {
      requestAuthority?.release(requestDigest);
    }
    return authenticateRootHelperSnapshotResponse(response, unsigned, this.authenticationKey);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    for (const socket of this.activeSockets) socket.destroy();
    this.activeSockets.clear();
    this.authenticationKey.fill(0);
  }
}

export interface RootHelperSnapshotSandboxPolicy {
  profile: string;
  sandboxProfile: string;
  filesystemRoots: readonly string[];
  networkPolicy: TaskNetworkPolicy;
  networkAllowlist: readonly string[];
  processTreePolicy: TaskProcessTreePolicy;
  protectedFilesystemRoots?: readonly string[];
}

export interface RootHelperSnapshotServerOptions {
  socketPath: string;
  authenticationKey: Buffer;
  /** Broker peer identity; the helper never accepts arbitrary local callers. */
  peerPolicy: NativePeerPolicy;
  verifier: DescriptorSnapshotAttestationVerifier;
  snapshotRoot: string;
  sandboxPolicies: ReadonlyMap<string, RootHelperSnapshotSandboxPolicy>;
  enabled?: boolean;
  hostEvidenceAccepted?: boolean;
  /** Independent proof that the production sandbox mechanism is supported. */
  sandboxIsolationAccepted?: boolean;
  sandboxEvidenceRef?: string;
  /** Independent proof that native code verifies Ed25519 before materialization. */
  attestationVerificationAccepted?: boolean;
  attestationEvidenceRef?: string;
  evidenceRef?: string;
  now?: () => number;
  pollIntervalMs?: number;
  protectedFilesystemRoots?: readonly string[];
  /** Broker-owned authority poller; required for an available root helper. */
  authorityPoller?: RootHelperSnapshotAuthorityPoller;
  authorityPollIntervalMs?: number;
  /** Explicit release provenance mode for the exact native root-helper executable. */
  releaseMode?: "development-probe" | "production";
  /** Required with production mode; generated by the read-only release preflight. */
  productionReleaseEvidence?: RootHelperSnapshotReleaseEvidence;
  /** Required with production mode; pins the Developer ID identity. */
  productionReleaseSignature?: CodeSignatureExpectation;
  /** Required with production mode; exact native helper executable path. */
  productionReleaseArtifactPath?: string;
}

/**
 * Root-domain server for the descriptor snapshot channel. It is unavailable
 * unless the current process is root, the snapshot root is protected, and a
 * host evidence gate is explicitly accepted. The server copies the executable
 * FD into a root-owned private path, renders only a Broker-owned Seatbelt
 * profile, drops the child to the authenticated Broker UID/GID, and cleans up
 * the snapshot before returning success.
 */
export class RootHelperSnapshotServer {
  readonly capability: RootHelperSnapshotCapability;
  readonly available: boolean;
  private readonly options: RootHelperSnapshotServerOptions;
  private readonly authenticationKey: Buffer;
  private readonly now: () => number;
  private readonly peerServer: MacOsNativePeerIpcServer | undefined;
  private readonly authorityPollIntervalMs: number;
  private readonly acceptedRequests = new Map<string, number>();
  private readonly activeHandlers = new Set<Promise<void>>();
  private closed = false;

  constructor(options: RootHelperSnapshotServerOptions) {
    validateServerOptions(options);
    this.options = options;
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.now = options.now ?? Date.now;
    const rootReady = inspectProtectedSnapshotRoot(options.snapshotRoot);
    this.authorityPollIntervalMs = options.authorityPollIntervalMs ?? 1_000;
    const releaseReady = options.releaseMode === "development-probe" ||
      (options.releaseMode === "production" && options.productionReleaseEvidence !== undefined);
    this.available = options.enabled === true && options.hostEvidenceAccepted === true &&
      options.sandboxIsolationAccepted === true && rootReady &&
      options.attestationVerificationAccepted === true &&
      options.authorityPoller !== undefined &&
      process.getuid?.() === 0 && options.evidenceRef !== undefined && options.sandboxEvidenceRef !== undefined &&
      options.attestationEvidenceRef !== undefined && releaseReady;
    this.capability = this.available
      ? {
        schemaVersion: ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION,
        mechanism: ROOT_HELPER_SNAPSHOT_MECHANISM,
        available: true,
        fdIdentity: "verified",
        immutableSelection: "enforced",
        snapshotOwnership: "root-owned-private",
        closeOnExec: "enforced",
        helperAuthentication: "native-peer-and-hmac",
        helperReleaseMode: options.releaseMode!,
        productionRelease: options.productionReleaseEvidence === undefined ? "unproven" : "developer-id-notarized",
        sandboxIsolation: "supported-production",
        sandboxEvidenceRef: options.sandboxEvidenceRef!,
        attestationVerification: "native-ed25519",
        attestationEvidenceRef: options.attestationEvidenceRef!,
        evidenceRef: options.evidenceRef!
      }
      : {
        schemaVersion: ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION,
        mechanism: ROOT_HELPER_SNAPSHOT_MECHANISM,
        available: false,
        fdIdentity: "unproven",
        immutableSelection: "unproven",
        snapshotOwnership: "unproven",
        closeOnExec: "unproven",
      helperAuthentication: "unproven",
        helperReleaseMode: "unproven",
        productionRelease: "unproven",
        sandboxIsolation: "unproven",
        attestationVerification: "unproven"
      };
    this.peerServer = this.available
      ? new MacOsNativePeerIpcServer({
        socketPath: options.socketPath,
        peerPolicy: options.peerPolicy,
        ...(options.pollIntervalMs === undefined ? {} : { pollIntervalMs: options.pollIntervalMs }),
        onSocket: (socket) => this.startSocketHandler(socket)
      })
      : undefined;
  }

  async listen(): Promise<void> {
    if (this.closed) throw new BrokerError("CANCELLED", "Root helper snapshot server is closed");
    if (!this.available || this.peerServer === undefined) {
      throw new BrokerError("POLICY_DENIED", "Root helper snapshot server is not available");
    }
    await this.peerServer.listen();
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try {
      await this.peerServer?.close();
      if (this.activeHandlers.size > 0) await Promise.allSettled([...this.activeHandlers]);
    } finally {
      this.options.authorityPoller?.dispose?.();
      this.authenticationKey.fill(0);
    }
  }

  private startSocketHandler(socket: Socket): void {
    const handler = Promise.resolve().then(() => this.handleSocket(socket));
    this.activeHandlers.add(handler);
    void handler.then(
      () => { this.activeHandlers.delete(handler); },
      () => { this.activeHandlers.delete(handler); }
    );
  }

  private async handleSocket(socket: Socket): Promise<void> {
    const descriptor = socketDescriptor(socket);
    if (descriptor === undefined) {
      socket.destroy();
      return;
    }
    socket.pause();
    let handoff: { credentials: ReturnType<typeof parsePeerCredentials>; frame: DescriptorHandoffFrame } | undefined;
    let unsignedEnvelope: UnsignedRootHelperSnapshotEnvelope | undefined;
    try {
      const native = loadNativePeerAdapter();
      const peer = parsePeerCredentials(native.getPeerCredentials(descriptor));
      authorizePeerCredentials(peer, this.options.peerPolicy, (pid) => native.getProcessIdentity(pid));
      handoff = receiveAuthenticatedDescriptorHandoff(descriptor, this.options.peerPolicy, {
        expectedDescriptorCount: 2,
        maxPayloadBytes: MAX_FRAME_BYTES
      });
      const envelope = parseSignedRootHelperSnapshotEnvelope(parseJsonUtf8Strict(handoff.frame.payload));
      unsignedEnvelope = authenticateRootHelperSnapshotEnvelope(envelope, this.authenticationKey);
      const nowMs = this.now();
      if (!Number.isSafeInteger(nowMs) || nowMs < 0 || envelope.timestampMs > nowMs + 5_000 || nowMs >= envelope.expiresAtMs ||
          envelope.expiresAtMs - envelope.timestampMs > MAX_TIMEOUT_MS + 5_000) {
        throw new BrokerError("AUTH_EXPIRED", "Root helper snapshot request is outside its validity window");
      }
      this.admitRequest(envelope);
      const verified = verifyDescriptorSnapshotHandoff({ credentials: handoff.credentials, frame: {
        payload: Buffer.from(JSON.stringify(envelope.signedAttestation), "utf8"),
        descriptors: handoff.frame.descriptors
      } }, this.options.verifier);
      if (sha256(canonicalJson(envelope.args)) !== verified.attestation.argsDigest ||
          sha256(canonicalJson(envelope.environment)) !== verified.attestation.environmentDigest) {
        throw new BrokerError("POLICY_DENIED", "Root helper snapshot plan digest does not match the signed attestation");
      }
      if (this.now() >= envelope.expiresAtMs || this.now() >= verified.expiresAtMs) {
        throw new BrokerError("AUTH_EXPIRED", "Root helper snapshot request has expired");
      }
      const result = await this.executeSnapshot(envelope, verified.attestation, handoff.credentials, handoff.frame.descriptors, socket);
      this.writeResponse(socket, rootHelperSnapshotSuccess(unsignedEnvelope, result, this.authenticationKey));
    } catch (error) {
      const brokerError = error instanceof BrokerError
        ? error
        : new BrokerError("UNKNOWN_OUTCOME", "Root helper snapshot execution outcome could not be established", true);
      if (!socket.destroyed && unsignedEnvelope !== undefined) {
        this.writeResponse(socket, rootHelperSnapshotFailure(unsignedEnvelope, brokerError, this.authenticationKey));
      } else {
        socket.destroy();
      }
    } finally {
      if (handoff !== undefined) closeDescriptors(handoff.frame.descriptors);
      if (!socket.destroyed) socket.destroy();
    }
  }

  private admitRequest(envelope: SignedRootHelperSnapshotEnvelope): void {
    const nowMs = this.now();
    if (this.acceptedRequests.size > 4096) {
      for (const [requestId, expiry] of this.acceptedRequests) if (expiry <= nowMs) this.acceptedRequests.delete(requestId);
    }
    if (this.acceptedRequests.has(envelope.requestId)) throw new BrokerError("REPLAY_DENIED", "Root helper snapshot request was already accepted");
    this.acceptedRequests.set(envelope.requestId, envelope.expiresAtMs);
  }

  private async executeSnapshot(
    envelope: SignedRootHelperSnapshotEnvelope,
    attestation: RootHelperSnapshotTaskRequest["signedAttestation"]["payload"],
    credentials: { uid: number; gid: number; pid: number },
    descriptors: readonly number[],
    socket: Socket
  ): Promise<ProcessExecutionResult> {
    if (!this.options.authorityPoller) {
      throw new BrokerError("PRIVILEGE_DENIED", "Root helper snapshot authority polling is unavailable");
    }
    const requestDigest = sha256(canonicalJson(envelope));
    let authorityRevoked = false;
    let authorityFailure: unknown;
    let authorityPollInFlight: Promise<void> | undefined;
    const pollAuthority = async (initial: boolean): Promise<void> => {
      if (authorityPollInFlight) return;
      const poll = Promise.resolve().then(() => this.options.authorityPoller!.assertAuthorized(requestDigest, envelope.expiresAtMs));
      authorityPollInFlight = poll.then(
        () => undefined,
        (error: unknown) => {
          authorityRevoked = true;
          authorityFailure = error;
        }
      ).finally(() => { authorityPollInFlight = undefined; });
      await authorityPollInFlight;
      if (initial && authorityFailure !== undefined) throw authorityFailure;
    };
    await pollAuthority(true);
    const authorityPollTimer = setInterval(() => { void pollAuthority(false); }, this.authorityPollIntervalMs);
    authorityPollTimer.unref?.();
    const policy = this.options.sandboxPolicies.get(attestation.profile);
    try {
      if (!policy || policy.profile !== attestation.profile || policy.sandboxProfile !== attestation.sandboxProfile ||
          policy.networkPolicy !== attestation.networkPolicy || policy.processTreePolicy !== attestation.processTreePolicy ||
          sha256(canonicalJson(policy.filesystemRoots)) !== attestation.filesystemRootsDigest) {
        throw new BrokerError("POLICY_DENIED", "Root helper sandbox policy is not bound to the attestation");
      }
      const cwdPath = getDescriptorPath(descriptors[1]!);
      const snapshotPath = await materializeExecutableSnapshot(
        descriptors[0]!,
        this.options.snapshotRoot,
        attestation.executableContentSha256
      );
      try {
        const profile: ResolvedTaskProfile = {
          profile: policy.profile,
          cwd: cwdPath,
          process: {
            executable: "/usr/bin/sandbox-exec",
            args: [],
            cwd: cwdPath,
            environment: envelope.environment,
            timeoutMs: envelope.timeoutMs,
            outputCapBytes: envelope.outputCapBytes,
            runAsUid: credentials.uid,
            runAsGid: credentials.gid
          },
          filesystemRoots: [...policy.filesystemRoots],
          networkPolicy: policy.networkPolicy,
          networkAllowlist: [...policy.networkAllowlist],
          credentialPolicy: "none",
          processTreePolicy: policy.processTreePolicy,
          sandboxProfile: policy.sandboxProfile,
          verificationStrategy: "exit_status_and_declared_task_verification"
        };
        const sandboxProfile = renderTaskSandboxProfile({
          ...profile,
          process: {
            ...profile.process,
            executable: snapshotPath,
            args: envelope.args,
            cwd: cwdPath
          }
        }, {
          protectedFilesystemRoots: [this.options.snapshotRoot, ...(this.options.protectedFilesystemRoots ?? []), ...(policy.protectedFilesystemRoots ?? [])]
        } satisfies TaskSandboxProfileOptions);
        const supervisor = new ProcessSupervisor({
          allowedEnvironmentKeys: Object.keys(envelope.environment),
          requireRootOwnedExecutable: true,
          requireSystemPublishedExecutable: true,
          maxConcurrent: 1,
          maxConcurrentPerExecutable: 1
        });
        try {
          const result = await supervisor.run({
            executable: "/usr/bin/sandbox-exec",
            args: ["-p", sandboxProfile, snapshotPath, ...envelope.args],
            cwd: cwdPath,
            environment: envelope.environment,
            timeoutMs: envelope.timeoutMs,
            outputCapBytes: envelope.outputCapBytes,
            requireCleanExitProof: policy.processTreePolicy === "single_process",
            runAsUid: credentials.uid,
            runAsGid: credentials.gid,
            shouldCancel: () => socket.destroyed || authorityRevoked,
            onStarted: (snapshot) => this.writeProcessEvent(socket, envelope, "process_started", snapshot),
            onOwnershipChanged: (snapshot) => this.writeProcessEvent(socket, envelope, "process_ownership_changed", snapshot)
          });
          if (authorityPollInFlight) await authorityPollInFlight;
          await pollAuthority(false);
          if (authorityRevoked) {
            throw new BrokerError("UNKNOWN_OUTCOME", "Root-helper snapshot authority changed during execution", true);
          }
          return result;
        } finally {
          await supervisor.close?.().catch(() => undefined);
        }
      } finally {
        await rm(snapshotPath, { force: true }).catch(() => {
          throw new BrokerError("UNKNOWN_OUTCOME", "Root helper snapshot cleanup could not be verified", true);
        });
      }
    } finally {
      clearInterval(authorityPollTimer);
      if (authorityPollInFlight) await authorityPollInFlight;
      if (authorityRevoked && authorityFailure instanceof BrokerError) {
        throw new BrokerError("UNKNOWN_OUTCOME", "Root-helper snapshot authority changed during execution", true);
      }
    }
  }

  private writeResponse(socket: Socket, response: RootHelperSnapshotResponse): void {
    const serialized = `${JSON.stringify(response)}\n`;
    if (Buffer.byteLength(serialized, "utf8") > MAX_RESPONSE_BYTES) {
      socket.destroy();
      return;
    }
    socket.end(serialized);
  }

  private writeProcessEvent(
    socket: Socket,
    request: UnsignedRootHelperSnapshotEnvelope,
    kind: RootHelperSnapshotProcessEvent["kind"],
    snapshot: ProcessOwnershipSnapshot
  ): void {
    if (socket.destroyed) throw new BrokerError("UNKNOWN_OUTCOME", "Root helper process event channel is closed", true);
    const body = {
      kind,
      requestId: request.requestId,
      snapshot: validateRootHelperSnapshotProcessOwnershipSnapshot(snapshot)
    };
    const event: RootHelperSnapshotProcessEvent = {
      ...body,
      eventProof: createRootHelperSnapshotResponseProof(request, body, this.authenticationKey)
    };
    const serialized = `${JSON.stringify(event)}\n`;
    if (Buffer.byteLength(serialized, "utf8") > MAX_RESPONSE_BYTES) {
      throw new BrokerError("OUTPUT_LIMIT", "Root helper process event exceeded the byte limit");
    }
    socket.write(serialized);
  }
}

function validateTransportOptions(options: NativeRootHelperSnapshotTransportOptions): void {
  if (options === null || typeof options !== "object" || !isCanonicalSocketPath(options.socketPath) ||
      !Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32 ||
      options.capability.available !== true || options.capability.immutableSelection !== "enforced" ||
      options.capability.snapshotOwnership !== "root-owned-private" || options.capability.closeOnExec !== "enforced" ||
      options.capability.helperAuthentication !== "native-peer-and-hmac" ||
      options.capability.helperReleaseMode === "unproven" ||
      (options.capability.helperReleaseMode === "production" && options.capability.productionRelease !== "developer-id-notarized") ||
      options.capability.sandboxIsolation !== "supported-production" || options.capability.sandboxEvidenceRef === undefined ||
      options.capability.attestationVerification !== "native-ed25519" || options.capability.attestationEvidenceRef === undefined ||
      (options.authorityRegistry !== undefined &&
       (typeof options.authorityRegistry.admit !== "function" || typeof options.authorityRegistry.assertAuthorized !== "function" ||
        typeof options.authorityRegistry.release !== "function" || typeof options.authorityRegistry.revoke !== "function")) ||
      !Number.isSafeInteger(options.timeoutMs ?? 30_000) || (options.timeoutMs ?? 30_000) < 25 || (options.timeoutMs ?? 30_000) > MAX_TIMEOUT_MS) {
    throw new Error("Root helper snapshot transport options are invalid");
  }
}

function validateServerOptions(options: RootHelperSnapshotServerOptions): void {
  if (options === null || typeof options !== "object" || !isCanonicalSocketPath(options.socketPath) ||
      !isCanonicalAbsolutePath(options.snapshotRoot) || !Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32 ||
      !options.verifier || !(options.sandboxPolicies instanceof Map) || options.sandboxPolicies.size < 1 ||
      (options.sandboxIsolationAccepted !== undefined && typeof options.sandboxIsolationAccepted !== "boolean") ||
      (options.attestationVerificationAccepted !== undefined && typeof options.attestationVerificationAccepted !== "boolean") ||
      (options.evidenceRef !== undefined && !/^[A-Za-z0-9._:/-]{1,256}$/u.test(options.evidenceRef)) ||
      (options.sandboxEvidenceRef !== undefined && !/^[A-Za-z0-9._:/-]{1,256}$/u.test(options.sandboxEvidenceRef)) ||
      (options.attestationEvidenceRef !== undefined && !/^[A-Za-z0-9._:/-]{1,256}$/u.test(options.attestationEvidenceRef)) ||
      (options.sandboxIsolationAccepted === true && options.sandboxEvidenceRef === undefined) ||
      (options.attestationVerificationAccepted === true && options.attestationEvidenceRef === undefined)) {
    throw new Error("Root helper snapshot server options are invalid");
  }
  if (options.releaseMode !== undefined && options.releaseMode !== "development-probe" && options.releaseMode !== "production") {
    throw new Error("Root helper snapshot release mode is invalid");
  }
  if (options.releaseMode === "production") {
    if (options.productionReleaseEvidence === undefined || options.productionReleaseSignature === undefined ||
        options.productionReleaseArtifactPath === undefined) {
      throw new Error("Production root-helper snapshot server requires Developer ID release evidence");
    }
    validateRootHelperSnapshotReleaseEvidence(options.productionReleaseEvidence, {
      helperPath: options.productionReleaseArtifactPath,
      artifactPath: options.productionReleaseArtifactPath,
      signature: options.productionReleaseSignature
    });
  }
  if (options.productionReleaseArtifactPath !== undefined &&
      (typeof options.productionReleaseArtifactPath !== "string" || !isCanonicalAbsolutePath(options.productionReleaseArtifactPath))) {
    throw new Error("Root helper snapshot release artifact path is invalid");
  }
  if (options.authorityPollIntervalMs !== undefined &&
      (!Number.isSafeInteger(options.authorityPollIntervalMs) || options.authorityPollIntervalMs < 1 || options.authorityPollIntervalMs > 60_000)) {
    throw new Error("Root helper snapshot authority poll interval is invalid");
  }
  for (const policy of options.sandboxPolicies.values()) validateSandboxPolicy(policy);
}

function validateSandboxPolicy(policy: RootHelperSnapshotSandboxPolicy): void {
  if (!isPlainDataRecord(policy) || typeof policy.profile !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(policy.profile) ||
      typeof policy.sandboxProfile !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(policy.sandboxProfile) ||
      !Array.isArray(policy.filesystemRoots) || policy.filesystemRoots.length < 1 || policy.filesystemRoots.some((root) => !isCanonicalAbsolutePath(root)) ||
      (policy.networkPolicy !== "none" && policy.networkPolicy !== "allowlist") || !Array.isArray(policy.networkAllowlist) ||
      (policy.networkPolicy === "none" && policy.networkAllowlist.length !== 0) ||
      (policy.processTreePolicy !== "single_process" && policy.processTreePolicy !== "owned_group")) {
    throw new Error("Root helper sandbox policy is invalid");
  }
}

function parseSignedRootHelperSnapshotEnvelope(value: unknown): SignedRootHelperSnapshotEnvelope {
  if (!isPlainDataRecord(value) || Object.keys(value).sort().join(",") !==
      "args,authenticationProof,environment,expiresAtMs,mechanism,outputCapBytes,requestId,schemaVersion,signedAttestation,timeoutMs,timestampMs") {
    throw new BrokerError("PRECONDITION_FAILED", "Root helper snapshot envelope is malformed");
  }
  const envelope = value as Partial<SignedRootHelperSnapshotEnvelope>;
  if (envelope.schemaVersion !== ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION || envelope.mechanism !== ROOT_HELPER_SNAPSHOT_MECHANISM ||
      typeof envelope.requestId !== "string" || !REQUEST_ID_PATTERN.test(envelope.requestId) ||
      !Number.isSafeInteger(envelope.timestampMs) || (envelope.timestampMs as number) < 0 ||
      !Number.isSafeInteger(envelope.expiresAtMs) || (envelope.expiresAtMs as number) <= (envelope.timestampMs as number) ||
      !Number.isSafeInteger(envelope.timeoutMs) || (envelope.timeoutMs as number) < 25 || (envelope.timeoutMs as number) > MAX_TIMEOUT_MS ||
      !Number.isSafeInteger(envelope.outputCapBytes) || (envelope.outputCapBytes as number) < 1 || (envelope.outputCapBytes as number) > MAX_OUTPUT_BYTES ||
      !Array.isArray(envelope.args) || Object.getPrototypeOf(envelope.args) !== Array.prototype || envelope.args.length > 128 ||
      envelope.args.some((arg) => typeof arg !== "string" || arg.includes("\0") || arg.includes("\n") || arg.length > 4_096) ||
      !isPlainDataRecord(envelope.environment) || Object.keys(envelope.environment).length > 64 ||
      Object.values(envelope.environment).some((entry) => typeof entry !== "string" || entry.includes("\0") || entry.includes("\n") || entry.length > 4_096) ||
      !envelope.signedAttestation || typeof envelope.authenticationProof !== "string" || !/^[a-f0-9]{64}$/u.test(envelope.authenticationProof)) {
    throw new BrokerError("PRECONDITION_FAILED", "Root helper snapshot envelope fields are malformed");
  }
  return {
    schemaVersion: ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION,
    mechanism: ROOT_HELPER_SNAPSHOT_MECHANISM,
    requestId: envelope.requestId,
    timestampMs: envelope.timestampMs as number,
    expiresAtMs: envelope.expiresAtMs as number,
    signedAttestation: snapshotSignedDescriptorSnapshotAttestation(envelope.signedAttestation),
    args: Object.freeze([...(envelope.args as readonly string[])]),
    environment: Object.freeze({ ...(envelope.environment as Record<string, string>) }),
    timeoutMs: envelope.timeoutMs as number,
    outputCapBytes: envelope.outputCapBytes as number,
    authenticationProof: envelope.authenticationProof
  };
}

function authenticateRootHelperSnapshotEnvelope(value: SignedRootHelperSnapshotEnvelope, key: Buffer): UnsignedRootHelperSnapshotEnvelope {
  const unsigned = { ...value } as Partial<SignedRootHelperSnapshotEnvelope> & { authenticationProof?: string };
  delete unsigned.authenticationProof;
  const expected = rootHelperSnapshotProof(unsigned as UnsignedRootHelperSnapshotEnvelope, key);
  if (!safeEqualHex(value.authenticationProof, expected)) throw new BrokerError("AUTH_INVALID", "Root helper snapshot authentication failed");
  return unsigned as UnsignedRootHelperSnapshotEnvelope;
}

function rootHelperSnapshotProof(value: UnsignedRootHelperSnapshotEnvelope, key: Buffer): string {
  if (!Buffer.isBuffer(key) || key.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Root helper snapshot key is invalid");
  return createHmac("sha256", key).update(ROOT_HELPER_SNAPSHOT_DOMAIN, "utf8").update(sha256(canonicalJson(value)), "utf8").digest("hex");
}

function rootHelperSnapshotSuccess(request: UnsignedRootHelperSnapshotEnvelope, result: ProcessExecutionResult, key: Buffer): RootHelperSnapshotSuccessResponse {
  const body = { ok: true as const, requestId: request.requestId, result: validateRootHelperSnapshotProcessResult(result) };
  return { ...body, responseProof: createRootHelperSnapshotResponseProof(request, body, key) };
}

function rootHelperSnapshotFailure(request: UnsignedRootHelperSnapshotEnvelope, error: BrokerError, key: Buffer): RootHelperSnapshotFailureResponse {
  const body = { ok: false as const, requestId: request.requestId, resultClass: error.errorClass, error: { message: error.message.slice(0, 512), retryable: error.retryable } };
  return { ...body, responseProof: createRootHelperSnapshotResponseProof(request, body, key) };
}

export function createRootHelperSnapshotResponseProof(request: UnsignedRootHelperSnapshotEnvelope, body: object, key: Buffer): string {
  return createHmac("sha256", key).update(ROOT_HELPER_SNAPSHOT_RESPONSE_DOMAIN, "utf8")
    .update(sha256(canonicalJson(request)), "utf8").update(canonicalJson(body), "utf8").digest("hex");
}

function authenticateRootHelperSnapshotResponse(
  raw: unknown,
  request: UnsignedRootHelperSnapshotEnvelope,
  key: Buffer
): ProcessExecutionResult {
  if (!isPlainDataRecord(raw) || typeof raw.requestId !== "string" || raw.requestId !== request.requestId || typeof raw.responseProof !== "string") {
    throw new BrokerError("AUTH_INVALID", "Root helper snapshot response identity is invalid");
  }
  const response = raw as Record<string, unknown>;
  const body = { ...response };
  delete body.responseProof;
  if (!safeEqualHex(response.responseProof as string, createRootHelperSnapshotResponseProof(request, body, key))) {
    throw new BrokerError("AUTH_INVALID", "Root helper snapshot response authentication failed");
  }
  if (response.ok === true && isPlainDataRecord(response.result)) {
    return validateRootHelperSnapshotProcessResult(response.result);
  }
  if (response.ok === false && typeof response.resultClass === "string" && isPlainDataRecord(response.error) &&
      typeof response.error.message === "string" && typeof response.error.retryable === "boolean") {
    throw new BrokerError(response.resultClass as BrokerError["errorClass"], response.error.message, response.error.retryable);
  }
  throw new BrokerError("EXECUTION_FAILED", "Root helper snapshot response is malformed");
}

function exchangeRootHelperSnapshotSocket(options: {
  socketPath: string;
  peerPolicy: PeerCredentialPolicy;
  signed: SignedRootHelperSnapshotEnvelope;
  request: UnsignedRootHelperSnapshotEnvelope;
  authenticationKey: Buffer;
  executableFd: number;
  cwdFd: number;
  timeoutMs: number;
  shouldCancel: () => boolean;
  onProcessStarted?: (snapshot: ProcessOwnershipSnapshot) => void;
  onProcessOwnershipChanged?: (snapshot: ProcessOwnershipSnapshot) => void;
  registerSocket: (socket: Socket) => void;
  unregisterSocket: (socket: Socket) => void;
}): Promise<unknown> {
  return new Promise<unknown>((resolvePromise, rejectPromise) => {
    const socket = connect(options.socketPath);
    options.registerSocket(socket);
    let settled = false;
    let cancelTimer: NodeJS.Timeout | undefined;
    let total = 0;
    let pending = Buffer.alloc(0);
    const cleanup = (): void => {
      if (cancelTimer) clearInterval(cancelTimer);
      options.unregisterSocket(socket);
    };
    const fail = (error: unknown): void => {
      if (settled) return;
      settled = true;
      cleanup();
      socket.destroy();
      rejectPromise(error);
    };
    socket.setTimeout(options.timeoutMs, () => fail(new BrokerError("TIMEOUT", "Root helper snapshot transport timed out", true)));
    socket.once("error", () => fail(new BrokerError("UNKNOWN_OUTCOME", "Root helper snapshot socket failed", true)));
    const handleMessage = (message: unknown): boolean => {
      if (isPlainDataRecord(message) && (message.kind === "process_started" || message.kind === "process_ownership_changed")) {
        const event = authenticateRootHelperSnapshotProcessEvent(message, options.request, options.authenticationKey);
        if (message.kind === "process_started") options.onProcessStarted?.(event);
        else options.onProcessOwnershipChanged?.(event);
        return true;
      }
      return false;
    };
    socket.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        fail(new BrokerError("OUTPUT_LIMIT", "Root helper snapshot response exceeded the byte limit"));
        return;
      }
      pending = Buffer.concat([pending, chunk]);
      for (;;) {
        const newline = pending.indexOf(0x0a);
        if (newline < 0) return;
        const line = pending.subarray(0, newline);
        pending = pending.subarray(newline + 1);
        if (line.byteLength === 0) {
          fail(new BrokerError("AUTH_INVALID", "Root helper snapshot response contained an empty frame"));
          return;
        }
        let message: unknown;
        try {
          message = parseJsonUtf8Strict(line);
          if (handleMessage(message)) continue;
          if (pending.some((byte) => !isAsciiWhitespace(byte))) {
            fail(new BrokerError("AUTH_INVALID", "Root helper snapshot response contained trailing bytes"));
            return;
          }
          settled = true;
          cleanup();
          socket.destroy();
          resolvePromise(message);
          return;
        } catch (error) {
          fail(error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "Root helper snapshot response is not valid JSON"));
          return;
        }
      }
    });
    socket.on("close", () => {
      if (!settled) fail(new BrokerError("UNKNOWN_OUTCOME", "Root helper snapshot socket closed without a response", true));
    });
    socket.once("connect", () => {
      try {
        const descriptor = socketDescriptor(socket);
        if (descriptor === undefined) throw new BrokerError("EXECUTION_FAILED", "Root helper socket descriptor is unavailable");
        const native = loadNativePeerAdapter();
        const credentials = parsePeerCredentials(native.getPeerCredentials(descriptor));
        authorizePeerCredentials(credentials, options.peerPolicy, (pid) => native.getProcessIdentity(pid));
        sendRootHelperSnapshotFrame(descriptor, options.signed, [options.executableFd, options.cwdFd]);
        cancelTimer = setInterval(() => {
          if (options.shouldCancel()) socket.destroy();
        }, 25);
        cancelTimer.unref?.();
      } catch (error) {
        fail(error instanceof BrokerError ? error : new BrokerError("POLICY_DENIED", "Root helper peer authentication failed"));
      }
    });
  });
}

export function authenticateRootHelperSnapshotProcessEvent(
  raw: Record<string, unknown>,
  request: UnsignedRootHelperSnapshotEnvelope,
  key: Buffer
): ProcessOwnershipSnapshot {
  if (Object.keys(raw).sort().join(",") !== "eventProof,kind,requestId,snapshot" ||
      (raw.kind !== "process_started" && raw.kind !== "process_ownership_changed") ||
      typeof raw.requestId !== "string" || raw.requestId !== request.requestId ||
      typeof raw.eventProof !== "string") {
    throw new BrokerError("AUTH_INVALID", "Root helper process event identity is invalid");
  }
  const body = { kind: raw.kind, requestId: raw.requestId, snapshot: raw.snapshot };
  if (!safeEqualHex(raw.eventProof, createRootHelperSnapshotResponseProof(request, body, key))) {
    throw new BrokerError("AUTH_INVALID", "Root helper process event authentication failed");
  }
  return validateRootHelperSnapshotProcessOwnershipSnapshot(raw.snapshot);
}

function sendRootHelperSnapshotFrame(socketDescriptor: number, envelope: SignedRootHelperSnapshotEnvelope, descriptors: readonly number[]): void {
  if (!Number.isSafeInteger(socketDescriptor) || socketDescriptor < 0 || descriptors.length !== 2 || descriptors.some((fd) => !Number.isSafeInteger(fd) || fd < 0)) {
    throw new BrokerError("PRECONDITION_FAILED", "Root helper descriptor handoff is malformed");
  }
  const payload = Buffer.from(JSON.stringify(envelope), "utf8");
  if (payload.byteLength > MAX_FRAME_BYTES) throw new BrokerError("OUTPUT_LIMIT", "Root helper snapshot request exceeded the byte limit");
  const native = loadNativePeerAdapter() as unknown as { sendDescriptorHandoff(socketDescriptor: number, payload: Buffer, descriptors: readonly number[]): void };
  native.sendDescriptorHandoff(socketDescriptor, payload, descriptors);
}

async function materializeExecutableSnapshot(descriptor: number, snapshotRoot: string, expectedDigest: string): Promise<string> {
  if (process.getuid?.() !== 0 || !inspectProtectedSnapshotRoot(snapshotRoot)) {
    throw new BrokerError("POLICY_DENIED", "Root helper snapshot root is unavailable");
  }
  const input = fstatSync(descriptor);
  if (!input.isFile() || input.size < 1 || input.size > MAX_SNAPSHOT_BYTES || (input.mode & 0o111) === 0) {
    throw new BrokerError("POLICY_DENIED", "Root helper executable descriptor is invalid");
  }
  const name = `snapshot-${randomBytes(24).toString("hex")}`;
  const finalPath = join(snapshotRoot, name);
  const temporaryPath = join(snapshotRoot, `.${name}.partial`);
  let outputFd: number | undefined;
  try {
    outputFd = openSync(temporaryPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o700);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let position = 0;
    while (position < input.size) {
      const bytes = readSync(descriptor, buffer, 0, Math.min(buffer.byteLength, input.size - position), position);
      if (bytes < 1) throw new BrokerError("POLICY_DENIED", "Root helper executable changed while snapshotting");
      let written = 0;
      while (written < bytes) written += writeSync(outputFd, buffer, written, bytes - written);
      hash.update(buffer.subarray(0, bytes));
      position += bytes;
    }
    if (hash.digest("hex") !== expectedDigest) throw new BrokerError("POLICY_DENIED", "Root helper snapshot digest does not match attestation");
    fchmodSync(outputFd, 0o700);
    fchownSync(outputFd, 0, 0);
    fsyncSync(outputFd);
    closeSync(outputFd);
    outputFd = undefined;
    await rename(temporaryPath, finalPath);
    const finalStat = lstatSync(finalPath);
    if (!finalStat.isFile() || finalStat.uid !== 0 || (finalStat.mode & 0o077) !== 0 || (finalStat.mode & 0o111) === 0 ||
        resolve(finalPath) !== finalPath) {
      throw new BrokerError("POLICY_DENIED", "Root helper executable snapshot readback is unsafe");
    }
    return finalPath;
  } catch (error) {
    if (outputFd !== undefined) closeSync(outputFd);
    await rm(temporaryPath, { force: true }).catch(() => undefined);
    await rm(finalPath, { force: true }).catch(() => undefined);
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("UNKNOWN_OUTCOME", "Root helper executable snapshot could not be materialized", true);
  }
}

function inspectProtectedSnapshotRoot(path: string): boolean {
  if (!isCanonicalAbsolutePath(path) || process.platform !== "darwin") return false;
  try {
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o077) !== 0 || (stat.mode & 0o700) !== 0o700 || resolve(path) !== path) return false;
    let cursor = dirname(path);
    for (;;) {
      const parent = lstatSync(cursor);
      if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== 0 || (parent.mode & 0o022) !== 0) return false;
      const next = dirname(cursor);
      if (next === cursor) break;
      cursor = next;
    }
    return true;
  } catch {
    return false;
  }
}

function socketDescriptor(socket: Socket): number | undefined {
  const handle = (socket as Socket & { _handle?: { fd?: unknown } })._handle;
  return Number.isSafeInteger(handle?.fd) && (handle!.fd as number) >= 0 ? handle!.fd as number : undefined;
}

function closeDescriptors(descriptors: readonly number[]): void {
  const native = loadNativePeerAdapter();
  const seen = new Set<number>();
  for (const descriptor of descriptors) {
    if (seen.has(descriptor)) continue;
    seen.add(descriptor);
    try { native.closeUnixDescriptor(descriptor); } catch { /* best-effort cleanup */ }
  }
}

function isCanonicalSocketPath(value: unknown): value is string {
  return isCanonicalAbsolutePath(value) && Buffer.byteLength(value, "utf8") < 104 && dirname(value) !== value;
}

function isCanonicalAbsolutePath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096 && isAbsolute(value) && resolve(value) === value && !value.includes("\0") && !value.includes("\n");
}

function safeEqualHex(left: unknown, right: string): boolean {
  if (typeof left !== "string" || !/^[a-f0-9]{64}$/u.test(left) || !/^[a-f0-9]{64}$/u.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0d || byte === 0x20;
}
