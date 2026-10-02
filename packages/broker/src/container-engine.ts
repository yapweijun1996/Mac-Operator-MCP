import { request, Agent } from "node:http";
import { createConnection, type Socket } from "node:net";
import { lstatSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, parseJsonUtf8Strict, sha256 } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";
import { parseWorkspaceArchive, createWorkspaceArchive, safeSnapshotPath, type SnapshotFile } from "./container-snapshot.js";
import {
  MacOsPeerCredentialVerifier, loadNativePeerAdapter,
  type PeerCredentialPolicy, type PeerCredentialVerifier
} from "./peer-credentials.js";

const API = "/v1.47";
const ID_PATTERN = /^[a-f0-9]{64}$/u;
const IMAGE_PATTERN = /^(?:sha256:[a-f0-9]{64}|[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}@sha256:[a-f0-9]{64})$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const OWNER_PATTERN = /^[A-Za-z0-9._:@/-]{1,128}$/u;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const MAX_RUNTIME_MS = 15 * 60_000;
const PID1_SCRIPT = "const ms=Number(process.argv[1]);if(!Number.isSafeInteger(ms)||ms<1||ms>900000)process.exit(125);setTimeout(()=>process.exit(124),ms);process.on('SIGTERM',()=>process.exit(143));";
const TASK_ENVIRONMENT = ["HOME=/home/agent", "PATH=/usr/local/bin:/usr/bin:/bin", "TMPDIR=/tmp", "LANG=C.UTF-8", "NODE_VERSION=", "YARN_VERSION="];
const STAGING_CHUNK_BYTES = 24 * 1024;
const STAGING_ARGUMENT_BYTES = 40 * 1024;

export const CONTAINER_LABELS = Object.freeze({
  namespace: "io.mac-operator.boundary",
  engineId: "io.mac-operator.engine",
  imageId: "io.mac-operator.image",
  taskId: "io.mac-operator.task",
  owner: "io.mac-operator.owner",
  nonce: "io.mac-operator.nonce"
});

export interface ContainerEngineControl { signal?: AbortSignal; timeoutMs?: number; }
export interface ContainerEngineOptions {
  socketPath: string;
  peerPolicy: PeerCredentialPolicy;
  requestTimeoutMs?: number;
  maxResponseBytes?: number;
  maxArchiveBytes?: number;
  /** Test seam; production always uses the native peer verifier and ACL checks. */
  peerVerifier?: PeerCredentialVerifier;
}
export interface ContainerCreateOptions {
  image: string;
  taskId: string;
  owner: string;
  nonce: string;
  maxRuntimeMs: number;
  readonlyWorkspace?: boolean;
  memoryBytes?: number;
  nanoCpus?: number;
  pidsLimit?: number;
}
export interface ContainerTaskHandle {
  readonly id: string;
  readonly imageId: string;
  readonly engineId: string;
  readonly taskId: string;
  readonly owner: string;
  readonly nonce: string;
  readonly maxRuntimeMs: number;
  readonly readonlyWorkspace: boolean;
  readonly memoryBytes: number;
  readonly nanoCpus: number;
  readonly pidsLimit: number;
}
export interface ContainerEngineInfo {
  id: string; serverVersion: string; osType: "linux"; architecture: string;
  securityOptions: string[]; cgroupVersion: string;
}
export interface ContainerEngineVersion { version: string; apiVersion: string; os: "linux"; arch: string; }
export interface ContainerImageInspection { id: string; repoDigests: string[]; os: "linux"; architecture: string; }
export interface ContainerInspection {
  id: string; running: boolean; status: string; exitCode: number; processId: number;
}
export interface ContainerExecOptions { command: readonly string[]; timeoutMs: number; outputCapBytes: number; }
export interface ContainerExecResult { exitCode: number; stdout: string; stderr: string; truncated: false; }

type RecordValue = Record<string, unknown>;
interface EngineResponse { status: number; bytes: Buffer; }
interface WorkspacePhase { handle: ContainerTaskHandle; phase: "new" | "staging" | "ready" | "executing" | "exporting" | "blocked"; activeExecutions: number; }
interface StagingChunk { path: string; offset: number; data: string; final: boolean; size: number; sha256: string; }
interface ExportFile { path: string; size: number; dev: string; ino: string; mtime: string; ctime: string; }
const EXPORT_TOTAL_BYTES = 32 * 1024 * 1024;
const EXPORT_CHUNK_BYTES = 256 * 1024;

/** Fixed Unix-only Engine operations; request paths and container authority never come from MCP callers. */
export class DockerContainerEngine {
  private readonly socketPath: string;
  private readonly socketIdentity: { device: number; inode: number };
  private readonly verifier: PeerCredentialVerifier;
  private readonly requestTimeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxArchiveBytes: number;
  private readonly productionAclChecks: boolean;
  private readonly ownerUid: number;
  private readonly peerPolicy: Required<Pick<PeerCredentialPolicy, "expectedUid" | "expectedGid" | "allowedProcessIdentity">>;
  private engineId: string | undefined;
  private readonly workspaces = new Map<string, WorkspacePhase>();

  constructor(options: ContainerEngineOptions) {
    const uid = process.getuid?.();
    if (!isPlainDataRecord(options) || Object.keys(options).some(key => !["socketPath", "peerPolicy", "requestTimeoutMs", "maxResponseBytes", "maxArchiveBytes", "peerVerifier"].includes(key)) || uid === undefined || uid < 1 || !isAbsolute(options.socketPath) ||
        resolve(options.socketPath) !== options.socketPath || realpathSync(options.socketPath) !== options.socketPath ||
        !isPlainDataRecord(options.peerPolicy) || options.peerPolicy.expectedUid !== uid ||
        !Number.isSafeInteger(options.peerPolicy.expectedGid) || !isPlainDataRecord(options.peerPolicy.allowedProcessIdentity) ||
        !Number.isSafeInteger(options.peerPolicy.allowedProcessIdentity.pid) || options.peerPolicy.allowedProcessIdentity.pid < 1 ||
        !Number.isSafeInteger(options.peerPolicy.allowedProcessIdentity.startTimeMicros) || options.peerPolicy.allowedProcessIdentity.startTimeMicros < 1) {
      throw denied("Container Engine startup socket and peer identity are invalid");
    }
    this.socketPath = options.socketPath;
    this.ownerUid = uid;
    this.peerPolicy = { expectedUid: uid, expectedGid: options.peerPolicy.expectedGid!, allowedProcessIdentity: { ...options.peerPolicy.allowedProcessIdentity } };
    this.requestTimeoutMs = integer(options.requestTimeoutMs ?? 30_000, 1, 120_000, "request timeout");
    this.maxResponseBytes = integer(options.maxResponseBytes ?? MAX_RESPONSE_BYTES, 256, MAX_RESPONSE_BYTES, "response limit");
    this.maxArchiveBytes = integer(options.maxArchiveBytes ?? MAX_ARCHIVE_BYTES, 512, MAX_ARCHIVE_BYTES, "archive limit");
    this.productionAclChecks = options.peerVerifier === undefined;
    this.verifier = options.peerVerifier ?? new MacOsPeerCredentialVerifier({
      ...this.peerPolicy
    });
    this.assertSocket();
    const stat = lstatSync(this.socketPath);
    this.socketIdentity = { device: stat.dev, inode: stat.ino };
  }

  async info(control?: ContainerEngineControl): Promise<ContainerEngineInfo> {
    const raw = object(await this.json("GET", "/info", undefined, control));
    const id = textField(raw.ID, 128, "engine identity");
    if (this.engineId !== undefined && this.engineId !== id) throw denied("Container Engine identity changed");
    if (raw.OSType !== "linux" || raw.CgroupVersion !== "2" || !["aarch64", "arm64"].includes(String(raw.Architecture)) ||
        !Array.isArray(raw.SecurityOptions) || raw.SecurityOptions.length > 32 || raw.SecurityOptions.some(value => typeof value !== "string" || value.length > 256) ||
        !raw.SecurityOptions.includes("name=seccomp,profile=builtin") || !raw.SecurityOptions.includes("name=cgroupns")) {
      throw denied("Container Engine must be the bounded Linux ARM64 runtime");
    }
    this.engineId = id;
    return { id, serverVersion: textField(raw.ServerVersion, 128, "engine version"), osType: "linux",
      architecture: String(raw.Architecture), securityOptions: [...raw.SecurityOptions] as string[],
      cgroupVersion: textField(raw.CgroupVersion, 32, "cgroup version") };
  }

  async version(control?: ContainerEngineControl): Promise<ContainerEngineVersion> {
    const raw = object(await this.json("GET", "/version", undefined, control));
    if (raw.Os !== "linux" || !["arm64", "aarch64"].includes(String(raw.Arch))) throw denied("Container Engine platform is unsupported");
    return { version: textField(raw.Version, 128, "engine version"), apiVersion: textField(raw.ApiVersion, 32, "API version"), os: "linux", arch: String(raw.Arch) };
  }

  async inspectImage(image: string, control?: ContainerEngineControl): Promise<ContainerImageInspection> {
    assertImage(image);
    const raw = object(await this.json("GET", `/images/${encodeURIComponent(image)}/json`, undefined, control));
    if (typeof raw.Id !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(raw.Id) || raw.Os !== "linux" || raw.Architecture !== "arm64" ||
        !Array.isArray(raw.RepoDigests) || raw.RepoDigests.length > 64 || raw.RepoDigests.some(value => typeof value !== "string" || !IMAGE_PATTERN.test(value))) {
      throw denied("Container image identity or platform is invalid");
    }
    if (image.startsWith("sha256:") ? raw.Id !== image : !raw.RepoDigests.includes(image)) throw denied("Container image does not match the pinned digest");
    return { id: raw.Id, repoDigests: [...raw.RepoDigests] as string[], os: "linux", architecture: "arm64" };
  }

  async create(input: ContainerCreateOptions, control?: ContainerEngineControl): Promise<ContainerTaskHandle> {
    validateCreate(input);
    input = Object.freeze({ ...input });
    const material = normalizeCreate(input);
    const engine = await this.info(control);
    const image = await this.inspectImage(input.image, control);
    const identity = { ...material, imageId: image.id, engineId: engine.id };
    const raw = object(await this.json("POST", "/containers/create", createConfig(identity), control, [201]));
    if (typeof raw.Id !== "string" || !ID_PATTERN.test(raw.Id)) throw denied("Container Engine returned a malformed full container ID");
    if (this.workspaces.has(raw.Id)) throw denied("Container Engine reused an active task container ID");
    const handle: ContainerTaskHandle = Object.freeze({ id: raw.Id, imageId: image.id, engineId: engine.id,
      taskId: material.taskId, owner: material.owner, nonce: material.nonce, maxRuntimeMs: material.maxRuntimeMs,
      readonlyWorkspace: material.readonlyWorkspace, memoryBytes: material.memoryBytes, nanoCpus: material.nanoCpus, pidsLimit: material.pidsLimit });
    await this.inspect(handle, control);
    this.workspaces.set(handle.id, { handle, phase: "new", activeExecutions: 0 });
    return handle;
  }

  async inspect(handle: ContainerTaskHandle, control?: ContainerEngineControl): Promise<ContainerInspection> {
    handle = snapshotHandle(handle);
    const engine = await this.info(control);
    if (engine.id !== handle.engineId) throw denied("Container belongs to a different Engine");
    const raw = object(await this.json("GET", `/containers/${handle.id}/json`, undefined, control));
    validateInspection(raw, handle);
    const state = object(raw.State);
    if (!["running", "created", "exited"].includes(String(state.Status)) || state.Paused === true || state.Restarting === true || state.Dead === true ||
        state.Running === true && state.Status !== "running" || state.Running === false && state.Pid !== 0 || typeof state.Running !== "boolean" || !Number.isSafeInteger(state.ExitCode) || !Number.isSafeInteger(state.Pid) || Number(state.Pid) < 0) {
      throw denied("Container state readback is invalid");
    }
    return { id: handle.id, running: state.Running, status: textField(state.Status, 32, "container state"),
      exitCode: Number(state.ExitCode), processId: Number(state.Pid) };
  }

  async start(handle: ContainerTaskHandle, control?: ContainerEngineControl): Promise<ContainerInspection> {
    handle = snapshotHandle(handle);
    const prior = await this.inspect(handle, control);
    if (prior.running || prior.status !== "created") throw denied("Only an owned newly created container can start");
    await this.json("POST", `/containers/${handle.id}/start`, undefined, control, [204]);
    const next = await this.inspect(handle, control);
    if (!next.running) throw new BrokerError("VERIFICATION_FAILED", "Container start did not read back as running");
    return next;
  }

  async kill(handle: ContainerTaskHandle, control?: ContainerEngineControl): Promise<ContainerInspection> {
    handle = snapshotHandle(handle);
    const workspace = this.workspaces.get(handle.id);
    if (workspace && Object.entries(workspace.handle).every(([key, value]) => value === handle[key as keyof ContainerTaskHandle])) workspace.phase = "blocked";
    const prior = await this.inspect(handle, control);
    if (prior.running) await this.json("POST", `/containers/${handle.id}/kill?signal=SIGKILL`, undefined, control, [204, 409]);
    const next = await this.inspect(handle, control);
    if (next.running) throw new BrokerError("UNKNOWN_OUTCOME", "Owned container stop remains unverified", true);
    return next;
  }

  async remove(handle: ContainerTaskHandle, control?: ContainerEngineControl): Promise<{ removed: true }> {
    handle = snapshotHandle(handle);
    const prior = await this.inspect(handle, control);
    if (prior.running) throw denied("Running containers must be stopped and verified before removal");
    await this.json("DELETE", `/containers/${handle.id}?force=false&v=false`, undefined, control, [204]);
    const result = await this.exchange("GET", `/containers/${handle.id}/json`, undefined, control, this.maxResponseBytes, [404]);
    if (result.status !== 404) throw new BrokerError("VERIFICATION_FAILED", "Container removal did not read back as absent");
    this.workspaces.delete(handle.id);
    return { removed: true };
  }

  async uploadArchive(handle: ContainerTaskHandle, archive: Buffer, control?: ContainerEngineControl): Promise<void> {
    handle = snapshotHandle(handle);
    if (!Buffer.isBuffer(archive) || archive.length < 512 || archive.length > this.maxArchiveBytes) {
      throw new BrokerError("OUTPUT_LIMIT", "Container upload archive exceeds its bounded size");
    }
    archive = Buffer.from(archive);
    const files = parseWorkspaceArchive(archive, false);
    const workspace = this.requireWorkspace(handle);
    if (workspace.phase !== "new") throw denied("Workspace staging is allowed exactly once before any task execution");
    workspace.phase = "staging";
    const deadline = Date.now() + integer(control?.timeoutMs ?? this.requestTimeoutMs, 1, MAX_RUNTIME_MS, "staging timeout");
    // Docker rejects archive PUT for a readonly rootfs even when the destination
    // is a writable tmpfs. Only this fixed pre-task program may use guest UID0.
    const stage = async (operation: Record<string, unknown>): Promise<void> => {
      const remaining = deadline - Date.now();
      if (remaining < 1) throw new BrokerError("TIMEOUT", "Workspace staging exceeded its deadline");
      const response = await this.executeAs(handle, { command: ["/usr/local/bin/node", "-e", WORKSPACE_STAGER, JSON.stringify(operation)],
        timeoutMs: remaining, outputCapBytes: 256 }, handle.readonlyWorkspace ? "0:0" : "65532:65532", control);
      if (response.exitCode !== 0 || response.stdout !== "STAGED" || response.stderr) throw new BrokerError("VERIFICATION_FAILED", "Fixed workspace staging did not verify");
    };
    try {
      await stage({ op: "begin", readonly: handle.readonlyWorkspace });
      let batch: StagingChunk[] = [];
      const flush = async (): Promise<void> => { if (batch.length) { await stage({ op: "chunks", chunks: batch }); batch = []; } };
      for (const file of files) {
        for (let offset = 0; offset < Math.max(1, file.content.length); offset += STAGING_CHUNK_BYTES) {
          const end = Math.min(offset + STAGING_CHUNK_BYTES, file.content.length);
          const chunk: StagingChunk = { path: file.path, offset, data: file.content.subarray(offset, end).toString("base64"),
            final: end === file.content.length, size: file.content.length, sha256: file.sha256 };
          if (batch.length >= 64 || Buffer.byteLength(JSON.stringify({ op: "chunks", chunks: [...batch, chunk] })) > STAGING_ARGUMENT_BYTES) await flush();
          batch.push(chunk);
        }
      }
      await flush();
      await stage({ op: "seal", readonly: handle.readonlyWorkspace });
      workspace.phase = "ready";
    } catch (error) {
      workspace.phase = "blocked";
      try { await this.kill(handle, { timeoutMs: this.requestTimeoutMs }); }
      catch { throw new BrokerError("UNKNOWN_OUTCOME", "Workspace staging failed and owned container stop remains unverified", true); }
      throw error;
    }
  }

  async downloadArchive(handle: ContainerTaskHandle, control?: ContainerEngineControl): Promise<Buffer> {
    handle = snapshotHandle(handle);
    const workspace = this.requireWorkspace(handle);
    if (!["ready", "executing"].includes(workspace.phase) || workspace.activeExecutions !== 0) throw denied("Workspace export requires completed task execution and exclusive ownership");
    workspace.phase = "exporting";
    const deadline = Date.now() + integer(control?.timeoutMs ?? this.requestTimeoutMs, 1, MAX_RUNTIME_MS, "export timeout");
    const call = async (operation: Record<string, unknown>, outputCapBytes: number): Promise<Record<string, unknown>> => {
      const remaining = deadline - Date.now();
      if (remaining < 1) throw new BrokerError("TIMEOUT", "Workspace export exceeded its deadline");
      const response = await this.executeAs(handle, { command: ["/usr/local/bin/node", "-e", WORKSPACE_EXPORTER, JSON.stringify(operation)],
        timeoutMs: remaining, outputCapBytes }, "65532:65532", control);
      if (response.exitCode !== 0 || response.stderr) throw new BrokerError("VERIFICATION_FAILED", "Fixed workspace export did not verify");
      return object(parseJsonUtf8Strict(Buffer.from(response.stdout)));
    };
    try {
      const index = await call({ op: "index" }, 4 * 1024 * 1024);
      if (!Array.isArray(index.files) || !Array.isArray(index.directories) || index.files.length + index.directories.length > 10_000) throw denied("Workspace export index exceeds its entry budget");
      const directories: string[] = [];
      const files: ExportFile[] = [];
      const seen = new Set<string>();
      let total = 0;
      for (const path of index.directories) {
        if (typeof path !== "string" || !safeSnapshotPath(path) || seen.has(path)) throw denied("Workspace export directory is forbidden or duplicated");
        seen.add(path); directories.push(path);
      }
      for (const raw of index.files) {
        if (!isPlainDataRecord(raw) || Object.keys(raw).sort().join(",") !== "ctime,dev,ino,mtime,path,size" ||
            typeof raw.path !== "string" || !safeSnapshotPath(raw.path) || seen.has(raw.path) ||
            !Number.isSafeInteger(raw.size) || Number(raw.size) < 0 || Number(raw.size) > 8 * 1024 * 1024 ||
            [raw.dev, raw.ino, raw.mtime, raw.ctime].some(value => typeof value !== "string" || !/^[0-9]{1,32}$/u.test(value))) throw denied("Workspace export file identity or path is invalid");
        total += Number(raw.size); if (total > EXPORT_TOTAL_BYTES) throw new BrokerError("OUTPUT_LIMIT", "Workspace export exceeds its byte budget");
        seen.add(raw.path); files.push(raw as unknown as ExportFile);
      }
      const hashes = new Map<string, string>();
      for (let offset = 0; offset < files.length; offset += 64) {
        const group = files.slice(offset, offset + 64);
        const response = await call({ op: "hashes", files: group }, 32 * 1024);
        if (!Array.isArray(response.files) || response.files.length !== group.length) throw denied("Workspace export hash evidence is invalid");
        for (let i = 0; i < group.length; i++) {
          const value = response.files[i];
          if (!isPlainDataRecord(value) || value.path !== group[i]!.path || typeof value.sha256 !== "string" || !ID_PATTERN.test(value.sha256)) throw denied("Workspace export hash evidence is invalid");
          hashes.set(value.path, value.sha256);
        }
      }
      const output: SnapshotFile[] = [];
      for (const file of files) {
        const chunks: Buffer[] = [];
        for (let offset = 0; offset < Math.max(1, file.size); offset += EXPORT_CHUNK_BYTES) {
          const length = Math.min(EXPORT_CHUNK_BYTES, file.size - offset);
          const response = await call({ op: "read", file, sha256: hashes.get(file.path), offset, length }, 512 * 1024);
          if (typeof response.data !== "string" || response.data.length > 350_000 || response.sha256 !== hashes.get(file.path)) throw denied("Workspace export chunk evidence is invalid");
          const bytes = Buffer.from(response.data, "base64");
          if (bytes.toString("base64") !== response.data || bytes.length !== length) throw denied("Workspace export chunk data is invalid");
          chunks.push(bytes);
        }
        const content = Buffer.concat(chunks);
        if (content.length !== file.size || sha256(content) !== hashes.get(file.path)) throw denied("Workspace export content changed after indexing");
        output.push({ path: file.path, content, sha256: hashes.get(file.path)! });
      }
      return createWorkspaceArchive(output, directories, handle.readonlyWorkspace);
    } catch (error) {
      workspace.phase = "blocked";
      try { await this.kill(handle, { timeoutMs: this.requestTimeoutMs }); }
      catch { throw new BrokerError("UNKNOWN_OUTCOME", "Workspace export failed and owned container stop remains unverified", true); }
      throw error;
    }
  }

  async exec(handle: ContainerTaskHandle, input: ContainerExecOptions, control?: ContainerEngineControl): Promise<ContainerExecResult> {
    handle = snapshotHandle(handle);
    validateExec(input);
    const workspace = this.requireWorkspace(handle);
    if (workspace.phase !== "ready" && workspace.phase !== "executing") throw denied("Task execution requires a successfully staged workspace");
    workspace.phase = "executing";
    workspace.activeExecutions++;
    try { return await this.executeAs(handle, input, "65532:65532", control); }
    finally { workspace.activeExecutions--; }
  }

  private requireWorkspace(handle: ContainerTaskHandle): WorkspacePhase {
    const workspace = this.workspaces.get(handle.id);
    if (!workspace || Object.entries(workspace.handle).some(([key, value]) => value !== handle[key as keyof ContainerTaskHandle])) {
      throw denied("Workspace staging requires the exact newly created task handle");
    }
    return workspace;
  }

  private async executeAs(handle: ContainerTaskHandle, input: ContainerExecOptions, user: "0:0" | "65532:65532", control?: ContainerEngineControl): Promise<ContainerExecResult> {
    handle = snapshotHandle(handle);
    validateExec(input);
    input = Object.freeze({ ...input, command: Object.freeze([...input.command]) });
    const controller = new AbortController();
    const abort = (): void => controller.abort();
    control?.signal?.addEventListener("abort", abort, { once: true });
    if (control?.signal?.aborted) controller.abort();
    const timer = setTimeout(abort, input.timeoutMs);
    try {
      const owned = await this.inspect(handle, { signal: controller.signal, timeoutMs: input.timeoutMs });
      if (!owned.running) throw denied("Task execution requires a running owned container");
      const exec = object(await this.json("POST", `/containers/${handle.id}/exec`, {
        AttachStdin: false, AttachStdout: true, AttachStderr: true, Tty: false, Privileged: false,
        User: user, WorkingDir: "/workspace", Env: [...TASK_ENVIRONMENT], Cmd: [...input.command]
      }, { signal: controller.signal, timeoutMs: input.timeoutMs }, [201]));
      if (typeof exec.Id !== "string" || !ID_PATTERN.test(exec.Id)) throw denied("Container Engine returned a malformed full exec ID");
      const result = await this.exchange("POST", `/exec/${exec.Id}/start`, Buffer.from(JSON.stringify({ Detach: false, Tty: false })),
        { signal: controller.signal, timeoutMs: input.timeoutMs }, Math.min(this.maxResponseBytes, input.outputCapBytes + 256 * 1024), [200]);
      const output = decodeMultiplexStream(result.bytes, input.outputCapBytes);
      const inspected = object(await this.json("GET", `/exec/${exec.Id}/json`, undefined, { signal: controller.signal, timeoutMs: input.timeoutMs }));
      const processConfig = object(inspected.ProcessConfig);
      if (inspected.ContainerID !== handle.id || inspected.ID !== exec.Id || inspected.Running !== false ||
          !Number.isSafeInteger(inspected.ExitCode) || processConfig.user !== user || processConfig.privileged !== false || processConfig.tty !== false) {
        throw new BrokerError("VERIFICATION_FAILED", "Task exec identity, user or exit state did not verify");
      }
      return { exitCode: Number(inspected.ExitCode), ...output, truncated: false };
    } catch (error) {
      // An HTTP stream deadline cannot terminate exec descendants. Stop the entire
      // owned cgroup with a fresh control, even when the caller's signal aborted.
      try { await this.kill(handle, { timeoutMs: this.requestTimeoutMs }); }
      catch { throw new BrokerError("UNKNOWN_OUTCOME", "Task transport failed and container stop remains unverified", true); }
      if (controller.signal.aborted) throw new BrokerError(control?.signal?.aborted ? "CANCELLED" : "TIMEOUT", "Container task execution was stopped after its deadline or cancellation");
      throw error;
    } finally {
      clearTimeout(timer);
      control?.signal?.removeEventListener("abort", abort);
    }
  }

  private async json(method: string, path: string, body: unknown, control?: ContainerEngineControl, statuses = [200]): Promise<unknown> {
    const encoded = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const response = await this.exchange(method, path, encoded, control, this.maxResponseBytes, statuses);
    if (response.bytes.length === 0) return null;
    try { return parseJsonUtf8Strict(response.bytes); }
    catch { throw new BrokerError("VERIFICATION_FAILED", "Container Engine returned malformed JSON"); }
  }

  private exchange(method: string, path: string, body: Buffer | undefined, control: ContainerEngineControl | undefined,
    byteCap: number, statuses: number[], contentType = "application/json"): Promise<EngineResponse> {
    this.assertSocket();
    if (control?.signal?.aborted) return Promise.reject(new BrokerError("CANCELLED", "Container Engine request was cancelled"));
    const timeout = integer(control?.timeoutMs ?? this.requestTimeoutMs, 1, MAX_RUNTIME_MS, "request timeout");
    return new Promise((resolvePromise, reject) => {
      let settled = false;
      let peerSocket: Socket | undefined;
      const agent = new Agent({ keepAlive: false, maxSockets: 1 });
      agent.createConnection = ((_options, callback) => {
        const socket = createConnection({ path: this.socketPath });
        peerSocket = socket;
        let delivered = false;
        const complete = (error: Error | null): void => {
          if (delivered) return;
          delivered = true;
          callback?.(error, socket);
        };
        socket.once("connect", () => {
          try {
            this.assertSocket();
            const peer = this.verifier.verify(socket);
            if (peer.uid !== this.peerPolicy.expectedUid || peer.gid !== this.peerPolicy.expectedGid ||
                peer.pid !== this.peerPolicy.allowedProcessIdentity.pid || settled) throw new Error("peer");
            complete(null);
          } catch { socket.destroy(); complete(denied("Container Engine peer identity verification failed")); }
        });
        socket.once("error", (error) => complete(error));
        return undefined;
      }) as Agent["createConnection"];
      const finish = (error?: unknown, value?: EngineResponse): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        control?.signal?.removeEventListener("abort", onAbort);
        agent.destroy();
        peerSocket?.destroy();
        if (error !== undefined) reject(error);
        else resolvePromise(value!);
      };
      const onAbort = (): void => finish(new BrokerError("CANCELLED", "Container Engine request was cancelled"));
      const timer = setTimeout(() => finish(new BrokerError("TIMEOUT", "Container Engine request exceeded its deadline")), timeout);
      control?.signal?.addEventListener("abort", onAbort, { once: true });
      const req = request({ method, socketPath: this.socketPath, path: `${API}${path}`, agent,
        headers: { "Content-Type": contentType, "Content-Length": body?.length ?? 0, Connection: "close" } }, (res) => {
        let size = 0;
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > byteCap) { finish(new BrokerError("OUTPUT_LIMIT", "Container Engine response exceeded its bounded size")); res.destroy(); return; }
          chunks.push(Buffer.from(chunk));
        });
        res.once("error", () => finish(new BrokerError("EXECUTION_FAILED", "Container Engine response transport failed")));
        res.once("aborted", () => finish(new BrokerError("EXECUTION_FAILED", "Container Engine response ended unexpectedly")));
        res.once("end", () => {
          const status = res.statusCode ?? 0;
          if (!statuses.includes(status)) {
            finish(new BrokerError(status === 404 ? "TARGET_NOT_FOUND" : "EXECUTION_FAILED", `Container Engine operation failed with status ${status}`));
          } else finish(undefined, { status, bytes: Buffer.concat(chunks, size) });
        });
      });
      req.once("error", (error) => {
        const code = (error as NodeJS.ErrnoException).code;
        const operation = path === "/info" ? "info" : path.endsWith("/json") ? "inspect" : path.endsWith("/exec") ? "exec-create" :
          path.startsWith("/exec/") && path.endsWith("/start") ? "exec-start" : "control";
        const knownCode = ["ECONNRESET", "EPIPE", "EMFILE", "ENFILE", "ENOBUFS", "EACCES", "ENOENT", "ECONNREFUSED"].includes(code ?? "") ? ` (${code}/${operation})` : "";
        finish(error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", `Container Engine request transport failed${knownCode}`));
      });
      if (body !== undefined) req.write(body);
      req.end();
    });
  }

  private assertSocket(): void {
    let socket;
    try {
      socket = lstatSync(this.socketPath);
      if (!socket.isSocket() || socket.isSymbolicLink() || socket.uid !== this.ownerUid || (socket.mode & 0o022) !== 0 ||
          realpathSync(this.socketPath) !== this.socketPath ||
          (this.socketIdentity !== undefined && (socket.dev !== this.socketIdentity.device || socket.ino !== this.socketIdentity.inode))) throw new Error("socket");
      // The owner home may carry the normal deny-delete ACL. Mandatory daemon
      // PID/start-time verification prevents a forged peer even across a path race.
      let path = dirname(this.socketPath);
      for (;;) {
        const parent = lstatSync(path);
        if (!parent.isDirectory() || parent.isSymbolicLink() || ![0, this.ownerUid].includes(parent.uid) || (parent.mode & 0o022) !== 0) throw new Error("parent");
        if (this.productionAclChecks && path === dirname(this.socketPath) && loadNativePeerAdapter().hasExtendedAclEntries(path) !== false) throw new Error("ACL");
        const next = dirname(path);
        if (next === path) break;
        path = next;
      }
      if (this.productionAclChecks && loadNativePeerAdapter().hasExtendedAclEntries(this.socketPath) !== false) throw new Error("ACL");
    } catch { throw denied("Container Engine socket path or ownership changed or is unsafe"); }
  }
}

function normalizeCreate(input: ContainerCreateOptions): Required<Omit<ContainerCreateOptions, "image">> {
  return { taskId: input.taskId, owner: input.owner, nonce: input.nonce, maxRuntimeMs: input.maxRuntimeMs,
    readonlyWorkspace: input.readonlyWorkspace ?? false, memoryBytes: input.memoryBytes ?? 512 * 1024 * 1024,
    nanoCpus: input.nanoCpus ?? 1_000_000_000, pidsLimit: input.pidsLimit ?? 128 };
}

function createConfig(input: Omit<ContainerTaskHandle, "id">): RecordValue {
  const workspace = input.readonlyWorkspace ? "rw,nosuid,nodev,size=536870912,uid=0,gid=0,mode=0555" : "rw,nosuid,nodev,size=536870912,uid=65532,gid=65532,mode=0700";
  return {
    Image: input.imageId, User: "65533:65533", WorkingDir: "/", Entrypoint: ["/usr/local/bin/node"],
    Cmd: ["-e", PID1_SCRIPT, String(input.maxRuntimeMs)], Env: [...TASK_ENVIRONMENT],
    AttachStdin: false, AttachStdout: false, AttachStderr: false, OpenStdin: false, StdinOnce: false, Tty: false,
    Labels: { [CONTAINER_LABELS.namespace]: "task-v1", [CONTAINER_LABELS.engineId]: input.engineId,
      [CONTAINER_LABELS.imageId]: input.imageId, [CONTAINER_LABELS.taskId]: input.taskId,
      [CONTAINER_LABELS.owner]: input.owner, [CONTAINER_LABELS.nonce]: input.nonce },
    NetworkingConfig: {},
    HostConfig: {
      AutoRemove: false, Privileged: false, ReadonlyRootfs: true, CapAdd: [], CapDrop: ["ALL"],
      SecurityOpt: ["no-new-privileges:true"], NetworkMode: "none", PidMode: "", IpcMode: "private", CgroupnsMode: "private",
      Binds: [], Mounts: [], VolumesFrom: [], Devices: [], DeviceRequests: [], DeviceCgroupRules: [], PortBindings: {}, PublishAllPorts: false, OomKillDisable: false,
      RestartPolicy: { Name: "no", MaximumRetryCount: 0 }, PidsLimit: input.pidsLimit,
      Memory: input.memoryBytes, MemorySwap: input.memoryBytes, NanoCpus: input.nanoCpus,
      Tmpfs: { "/workspace": workspace, "/tmp": "rw,nosuid,nodev,noexec,size=67108864,uid=65532,gid=65532,mode=0700",
        "/home/agent": "rw,nosuid,nodev,noexec,size=16777216,uid=65532,gid=65532,mode=0700" }
    }
  };
}

function validateInspection(raw: RecordValue, handle: ContainerTaskHandle): void {
  const config = object(raw.Config);
  const host = object(raw.HostConfig);
  const expected = createConfig(handle);
  const expectedHost = object(expected.HostConfig);
  const labels = object(config.Labels);
  const expectedLabels = object(expected.Labels);
  if (raw.Id !== handle.id || raw.Image !== handle.imageId ||
      Object.entries(expectedLabels).some(([key, value]) => labels[key] !== value) ||
      ["Image", "User", "WorkingDir", "Entrypoint", "Cmd", "OpenStdin", "Tty"].some(key => !same(config[key], expected[key])) ||
      !sameEnvironment(config.Env, TASK_ENVIRONMENT) ||
      Object.entries(expectedHost).some(([key, value]) => {
        // Docker cgroup v2 readback normalizes disabled OOM override to null.
        if (key === "OomKillDisable") return host[key] !== null && host[key] !== false;
        // Docker normalizes absent empty collections to null on inspection.
        return value !== null && (Array.isArray(value) && value.length === 0 || isPlainDataRecord(value) && Object.keys(value).length === 0)
          ? host[key] !== null && host[key] !== undefined && !same(host[key], value)
          : !same(host[key], value);
      })) throw denied("Container identity or fixed isolation configuration does not match");
  if (host.Init === true || host.UsernsMode === "host" || host.UTSMode === "host" || host.CgroupParent || host.Runtime && host.Runtime !== "runc" ||
      config.Volumes !== null && config.Volumes !== undefined && (!isPlainDataRecord(config.Volumes) || Object.keys(config.Volumes).length > 0)) throw denied("Container has an unexpected runtime or namespace override");
  const networks = object(object(raw.NetworkSettings).Networks);
  if (Object.keys(networks).some(key => key !== "none")) throw denied("Container has an unexpected network attachment");
  const mounts = raw.Mounts;
  if (!Array.isArray(mounts) || mounts.length > 3 || mounts.some(value => {
    const mount = object(value);
    return mount.Type !== "tmpfs" || !["/workspace", "/tmp", "/home/agent"].includes(String(mount.Destination)) || mount.RW !== true;
  }) || new Set(mounts.map(value => object(value).Destination)).size !== mounts.length) throw denied("Container has an unexpected host mount");
}

function validateCreate(input: ContainerCreateOptions): void {
  if (!isPlainDataRecord(input) || Object.keys(input).some(key => !["image", "taskId", "owner", "nonce", "maxRuntimeMs", "readonlyWorkspace", "memoryBytes", "nanoCpus", "pidsLimit"].includes(key))) throw denied("Container creation input is malformed");
  assertImage(input.image);
  for (const field of [input.taskId, input.nonce]) if (typeof field !== "string" || !IDENTIFIER_PATTERN.test(field)) throw denied("Container task identity is malformed");
  if (typeof input.owner !== "string" || !OWNER_PATTERN.test(input.owner)) throw denied("Container owner identity is malformed");
  integer(input.maxRuntimeMs, 1, MAX_RUNTIME_MS, "runtime");
  if (input.readonlyWorkspace !== undefined && typeof input.readonlyWorkspace !== "boolean") throw denied("Container workspace mode is invalid");
  integer(input.memoryBytes ?? 512 * 1024 * 1024, 64 * 1024 * 1024, 4 * 1024 * 1024 * 1024, "memory");
  integer(input.nanoCpus ?? 1_000_000_000, 100_000_000, 4_000_000_000, "CPU");
  integer(input.pidsLimit ?? 128, 16, 512, "process limit");
}

function snapshotHandle(handle: ContainerTaskHandle): ContainerTaskHandle {
  validateHandle(handle);
  return Object.freeze({ ...handle });
}

function validateHandle(handle: ContainerTaskHandle): void {
  if (!isPlainDataRecord(handle) || Object.keys(handle).some(key => !["id", "imageId", "engineId", "taskId", "owner", "nonce", "maxRuntimeMs", "readonlyWorkspace", "memoryBytes", "nanoCpus", "pidsLimit"].includes(key)) || typeof handle.id !== "string" || !ID_PATTERN.test(handle.id) ||
      typeof handle.imageId !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(handle.imageId) ||
      typeof handle.engineId !== "string" || handle.engineId.length < 1 || handle.engineId.length > 128) throw denied("A full container ID and exact task identity are required");
  validateCreate({ image: handle.imageId, taskId: handle.taskId, owner: handle.owner, nonce: handle.nonce,
    maxRuntimeMs: handle.maxRuntimeMs, readonlyWorkspace: handle.readonlyWorkspace,
    memoryBytes: handle.memoryBytes, nanoCpus: handle.nanoCpus, pidsLimit: handle.pidsLimit });
}

function validateExec(input: ContainerExecOptions): void {
  if (!isPlainDataRecord(input) || Object.keys(input).some(key => !["command", "timeoutMs", "outputCapBytes"].includes(key)) ||
      !Array.isArray(input.command) || input.command.length < 1 || input.command.length > 128 ||
      input.command.some(value => typeof value !== "string" || value.includes("\0")) ||
      typeof input.command[0] !== "string" || !isAbsolute(input.command[0]) ||
      Buffer.byteLength(input.command.join("\0")) > 64 * 1024) throw denied("Container task command is malformed");
  integer(input.timeoutMs, 1, MAX_RUNTIME_MS, "task timeout");
  integer(input.outputCapBytes, 1, 4 * 1024 * 1024, "task output limit");
}

function decodeMultiplexStream(bytes: Buffer, cap: number): { stdout: string; stderr: string } {
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  let offset = 0;
  let size = 0;
  let frames = 0;
  while (offset < bytes.length) {
    if (++frames > 65_536 || bytes.length - offset < 8 || ![1, 2].includes(bytes[offset]!) ||
        bytes[offset + 1] !== 0 || bytes[offset + 2] !== 0 || bytes[offset + 3] !== 0) throw denied("Container multiplex output framing is malformed");
    const length = bytes.readUInt32BE(offset + 4);
    if (length > bytes.length - offset - 8) throw denied("Container multiplex output frame is incomplete");
    size += length;
    if (size > cap) throw new BrokerError("OUTPUT_LIMIT", "Container task output exceeded its bounded size");
    const content = bytes.subarray(offset + 8, offset + 8 + length);
    (bytes[offset] === 1 ? stdout : stderr).push(content);
    offset += 8 + length;
  }
  return { stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") };
}

function sameEnvironment(value: unknown, expected: readonly string[]): boolean {
  if (!Array.isArray(value) || value.length !== expected.length || value.some(item => typeof item !== "string" || !item.includes("="))) return false;
  const entries = value.map(item => [item.slice(0, item.indexOf("=")), item.slice(item.indexOf("=") + 1)] as const);
  const actual = new Map(entries);
  return actual.size === entries.length && expected.every(item => actual.get(item.slice(0, item.indexOf("="))) === item.slice(item.indexOf("=") + 1));
}

function assertImage(image: string): void { if (typeof image !== "string" || !IMAGE_PATTERN.test(image)) throw denied("Container image must be pinned by its complete SHA-256 digest"); }
function object(value: unknown): RecordValue { if (!isPlainDataRecord(value)) throw denied("Container Engine data shape is invalid"); return value; }
function textField(value: unknown, cap: number, label: string): string { if (typeof value !== "string" || value.length < 1 || value.length > cap || value.includes("\0")) throw denied(`Container ${label} is invalid`); return value; }
function integer(value: number, min: number, max: number, label: string): number { if (!Number.isSafeInteger(value) || value < min || value > max) throw denied(`Container ${label} is outside its bounded range`); return value; }
function same(left: unknown, right: unknown): boolean { if (Array.isArray(left) && Array.isArray(right)) return left.length === right.length && left.every((value, i) => same(value, right[i])); if (isPlainDataRecord(left) && isPlainDataRecord(right)) return Object.keys(left).length === Object.keys(right).length && Object.entries(left).every(([key, value]) => same(value, right[key])); return left === right; }
function denied(message: string): BrokerError { return new BrokerError("POLICY_DENIED", message); }

// This program receives validated regular-file chunks as data before any task
// code exists. Guest UID0 only seals readonly snapshots; it has no host mounts,
// no Linux capabilities, no network, and no caller-selected command or paths.
const WORKSPACE_STAGER = String.raw`
const fs=require('fs'),path=require('path'),crypto=require('crypto'),C=fs.constants;
const q=JSON.parse(process.argv[1]),fds=[];
const fail=()=>{throw Error('STAGING_DENIED')};
const release=mark=>{while(fds.length>mark)try{fs.closeSync(fds.pop());}catch{}};
const valid=p=>typeof p==='string'&&p.length>0&&p.length<=240&&path.posix.normalize(p)===p&&!p.startsWith('/')&&!/[\x00-\x1f\\]/.test(p)&&p.split('/').every(s=>s&&s!=='.'&&s!=='..'&&s!=='.git');
const pinned=fd=>{const p=fs.readlinkSync('/proc/self/fd/'+fd);if(p!=='/workspace'&&!p.startsWith('/workspace/'))fail();};
const openDir=parts=>{let fd=fs.openSync('/workspace',C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);fds.push(fd);for(const part of parts){pinned(fd);const at='/proc/self/fd/'+fd+'/'+part;try{fs.mkdirSync(at,{mode:0o700});fs.fsyncSync(fd);}catch(e){if(e.code!=='EEXIST')throw e;}fd=fs.openSync(at,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);fds.push(fd);pinned(fd);}return fd;};
try{
if(q.op==='begin'){
if(typeof q.readonly!=='boolean'||fs.readdirSync('/workspace').length)fail();
if(q.readonly){if(process.getuid()!==0)fail();fs.chmodSync('/workspace',0o700);}else if(process.getuid()!==65532)fail();
}else if(q.op==='chunks'){
if(!Array.isArray(q.chunks)||q.chunks.length>64)fail();
for(const e of q.chunks){
const mark=fds.length;try{
if(!valid(e.path)||!Number.isSafeInteger(e.offset)||e.offset<0||!Number.isSafeInteger(e.size)||e.size<0||e.size>8388608||typeof e.final!=='boolean'||typeof e.data!=='string'||e.data.length>32768||!/^[a-f0-9]{64}$/.test(e.sha256))fail();
const data=Buffer.from(e.data,'base64');if(data.toString('base64')!==e.data||e.offset+data.length>e.size)fail();
const parts=e.path.split('/'),name=parts.pop(),dir=openDir(parts),at='/proc/self/fd/'+dir+'/'+name;
const file=fs.openSync(at,C.O_WRONLY|C.O_NOFOLLOW|(e.offset===0?C.O_CREAT|C.O_EXCL:0),0o600);fds.push(file);
const stat=fs.fstatSync(file);if(!stat.isFile()||stat.size!==e.offset)fail();
let n=0;while(n<data.length)n+=fs.writeSync(file,data,n,data.length-n,e.offset+n);fs.fsyncSync(file);pinned(dir);
if(e.final){if(fs.fstatSync(file).size!==e.size)fail();const read=fs.openSync(at,C.O_RDONLY|C.O_NOFOLLOW);fds.push(read);const bytes=fs.readFileSync(read);if(bytes.length!==e.size||crypto.createHash('sha256').update(bytes).digest('hex')!==e.sha256)fail();}
}finally{release(mark);}
}
}else if(q.op==='seal'){
if(typeof q.readonly!=='boolean')fail();
if(q.readonly){if(process.getuid()!==0)fail();let count=0;const seal=p=>{if(++count>10001)fail();const mark=fds.length;try{const dir=openDir(p?p.split('/'):[]);for(const name of fs.readdirSync('/proc/self/fd/'+dir)){const rel=p?p+'/'+name:name;if(!valid(rel))fail();const at='/proc/self/fd/'+dir+'/'+name,s=fs.lstatSync(at);if(s.isDirectory())seal(rel);else if(s.isFile()){const file=fs.openSync(at,C.O_RDONLY|C.O_NOFOLLOW);try{fs.fchmodSync(file,0o444);}finally{fs.closeSync(file);}}else fail();}pinned(dir);fs.fchmodSync(dir,0o555);}finally{release(mark);}};seal('');}
}else fail();
process.stdout.write('STAGED');
}catch{process.stderr.write('STAGING_DENIED');process.exitCode=1;}finally{for(const fd of fds.reverse())try{fs.closeSync(fd);}catch{}}
`;

// Export begins only after normal exec admission is fenced. The first call
// kills the complete task UID before reading; every call verifies that only
// this exporter and the separate trusted PID1 remain alive in the namespace.
const WORKSPACE_EXPORTER = String.raw`
const fs=require('fs'),path=require('path'),crypto=require('crypto'),C=fs.constants;
const q=JSON.parse(process.argv[1]),fds=[];
const fail=()=>{throw Error('EXPORT_DENIED')};
const release=mark=>{while(fds.length>mark)try{fs.closeSync(fds.pop());}catch{}};
const valid=p=>typeof p==='string'&&p.length>0&&Buffer.byteLength(p)<=240&&path.posix.normalize(p)===p&&!p.startsWith('/')&&!/[\x00-\x1f\\]/.test(p)&&p.split('/').every(s=>s&&s!=='.'&&s!=='..'&&s!=='.git');
const pinned=fd=>{const p=fs.readlinkSync('/proc/self/fd/'+fd);if(p!=='/workspace'&&!p.startsWith('/workspace/'))fail();};
const openDir=parts=>{let fd=fs.openSync('/workspace',C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);fds.push(fd);for(const part of parts){pinned(fd);fd=fs.openSync('/proc/self/fd/'+fd+'/'+part,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);fds.push(fd);pinned(fd);}return fd;};
const identity=(p,s)=>({path:p,size:Number(s.size),dev:String(s.dev),ino:String(s.ino),mtime:String(s.mtimeNs),ctime:String(s.ctimeNs)});
const quiet=()=>{for(const name of fs.readdirSync('/proc')){if(!/^[0-9]+$/.test(name)||Number(name)===process.pid)continue;let status;try{status=fs.readFileSync('/proc/'+name+'/status','utf8');}catch(e){if(e.code==='ENOENT')continue;throw e;}if(/^State:\s+Z/m.test(status))continue;const uid=/^Uid:\s+(\d+)/m.exec(status);if(Number(name)!==1||!uid||uid[1]!=='65533')return false;}return true;};
const read=e=>{
if(!valid(e.path)||!Number.isSafeInteger(e.size)||e.size<0||e.size>8388608)fail();const mark=fds.length;
try{const parts=e.path.split('/'),name=parts.pop(),dir=openDir(parts),file=fs.openSync('/proc/self/fd/'+dir+'/'+name,C.O_RDONLY|C.O_NOFOLLOW);fds.push(file);
const stat=fs.fstatSync(file,{bigint:true});if(!stat.isFile())fail();const before=identity(e.path,stat);for(const key of ['size','dev','ino','mtime','ctime'])if(before[key]!==e[key])fail();
const bytes=fs.readFileSync(file);const after=identity(e.path,fs.fstatSync(file,{bigint:true}));if(bytes.length!==e.size||JSON.stringify(before)!==JSON.stringify(after))fail();pinned(dir);
return {bytes,sha256:crypto.createHash('sha256').update(bytes).digest('hex')};}finally{release(mark);}
};
(async()=>{
if(process.getuid()!==65532)fail();
if(q.op==='index'){
try{process.kill(-1,'SIGKILL');}catch(e){if(e.code!=='ESRCH'&&e.code!=='EPERM')throw e;}
const until=Date.now()+2000;while(!quiet()){if(Date.now()>=until)fail();await new Promise(resolve=>setTimeout(resolve,10));}
}else if(!quiet())fail();
let result;
if(q.op==='index'){
const files=[],directories=[];let total=0,count=0;
const scan=p=>{const mark=fds.length;try{const dir=openDir(p?p.split('/'):[]);for(const name of fs.readdirSync('/proc/self/fd/'+dir).sort()){
if(++count>10000)fail();const rel=p?p+'/'+name:name;if(!valid(rel))fail();const at='/proc/self/fd/'+dir+'/'+name,s=fs.lstatSync(at,{bigint:true});
if(s.isDirectory()){directories.push(rel);scan(rel);}else if(s.isFile()){if(s.size>8388608n)fail();total+=Number(s.size);if(total>33554432)fail();files.push(identity(rel,s));}else fail();
}pinned(dir);}finally{release(mark);}};scan('');result={files,directories};
}else if(q.op==='hashes'){
if(!Array.isArray(q.files)||q.files.length>64)fail();result={files:q.files.map(e=>({path:e.path,sha256:read(e).sha256}))};
}else if(q.op==='read'){
if(!Number.isSafeInteger(q.offset)||q.offset<0||!Number.isSafeInteger(q.length)||q.length<0||q.length>262144||q.offset+q.length>q.file.size||!/^[a-f0-9]{64}$/.test(q.sha256))fail();
const data=read(q.file);if(data.sha256!==q.sha256)fail();result={data:data.bytes.subarray(q.offset,q.offset+q.length).toString('base64'),sha256:data.sha256};
}else fail();
if(!quiet())fail();process.stdout.write(JSON.stringify(result));
})().catch(()=>{process.stderr.write('EXPORT_DENIED');process.exitCode=1;}).finally(()=>release(0));
`;
