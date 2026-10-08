import { createConnection } from "node:net";
import { lstatSync, mkdirSync, realpathSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { z } from "zod";
import { sha256 } from "@mac-operator/contracts";
import { CodexController, CODEX_CONTROLLER_EXECUTABLE_SHA256, CODEX_CONTROLLER_VERSION, ContainerTaskProfileRegistry,
  ContainerTaskRunner, DevelopmentGateway, DockerContainerEngine, DockerEngineInspector, ManagedWorktrees, MacOsPeerCredentialVerifier,
  loadNativePeerAdapter, safeSnapshotPath, assertContentPathAllowed, type CodingAgentProvider, type RegisteredDevelopmentCommand, type TaskIsolationProof } from "@mac-operator/broker";
import { readAuthFile } from "./cli.js";
import type { V2PolicyConfiguration } from "./v2-policy.js";

const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u);
const path = z.string().max(4096).refine(value => isAbsolute(value) && resolve(value) === value && !value.includes("\0"));
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const image = z.string().regex(/^sha256:[a-f0-9]{64}$/u);
const entrySchema = z.object({
  profile: id, projectRoot: path, manifestPath: z.string().min(1).max(4096), manifestSha256: digest,
  scriptName: id, scriptValue: z.string().min(1).max(16384), command: z.array(z.string().min(1).max(4096)).min(1).max(64),
  timeoutMs: z.number().int().min(1).max(600000), outputCapBytes: z.number().int().min(256).max(2097152),
  type: z.enum(["test", "build", "lint", "typecheck", "package_script"]),
}).strict();
const runtimeSchema = z.object({
  schemaVersion: z.literal("0.1"), ownerProjectRoot: path, developmentProjects: z.array(path).min(1).max(8),
  gitPushDeniedProjects: z.array(path).max(8).default([]),
  stateRoot: path, worktreeRoot: path, taskProfiles: z.array(id).min(1).max(256), socketPath: path,
  engineId: id, imageId: image, codexExecutable: path, codexExecutableSha256: z.literal(CODEX_CONTROLLER_EXECUTABLE_SHA256),
  codexVersion: z.literal(CODEX_CONTROLLER_VERSION), evidencePath: path, evidenceSha256: digest,
  snapshotExcludedPaths: z.array(z.string().refine(safeSnapshotPath)).max(64).default([]),
  entries: z.array(entrySchema).min(1).max(256),
}).strict();
export type PersonalDevelopmentRuntimeConfig = z.infer<typeof runtimeSchema> & V2PolicyConfiguration;

export const REQUIRED_CONTAINER_EVIDENCE = [
  "filesystem_isolation", "secret_denial", "no_sudo", "network_denial", "readonly_workspace", "workspace_write",
  "process_tree_timeout", "cancellation", "restart_recovery", "concurrent_isolation", "registered_test_success",
  "registered_test_failure", "registered_build", "codex_readonly", "codex_workspace_write", "primary_unchanged",
] as const;

export function loadPersonalDevelopmentRuntimeConfig(configPath: string): PersonalDevelopmentRuntimeConfig {
  const config = runtimeSchema.parse(JSON.parse(readAuthFile(configPath, 131072).toString("utf8")));
  if (new Set(config.gitPushDeniedProjects).size !== config.gitPushDeniedProjects.length ||
      config.gitPushDeniedProjects.some(project => !config.developmentProjects.includes(project))) throw new Error("Git push denial list differs from approved projects");
  if (new Set(config.snapshotExcludedPaths).size !== config.snapshotExcludedPaths.length || new Set(config.developmentProjects).size !== config.developmentProjects.length || new Set(config.taskProfiles).size !== config.taskProfiles.length ||
      config.entries.some(entry => !config.developmentProjects.includes(entry.projectRoot)) ||
      [...config.entries.map(entry => entry.profile)].sort().join() !== [...config.taskProfiles].sort().join()) throw new Error("Development registry differs from approved projects/profiles");
  const bytes = readAuthFile(config.evidencePath, 131072);
  if (sha256(bytes) !== config.evidenceSha256) throw new Error("Development isolation evidence content changed");
  const evidence = JSON.parse(bytes.toString("utf8")) as Record<string, unknown>;
  const checks = Array.isArray(evidence.checks) ? evidence.checks : [];
  if (evidence.schemaVersion !== "0.1" || evidence.imageId !== config.imageId || evidence.engineId !== config.engineId ||
      evidence.codexExecutableSha256 !== config.codexExecutableSha256 || evidence.codexVersion !== config.codexVersion ||
      !Array.isArray(evidence.checks) || REQUIRED_CONTAINER_EVIDENCE.some(name =>
        !checks.some((entry: unknown) => typeof entry === "object" && entry !== null &&
          "name" in entry && entry.name === name && "status" in entry && entry.status === "pass"))) throw new Error("Development isolation evidence is incomplete or belongs to a different runtime");
  return config;
}

export async function createPersonalDevelopmentRuntime(config: PersonalDevelopmentRuntimeConfig, principalId: string) {
  assertContentPathAllowed(config.worktreeRoot);
  for (const directory of [config.stateRoot, config.worktreeRoot]) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0 || realpathSync.native(directory) !== directory) {
      throw new Error("Development control storage is not a private canonical directory");
    }
  }
  const socket = createConnection(config.socketPath);
  let peer;
  try {
    await new Promise<void>((ok, fail) => { socket.setTimeout(5000, () => fail(new Error("Engine peer connection timed out"))); socket.once("connect", ok); socket.once("error", fail); });
    peer = new MacOsPeerCredentialVerifier({ expectedUid: process.getuid!() }).verify(socket);
  } finally { socket.destroy(); }
  const identity = loadNativePeerAdapter().getProcessIdentity(peer.pid) as { pid: number; startTimeMicros: number };
  const engine = new DockerContainerEngine({ socketPath: config.socketPath,
    peerPolicy: { expectedUid: peer.uid, expectedGid: peer.gid, allowedProcessIdentity: { pid: identity.pid, startTimeMicros: identity.startTimeMicros } } });
  const information = await engine.info(), inspectedImage = await engine.inspectImage(config.imageId);
  if (information.id !== config.engineId || inspectedImage.id !== config.imageId) throw new Error("Approved Engine/image identity changed");
  const controller = new CodexController({ executable: config.codexExecutable,
    expectedExecutableSha256: config.codexExecutableSha256, stateRoot: join(config.stateRoot, "codex-controller") });
  const preflight = await controller.preflight();
  if (!preflight.installed || preflight.authentication !== "authenticated" || preflight.version !== config.codexVersion || preflight.reasonCodes.length) {
    throw new Error("Approved Codex controller is not ready");
  }
  const worktrees = new ManagedWorktrees(config.stateRoot, config.worktreeRoot);
  try {
    const profiles = new ContainerTaskProfileRegistry({ imageId: config.imageId, engineId: config.engineId,
      entries: config.entries.map(({ type: _type, ...entry }) => entry), agentProjects: config.developmentProjects,
      validateWorkspace: async (cwd, projectRoot, taskId) => {
        if (!config.developmentProjects.includes(projectRoot)) throw new Error("Development project is not registered");
        worktrees.require(cwd, projectRoot, principalId, taskId);
        return { owner: principalId, isWorktree: true };
      },
      validateRuntime: async (imageId, engineId) => (await engine.info()).id === engineId && (await engine.inspectImage(imageId)).id === imageId,
      preflight: () => controller.preflight(),
    });
    const proof: TaskIsolationProof = { schemaVersion: "0.1", sandboxMechanism: "docker-container", sandboxProfile: "docker-container",
      filesystem: "enforced", network: "enforced", credentials: "isolated", persistence: "isolated",
      credentialIsolation: "docker-container-no-host-credentials-v1", processTree: "owned", processTreePolicy: "owned_group",
      evidenceRef: `container-evidence:${config.evidenceSha256}`, containerImage: { imageId: config.imageId, engineId: config.engineId } };
    const runner = new ContainerTaskRunner({ engine, imageId: config.imageId, engineId: config.engineId, enabled: true,
      hostEvidenceAccepted: true, isolationProof: proof, controller, snapshotExcludedPaths: config.snapshotExcludedPaths,
      registeredCommands: config.entries.map(entry => ({ name: entry.profile, executable: entry.command[0]!, args: entry.command.slice(1), kind: entry.type, projectRoot: entry.projectRoot })) });
    const provider: CodingAgentProvider = { readiness: {
      installed: preflight.installed, version: preflight.version, authentication: "ready", supportedModels: preflight.supportedModels,
      enforcedProfiles: ["readonly", "workspace-write", "test-only"], hostGitDenied: true, networkPolicies: ["none"],
    }, resolve: (input, record) => profiles.resolveAgent({ cwd: record.worktree, projectRoot: record.projectRoot, taskId: record.taskId,
      task: input.task as string, executionProfile: input.execution_profile as "readonly" | "workspace-write" | "test-only",
      maxRuntimeMs: input.max_runtime as number, ...(input.model === undefined ? {} : { model: input.model as string }),
      ...(input.allowed_paths === undefined ? {} : { allowedPaths: input.allowed_paths as string[] }) }) };
    const commands: RegisteredDevelopmentCommand[] = config.entries.map(entry => ({ projectRoot: entry.projectRoot, type: entry.type, profile: entry.profile }));
    const gateway = new DevelopmentGateway({ worktrees, commands, codingAgent: provider, codexExecutable: config.codexExecutable });
    return { gateway, runner, profiles, config, dockerInspector: new DockerEngineInspector(engine.dockerReadTransport()) };
  } catch (error) { await worktrees.close(); throw error; }
}

export function developmentPolicyConfiguration(config: PersonalDevelopmentRuntimeConfig): V2PolicyConfiguration {
  return { developmentProjects: config.developmentProjects, stateRoot: config.stateRoot,
    worktreeRoot: config.worktreeRoot, taskProfiles: config.taskProfiles,
    ...(config.gitPushDeniedProjects.length === 0 ? {} : { gitPushDeniedProjects: config.gitPushDeniedProjects }) };
}
