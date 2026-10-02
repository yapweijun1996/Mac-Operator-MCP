import { spawn, type ChildProcessWithoutNullStreams, type SpawnOptionsWithoutStdio } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, readlink, realpath, symlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { containsSecretRepresentation, redactBoundedText } from "./secret-policy.js";

export const CODEX_CONTROLLER_VERSION = "0.153.4";
export const CODEX_CONTROLLER_EXECUTABLE_SHA256 = "b973d440acac501fd2594a43e7ca9ce41e0a65b9dfb28d0d7a7837c99e1261e3";

const MAX_PROTOCOL_BYTES = 4 * 1024 * 1024;
const MAX_LINE_BYTES = 256 * 1024;
const MAX_TOOL_CALLS = 128;
const DISABLED_FEATURES = [
  "shell_tool", "unified_exec", "code_mode", "code_mode_host", "apps", "plugins", "remote_plugin", "hooks",
  "multi_agent", "multi_agent_v2", "browser_use", "browser_use_external", "browser_use_full_cdp_access",
  "computer_use", "in_app_browser", "image_generation", "view_image", "workspace_dependencies", "memories",
  "shell_snapshot", "shell_snapshot_v2", "sleep_tool", "skill_mcp_dependency_install",
  "skill_env_var_dependency_prompt", "skill_search", "request_permissions_tool", "auth_elicitation", "tool_suggest"
] as const;
const INSTRUCTIONS = "You are a coding controller. Use only the supplied gateway tools. Those tools operate in an isolated project workspace. You have no host filesystem, shell, browser, credentials, network, or subagent tools. Never request privilege escalation or external authorization.";
const CONTROLLER_PERMISSION_PROFILE = "mac-operator-controller";
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;
const SAFE_TOOL = /^[A-Za-z][A-Za-z0-9_]{0,63}$/u;

function codingInstructions(profile: CodexControllerRun["executionProfile"], toolNames: Iterable<string>): string {
  const authority = profile === "workspace-write"
    ? "Source writes are authorized through the supplied write_file and edit_file tools when those tools are listed. Use them to complete requested source edits."
    : profile === "test-only"
      ? "Source writes are unavailable. Only supplied read tools and registered test commands are authorized."
      : "Source writes and command execution are unavailable. Use only the supplied read tools.";
  return `${INSTRUCTIONS} The logical isolated project workspace is /workspace; tool paths are relative to it. ` +
    `Execution profile: ${profile}. ${authority} ` +
    "The controller's host permission profile denies direct host access. It does not restrict separately authorized gateway tool operations inside /workspace. " +
    `Exact supplied gateway tool names: ${[...toolNames].join(", ") || "none"}. Do not invent gateway aliases or infer gateway write denial from the host permission profile.`;
}

export interface CodexControllerOptions {
  executable: string;
  catalogPath?: string;
  stateRoot?: string;
  ownerHome?: string;
  expectedExecutableSha256?: string;
  outputCapBytes?: number;
  /** Trusted dependency injection for protocol tests; never accepted from MCP inputs. */
  spawnProcess?: (executable: string, args: string[], options: SpawnOptionsWithoutStdio) => ChildProcessWithoutNullStreams;
}

export interface CodexControllerPreflight {
  installed: boolean;
  version: string | null;
  authentication: "authenticated" | "not_authenticated" | "unknown";
  supportedModels: string[];
  executableSha256: string | null;
  catalogSha256: string | null;
  reasonCodes: string[];
}

export interface CodexDynamicTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (argumentsValue: Record<string, unknown>, context: { signal: AbortSignal; executionProfile: CodexControllerRun["executionProfile"] }) => unknown | Promise<unknown>;
}

export interface CodexControllerRun {
  cwd: string;
  task: string;
  model?: string;
  maxRuntimeMs: number;
  executionProfile: "readonly" | "workspace-write" | "test-only";
  dynamicTools: CodexDynamicTool[];
  signal?: AbortSignal;
}

export interface CodexControllerResult {
  status: "completed" | "failed" | "timed_out" | "cancelled";
  output: string;
  toolCalls: Array<{ tool: string; callId: string; success: boolean }>;
  reasonCodes: string[];
  durationMs: number;
  /** Trusted schema names and value types only; never argument values or unknown keys. */
  argumentRejections?: Array<{ tool: string; fields: Array<{ field: string; type: string; valid: boolean }>; extraFieldCount: number }>;
}

class ControllerError extends Error {
  constructor(readonly reasonCode: string) { super(reasonCode); }
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function digest(value: Buffer | string): string { return createHash("sha256").update(value).digest("hex"); }

async function privateDirectory(path: string): Promise<void> {
  if (!isAbsolute(path)) throw new ControllerError("CONTROLLER_STATE_INVALID");
  await mkdir(path, { mode: 0o700, recursive: true });
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0 || await realpath(path) !== path) {
    throw new ControllerError("CONTROLLER_STATE_UNSAFE");
  }
}

/** Minimal schema validation intentionally rejects unsupported schema constructs. */
function validateArguments(schema: Record<string, unknown>, value: unknown, depth = 0): boolean {
  if (depth > 12 || Object.keys(schema).some(key => !["type", "properties", "required", "additionalProperties", "items", "enum", "minLength", "maxLength", "minimum", "maximum", "description", "title"].includes(key))) return false;
  if (Array.isArray(schema.enum) && !schema.enum.some(item => JSON.stringify(item) === JSON.stringify(value))) return false;
  if (schema.type === "object") {
    if (!object(value) || !object(schema.properties)) return false;
    if (Array.isArray(schema.required) && schema.required.some(key => typeof key !== "string" || !Object.hasOwn(value, key))) return false;
    for (const [key, item] of Object.entries(value)) {
      const child = schema.properties[key];
      if (child === undefined) { if (schema.additionalProperties !== true) return false; }
      else if (!object(child) || !validateArguments(child, item, depth + 1)) return false;
    }
    return true;
  }
  if (schema.type === "array") return Array.isArray(value) && value.length <= 256 && object(schema.items) && value.every(item => validateArguments(schema.items as Record<string, unknown>, item, depth + 1));
  if (schema.type === "string") return typeof value === "string" && (typeof schema.minLength !== "number" || value.length >= schema.minLength) && (typeof schema.maxLength !== "number" || value.length <= schema.maxLength);
  if (schema.type === "number" || schema.type === "integer") return typeof value === "number" && Number.isFinite(value) && (schema.type !== "integer" || Number.isInteger(value)) && (typeof schema.minimum !== "number" || value >= schema.minimum) && (typeof schema.maximum !== "number" || value <= schema.maximum);
  if (schema.type === "boolean") return typeof value === "boolean";
  if (schema.type === "null") return value === null;
  return false;
}

function argumentShape(tool: CodexDynamicTool, value: Record<string, unknown>): NonNullable<CodexControllerResult["argumentRejections"]>[number] {
  const properties = tool.inputSchema.properties as Record<string, unknown>;
  const names = Object.keys(properties);
  const required = Array.isArray(tool.inputSchema.required) ? tool.inputSchema.required : [];
  const fields = names.filter(name => /^[A-Za-z][A-Za-z0-9_]{0,63}$/u.test(name)).slice(0, 32).map(field => {
    const supplied = Object.hasOwn(value, field);
    const item = value[field];
    const schema = properties[field];
    return { field, type: !supplied ? "absent" : item === null ? "null" : Array.isArray(item) ? "array" : typeof item,
      valid: supplied ? object(schema) && validateArguments(schema, item) : !required.includes(field) };
  });
  return { tool: tool.name, fields, extraFieldCount: Object.keys(value).filter(name => !Object.hasOwn(properties, name)).length };
}

interface PreparedController { home: string; cwd: string; catalog: string; catalogSha256: string; configSha256: string; models: string[] }

/**
 * Trusted inference lives outside the checkout. Its only coding interface is a
 * fixed dynamic-tool set implemented by the isolated executor. The opaque auth
 * reference is private host control-plane state and is never copied into a task.
 */
export class CodexController {
  private readonly options: CodexControllerOptions;
  private prepared: Promise<PreparedController> | undefined;
  private readonly expectedHash: string;

  constructor(options: CodexControllerOptions) {
    this.options = options;
    this.expectedHash = options.expectedExecutableSha256 ?? CODEX_CONTROLLER_EXECUTABLE_SHA256;
    if (!isAbsolute(options.executable) || !/^[a-f0-9]{64}$/u.test(this.expectedHash) ||
        !Number.isInteger(options.outputCapBytes ?? 16_384) || (options.outputCapBytes ?? 16_384) < 256 || (options.outputCapBytes ?? 16_384) > 65_536) throw new ControllerError("CONTROLLER_CONFIGURATION_INVALID");
  }

  private spawn(args: string[], prepared?: PreparedController): ChildProcessWithoutNullStreams {
    const ownerHome = this.options.ownerHome ?? homedir();
    const options: SpawnOptionsWithoutStdio = {
      cwd: prepared?.cwd ?? tmpdir(),
      env: { HOME: prepared?.home ?? ownerHome, CODEX_HOME: prepared?.home ?? join(ownerHome, ".codex"), PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C", CODEX_NON_INTERACTIVE: "1", CODEX_INTERNAL_APP_SERVER_REMOTE_CONTROL_DISABLED: "1" },
      windowsHide: true, shell: false
    };
    return this.options.spawnProcess?.(this.options.executable, args, options) ?? spawn(this.options.executable, args, { ...options, stdio: "pipe" });
  }

  private async executableHash(): Promise<string> {
    const stat = await lstat(this.options.executable);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 512 * 1024 * 1024 || await realpath(this.options.executable) !== this.options.executable || (stat.mode & 0o022) !== 0) throw new ControllerError("CODEX_EXECUTABLE_UNSAFE");
    const hash = digest(await readFile(this.options.executable));
    if (hash !== this.expectedHash) throw new ControllerError("CODEX_EXECUTABLE_HASH_MISMATCH");
    return hash;
  }

  private authSource(): string { return join(this.options.ownerHome ?? homedir(), ".codex", "auth.json"); }

  private async safeAuthSourceExists(): Promise<boolean> {
    const source = this.authSource();
    try {
      const stat = await lstat(source);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0 || await realpath(source) !== source) throw new ControllerError("CODEX_AUTH_REFERENCE_UNSAFE");
      return true;
    } catch (error) { if (object(error) && error.code === "ENOENT") return false; throw error; }
  }

  private async assertAuthReference(home: string): Promise<void> {
    const path = join(home, "auth.json");
    try {
      const stat = await lstat(path);
      if (stat.uid !== process.getuid?.()) throw new ControllerError("CODEX_AUTH_REFERENCE_UNSAFE");
      if (stat.isSymbolicLink()) {
        if (await readlink(path) !== this.authSource() || !await this.safeAuthSourceExists()) throw new ControllerError("CODEX_AUTH_REFERENCE_UNSAFE");
      } else if (!stat.isFile() || (stat.mode & 0o077) !== 0 || await realpath(path) !== path) {
        throw new ControllerError("CODEX_AUTH_REFERENCE_UNSAFE");
      }
    } catch (error) { if (!(object(error) && error.code === "ENOENT")) throw error; }
  }

  private async command(args: string[], byteLimit: number, prepared?: PreparedController, signal?: AbortSignal): Promise<string> {
    if (signal?.aborted) throw new ControllerError("CODEX_CANCELLED");
    const child = this.spawn(args, prepared);
    return await new Promise((resolve, reject) => {
      let stdout = Buffer.alloc(0); let count = 0; let failed: ControllerError | undefined;
      const fail = (code: string) => { if (failed) return; failed = new ControllerError(code); child.kill("SIGKILL"); };
      const onAbort = () => fail("CODEX_CANCELLED");
      signal?.addEventListener("abort", onAbort, { once: true });
      const timer = setTimeout(() => fail("CODEX_PREFLIGHT_TIMEOUT"), 10_000);
      child.stdin.end();
      child.stdout.on("data", (chunk: Buffer) => { count += chunk.length; if (count > byteLimit) fail("CODEX_PREFLIGHT_OUTPUT_LIMIT"); else stdout = Buffer.concat([stdout, chunk]); });
      child.stderr.on("data", (chunk: Buffer) => { count += chunk.length; if (count > byteLimit) fail("CODEX_PREFLIGHT_OUTPUT_LIMIT"); });
      child.once("error", () => fail("CODEX_PROCESS_START_FAILED"));
      child.once("close", code => { clearTimeout(timer); signal?.removeEventListener("abort", onAbort); if (failed) reject(failed); else if (code === 0) resolve(stdout.toString("utf8")); else reject(new ControllerError("CODEX_PREFLIGHT_FAILED")); });
    });
  }

  private async prepare(signal?: AbortSignal): Promise<PreparedController> {
    this.prepared ??= this.createPrepared(signal);
    try { return await this.prepared; }
    catch (error) { this.prepared = undefined; throw error; }
  }

  private async createPrepared(signal?: AbortSignal): Promise<PreparedController> {
    await this.executableHash();
    const root = this.options.stateRoot ?? await mkdtemp(join(await realpath(tmpdir()), "mac-operator-codex-state-"));
    await privateDirectory(root);
    const home = await mkdtemp(join(root, "controller-"));
    await chmod(home, 0o700);
    const cwd = join(home, "workspace");
    await mkdir(cwd, { mode: 0o700 });
    if (await this.safeAuthSourceExists()) await symlink(this.authSource(), join(home, "auth.json"));
    if (this.options.catalogPath) {
      const catalogStat = await lstat(this.options.catalogPath);
      if (!catalogStat.isFile() || catalogStat.isSymbolicLink() || catalogStat.size > 4 * 1024 * 1024 || (catalogStat.mode & 0o022) !== 0 || await realpath(this.options.catalogPath) !== this.options.catalogPath) throw new ControllerError("CODEX_CATALOG_SOURCE_UNSAFE");
    }
    const raw = this.options.catalogPath ? await readFile(this.options.catalogPath, "utf8") : await this.command(["debug", "models", "--bundled"], 4 * 1024 * 1024, { home, cwd, catalog: "", catalogSha256: "", configSha256: "", models: [] }, signal);
    const parsed: unknown = JSON.parse(raw);
    if (!object(parsed) || !Array.isArray(parsed.models) || !parsed.models.length || parsed.models.length > 128) throw new ControllerError("CODEX_CATALOG_INVALID");
    const models: string[] = [];
    const stripped = parsed.models.map((value: unknown) => {
      if (!object(value) || typeof value.slug !== "string" || !SAFE_ID.test(value.slug)) throw new ControllerError("CODEX_CATALOG_INVALID");
      models.push(value.slug);
      return { ...value, shell_type: "disabled", apply_patch_tool_type: null, tool_mode: "direct", node_repl_disabled: true,
        experimental_supported_tools: [], supports_search_tool: false, include_skills_usage_instructions: false,
        include_apps_usage_instructions: false, include_plugin_usage_instructions: false,
        model_messages: { instructions_template: INSTRUCTIONS, instructions_variables: {} },
        base_instructions: INSTRUCTIONS };
    });
    const catalog = join(home, "models.json");
    const content = JSON.stringify({ models: stripped });
    await writeFile(catalog, content, { mode: 0o400, flag: "wx" });
    const config = [
      `model_catalog_json = ${JSON.stringify(catalog)}`, 'model_provider = "openai"', 'approval_policy = "never"',
      'approvals_reviewer = "user"', `default_permissions = ${JSON.stringify(CONTROLLER_PERMISSION_PROFILE)}`, 'web_search = "disabled"', 'project_doc_max_bytes = 0',
      'project_root_markers = []', 'check_for_update_on_startup = false', 'cli_auth_credentials_store = "file"',
      'developer_instructions = ""', 'suppress_unstable_features_warning = true', '[features]', ...DISABLED_FEATURES.map(feature => `${feature} = false`),
      'skip_host_skill_discovery = true', '[history]', 'persistence = "none"', '[analytics]', 'enabled = false',
      '[feedback]', 'enabled = false', '[shell_environment_policy]', 'inherit = "none"', '[mcp_servers]', '[hooks]', '[plugins]',
      '[agents]', 'enabled = false',
      '[skills]', 'include_instructions = false', '[skills.bundled]', 'enabled = false',
      '[orchestrator.skills]', 'enabled = false', '[orchestrator.mcp]', 'enabled = false',
      '[tools.experimental_request_user_input]', 'enabled = false', '[tools.update_plan]', 'enabled = false',
      `[permissions.${CONTROLLER_PERMISSION_PROFILE}.filesystem]`, '"/" = "deny"',
      `[permissions.${CONTROLLER_PERMISSION_PROFILE}.network]`, 'enabled = false'
    ].join("\n") + "\n";
    await writeFile(join(home, "config.toml"), config, { mode: 0o400, flag: "wx" });
    return { home, cwd, catalog, catalogSha256: digest(content), configSha256: digest(config), models };
  }

  private async assertPrepared(prepared: PreparedController): Promise<void> {
    await this.executableHash();
    await privateDirectory(prepared.home);
    await this.assertAuthReference(prepared.home);
    for (const [path, expected] of [[prepared.catalog, prepared.catalogSha256], [join(prepared.home, "config.toml"), prepared.configSha256]] as const) {
      const stat = await lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0 || digest(await readFile(path)) !== expected) throw new ControllerError("CODEX_CONTROL_PLANE_CHANGED");
    }
  }

  async preflight(signal?: AbortSignal): Promise<CodexControllerPreflight> {
    const result: CodexControllerPreflight = { installed: false, version: null, authentication: "unknown", supportedModels: [], executableSha256: null, catalogSha256: null, reasonCodes: [] };
    try {
      result.executableSha256 = await this.executableHash(); result.installed = true;
      const version = (await this.command(["--version"], 4096, undefined, signal)).trim();
      if (version !== `codex-cli ${CODEX_CONTROLLER_VERSION}`) throw new ControllerError("CODEX_VERSION_UNSUPPORTED");
      result.version = CODEX_CONTROLLER_VERSION;
      const prepared = await this.prepare(signal); await this.assertPrepared(prepared); result.catalogSha256 = prepared.catalogSha256;
      const session = new ControllerSession(this.spawn(["app-server", "--stdio", "--strict-config"], prepared), 10_000, signal);
      try {
        await session.initialize();
        const account = await session.request("account/read", { refreshToken: false });
        if (!object(account)) throw new ControllerError("CODEX_AUTH_RESPONSE_INVALID");
        result.authentication = object(account.account) ? "authenticated" : "not_authenticated";
        const catalog = await session.request("model/list", { limit: 128, includeHidden: false });
        if (!object(catalog) || !Array.isArray(catalog.data) || catalog.data.some(value => !object(value) || typeof value.model !== "string" || !prepared.models.includes(value.model))) throw new ControllerError("CODEX_MODEL_RESPONSE_INVALID");
        result.supportedModels = catalog.data.map(value => String((value as Record<string, unknown>).model));
        if (!result.supportedModels.length) throw new ControllerError("CODEX_MODEL_CATALOG_EMPTY");
      } finally { await session.close(); }
    } catch (error) { result.reasonCodes.push(error instanceof ControllerError ? error.reasonCode : "CODEX_PREFLIGHT_UNAVAILABLE"); }
    return result;
  }

  async run(input: CodexControllerRun): Promise<CodexControllerResult> {
    const started = Date.now();
    const result: CodexControllerResult = { status: "failed", output: "", toolCalls: [], reasonCodes: [], durationMs: 0 };
    let session: ControllerSession | undefined;
    const handlersAbort = new AbortController();
    let deadlineExpired = false;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const onAbort = () => handlersAbort.abort();
    let output = "";
    try {
      if (!isAbsolute(input.cwd) || typeof input.task !== "string" || !input.task.trim() || input.task.length > 32_768 ||
          !Number.isInteger(input.maxRuntimeMs) || input.maxRuntimeMs < 100 || input.maxRuntimeMs > 3_600_000 ||
          !["readonly", "workspace-write", "test-only"].includes(input.executionProfile) || !Array.isArray(input.dynamicTools) || input.dynamicTools.length > 16) throw new ControllerError("CODEX_RUN_INPUT_INVALID");
      const tools = new Map<string, CodexDynamicTool>();
      for (const tool of input.dynamicTools) {
        if (!SAFE_TOOL.test(tool.name) || tools.has(tool.name) || typeof tool.description !== "string" || tool.description.length > 2048 ||
            !object(tool.inputSchema) || tool.inputSchema.type !== "object" || !object(tool.inputSchema.properties) || tool.inputSchema.additionalProperties !== false || typeof tool.handler !== "function") throw new ControllerError("CODEX_TOOL_CONFIGURATION_INVALID");
        tools.set(tool.name, tool);
      }
      if (input.signal?.aborted) throw new ControllerError("CODEX_CANCELLED");
      if (containsSecretRepresentation(input.task)) throw new ControllerError("CODEX_TASK_SECRET_DENIED");
      input.signal?.addEventListener("abort", onAbort, { once: true });
      deadline = setTimeout(() => { deadlineExpired = true; handlersAbort.abort(); }, input.maxRuntimeMs);
      const preflight = await this.preflight(handlersAbort.signal);
      if (preflight.reasonCodes.length || preflight.authentication !== "authenticated") throw new ControllerError(preflight.reasonCodes[0] ?? "CODEX_AUTHENTICATION_REQUIRED");
      if (input.model && !preflight.supportedModels.includes(input.model)) throw new ControllerError("CODEX_MODEL_UNAVAILABLE");
      const prepared = await this.prepare(handlersAbort.signal); await this.assertPrepared(prepared);
      if (handlersAbort.signal.aborted) throw new ControllerError("CODEX_CANCELLED");
      session = new ControllerSession(this.spawn(["app-server", "--stdio", "--strict-config"], prepared), Math.max(1, input.maxRuntimeMs - (Date.now() - started)), handlersAbort.signal);
      await session.initialize(true);
      const model = input.model ?? preflight.supportedModels[0]!;
      const instructions = codingInstructions(input.executionProfile, tools.keys());
      const thread = await session.request("thread/start", {
        model, cwd: prepared.cwd, ephemeral: true, runtimeWorkspaceRoots: [], environments: [],
        approvalPolicy: "never", approvalsReviewer: "user", permissions: CONTROLLER_PERMISSION_PROFILE, baseInstructions: instructions,
        developerInstructions: instructions, experimentalRawEvents: true,
        dynamicTools: input.dynamicTools.map(tool => ({ type: "function", name: tool.name, description: tool.description, inputSchema: tool.inputSchema, deferLoading: false }))
      });
      if (!object(thread) || !object(thread.thread) || typeof thread.thread.id !== "string" || !SAFE_ID.test(thread.thread.id)) throw new ControllerError("CODEX_THREAD_ID_INVALID");
      if (!object(thread.activePermissionProfile) || thread.activePermissionProfile.id !== CONTROLLER_PERMISSION_PROFILE || thread.cwd !== prepared.cwd ||
          thread.model !== model || !Array.isArray(thread.runtimeWorkspaceRoots) || thread.runtimeWorkspaceRoots.length !== 0 ||
          !Array.isArray(thread.instructionSources) || thread.instructionSources.length !== 0) throw new ControllerError("CODEX_CONTROLLER_CAPABILITY_MISSING");
      const threadId = thread.thread.id;
      const calls = new Set<string>();
      session.activate(threadId, async params => {
        if (!object(params) || typeof params.tool !== "string" || typeof params.callId !== "string" || !SAFE_ID.test(params.callId) || containsSecretRepresentation(params.callId) ||
            calls.has(params.callId) || params.namespace != null || !object(params.arguments) || result.toolCalls.length >= MAX_TOOL_CALLS) throw new ControllerError("CODEX_TOOL_REQUEST_INVALID");
        const tool = tools.get(params.tool);
        if (!tool) throw new ControllerError("CODEX_UNKNOWN_TOOL");
        if (containsSecretRepresentation(JSON.stringify(params.arguments))) throw new ControllerError("CODEX_TOOL_ARGUMENTS_SECRET_DENIED");
        calls.add(params.callId);
        const evidence = { tool: tool.name, callId: params.callId, success: false }; result.toolCalls.push(evidence);
        if (!validateArguments(tool.inputSchema, params.arguments)) {
          const shape = argumentShape(tool, params.arguments);
          (result.argumentRejections ??= []).push(shape);
          // A rejected operation grants no authority. Bounded model correction
          // still uses the same exact schema and identity checks.
          return { success: false, contentItems: [{ type: "inputText", text: JSON.stringify({
            error: "CODEX_TOOL_ARGUMENTS_INVALID",
            message: "Match the declared schema, respect its bounds and omit optional fields instead of null.",
            fields: shape.fields, extraFieldCount: shape.extraFieldCount
          }) }] };
        }
        const value = await tool.handler(params.arguments, { signal: handlersAbort.signal, executionProfile: input.executionProfile });
        if (handlersAbort.signal.aborted) throw new ControllerError("CODEX_CANCELLED");
        const serialized = typeof value === "string" ? value : JSON.stringify(value);
        if (serialized === undefined || Buffer.byteLength(serialized) > MAX_LINE_BYTES / 2) throw new ControllerError("CODEX_TOOL_OUTPUT_LIMIT");
        evidence.success = true;
        return { success: true, contentItems: [{ type: "inputText", text: redactBoundedText(serialized, 65_536).text }] };
      }, text => { output += text; if (Buffer.byteLength(output) > 256 * 1024) throw new ControllerError("CODEX_OUTPUT_LIMIT"); }, tools.keys());
      const turn = await session.request("turn/start", {
        threadId, cwd: prepared.cwd, input: [{ type: "text", text: input.task }], model,
        approvalPolicy: "never", approvalsReviewer: "user", environments: [], runtimeWorkspaceRoots: [],
        permissions: CONTROLLER_PERMISSION_PROFILE
      });
      session.validateTurnResponse(turn);
      const completed = await session.completion;
      result.status = completed === "completed" ? "completed" : "failed";
      if (completed !== "completed") result.reasonCodes.push("CODEX_TURN_FAILED");
      if (result.argumentRejections?.length && !result.toolCalls.some(call => call.success)) {
        result.status = "failed"; result.reasonCodes.push("CODEX_TOOL_ARGUMENTS_INVALID");
      }
      result.output = redactBoundedText(output, this.options.outputCapBytes ?? 16_384).text;
      await this.assertPrepared(prepared);
    } catch (error) {
      const code = deadlineExpired ? "CODEX_TIMEOUT" : error instanceof ControllerError ? error.reasonCode : "CODEX_CONTROLLER_FAILED";
      result.reasonCodes.push(code);
      result.status = code === "CODEX_CANCELLED" ? "cancelled" : code === "CODEX_TIMEOUT" ? "timed_out" : "failed";
    } finally {
      clearTimeout(deadline); input.signal?.removeEventListener("abort", onAbort);
      handlersAbort.abort(); await session?.close(); result.output = redactBoundedText(output, this.options.outputCapBytes ?? 16_384).text; result.durationMs = Date.now() - started;
    }
    return result;
  }
}

class ControllerSession {
  private buffer = Buffer.alloc(0);
  private totalBytes = 0;
  private nextId = 0;
  private readonly pending = new Map<number, { resolve: (result: unknown) => void; reject: (error: Error) => void }>();
  private readonly inboundIds = new Set<string>();
  private failed: ControllerError | undefined;
  private threadId: string | undefined;
  private announcedThreadId: string | undefined;
  private turnId: string | undefined;
  private responseTurnId: string | undefined;
  private toolHandler: ((params: unknown) => Promise<unknown>) | undefined;
  private outputHandler: ((text: string) => void) | undefined;
  private toolNames = new Set<string>();
  private completed = false;
  private activeTools = 0;
  private readonly timer: ReturnType<typeof setTimeout>;
  private readonly onAbort: () => void;
  private readonly completionResolve: (state: string) => void;
  private readonly completionReject: (error: Error) => void;
  private readonly exited: Promise<void>;
  readonly completion: Promise<string>;

  constructor(private readonly child: ChildProcessWithoutNullStreams, timeout: number, private readonly signal?: AbortSignal) {
    let resolve!: (state: string) => void; let reject!: (error: Error) => void;
    this.completion = new Promise<string>((a, b) => { resolve = a; reject = b; });
    this.completionResolve = resolve; this.completionReject = reject;
    // Preflight sessions do not await turn completion; the rejection is still observed.
    void this.completion.catch(() => undefined);
    this.timer = setTimeout(() => this.fail(new ControllerError("CODEX_TIMEOUT")), timeout);
    this.onAbort = () => { if (!this.completed) this.fail(new ControllerError("CODEX_CANCELLED")); };
    signal?.addEventListener("abort", this.onAbort, { once: true });
    if (signal?.aborted) this.onAbort();
    this.exited = new Promise(resolveExit => child.once("close", () => { if (!this.completed && !this.failed) this.fail(new ControllerError("CODEX_PROCESS_EXITED")); resolveExit(); }));
    child.once("error", () => this.fail(new ControllerError("CODEX_PROCESS_START_FAILED")));
    child.stdin.on("error", () => this.fail(new ControllerError("CODEX_PROTOCOL_CLOSED")));
    child.stdout.on("data", (chunk: Buffer) => this.receive(chunk));
    child.stderr.on("data", (chunk: Buffer) => { this.totalBytes += chunk.length; if (this.totalBytes > MAX_PROTOCOL_BYTES) this.fail(new ControllerError("CODEX_PROTOCOL_OUTPUT_LIMIT")); });
  }

  private send(value: unknown): void {
    if (this.failed) return;
    this.child.stdin.write(JSON.stringify(value) + "\n");
  }

  async initialize(experimental = false): Promise<void> {
    const initialized = await this.request("initialize", { clientInfo: { name: "mac_operator_controller", title: "Mac Operator controller", version: "0.1.0" }, capabilities: { experimentalApi: experimental } });
    if (!object(initialized)) throw new ControllerError("CODEX_INITIALIZE_INVALID");
    this.send({ method: "initialized", params: {} });
  }

  request(method: "initialize" | "account/read" | "model/list" | "thread/start" | "turn/start" | "turn/interrupt", params: unknown): Promise<unknown> {
    if (this.failed) return Promise.reject(this.failed);
    const id = ++this.nextId;
    return new Promise((resolve, reject) => { this.pending.set(id, { resolve, reject }); this.send({ id, method, params }); });
  }

  activate(threadId: string, toolHandler: (params: unknown) => Promise<unknown>, outputHandler: (text: string) => void, toolNames: Iterable<string>): void {
    if (this.announcedThreadId !== undefined && this.announcedThreadId !== threadId) throw new ControllerError("CODEX_EVENT_IDENTITY_MISMATCH");
    this.threadId = threadId; this.toolHandler = toolHandler; this.outputHandler = outputHandler; this.toolNames = new Set(toolNames);
  }

  validateTurnResponse(value: unknown): void {
    if (!object(value) || !object(value.turn) || typeof value.turn.id !== "string" || !SAFE_ID.test(value.turn.id) ||
        this.turnId !== undefined && value.turn.id !== this.turnId) throw new ControllerError("CODEX_TURN_ID_INVALID");
    this.responseTurnId = value.turn.id;
  }

  private fail(error: ControllerError): void {
    if (this.failed) return;
    // Cancellation is best-effort; the owned process is terminated even when RPC stalls.
    if (this.threadId && this.turnId) this.send({ id: ++this.nextId, method: "turn/interrupt", params: { threadId: this.threadId, turnId: this.turnId } });
    this.failed = error;
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear(); this.completionReject(error); this.child.kill("SIGTERM");
  }

  private receive(chunk: Buffer): void {
    if (this.failed) return;
    this.totalBytes += chunk.length;
    if (this.totalBytes > MAX_PROTOCOL_BYTES) { this.fail(new ControllerError("CODEX_PROTOCOL_OUTPUT_LIMIT")); return; }
    this.buffer = Buffer.concat([this.buffer, chunk]);
    let newline: number;
    while ((newline = this.buffer.indexOf(10)) !== -1) {
      if (newline > MAX_LINE_BYTES) { this.fail(new ControllerError("CODEX_PROTOCOL_LINE_LIMIT")); return; }
      const line = this.buffer.subarray(0, newline); this.buffer = this.buffer.subarray(newline + 1);
      try { const message: unknown = JSON.parse(line.toString("utf8")); this.message(message); }
      catch (error) { this.fail(error instanceof ControllerError ? error : new ControllerError("CODEX_PROTOCOL_MALFORMED")); return; }
    }
    if (this.buffer.length > MAX_LINE_BYTES) this.fail(new ControllerError("CODEX_PROTOCOL_LINE_LIMIT"));
  }

  private message(message: unknown): void {
    if (!object(message)) throw new ControllerError("CODEX_PROTOCOL_MALFORMED");
    if (message.method === undefined) {
      if (typeof message.id !== "number" || !Number.isSafeInteger(message.id) || !this.pending.has(message.id)) throw new ControllerError("CODEX_RESPONSE_ID_INVALID");
      const pending = this.pending.get(message.id)!; this.pending.delete(message.id);
      if (message.error !== undefined) pending.reject(new ControllerError("CODEX_RPC_FAILED")); else if (Object.hasOwn(message, "result")) pending.resolve(message.result); else throw new ControllerError("CODEX_RESPONSE_INVALID");
      return;
    }
    if (typeof message.method !== "string" || !object(message.params)) throw new ControllerError("CODEX_NOTIFICATION_INVALID");
    const params = message.params;
    if (message.id !== undefined) {
      const identity = `${typeof message.id}:${String(message.id)}`;
      if (!(typeof message.id === "string" && SAFE_ID.test(message.id)) && !(typeof message.id === "number" && Number.isSafeInteger(message.id) && message.id >= 0)) throw new ControllerError("CODEX_REQUEST_ID_INVALID");
      if (this.inboundIds.has(identity)) throw new ControllerError("CODEX_DUPLICATE_REQUEST_ID");
      this.inboundIds.add(identity);
      if (message.method !== "item/tool/call" || !this.toolHandler) throw new ControllerError("CODEX_UNEXPECTED_SERVER_REQUEST");
      this.validateTurn(params);
      const id = message.id;
      this.activeTools++;
      void this.toolHandler(params).then(result => { if (!this.failed) this.send({ id, result }); }).catch(error => this.fail(error instanceof ControllerError ? error : new ControllerError("CODEX_TOOL_FAILED"))).finally(() => { this.activeTools--; });
      return;
    }
    if (message.method === "thread/started") {
      if (!object(params.thread) || typeof params.thread.id !== "string" || !SAFE_ID.test(params.thread.id) ||
          this.announcedThreadId !== undefined || this.threadId !== undefined && params.thread.id !== this.threadId) throw new ControllerError("CODEX_THREAD_ID_INVALID");
      this.announcedThreadId = params.thread.id; return;
    }
    if (["account/updated", "account/rateLimits/updated", "model/rerouted", "warning", "remoteControl/status/changed"].includes(message.method)) return;
    if (!this.threadId) {
      // No tool startup should occur before an isolated thread is activated.
      throw new ControllerError("CODEX_UNEXPECTED_NOTIFICATION");
    }
    if (message.method === "turn/started") {
      if (params.threadId !== this.threadId || !object(params.turn) || typeof params.turn.id !== "string" || !SAFE_ID.test(params.turn.id) || this.turnId !== undefined ||
          this.responseTurnId !== undefined && params.turn.id !== this.responseTurnId) throw new ControllerError("CODEX_TURN_ID_INVALID");
      this.turnId = params.turn.id; return;
    }
    if (message.method === "thread/status/changed") {
      if (params.threadId !== this.threadId || !object(params.status)) throw new ControllerError("CODEX_EVENT_IDENTITY_MISMATCH");
      return;
    }
    this.validateTurn(params);
    if (message.method === "rawResponse/completed") {
      if (typeof params.responseId !== "string" || !SAFE_ID.test(params.responseId)) throw new ControllerError("CODEX_RAW_RESPONSE_INVALID");
      return;
    }
    if (message.method === "rawResponseItem/completed") {
      if (!object(params.item) || typeof params.item.type !== "string") throw new ControllerError("CODEX_RAW_ITEM_INVALID");
      if (["message", "reasoning", "function_call_output"].includes(params.item.type)) return;
      if (params.item.type !== "function_call" || typeof params.item.name !== "string" ||
          !this.toolNames.has(params.item.name.replace(/^functions\./u, "")) ||
          (params.item.namespace != null && params.item.namespace !== "functions") ||
          typeof params.item.call_id !== "string" || !SAFE_ID.test(params.item.call_id)) throw new ControllerError("CODEX_UNEXPECTED_RAW_TOOL");
      return;
    }
    if (message.method === "turn/completed") {
      if (!object(params.turn) || params.turn.id !== this.turnId || this.activeTools !== 0 || !["completed", "failed", "interrupted"].includes(String(params.turn.status))) throw new ControllerError("CODEX_COMPLETION_INVALID");
      this.completed = true; this.completionResolve(String(params.turn.status)); return;
    }
    if (message.method === "item/agentMessage/delta") {
      if (typeof params.delta !== "string" || typeof params.itemId !== "string" || !SAFE_ID.test(params.itemId)) throw new ControllerError("CODEX_MESSAGE_INVALID");
      this.outputHandler?.(params.delta); return;
    }
    if (message.method === "item/started" || message.method === "item/completed") {
      if (!object(params.item) || typeof params.item.id !== "string" || !SAFE_ID.test(params.item.id) || !["agentMessage", "reasoning", "dynamicToolCall", "contextCompaction", "userMessage"].includes(String(params.item.type))) throw new ControllerError("CODEX_BUILTIN_TOOL_OBSERVED");
      return;
    }
    if (["thread/tokenUsage/updated", "item/reasoning/summaryTextDelta", "item/reasoning/summaryPartAdded", "item/reasoning/textDelta", "turn/diff/updated", "turn/plan/updated", "codex/event"].includes(message.method)) return;
    throw new ControllerError("CODEX_UNEXPECTED_NOTIFICATION");
  }

  private validateTurn(params: Record<string, unknown>): void {
    const embeddedTurn = object(params.turn) ? params.turn.id : undefined;
    if (params.threadId !== this.threadId || this.turnId === undefined || (params.turnId ?? embeddedTurn) !== this.turnId) throw new ControllerError("CODEX_EVENT_IDENTITY_MISMATCH");
  }

  async close(): Promise<void> {
    clearTimeout(this.timer); this.signal?.removeEventListener("abort", this.onAbort);
    for (const pending of this.pending.values()) pending.reject(new ControllerError("CODEX_SESSION_CLOSED"));
    this.pending.clear(); this.child.stdin.end();
    const soft = setTimeout(() => this.child.kill("SIGTERM"), 100);
    const hard = setTimeout(() => this.child.kill("SIGKILL"), 500);
    await this.exited; clearTimeout(soft); clearTimeout(hard);
  }
}
