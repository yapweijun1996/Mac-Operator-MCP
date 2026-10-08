import { lstatSync } from "node:fs";
import { join } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";
import { assertProjectIdentity, canonicalProjectRoot, SAFE_GIT_ENVIRONMENT, type GitExecutionControl, type GitMetadataResolver } from "./git-inspector.js";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";

export interface GitPushInput {
  project_root: string;
  remote: "origin";
  branch_name: string;
  expected_commit: string;
  idempotency_key: string;
}
export interface GitPushResult { remote: "origin"; branch_name: string; pushed: boolean }
export interface GitPushInspector {
  push(input: GitPushInput, control: GitExecutionControl): Promise<GitPushResult>;
  verify(input: GitPushInput, control: GitExecutionControl): Promise<boolean>;
  close?(): Promise<void>;
}

export function validateGitPushInput(value: unknown, managedMetadata?: GitMetadataResolver): asserts value is GitPushInput {
  if (!isPlainDataRecord(value) || Object.keys(value).sort().join() !== "branch_name,expected_commit,idempotency_key,project_root,remote" ||
      typeof value.project_root !== "string" || value.remote !== "origin" ||
      typeof value.branch_name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u.test(value.branch_name) ||
      value.branch_name.includes("..") || value.branch_name.includes("//") || value.branch_name.endsWith(".") ||
      value.branch_name.split("/").some(part => !part || part.startsWith(".") || part.endsWith(".lock")) ||
      typeof value.expected_commit !== "string" || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(value.expected_commit) ||
      typeof value.idempotency_key !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.idempotency_key)) {
    throw new BrokerError("PRECONDITION_FAILED", "Push requires an exact origin, branch, commit and retry binding");
  }
  canonicalProjectRoot(value.project_root, managedMetadata);
}

/** Branches that are never overwritten by an agent push, whatever the caller binds. */
const PROTECTED_BRANCHES = /^(?:main|master|trunk|develop|development|production|prod|stable|release(?:\/.*)?|hotfix\/.*)$/u;
/** Repository-owned opt-out: `git config macoperator.nopush true` or a NO_PUSH file in the checkout root. */
const NO_PUSH_FILE = "NO_PUSH";

export interface GitPushInspectorOptions {
  supervisor?: Pick<ProcessSupervisor, "run" | "close">;
  /** Accepts an origin push URL. Defaults to a single github.com HTTPS repository URL. */
  endpointAllowed?: (url: string) => boolean;
  /** GIT_ALLOW_PROTOCOL value; production stays "https". */
  allowProtocol?: string;
  /** Resolves a managed worktree's Git metadata, as for the other governed Git adapters. */
  managedMetadata?: GitMetadataResolver;
}

export function isProtectedBranch(branchName: string): boolean { return PROTECTED_BRANCHES.test(branchName); }

/** Returns the reason a repository or branch opted out of agent pushes, if any. */
export function noPushReason(localConfig: string, branchName: string, checkoutRoot: string): string | undefined {
  for (const entry of localConfig.split("\0")) {
    const newline = entry.indexOf("\n");
    const key = (newline < 0 ? entry : entry.slice(0, newline)).toLowerCase();
    const value = newline < 0 ? "" : entry.slice(newline + 1).trim();
    if (key === "macoperator.nopush" && /^(?:true|yes|on|1)$/iu.test(value)) return "repository sets macoperator.nopush";
    if (key === "macoperator.nopushbranch" && value === branchName) return "branch is listed in macoperator.nopushbranch";
  }
  try {
    if (lstatSync(join(checkoutRoot, NO_PUSH_FILE)).isFile()) return "checkout contains a NO_PUSH file";
  } catch { /* absent marker means push is allowed */ }
  return undefined;
}

/** Fixed, non-force, single-branch push. Repository hooks and configurable transport programs stay inert. */
export class GitPushInspectorImpl implements GitPushInspector {
  private readonly supervisor: Pick<ProcessSupervisor, "run" | "close">;
  private readonly endpointAllowed: (url: string) => boolean;
  private readonly environment: Record<string, string>;
  private readonly managedMetadata: GitMetadataResolver | undefined;

  constructor(options: GitPushInspectorOptions = {}) {
    this.environment = { ...SAFE_GIT_ENVIRONMENT, GIT_ALLOW_PROTOCOL: options.allowProtocol ?? "https" };
    this.supervisor = options.supervisor ?? new ProcessSupervisor({ maxConcurrent: 1, allowedEnvironmentKeys: Object.keys(this.environment) });
    this.endpointAllowed = options.endpointAllowed ?? safeEndpoint;
    this.managedMetadata = options.managedMetadata;
  }

  close(): Promise<void> { return this.supervisor.close(); }

  async push(input: GitPushInput, control: GitExecutionControl): Promise<GitPushResult> {
    validateGitPushInput(input, this.managedMetadata);
    if (!control.beforeMutation) throw new BrokerError("POLICY_DENIED", "Push requires live Broker authority");
    if (isProtectedBranch(input.branch_name)) {
      throw new BrokerError("POLICY_DENIED", "PROTECTED_BRANCH: agents never push to a protected branch");
    }
    const identity = canonicalProjectRoot(input.project_root, this.managedMetadata);
    const endpoint = await this.endpoint(input, control, true);
    const readLocal = async () => {
      const branch = await this.run(input, ["symbolic-ref", "--quiet", "HEAD"], control);
      const head = await this.run(input, ["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"], control);
      if (!clean(branch) || branch.stdout !== `refs/heads/${input.branch_name}\n` ||
          !clean(head) || head.stdout !== `${input.expected_commit}\n`) {
        throw new BrokerError("PRECONDITION_FAILED", "Push branch or HEAD differs from the approved binding");
      }
      assertProjectIdentity(input.project_root, identity.identity, this.managedMetadata);
    };
    await readLocal();
    if (await this.readRemote(input, endpoint, control) === input.expected_commit) {
      return { remote: "origin", branch_name: input.branch_name, pushed: false };
    }
    // Recheck after network preflight; push the approved object, never a moving local ref.
    await readLocal();
    let mutationStarted = false;
    try {
      await this.run(input, ["push", "--porcelain", "--no-verify", "--no-follow-tags", "--recurse-submodules=no",
        "--", endpoint, `${input.expected_commit}:refs/heads/${input.branch_name}`], control, () => {
        assertProjectIdentity(input.project_root, identity.identity, this.managedMetadata);
        control.beforeMutation!();
        mutationStarted = true;
      });
    } catch (error) {
      if (!mutationStarted) throw error;
      // A failed or interrupted process can still have changed the remote. Only readback settles it.
    }
    try {
      assertProjectIdentity(input.project_root, identity.identity, this.managedMetadata);
      if (await this.readRemote(input, endpoint, control) === input.expected_commit) {
        return { remote: "origin", branch_name: input.branch_name, pushed: true };
      }
    } catch { /* Keep uncertainty when independent remote readback is unavailable. */ }
    throw new BrokerError("UNKNOWN_OUTCOME", "Push remote postcondition could not prove the expected commit", true);
  }

  async verify(input: GitPushInput, control: GitExecutionControl): Promise<boolean> {
    validateGitPushInput(input, this.managedMetadata);
    const identity = canonicalProjectRoot(input.project_root, this.managedMetadata);
    const endpoint = await this.endpoint(input, control);
    const commit = await this.readRemote(input, endpoint, control);
    assertProjectIdentity(input.project_root, identity.identity, this.managedMetadata);
    return commit === input.expected_commit;
  }

  private async endpoint(input: GitPushInput, control: GitExecutionControl, enforceOptOut = false): Promise<string> {
    const config = await this.run(input, ["config", "--local", "--null", "--list"], control);
    if (enforceOptOut && clean(config)) {
      const optOut = noPushReason(config.stdout, input.branch_name, input.project_root);
      if (optOut) throw new BrokerError("POLICY_DENIED", `NO_PUSH: ${optOut}`);
    }
    // Do not allow per-URL credentials, proxies, transport overrides, or multiple push destinations.
    if (!clean(config) || config.stdout.split("\0").some(entry => /^(?:http\.|https\.|protocol\.|remote\.[^.]+\.(?:proxy|vcs|receivepack|uploadpack)|push\.pushoption)/u.test(entry))) {
      throw new BrokerError("POLICY_DENIED", "Push transport configuration is unsupported");
    }
    const remote = await this.run(input, ["remote", "get-url", "--push", "--all", "origin"], control);
    if (!clean(remote)) throw new BrokerError("PRECONDITION_FAILED", "Origin push destination is unavailable");
    const lines = remote.stdout.split("\n");
    if (lines.length !== 2 || lines[1] !== "" || !this.endpointAllowed(lines[0]!)) {
      throw new BrokerError("POLICY_DENIED", "Origin requires exactly one allowed push destination");
    }
    return lines[0]!;
  }

  private async readRemote(input: GitPushInput, endpoint: string, control: GitExecutionControl): Promise<string | undefined> {
    const result = await this.run(input, ["ls-remote", "--refs", "--", endpoint, `refs/heads/${input.branch_name}`], control);
    if (!clean(result)) throw new BrokerError("VERIFICATION_FAILED", "Remote branch readback failed");
    if (result.stdout === "") return undefined;
    const match = /^(?<commit>[a-f0-9]{40}|[a-f0-9]{64})\t(?<ref>refs\/heads\/[^\n]+)\n$/u.exec(result.stdout);
    if (!match || match.groups!.ref !== `refs/heads/${input.branch_name}`) {
      throw new BrokerError("VERIFICATION_FAILED", "Remote branch readback is not exact");
    }
    return match.groups!.commit;
  }

  private run(input: GitPushInput, args: readonly string[], control: GitExecutionControl, beforeSpawn?: () => void): Promise<ProcessExecutionResult> {
    return this.supervisor.run({ executable: "/usr/bin/git", cwd: input.project_root,
      args: ["--no-pager", "--no-optional-locks", `--git-dir=${canonicalProjectRoot(input.project_root, this.managedMetadata).gitArgument}`, "--work-tree=.",
        "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "push.gpgSign=false",
        "-c", "credential.helper=osxkeychain", ...args],
      environment: this.environment, timeoutMs: Math.min(control.timeoutMs, 30_000), outputCapBytes: 131_072,
      shouldCancel: control.shouldCancel, ...(beforeSpawn ? { beforeSpawn } : {}) });
  }
}
function clean(result: ProcessExecutionResult): boolean {
  return result.resultClass === "SUCCEEDED" && result.exitCode === 0 && !result.truncated;
}
function safeEndpoint(value: string): boolean {
  if (/[\s\x00-\x1f\x7f]/u.test(value) || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "github.com" && !url.username && !url.password &&
      !url.search && !url.hash && /^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/u.test(url.pathname);
  } catch { return false; }
}
