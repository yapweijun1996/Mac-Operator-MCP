import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, sha256 } from "@mac-operator/contracts";
import { ContainerTaskProfileRegistry, type ApprovedContainerTask, type ContainerTaskProfileOptions, type ContainerAgentRequest } from "./container-task-profile.js";
import type { CodexControllerPreflight } from "./codex-controller.js";

const IMAGE = `sha256:${"a".repeat(64)}`;
const ENGINE = "engine-test-1234";
const errorClass = (expected: string) => (error: unknown) => error instanceof BrokerError && error.errorClass === expected;
const ready = (): CodexControllerPreflight => ({ installed: true, version: "0.153.4", authentication: "authenticated",
  supportedModels: ["coding-test"], executableSha256: "b".repeat(64), catalogSha256: "c".repeat(64), reasonCodes: [] });

async function fixture() {
  const directory = await mkdtemp(join(await realpath(tmpdir()), "mac-container-profile-"));
  const project = join(directory, "project");
  const worktree = join(directory, "worktree");
  await mkdir(project); await mkdir(worktree);
  const manifest = JSON.stringify({ name: "fixture", scripts: { test: "node --test", build: "node build.js" } });
  await writeFile(join(project, "package.json"), manifest); await writeFile(join(worktree, "package.json"), manifest);
  const entry: ApprovedContainerTask = { profile: "fixture.test", projectRoot: project, manifestPath: "package.json",
    manifestSha256: sha256(manifest), scriptName: "test", scriptValue: "node --test",
    command: ["/usr/local/bin/npm", "run", "test"], timeoutMs: 10_000, outputCapBytes: 4096 };
  let runtimeCalls = 0;
  const options: ContainerTaskProfileOptions = { imageId: IMAGE, engineId: ENGINE, entries: [entry],
    async validateWorkspace(cwd, projectRoot, taskId) {
      if (cwd !== worktree || projectRoot !== project || taskId !== "task-fixture") throw new BrokerError("POLICY_DENIED", "Workspace is not owned by this task");
      return { owner: "principal-test", isWorktree: true };
    },
    async validateRuntime(image, engine, command) {
      assert.equal(image, IMAGE); assert.equal(engine, ENGINE); assert.equal(command[0]?.startsWith("/usr/local/bin/"), true);
      runtimeCalls += 1; return true;
    }, preflight: async () => ready() };
  return { directory, project, worktree, entry, options, runtimeCalls: () => runtimeCalls,
    request: { profile: "fixture.test", cwd: worktree, taskId: "task-fixture" },
    agent: { cwd: worktree, taskId: "task-fixture", task: "Add a brief README note", model: "coding-test",
      executionProfile: "workspace-write" as const, maxRuntimeMs: 10_000, allowedPaths: ["README.md"] },
    close: () => rm(directory, { recursive: true, force: true }) };
}

test("container task resolves a pinned guest command without fabricating host executable identity", async () => {
  const f = await fixture();
  try {
    const registry = new ContainerTaskProfileRegistry(f.options);
    assert.deepEqual(registry.names(), ["fixture.test"]);
    const profile = await registry.resolve(f.request);
    assert.equal(profile.process.executable, "/usr/local/bin/npm");
    assert.equal(profile.process.expectedExecutableContentSha256, undefined);
    assert.equal(profile.process.cwd, f.worktree);
    assert.deepEqual(profile.process.args, ["run", "test"]);
    assert.deepEqual(profile.process.environment, {});
    assert.deepEqual(profile.filesystemRoots, [f.worktree]);
    assert.equal(profile.networkPolicy, "none"); assert.equal(profile.credentialPolicy, "none");
    assert.deepEqual(profile.containerExecution, { projectRoot: f.project, imageId: IMAGE, engineId: ENGINE, taskId: "task-fixture", owner: "principal-test", readonlyWorkspace: false });
    for (const value of [profile, profile.process, profile.process.args, profile.filesystemRoots, profile.containerExecution]) assert.equal(Object.isFrozen(value), true);
    assert.equal(f.runtimeCalls(), 1);
  } finally { await f.close(); }
});

test("operator entries are snapshotted and cannot widen authorization after registration", async () => {
  const f = await fixture();
  try {
    const registry = new ContainerTaskProfileRegistry(f.options);
    f.entry.scriptValue = "different"; f.entry.timeoutMs = 600_000;
    (f.entry.command as string[]).push("--dangerous");
    (f.options.entries as ApprovedContainerTask[]).push({ ...f.entry, profile: "late-profile" });
    const profile = await registry.resolve(f.request);
    assert.deepEqual(profile.process.args, ["run", "test"]);
    assert.equal(profile.process.timeoutMs, 10_000); assert.deepEqual(registry.names(), ["fixture.test"]);
  } finally { await f.close(); }
});

test("container registration rejects mutable image tags, duplicate profiles, secret command options and shells", async () => {
  const f = await fixture();
  try {
    for (const options of [
      { ...f.options, imageId: "node:latest" }, { ...f.options, engineId: "unix:///var/run/docker.sock" },
      { ...f.options, entries: [f.entry, f.entry] }, { ...f.options, validateRuntime: undefined }
    ]) assert.throws(() => new ContainerTaskProfileRegistry(options as ContainerTaskProfileOptions));
    for (const command of [["npm", "test"], ["/usr/bin/sudo", "npm", "test"], ["/bin/sh", "-c", "npm test"],
      ["/usr/bin/env", "npm", "test"], ["/usr/local/bin/npm", "--token=value"]]) {
      assert.throws(() => new ContainerTaskProfileRegistry({ ...f.options, entries: [{ ...f.entry, command }] }));
    }
  } finally { await f.close(); }
});

test("caller arguments, unknown authority fields, sparse arrays and accessors never reach runtime readiness", async () => {
  const f = await fixture();
  try {
    const registry = new ContainerTaskProfileRegistry(f.options);
    const accessor = Object.defineProperty({ ...f.request }, "cwd", { get() { throw new Error("Accessor must not execute"); }, enumerable: true });
    for (const input of [{ ...f.request, args: ["--eval", "arbitrary code"] }, { ...f.request, command: "npm test" },
      { ...f.request, args: new Array(1) }, { ...f.request, owner: "other-owner" }, accessor,
      Object.create(f.request), { ...f.request, taskId: undefined }]) {
      await assert.rejects(registry.resolve(input), errorClass("PRECONDITION_FAILED"));
    }
    await registry.resolve({ ...f.request, args: [] });
    assert.equal(f.runtimeCalls(), 1);
  } finally { await f.close(); }
});

test("project and task ownership denial occurs before manifest or runtime access", async () => {
  const f = await fixture();
  try {
    await writeFile(join(f.project, "package.json"), "invalid-json");
    const registry = new ContainerTaskProfileRegistry(f.options);
    await assert.rejects(registry.resolve({ ...f.request, taskId: "another-task" }), errorClass("POLICY_DENIED"));
    await assert.rejects(registry.resolve({ ...f.request, cwd: join(f.directory, "unauthorized-missing") }), errorClass("POLICY_DENIED"));
    assert.equal(f.runtimeCalls(), 0);
  } finally { await f.close(); }
});

test("AGENT_RUN denies primary repositories and unowned workspaces even when the callback misclassifies one", async () => {
  const f = await fixture();
  try {
    const registry = new ContainerTaskProfileRegistry({ ...f.options, validateWorkspace: async () => ({ owner: "principal-test", isWorktree: true }) });
    await assert.rejects(registry.resolve({ ...f.request, cwd: f.project }), errorClass("POLICY_DENIED"));
    await assert.rejects(registry.resolveAgent({ ...f.agent, cwd: f.project }), errorClass("POLICY_DENIED"));
    const unowned = new ContainerTaskProfileRegistry({ ...f.options, validateWorkspace: async () => ({ owner: "principal-test", isWorktree: false }) });
    await assert.rejects(unowned.resolve(f.request), errorClass("POLICY_DENIED"));
  } finally { await f.close(); }
});

test("changed project manifest, changed worktree manifest and mismatched approved script fail closed", async () => {
  for (const target of ["project", "worktree", "script"] as const) {
    const f = await fixture();
    try {
      const options = target === "script" ? { ...f.options, entries: [{ ...f.entry, scriptValue: "node changed.js" }] } : f.options;
      const registry = new ContainerTaskProfileRegistry(options);
      if (target !== "script") await writeFile(join(f[target], "package.json"), JSON.stringify({ scripts: { test: "node changed.js" } }));
      await assert.rejects(registry.resolve(f.request), errorClass("POLICY_DENIED"));
      assert.equal(f.runtimeCalls(), 0);
    } finally { await f.close(); }
  }
});

test("manifest checks reject final and intermediate symlinks and canonical cwd escapes", async () => {
  const f = await fixture();
  try {
    const linked = join(f.directory, "worktree-link"); await symlink(f.worktree, linked);
    const permissive = { ...f.options, validateWorkspace: async () => ({ owner: "principal-test", isWorktree: true }) };
    await assert.rejects(new ContainerTaskProfileRegistry(permissive).resolve({ ...f.request, cwd: linked }), errorClass("POLICY_DENIED"));
    await rm(join(f.worktree, "package.json")); await symlink(join(f.project, "package.json"), join(f.worktree, "package.json"));
    await assert.rejects(new ContainerTaskProfileRegistry(f.options).resolve(f.request), errorClass("POLICY_DENIED"));
    await symlink(f.project, join(f.worktree, "linked"));
    const nested = new ContainerTaskProfileRegistry({ ...f.options, entries: [{ ...f.entry, manifestPath: "linked/package.json" }] });
    await assert.rejects(nested.resolve(f.request));
  } finally { await f.close(); }
});

test("manifest registration denies traversal, secret zones, dependencies and Git metadata", async () => {
  const f = await fixture();
  try {
    for (const manifestPath of ["../package.json", "src/../package.json", ".env", ".env.local", ".ssh/config",
      ".git/config", "node_modules/tool/package.json", join(f.project, "..", "outside.json")]) {
      assert.throws(() => new ContainerTaskProfileRegistry({ ...f.options, entries: [{ ...f.entry, manifestPath }] }));
    }
    const absolute = new ContainerTaskProfileRegistry({ ...f.options, entries: [{ ...f.entry, manifestPath: join(f.project, "package.json") }] });
    await absolute.resolve(f.request);
  } finally { await f.close(); }
});

test("missing immutable image runtime and invalid resource budgets deny execution", async () => {
  const f = await fixture();
  try {
    const registry = new ContainerTaskProfileRegistry({ ...f.options, validateRuntime: async () => false });
    await assert.rejects(registry.resolve(f.request), errorClass("POLICY_DENIED"));
    await assert.rejects(registry.resolve({ ...f.request, maxRuntimeMs: 10_001 }), errorClass("POLICY_DENIED"));
    await assert.rejects(registry.resolve({ ...f.request, maxRuntimeMs: 600_001 }), errorClass("PRECONDITION_FAILED"));
    assert.throws(() => new ContainerTaskProfileRegistry({ ...f.options, entries: [{ ...f.entry, outputCapBytes: 2_097_153 }] }));
    const reduced = await new ContainerTaskProfileRegistry(f.options).resolve({ ...f.request, maxRuntimeMs: 1000 });
    assert.equal(reduced.process.timeoutMs, 1000);
  } finally { await f.close(); }
});

test("Codex profiles bind model, task, paths and all three execution profiles to isolated worktrees", async () => {
  const f = await fixture();
  try {
    const registry = new ContainerTaskProfileRegistry(f.options);
    for (const executionProfile of ["readonly", "workspace-write", "test-only"] as const) {
      const profile = await registry.resolveAgent({ ...f.agent, executionProfile, projectRoot: f.project });
      assert.equal(profile.containerExecution?.readonlyWorkspace, executionProfile !== "workspace-write");
      assert.deepEqual(profile.containerExecution?.agent, { task: f.agent.task, model: "coding-test", executionProfile, allowedPaths: ["README.md"] });
      assert.equal(Object.isFrozen(profile.containerExecution?.agent?.allowedPaths), true);
      assert.equal(profile.process.expectedExecutableContentSha256, undefined);
    }
    assert.equal(f.runtimeCalls(), 3);
    assert.deepEqual(await registry.agentPreflight(), ready());
  } finally { await f.close(); }
});

test("Codex resolution denies missing auth, unsupported models, missing runtime and unknown projects", async () => {
  const f = await fixture();
  try {
    for (const preflight of [undefined, async () => ({ ...ready(), authentication: "not_authenticated" as const }),
      async () => ({ ...ready(), installed: false }), async () => ({ ...ready(), reasonCodes: ["NOT_READY"] }),
      async () => ({ ...ready(), supportedModels: [] })]) {
      const { preflight: _preflight, ...withoutPreflight } = f.options;
      const registry = new ContainerTaskProfileRegistry(preflight === undefined ? withoutPreflight : { ...withoutPreflight, preflight });
      await assert.rejects(registry.resolveAgent(f.agent), errorClass("POLICY_DENIED"));
    }
    await assert.rejects(new ContainerTaskProfileRegistry(f.options).resolveAgent({ ...f.agent, model: "unknown-model" }), errorClass("POLICY_DENIED"));
    await assert.rejects(new ContainerTaskProfileRegistry(f.options).resolveAgent({ ...f.agent, projectRoot: f.directory }), errorClass("POLICY_DENIED"));
    await assert.rejects(new ContainerTaskProfileRegistry({ ...f.options, validateRuntime: async () => false }).resolveAgent(f.agent), errorClass("POLICY_DENIED"));
  } finally { await f.close(); }
});

test("Codex caller paths and data shape cannot grant secrets, traversal, shell or credential authority", async () => {
  const f = await fixture();
  try {
    const registry = new ContainerTaskProfileRegistry(f.options);
    const wrongProfile = { toString() { throw new Error("Input coercion must not execute"); } };
    for (const input of [
      { ...f.agent, allowedPaths: ["../outside"] }, { ...f.agent, allowedPaths: ["/absolute"] },
      { ...f.agent, allowedPaths: [".ssh/id_rsa"] }, { ...f.agent, allowedPaths: [".env"] },
      { ...f.agent, allowedPaths: [".git/config"] }, { ...f.agent, args: ["sudo"] },
      { ...f.agent, executionProfile: wrongProfile }, { ...f.agent, task: "" }, { ...f.agent, maxRuntimeMs: 0 },
      { ...f.agent, task: "api_key=fixture-secret-value-for-denial" }
    ]) await assert.rejects(registry.resolveAgent(input as ContainerAgentRequest));
    assert.equal(f.runtimeCalls(), 0);
  } finally { await f.close(); }
});

test("strict JSON manifest duplicate keys and secret content are rejected without returning content", async () => {
  const f = await fixture();
  try {
    const bad = '{"scripts":{"test":"node --test","test":"node changed.js"}}';
    await writeFile(join(f.project, "package.json"), bad); await writeFile(join(f.worktree, "package.json"), bad);
    const registry = new ContainerTaskProfileRegistry({ ...f.options, entries: [{ ...f.entry, manifestSha256: sha256(bad) }] });
    await assert.rejects(registry.resolve(f.request), errorClass("PRECONDITION_FAILED"));
    assert.equal(await readFile(join(f.worktree, "package.json"), "utf8"), bad);
    assert.equal(f.runtimeCalls(), 0);
  } finally { await f.close(); }
});
