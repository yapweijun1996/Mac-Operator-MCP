import assert from "node:assert/strict";
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { captureProcessPathIdentity } from "./process-supervisor.js";
import { TaskProfileRegistry, validateTaskRunArguments, type TaskProfile } from "./task-profile.js";

function profile(root: string, overrides: Partial<TaskProfile> = {}): TaskProfile {
  return {
    schemaVersion: "0.1",
    profile: "tests.echo",
    executable: "/bin/echo",
    allowedCwdRoots: [root],
    allowedArgumentPattern: "^[a-z0-9._=-]{1,32}$",
    maxArguments: 2,
    environment: { LANG: "C" },
    filesystemRoots: [root],
    networkPolicy: "none",
    credentialPolicy: "none",
    sandboxProfile: "deny-default-v0.1",
    timeoutMs: 1_000,
    outputCapBytes: 1_024,
    verificationStrategy: "exit_status_and_declared_task_verification",
    enabled: true,
    ...overrides
  };
}

test("named task resolution fixes executable, environment, roots, and budgets", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-task-profile-"));
  try {
    const canonicalRoot = await realpath(root);
    const registry = new TaskProfileRegistry([profile(canonicalRoot)]);
    assert.deepEqual(registry.names(), ["tests.echo"]);
    const resolved = await registry.resolve({ profile: "tests.echo", cwd: canonicalRoot, args: ["hello", "world"] });
    assert.equal(resolved.profile, "tests.echo");
    assert.deepEqual(resolved.process, {
      executable: "/bin/echo",
      expectedExecutableContentSha256: resolved.process.expectedExecutableContentSha256,
      args: ["hello", "world"],
      cwd: canonicalRoot,
      environment: { LANG: "C" },
      timeoutMs: 1_000,
      outputCapBytes: 1_024
    });
    assert.match(resolved.process.expectedExecutableContentSha256 ?? "", /^[a-f0-9]{64}$/u);
    assert.deepEqual(resolved.filesystemRoots, [canonicalRoot]);
    assert.equal(resolved.networkPolicy, "none");
    assert.deepEqual(resolved.networkAllowlist, []);
    assert.equal(resolved.credentialPolicy, "none");
    assert.equal(resolved.processTreePolicy, "single_process");
    assert.equal(resolved.sandboxProfile, "deny-default-v0.1");
    assert.equal(Object.isFrozen(resolved), true);
    assert.equal(Object.isFrozen(resolved.process), true);
    assert.equal(Object.isFrozen(resolved.process.args), true);
    assert.equal(Object.isFrozen(resolved.process.environment), true);
    assert.throws(
      () => { (resolved.process as unknown as { executable: string }).executable = "/bin/sh"; },
      TypeError
    );
    assert.throws(
      () => { (resolved.filesystemRoots as string[]).push("/tmp/escape"); },
      TypeError
    );
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("named task resolution binds executable content identity and rejects a mismatched profile digest", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-task-profile-digest-"));
  try {
    const canonicalRoot = await realpath(root);
    const identity = await captureProcessPathIdentity("/bin/echo", "executable");
    assert.match(identity.contentSha256 ?? "", /^[a-f0-9]{64}$/u);
    const digest = identity.contentSha256;
    assert.ok(digest);
    const registry = new TaskProfileRegistry([profile(canonicalRoot, {
      executableContentSha256: digest
    })]);
    const resolved = await registry.resolve({ profile: "tests.echo", cwd: canonicalRoot });
    assert.equal(resolved.process.expectedExecutableContentSha256, digest);
    const mismatched = new TaskProfileRegistry([profile(canonicalRoot, {
      executableContentSha256: "a".repeat(64)
    })]);
    await assert.rejects(
      mismatched.resolve({ profile: "tests.echo", cwd: canonicalRoot }),
      /content identity does not match/u
    );
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("posix-sh task profiles bind a Broker-owned script digest and reject script escapes", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-task-profile-script-"));
  const root = join(parent, "root");
  const outside = join(parent, "outside.sh");
  await mkdir(root);
  await writeFile(join(root, "task.sh"), "#!/bin/sh\nprintf '%s\\n' safe\n", { mode: 0o700 });
  await writeFile(outside, "#!/bin/sh\nprintf '%s\\n' outside\n", { mode: 0o700 });
  try {
    const canonicalRoot = await realpath(root);
    const scriptPath = await realpath(join(root, "task.sh"));
    const canonicalOutside = await realpath(outside);
    const resolved = await new TaskProfileRegistry([profile(canonicalRoot, {
      profile: "tests.script",
      executable: "/bin/sh",
      executionKind: "posix-sh-script",
      scriptPath,
      fixedArgs: ["bounded"],
      allowedArgumentPattern: "^[a-z]+$",
      maxArguments: 0
    })]).resolve({ profile: "tests.script", cwd: canonicalRoot });
    assert.equal(resolved.executionKind, "posix-sh-script");
    assert.equal(resolved.scriptPath, scriptPath);
    assert.equal(resolved.scriptContent, "#!/bin/sh\nprintf '%s\\n' safe\n");
    assert.match(resolved.scriptContentSha256 ?? "", /^[a-f0-9]{64}$/u);
    assert.equal(resolved.process.executable, "/bin/sh");
    assert.deepEqual(resolved.process.args, ["bounded"]);
    assert.throws(() => new TaskProfileRegistry([profile(canonicalRoot, {
      profile: "tests.bad-script-shape",
      scriptPath,
      executionKind: "binary"
    })]), /script binding/u);
    await assert.rejects(
      new TaskProfileRegistry([profile(canonicalRoot, {
        profile: "tests.bad-script-root",
        executable: "/bin/sh",
        executionKind: "posix-sh-script",
        scriptPath: canonicalOutside
      })]).resolve({ profile: "tests.bad-script-root", cwd: canonicalRoot }),
      /outside the Broker-owned filesystem roots/u
    );
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test("named task resolution rejects unknown, disabled, extra, and non-allowlisted arguments", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-task-profile-deny-"));
  try {
    const canonicalRoot = await realpath(root);
    const registry = new TaskProfileRegistry([
      profile(canonicalRoot),
      profile(canonicalRoot, { profile: "tests.disabled", enabled: false })
    ]);
    await assert.rejects(registry.resolve({ profile: "tests.missing", cwd: canonicalRoot }), /not found/u);
    await assert.rejects(registry.resolve({ profile: "tests.disabled", cwd: canonicalRoot }), /disabled/u);
    await assert.rejects(
      registry.resolve({ profile: "tests.echo", cwd: canonicalRoot, args: ["hello;whoami"] }),
      /not allowlisted/u
    );
    await assert.rejects(
      registry.resolve({ profile: "tests.echo", cwd: canonicalRoot, args: ["a", "b", "c"] }),
      /profile limit/u
    );
    await assert.rejects(
      registry.resolve({ profile: "tests.echo", cwd: canonicalRoot, extra: "executable" } as never),
      /malformed/u
    );
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("named task resolution rejects cwd traversal, symlink roots, and symlink executables", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-task-profile-path-"));
  const root = join(parent, "allowed");
  const outside = join(parent, "outside");
  const cwdLink = join(root, "cwd-link");
  const executableLink = join(parent, "echo-link");
  await mkdir(root);
  await mkdir(outside);
  await symlink(outside, cwdLink);
  await symlink("/bin/echo", executableLink);
  try {
    const canonicalRoot = await realpath(root);
    const canonicalOutside = await realpath(outside);
    const registry = new TaskProfileRegistry([profile(canonicalRoot)]);
    await assert.rejects(
      registry.resolve({ profile: "tests.echo", cwd: canonicalOutside }),
      /outside the profile roots/u
    );
    await assert.rejects(
      registry.resolve({ profile: "tests.echo", cwd: cwdLink }),
      /non-symlink directory|canonical/u
    );
    const linkedExecutableRegistry = new TaskProfileRegistry([profile(canonicalRoot, { executable: executableLink })]);
    await assert.rejects(
      linkedExecutableRegistry.resolve({ profile: "tests.echo", cwd: canonicalRoot }),
      /non-symlink executable|canonical/u
    );
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test("task profile documents reject secret environments, unanchored arguments, and unsafe network declarations", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-task-profile-config-"));
  try {
    const canonicalRoot = await realpath(root);
    assert.throws(() => new TaskProfileRegistry([profile(root, { environment: { API_TOKEN: "secret" } })]), /unsafe entry/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { environment: { PATH: "/tmp/untrusted" } })]), /unsafe entry/u);
  assert.throws(() => new TaskProfileRegistry([profile(root, { environment: { NODE_OPTIONS: "--require=/tmp/untrusted.js" } })]), /unsafe entry/u);
  assert.throws(() => new TaskProfileRegistry([profile(root, { environment: { PROFILE_DATA: "Bearer opaque-token-value-123456" } })]), /unsafe entry/u);
  const encoded = Buffer.from("token=ghp_123456789012345678901234", "utf8").toString("base64");
  assert.throws(() => new TaskProfileRegistry([profile(root, { environment: { PROFILE_DATA: encoded } })]), /unsafe entry/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { schemaVersion: "0.2" as never })]), /malformed/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { allowedArgumentPattern: "echo" })]), /anchored/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { allowedArgumentPattern: "^(a+)+$" })]), /unsupported construct/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { allowedArgumentPattern: "^a|b$" })]), /unsupported construct/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { allowedArgumentPattern: "^a{1,}$" })]), /invalid/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { allowedArgumentPattern: `^${"a".repeat(257)}$` })]), /invalid/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { networkPolicy: "none", networkAllowlist: ["example.com"] })]), /no-network/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { networkPolicy: "allowlist", networkAllowlist: ["https://example.com"] })]), /allowlist is malformed/u);
    assert.doesNotThrow(() => new TaskProfileRegistry([profile(root, { networkPolicy: "allowlist", networkAllowlist: ["tcp://localhost:443"] })]));
    assert.throws(() => new TaskProfileRegistry([profile(root, { networkPolicy: "allowlist", networkAllowlist: ["tcp://10.0.0.1:443"] })]), /allowlist is malformed/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { networkPolicy: "allowlist", networkAllowlist: [] })]), /must declare destinations/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { processTreePolicy: "unbounded" as never })]), /malformed/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { credentialPolicy: "broker-managed" as never })]), /malformed/u);
    const secretArgumentRegistry = new TaskProfileRegistry([
      profile(canonicalRoot, { allowedArgumentPattern: "^[a-zA-Z0-9._=-]{1,64}$" })
    ]);
    await assert.rejects(
      secretArgumentRegistry.resolve({ profile: "tests.echo", cwd: canonicalRoot, args: ["--token", "value"] }),
      /protected secret option/u
    );
    assert.throws(
      () => new TaskProfileRegistry([
        profile(root, { fixedArgs: ["--api-key=opaque-value"], allowedArgumentPattern: "^[a-zA-Z0-9._=-]{1,64}$" })
      ]),
      /protected secret option/u
    );
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("task profile boundaries reject inherited, accessor, symbolic, and sparse authority data", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-task-profile-shape-"));
  try {
    const canonicalRoot = await realpath(root);
    const base = profile(canonicalRoot);
    assert.throws(() => new TaskProfileRegistry([Object.create(base) as TaskProfile]), /malformed/u);
    const accessorProfile = { ...base } as Record<string, unknown>;
    Object.defineProperty(accessorProfile, "executable", { enumerable: true, get: () => "/bin/echo" });
    assert.throws(() => new TaskProfileRegistry([accessorProfile as unknown as TaskProfile]), /malformed/u);
    const symbolicProfile = { ...base } as Record<string, unknown>;
    Object.defineProperty(symbolicProfile, Symbol("hidden"), { value: "authority" });
    assert.throws(() => new TaskProfileRegistry([symbolicProfile as unknown as TaskProfile]), /malformed/u);
    assert.throws(() => new TaskProfileRegistry([{ ...base, unexpected: true } as TaskProfile]), /malformed/u);
    const sparseArgs = new Array<string>(1);
    assert.throws(() => new TaskProfileRegistry([profile(canonicalRoot, { fixedArgs: sparseArgs })]), /malformed/u);
    const accessorRoots = [canonicalRoot] as string[];
    Object.defineProperty(accessorRoots, "0", { enumerable: true, get: () => canonicalRoot });
    assert.throws(() => new TaskProfileRegistry([profile(canonicalRoot, { allowedCwdRoots: accessorRoots })]), /malformed/u);
    const customPrototypeArgs = ["safe"] as string[];
    Object.setPrototypeOf(customPrototypeArgs, { some: () => true });
    assert.throws(() => new TaskProfileRegistry([profile(canonicalRoot, { fixedArgs: customPrototypeArgs })]), /malformed/u);

    assert.throws(
      () => validateTaskRunArguments(Object.create({ profile: "tests.echo", cwd: canonicalRoot })),
      /malformed/u
    );
    const sparseRequestArgs = new Array<string>(1);
    assert.throws(
      () => validateTaskRunArguments({ profile: "tests.echo", cwd: canonicalRoot, args: sparseRequestArgs }),
      /malformed/u
    );
    const customPrototypeRequestArgs = ["safe"] as string[];
    Object.setPrototypeOf(customPrototypeRequestArgs, { some: () => true });
    assert.throws(
      () => validateTaskRunArguments({ profile: "tests.echo", cwd: canonicalRoot, args: customPrototypeRequestArgs }),
      /malformed/u
    );
    const registry = new TaskProfileRegistry([base]);
    await assert.rejects(
      registry.resolve(Object.create({ profile: "tests.echo", cwd: canonicalRoot })),
      /malformed/u
    );
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("task profile resolution snapshots caller arguments before asynchronous target checks", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-task-profile-snapshot-"));
  try {
    const canonicalRoot = await realpath(root);
    const registry = new TaskProfileRegistry([profile(canonicalRoot)]);
    const request = { profile: "tests.echo", cwd: canonicalRoot, args: ["hello"] };
    const resolution = registry.resolve(request);
    request.args[0] = "hello;whoami";
    const resolved = await resolution;
    assert.deepEqual(resolved.process.args, ["hello"]);
  } finally { await rm(root, { recursive: true, force: true }); }
});
