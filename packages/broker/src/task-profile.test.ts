import assert from "node:assert/strict";
import { mkdtemp, mkdir, realpath, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { TaskProfileRegistry, type TaskProfile } from "./task-profile.js";

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
      args: ["hello", "world"],
      cwd: canonicalRoot,
      environment: { LANG: "C" },
      timeoutMs: 1_000,
      outputCapBytes: 1_024
    });
    assert.deepEqual(resolved.filesystemRoots, [canonicalRoot]);
    assert.equal(resolved.networkPolicy, "none");
    assert.deepEqual(resolved.networkAllowlist, []);
    assert.equal(resolved.processTreePolicy, "single_process");
    assert.equal(resolved.sandboxProfile, "deny-default-v0.1");
  } finally { await rm(root, { recursive: true, force: true }); }
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
    assert.throws(() => new TaskProfileRegistry([profile(root, { environment: { API_TOKEN: "secret" } })]), /unsafe entry/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { environment: { PATH: "/tmp/untrusted" } })]), /unsafe entry/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { environment: { NODE_OPTIONS: "--require=/tmp/untrusted.js" } })]), /unsafe entry/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { schemaVersion: "0.2" as never })]), /malformed/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { allowedArgumentPattern: "echo" })]), /anchored/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { networkPolicy: "none", networkAllowlist: ["example.com"] })]), /no-network/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { networkPolicy: "allowlist", networkAllowlist: ["https://example.com"] })]), /allowlist is malformed/u);
    assert.doesNotThrow(() => new TaskProfileRegistry([profile(root, { networkPolicy: "allowlist", networkAllowlist: ["tcp://localhost:443"] })]));
    assert.throws(() => new TaskProfileRegistry([profile(root, { networkPolicy: "allowlist", networkAllowlist: ["tcp://10.0.0.1:443"] })]), /allowlist is malformed/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { networkPolicy: "allowlist", networkAllowlist: [] })]), /must declare destinations/u);
    assert.throws(() => new TaskProfileRegistry([profile(root, { processTreePolicy: "unbounded" as never })]), /malformed/u);
  } finally { await rm(root, { recursive: true, force: true }); }
});
