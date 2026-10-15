import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { acquireDeploymentLock } from "./auto-deploy/lock.mjs";
import {
  PM2_RESTART_POLICY, classifyRelation, decideAction, isHealthy, isRuntimeRelevant, parseFailedTestFiles, parsePm2Service, patchEdgeConfig, pm2Ecosystem,
  releaseName, selectPrunable
} from "./auto-deploy/lib.mjs";

const REV = "a".repeat(40);

function lockFixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mop-auto-lock-")));
  return { root, path: join(root, "lock"), cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

for (const aged of [false, true]) {
  test(`auto-deploy ${aged ? "recovers an old" : "preserves a fresh"} unpublished lock`, () => {
    const f = lockFixture();
    let release;
    try {
      mkdirSync(f.path, { mode: 0o700 });
      if (aged) { const old = new Date(Date.now() - 60_000); utimesSync(f.path, old, old); }
      release = acquireDeploymentLock(f.path);
      if (aged) {
        assert.equal(typeof release, "function");
        assert.equal(readFileSync(join(f.path, "pid"), "utf8"), String(process.pid));
      } else assert.equal(release, null);
    } finally { release?.(); f.cleanup(); }
  });
}

test("auto-deploy excludes another owner and releases only its own generation", () => {
  const f = lockFixture();
  let first;
  let second;
  try {
    first = acquireDeploymentLock(f.path);
    assert.equal(typeof first, "function");
    assert.equal(acquireDeploymentLock(f.path), null);
    first();
    second = acquireDeploymentLock(f.path);
    assert.equal(typeof second, "function");
    first();
    assert.equal(acquireDeploymentLock(f.path), null, "an old release must not unlock its successor");
  } finally { second?.(); f.cleanup(); }
});

test("auto-deploy reclaims a dead legacy PID but preserves a live legacy owner", () => {
  const f = lockFixture();
  let release;
  try {
    mkdirSync(f.path, { mode: 0o700 });
    writeFileSync(join(f.path, "pid"), String(process.pid));
    assert.equal(acquireDeploymentLock(f.path), null);
    writeFileSync(join(f.path, "pid"), "2147483647");
    release = acquireDeploymentLock(f.path);
    assert.equal(typeof release, "function");
    assert.equal(statSync(f.path).mode & 0o777, 0o700);
  } finally { release?.(); f.cleanup(); }
});

test("auto-deploy preserves malformed or unexpected lock evidence", () => {
  const f = lockFixture();
  try {
    mkdirSync(f.path, { mode: 0o700 });
    writeFileSync(join(f.path, "pid"), "not-a-pid");
    assert.throws(() => acquireDeploymentLock(f.path), /invalid|malformed/u);
    assert.equal(readFileSync(join(f.path, "pid"), "utf8"), "not-a-pid");
    writeFileSync(join(f.path, "pid"), "2147483647");
    writeFileSync(join(f.path, "unexpected"), "preserve");
    assert.throws(() => acquireDeploymentLock(f.path), /unexpected evidence/u);
    assert.equal(readFileSync(join(f.path, "unexpected"), "utf8"), "preserve");
  } finally { f.cleanup(); }
});

test("auto-deploy release preserves a replacement lock directory and frees its kernel lock", () => {
  const f = lockFixture();
  const release = acquireDeploymentLock(f.path);
  try {
    renameSync(f.path, join(f.root, "original"));
    mkdirSync(f.path, { mode: 0o700 });
    writeFileSync(join(f.path, "pid"), String(process.pid));
    assert.throws(release, /ownership|changed/u);
    assert.equal(readFileSync(join(f.path, "pid"), "utf8"), String(process.pid));
    rmSync(f.path, { recursive: true });
    const next = acquireDeploymentLock(f.path);
    assert.equal(typeof next, "function");
    next();
  } finally { f.cleanup(); }
});

test("auto-deploy recovers the kernel lock after its actual owner is killed", () => {
  const f = lockFixture();
  let release;
  try {
    const source = `import { acquireDeploymentLock } from ${JSON.stringify(new URL("./auto-deploy/lock.mjs", import.meta.url).href)};
      if (!acquireDeploymentLock(process.argv[1])) throw new Error("Child could not acquire lock");
      process.kill(process.pid, "SIGKILL");`;
    assert.throws(() => execFileSync(process.execPath, ["--input-type=module", "--eval", source, f.path], {
      cwd: f.root, env: { PATH: "/usr/bin:/bin" }, shell: false, timeout: 5_000, maxBuffer: 8_192, stdio: "pipe"
    }), (error) => error.signal === "SIGKILL");
    release = acquireDeploymentLock(f.path);
    assert.equal(typeof release, "function");
  } finally { release?.(); f.cleanup(); }
});

test("auto-deploy reclaims a complete dead PID published before temporary-link cleanup", () => {
  const f = lockFixture();
  let release;
  try {
    mkdirSync(f.path, { mode: 0o700 });
    const retained = join(f.root, ".auto-deploy-pid-crash");
    writeFileSync(retained, "2147483647", { mode: 0o600 });
    linkSync(retained, join(f.path, "pid"));
    release = acquireDeploymentLock(f.path);
    assert.equal(typeof release, "function");
    assert.equal(readFileSync(retained, "utf8"), "2147483647");
  } finally { release?.(); f.cleanup(); }
});

test("auto-deploy refuses a redirected kernel lock without changing its target", () => {
  const f = lockFixture();
  try {
    const target = join(f.root, "unrelated");
    writeFileSync(target, "preserve", { mode: 0o600 });
    symlinkSync(target, `${f.path}.sqlite`);
    assert.throws(() => acquireDeploymentLock(f.path), /protected regular file/u);
    assert.equal(readFileSync(target, "utf8"), "preserve");
  } finally { f.cleanup(); }
});

test("patchEdgeConfig rebinds exactly packageRoot, contractsDirectory and sourceRevision", () => {
  const before = { packageRoot: "/old", contractsDirectory: "/old/tool-contracts", sourceRevision: "b".repeat(40), bindPort: 3443, oauthScopes: ["x"] };
  const after = patchEdgeConfig(before, { packageRoot: "/new", sourceRevision: REV });
  assert.deepEqual(after, { ...before, packageRoot: "/new", contractsDirectory: "/new/tool-contracts", sourceRevision: REV });
  assert.equal(before.packageRoot, "/old");
  assert.throws(() => patchEdgeConfig(before, { packageRoot: "relative", sourceRevision: REV }));
  assert.throws(() => patchEdgeConfig(before, { packageRoot: "/new", sourceRevision: "abc123" }));
});

test("isRuntimeRelevant ignores docs, tests and tooling but not runtime sources, contracts or dependencies", () => {
  for (const path of ["PROGRESS.md", "evidence/x.md", "docs/a.md", "packages/broker/src/a.test.ts", "scripts/auto-deploy/run.mjs", "scripts/x.test.mjs",
    "packages/broker/src/fixtures/y.ts"]) assert.equal(isRuntimeRelevant(path), false, path);
  for (const path of ["packages/broker/src/broker.ts", "packages/broker/native/gui_vision.m", "tool-contracts/mac_health.json", "schemas/policy-document.schema.json",
    "package-lock.json", "package.json", "runtime/x.json", "packaging/macos/y.plist.in"]) assert.equal(isRuntimeRelevant(path), true, path);
});

test("classifyRelation distinguishes same, behind, ahead, diverged and unknown", () => {
  assert.equal(classifyRelation({ currentKnown: false, currentIsAncestor: false, targetIsAncestor: false }), "unknown");
  assert.equal(classifyRelation({ currentKnown: true, currentIsAncestor: true, targetIsAncestor: true }), "same");
  assert.equal(classifyRelation({ currentKnown: true, currentIsAncestor: true, targetIsAncestor: false }), "behind");
  assert.equal(classifyRelation({ currentKnown: true, currentIsAncestor: false, targetIsAncestor: true }), "ahead");
  assert.equal(classifyRelation({ currentKnown: true, currentIsAncestor: false, targetIsAncestor: false }), "diverged");
});

test("decideAction deploys only forward runtime changes and never downgrades or merges", () => {
  assert.equal(decideAction({ relation: "same", changedPaths: [] }).action, "none");
  assert.equal(decideAction({ relation: "ahead", changedPaths: [] }).action, "none");
  assert.equal(decideAction({ relation: "unknown", changedPaths: [] }).action, "manual");
  assert.equal(decideAction({ relation: "diverged", changedPaths: ["packages/broker/src/a.ts"] }).action, "manual");
  assert.equal(decideAction({ relation: "behind", changedPaths: ["README.md", "packages/broker/src/a.test.ts"] }).action, "skip");
  assert.equal(decideAction({ relation: "behind", changedPaths: ["README.md", "packages/broker/src/a.ts"] }).action, "deploy");
});

test("releaseName and selectPrunable only touch auto-named releases and keep the live and rollback releases", () => {
  assert.equal(releaseName(new Date(2026, 9, 5), REV), "personal-20261005-aaaaaaa");
  const entries = [
    { name: "personal-20261001-1111111", path: "/r/1", mtimeMs: 1 }, { name: "personal-20261002-2222222", path: "/r/2", mtimeMs: 2 },
    { name: "personal-20261003-3333333", path: "/r/3", mtimeMs: 3 }, { name: "personal-20261004-4444444", path: "/r/4", mtimeMs: 4 },
    { name: "personal-20261002-gui-window-c", path: "/r/hand", mtimeMs: 0 }, { name: ".tmp-personal-20261005-5555555", path: "/r/tmp", mtimeMs: 0 }
  ];
  assert.deepEqual(selectPrunable(entries, 2, ["/r/1"]).map((entry) => entry.path), ["/r/2"]);
  assert.deepEqual(selectPrunable(entries, 10, []), []);
});

test("parseFailedTestFiles lists each failing file once", () => {
  const log = "test at packages/broker/dist/a.test.js:84:1\nnoise\ntest at packages/broker/dist/a.test.js:90:1\ntest at scripts/b.test.mjs:5:1\n";
  assert.deepEqual(parseFailedTestFiles(log), ["packages/broker/dist/a.test.js", "scripts/b.test.mjs"]);
  assert.deepEqual(parseFailedTestFiles("all good"), []);
});

test("parsePm2Service and isHealthy require an online, never-restarted service whose endpoints still answer 401", () => {
  const jlist = JSON.stringify([{ name: "other" }, { name: "svc", pm2_env: { status: "online", restart_time: 0, pm_uptime: Date.now() - 5000, pm_exec_path: "/n", pm_cwd: "/c", args: ["a", "/state"] } }]);
  const service = parsePm2Service(jlist, "svc");
  assert.equal(service.status, "online");
  assert.deepEqual(service.args, ["a", "/state"]);
  assert.equal(parsePm2Service(jlist, "missing"), undefined);
  assert.equal(isHealthy({ service, statuses: [401, 401] }), true);
  assert.equal(isHealthy({ service, statuses: [401, 502] }), false);
  assert.equal(isHealthy({ service, statuses: [] }), false);
  assert.equal(isHealthy({ service: { ...service, restarts: 1 }, statuses: [401] }), false);
  assert.equal(isHealthy({ service: { ...service, status: "errored" }, statuses: [401] }), false);
  assert.equal(isHealthy({ service: undefined, statuses: [401] }), false);
});

test("pm2Ecosystem binds the service to absolute paths and a restart policy that actually bounds a fail-closed loop", () => {
  const document = pm2Ecosystem({ name: "svc", execPath: "/opt/homebrew/bin/node", release: "/r/release", stateRoot: "/r/state" });
  assert.deepEqual(document, { apps: [{
    name: "svc", script: "/opt/homebrew/bin/node", args: ["/r/release/packages/auth/dist/personal-service.js", "start", "/r/state"],
    cwd: "/r/release", interpreter: "none", kill_timeout: 15000, max_restarts: 60, restart_delay: 5000, min_uptime: 30000
  }] });
  // PM2 counts a restart against max_restarts only when the process died before min_uptime. The fail-closed startup
  // lives a few seconds, so min_uptime must stay well above PM2's 1000 ms default or the bound never applies.
  assert.ok(PM2_RESTART_POLICY.min_uptime >= 10_000);
  assert.ok(Number.isInteger(PM2_RESTART_POLICY.max_restarts) && PM2_RESTART_POLICY.max_restarts > 3);
  // Retry window must outlast a reboot where the Container Engine is slow to come up (about 8 minutes) yet stay finite.
  const windowMs = PM2_RESTART_POLICY.max_restarts * PM2_RESTART_POLICY.restart_delay;
  assert.ok(windowMs >= 5 * 60_000 && windowMs <= 30 * 60_000);
  assert.throws(() => pm2Ecosystem({ name: "svc", execPath: "node", release: "/r", stateRoot: "/s" }), /absolute/u);
  assert.throws(() => pm2Ecosystem({ name: "svc", execPath: "/n", release: "r", stateRoot: "/s" }), /absolute/u);
  assert.throws(() => pm2Ecosystem({ name: "svc", execPath: "/n", release: "/r", stateRoot: undefined }), /absolute/u);
  assert.throws(() => { PM2_RESTART_POLICY.max_restarts = 1; });
});
