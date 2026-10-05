import assert from "node:assert/strict";
import test from "node:test";
import {
  classifyRelation, decideAction, isHealthy, isRuntimeRelevant, parseFailedTestFiles, parsePm2Service, patchEdgeConfig, releaseName, selectPrunable
} from "./auto-deploy/lib.mjs";

const REV = "a".repeat(40);

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
