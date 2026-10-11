import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { cutoverRelease } from "./auto-deploy/cutover.mjs";

const manualScripts = ["deploy-release.zsh", "deploy-git-push-release.zsh", "deploy-codex-controller.zsh",
  "deploy-development-project-add.zsh", "deploy-v2-access-widening.zsh", "enable-terminal-connection.zsh"];
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "mop-cutover-test-"));
  const stateRoot = join(root, "state"), edgePath = join(stateRoot, "edge.json");
  mkdirSync(stateRoot, { mode: 0o700 });
  writeFileSync(join(stateRoot, "intact"), "original");
  writeFileSync(edgePath, JSON.stringify({ packageRoot: "/old", contractsDirectory: "/old/tool-contracts", sourceRevision: "b".repeat(40) }));
  return { root, stateRoot, edgePath, backup: join(root, "backup"), failedState: join(root, "failed"),
    target: "a".repeat(40), release: "/new", previous: "/old" };
}
function operations() {
  const starts = [], events = [];
  return { starts, events, stop: () => true, settle: async () => {},
    copyTree: (from, to) => cpSync(from, to, { recursive: true, errorOnExist: true, force: false }),
    start: release => { starts.push(release); return true; }, healthy: async () => true,
    save: () => true, log: event => events.push(event) };
}
function shell(root, body) {
  return spawnSync("/bin/zsh", ["-c", body], { cwd: root,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C" }, shell: false,
    timeout: 10_000, maxBuffer: 65_536, encoding: "utf8" });
}

for (const [name, snapshot, expected] of [
  ["absent service", "[]", 0],
  ["stopped service", '[{"name":"fixture","pm2_env":{"status":"stopped"}}]', 0],
  ["running service", '[{"name":"fixture","pm2_env":{"status":"online"}}]', 1],
  ["malformed service snapshot", "invalid", 1],
  ["unavailable service snapshot", undefined, 1]
]) test(`manual recovery stop confirmation handles ${name}`, () => {
  const config = fixture();
  const preload = join(config.root, "stop-fixture.cjs");
  writeFileSync(preload, `require("node:child_process").execFileSync = () => {
    ${snapshot === undefined ? 'throw new Error("unavailable");' : `return Buffer.from(${JSON.stringify(snapshot)});`}
  };\n`);
  try {
    const result = shell(config.root, `
      source ${quote(resolve("scripts/deployment-service.zsh"))}
      fixture_pm2() { return 1; }
      fixture_node() { ${quote(process.execPath)} --require ${quote(preload)} "$@"; }
      stop_deployment_service fixture_pm2 fixture_node fixture
    `);
    assert.equal(result.status, expected, result.stdout + result.stderr);
  } finally { rmSync(config.root, { recursive: true, force: true }); }
});

for (const failure of ["stop", "settle", "backup"]) test(`auto cutover recovers intact state when ${failure} fails`, async () => {
  const config = fixture(), ops = operations(config);
  if (failure === "stop") ops.stop = () => false;
  if (failure === "settle") ops.settle = async () => { throw new Error("settle failure"); };
  if (failure === "backup") ops.copyTree = (_from, to) => { mkdirSync(to); writeFileSync(join(to, "partial"), "incomplete"); throw new Error("ENOSPC"); };
  try {
    const result = await cutoverRelease(config, ops);
    assert.equal(result.ok, false);
    assert.equal(result.restored, true);
    assert.deepEqual(ops.starts, ["/old"]);
    assert.equal(readFileSync(join(config.stateRoot, "intact"), "utf8"), "original");
    assert.equal(existsSync(join(config.backup, "state")), false);
    assert.equal(existsSync(config.failedState), false);
  } finally { rmSync(config.root, { recursive: true, force: true }); }
});

test("healthy auto cutover publishes a complete rollback snapshot and persists the new release", async () => {
  const config = fixture(), ops = operations();
  let saves = 0;
  ops.save = () => { saves += 1; return true; };
  try {
    assert.deepEqual(await cutoverRelease(config, ops), { ok: true, backup: config.backup });
    assert.deepEqual(ops.starts, ["/new"]);
    assert.equal(saves, 1);
    assert.equal(JSON.parse(readFileSync(config.edgePath, "utf8")).packageRoot, "/new");
    assert.equal(JSON.parse(readFileSync(join(config.backup, "state", "edge.json"), "utf8")).packageRoot, "/old");
    assert.equal(existsSync(join(config.backup, "state.partial")), false);
    assert.equal(existsSync(config.failedState), false);
  } finally { rmSync(config.root, { recursive: true, force: true }); }
});

for (const failure of ["configuration", "startup", "health", "persistence"]) test(`auto cutover restores its completed snapshot when ${failure} throws or fails`, async () => {
  const config = fixture(), ops = operations(config);
  if (failure === "configuration") mkdirSync(`${config.edgePath}.tmp`);
  if (failure === "startup") ops.start = release => {
    ops.starts.push(release);
    if (release === "/new") { writeFileSync(join(config.stateRoot, "intact"), "mutated"); throw new Error("startup failed"); }
    return true;
  };
  if (failure === "health") ops.healthy = async edge => { if (edge.packageRoot === "/new") throw new Error("probe failed"); return true; };
  if (failure === "persistence") { let saves = 0; ops.save = () => ++saves > 1; }
  try {
    const result = await cutoverRelease(config, ops);
    assert.equal(result.ok, false);
    assert.equal(result.restored, true);
    assert.equal(ops.starts.at(-1), "/old");
    assert.equal(JSON.parse(readFileSync(config.edgePath, "utf8")).packageRoot, "/old");
    assert.equal(readFileSync(join(config.stateRoot, "intact"), "utf8"), "original");
    assert.equal(existsSync(join(config.backup, "state", "intact")), true);
  } finally { rmSync(config.root, { recursive: true, force: true }); }
});

test("auto cutover preserves live and backup state when the recovery copy fails", async () => {
  const config = fixture(), ops = operations(config);
  ops.healthy = async () => false;
  ops.copyTree = (from, to) => {
    if (from === join(config.backup, "state")) throw new Error("restore ENOSPC");
    cpSync(from, to, { recursive: true });
  };
  try {
    const result = await cutoverRelease(config, ops);
    assert.equal(result.restored, false);
    assert.match(result.recoveryError, /restore ENOSPC/u);
    assert.deepEqual(ops.starts, ["/new"]);
    assert.equal(existsSync(config.failedState), false);
    assert.equal(existsSync(join(config.stateRoot, "intact")), true);
    assert.equal(existsSync(join(config.backup, "state", "intact")), true);
  } finally { rmSync(config.root, { recursive: true, force: true }); }
});

for (const failure of ["recovery-stop", "recovery-settle", "publication", "logging"]) test(`auto cutover preserves the known state location when ${failure} fails`, async () => {
  const config = fixture(), ops = operations();
  ops.start = release => {
    ops.starts.push(release);
    if (release === "/new") writeFileSync(join(config.stateRoot, "intact"), "mutated");
    return true;
  };
  ops.healthy = async edge => edge.packageRoot !== "/new";
  if (failure === "recovery-stop") { let stops = 0; ops.stop = () => ++stops === 1; }
  if (failure === "recovery-settle") {
    let settles = 0;
    ops.settle = async () => { if (++settles > 1) throw new Error("recovery settle failed"); };
  }
  if (failure === "publication") ops.renameState = (from, to) => {
    if (from.includes(".restore-")) throw new Error("publish failed");
    renameSync(from, to);
  };
  if (failure === "logging") ops.log = () => { throw new Error("log failed"); };
  try {
    const result = await cutoverRelease(config, ops);
    assert.equal(result.ok, false);
    assert.equal(result.restored, failure === "logging");
    assert.equal(readFileSync(join(config.stateRoot, "intact"), "utf8"), failure === "logging" ? "original" : "mutated");
    assert.equal(existsSync(config.failedState), failure === "logging");
    assert.equal(readFileSync(join(config.backup, "state", "intact"), "utf8"), "original");
    assert.equal(ops.starts.includes("/old"), failure === "logging");
  } finally { rmSync(config.root, { recursive: true, force: true }); }
});

for (const file of manualScripts) {
  const source = readFileSync(resolve("scripts", file), "utf8");
  const rollback = source.slice(source.indexOf("rollback() {"), source.indexOf("\ntrap rollback ERR"));
  for (const failure of ["backup", "migration", "restore", "recovery-stop", "publication"]) test(`${file} preserves complete state after ${failure} failure`, () => {
    const config = fixture();
    mkdirSync(config.backup);
    const prior = join(config.root, "prior-edge.json");
    cpSync(config.edgePath, prior);
    const copyFailure = failure === "backup" ? `
      cp() { if [[ "$3" == "$BACKUP/state.partial" ]]; then mkdir "$3"; print incomplete > "$3/partial"; return 42; fi; command cp "$@"; }
    ` : failure === "restore" ? `
      cp() { if [[ "$3" == "$STATE.restore-test" ]]; then return 42; fi; command cp "$@"; }
    ` : failure === "publication" ? `
      mv() { if [[ "$1" == "$STATE.restore-test" ]]; then return 42; fi; command mv "$@"; }
    ` : "";
    const body = `set -euo pipefail
      source ${quote(resolve("scripts/deployment-state.zsh"))}
      source ${quote(resolve("scripts/deployment-service.zsh"))}
      STATE=${quote(config.stateRoot)}; EDGE=${quote(config.edgePath)}; BACKUP=${quote(config.backup)}
      PRIOR_EDGE=${quote(prior)}; STAMP=test; SERVICE=fixture; REL=/new; PREVIOUS=/old
      STOPPED=1; BACKUP_COMPLETE=0; PM2=fixture_pm2; NODE=fixture_node
      fixture_pm2() { return ${failure === "recovery-stop" ? 1 : 0}; }
      fixture_node() { return 1; }; sleep() { return 0; }
      start_service() { print -r -- "$1" > ${quote(join(config.root, "started"))}; }
      ${copyFailure}
      ${rollback}
      trap rollback ERR
      backup_protected_state "$STATE" "$BACKUP"
      BACKUP_COMPLETE=1
      print mutated > "$STATE/intact"
      false
    `;
    try {
      const result = shell(config.root, body);
      assert.notEqual(result.status, 0, result.stdout + result.stderr);
      if (["restore", "recovery-stop", "publication"].includes(failure)) {
        assert.equal(readFileSync(join(config.stateRoot, "intact"), "utf8").trim(), "mutated");
        assert.equal(existsSync(join(config.root, "started")), false);
      } else {
        assert.equal(readFileSync(join(config.stateRoot, "intact"), "utf8"), "original");
        assert.equal(readFileSync(join(config.root, "started"), "utf8").trim(), file === "enable-terminal-connection.zsh" ? "/new" : "/old");
      }
      assert.equal(existsSync(`${config.stateRoot}.failed-test`), failure === "migration");
      assert.equal(existsSync(join(config.backup, "state")), failure !== "backup");
      assert.equal(statSync(config.stateRoot).mode & 0o777, 0o700);
    } finally { rmSync(config.root, { recursive: true, force: true }); }
  });

  if (file === "enable-terminal-connection.zsh") continue;
  test(`${file} rejects an unhealthy final restart before saving or reporting success`, () => {
    const config = fixture();
    const finalStage = source.slice(source.indexOf('echo "8/8 restart once more:'));
    const body = `set -euo pipefail
      PM2=fixture_pm2; SERVICE=fixture; REV=test; REL=/new; BACKUP=/backup
      fixture_pm2() { [[ "$1" != save ]] || print save > ${quote(join(config.root, "saved"))}; }
      healthy() { return 9; }; config_ok() { return 0; }; push_enabled() { return 0; }; policy_ok() { return 0; }; scopes_ok() { return 0; }
      rollback() { rc=$?; print failed > ${quote(join(config.root, "rolled-back"))}; exit $rc; }
      trap rollback ERR
      ${finalStage}
    `;
    try {
      const result = shell(config.root, body);
      assert.equal(result.status, 9, result.stdout + result.stderr);
      assert.equal(existsSync(join(config.root, "rolled-back")), true);
      assert.equal(existsSync(join(config.root, "saved")), false);
      assert.doesNotMatch(result.stdout, /OK:/u);
    } finally { rmSync(config.root, { recursive: true, force: true }); }
  });

  for (const restartCount of [1, 2]) test(`${file} ${restartCount === 1 ? "accepts the expected" : "rejects an additional automatic"} final restart`, () => {
    const config = fixture();
    const finalStage = source.slice(source.indexOf('echo "8/8 restart once more:'));
    const healthy = source.match(/healthy\(\) \{[\s\S]*?\n\}/u)[0];
    const preload = join(config.root, "healthy-fixture.cjs");
    writeFileSync(preload, `global.fetch = async () => ({ status: 401 });
      global.setTimeout = callback => { queueMicrotask(callback); return 0; };
      require("node:child_process").execFileSync = () => Buffer.from(${JSON.stringify(JSON.stringify([
        { name: "fixture", pm2_env: { status: "online", restart_time: restartCount } }
      ]))});\n`);
    const body = `set -euo pipefail
      EDGE=${quote(config.edgePath)}; PM2=fixture_pm2; NODE=fixture_node; SERVICE=fixture; REV=test; REL=/new; BACKUP=/backup
      fixture_node() { ${quote(process.execPath)} --require ${quote(preload)} "$@"; }
      fixture_pm2() { [[ "$1" != save ]] || print save > ${quote(join(config.root, "saved"))}; }
      sleep() { return 0; }; config_ok() { return 0; }; push_enabled() { return 0; }; policy_ok() { return 0; }; scopes_ok() { return 0; }
      ${healthy}
      rollback() { rc=$?; print failed > ${quote(join(config.root, "rolled-back"))}; exit $rc; }
      trap rollback ERR
      ${finalStage}
    `;
    try {
      const result = shell(config.root, body);
      assert.equal(result.status, restartCount === 1 ? 0 : 1, result.stdout + result.stderr);
      assert.equal(existsSync(join(config.root, "saved")), restartCount === 1);
      assert.equal(existsSync(join(config.root, "rolled-back")), restartCount === 2);
      if (restartCount === 1) assert.match(result.stdout, /OK:/u);
      else assert.doesNotMatch(result.stdout, /OK:/u);
    } finally { rmSync(config.root, { recursive: true, force: true }); }
  });
}
