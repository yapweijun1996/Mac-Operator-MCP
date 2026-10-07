#!/usr/bin/env node
// Polling auto-deploy for the personal Mac Operator service on this machine.
//
// Safety model: the agent only pulls (no inbound port), only fast-forwards to origin/main, never downgrades, never
// re-signs the policy, and rolls the full protected state back when the new release is not healthy.
import { execFileSync, spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { preflightState } from "./preflight.mjs";
import { setTimeout as delay } from "node:timers/promises";
import {
  classifyRelation, decideAction, isHealthy, parseFailedTestFiles, parsePm2Service, patchEdgeConfig, releaseName, selectPrunable
} from "./lib.mjs";

const HOME = homedir();
const MAC_ROOT = join(HOME, "Library/Application Support/MacOperator");
const ROOT = join(MAC_ROOT, "auto-deploy");
const CHECKOUT = join(ROOT, "checkout");
const LOGS = join(ROOT, "logs");
const PAUSE_FILE = join(ROOT, "PAUSE");
const LOCK_DIR = join(ROOT, "lock");
const STATE_FILE = join(ROOT, "state.json");
const LABEL = "com.yapweijun.mac-operator-autodeploy";
const PLIST = join(HOME, "Library/LaunchAgents", `${LABEL}.plist`);
const SERVICE = "mac-operator-personal";
const REPO_URL = process.env.MOP_AUTODEPLOY_REPO ?? "https://github.com/yapweijun1996/Mac-Operator-MCP.git";
const KEEP_RELEASES = 5;
const POLL_SECONDS = 300;
const PM2_FLAGS = ["--interpreter", "none", "--kill-timeout", "15000", "--max-restarts", "3", "--restart-delay", "5000"];
const PATH_ENV = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
const env = { ...process.env, PATH: PATH_ENV, HOME };

const log = (event, detail = {}) => {
  const line = JSON.stringify({ at: new Date().toISOString(), event, ...detail });
  console.log(line);
  try { mkdirSync(LOGS, { recursive: true }); appendFileSync(join(LOGS, "events.jsonl"), `${line}\n`); } catch { /* console copy remains */ }
};
const notify = (title, message) => {
  log("notify", { title, message });
  spawnSync("/usr/bin/osascript", ["-e", `display notification ${JSON.stringify(message)} with title ${JSON.stringify(title)}`], { env, timeout: 10_000 });
};
const run = (file, args, options = {}) => {
  const result = spawnSync(file, args, { env, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...options });
  return { ok: result.status === 0, status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
};
const git = (args, cwd = CHECKOUT) => run("/usr/bin/git", args, { cwd, timeout: 600_000 });
const readState = () => { try { return JSON.parse(readFileSync(STATE_FILE, "utf8")); } catch { return {}; } };
const writeState = (state) => writeFileSync(STATE_FILE, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });

function service() {
  const result = run("pm2", ["jlist"], { timeout: 30_000 });
  return result.ok ? parsePm2Service(result.stdout.slice(result.stdout.indexOf("[")), SERVICE) : undefined;
}

function acquireLock() {
  mkdirSync(ROOT, { recursive: true, mode: 0o700 });
  try { mkdirSync(LOCK_DIR); } catch {
    const holder = Number(readFileSync(join(LOCK_DIR, "pid"), "utf8").trim());
    let alive = true;
    try { process.kill(holder, 0); } catch { alive = false; }
    if (alive) return false;
    rmSync(LOCK_DIR, { recursive: true, force: true });
    mkdirSync(LOCK_DIR);
  }
  writeFileSync(join(LOCK_DIR, "pid"), String(process.pid));
  return true;
}

/** Queued or running Jobs mean a restart could interrupt work, so the cutover waits for the next poll. */
function activeJobs(stateRoot) {
  const database = new DatabaseSync(join(stateRoot, "personal/broker.sqlite"), { readOnly: true });
  try { return database.prepare("SELECT COUNT(*) AS n FROM jobs WHERE state IN ('queued', 'running')").get().n; } finally { database.close(); }
}

function ensureCheckout() {
  if (!existsSync(join(CHECKOUT, ".git"))) {
    const cloned = run("/usr/bin/git", ["clone", "--quiet", REPO_URL, CHECKOUT], { timeout: 600_000 });
    if (!cloned.ok) throw new Error(`clone failed: ${cloned.stderr.trim().slice(0, 300)}`);
  }
  git(["remote", "set-url", "origin", REPO_URL]);
  const fetched = git(["fetch", "--quiet", "origin", "main"]);
  if (!fetched.ok) throw new Error(`fetch failed: ${fetched.stderr.trim().slice(0, 300)}`);
}

function relation(current, target) {
  const known = git(["cat-file", "-e", `${current}^{commit}`]).ok;
  return classifyRelation({
    currentKnown: known,
    currentIsAncestor: known && git(["merge-base", "--is-ancestor", current, target]).ok,
    targetIsAncestor: known && git(["merge-base", "--is-ancestor", target, current]).ok
  });
}

/** Builds and tests the target in the dedicated checkout; a failed file is rerun alone so load flakes do not block a deploy. */
function buildAndTest(target, short) {
  for (const step of [["checkout", ["checkout", "--quiet", "--detach", "--force", target]], ["clean", ["clean", "-fdxq"]]]) {
    if (!git(step[1]).ok) return { ok: false, why: `git ${step[0]} failed` };
  }
  const install = run("npm", ["ci", "--no-audit", "--no-fund"], { cwd: CHECKOUT, timeout: 1_200_000 });
  if (!install.ok) return { ok: false, why: "npm ci failed", detail: install.stderr.slice(-600) };
  const logPath = join(LOGS, `test-${short}.log`);
  const tested = run("nice", ["-n", "10", "npm", "test"], { cwd: CHECKOUT, timeout: 1_800_000 });
  writeFileSync(logPath, tested.stdout + tested.stderr);
  if (tested.ok) return { ok: true, flaky: [] };
  const failed = parseFailedTestFiles(tested.stdout + tested.stderr);
  if (failed.length === 0) return { ok: false, why: "npm test failed without a parsable test file", detail: logPath };
  const stillFailing = failed.filter((file) => !run("node", ["--test", "--test-timeout=120000", file], { cwd: CHECKOUT, timeout: 900_000 }).ok);
  return stillFailing.length === 0 ? { ok: true, flaky: failed } : { ok: false, why: `tests failed in isolation: ${stillFailing.join(", ")}`, detail: logPath };
}

function stageRelease(target, name) {
  const releases = join(MAC_ROOT, "releases");
  const finalDir = join(releases, name);
  const temp = join(releases, `.tmp-${name}`);
  rmSync(temp, { recursive: true, force: true });
  mkdirSync(temp, { mode: 0o700 });
  const copied = run("rsync", ["-a", "--exclude", ".git", "--exclude", "*.log", `${CHECKOUT}/`, `${temp}/`], { timeout: 600_000 });
  if (!copied.ok) throw new Error("rsync of the release failed");
  writeFileSync(join(temp, "SOURCE-REVISION"), `${target}\n`);
  rmSync(finalDir, { recursive: true, force: true });
  renameSync(temp, finalDir);
  return finalDir;
}

/**
 * `cp -Rp` keeps owner-only modes. Node's cpSync creates directories as 0755, which the service rejects as a
 * non-private state root, so it must not be used for protected state.
 */
function copyTree(from, to) {
  const copied = run("/bin/cp", ["-Rp", from, to], { timeout: 600_000 });
  if (!copied.ok) throw new Error(`state copy failed: ${copied.stderr.trim().slice(0, 200)}`);
}

function startService(release, stateRoot, execPath) {
  run("pm2", ["delete", SERVICE], { timeout: 30_000 });
  return run("pm2", ["start", execPath, "--name", SERVICE, ...PM2_FLAGS, "--cwd", release, "--", `${release}/packages/auth/dist/personal-service.js`, "start", stateRoot],
    { cwd: release, timeout: 60_000 }).ok;
}

let forcedUnhealthyUsed = false;
async function healthy(edge) {
  // Test-only switch to rehearse the rollback path once against the real service; unset in normal operation.
  if (process.env.MOP_AUTODEPLOY_TEST_UNHEALTHY_ONCE === "1" && !forcedUnhealthyUsed) { forcedUnhealthyUsed = true; return false; }
  const urls = [edge.resourceServerUrl];
  if (edge.ownerTerminalConnection === true) urls.push(new URL("/terminal/mcp", edge.resourceServerUrl).toString());
  await delay(25_000);
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const statuses = [];
    for (const url of urls) {
      try { statuses.push((await fetch(url, { method: "POST", signal: AbortSignal.timeout(10_000) })).status); } catch { statuses.push(0); }
    }
    if (isHealthy({ service: service(), statuses })) return true;
    await delay(10_000);
  }
  return false;
}

async function cutover({ target, short, release, stateRoot, edgePath, previous }) {
  const stamp = new Date().toISOString().replace(/[-:]/gu, "").slice(0, 15);
  const backup = join(MAC_ROOT, "backups", `auto-${stamp}-${short}`);
  const execPath = service()?.execPath ?? "/opt/homebrew/bin/node";
  run("pm2", ["stop", SERVICE], { timeout: 60_000 });
  await delay(4_000);
  mkdirSync(backup, { recursive: true, mode: 0o700 });
  copyTree(stateRoot, join(backup, "state"));
  const priorEdge = JSON.parse(readFileSync(edgePath, "utf8"));
  const patched = patchEdgeConfig(priorEdge, { packageRoot: release, sourceRevision: target });
  writeFileSync(`${edgePath}.tmp`, `${JSON.stringify(patched, null, 2)}\n`, { mode: 0o600 });
  renameSync(`${edgePath}.tmp`, edgePath);
  const ok = startService(release, stateRoot, execPath) && await healthy(patched);
  if (ok) { run("pm2", ["save"], { timeout: 30_000 }); return { ok: true, backup }; }
  log("rollback-start", { backup });
  run("pm2", ["delete", SERVICE], { timeout: 30_000 });
  const failedState = join(MAC_ROOT, "backups", `auto-failed-${stamp}-${short}`);
  renameSync(stateRoot, failedState);
  copyTree(join(backup, "state"), stateRoot);
  const restored = startService(previous, stateRoot, execPath) && await healthy(priorEdge);
  if (restored) run("pm2", ["save"], { timeout: 30_000 });
  return { ok: false, restored, backup, failedState };
}

function prune(keepPaths) {
  const releases = join(MAC_ROOT, "releases");
  const entries = readdirSync(releases).map((name) => ({ name, path: join(releases, name), mtimeMs: statSync(join(releases, name)).mtimeMs }));
  for (const entry of selectPrunable(entries, KEEP_RELEASES, keepPaths)) { rmSync(entry.path, { recursive: true, force: true }); log("pruned-release", { name: entry.name }); }
  const backups = join(MAC_ROOT, "backups");
  const autos = readdirSync(backups).filter((name) => /^auto-\d/u.test(name)).map((name) => ({ name, mtimeMs: statSync(join(backups, name)).mtimeMs }))
    .sort((a, b) => b.mtimeMs - a.mtimeMs).slice(KEEP_RELEASES);
  for (const entry of autos) { rmSync(join(backups, entry.name), { recursive: true, force: true }); log("pruned-backup", { name: entry.name }); }
}

async function once({ dryRun }) {
  if (existsSync(PAUSE_FILE)) return log("paused", { file: PAUSE_FILE });
  if (!acquireLock()) return log("busy", { reason: "another run holds the lock" });
  try {
    const live = service();
    if (live === undefined || live.status !== "online") return notify("Auto-deploy skipped", `${SERVICE} is not online; fix it by hand first`);
    const stateRoot = live.args.at(-1);
    const edgePath = join(stateRoot, "personal/edge-service.json");
    const edge = JSON.parse(readFileSync(edgePath, "utf8"));
    ensureCheckout();
    const target = git(["rev-parse", "origin/main"]).stdout.trim();
    const short = target.slice(0, 7);
    const rel = relation(edge.sourceRevision, target);
    const changed = rel === "behind" ? git(["diff", "--name-only", edge.sourceRevision, target]).stdout.split("\n").filter(Boolean) : [];
    const decision = decideAction({ relation: rel, changedPaths: changed });
    const state = readState();
    log("checked", { live: edge.sourceRevision, target, relation: rel, ...decision, dryRun });
    if (decision.action === "none") return;
    if (decision.action !== "deploy") {
      if (state.handled !== target) { writeState({ ...state, handled: target }); notify(`Auto-deploy ${decision.action}`, `${short}: ${decision.reason}`); }
      return;
    }
    if (dryRun) return log("dry-run", { wouldDeploy: target });
    if (state.failed === target) return log("skip-failed", { target, reason: "this revision failed before; push a new commit" });
    const name = releaseName(new Date(), target);
    const built = buildAndTest(target, short);
    if (!built.ok) { writeState({ ...state, failed: target }); return notify("Auto-deploy blocked", `${short}: ${built.why}`); }
    // The new build must open a private copy of the live state before the running service is touched.
    const preflight = preflightState({ packageRoot: CHECKOUT, stateRoot, nodePath: live.execPath ?? process.execPath });
    if (!preflight.ok) {
      writeState({ ...state, failed: target });
      log("preflight-failed", { target, why: preflight.why });
      return notify("Auto-deploy blocked", `${short}: new build cannot open the live state (${preflight.why})`);
    }
    const release = stageRelease(target, name);
    const jobs = activeJobs(stateRoot);
    if (jobs > 0) return log("deferred", { target, activeJobs: jobs, release });
    const previous = edge.packageRoot;
    const outcome = await cutover({ target, short, release, stateRoot, edgePath, previous });
    if (outcome.ok) {
      writeState({ ...state, deployed: target, failed: undefined });
      prune([release, previous]);
      notify("Auto-deploy succeeded", `${short} is live${built.flaky.length > 0 ? ` (flaky tests passed alone: ${built.flaky.length})` : ""}`);
    } else {
      writeState({ ...state, failed: target });
      notify("Auto-deploy ROLLED BACK", `${short} was unhealthy; previous release ${outcome.restored ? "restored" : "COULD NOT BE RESTORED - check pm2"}`);
    }
  } finally { rmSync(LOCK_DIR, { recursive: true, force: true }); }
}

function install() {
  mkdirSync(LOGS, { recursive: true, mode: 0o700 });
  ensureCheckout();
  const script = join(CHECKOUT, "scripts/auto-deploy/run.mjs");
  const node = execFileSync("which", ["node"], { env, encoding: "utf8" }).trim();
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key><array><string>${node}</string><string>${script}</string><string>once</string></array>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>${PATH_ENV}</string></dict>
  <key>StartInterval</key><integer>${POLL_SECONDS}</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>${join(LOGS, "launchd.out.log")}</string>
  <key>StandardErrorPath</key><string>${join(LOGS, "launchd.err.log")}</string>
</dict>
</plist>
`;
  writeFileSync(PLIST, plist, { mode: 0o644 });
  const uid = String(process.getuid());
  run("launchctl", ["bootout", `gui/${uid}/${LABEL}`]);
  const loaded = run("launchctl", ["bootstrap", `gui/${uid}`, PLIST]);
  log("installed", { plist: PLIST, intervalSeconds: POLL_SECONDS, loaded: loaded.ok, stderr: loaded.stderr.trim() });
}

function uninstall() {
  run("launchctl", ["bootout", `gui/${process.getuid()}/${LABEL}`]);
  rmSync(PLIST, { force: true });
  log("uninstalled", { plist: PLIST });
}

function status() {
  const live = service();
  const edgePath = live ? join(live.args.at(-1), "personal/edge-service.json") : undefined;
  const loaded = run("launchctl", ["print", `gui/${process.getuid()}/${LABEL}`]).ok;
  console.log(JSON.stringify({
    agentLoaded: loaded, paused: existsSync(PAUSE_FILE), service: live?.status,
    liveRevision: edgePath ? JSON.parse(readFileSync(edgePath, "utf8")).sourceRevision : undefined, state: readState()
  }, null, 2));
}

const [command = "once", ...flags] = process.argv.slice(2);
const commands = {
  once: () => once({ dryRun: flags.includes("--dry-run") }),
  install, uninstall, status,
  pause: () => { mkdirSync(ROOT, { recursive: true }); writeFileSync(PAUSE_FILE, `${new Date().toISOString()}\n`); log("paused-by-owner"); },
  resume: () => { rmSync(PAUSE_FILE, { force: true }); log("resumed-by-owner"); }
};
if (commands[command] === undefined) { console.error(`usage: run.mjs ${Object.keys(commands).join("|")} [--dry-run]`); process.exit(2); }
try { await commands[command](); } catch (error) {
  notify("Auto-deploy error", String(error?.message ?? error).slice(0, 200));
  process.exitCode = 1;
}
