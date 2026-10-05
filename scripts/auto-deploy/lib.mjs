// Pure decision helpers for the personal auto-deploy agent. No I/O happens here so every rule is unit-testable.

const RELEASE_NAME = /^personal-\d{8}-[0-9a-f]{7,40}$/u;
const TEST_FILE = /(^|\/)[^/]+\.test\.[cm]?[jt]sx?$/u;
const RUNTIME_PREFIXES = ["tool-contracts/", "schemas/", "runtime/", "packaging/"];
const RUNTIME_FILES = new Set(["package.json", "package-lock.json", "tsconfig.json"]);

/** Rewrites only the three Edge fields that bind a release; every other field is preserved byte-for-byte in meaning. */
export function patchEdgeConfig(config, { packageRoot, sourceRevision }) {
  if (typeof packageRoot !== "string" || !packageRoot.startsWith("/")) throw new Error("packageRoot must be absolute");
  if (!/^[0-9a-f]{40}$/u.test(sourceRevision)) throw new Error("sourceRevision must be a full commit id");
  return { ...config, packageRoot, contractsDirectory: `${packageRoot}/tool-contracts`, sourceRevision };
}

/** True when a changed path can alter what the running service executes (tests, docs and evidence cannot). */
export function isRuntimeRelevant(path) {
  if (TEST_FILE.test(path)) return false;
  if (RUNTIME_FILES.has(path) || RUNTIME_PREFIXES.some((prefix) => path.startsWith(prefix))) return true;
  if (path.startsWith("packages/")) return !path.includes("/fixtures/");
  if (path.startsWith("scripts/")) return false;
  return false;
}

/** How the live revision relates to the fetched origin/main tip; unknown means the live commit is absent from origin. */
export function classifyRelation({ currentKnown, currentIsAncestor, targetIsAncestor }) {
  if (!currentKnown) return "unknown";
  if (currentIsAncestor && targetIsAncestor) return "same";
  if (currentIsAncestor) return "behind";
  if (targetIsAncestor) return "ahead";
  return "diverged";
}

/** Single place that turns the relation and the changed paths into an action; never downgrades or merges. */
export function decideAction({ relation, changedPaths }) {
  if (relation === "same") return { action: "none", reason: "live revision already equals origin/main" };
  if (relation === "ahead") return { action: "none", reason: "live revision is newer than origin/main; push it first" };
  if (relation === "unknown") return { action: "manual", reason: "live revision is not in origin/main history; push it or deploy by hand" };
  if (relation === "diverged") return { action: "manual", reason: "live revision and origin/main diverged; deploy by hand" };
  if (!changedPaths.some(isRuntimeRelevant)) return { action: "skip", reason: "only docs, tests or tooling changed; no restart needed" };
  return { action: "deploy", reason: "runtime files changed" };
}

/** Release directory name for an auto-deployed commit. */
export function releaseName(date, revision) {
  const stamp = `${date.getFullYear()}${String(date.getMonth() + 1).padStart(2, "0")}${String(date.getDate()).padStart(2, "0")}`;
  return `personal-${stamp}-${revision.slice(0, 7)}`;
}

/** Oldest releases beyond the retention count; hand-named releases, the live release and the rollback target are never pruned. */
export function selectPrunable(entries, keep, protectedPaths) {
  const eligible = entries.filter((entry) => RELEASE_NAME.test(entry.name) && !protectedPaths.includes(entry.path));
  return eligible.sort((a, b) => b.mtimeMs - a.mtimeMs).slice(Math.max(0, keep));
}

/** Test files that failed in a full node:test run, so they can be rerun alone to rule out load-related flakes. */
export function parseFailedTestFiles(log) {
  const files = new Set();
  for (const match of log.matchAll(/^test at (\S+?\.(?:m?js)):\d+:\d+$/gmu)) files.add(match[1]);
  return [...files].sort();
}

/** Reads the supervised service out of `pm2 jlist` output; undefined when it is not registered. */
export function parsePm2Service(jlist, name) {
  const entry = JSON.parse(jlist).find((item) => item.name === name);
  if (entry === undefined) return undefined;
  const env = entry.pm2_env;
  return {
    status: env.status, restarts: env.restart_time, uptimeMs: Date.now() - env.pm_uptime,
    execPath: env.pm_exec_path, cwd: env.pm_cwd, args: env.args ?? []
  };
}

/** A deployment is healthy only when the process stayed up without restarts and the public endpoints still challenge for auth. */
export function isHealthy({ service, statuses }) {
  return service !== undefined && service.status === "online" && service.restarts === 0 && statuses.length > 0 &&
    statuses.every((status) => status === 401);
}
