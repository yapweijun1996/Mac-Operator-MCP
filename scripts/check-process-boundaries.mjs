import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const SOURCE_ROOTS = ["packages/auth/src", "packages/edge/src", "packages/broker/src"];
const SCRIPT_ROOT = "scripts";
const ALLOWED_FILES = new Set([
  "packages/auth/src/personal-service.ts",
  "packages/broker/src/process-supervisor.ts",
  "packages/broker/src/app-sandbox-task-executor.ts",
  "packages/broker/src/codex-controller.ts",
  "packages/broker/src/container-physical-validation.ts"
]);
const ALLOWED_SCRIPT_FILES = new Set([
  "scripts/probe-v2-yap-container.mjs",
  "scripts/check-completion-audit.mjs",
  "scripts/check-style.mjs",
  "scripts/probe-app-sandbox-boundary.mjs",
  "scripts/probe-app-sandbox-helper.mjs",
  "scripts/probe-d1-git-boundary.mjs",
  "scripts/probe-host-readiness.mjs",
  "scripts/probe-root-helper-native-auth.mjs",
  "scripts/probe-sandbox-boundary.mjs",
  "scripts/probe-user-service-mutation-boundary.mjs",
  "scripts/probe-user-service-rollback-boundary.mjs",
  "scripts/build-privileged-helper-app.mjs",
  "scripts/probe-privileged-helper-app.mjs",
  "scripts/probe-privileged-helper-sea.mjs",
  "scripts/record-host-readiness.mjs",
  "scripts/privileged-helper-handoff.test.mjs",
  "scripts/gui-hit-testing.test.mjs",
  "scripts/gui-transport.test.mjs"
]);
const CHILD_PROCESS_IMPORT = /from\s+["']node:child_process["']/u;
const CHILD_PROCESS_CALL = /\b(?:spawn|spawnSync|execFile|execFileSync|fork)\s*\(/u;
const PRODUCTION_BOUNDARY_REQUIREMENTS = new Map([
  ["packages/auth/src/personal-service.ts", [
    /\bcwd\s*:/u, /\benv\s*:/u, /\bshell\s*:\s*false\b/u, /\.kill\(/u
  ]],
  ["packages/broker/src/process-supervisor.ts", [
    /\bcwd\s*:/u, /\benv\s*:/u, /\bshell\s*:\s*false\b/u,
    /timeoutMs/u, /outputCapBytes/u, /shouldCancel/u, /\.kill\(/u
  ]],
  ["packages/broker/src/app-sandbox-task-executor.ts", [
    /\bcwd\s*:/u, /\benv\s*:/u, /\bshell\s*:\s*false\b/u,
    /MAX_HELPER_STARTUP_MS/u, /MAX_HELPER_STDERR_BYTES/u, /shouldCancel/u, /\.kill\(/u
  ]]
]);
const SCRIPT_BOUNDARY_REQUIREMENTS = new Map([
  ["scripts/check-completion-audit.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]],
  ["scripts/check-style.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]],
  ["scripts/probe-app-sandbox-boundary.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /MAX_CHILD_OUTPUT_BYTES/u, /CHILD_TIMEOUT_MS/u, /\.kill\(/u]],
  ["scripts/probe-app-sandbox-helper.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /MAX_CHILD_OUTPUT_BYTES/u, /MAX_RESPONSE_BYTES/u, /CHILD_TIMEOUT_MS/u, /\.kill\(/u]],
  ["scripts/probe-d1-git-boundary.mjs", [/\bcwd\s*(?::|,)/u, /\benv\s*:/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]],
  ["scripts/probe-host-readiness.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]],
  ["scripts/probe-root-helper-native-auth.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /MAX_CHILD_OUTPUT_BYTES/u, /MAX_RESPONSE_BYTES/u, /CHILD_TIMEOUT_MS/u, /\.kill\(/u]],
  ["scripts/probe-sandbox-boundary.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /MAX_CHILD_OUTPUT_BYTES/u, /CHILD_TIMEOUT_MS/u, /\.kill\(/u]],
  ["scripts/probe-user-service-mutation-boundary.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]],
  ["scripts/probe-user-service-rollback-boundary.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]],
  ["scripts/build-privileged-helper-app.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /\bshell\s*:\s*false\b/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]],
  ["scripts/probe-privileged-helper-app.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /\bshell\s*:\s*false\b/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]],
  ["scripts/probe-privileged-helper-sea.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /\bshell\s*:\s*false\b/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]],
  ["scripts/record-host-readiness.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]],
  ["scripts/gui-hit-testing.test.mjs", [/\bcwd\s*(?::|,)/u, /\benv\s*:/u, /\bshell\s*:\s*false\b/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]],
  ["scripts/gui-transport.test.mjs", [/\bcwd\s*(?::|,)/u, /\benv\s*:/u, /\bshell\s*:\s*false\b/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u, /stderrBytes/u, /\.kill\(/u]],
  ["scripts/privileged-helper-handoff.test.mjs", [/\bcwd\s*:/u, /\benv\s*:/u, /\bshell\s*:\s*false\b/u, /\bmaxBuffer\s*:/u, /\btimeout\s*:/u]]
]);

const entries = [];
const scriptEntries = [];
for (const root of SOURCE_ROOTS) {
  await scanDirectory(root);
}
await scanScriptDirectory(SCRIPT_ROOT);

const unexpected = entries.filter((entry) => !ALLOWED_FILES.has(entry.path));
if (unexpected.length > 0) {
  throw new Error(`unreviewed production child-process entry: ${unexpected.map((entry) => entry.path).join(", ")}`);
}
for (const entry of entries) {
  if (!/\bshell\s*:\s*false\b/u.test(entry.source) || /\bshell\s*:\s*true\b/u.test(entry.source)) {
    throw new Error(`production child-process entry lacks an explicit shell:false boundary: ${entry.path}`);
  }
  for (const requirement of PRODUCTION_BOUNDARY_REQUIREMENTS.get(entry.path) ?? []) {
    if (!requirement.test(entry.source)) throw new Error(`production child-process boundary is incomplete: ${entry.path}`);
  }
}
if (entries.length !== ALLOWED_FILES.size) {
  throw new Error(`expected ${ALLOWED_FILES.size} audited production child-process files, found ${entries.length}`);
}
const unexpectedScripts = scriptEntries.filter((entry) => !ALLOWED_SCRIPT_FILES.has(entry.path));
if (unexpectedScripts.length > 0) {
  throw new Error(`unreviewed repository-script child-process entry: ${unexpectedScripts.map((entry) => entry.path).join(", ")}`);
}
for (const entry of scriptEntries) {
  if (!/\bshell\s*:\s*false\b/u.test(entry.source) || /\bshell\s*:\s*true\b/u.test(entry.source)) {
    throw new Error(`repository-script child-process entry lacks an explicit shell:false boundary: ${entry.path}`);
  }
  for (const requirement of SCRIPT_BOUNDARY_REQUIREMENTS.get(entry.path) ?? []) {
    if (!requirement.test(entry.source)) throw new Error(`repository-script child-process boundary is incomplete: ${entry.path}`);
  }
}

process.stdout.write(`${JSON.stringify({
  schemaVersion: "0.1",
  mechanism: "production-child-process-boundary-audit-v1",
  auditedFiles: entries.map((entry) => entry.path).sort(),
  auditedScripts: scriptEntries.map((entry) => entry.path).sort(),
  shell: "explicit-false",
  limits: "explicit-cwd-minimal-env-timeout-output-cap-cancellation",
  unreviewedEntries: 0,
  unreviewedScriptEntries: 0
})}\n`);

async function scanDirectory(directory) {
  const children = await readdir(directory, { withFileTypes: true });
  for (const child of children) {
    const path = join(directory, child.name);
    if (child.isDirectory()) {
      await scanDirectory(path);
      continue;
    }
    if (!child.isFile() || !path.endsWith(".ts") || path.endsWith(".test.ts")) continue;
    const source = await readFile(path, "utf8");
    if (CHILD_PROCESS_IMPORT.test(source) && CHILD_PROCESS_CALL.test(source)) {
      entries.push({ path, source });
    }
  }
}

async function scanScriptDirectory(directory) {
  const children = await readdir(directory, { withFileTypes: true });
  for (const child of children) {
    const path = join(directory, child.name);
    if (child.isDirectory()) {
      await scanScriptDirectory(path);
      continue;
    }
    if (!child.isFile() || !path.endsWith(".mjs")) continue;
    const source = await readFile(path, "utf8");
    if (CHILD_PROCESS_IMPORT.test(source) && CHILD_PROCESS_CALL.test(source)) {
      scriptEntries.push({ path, source });
    }
  }
}
