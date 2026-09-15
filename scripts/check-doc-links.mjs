import { lstatSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, relative, resolve } from "node:path";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const readmePath = resolve(repositoryRoot, "README.md");
const requiredRunbooks = [
  "TESTING.md",
  "CONFIGURATION.md",
  "DEPLOYMENT.md",
  "OPERATIONS.md",
  "INCIDENT_RESPONSE.md",
  "ROLLBACK.md",
  "KILL_SWITCH.md",
  "PERSISTENCE_CUTOVER.md"
];

const failures = [];
const readme = readText(readmePath, "README.md");
const linkPattern = /\]\((<[^>]+>|[^)\s]+)\)/gu;
let checkedLinks = 0;
for (const match of readme.matchAll(linkPattern)) {
  const rawTarget = match[1];
  if (rawTarget === undefined || rawTarget.startsWith("<http://") || rawTarget.startsWith("<https://") || rawTarget.startsWith("http://") || rawTarget.startsWith("https://") || rawTarget.startsWith("#")) continue;
  const target = rawTarget.replace(/^<|>$/gu, "").split("#", 1)[0];
  if (target.length === 0) continue;
  checkedLinks += 1;
  const candidate = resolve(repositoryRoot, target);
  const escaped = relative(repositoryRoot, candidate).startsWith("..") || resolve(candidate) !== candidate;
  if (escaped) {
    failures.push(`README.md: link escapes repository: ${target}`);
    continue;
  }
  try {
    if (!lstatSync(candidate).isFile()) failures.push(`README.md: link target is not a regular file: ${target}`);
  } catch {
    failures.push(`README.md: link target is unavailable: ${target}`);
  }
}

for (const relativePath of requiredRunbooks) {
  const path = resolve(repositoryRoot, relativePath);
  try {
    if (!lstatSync(path).isFile()) failures.push(`${relativePath}: required runbook is not a regular file`);
  } catch {
    failures.push(`${relativePath}: required runbook is unavailable`);
  }
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  process.exitCode = 1;
} else {
  console.log(`Documentation check passed for ${checkedLinks} README local links and ${requiredRunbooks.length} required runbooks.`);
}

function readText(path, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(path));
  } catch {
    failures.push(`${label}: documentation is unavailable or not valid UTF-8`);
    return "";
  }
}
