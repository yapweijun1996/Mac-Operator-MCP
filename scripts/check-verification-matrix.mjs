import { lstatSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const matrixPath = resolve(repositoryRoot, "VERIFICATION.md");
const threatModelPath = resolve(repositoryRoot, "THREAT_MODEL.md");
const taskPath = resolve(repositoryRoot, "TASK.md");
const failures = [];

const matrix = readText(matrixPath, "VERIFICATION.md");
const threatModel = readText(threatModelPath, "THREAT_MODEL.md");
const taskLedger = readText(taskPath, "TASK.md");

const rows = [];
let inMatrix = false;
for (const [index, line] of matrix.split("\n").entries()) {
  if (line === "## Requirement-to-release matrix") {
    inMatrix = true;
    continue;
  }
  if (inMatrix && line.startsWith("## ")) break;
  if (!inMatrix || !line.startsWith("| VT-")) continue;
  const cells = line.split("|").slice(1, -1).map((cell) => cell.trim());
  if (cells.length !== 7) {
    failures.push(`VERIFICATION.md:${index + 1}: matrix row must contain exactly 7 cells`);
    continue;
  }
  rows.push({ line: index + 1, cells });
}

if (rows.length === 0) failures.push("VERIFICATION.md: requirement matrix has no data rows");

const seenVerificationIds = new Set();
const referencedThreatIds = new Set();
const referencedTaskIds = new Set();
const referencedEvidence = new Set();
const allowedStatuses = new Set(["OPEN", "BLOCKED", "PASS", "FAIL"]);
const allowedGates = new Set(["Documentation", "Local", "Local/Remote", "L0/L1", "L2", "L2/L5", "Mutation", "GUI", "L5", "Release", "Local/Remote/L5"]);

for (const row of rows) {
  const [verificationId, requirement, threats, tasks, requiredEvidence, gate, status] = row.cells;
  if (verificationId === undefined || !/^VT-[A-Z0-9-]{2,32}$/u.test(verificationId)) {
    failures.push(`VERIFICATION.md:${row.line}: verification ID is malformed`);
  } else if (seenVerificationIds.has(verificationId)) {
    failures.push(`VERIFICATION.md:${row.line}: duplicate verification ID ${verificationId}`);
  } else {
    seenVerificationIds.add(verificationId);
  }
  if (requirement === undefined || requirement.length === 0) failures.push(`VERIFICATION.md:${row.line}: requirement is empty`);
  if (requiredEvidence === undefined || requiredEvidence.length === 0) failures.push(`VERIFICATION.md:${row.line}: test/evidence requirement is empty`);
  if (gate === undefined || !allowedGates.has(gate)) failures.push(`VERIFICATION.md:${row.line}: unsupported release gate ${gate ?? "<missing>"}`);

  for (const id of extractIds(threats, /T-\d{3}/gu)) referencedThreatIds.add(id);
  for (const id of extractIds(tasks, /MOP-\d{3}/gu)) referencedTaskIds.add(id);
  for (const evidence of extractEvidence(requiredEvidence)) referencedEvidence.add(evidence);
  for (const evidence of extractEvidence(status)) referencedEvidence.add(evidence);

  const statusWord = status?.split(" ", 1)[0];
  if (statusWord === undefined || !allowedStatuses.has(statusWord)) {
    failures.push(`VERIFICATION.md:${row.line}: unsupported status ${status ?? "<missing>"}`);
  }
}

for (const id of referencedThreatIds) {
  if (!new RegExp(`^\\| ${id} `, "mu").test(threatModel)) failures.push(`VERIFICATION.md: unknown threat reference ${id}`);
}
for (const id of referencedTaskIds) {
  if (!new RegExp(`(?:^|\\n).*\\b${id}\\b`, "u").test(taskLedger)) failures.push(`VERIFICATION.md: unknown task reference ${id}`);
}
for (const evidence of referencedEvidence) {
  const evidencePath = resolve(repositoryRoot, evidence);
  if (!isRepositoryRelative(evidence) || !isRegularFile(evidencePath)) {
    failures.push(`VERIFICATION.md: evidence reference is unavailable or escapes repository: ${evidence}`);
  }
}

const threatModelVerificationIds = new Set();
for (const match of threatModel.matchAll(/\| (T-\d{3}) [^|]+\|[^|]+\|[^|]+\|[^|]+\| (VT-[A-Z0-9-]+) \|/gu)) {
  const verificationId = match[2];
  if (verificationId !== undefined) threatModelVerificationIds.add(verificationId);
}
for (const id of threatModelVerificationIds) {
  if (!seenVerificationIds.has(id)) failures.push(`THREAT_MODEL.md: verification target ${id} is missing from VERIFICATION.md`);
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  process.exitCode = 1;
} else {
  console.log(`Verification matrix check passed for ${rows.length} targets, ${referencedThreatIds.size} threats, ${referencedTaskIds.size} tasks, and ${referencedEvidence.size} evidence references.`);
}

function readText(path, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(path));
  } catch {
    failures.push(`${label}: file is unavailable or not valid UTF-8`);
    return "";
  }
}

function extractIds(value, pattern) {
  if (typeof value !== "string") return [];
  return [...value.matchAll(pattern)].map((match) => match[0]);
}

function extractEvidence(value) {
  if (typeof value !== "string") return [];
  return [...value.matchAll(/(?:^|[`\s(])((?:evidence|docs\/adr)\/[^`\s),;]+)/gu)].map((match) => match[1]).filter((path) => path !== undefined);
}

function isRepositoryRelative(value) {
  return value.startsWith("evidence/") || value.startsWith("docs/adr/");
}

function isRegularFile(path) {
  try {
    return lstatSync(path).isFile();
  } catch {
    return false;
  }
}
