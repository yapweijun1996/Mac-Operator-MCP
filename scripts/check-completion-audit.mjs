import { spawnSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readProductionAcceptanceRecord } from "./production-acceptance-record.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const hostProbePath = resolve(repositoryRoot, "scripts/probe-host-readiness.mjs");
const requiredEvidence = [
  "VERIFICATION.md",
  "AUDIT_ARCHIVE_RUNBOOK.md",
  "evidence/2026-09-22-completion-audit.md",
  "evidence/2026-09-22-audit-integrity-readback.md",
  "evidence/2026-09-22-audit-retention-boundary.md",
  "evidence/2026-09-23-audit-export-recovery.md",
  "LEDGER_ARCHIVE_RUNBOOK.md",
  "evidence/2026-09-23-ledger-export-recovery.md",
  "evidence/2026-09-22-operator-launchd-identity-boundary.md",
  "evidence/2026-09-22-host-release-gui-readiness.md",
  "evidence/2026-09-22-keychain-acl-readback.md",
  "evidence/2026-09-22-packaged-launchagent-smoke.md",
  "evidence/2026-09-22-install-plan-launchagent-lifecycle.md",
  "evidence/2026-09-22-root-helper-release-gate.md",
  "evidence/2026-09-22-production-process-boundary-audit.md",
  "evidence/2026-09-22-script-process-boundary-audit.md",
  "evidence/2026-09-22-macos-launchagent-plan-cli.md",
  "evidence/2026-09-22-root-helper-snapshot-plan-cli.md",
  "evidence/2026-09-22-macos-launchagent-coordinator.md",
  "evidence/2026-09-22-macos-launchagent-apply-boundary.md",
  "evidence/2026-09-23-launchagent-deployment-journal.md",
  "evidence/2026-09-23-process-final-cancellation-fence.md",
  "evidence/2026-09-23-job-terminal-invariants.md",
  "evidence/2026-09-23-queued-job-recovery-metadata.md",
  "evidence/2026-09-23-request-job-idempotency-fence.md",
  "evidence/2026-09-22-privileged-helper-three-socket-readback.md",
  "evidence/2026-09-23-privileged-helper-handoff.md",
  "evidence/2026-09-22-production-acceptance-record.md"
];

const verificationText = readText("VERIFICATION.md");
const progress = readProgress(verificationText);
const host = readHostReadiness();
const productionAcceptance = await readProductionAcceptanceRecord({
  repositoryRoot,
  currentHost: host
});
const evidence = readEvidence(requiredEvidence);
const requirementMatrix = readRequirementMatrix(verificationText);
const gates = [
  {
    id: "contract-and-boundary-evidence",
    status: evidence.every((item) => item.present) ? "verified" : "incomplete",
    evidence: requiredEvidence
  },
  {
    id: "developer-id-and-notarized-release",
    status: host?.readyForRelease === true ? "verified" : "incomplete",
    reason: host?.readyForRelease === true
      ? "current host reports a Developer ID identity and enabled Gatekeeper"
      : "current host does not report a complete Developer ID/Gatekeeper release gate"
  },
  {
    id: "accessibility-gui-readiness",
    status: host?.readyForGui === true ? "verified" : "incomplete",
    reason: host?.readyForGui === true
      ? "current host reports permission-granted Accessibility readiness"
      : "current host does not report permission-granted Accessibility readiness"
  },
  {
    id: "persistent-service-lifecycle",
    status: host?.persistentServiceVerified === true ? "verified" : "incomplete",
    reason: host?.persistentServiceVerified === true
      ? "all target LaunchAgent/LaunchDaemon labels are present"
      : "target production service labels are not all present"
  },
  {
    id: "protected-production-material-and-rollback",
    status: productionAcceptance.valid ? "verified" : "incomplete",
    reason: productionAcceptance.valid
      ? "owner-only production material, rollback, readback, and independent review record is valid"
      : productionAcceptance.reason,
    evidence: [productionAcceptance.path]
  },
  {
    id: "requirement-to-release-matrix",
    status: requirementMatrix.complete ? "verified" : "incomplete",
    reason: requirementMatrix.complete
      ? "every requirement-to-release row is PASS"
      : `${requirementMatrix.open} OPEN, ${requirementMatrix.blocked} BLOCKED, and ${requirementMatrix.fail} FAIL requirement rows remain`,
    evidence: ["VERIFICATION.md"]
  }
];

const complete = gates.every((gate) => gate.status === "verified");
const report = {
  schemaVersion: "0.1",
  mechanism: "mac-operator-completion-audit-v1",
  capturedAtMs: Date.now(),
  status: complete ? "complete" : "partial",
  failClosed: true,
  overallProgressPercent: progress,
  hostReadiness: host,
  productionAcceptance,
  requirementMatrix,
  evidence,
  gates
};

process.stdout.write(`${JSON.stringify(report)}\n`);
if (!complete) process.exitCode = 1;

function readHostReadiness() {
  if (process.platform !== "darwin") {
    return {
      schemaVersion: "0.1",
      mechanism: "macos-host-readiness-v1",
      status: "unsupported-platform",
      failClosed: true,
      readyForRelease: false,
      readyForGui: false,
      persistentServiceVerified: false
    };
  }
  const result = spawnSync(process.execPath, [hostProbePath], {
    cwd: repositoryRoot,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C" },
    encoding: "utf8",
    maxBuffer: 256 * 1024,
    shell: false,
    timeout: 15_000,
    windowsHide: true
  });
  const line = `${result.stdout ?? ""}`.trim().split("\n").at(-1) ?? "";
  try {
    const value = JSON.parse(line);
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
        value.schemaVersion !== "0.1" || value.mechanism !== "macos-host-readiness-v1" ||
        value.failClosed !== true) throw new Error("malformed host readiness");
    return value;
  } catch {
    return {
      schemaVersion: "0.1",
      mechanism: "macos-host-readiness-v1",
      status: "probe-failed",
      failClosed: true,
      readyForRelease: false,
      readyForGui: false,
      persistentServiceVerified: false
    };
  }
}

function readEvidence(paths) {
  return paths.map((path) => ({ path, present: isRegularRepositoryFile(path) }));
}

function readProgress(text) {
  const match = text.match(/^## Current overall progress: (\d+)%$/mu);
  if (match === null) return null;
  const value = Number(match[1]);
  return Number.isSafeInteger(value) && value >= 0 && value <= 100 ? value : null;
}

function readRequirementMatrix(text) {
  const header = "## Requirement-to-release matrix";
  const start = text.indexOf(header);
  if (start < 0) return { total: 0, pass: 0, open: 0, blocked: 0, fail: 0, complete: false };
  const end = text.indexOf("\n## ", start + header.length);
  const section = text.slice(start, end < 0 ? undefined : end);
  const rows = section.split("\n")
    .filter((line) => line.startsWith("| VT-"))
    .map((line) => line.split("|").slice(1, -1).map((cell) => cell.trim()));
  const counts = { total: rows.length, pass: 0, open: 0, blocked: 0, fail: 0 };
  for (const row of rows) {
    const status = row[6]?.split(" ", 1)[0];
    if (status === "PASS") counts.pass += 1;
    else if (status === "OPEN") counts.open += 1;
    else if (status === "BLOCKED") counts.blocked += 1;
    else if (status === "FAIL") counts.fail += 1;
  }
  return { ...counts, complete: counts.total > 0 && counts.pass === counts.total };
}

function readText(path) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(resolve(repositoryRoot, path)));
  } catch {
    return "";
  }
}

function isRegularRepositoryFile(path) {
  const candidate = resolve(repositoryRoot, path);
  const escaped = relative(repositoryRoot, candidate).startsWith("..") || resolve(candidate) !== candidate;
  if (escaped) return false;
  try {
    return lstatSync(candidate).isFile();
  } catch {
    return false;
  }
}
