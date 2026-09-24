import { lstatSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { hasSafeParentChain as hasSafeReleaseParentChain } from "./safe-path-parent.mjs";
import { readProtectedRegularFile } from "./protected-file-read.mjs";

const MAX_RECORD_BYTES = 128 * 1024;
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1_000;
const MAX_EVIDENCE_REFS = 32;
const ACCEPTANCE_RELATIVE_PATH = "evidence/production-acceptance.json";

/**
 * Reads the owner-supplied production acceptance assertion without treating it
 * as proof by itself. Dynamic host readiness and every referenced evidence file
 * must still validate before the completion audit can accept this gate.
 */
export async function readProductionAcceptanceRecord({ repositoryRoot, currentHost, path, now = Date.now() }) {
  const recordPath = path ?? resolve(repositoryRoot, ACCEPTANCE_RELATIVE_PATH);
  const relativePath = relative(repositoryRoot, recordPath);
  const base = { path: relativePath || ACCEPTANCE_RELATIVE_PATH, valid: false };
  if (relativePath.startsWith("..") || resolve(recordPath) !== recordPath) {
    return { ...base, status: "invalid", reason: "acceptance record path is outside the repository" };
  }
  if (!hasSafeRepositoryParentChain(repositoryRoot, recordPath)) {
    return { ...base, status: "invalid", reason: "acceptance record parent path is symlinked or unsafe" };
  }
  let stats;
  try {
    stats = lstatSync(recordPath);
  } catch {
    return { ...base, status: "absent", reason: "owner-only production acceptance record is absent" };
  }
  const ownerUid = currentHost?.host?.ownerUid;
  if (!stats.isFile() || stats.uid !== ownerUid || (stats.mode & 0o077) !== 0) {
    return { ...base, status: "invalid", reason: "acceptance record must be an owner-only regular file" };
  }
  let record;
  try {
    const bytes = await readProtectedRegularFile(recordPath, {
      ownerUid,
      maxBytes: MAX_RECORD_BYTES,
      unavailableMessage: "acceptance record is unavailable",
      invalidMessage: "acceptance record is not an owner-only regular file",
      oversizedMessage: "acceptance record is oversized"
    });
    record = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return { ...base, status: "invalid", reason: "acceptance record is not bounded strict UTF-8 JSON" };
  }
  try {
    validateRecord(record, repositoryRoot, currentHost, now);
  } catch {
    return { ...base, status: "invalid", reason: "acceptance record fields or evidence references are invalid" };
  }
  return {
    ...base,
    status: "verified",
    valid: true,
    sourceRevision: record.sourceRevision,
    evidenceCount: record.evidenceRefs.length
  };
}

function validateRecord(record, repositoryRoot, currentHost, now) {
  if (!isPlainRecord(record) || !sameKeys(record, [
    "schemaVersion", "mechanism", "capturedAtMs", "sourceRevision", "host",
    "productionMaterial", "rollback", "securityReview", "evidenceRefs"
  ]) || record.schemaVersion !== "0.1" ||
      record.mechanism !== "mac-operator-production-acceptance-v1" ||
      !Number.isSafeInteger(record.capturedAtMs) || record.capturedAtMs <= 0 ||
      record.capturedAtMs > now || now - record.capturedAtMs > MAX_AGE_MS ||
      typeof record.sourceRevision !== "string" ||
      !/^[A-Za-z0-9._:/-]{1,128}$/u.test(record.sourceRevision) ||
      !isPlainRecord(record.host) || !sameKeys(record.host, ["platform", "arch", "ownerUid"]) ||
      record.host.platform !== currentHost?.host?.platform ||
      record.host.arch !== currentHost?.host?.arch ||
      record.host.ownerUid !== currentHost?.host?.ownerUid ||
      !isPlainRecord(record.productionMaterial) ||
      !sameKeys(record.productionMaterial, ["keychainAclReadback", "helperMaterial"]) ||
      record.productionMaterial.keychainAclReadback !== "verified" ||
      record.productionMaterial.helperMaterial !== "verified" ||
      !isPlainRecord(record.rollback) ||
      !sameKeys(record.rollback, ["rootHelperRollback", "edgeBrokerRollback"]) ||
      record.rollback.rootHelperRollback !== "verified" ||
      record.rollback.edgeBrokerRollback !== "verified" ||
      !isPlainRecord(record.securityReview) ||
      !sameKeys(record.securityReview, ["status", "p0Findings", "p1Findings", "reviewRef"]) ||
      record.securityReview.status !== "passed" || record.securityReview.p0Findings !== 0 ||
      record.securityReview.p1Findings !== 0 || typeof record.securityReview.reviewRef !== "string" ||
      record.securityReview.reviewRef.length < 1 || record.securityReview.reviewRef.length > 512 ||
      !Array.isArray(record.evidenceRefs) || record.evidenceRefs.length < 4 ||
      record.evidenceRefs.length > MAX_EVIDENCE_REFS ||
      new Set(record.evidenceRefs).size !== record.evidenceRefs.length ||
      !record.evidenceRefs.includes(record.securityReview.reviewRef)) {
    throw new Error("invalid acceptance record");
  }
  for (const evidenceRef of record.evidenceRefs) {
    if (typeof evidenceRef !== "string" || evidenceRef.length < 1 || evidenceRef.length > 256 ||
        evidenceRef.includes("\0") || evidenceRef.includes("\n") || isAbsolute(evidenceRef) ||
        !isRegularRepositoryFile(repositoryRoot, evidenceRef)) {
      throw new Error("invalid evidence reference");
    }
  }
}

function isRegularRepositoryFile(repositoryRoot, path) {
  const candidate = resolve(repositoryRoot, path);
  const escaped = relative(repositoryRoot, candidate).startsWith("..") || resolve(candidate) !== candidate;
  if (escaped || !hasSafeRepositoryParentChain(repositoryRoot, candidate)) return false;
  try {
    const stats = lstatSync(candidate);
    return stats.isFile() && !stats.isSymbolicLink();
  } catch {
    return false;
  }
}

function hasSafeRepositoryParentChain(repositoryRoot, candidate) {
  const root = resolve(repositoryRoot);
  const parent = dirname(resolve(candidate));
  const relativeParent = relative(root, parent);
  if (relativeParent.startsWith("..") || resolve(parent) !== parent) return false;
  if (!hasSafeReleaseParentChain(candidate, currentOwnerUid(repositoryRoot))) return false;
  try {
    const rootStats = lstatSync(root);
    if (!rootStats.isDirectory() || rootStats.isSymbolicLink()) return false;
  } catch {
    return false;
  }
  let current = root;
  for (const component of relativeParent.split(sep).filter(Boolean)) {
    current = resolve(current, component);
    let stats;
    try {
      stats = lstatSync(current);
    } catch {
      return true;
    }
    if (!stats.isDirectory() || stats.isSymbolicLink()) return false;
  }
  return true;
}

function currentOwnerUid(repositoryRoot) {
  try {
    return lstatSync(repositoryRoot).uid;
  } catch {
    return -1;
  }
}

function isPlainRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function sameKeys(value, expected) {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === [...expected].sort()[index]);
}
