import { basename, dirname, resolve } from "node:path";
import {
  validateCodeSignatureReadback,
  type CodeSignatureExpectation,
  type CodeSignatureReadback
} from "./macos-install-plan.js";
import {
  validateMacOsNotarizationReadback,
  type MacOsNotarizationReadback
} from "./macos-notarization.js";
import type { MacOsReleaseArtifactSummary } from "./macos-release-preflight.js";
import { isPlainDataRecord } from "./plain-record.js";

const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;

/** Redacted, identity-bound release readback for the exact App Sandbox bundle. */
export interface AppSandboxHelperReleaseEvidence {
  artifact: MacOsReleaseArtifactSummary;
  signature: CodeSignatureReadback;
  notarization: MacOsNotarizationReadback;
  policy: "developer-id-notarized";
}

export interface AppSandboxHelperReleaseExpectation {
  helperPath: string;
  helperContentSha256: string;
  signature: CodeSignatureExpectation;
}

/**
 * Validate release evidence supplied by the host-owned installer/readback
 * path. This does not execute commands and never trusts MCP request data.
 */
export function validateAppSandboxHelperReleaseEvidence(
  evidence: unknown,
  expectation: AppSandboxHelperReleaseExpectation
): asserts evidence is AppSandboxHelperReleaseEvidence {
  if (!isPlainDataRecord(evidence) || !hasExactKeys(evidence, ["artifact", "notarization", "policy", "signature"]) ||
      evidence.policy !== "developer-id-notarized" ||
      !DIGEST_PATTERN.test(expectation.helperContentSha256)) {
    fail("App Sandbox helper release evidence is malformed");
  }
  if (!isCanonicalAbsolutePath(expectation.helperPath)) {
    fail("App Sandbox helper release expectation path is not canonical");
  }
  const bundlePath = deriveBundlePath(expectation.helperPath);
  const artifact = evidence.artifact;
  if (!isPlainDataRecord(artifact) ||
      !hasExactKeys(artifact, ["artifactPath", "bytes", "device", "directories", "files", "inode", "mode", "sha256"]) ||
      artifact.artifactPath !== bundlePath ||
      typeof artifact.sha256 !== "string" || !DIGEST_PATTERN.test(artifact.sha256) ||
      typeof artifact.bytes !== "number" || !Number.isSafeInteger(artifact.bytes) || artifact.bytes < 1 ||
      typeof artifact.files !== "number" || !Number.isSafeInteger(artifact.files) || artifact.files < 1 ||
      typeof artifact.directories !== "number" || !Number.isSafeInteger(artifact.directories) || artifact.directories < 1 ||
      typeof artifact.device !== "string" || artifact.device.length < 1 || artifact.device.length > 64 ||
      typeof artifact.inode !== "string" || artifact.inode.length < 1 || artifact.inode.length > 64 ||
      typeof artifact.mode !== "number" || !Number.isSafeInteger(artifact.mode) || artifact.mode < 0) {
    fail("App Sandbox helper release artifact readback is malformed");
  }
  if (!isPlainDataRecord(evidence.signature) ||
      !hasExactKeys(evidence.signature, ["artifactPath", "authority", "cdHash", "identifier", "signatureType", "teamIdentifier", "valid"]) ||
      !isPlainDataRecord(evidence.notarization) ||
      !hasExactKeys(evidence.notarization, ["artifactPath", "assessed", "origin", "source", "teamIdentifier"])) {
    fail("App Sandbox helper release identity readback is malformed");
  }
  const signature = evidence.signature as unknown as CodeSignatureReadback;
  const notarization = evidence.notarization as unknown as MacOsNotarizationReadback;
  if (expectation.signature.teamIdentifier === undefined) {
    fail("App Sandbox helper release policy must pin a Developer ID Team ID");
  }
  try {
    validateCodeSignatureReadback(expectation.signature, signature, bundlePath);
    validateMacOsNotarizationReadback(notarization, bundlePath, expectation.signature.teamIdentifier);
  } catch {
    fail("App Sandbox helper release signature or notarization readback is not valid");
  }
}

export function appSandboxHelperBundlePath(helperPath: string): string {
  if (!isCanonicalAbsolutePath(helperPath)) {
    fail("App Sandbox helper path is not canonical");
  }
  return deriveBundlePath(helperPath);
}

function deriveBundlePath(helperPath: string): string {
  const macosDirectory = dirname(helperPath);
  const contentsDirectory = dirname(macosDirectory);
  const bundlePath = dirname(contentsDirectory);
  if (basename(macosDirectory) !== "MacOS" || basename(contentsDirectory) !== "Contents" ||
      !bundlePath.endsWith(".app") || bundlePath === "/") {
    fail("App Sandbox helper must be inside an AppSandboxHelper.app-style bundle");
  }
  return bundlePath;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isCanonicalAbsolutePath(value: string): boolean {
  return isAbsolutePath(value) && resolve(value) === value && !value.includes("\0") &&
    !value.includes("\r") && !value.includes("\n");
}

function isAbsolutePath(value: string): boolean {
  return value.startsWith("/");
}

function fail(message: string): never {
  throw new Error(message);
}
