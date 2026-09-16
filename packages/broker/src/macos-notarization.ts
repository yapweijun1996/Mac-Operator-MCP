import { resolve, isAbsolute } from "node:path";
import type { ProcessExecutionResult } from "./process-supervisor.js";
import { isPlainDataRecord } from "./plain-record.js";

const SPCTL_PATH = "/usr/sbin/spctl" as const;
const ASSESSMENT_TIMEOUT_MS = 5_000 as const;
const ASSESSMENT_OUTPUT_CAP_BYTES = 131_072 as const;
const TEAM_IDENTIFIER_PATTERN = /^[A-Z0-9]{10}$/u;
const AUTHORITY_PATTERN = /^Developer ID Application: .+ \(([A-Z0-9]{10})\)$/u;

export type MacOsNotarizationErrorCode =
  | "INVALID_ARTIFACT"
  | "INVALID_TEAM_IDENTIFIER"
  | "ASSESSMENT_FAILED"
  | "ASSESSMENT_MISMATCH"
  | "INVALID_READBACK";

export class MacOsNotarizationError extends Error {
  readonly code: MacOsNotarizationErrorCode;

  constructor(code: MacOsNotarizationErrorCode, message: string) {
    super(message);
    this.name = "MacOsNotarizationError";
    this.code = code;
  }
}

export interface MacOsNotarizationAssessmentCommand {
  executable: typeof SPCTL_PATH;
  args: readonly ["--assess", "--type", "execute", "--verbose=4", string];
  cwd: "/";
  environment: Readonly<Record<string, string>>;
  timeoutMs: typeof ASSESSMENT_TIMEOUT_MS;
  outputCapBytes: typeof ASSESSMENT_OUTPUT_CAP_BYTES;
}

export interface MacOsNotarizationReadback {
  artifactPath: string;
  assessed: true;
  source: "Notarized Developer ID";
  teamIdentifier: string;
  origin: string;
}

export interface MacOsNotarizationExecutor {
  run(command: MacOsNotarizationAssessmentCommand): Promise<ProcessExecutionResult>;
}

/** Build the fixed Gatekeeper assessment command for one canonical artifact. */
export function buildMacOsNotarizationAssessmentCommand(artifactPath: string): MacOsNotarizationAssessmentCommand {
  if (typeof artifactPath !== "string" || !isAbsolute(artifactPath) || artifactPath.includes("\0") ||
      artifactPath.includes("\r") || artifactPath.includes("\n") || resolve(artifactPath) !== artifactPath || artifactPath === "/") {
    fail("INVALID_ARTIFACT", "notarization assessment artifact path is not canonical");
  }
  return {
    executable: SPCTL_PATH,
    args: ["--assess", "--type", "execute", "--verbose=4", artifactPath],
    cwd: "/",
    environment: {},
    timeoutMs: ASSESSMENT_TIMEOUT_MS,
    outputCapBytes: ASSESSMENT_OUTPUT_CAP_BYTES
  };
}

/** Parse only the bounded Gatekeeper provenance fields; raw output never crosses this boundary. */
export function parseMacOsNotarizationAssessment(
  output: string,
  expectedTeamIdentifier: string
): Omit<MacOsNotarizationReadback, "artifactPath"> {
  if (typeof expectedTeamIdentifier !== "string" || !TEAM_IDENTIFIER_PATTERN.test(expectedTeamIdentifier)) {
    fail("INVALID_TEAM_IDENTIFIER", "notarization assessment Team ID is invalid");
  }
  if (typeof output !== "string" || Buffer.byteLength(output, "utf8") > ASSESSMENT_OUTPUT_CAP_BYTES) {
    fail("ASSESSMENT_MISMATCH", "notarization assessment output is oversized");
  }
  const acceptedLines = output.split(/\r?\n/u).filter((line) => /: accepted$/u.test(line));
  const sourceMatches = [...output.matchAll(/^source=([^\r\n]+)$/gmu)];
  const originMatches = [...output.matchAll(/^origin=([^\r\n]+)$/gmu)];
  if (acceptedLines.length !== 1 || sourceMatches.length !== 1 || originMatches.length !== 1) {
    fail("ASSESSMENT_MISMATCH", "notarization assessment provenance is incomplete");
  }
  const source = sourceMatches[0]?.[1]?.trim();
  const origin = originMatches[0]?.[1]?.trim();
  if (source !== "Notarized Developer ID" || origin === undefined || origin.length < 1 || origin.length > 256) {
    fail("ASSESSMENT_MISMATCH", "notarization assessment source is not notarized Developer ID");
  }
  const originMatch = AUTHORITY_PATTERN.exec(origin);
  if (originMatch?.[1] !== expectedTeamIdentifier) {
    fail("ASSESSMENT_MISMATCH", "notarization assessment origin does not match the expected Team ID");
  }
  return { assessed: true, source, teamIdentifier: expectedTeamIdentifier, origin };
}

/** Run the fixed assessment and return only redacted, identity-bound evidence. */
export async function readMacOsNotarizationAssessment(
  artifactPath: string,
  expectedTeamIdentifier: string,
  executor: MacOsNotarizationExecutor
): Promise<MacOsNotarizationReadback> {
  const command = buildMacOsNotarizationAssessmentCommand(artifactPath);
  if (executor === null || typeof executor !== "object" || typeof executor.run !== "function") {
    fail("ASSESSMENT_FAILED", "notarization assessment executor is unavailable");
  }
  let result: ProcessExecutionResult;
  try {
    result = await executor.run(command);
  } catch {
    fail("ASSESSMENT_FAILED", "notarization assessment command failed");
  }
  if (result.resultClass !== "SUCCEEDED" || result.truncated) {
    fail("ASSESSMENT_FAILED", "notarization assessment was not accepted");
  }
  try {
    return { artifactPath, ...parseMacOsNotarizationAssessment(`${result.stdout}\n${result.stderr}`, expectedTeamIdentifier) };
  } catch (error) {
    if (error instanceof MacOsNotarizationError) throw error;
    fail("ASSESSMENT_MISMATCH", "notarization assessment readback is invalid");
  }
}

export function validateMacOsNotarizationReadback(
  readback: MacOsNotarizationReadback,
  expectedArtifactPath: string,
  expectedTeamIdentifier: string
): void {
  if (!isPlainDataRecord(readback) || readback.artifactPath !== expectedArtifactPath ||
      readback.assessed !== true || readback.source !== "Notarized Developer ID" ||
      readback.teamIdentifier !== expectedTeamIdentifier || typeof readback.origin !== "string" ||
      readback.origin.length < 1 || readback.origin.length > 256 ||
      AUTHORITY_PATTERN.exec(readback.origin)?.[1] !== expectedTeamIdentifier) {
    fail("ASSESSMENT_MISMATCH", "notarization assessment readback does not match the expected artifact");
  }
}

function fail(code: MacOsNotarizationErrorCode, message: string): never {
  throw new MacOsNotarizationError(code, message);
}
