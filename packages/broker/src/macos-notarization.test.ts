import assert from "node:assert/strict";
import test from "node:test";
import type { ProcessExecutionResult } from "./process-supervisor.js";
import {
  buildMacOsNotarizationAssessmentCommand,
  MacOsNotarizationError,
  parseMacOsNotarizationAssessment,
  readMacOsNotarizationAssessment,
  validateMacOsNotarizationReadback
} from "./macos-notarization.js";

const artifactPath = "/Users/operator/Library/Application Support/MacOperator/MacOperatorBroker.app";
const teamIdentifier = "ABCDE12345";
const acceptedOutput = [
  `${artifactPath}: accepted`,
  "source=Notarized Developer ID",
  "origin=Developer ID Application: Mac Operator (ABCDE12345)"
].join("\n");

function success(stdout: string): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    signal: null,
    stdout,
    stderr: "",
    truncated: false,
    durationMs: 1,
    processId: 1,
    processGroupId: 1,
    terminationObserved: true
  };
}

function failed(stdout: string): ProcessExecutionResult {
  return {
    ...success(stdout),
    resultClass: "EXECUTION_FAILED",
    exitCode: 1
  };
}

test("notarization assessment uses fixed spctl argv and parses only notarized Developer ID provenance", async () => {
  const command = buildMacOsNotarizationAssessmentCommand(artifactPath);
  assert.deepEqual(command, {
    executable: "/usr/sbin/spctl",
    args: ["--assess", "--type", "execute", "--verbose=4", artifactPath],
    cwd: "/",
    environment: {},
    timeoutMs: 5_000,
    outputCapBytes: 131_072
  });
  assert.deepEqual(parseMacOsNotarizationAssessment(acceptedOutput, teamIdentifier), {
    assessed: true,
    source: "Notarized Developer ID",
    teamIdentifier,
    origin: "Developer ID Application: Mac Operator (ABCDE12345)"
  });
  const observed = await readMacOsNotarizationAssessment(artifactPath, teamIdentifier, {
    run: async (received) => {
      assert.deepEqual(received, command);
      return success(acceptedOutput);
    }
  });
  validateMacOsNotarizationReadback(observed, artifactPath, teamIdentifier);
  assert.equal(observed.artifactPath, artifactPath);
});

test("notarization assessment rejects Apple System, mismatched origin, malformed, and failed results", async () => {
  assert.throws(
    () => parseMacOsNotarizationAssessment([
      `${artifactPath}: accepted`,
      "source=Apple System",
      "origin=Software Signing"
    ].join("\n"), teamIdentifier),
    (error: unknown) => error instanceof MacOsNotarizationError && error.code === "ASSESSMENT_MISMATCH"
  );
  assert.throws(
    () => parseMacOsNotarizationAssessment(acceptedOutput.replace(teamIdentifier, "ZZZZZ99999"), teamIdentifier),
    (error: unknown) => error instanceof MacOsNotarizationError && error.code === "ASSESSMENT_MISMATCH"
  );
  assert.throws(
    () => buildMacOsNotarizationAssessmentCommand(`${artifactPath}/../other`),
    (error: unknown) => error instanceof MacOsNotarizationError && error.code === "INVALID_ARTIFACT"
  );
  await assert.rejects(
    readMacOsNotarizationAssessment(artifactPath, teamIdentifier, {
      run: async () => failed(`${artifactPath}: rejected\nsource=Notarized Developer ID`)
    }),
    (error: unknown) => error instanceof MacOsNotarizationError && error.code === "ASSESSMENT_FAILED"
  );
  await assert.rejects(
    readMacOsNotarizationAssessment(artifactPath, teamIdentifier, {
      run: async () => success(`${acceptedOutput}\n${"x".repeat(131_073)}`)
    }),
    (error: unknown) => error instanceof MacOsNotarizationError && error.code === "ASSESSMENT_MISMATCH"
  );
});
