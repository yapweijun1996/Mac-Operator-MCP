import { strict as assert } from "node:assert";
import { chmod, mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";
import {
  MacOsReleasePreflightError,
  readMacOsReleaseArtifactSummary,
  runMacOsReleasePreflight,
  type MacOsReleasePreflightInput
} from "./macos-release-preflight.js";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";

const teamIdentifier = "ABCDE12345";
const cdHash = "a".repeat(40);
const ownerUid = process.getuid?.() ?? 0;

test("release preflight binds artifact digest, Developer ID identity, and notarization", async () => {
  const root = await mkdtemp(join(tmpdir(), "mops-release-preflight-"));
  try {
    const artifact = join(root, "MacOperatorBroker.app");
    await mkdir(join(artifact, "Contents", "MacOS"), { recursive: true, mode: 0o700 });
    await writeFile(join(artifact, "Contents", "Info.plist"), "bundle", { mode: 0o600 });
    await writeFile(join(artifact, "Contents", "MacOS", "broker"), "executable", { mode: 0o700 });
    await chmod(artifact, 0o700);
    const summary = await readMacOsReleaseArtifactSummary(artifact, ownerUid);
    const input: MacOsReleasePreflightInput = {
      artifactPath: artifact,
      artifactSha256: summary.sha256,
      artifactBytes: summary.bytes,
      ownerUid,
      signature: { identifier: "com.mac-operator.broker", teamIdentifier, cdHash }
    };
    const executor = {
      run: async (command: { args: readonly string[] }): Promise<ProcessExecutionResult> => {
        if (command.args[0] === "--verify") return result("", "");
        if (command.args[0] === "-dv") {
          return result(
            "",
            [
              "Identifier=com.mac-operator.broker",
              `TeamIdentifier=${teamIdentifier}`,
              `CDHash=${cdHash}`,
              "Signature=valid",
              "Authority=Developer ID Application: Mac Operator (ABCDE12345)"
            ].join("\n")
          );
        }
        return result("/MacOperatorBroker.app: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Mac Operator (ABCDE12345)", "");
      }
    };
    const evidence = await runMacOsReleasePreflight(input, executor);
    assert.equal(evidence.policy, "developer-id-notarized");
    assert.deepEqual(evidence.artifact, summary);
    assert.equal(evidence.signature.teamIdentifier, teamIdentifier);
    assert.equal(evidence.signature.cdHash, cdHash);
    assert.equal(evidence.notarization.teamIdentifier, teamIdentifier);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release preflight rejects ad-hoc provenance, digest mismatch, and symlink entries", async () => {
  const root = await mkdtemp(join(tmpdir(), "mops-release-preflight-"));
  try {
    const artifact = join(root, "artifact");
    await mkdir(artifact, { mode: 0o700 });
    await writeFile(join(artifact, "payload"), "payload", { mode: 0o600 });
    const summary = await readMacOsReleaseArtifactSummary(artifact, ownerUid);
    const base: MacOsReleasePreflightInput = {
      artifactPath: artifact,
      artifactSha256: summary.sha256,
      ownerUid,
      signature: { identifier: "com.mac-operator.broker", teamIdentifier, cdHash }
    };
    const adHocExecutor = { run: async (command: { args: readonly string[] }) =>
      result(command.args[0] === "-dv" ? "" : "", command.args[0] === "-dv" ? "Identifier=com.mac-operator.broker\nSignature=adhoc" : "") };
    await assert.rejects(
      runMacOsReleasePreflight(base, adHocExecutor),
      (error: unknown) => error instanceof MacOsReleasePreflightError && error.code === "SIGNATURE_MISMATCH"
    );
    await assert.rejects(
      runMacOsReleasePreflight({ ...base, artifactSha256: "f".repeat(64) }, adHocExecutor),
      (error: unknown) => error instanceof MacOsReleasePreflightError && error.code === "DIGEST_MISMATCH"
    );
    await symlink(join(artifact, "payload"), join(artifact, "linked"));
    await assert.rejects(
      readMacOsReleaseArtifactSummary(artifact, ownerUid),
      (error: unknown) => error instanceof MacOsReleasePreflightError && error.code === "ARTIFACT_UNSAFE"
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release preflight uses the real macOS codesign boundary and rejects an ad-hoc bundle", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("The production release target is macOS");
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "mops-release-real-codesign-"));
  try {
    const artifact = join(root, "MacOperatorBroker.app");
    await mkdir(join(artifact, "Contents", "MacOS"), { recursive: true, mode: 0o700 });
    await writeFile(join(artifact, "Contents", "MacOS", "broker"), "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await writeFile(join(artifact, "Contents", "Info.plist"), [
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
      "<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.mac-operator.broker</string><key>CFBundleExecutable</key><string>broker</string></dict></plist>"
    ].join("\n"), { mode: 0o600 });
    const supervisor = new ProcessSupervisor({ allowedEnvironmentKeys: [] });
    const signed = await supervisor.run({
      executable: "/usr/bin/codesign",
      args: ["--force", "--deep", "--sign", "-", "--timestamp=none", artifact],
      cwd: "/",
      environment: {},
      timeoutMs: 5_000,
      outputCapBytes: 131_072
    });
    assert.equal(signed.resultClass, "SUCCEEDED");
    const summary = await readMacOsReleaseArtifactSummary(artifact, ownerUid);
    await assert.rejects(
      runMacOsReleasePreflight({
        artifactPath: artifact,
        artifactSha256: summary.sha256,
        artifactBytes: summary.bytes,
        ownerUid,
        signature: { identifier: "com.mac-operator.broker", teamIdentifier, cdHash }
      }, supervisor),
      (error: unknown) => error instanceof MacOsReleasePreflightError && error.code === "SIGNATURE_MISMATCH"
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function result(stdout: string, stderr: string): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    signal: null,
    stdout,
    stderr,
    truncated: false,
    durationMs: 1,
    processId: 1,
    processGroupId: 1,
    terminationObserved: true
  };
}
