import {
  readMacOsReleaseArtifactSummary,
  validateMacOsReleasePreflightEvidence,
  type MacOsReleasePreflightEvidence,
  type MacOsReleasePreflightEvidenceExpectation
} from "./macos-release-preflight.js";
import type { CodeSignatureExpectation } from "./macos-install-plan.js";

export type RootHelperSnapshotReleaseEvidence = MacOsReleasePreflightEvidence;

export interface RootHelperSnapshotReleaseExpectation extends MacOsReleasePreflightEvidenceExpectation {
  helperPath: string;
  signature: CodeSignatureExpectation;
}

/** Validate release provenance for the exact native root-helper executable. */
export function validateRootHelperSnapshotReleaseEvidence(
  evidence: unknown,
  expectation: RootHelperSnapshotReleaseExpectation
): asserts evidence is RootHelperSnapshotReleaseEvidence {
  validateMacOsReleasePreflightEvidence(evidence, {
    artifactPath: expectation.helperPath,
    signature: expectation.signature
  });
}

/** Re-read the root-owned helper artifact before a production dispatch. */
export async function assertRootHelperSnapshotReleaseArtifactStable(
  evidence: RootHelperSnapshotReleaseEvidence
): Promise<void> {
  const current = await readMacOsReleaseArtifactSummary(evidence.artifact.artifactPath, 0);
  const expected = evidence.artifact;
  if (current.artifactPath !== expected.artifactPath || current.sha256 !== expected.sha256 ||
      current.bytes !== expected.bytes || current.files !== expected.files ||
      current.directories !== expected.directories || current.device !== expected.device ||
      current.inode !== expected.inode || current.mode !== expected.mode) {
    throw new Error("Production root-helper release artifact changed");
  }
}
