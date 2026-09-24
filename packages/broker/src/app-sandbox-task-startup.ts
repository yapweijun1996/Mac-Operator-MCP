import {
  DescriptorSnapshotAttestationSigner,
  DescriptorSnapshotAttestationVerifier,
  DescriptorSnapshotRegistry
} from "./descriptor-snapshot-attestation.js";
import {
  AppSandboxTaskRunner,
  type AppSandboxTaskRunnerOptions,
  type TaskIsolationProof
} from "./task-runner.js";
import {
  DisabledAppSandboxTaskExecutor,
  NativeAppSandboxTaskExecutor,
  type AppSandboxTaskExecutorCapability
} from "./app-sandbox-task-executor.js";
import type { AppSandboxHelperReleaseEvidence } from "./app-sandbox-helper-release.js";
import type { CodeSignatureExpectation } from "./macos-install-plan.js";

export interface AppSandboxTaskRunnerStartupOptions {
  /** Explicit opt-in; omitted and false both remain unavailable. */
  enabled?: boolean;
  /** Independent host evidence gate; request arguments cannot provide it. */
  hostEvidenceAccepted?: boolean;
  /** Independent physical evidence gate for the Broker-owned network channel. */
  networkEvidenceAccepted?: boolean;
  isolationProof?: TaskIsolationProof | null;
  /** Broker-owned descriptor signer and native helper verifier. */
  signer?: DescriptorSnapshotAttestationSigner;
  verifier?: DescriptorSnapshotAttestationVerifier;
  /** Canonical signed helper executable and its App Sandbox container root. */
  helperPath?: string;
  containerRoot?: string;
  /** Host-owned content identity for the exact signed helper artifact. */
  helperContentSha256?: string;
  /** Required explicit mode when enabling the helper. */
  releaseMode?: "development-probe" | "production";
  /** Required for production mode; sourced from the read-only release preflight. */
  productionReleaseEvidence?: AppSandboxHelperReleaseEvidence;
  /** Host-owned Developer ID identity policy for production mode. */
  productionReleaseSignature?: CodeSignatureExpectation;
  evidenceRef?: string;
}

export interface AppSandboxTaskRunnerStartupAssembly {
  readonly taskRunner: AppSandboxTaskRunner;
  readonly snapshotRegistry: DescriptorSnapshotRegistry;
  readonly executor: NativeAppSandboxTaskExecutor | DisabledAppSandboxTaskExecutor;
  readonly capability: AppSandboxTaskExecutorCapability;
}

/**
 * Assemble the App Sandbox runner without accepting MCP authority. The
 * disabled branch carries no helper key or filesystem capability. The enabled
 * branch requires host-owned signing material and a separately accepted host
 * evidence gate before constructing the native executor.
 */
export function createAppSandboxTaskRunnerFromStartup(
  startup: AppSandboxTaskRunnerStartupOptions = {}
): AppSandboxTaskRunnerStartupAssembly {
  const evidenceAccepted = startup.enabled === true && startup.hostEvidenceAccepted === true;
  const snapshotRegistry = new DescriptorSnapshotRegistry({
    enabled: evidenceAccepted,
    ...(startup.signer === undefined ? {} : { signer: startup.signer }),
    ...(startup.verifier === undefined ? {} : { verifier: startup.verifier })
  });
  const executor = evidenceAccepted
    ? createEnabledExecutor(startup)
    : new DisabledAppSandboxTaskExecutor();
  const runnerOptions: AppSandboxTaskRunnerOptions = {
    ...(startup.enabled === undefined ? {} : { enabled: startup.enabled }),
    ...(startup.hostEvidenceAccepted === undefined ? {} : { hostEvidenceAccepted: startup.hostEvidenceAccepted }),
    ...(startup.isolationProof === undefined ? {} : { isolationProof: startup.isolationProof }),
    executor,
    snapshotRegistry
  };
  const taskRunner = new AppSandboxTaskRunner(runnerOptions);
  return { taskRunner, snapshotRegistry, executor, capability: executor.capability };
}

function createEnabledExecutor(startup: AppSandboxTaskRunnerStartupOptions): NativeAppSandboxTaskExecutor {
  if (!(startup.signer instanceof DescriptorSnapshotAttestationSigner) ||
      !(startup.verifier instanceof DescriptorSnapshotAttestationVerifier) ||
      typeof startup.helperPath !== "string" || typeof startup.containerRoot !== "string" ||
      typeof startup.helperContentSha256 !== "string" ||
      (startup.releaseMode !== "development-probe" && startup.releaseMode !== "production")) {
    throw new Error("Enabled App Sandbox tasks require host-owned signer, verifier, helper identity, release mode, and container configuration");
  }
  return new NativeAppSandboxTaskExecutor({
    enabled: true,
    hostEvidenceAccepted: true,
    ...(startup.networkEvidenceAccepted === undefined ? {} : { networkEvidenceAccepted: startup.networkEvidenceAccepted }),
    helperPath: startup.helperPath,
    containerRoot: startup.containerRoot,
    expectedHelperContentSha256: startup.helperContentSha256,
    releaseMode: startup.releaseMode,
    ...(startup.productionReleaseEvidence === undefined ? {} : { productionReleaseEvidence: startup.productionReleaseEvidence }),
    ...(startup.productionReleaseSignature === undefined ? {} : { productionReleaseSignature: startup.productionReleaseSignature }),
    attestationKeyId: startup.signer.keyId,
    attestationPublicKey: startup.signer.exportPublicKey(),
    attestationVerifier: startup.verifier,
    ...(startup.evidenceRef === undefined ? {} : { evidenceRef: startup.evidenceRef })
  });
}
