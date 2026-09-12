import type { Scope } from "@mac-operator/contracts";
import type { BrokerPolicy, PrincipalGrant, TargetRule, ToolPolicy } from "./policy.js";
import type { FilesystemRootPolicy } from "./filesystem-inspector.js";

const tools: ToolPolicy[] = [
  {
    tool: "mac_health",
    contractVersion: "0.1",
    requiredScopes: ["mac.control.read"],
    capabilityFamilies: ["read"],
    targetType: "broker",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 65_536,
    timeoutMs: 5_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_capabilities",
    contractVersion: "0.1",
    requiredScopes: ["mac.control.read"],
    capabilityFamilies: ["read"],
    targetType: "broker",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 262_144,
    timeoutMs: 5_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_system_summary",
    contractVersion: "0.1",
    requiredScopes: ["mac.system.read"],
    capabilityFamilies: ["read"],
    targetType: "broker",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 131_072,
    timeoutMs: 5_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_network_status",
    contractVersion: "0.1",
    requiredScopes: ["mac.network.read"],
    capabilityFamilies: ["network"],
    targetType: "broker",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 262_144,
    timeoutMs: 5_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_service_status",
    contractVersion: "0.1",
    requiredScopes: ["mac.service.read"],
    capabilityFamilies: ["read"],
    targetType: "service",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 131_072,
    timeoutMs: 5_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_log_tail",
    contractVersion: "0.1",
    requiredScopes: ["mac.log.read"],
    capabilityFamilies: ["read"],
    targetType: "log_source",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 524_288,
    timeoutMs: 10_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_process_list",
    contractVersion: "0.1",
    requiredScopes: ["mac.process.read"],
    capabilityFamilies: ["process"],
    targetType: "process",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 262_144,
    timeoutMs: 5_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_process_inspect",
    contractVersion: "0.1",
    requiredScopes: ["mac.process.read"],
    capabilityFamilies: ["process"],
    targetType: "process",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 131_072,
    timeoutMs: 5_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_policy_explain",
    contractVersion: "0.1",
    requiredScopes: ["mac.policy.explain"],
    capabilityFamilies: ["read"],
    targetType: "policy_query",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 131_072,
    timeoutMs: 5_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_stat_path",
    contractVersion: "0.1",
    requiredScopes: ["mac.files.read"],
    capabilityFamilies: ["read"],
    targetType: "path",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 131_072,
    timeoutMs: 5_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_read_file",
    contractVersion: "0.1",
    requiredScopes: ["mac.files.read"],
    capabilityFamilies: ["read"],
    targetType: "path",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 1_200_000,
    timeoutMs: 10_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_hash_file",
    contractVersion: "0.1",
    requiredScopes: ["mac.files.hash"],
    capabilityFamilies: ["read"],
    targetType: "path",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 131_072,
    timeoutMs: 30_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_list_directory",
    contractVersion: "0.1",
    requiredScopes: ["mac.files.read"],
    capabilityFamilies: ["read"],
    targetType: "path",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 262_144,
    timeoutMs: 5_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_directory_tree",
    contractVersion: "0.1",
    requiredScopes: ["mac.files.read"],
    capabilityFamilies: ["read"],
    targetType: "path",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 524_288,
    timeoutMs: 10_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_find_files",
    contractVersion: "0.1",
    requiredScopes: ["mac.files.search"],
    capabilityFamilies: ["read"],
    targetType: "filesystem_roots",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 524_288,
    timeoutMs: 20_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_recent_files",
    contractVersion: "0.1",
    requiredScopes: ["mac.files.search"],
    capabilityFamilies: ["read"],
    targetType: "filesystem_roots",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 262_144,
    timeoutMs: 20_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_search_text",
    contractVersion: "0.1",
    requiredScopes: ["mac.files.search"],
    capabilityFamilies: ["read"],
    targetType: "filesystem_roots",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 524_288,
    timeoutMs: 30_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_project_discover",
    contractVersion: "0.1",
    requiredScopes: ["mac.project.read"],
    capabilityFamilies: ["read"],
    targetType: "filesystem_roots",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 524_288,
    timeoutMs: 30_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_project_summary",
    contractVersion: "0.1",
    requiredScopes: ["mac.project.read"],
    capabilityFamilies: ["read"],
    targetType: "path",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 524_288,
    timeoutMs: 15_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_storage_analysis",
    contractVersion: "0.1",
    requiredScopes: ["mac.storage.read"],
    capabilityFamilies: ["read"],
    targetType: "filesystem_roots",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 524_288,
    timeoutMs: 30_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_write_file_atomic",
    contractVersion: "0.1",
    requiredScopes: ["mac.files.write"],
    capabilityFamilies: ["write"],
    targetType: "path",
    mutation: true,
    approvalPolicy: "trusted_write",
    outputCapBytes: 1_048_576,
    timeoutMs: 30_000,
    implemented: true,
    enabled: false
  },
  {
    tool: "mac_job_status",
    contractVersion: "0.1",
    requiredScopes: ["mac.job.read"],
    capabilityFamilies: ["read"],
    targetType: "job",
    mutation: false,
    approvalPolicy: "trusted_read",
    outputCapBytes: 600_000,
    timeoutMs: 5_000,
    implemented: true,
    enabled: true
  },
  {
    tool: "mac_job_cancel",
    contractVersion: "0.1",
    requiredScopes: ["mac.job.cancel"],
    capabilityFamilies: ["process"],
    targetType: "job",
    mutation: true,
    approvalPolicy: "trusted_write",
    outputCapBytes: 131_072,
    timeoutMs: 10_000,
    implemented: true,
    enabled: true
  }
];

export function createDefaultPolicy(
  edgeId: string,
  enableReadTools = false,
  principalScopes: readonly Scope[] = [],
  trustedKeyIds: readonly string[] = ["edge-key-1"],
  filesystemRoots: readonly FilesystemRootPolicy[] = [],
  serviceIds: readonly string[] = [],
  logSources: readonly string[] = []
): BrokerPolicy {
  const grants = new Map<string, PrincipalGrant>();
  if (principalScopes.length > 0) {
    grants.set("principal-1", {
      principalId: "principal-1",
      issuer: "test-issuer",
      scopes: principalScopes,
      enabled: true
    });
  }
  const targetRules: TargetRule[] = [];
  principalScopes.forEach((scope, index) => {
    if (scope === "mac.files.read" || scope === "mac.files.search" || scope === "mac.files.hash" || scope === "mac.files.write" || scope === "mac.project.read" || scope === "mac.storage.read") {
      filesystemRoots.filter((root) => scope === "mac.files.write" ? root.write === true : scope === "mac.files.search" || scope === "mac.project.read" || scope === "mac.storage.read" ? root.metadata === true : root.metadata || root.contentRead === true).forEach((root, rootIndex) => targetRules.push({
        ruleId: `test-path-${index}-${rootIndex}`,
        effect: "allow",
        principalId: "principal-1",
        scope,
        target: { kind: "path", reference: root.rootId }
      }));
      return;
    }
    if (scope === "mac.job.read" || scope === "mac.job.cancel") {
      targetRules.push({
        ruleId: `test-job-${index}`,
        effect: "allow",
        principalId: "principal-1",
        scope,
        target: { kind: "job", reference: "owned" }
      });
      return;
    }
    if (scope === "mac.process.read") {
      targetRules.push({
        ruleId: `test-process-${index}`,
        effect: "allow",
        principalId: "principal-1",
        scope,
        target: { kind: "process", reference: "all" }
      });
      return;
    }
    if (scope === "mac.service.read") {
      serviceIds.forEach((serviceId, serviceIndex) => targetRules.push({
        ruleId: `test-service-${index}-${serviceIndex}`,
        effect: "allow",
        principalId: "principal-1",
        scope,
        target: { kind: "service", reference: serviceId }
      }));
      return;
    }
    if (scope === "mac.log.read") {
      logSources.forEach((source, sourceIndex) => targetRules.push({
        ruleId: `test-log-${index}-${sourceIndex}`,
        effect: "allow",
        principalId: "principal-1",
        scope,
        target: { kind: "log_source", reference: source }
      }));
      return;
    }
    targetRules.push({
      ruleId: `test-host-${index}`,
      effect: "allow",
      principalId: "principal-1",
      scope,
      target: { kind: "host", reference: "broker" }
    });
  });
  return {
    revision: 0,
    version: "policy-0.1",
    audience: "mac-operator-broker",
    trustedEdgeIds: new Set([edgeId]),
    trustedEdgeKeys: new Map(trustedKeyIds.map((keyId) => [
      `${edgeId}:${keyId}`,
      { notBeforeMs: 0, expiresAtMs: Number.MAX_SAFE_INTEGER }
    ])),
    principalGrants: grants,
    targetRules,
    filesystemRoots: filesystemRoots.map((root) => ({ ...root, denyRelativePaths: [...root.denyRelativePaths] })),
    killSwitches: {
      global: false,
      mutations: false,
      process: false,
      network: false,
      gui: false,
      destructive: false,
      privileged: false
    },
    tools: new Map(tools.map((tool) => [tool.tool, {
      ...tool,
      enabled: enableReadTools && (tool.tool === "mac_job_cancel" || !tool.mutation)
    }]))
  };
}
