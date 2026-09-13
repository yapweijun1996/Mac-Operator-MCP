import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import type { DockerInspector } from "./docker-inspector.js";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default as new (options: Record<string, unknown>) => {
  compile(schema: object): ((value: unknown) => boolean) & { errors?: unknown };
  errorsText(errors: unknown): string;
};
const addFormats = require("ajv-formats").default as (ajv: InstanceType<typeof Ajv2020>) => void;
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const appId = "bundle:com.example.ContractApp";

test("implemented broker results conform to versioned success and failure schemas", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-contract-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const now = Date.now();
  const samplePath = join(directory, "sample.txt");
  const writePath = join(directory, "contract-write.txt");
  await writeFile(samplePath, "hello");
  const keyring = new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: now - 1_000, expiresAtMs: now + 60_000 }]);
  const basePolicy = createDefaultPolicy(
    "edge-1",
    true,
    ["mac.control.read", "mac.policy.explain", "mac.system.read", "mac.network.read", "mac.service.read", "mac.log.read", "mac.process.read", "mac.app.read", "mac.app.control", "mac.ui.observe", "mac.ui.control", "mac.files.read", "mac.files.search", "mac.project.read", "mac.git.read", "mac.package.read", "mac.docker.read", "mac.storage.read", "mac.files.hash", "mac.files.write", "mac.job.read", "mac.job.cancel"],
    ["edge-key-1"],
    [{ rootId: "test-root", path: directory, metadata: true, contentRead: true, write: true, denyRelativePaths: [] }],
    ["system/com.apple.logd"],
    ["system"],
    [repositoryRoot],
    ["contract-container"],
    [],
    [appId]
  );
  const writeTool = basePolicy.tools.get("mac_write_file_atomic");
  assert.ok(writeTool);
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools)
      .set("mac_write_file_atomic", { ...writeTool, enabled: true })
      .set("mac_app_open", { ...basePolicy.tools.get("mac_app_open")!, enabled: true })
      .set("mac_app_focus", { ...basePolicy.tools.get("mac_app_focus")!, enabled: true })
      .set("mac_ui_action", { ...basePolicy.tools.get("mac_ui_action")!, enabled: true })
  };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: keyring,
    now: () => now,
    dockerInspector: fakeDockerInspector(),
    appControlInspector: {
      async open(requestedAppId) {
        assert.equal(requestedAppId, appId);
        return {
          appId,
          state: "launched",
          processId: null,
          target: { kind: "app", reference: appId },
          verified: true,
          warnings: [],
          truncated: false
        };
      },
      async focus(requestedAppId) {
        assert.equal(requestedAppId, appId);
        return {
          appId,
          windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
          windowTitle: "Example",
          focused: true,
          verified: true,
          warnings: [],
          truncated: false
        };
      }
    },
    uiInspector: {
      async observe(requestedAppId) {
        assert.equal(requestedAppId, appId);
        return {
          appId,
          windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
          windowTitle: "Example",
          focused: true,
          nodes: [{
            elementRef: "element:0123456789abcdef0123456789abcdef0123456789abcdef",
            role: "AXWindow",
            label: "Example",
            enabled: true,
            focused: true,
            secure: false
          }],
          truncated: false,
          warnings: []
        };
      },
      async action(execution) {
        assert.equal(execution.snapshot.appId, appId);
        return {
          elementRef: execution.snapshot.elementRef,
          action: execution.action,
          accepted: true,
          appId,
          windowId: execution.snapshot.windowId,
          reobserved: { role: execution.snapshot.role, enabled: true, focused: false, secure: false },
          warnings: [],
          truncated: false,
          verified: true
        };
      }
    }
  });
  store.createJob({
    jobId: "job:contract",
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: "mac_task_run",
    targetRef: "task:contract",
    policyVersion: "policy-0.1",
    payloadDigest: "a".repeat(64),
    idempotencyKey: "contract-job",
    createdAtMs: now - 1_000
  });
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  try {
    const cases = [
      { tool: "mac_health", arguments: { include_components: true } },
      { tool: "mac_capabilities", arguments: {} },
      { tool: "mac_app_open", arguments: { app_id: appId } },
      { tool: "mac_app_focus", arguments: { app_id: appId, window_hint: "Example" } },
      { tool: "mac_ui_observe", arguments: { app_id: appId, max_nodes: 20 } },
      { tool: "mac_ui_action", arguments: { element_ref: "element:0123456789abcdef0123456789abcdef0123456789abcdef", action: "press" } },
      { tool: "mac_app_list", arguments: { running_only: true, include_installed: false } },
      { tool: "mac_system_summary", arguments: { include_load: true } },
      { tool: "mac_network_status", arguments: { include_listeners: true } },
      { tool: "mac_service_status", arguments: { service_id: "system/com.apple.logd" } },
      { tool: "mac_log_tail", arguments: { source: "system", lines: 5, since_seconds: 1 } },
      { tool: "mac_process_list", arguments: { limit: 20, sort: "pid" } },
      { tool: "mac_process_inspect", arguments: { pid: process.pid } },
      { tool: "mac_policy_explain", arguments: { proposed_tool: "mac_health", target: { kind: "host", reference: "broker" } } },
      { tool: "mac_stat_path", arguments: { path: samplePath, follow_symlink: true } },
      { tool: "mac_read_file", arguments: { path: samplePath, max_bytes: 5, encoding: "utf8" } },
      { tool: "mac_hash_file", arguments: { path: samplePath, algorithm: "sha256" } },
      { tool: "mac_list_directory", arguments: { path: directory, limit: 10, include_hidden: false } },
      { tool: "mac_directory_tree", arguments: { path: directory, depth: 1, max_entries: 20 } },
      { tool: "mac_find_files", arguments: { roots: [directory], query: "sample", max_results: 20 } },
      { tool: "mac_recent_files", arguments: { roots: [directory], since_seconds: 86_400, limit: 20 } },
      { tool: "mac_search_text", arguments: { roots: [directory], query: "hello", glob: "*.txt", max_results: 20 } },
      { tool: "mac_project_discover", arguments: { roots: [directory], types: ["node"], max_results: 20 } },
      { tool: "mac_project_summary", arguments: { project_root: directory, include_tree: true, tree_depth: 1 } },
      { tool: "mac_git_status", arguments: { project_root: repositoryRoot, include_untracked: false } },
      { tool: "mac_git_branch_list", arguments: { project_root: repositoryRoot, include_remote: false } },
      { tool: "mac_git_log", arguments: { project_root: repositoryRoot, limit: 5, ref: "HEAD" } },
      { tool: "mac_git_diff", arguments: { project_root: repositoryRoot, paths: ["packages/broker/src/git-inspector.ts"], staged: false, max_bytes: 65_536 } },
      { tool: "mac_package_inspect", arguments: { project_root: repositoryRoot, manager: "npm", check_outdated: false } },
      { tool: "mac_docker_status", arguments: { include_images: false, include_storage: false } },
      { tool: "mac_docker_inspect", arguments: { object_type: "container", id: "contract-container" } },
      { tool: "mac_docker_logs", arguments: { container_id: "contract-container", tail: 5, since_seconds: 1 } },
      { tool: "mac_storage_analysis", arguments: { roots: [directory], top_n: 20, max_depth: 1 } },
      { tool: "mac_write_file_atomic", arguments: { path: writePath, content: "safe", idempotency_key: "contract-write-1", encoding: "utf8", create_only: true } },
      { tool: "mac_job_status", arguments: { job_id: "job:contract", tail_bytes: 128 } },
      { tool: "mac_job_cancel", arguments: { job_id: "job:contract", reason: "contract-test" } }
    ];
    const cancelCase = cases.find((item) => item.tool === "mac_job_cancel");
    assert.ok(cancelCase);
    store.issueApproval({
      approvalId: "approval:contract-cancel",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_job_cancel",
      contractVersion: "0.1",
      targetKind: "job",
      targetRef: "job:job:contract",
      payloadDigest: sha256(canonicalJson(cancelCase.arguments)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: now - 500,
      expiresAtMs: now + 30_000
    });
    const appFocusCase = cases.find((item) => item.tool === "mac_app_focus");
    assert.ok(appFocusCase);
    store.issueApproval({
      approvalId: "approval:contract-app-focus",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_app_focus",
      contractVersion: "0.1",
      targetKind: "app_window",
      targetRef: `app_window:window:${appId}`,
      payloadDigest: sha256(canonicalJson(appFocusCase.arguments)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_gui",
      unattended: false,
      issuedAtMs: now - 500,
      expiresAtMs: now + 30_000
    });
    const uiActionCase = cases.find((item) => item.tool === "mac_ui_action");
    assert.ok(uiActionCase);
    store.issueApproval({
      approvalId: "approval:contract-ui-action",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_ui_action",
      contractVersion: "0.1",
      targetKind: "ui_element",
      targetRef: `ui_element:${uiActionCase.arguments.element_ref}`,
      payloadDigest: sha256(canonicalJson(uiActionCase.arguments)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_gui",
      unattended: false,
      issuedAtMs: now - 500,
      expiresAtMs: now + 30_000
    });
    const writeCase = cases.find((item) => item.tool === "mac_write_file_atomic");
    assert.ok(writeCase);
    store.issueApproval({
      approvalId: "approval:contract-write",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_write_file_atomic",
      contractVersion: "0.1",
      targetKind: "path",
      targetRef: "path:test-root",
      payloadDigest: sha256(canonicalJson(writeCase.arguments)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: now - 500,
      expiresAtMs: now + 30_000
    });
    const appOpenCase = cases.find((item) => item.tool === "mac_app_open");
    assert.ok(appOpenCase);
    store.issueApproval({
      approvalId: "approval:contract-app-open",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_app_open",
      contractVersion: "0.1",
      targetKind: "app",
      targetRef: `app:${appId}`,
      payloadDigest: sha256(canonicalJson(appOpenCase.arguments)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_gui",
      unattended: false,
      issuedAtMs: now - 500,
      expiresAtMs: now + 30_000
    });
    for (const [index, item] of cases.entries()) {
      const result = await broker.handle(signRequest(makeRequest(now, index, item.tool, item.arguments), key));
      const contract = JSON.parse(await readFile(join(repositoryRoot, "tool-contracts", `${item.tool}.json`), "utf8")) as {
        approval_policy: string;
        output_schema: object;
      };
      assert.equal(policy.tools.get(item.tool)?.approvalPolicy, contract.approval_policy);
      const validate = ajv.compile(contract.output_schema);
      assert.equal(validate(result), true, ajv.errorsText(validate.errors));
    }

    const deniedRequest = makeRequest(now, cases.length + 1, "mac_health", {});
    deniedRequest.principal = { ...deniedRequest.principal, scopes: ["mac.files.read"] };
    const denied = await broker.handle(signRequest(deniedRequest, key));
    const failureSchema = JSON.parse(await readFile(join(repositoryRoot, "schemas", "broker-failure.schema.json"), "utf8")) as object;
    const validateFailure = ajv.compile(failureSchema);
    assert.equal(validateFailure(denied), true, ajv.errorsText(validateFailure.errors));
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

function makeRequest(now: number, index: number, tool: string, args: Record<string, unknown>): UnsignedBrokerRequest {
  return {
    protocolVersion: "0.1",
    requestId: `contract-request-${index}`,
    contractVersion: "0.1",
    tool,
    arguments: args,
    principal: {
      principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer",
      audience: "mac-operator-broker", scopes: ["mac.control.read", "mac.policy.explain", "mac.system.read", ...(tool === "mac_network_status" ? ["mac.network.read"] : []), ...(tool === "mac_service_status" ? ["mac.service.read"] : []), ...(tool === "mac_log_tail" ? ["mac.log.read"] : []), ...(tool === "mac_process_list" || tool === "mac_process_inspect" ? ["mac.process.read"] : []), ...(tool === "mac_app_list" ? ["mac.app.read"] : []), ...(tool === "mac_app_open" || tool === "mac_app_focus" ? ["mac.app.control"] : []), ...(tool === "mac_ui_observe" ? ["mac.ui.observe"] : []), ...(tool === "mac_ui_action" ? ["mac.ui.control"] : []), "mac.files.read", ...(tool === "mac_find_files" || tool === "mac_recent_files" || tool === "mac_search_text" ? ["mac.files.search"] : []), ...(tool === "mac_project_discover" || tool === "mac_project_summary" ? ["mac.project.read"] : []), ...(tool === "mac_git_status" || tool === "mac_git_branch_list" || tool === "mac_git_log" || tool === "mac_git_diff" ? ["mac.git.read"] : []), ...(tool === "mac_package_inspect" ? ["mac.package.read"] : []), ...(tool === "mac_docker_status" || tool === "mac_docker_inspect" || tool === "mac_docker_logs" ? ["mac.docker.read"] : []), ...(tool === "mac_storage_analysis" ? ["mac.storage.read"] : []), ...(tool === "mac_hash_file" ? ["mac.files.hash"] : []), ...(tool === "mac_write_file_atomic" ? ["mac.files.write"] : []), "mac.job.read", "mac.job.cancel"] as Scope[],
      issuedAtMs: now - 1_000, expiresAtMs: now + 60_000, edgeId: "edge-1"
    },
    timestampMs: now,
    nonce: `contract-nonce-${index}`,
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: "edge-key-1"
  };
}

function fakeDockerInspector(): DockerInspector {
  return {
    async status() {
      return { daemon: { available: true, version: "27.5.1", context: "local" }, containers: [], images: [], warnings: [], truncated: false };
    },
    async inspect() {
      return { objectType: "container", id: "contract-container", name: "contract", state: "created", image: "example/app:latest", ports: [], mounts: [], warnings: [], truncated: false };
    },
    async logs() {
      return { containerId: "contract-container", entries: [], warnings: [], truncated: false };
    }
  };
}
