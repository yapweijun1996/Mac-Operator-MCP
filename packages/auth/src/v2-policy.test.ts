import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, relative } from "node:path";
import test from "node:test";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { FilesystemInspector, PolicyBundleVerifier, type PolicyDocument, type SignedPolicyBundle } from "@mac-operator/broker";
import { configSchema, O1_SCOPES, O1_TOOLS, OAUTH_SCOPES, recordSchemas, scopesForGrantProfile, V2_SCOPES, V2_CODING_SCOPES, V2_TOOLS } from "./contracts.js";
import { assertO1Policy, buildO1TargetRules, w1FilesystemRoots } from "./w1-policy.js";
import { assertV2Policy, buildV2PolicyDocument, buildV2TargetRules, v2FilesystemRoots, type V2PolicyConfiguration } from "./v2-policy.js";

async function fixture() {
  const root = await mkdtemp(join(homedir(), ".mac-operator-v2-test-"));
  const ownerProject = join(root, "Mac-Operator-MCP");
  const developmentProject = join(root, "YAP-MCP");
  const otherProject = join(root, "other-project");
  const stateRoot = join(root, "private-state");
  const worktreeRoot = join(root, "all-worktrees");
  for (const directory of [ownerProject, developmentProject, otherProject, stateRoot, worktreeRoot]) await mkdir(directory);
  for (const project of [ownerProject, developmentProject, otherProject]) await mkdir(join(project, ".git"));
  const config: V2PolicyConfiguration = { developmentProjects: [developmentProject], stateRoot, worktreeRoot, taskProfiles: ["yap.test", "yap.build"] };
  const now = Date.now();
  const roots = w1FilesystemRoots(ownerProject);
  const base: PolicyDocument = { schema_version: "0.1", revision: 10, audience: "mac-operator-broker", issued_at_ms: now,
    trusted_edge_keys: [{ edge_id: "personal-edge", key_id: "personal-edge-1", not_before_ms: now - 5_000, expires_at_ms: now + 60_000 }],
    principal_grants: [{ principal_id: "owner-1", issuer: "mac-operator-auth", scopes: [...O1_SCOPES], enabled: true }],
    target_rules: buildO1TargetRules("owner-1", roots, ownerProject), filesystem_roots: roots,
    tool_enablement: O1_TOOLS.map(tool => ({ tool, enabled: true })),
    kill_switches: { global: false, mutations: false, process: false, network: false, gui: false, destructive: true, privileged: true } };
  const keys = generateKeyPairSync("ed25519");
  const verifier = await PolicyBundleVerifier.create({ schemaDirectory: join(process.cwd(), "schemas"), expectedKeyId: "personal-policy-1",
    publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }) });
  const verify = (document: PolicyDocument) => {
    const bytes = Buffer.from(canonicalJson(document));
    const bundle: SignedPolicyBundle = { bundle_version: "0.1", key_id: "personal-policy-1", algorithm: "Ed25519",
      payload_digest: sha256(bytes), payload: document, signature: sign(null, bytes, keys.privateKey).toString("base64") };
    return verifier.verify(bundle).policy;
  };
  return { root, ownerProject, developmentProject, otherProject, stateRoot, worktreeRoot, config, base, verify,
    document: () => buildV2PolicyDocument(base, "owner-1", "mac-operator-auth", config),
    close: () => rm(root, { recursive: true, force: true }) };
}

test("V2 grant profile adds exactly the development authority while O1 remains unchanged", () => {
  assert.equal(V2_TOOLS.length, 50); assert.equal(O1_TOOLS.length, 39);
  assert.deepEqual(scopesForGrantProfile("v2"), V2_CODING_SCOPES); assert.equal(V2_CODING_SCOPES.includes("mac.terminal.exec" as never), false); assert.deepEqual(scopesForGrantProfile("o1"), O1_SCOPES);
  assert.equal(new Set(OAUTH_SCOPES).size, OAUTH_SCOPES.length); assert.equal(new Set(V2_TOOLS).size, V2_TOOLS.length);
  for (const name of ["mac_git_push", "mac_service_control", "mac_package_install"]) assert.equal((V2_TOOLS as readonly string[]).includes(name), false);
  for (const scope of ["mac.git.push", "mac.service.control", "mac.package.install", "mac.privileged.run"]) assert.equal((V2_SCOPES as readonly string[]).includes(scope), false);
  assert.equal((O1_SCOPES as readonly string[]).includes("mac.task.run"), false);
  const config = configSchema.parse({ version: 1, issuer: "https://mac.example/", resource: "https://mac.example/mcp",
    issuerId: "mac-operator-auth", principalId: "owner-1", keyId: "key-1", port: 3444, allowedRedirectUris: ["https://chat.example/callback"], grantProfile: "v2" });
  assert.equal(config.grantProfile, "v2");
  const grant = recordSchemas.grant.parse({ clientId: "client-1", principalId: "owner-1", scopes: [...V2_SCOPES], expiresAt: 100, revoked: false });
  assert.deepEqual(grant.scopes, V2_SCOPES);
});

test("signed V2 policy matches fixed projects, finite task profiles and enabled tools", async () => {
  const f = await fixture();
  try {
    const document = f.document();
    const policy = f.verify(document);
    assert.doesNotThrow(() => assertV2Policy(policy, "owner-1", "mac-operator-auth", f.config));
    assert.deepEqual([...policy.tools.values()].filter(tool => tool.enabled).map(tool => tool.tool).sort(), [...V2_TOOLS].sort());
    const taskRule = policy.targetRules.find(rule => rule.ruleId === "owner-v2-task-profiles")!;
    assert.deepEqual(taskRule.targetConstraint, { mode: "finite_set", references: ["yap.build", "yap.test"] });
    for (const scope of ["mac.agent.read", "mac.agent.run", "mac.audit.read", "mac.task.run"] as const) {
      const rules = policy.targetRules.filter(rule => rule.scope === scope && rule.target.kind === "project");
      assert.deepEqual(rules.map(rule => rule.target.reference), [f.developmentProject]);
    }
    assert.equal(document.revision, f.base.revision); assert.equal(document.issued_at_ms, f.base.issued_at_ms);
    assert.deepEqual(document.trusted_edge_keys, f.base.trusted_edge_keys);
    assert.equal(f.base.principal_grants[0]?.scopes.includes("mac.agent.run"), false);
  } finally { await f.close(); }
});

test("V2 filesystem roots deny private state and all task storage under both home and slash", async () => {
  const f = await fixture();
  try {
    const roots = v2FilesystemRoots(f.ownerProject, f.config);
    for (const path of [homedir(), "/"]) {
      const root = roots.find(candidate => candidate.path === path)!;
      assert.equal(root.deny_relative_paths.includes(relative(path, f.stateRoot)), true);
      assert.equal(root.deny_relative_paths.includes(relative(path, f.worktreeRoot)), true);
    }
    await writeFile(join(f.stateRoot, "control-state.json"), "{}");
    await writeFile(join(f.worktreeRoot, "task-metadata.json"), "{}");
    const policy = f.verify(f.document());
    const inspector = new FilesystemInspector(policy.filesystemRoots);
    for (const path of [f.stateRoot, f.worktreeRoot, join(f.stateRoot, "control-state.json"), join(f.worktreeRoot, "task-metadata.json")]) {
      assert.throws(() => inspector.planPath(path, "metadata"));
      assert.throws(() => inspector.planPath(path, "content_read"));
    }
    assert.doesNotThrow(() => inspector.planPath(join(f.developmentProject, "README.md"), "write"));
    assert.equal(policy.filesystemRoots.find(root => root.path === f.developmentProject)?.write, true);
  } finally { await f.close(); }
});

test("protected storage inside the owner source is denied by every covering source root", async () => {
  const f = await fixture();
  try {
    const nestedState = join(f.ownerProject, "private-task-state"); await mkdir(nestedState);
    const config = { ...f.config, stateRoot: nestedState };
    const roots = v2FilesystemRoots(f.ownerProject, config);
    const owner = roots.find(root => root.root_id === "owner-project")!;
    assert.deepEqual(owner.deny_relative_paths, ["private-task-state"]);
    for (const root of roots.filter(root => root.path === "/" || root.path === homedir())) {
      assert.equal(root.deny_relative_paths.includes(relative(root.path, nestedState)), true);
    }
    const document = buildV2PolicyDocument(f.base, "owner-1", "mac-operator-auth", config);
    assert.doesNotThrow(() => assertV2Policy(f.verify(document), "owner-1", "mac-operator-auth", config));
  } finally { await f.close(); }
});

test("strict V2 assertion rejects widened scopes, extra tools and revoked grant boundaries", async () => {
  const f = await fixture();
  try {
    const document = f.document();
    const widened = { ...document, principal_grants: document.principal_grants.map(grant => ({ ...grant, scopes: [...grant.scopes, "mac.git.push" as const] })) };
    assert.throws(() => assertV2Policy(f.verify(widened), "owner-1", "mac-operator-auth", f.config), /grant mismatch/u);
    for (const tool of ["mac_git_push", "mac_service_control"] as const) {
      const widenedTools = { ...document, tool_enablement: [...document.tool_enablement, { tool, enabled: true }] };
      assert.throws(() => assertV2Policy(f.verify(widenedTools), "owner-1", "mac-operator-auth", f.config), /tool set mismatch/u);
    }
    const disabled = { ...document, principal_grants: document.principal_grants.map(grant => ({ ...grant, enabled: false })) };
    assert.throws(() => assertV2Policy(f.verify(disabled), "owner-1", "mac-operator-auth", f.config), /grant mismatch/u);
    assert.throws(() => assertV2Policy(f.verify(document), "another-owner", "mac-operator-auth", f.config), /grant mismatch/u);
  } finally { await f.close(); }
});

test("signed policy cannot remove ancestor deny paths or introduce new filesystem roots", async () => {
  const f = await fixture();
  try {
    const document = f.document();
    for (const rootId of ["owner-home", "system-metadata"]) {
      const altered = { ...document, filesystem_roots: document.filesystem_roots.map(root => root.root_id === rootId ? { ...root, deny_relative_paths: [] } : root) };
      assert.throws(() => assertV2Policy(f.verify(altered), "owner-1", "mac-operator-auth", f.config), /filesystem roots mismatch/u);
    }
    const extra = { ...document, filesystem_roots: [...document.filesystem_roots, { root_id: "unapproved-source", path: f.otherProject,
      metadata: true, content_read: true, write: true, deny_relative_paths: [] }] };
    assert.throws(() => assertV2Policy(f.verify(extra), "owner-1", "mac-operator-auth", f.config), /filesystem roots mismatch/u);
    const widenedRoot = { ...document, filesystem_roots: document.filesystem_roots.map(root => root.root_id === "gateway-project-0" ? { ...root, path: f.root } : root) };
    assert.throws(() => assertV2Policy(f.verify(widenedRoot), "owner-1", "mac-operator-auth", f.config), /filesystem roots mismatch/u);
  } finally { await f.close(); }
});

test("signed policy cannot widen agent projects or finite named task grants", async () => {
  const f = await fixture();
  try {
    const document = f.document();
    const extra = { ...document, target_rules: [...document.target_rules, { rule_id: "agent-unapproved-project", principal_id: "owner-1",
      effect: "allow" as const, scope: "mac.agent.run" as const, target: { kind: "project" as const, reference: f.otherProject } }] };
    assert.throws(() => assertV2Policy(f.verify(extra), "owner-1", "mac-operator-auth", f.config), /target rules mismatch/u);
    const finite = { ...document, target_rules: document.target_rules.map(rule => rule.rule_id === "owner-v2-task-profiles" ?
      { ...rule, target_constraint: { mode: "finite_set" as const, references: ["unapproved.shell", "yap.build", "yap.test"] } } : rule) };
    assert.throws(() => assertV2Policy(f.verify(finite), "owner-1", "mac-operator-auth", f.config), /target rules mismatch/u);
    assert.throws(() => assertV2Policy(f.verify(document), "owner-1", "mac-operator-auth", { ...f.config, developmentProjects: [f.otherProject] }), /filesystem roots mismatch/u);
  } finally { await f.close(); }
});

test("V2 kill switches keep destructive and privileged operations denied", async () => {
  const f = await fixture();
  try {
    const document = f.document();
    for (const key of ["destructive", "privileged", "gui", "network"] as const) {
      const altered = { ...document, kill_switches: { ...document.kill_switches, [key]: !document.kill_switches[key] } };
      assert.throws(() => assertV2Policy(f.verify(altered), "owner-1", "mac-operator-auth", f.config), /kill-switch boundary mismatch/u);
    }
  } finally { await f.close(); }
});

test("V2 configuration rejects symlinks, traversal, primary storage and unapproved task authority shapes", async () => {
  const f = await fixture();
  try {
    const linkedState = join(f.root, "state-link"); await symlink(f.stateRoot, linkedState);
    const linkedProject = join(f.root, "project-link"); await symlink(f.developmentProject, linkedProject);
    for (const config of [
      { ...f.config, developmentProjects: [] }, { ...f.config, developmentProjects: [f.developmentProject, f.developmentProject] },
      { ...f.config, developmentProjects: [linkedProject] }, { ...f.config, stateRoot: linkedState },
      { ...f.config, stateRoot: f.ownerProject }, { ...f.config, worktreeRoot: f.root },
      { ...f.config, taskProfiles: [] }, { ...f.config, taskProfiles: ["../shell"] },
      { ...f.config, taskProfiles: ["duplicate", "duplicate"] }, { ...f.config, stateRoot: `${f.stateRoot}/../private-state` },
      { ...f.config, scopes: ["mac.git.push"] }, Object.create(f.config)
    ]) assert.throws(() => v2FilesystemRoots(f.ownerProject, config));
    const roots = v2FilesystemRoots(f.ownerProject, f.config);
    assert.throws(() => buildV2TargetRules("owner-1", roots.map(root => ({ ...root, deny_relative_paths: [] })), f.ownerProject, f.config));
  } finally { await f.close(); }
});

test("existing signed O1 policy remains accepted only by its unchanged strict checker", async () => {
  const f = await fixture();
  try {
    const legacy = f.verify(f.base);
    assert.doesNotThrow(() => assertO1Policy(legacy, "owner-1", "mac-operator-auth"));
    assert.throws(() => assertV2Policy(legacy, "owner-1", "mac-operator-auth", f.config), /grant mismatch/u);
    assert.throws(() => assertO1Policy(f.verify(f.document()), "owner-1", "mac-operator-auth"), /grant mismatch/u);
  } finally { await f.close(); }
});
