import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { authorizeTarget, PolicyBundleVerifier, type PolicyDocument, type SignedPolicyBundle } from "@mac-operator/broker";
import { G1_SCOPES, G1_TOOLS, O1_SCOPES, O1_TOOLS, W1_SCOPES, W1_TOOLS } from "./contracts.js";
import { assertG1Policy, assertO1Policy, assertW1Policy, buildG1TargetRules, buildO1TargetRules, buildW1TargetRules,
  w1FilesystemRoots, w1ProjectRoot, type GuiAccess } from "./w1-policy.js";

test("W1 signed policy allows one owner project and rejects widened authority", async () => {
  const root = await mkdtemp(join(homedir(), ".mac-operator-w1-test-"));
  const project = join(root, "project");
  await mkdir(project);
  await mkdir(join(project, ".git"));
  await symlink(project, join(root, "project-link"));
  try {
    assert.equal(w1ProjectRoot(project), project);
    assert.throws(() => w1ProjectRoot(join(root, "project-link")), /symlink/u);
    assert.throws(() => w1ProjectRoot(root), /Git repository/u);
    assert.throws(() => w1ProjectRoot(`${project}/../project`), /canonical/u);
    const linkedGit = join(root, "linked-git");
    await mkdir(linkedGit);
    await writeFile(join(linkedGit, ".git"), `gitdir: ${join(project, ".git")}\n`);
    assert.throws(() => w1ProjectRoot(linkedGit), /own Git directory/u);

    const now = Date.now();
    const roots = w1FilesystemRoots(project);
    const document: PolicyDocument = {
      schema_version: "0.1", revision: 1, audience: "mac-operator-broker", issued_at_ms: now,
      trusted_edge_keys: [{ edge_id: "personal-edge", key_id: "personal-edge-1", not_before_ms: now - 5_000,
        expires_at_ms: now + 60_000 }],
      principal_grants: [{ principal_id: "owner-1", issuer: "mac-operator-auth", scopes: [...W1_SCOPES], enabled: true }],
      target_rules: buildW1TargetRules("owner-1", roots, project),
      filesystem_roots: roots,
      tool_enablement: W1_TOOLS.map(tool => ({ tool, enabled: true })),
      kill_switches: { global: false, mutations: false, process: false, network: false, gui: true, destructive: true, privileged: true }
    };
    const keys = generateKeyPairSync("ed25519");
    const verifier = await PolicyBundleVerifier.create({
      schemaDirectory: join(process.cwd(), "schemas"), expectedKeyId: "personal-policy-1",
      publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" })
    });
    const verify = (value: PolicyDocument) => {
      const bytes = Buffer.from(canonicalJson(value));
      const bundle: SignedPolicyBundle = { bundle_version: "0.1", key_id: "personal-policy-1", algorithm: "Ed25519",
        payload_digest: sha256(bytes), payload: value, signature: sign(null, bytes, keys.privateKey).toString("base64") };
      return verifier.verify(bundle).policy;
    };
    const policy = verify(document);
    assert.doesNotThrow(() => assertW1Policy(policy, "owner-1", "mac-operator-auth"));
    assert.deepEqual([...policy.tools.values()].filter(tool => tool.enabled).map(tool => tool.tool).sort(), [...W1_TOOLS].sort());
    assert.equal((W1_SCOPES as readonly string[]).includes("mac.docker.read"), false);
    for (const tool of ["mac_task_run", "mac_service_control", "mac_gui_click", "mac_root_helper",
      "mac_docker_status", "mac_docker_inspect", "mac_docker_logs"] as const) {
      assert.notEqual(policy.tools.get(tool)?.enabled, true);
    }
    const widerRoots = [...roots, { root_id: "extra-write", path: root, metadata: true, content_read: true,
      write: true, deny_relative_paths: [] }];
    assert.throws(() => assertW1Policy(verify({ ...document, filesystem_roots: widerRoots }), "owner-1", "mac-operator-auth"), /filesystem roots mismatch/u);
    assert.throws(() => assertW1Policy(verify({ ...document, kill_switches: { ...document.kill_switches, gui: false } }),
      "owner-1", "mac-operator-auth"), /kill-switch boundary mismatch/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

for (const profile of ["g1", "o1"] as const) {
  test(`${profile.toUpperCase()} desktop GUI authority requires an explicit protected profile choice`, async () => {
    const root = await mkdtemp(join(homedir(), ".mac-operator-gui-policy-test-"));
    const project = join(root, "project");
    await mkdir(project); await mkdir(join(project, ".git"));
    try {
      const now = Date.now();
      const roots = w1FilesystemRoots(project);
      const build = profile === "o1" ? buildO1TargetRules : buildG1TargetRules;
      const assertProfile = profile === "o1" ? assertO1Policy : assertG1Policy;
      const scopes = profile === "o1" ? O1_SCOPES : G1_SCOPES;
      const tools = profile === "o1" ? O1_TOOLS : G1_TOOLS;
      assert.deepEqual(build("owner-1", roots, project), build("owner-1", roots, project, "browsers"));
      assert.equal(build("owner-1", roots, project).some(rule => rule.target.reference === "desktop"), false);
      const keys = generateKeyPairSync("ed25519");
      const verifier = await PolicyBundleVerifier.create({ schemaDirectory: join(process.cwd(), "schemas"), expectedKeyId: "personal-policy-1",
        publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }) });
      const document = (guiAccess: GuiAccess): PolicyDocument => ({
        schema_version: "0.1", revision: 1, audience: "mac-operator-broker", issued_at_ms: now,
        trusted_edge_keys: [{ edge_id: "personal-edge", key_id: "personal-edge-1", not_before_ms: now - 5000, expires_at_ms: now + 60_000 }],
        principal_grants: [{ principal_id: "owner-1", issuer: "mac-operator-auth", scopes: [...scopes], enabled: true }],
        target_rules: build("owner-1", roots, project, guiAccess), filesystem_roots: roots,
        tool_enablement: tools.map(tool => ({ tool, enabled: true })),
        kill_switches: { global: false, mutations: false, process: false, network: false, gui: false, destructive: true, privileged: true }
      });
      const verify = (payload: PolicyDocument) => {
        const bytes = Buffer.from(canonicalJson(payload));
        return verifier.verify({ bundle_version: "0.1", key_id: "personal-policy-1", algorithm: "Ed25519", payload,
          payload_digest: sha256(bytes), signature: sign(null, bytes, keys.privateKey).toString("base64") }).policy;
      };
      const browsers = verify(document("browsers"));
      assert.doesNotThrow(() => assertProfile(browsers, "owner-1", "mac-operator-auth"));
      assert.throws(() => authorizeTarget(browsers, "owner-1", ["mac.ui.observe"], {
        kind: "app_window", reference: "window:bundle:com.apple.TextEdit"
      }), /not allowed/u);
      assert.throws(() => assertProfile(browsers, "owner-1", "mac-operator-auth", "desktop"), /target rules mismatch/u);
      const desktopDocument = document("desktop");
      const desktop = verify(desktopDocument);
      assert.doesNotThrow(() => assertProfile(desktop, "owner-1", "mac-operator-auth", "desktop"));
      assert.throws(() => assertProfile(desktop, "owner-1", "mac-operator-auth"), /target rules mismatch/u);
      assert.doesNotThrow(() => authorizeTarget(desktop, "owner-1", ["mac.ui.observe"], {
        kind: "app_window", reference: "window:bundle:com.apple.TextEdit"
      }));
      assert.deepEqual(desktopDocument.principal_grants, document("browsers").principal_grants);
      assert.deepEqual(desktopDocument.tool_enablement, document("browsers").tool_enablement);
      assert.deepEqual(desktopDocument.filesystem_roots, document("browsers").filesystem_roots);
      assert.equal(desktop.targetRules.filter(rule => rule.target.reference === "desktop").length, 4);
      const altered = { ...desktopDocument, target_rules: desktopDocument.target_rules.map(rule => rule.rule_id === "owner-g1-desktop-observe"
        ? { ...rule, target: { kind: "app_window" as const, reference: "window:bundle:com.apple.TextEdit" } } : rule) };
      assert.throws(() => assertProfile(verify(altered), "owner-1", "mac-operator-auth", "desktop"), /target rules mismatch/u);
      assert.throws(() => build("owner-1", roots, project, "all" as GuiAccess), /GUI access mode is invalid/u);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
}
