import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:net";
import { chmod, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  buildMacOsAuthorityInstallPlan,
  composeMacOsAuthorityInstallReadback,
  readMacOsOwnerSocketReadback
} from "./macos-install-plan.js";

const base = {
  operation: "install" as const,
  uid: 501,
  userHome: "/Users/operator",
  installRoot: "/Users/operator/MacOperator",
  plistPath: "/Users/operator/Library/LaunchAgents/com.mac-operator.authority.plist",
  service: {
    label: "com.mac-operator.authority",
    program: "/Users/operator/MacOperator/node",
    programArguments: [
      "/Users/operator/MacOperator/node",
      "/Users/operator/MacOperator/authority-control-service.js",
      "--config",
      "/Users/operator/MacOperator/broker-service.json"
    ],
    workingDirectory: "/Users/operator/MacOperator",
    stdoutPath: "/Users/operator/MacOperator/logs/authority.out.log",
    stderrPath: "/Users/operator/MacOperator/logs/authority.err.log",
    runAtLoad: true,
    keepAlive: true,
    throttleIntervalSeconds: 5
  },
  metadata: {
    component: "mac-operator-authority" as const,
    sourceRevision: "0123456789abcdef0123456789abcdef01234567",
    contractVersion: "0.1",
    policyVersion: "policy-1"
  },
  signature: { identifier: "com.mac-operator.authority" },
  signaturePolicy: "development-ad-hoc" as const,
  signedArtifactPath: "/Users/operator/MacOperator/node",
  enabledCapabilities: [],
  authorityConfigPath: "/Users/operator/MacOperator/broker-service.json",
  authorityOperatorSocketPath: "/Users/operator/MacOperator/run/authority-operator.sock"
};

test("Authority LaunchAgent plan binds the stable proxy entrypoint and rollback actions", () => {
  const plan = buildMacOsAuthorityInstallPlan(base);
  assert.equal(plan.component, "mac-operator-authority");
  assert.equal(plan.label, "com.mac-operator.authority");
  assert.equal(plan.authorityConfigPath, base.authorityConfigPath);
  assert.equal(plan.authorityOperatorSocketPath, base.authorityOperatorSocketPath);
  assert.deepEqual(plan.launchd.programArguments, base.service.programArguments);
  assert.equal(plan.install.file.kind, "write-plist");
  assert.equal(plan.rollback.file.kind, "restore-plist");
  assert.equal(plan.uninstall.file.kind, "remove-plist");
  assert.equal(plan.install.bootstrap.args[0], "bootstrap");
  assert.equal(plan.rollback.bootout.args[0], "bootout");
});

test("Authority LaunchAgent plan rejects config substitution and capabilities", () => {
  assert.throws(
    () => buildMacOsAuthorityInstallPlan({ ...base, authorityConfigPath: "/Users/operator/other.json" }),
    /fixed broker-service\.json configuration and operator socket paths/u
  );
  assert.throws(
    () => buildMacOsAuthorityInstallPlan({ ...base, enabledCapabilities: ["mac_health"] }),
    /must not (?:enable capabilities|advertise MCP capabilities)/u
  );
});

test("Authority readback binds launchd, process, plist, signature, and operator socket identity", () => {
  const plan = buildMacOsAuthorityInstallPlan(base);
  const pid = 4242;
  const sources = {
    launchd: {
      serviceId: `${plan.domain}/${plan.label}`,
      domain: plan.domain as `gui/${number}`,
      label: plan.label,
      state: "running" as const,
      pid,
      program: plan.launchd.program,
      arguments: [...plan.launchd.programArguments],
      plistPath: plan.plistPath,
      type: "LaunchAgent" as const,
      lastExitCode: 0,
      truncated: false as const
    },
    processIdentity: { pid, startTimeMicros: 987654321 },
    plist: {
      path: plan.plistPath,
      bytes: Buffer.byteLength(plan.renderedPlist, "utf8"),
      sha256: createHash("sha256").update(plan.renderedPlist, "utf8").digest("hex"),
      device: "1",
      inode: "2"
    },
    operatorSocket: {
      path: base.authorityOperatorSocketPath,
      ownerUid: 501,
      mode: 0o600,
      device: 1,
      inode: 3
    },
    signature: {
      artifactPath: plan.signedArtifactPath,
      valid: true as const,
      identifier: plan.signature.identifier,
      teamIdentifier: null,
      cdHash: null,
      signatureType: "development-ad-hoc" as const,
      authority: null
    }
  };
  const readback = composeMacOsAuthorityInstallReadback(plan, sources);
  assert.equal(readback.authority.component, "mac-operator-authority");
  assert.equal(readback.authority.operatorSocketPath, base.authorityOperatorSocketPath);
  assert.equal(readback.processIdentity.startTimeMicros, 987654321);
});

test("owner socket readback binds type, owner-only mode, and stable identity", async (t) => {
  if (process.platform === "win32") {
    t.skip("Unix socket readback is not available on Windows");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-owner-socket-"));
  const socketPath = join(directory, "authority.sock");
  const linkPath = join(directory, "authority-link.sock");
  const server = createServer();
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, resolve);
    });
    await chmod(socketPath, 0o600);
    const ownerUid = process.getuid?.();
    if (ownerUid === undefined) throw new Error("owner UID is unavailable");
    const readback = await readMacOsOwnerSocketReadback(socketPath, ownerUid);
    assert.deepEqual(readback, {
      path: socketPath,
      ownerUid,
      mode: 0o600,
      device: readback.device,
      inode: readback.inode
    });
    await symlink(socketPath, linkPath);
    await assert.rejects(readMacOsOwnerSocketReadback(linkPath, ownerUid), /owner socket|identity|unsafe/u);

    const realRoot = join(directory, "r");
    const realRun = join(realRoot, "u");
    await mkdir(realRun, { recursive: true, mode: 0o700 });
    const nestedSocketPath = join(realRun, "s.sock");
    const nestedServer = createServer();
    await new Promise<void>((resolve, reject) => {
      nestedServer.once("error", reject);
      nestedServer.listen(nestedSocketPath, resolve);
    });
    await chmod(nestedSocketPath, 0o600);
    const aliasRoot = join(directory, "a");
    await symlink(realRoot, aliasRoot);
    try {
      await assert.rejects(
        readMacOsOwnerSocketReadback(join(aliasRoot, "u", "s.sock"), ownerUid),
        /owner socket|parent chain|unsafe/u
      );
    } finally {
      await new Promise<void>((resolve) => nestedServer.close(() => resolve()));
    }
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});
