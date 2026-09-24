import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  buildRootHelperSnapshotPackagePlan,
  RootHelperSnapshotPackageError,
  type RootHelperSnapshotPackagePlanInput
} from "./root-helper-snapshot-package.js";
import {
  collectRootHelperSnapshotPackageReadbackSources,
  createRootHelperSnapshotPackageHostObserver,
  executeRootHelperSnapshotPackagePlan,
  readRootHelperSnapshotPackageSocketReadbacks,
  validateRootHelperSnapshotPackageReadback
} from "./root-helper-snapshot-package-executor.js";
import type { RootHelperSnapshotReleaseEvidence } from "./root-helper-snapshot-release.js";

const root = "/Library/Application Support/MacOperator/RootHelper";
const program = `${root}/bin/root-helper-snapshot`;
const signature = {
  identifier: "com.mac-operator.root-helper-snapshot",
  teamIdentifier: "ABCDE12345",
  cdHash: "0123456789abcdef0123456789abcdef01234567"
} as const;
const releaseEvidence: RootHelperSnapshotReleaseEvidence = {
  artifact: {
    artifactPath: program,
    sha256: "a".repeat(64),
    bytes: 1,
    files: 1,
    directories: 0,
    device: "1",
    inode: "2",
    mode: 0o755
  },
  signature: {
    artifactPath: program,
    valid: true,
    identifier: signature.identifier,
    teamIdentifier: signature.teamIdentifier,
    cdHash: signature.cdHash,
    signatureType: "developer-id",
    authority: "Developer ID Application: Test (ABCDE12345)"
  },
  notarization: {
    artifactPath: program,
    assessed: true,
    source: "Notarized Developer ID",
    teamIdentifier: signature.teamIdentifier,
    origin: "Developer ID Application: Test (ABCDE12345)"
  },
  policy: "developer-id-notarized"
};

const base: RootHelperSnapshotPackagePlanInput = {
  helperRoot: root,
  service: {
    label: "com.mac-operator.root-helper-snapshot",
    program,
    programArguments: [program, "--config", `${root}/etc/runtime.json`],
    workingDirectory: root,
    stdoutPath: `${root}/log/stdout.log`,
    stderrPath: `${root}/log/stderr.log`
  },
  signedArtifactPath: program,
  signature,
  releaseEvidence,
  helperKeyConfigPath: `${root}/etc/helper-key.json`,
  attestationPublicKeyConfigPath: `${root}/etc/attestation-keys.json`,
  snapshotRoot: `${root}/snapshots`,
  socketPath: "/var/run/mac-operator/root-helper-snapshot.sock",
  brokerSocketPath: "/Users/yapweijun/Library/Application Support/MacOperator/broker.sock",
  authoritySocketPath: "/Users/yapweijun/Library/Application Support/MacOperator/root-helper-authority.sock",
  reservedSocketPaths: ["/var/run/mac-operator/root-helper-authority.sock"],
  brokerPeer: { uid: 501, gid: 20 },
  sourceRevision: "0123456789abcdef0123456789abcdef01234567",
  contractVersion: "0.1",
  policyVersion: "0.1",
  evidenceRef: "evidence:root-helper-snapshot-v1"
};

test("root-helper snapshot package plan is a distinct native root LaunchDaemon", () => {
  const plan = buildRootHelperSnapshotPackagePlan(base);

  assert.equal(plan.domain, "system");
  assert.equal(plan.label, "com.mac-operator.root-helper-snapshot");
  assert.equal(plan.plistPath, "/Library/LaunchDaemons/com.mac-operator.root-helper-snapshot.plist");
  assert.equal(plan.launchd.runsAsRoot, true);
  assert.equal(plan.launchd.usesEnvironmentVariables, false);
  assert.equal(plan.launchd.usesShell, false);
  assert.equal(plan.statusSocketPath, `${base.socketPath}.status`);
  assert.match(plan.renderedPlist, /<key>UserName<\/key><string>root<\/string>/u);
  assert.match(plan.renderedPlist, /com\.mac-operator\.root-helper-snapshot/u);
  assert.deepEqual(plan.install.bootstrap.args, ["bootstrap", "system", plan.plistPath]);
  assert.deepEqual(plan.rollback.bootout.args, ["bootout", "system/com.mac-operator.root-helper-snapshot"]);
  assert.equal(plan.signatureVerify.executable, "/usr/bin/codesign");
  assert.equal(plan.notarizationAssess.executable, "/usr/sbin/spctl");
  assert.equal(plan.reservedSocketPaths.length, 1);
  assert.equal(plan.attestationPublicKeyConfigPath, `${root}/etc/attestation-keys.json`);
});

test("root-helper snapshot package plan requires a native signed artifact and exact root domain", () => {
  assert.throws(
    () => buildRootHelperSnapshotPackagePlan({
      ...base,
      service: { ...base.service, program: `${root}/bin/root-helper.js`, programArguments: [`${root}/bin/root-helper.js`] },
      signedArtifactPath: `${root}/bin/root-helper.js`
    }),
    (error: unknown) => error instanceof RootHelperSnapshotPackageError && error.code === "INVALID_PACKAGE_PATH"
  );
  assert.throws(
    () => buildRootHelperSnapshotPackagePlan({ ...base, plistPath: "/Users/yapweijun/Library/LaunchAgents/root-helper.plist" }),
    (error: unknown) => error instanceof RootHelperSnapshotPackageError && error.code === "INVALID_ROOT_DOMAIN"
  );
  assert.throws(
    () => buildRootHelperSnapshotPackagePlan({ ...base, brokerSocketPath: base.socketPath }),
    (error: unknown) => error instanceof RootHelperSnapshotPackageError && error.code === "INVALID_SOCKET_BOUNDARY"
  );
});

test("root-helper snapshot package plan keeps the attestation key config inside the protected package", () => {
  assert.throws(
    () => buildRootHelperSnapshotPackagePlan({ ...base, attestationPublicKeyConfigPath: "/tmp/root-helper-attestation-keys.json" }),
    (error: unknown) => error instanceof RootHelperSnapshotPackageError && error.code === "INVALID_PACKAGE_PATH"
  );
});

test("root-helper package socket readback binds each endpoint to its planned owner", async () => {
  const observed: Array<[string, number, number | undefined, string]> = [];
  const sockets = await readRootHelperSnapshotPackageSocketReadbacks(planForTest(), async (path, uid, gid, label) => {
    observed.push([path, uid, gid, label]);
    return { path, ownerUid: uid, ownerGid: gid ?? 0, mode: 0o600, device: 1, inode: observed.length };
  });

  assert.deepEqual(observed, [
    [base.socketPath, 0, 0, "root-helper"],
    [planForTest().statusSocketPath, 0, 0, "root-helper status"],
    [base.brokerSocketPath, base.brokerPeer.uid, base.brokerPeer.gid, "Broker"],
    [base.authoritySocketPath, base.brokerPeer.uid, base.brokerPeer.gid, "root-helper authority"]
  ]);
  assert.equal(sockets.rootHelperSocket.path, base.socketPath);
  assert.equal(sockets.brokerSocket.path, base.brokerSocketPath);
  assert.equal(sockets.authoritySocket.path, base.authoritySocketPath);
});

test("root-helper host observer independently samples launchd, process credentials, and plist", async () => {
  const plan = planForTest();
  const launchd = {
    serviceId: "system/com.mac-operator.root-helper-snapshot",
    domain: "system" as const,
    label: "com.mac-operator.root-helper-snapshot",
    state: "running" as const,
    type: "LaunchDaemon" as const,
    pid: 42,
    program,
    arguments: [...plan.launchd.programArguments],
    plistPath: plan.plistPath,
    lastExitCode: null,
    truncated: false as const
  };
  const plist = {
    path: plan.plistPath,
    bytes: Buffer.byteLength(plan.renderedPlist, "utf8"),
    sha256: createHash("sha256").update(plan.renderedPlist, "utf8").digest("hex"),
    device: "1",
    inode: "2"
  };
  const observer = createRootHelperSnapshotPackageHostObserver(plan, {
    readReleaseEvidence: async () => releaseEvidence,
    launchdExecutor: { run: async () => { throw new Error("not used by injected launchd source"); } },
    processIdentityReader: () => ({ pid: 42, startTimeMicros: 1 }),
    processCredentialsReader: () => ({ uid: 0, gid: 0, pid: 42 }),
    readPlist: async () => plist
  });
  const sources = await collectRootHelperSnapshotPackageReadbackSources(plan, {
    ...observer,
    readLaunchd: async () => launchd
  });

  assert.equal(sources.launchd.pid, 42);
  assert.deepEqual(sources.processIdentity, { pid: 42, startTimeMicros: 1 });
  assert.equal(sources.processUid, 0);
  assert.deepEqual(sources.plist, plist);
  assert.equal(sources.releaseEvidence.artifact.sha256, releaseEvidence.artifact.sha256);
});

test("root-helper host observer rejects process replacement during source collection", async () => {
  const plan = planForTest();
  let launchdReads = 0;
  const launchd = (pid: number) => ({
    serviceId: "system/com.mac-operator.root-helper-snapshot",
    domain: "system" as const,
    label: "com.mac-operator.root-helper-snapshot",
    state: "running" as const,
    type: "LaunchDaemon" as const,
    pid,
    program,
    arguments: [...plan.launchd.programArguments],
    plistPath: plan.plistPath,
    lastExitCode: null,
    truncated: false as const
  });
  const observer = createRootHelperSnapshotPackageHostObserver(plan, {
    readReleaseEvidence: async () => releaseEvidence,
    processIdentityReader: (pid) => ({ pid, startTimeMicros: pid === 42 ? 1 : 2 }),
    processCredentialsReader: (pid) => ({ uid: 0, gid: 0, pid }),
    readPlist: async () => ({
      path: plan.plistPath,
      bytes: Buffer.byteLength(plan.renderedPlist, "utf8"),
      sha256: createHash("sha256").update(plan.renderedPlist, "utf8").digest("hex"),
      device: "1",
      inode: "2"
    })
  });

  await assert.rejects(
    collectRootHelperSnapshotPackageReadbackSources(plan, {
      ...observer,
      readLaunchd: async () => launchd(++launchdReads === 1 ? 42 : 43)
    }),
    (error: unknown) => error instanceof RootHelperSnapshotPackageError && error.code === "SERVICE_MISMATCH"
  );
});

test("root-helper snapshot package plan rejects release evidence for another artifact", () => {
  assert.throws(
    () => buildRootHelperSnapshotPackagePlan({
      ...base,
      releaseEvidence: {
        ...releaseEvidence,
        artifact: { ...releaseEvidence.artifact, artifactPath: `${root}/bin/other-helper` }
      }
    }),
    (error: unknown) => error instanceof RootHelperSnapshotPackageError && error.code === "INVALID_SIGNATURE"
  );
});

test("root-helper snapshot package plan binds launchd to the proven release artifact", () => {
  assert.throws(
    () => buildRootHelperSnapshotPackagePlan({
      ...base,
      service: { ...base.service, program: `${root}/bin/other-helper`, programArguments: [`${root}/bin/other-helper`] }
    }),
    (error: unknown) => error instanceof RootHelperSnapshotPackageError && error.code === "INVALID_PACKAGE_PATH"
  );
});

test("root-helper package executor requires an exact host confirmation before authority checks", async () => {
  await assert.rejects(
    executeRootHelperSnapshotPackagePlan(buildRootHelperSnapshotPackagePlan(base), {
      confirmOperation: "upgrade",
      readExistingService: () => { throw new Error("must not read host state"); },
      readback: async () => null
    }),
    (error: unknown) => error instanceof RootHelperSnapshotPackageError && error.code === "CONFIRMATION_REQUIRED"
  );
});

function planForTest() {
  return buildRootHelperSnapshotPackagePlan(base);
}

test("root-helper package executor refuses non-root mutation before host readback", {
  skip: process.getuid?.() === 0 ? "this negative case requires a non-root test process" : false
}, async () => {
  await assert.rejects(
    executeRootHelperSnapshotPackagePlan(buildRootHelperSnapshotPackagePlan(base), {
      confirmOperation: "install",
      readExistingService: () => { throw new Error("must not read host state"); },
      readback: async () => null
    }),
    (error: unknown) => error instanceof RootHelperSnapshotPackageError && error.code === "AUTHORITY_FAILED"
  );
});

test("root-helper package readback rejects Broker socket path drift before release validation", async () => {
  const plan = buildRootHelperSnapshotPackagePlan(base);
  const readback = {
    launchd: {
      serviceId: "system/com.mac-operator.root-helper-snapshot",
      domain: "system" as const,
      label: "com.mac-operator.root-helper-snapshot",
      state: "running" as const,
      type: "LaunchDaemon" as const,
      pid: 42,
      program,
      arguments: [...plan.launchd.programArguments],
      plistPath: plan.plistPath,
      lastExitCode: null,
      truncated: false as const
    },
    processIdentity: { pid: 42, startTimeMicros: 1 },
    processUid: 0,
    plist: {
      path: plan.plistPath,
      bytes: Buffer.byteLength(plan.renderedPlist, "utf8"),
      sha256: createHash("sha256").update(plan.renderedPlist, "utf8").digest("hex"),
      device: "1",
      inode: "2"
    },
    rootHelperSocket: {
      path: plan.socketPath,
      ownerUid: 0,
      ownerGid: 0,
      mode: 0o600,
      device: 1,
      inode: 3
    },
    statusSocket: {
      path: plan.statusSocketPath,
      ownerUid: 0,
      ownerGid: 0,
      mode: 0o600,
      device: 1,
      inode: 6
    },
    brokerSocket: {
      path: `${plan.brokerSocketPath}.replacement`,
      ownerUid: plan.brokerPeer.uid,
      ownerGid: plan.brokerPeer.gid!,
      mode: 0o600,
      device: 1,
      inode: 4
    },
    authoritySocket: {
      path: plan.authoritySocketPath,
      ownerUid: plan.brokerPeer.uid,
      ownerGid: plan.brokerPeer.gid!,
      mode: 0o600,
      device: 1,
      inode: 5
    },
    releaseEvidence
  };

  await assert.rejects(
    validateRootHelperSnapshotPackageReadback(plan, readback),
    (error: unknown) => error instanceof RootHelperSnapshotPackageError && error.code === "SERVICE_MISMATCH"
  );
});
