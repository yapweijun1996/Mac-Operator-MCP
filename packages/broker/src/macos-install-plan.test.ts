import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { realpathSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import test from "node:test";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildMacOsInstallPlan,
  buildMacOsEdgeInstallPlan,
  applyMacOsPlistPlan,
  collectMacOsInstallReadbackSources,
  collectMacOsEdgeInstallReadbackSources,
  composeMacOsInstallReadback,
  composeMacOsEdgeInstallReadback,
  createMacOsInstallHostObserver,
  createMacOsEdgeInstallHostObserver,
  executeMacOsInstallPlan,
  executeMacOsEdgeInstallPlan,
  inspectMacOsInstallFilesystem,
  observeMacOsInstallReadback,
  observeMacOsEdgeInstallReadback,
  readMacOsCodeSignature,
  readMacOsPlistReadback,
  MacOsInstallPlanError,
  validateCodeSignatureReadback,
  validateExistingServicePrecondition,
  validateMacOsInstallReadback,
  validateMacOsEdgeInstallReadback,
  type CodeSignatureCommandSpec,
  type LaunchdCommandSpec,
  type MacOsInstallPlan,
  type MacOsInstallPlanInput,
  type MacOsEdgeInstallPlanInput
} from "./macos-install-plan.js";
import { createAuthorityControlUninstallActions, executeMacOsUninstallPlan } from "./macos-uninstall-plan.js";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { BrokerStatusIpcServer } from "./broker-status-ipc.js";

const base: MacOsInstallPlanInput = {
  uid: 501,
  userHome: "/Users/operator",
  installRoot: "/Users/operator/Library/Application Support/MacOperator",
  plistPath: "/Users/operator/Library/LaunchAgents/com.mac-operator.broker.plist",
  service: {
    label: "com.mac-operator.broker",
    program: "/Users/operator/Library/Application Support/MacOperator/bin/node",
    programArguments: [
      "/Users/operator/Library/Application Support/MacOperator/bin/node",
      "/Users/operator/Library/Application Support/MacOperator/service-entrypoint.js"
    ],
    workingDirectory: "/Users/operator/Library/Application Support/MacOperator",
    stdoutPath: "/Users/operator/Library/Application Support/MacOperator/logs/broker.out.log",
    stderrPath: "/Users/operator/Library/Application Support/MacOperator/logs/broker.err.log"
  },
  metadata: {
    component: "mac-operator-broker",
    sourceRevision: "0123456789abcdef0123456789abcdef01234567",
    contractVersion: "0.1",
    policyVersion: "0.1"
  },
  signature: {
    identifier: "com.mac-operator.broker",
    teamIdentifier: "ABCDE12345",
    cdHash: "0123456789abcdef0123456789abcdef01234567"
  },
  signedArtifactPath: "/Users/operator/Library/Application Support/MacOperator/MacOperatorBroker.app",
  enabledCapabilities: []
};

const edgeBase: MacOsEdgeInstallPlanInput = {
  ...base,
  plistPath: "/Users/operator/Library/LaunchAgents/com.mac-operator.edge.plist",
  service: {
    label: "com.mac-operator.edge",
    program: base.service.program,
    programArguments: [base.service.program, "/Users/operator/Library/Application Support/MacOperator/edge-service-entrypoint.js"],
    workingDirectory: base.service.workingDirectory,
    stdoutPath: "/Users/operator/Library/Application Support/MacOperator/logs/edge.out.log",
    stderrPath: "/Users/operator/Library/Application Support/MacOperator/logs/edge.err.log"
  },
  metadata: {
    component: "mac-operator-edge",
    sourceRevision: base.metadata.sourceRevision,
    contractVersion: base.metadata.contractVersion,
    policyVersion: base.metadata.policyVersion
  },
  signature: { ...base.signature, identifier: "com.mac-operator.edge" },
  signedArtifactPath: "/Users/operator/Library/Application Support/MacOperator/MacOperatorEdge.app",
  bindHost: "127.0.0.1",
  bindPort: 9443
};

test("install plan uses a per-user domain, fixed argv, and explicit rollback actions", () => {
  const plan = buildMacOsInstallPlan(base);
  assert.equal(plan.domain, "gui/501");
  assert.deepEqual(plan.install.bootstrap, {
    executable: "/bin/launchctl",
    args: ["bootstrap", "gui/501", base.plistPath],
    cwd: "/",
    environment: {},
    timeoutMs: 5_000,
    outputCapBytes: 131_072
  });
  assert.deepEqual(plan.rollback.bootout.args, ["bootout", "gui/501/com.mac-operator.broker"]);
  assert.equal(plan.install.file.mode, 0o600);
  assert.deepEqual(plan.signatureVerify, {
    executable: "/usr/bin/codesign",
    args: ["--verify", "--strict", "--deep", base.signedArtifactPath],
    cwd: "/",
    environment: {},
    timeoutMs: 5_000,
    outputCapBytes: 131_072
  });
  assert.equal(plan.rollback.file.kind, "restore-plist");
  assert.equal(plan.uninstall.file.kind, "remove-plist");
  assert.doesNotMatch(plan.renderedPlist, /EnvironmentVariables|UserName|Shell/u);
  assert.equal(buildMacOsInstallPlan({ ...base, metadata: { ...base.metadata, policyVersion: "policy-1" } }).metadata.policyVersion, "policy-1");
});

test("install plan rejects root domains, daemon paths, escapes, and script-like argv", () => {
  assert.throws(() => buildMacOsInstallPlan({ ...base, uid: 0 }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_USER_DOMAIN");
  assert.throws(() => buildMacOsInstallPlan({ ...base, plistPath: "/Library/LaunchDaemons/com.mac-operator.broker.plist" }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_PLIST_PATH");
  assert.throws(() => buildMacOsInstallPlan({ ...base, service: { ...base.service, program: "/usr/local/bin/node", programArguments: ["/usr/local/bin/node", base.service.programArguments[1]!] } }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_PACKAGE_PATH");
  assert.throws(() => buildMacOsInstallPlan({ ...base, service: { ...base.service, programArguments: [base.service.program, "-e", "process.exit()"] } }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_PACKAGE_PATH");
  assert.throws(() => buildMacOsInstallPlan({ ...base, installRoot: "/Users/operator/Library/Application Support/MacOperator/../Other" }), /canonical absolute path/u);
});

test("production install plans require Developer ID identity and isolate ad-hoc development mode", () => {
  assert.throws(
    () => buildMacOsInstallPlan({ ...base, signature: { identifier: "com.mac-operator.broker" } }),
    (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_SIGNATURE_EXPECTATION"
  );
  assert.throws(
    () => buildMacOsInstallPlan({ ...base, signature: { ...base.signature, identifier: "com.attacker.broker" } }),
    /identifier must be com\.mac-operator\.broker/u
  );
  const development = buildMacOsInstallPlan({
    ...base,
    signaturePolicy: "development-ad-hoc",
    signature: { identifier: "com.mac-operator.broker" }
  });
  assert.equal(development.signaturePolicy, "development-ad-hoc");
  assert.throws(
    () => buildMacOsInstallPlan({
      ...base,
      signaturePolicy: "development-ad-hoc",
      enabledCapabilities: ["mac.health.read"],
      signature: { identifier: "com.mac-operator.broker" }
    }),
    /must not enable capabilities/u
  );
});

test("Edge install plan binds the reviewed LaunchAgent to the Edge listener", async () => {
  const plan = buildMacOsEdgeInstallPlan(edgeBase);
  assert.equal(plan.component, "mac-operator-edge");
  assert.equal(plan.label, "com.mac-operator.edge");
  assert.deepEqual(plan.edgeListener, { bindHost: "127.0.0.1", bindPort: 9443 });
  assert.deepEqual(plan.install.bootstrap.args, ["bootstrap", "gui/501", edgeBase.plistPath]);
  const source = {
    launchd: {
      serviceId: `${plan.domain}/${plan.label}`,
      domain: plan.domain as `gui/${number}`,
      label: plan.label,
      state: "running" as const,
      pid: 1234,
      program: plan.launchd.program,
      arguments: [...plan.launchd.programArguments],
      plistPath: plistReadback(plan).path,
      type: "LaunchAgent" as const,
      lastExitCode: null,
      truncated: false as const
    },
    processIdentity: { pid: 1234, startTimeMicros: 987654321 },
    plist: plistReadback(plan),
    edge: {
      component: "mac-operator-edge" as const,
      state: "running" as const,
      sourceRevision: edgeBase.metadata.sourceRevision,
      contractVersion: edgeBase.metadata.contractVersion,
      policyVersion: edgeBase.metadata.policyVersion,
      bindHost: "127.0.0.1",
      bindPort: 9443,
      listening: true
    },
    signature: {
      artifactPath: plan.signedArtifactPath,
      valid: true,
      identifier: plan.signature.identifier,
      teamIdentifier: plan.signature.teamIdentifier ?? null,
      cdHash: plan.signature.cdHash ?? null
    }
  };
  const composed = composeMacOsEdgeInstallReadback(plan, source);
  validateMacOsEdgeInstallReadback(plan, composed);
  assert.equal(composed.edge.bindPort, 9443);
  assert.throws(() => validateMacOsEdgeInstallReadback(plan, {
    ...composed,
    edge: { ...composed.edge, listening: false }
  }), /Edge service readback/u);
  let edgeReads = 0;
  const observer = createMacOsEdgeInstallHostObserver(plan, {
    readEdge: async () => { edgeReads += 1; return source.edge; },
    processIdentityReader: (pid) => ({ pid, startTimeMicros: 987654321 }),
    readSignature: async () => source.signature
  });
  const collected = await collectMacOsEdgeInstallReadbackSources(plan, {
    ...observer,
    readLaunchd: async () => source.launchd,
    readPlist: async () => source.plist
  });
  assert.equal(collected.edge.bindHost, "127.0.0.1");
  const observed = await observeMacOsEdgeInstallReadback(plan, {
    ...observer,
    readLaunchd: async () => source.launchd,
    readPlist: async () => source.plist
  });
  assert.equal(observed.edge.component, "mac-operator-edge");
  assert.equal(edgeReads, 2);
  let launchdReads = 0;
  await assert.rejects(collectMacOsEdgeInstallReadbackSources(plan, {
    ...observer,
    readLaunchd: async () => {
      launchdReads += 1;
      return launchdReads === 1 ? source.launchd : { ...source.launchd, pid: 4321 };
    },
    readPlist: async () => source.plist
  }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "SERVICE_MISMATCH");
});

test("Edge install plan rejects component or listener substitution", () => {
  assert.throws(() => buildMacOsEdgeInstallPlan({ ...edgeBase, service: { ...edgeBase.service, label: "com.mac-operator.broker" } }), /service label/u);
  assert.throws(() => buildMacOsEdgeInstallPlan({ ...edgeBase, bindPort: 0 }), /listener binding/u);
  assert.throws(() => buildMacOsEdgeInstallPlan({ ...edgeBase, metadata: { ...edgeBase.metadata, component: "mac-operator-broker" as never } }), /metadata/u);
});

test("Edge executor requires explicit host confirmation before any mutation", async () => {
  const plan = buildMacOsEdgeInstallPlan(edgeBase);
  await assert.rejects(executeMacOsEdgeInstallPlan(plan, {
    ownerUid: 501,
    confirmOperation: "upgrade",
    existingService: { present: false, sourceRevision: null },
    readback: async () => null
  }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "CONFIRMATION_REQUIRED");
});

test("readback requires matching signature, launchd identity, native transport, and Broker metadata", () => {
  const plan = buildMacOsInstallPlan(base);
  const readback = {
    domain: plan.domain,
    label: plan.label,
    plistPath: plan.plistPath,
    pid: 1234,
    processIdentity: { pid: 1234, startTimeMicros: 987654321 },
    plist: plistReadback(plan),
    launchd: plan.launchd,
    broker: {
      ...base.metadata,
      state: "running" as const,
      runtimeState: "running" as const,
      nativeTransportRequired: true as const,
      enabledCapabilities: []
    },
    signature: {
      artifactPath: base.signedArtifactPath,
      valid: true,
      identifier: base.signature.identifier,
      teamIdentifier: base.signature.teamIdentifier ?? null,
      cdHash: base.signature.cdHash ?? null
    }
  };
  validateMacOsInstallReadback(plan, readback);
  validateCodeSignatureReadback(base.signature, readback.signature, base.signedArtifactPath);
  assert.throws(() => validateMacOsInstallReadback(plan, { ...readback, processIdentity: { pid: 4321, startTimeMicros: 987654321 } }), /launchd readback/u);
  assert.throws(() => validateMacOsInstallReadback(plan, { ...readback, pid: 1234, processIdentity: { pid: 1234, startTimeMicros: 0 } }), /launchd readback/u);
  assert.throws(() => validateMacOsInstallReadback(plan, { ...readback, broker: { ...readback.broker, nativeTransportRequired: false as never } }), /Broker service readback/u);
  assert.throws(() => validateCodeSignatureReadback(base.signature, { ...readback.signature, identifier: "com.attacker.broker" }, base.signedArtifactPath), /code signature readback/u);
});

test("readback composition binds launchd service identity to native process and Broker sources", () => {
  const plan = buildMacOsInstallPlan(base);
  const composed = composeMacOsInstallReadback(plan, {
    launchd: {
      serviceId: `${plan.domain}/${plan.label}`,
      domain: plan.domain as `gui/${number}`,
      label: plan.label,
      state: "running",
      pid: 1234,
      program: plan.launchd.program,
      arguments: [...plan.launchd.programArguments],
      plistPath: plistReadback(plan).path,
      type: "LaunchAgent",
      lastExitCode: null,
      truncated: false
    },
    processIdentity: { pid: 1234, startTimeMicros: 987654321 },
    plist: plistReadback(plan),
    broker: {
      ...base.metadata,
      state: "running",
      runtimeState: "running",
      nativeTransportRequired: true,
      enabledCapabilities: []
    },
    signature: {
      artifactPath: base.signedArtifactPath,
      valid: true,
      identifier: base.signature.identifier,
      teamIdentifier: base.signature.teamIdentifier ?? null,
      cdHash: base.signature.cdHash ?? null
    }
  });
  assert.equal(composed.pid, 1234);
  assert.equal(composed.processIdentity.startTimeMicros, 987654321);
  assert.throws(() => composeMacOsInstallReadback(plan, {
    launchd: {
      serviceId: "gui/501/com.mac-operator.attacker",
      domain: plan.domain as `gui/${number}`,
      label: plan.label,
      state: "running",
      pid: 1234,
      program: plan.launchd.program,
      arguments: [...plan.launchd.programArguments],
      plistPath: plistReadback(plan).path,
      type: "LaunchAgent",
      lastExitCode: null,
      truncated: false
    },
    processIdentity: composed.processIdentity,
    plist: composed.plist,
    broker: composed.broker,
    signature: composed.signature
  }), /launchd readback sources/u);
});

test("install readback collection double-reads mutable identities before composition", async () => {
  const plan = buildMacOsInstallPlan(base);
  const source = readbackSources(plan);
  let launchdReads = 0;
  let processReads = 0;
  let plistReads = 0;
  const observer = {
    readLaunchd: async () => { launchdReads += 1; return source.launchd; },
    readProcessIdentity: (pid: number) => { processReads += 1; return { pid, startTimeMicros: 987654321 }; },
    readPlist: async () => { plistReads += 1; return source.plist; },
    readBroker: async () => source.broker,
    readSignature: async () => source.signature
  };
  const collected = await collectMacOsInstallReadbackSources(plan, observer);
  assert.equal(collected.launchd.pid, 1234);
  assert.equal(launchdReads, 2);
  assert.equal(processReads, 2);
  assert.equal(plistReads, 2);
  const composed = await observeMacOsInstallReadback(plan, observer);
  assert.equal(composed.broker.state, "running");
});

test("install readback collection rejects a launchd target swap", async () => {
  const plan = buildMacOsInstallPlan(base);
  const source = readbackSources(plan);
  let launchdReads = 0;
  const observer = {
    readLaunchd: async () => {
      launchdReads += 1;
      return launchdReads === 1 ? source.launchd : { ...source.launchd, pid: 4321 };
    },
    readProcessIdentity: (pid: number) => ({ pid, startTimeMicros: 987654321 }),
    readPlist: async () => source.plist,
    readBroker: async () => source.broker,
    readSignature: async () => source.signature
  };
  await assert.rejects(
    collectMacOsInstallReadbackSources(plan, observer),
    (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "SERVICE_MISMATCH"
  );
});

test("install host observer binds real adapter sources without accepting a final readback", async () => {
  const plan = buildMacOsInstallPlan(base);
  const output = [
    `${plan.domain}/${plan.label} = {`,
    "\tstate = running",
    "\tpid = 1234",
    `\tprogram = ${plan.launchd.program}`,
    "\targuments = {",
    `\t\t${plan.launchd.program}`,
    `\t\t${plan.launchd.programArguments[1]}`,
    "\t}",
    `\tpath = ${plan.plistPath}`,
    "\ttype = LaunchAgent",
    "\tlast exit code = (never exited)",
    "}"
  ].join("\n");
  const observer = createMacOsInstallHostObserver(plan, {
    readBroker: async () => readbackSources(plan).broker,
    launchdExecutor: {
      run: async () => ({
        state: "completed",
        resultClass: "SUCCEEDED",
        exitCode: 0,
        signal: null,
        stdout: output,
        stderr: "",
        truncated: false,
        durationMs: 1,
        processId: 1,
        processGroupId: 1,
        terminationObserved: true
      })
    },
    processIdentityReader: (pid) => ({ pid, startTimeMicros: 987654321 }),
    readPlist: async () => readbackSources(plan).plist,
    readSignature: async () => readbackSources(plan).signature
  });
  const sources = await collectMacOsInstallReadbackSources(plan, observer);
  assert.equal(sources.launchd.type, "LaunchAgent");
  assert.equal(sources.processIdentity.startTimeMicros, 987654321);
});

test("install host observer can read through the authenticated Broker status client", async () => {
  const plan = buildMacOsInstallPlan(base);
  const directory = await mkdtemp(join(tmpdir(), "mobs-"));
  const socketPath = join(directory, "status.sock");
  const authenticationKey = randomBytes(32);
  const storeReplay = new Set<string>();
  const server = new BrokerStatusIpcServer({
    socketPath,
    authenticationKey,
    replayGuard: { admit: ({ nonce }) => {
      if (storeReplay.has(nonce)) throw new Error("replay");
      storeReplay.add(nonce);
    } },
    peerCredentialVerifier: { verify: () => undefined },
    authorizeStatus: () => undefined,
    readStatus: () => readbackSources(plan).broker
  });
  try {
    await server.listen();
    const observer = createMacOsInstallHostObserver(plan, {
      brokerStatusClient: { socketPath, authenticationKey }
    });
    assert.deepEqual(await observer.readBroker(), readbackSources(plan).broker);
  } finally {
    await server.close();
    authenticationKey.fill(0);
    await rm(directory, { recursive: true, force: true });
  }
});

test("upgrade and uninstall plans bind an exact existing revision and fail closed on precondition mismatch", () => {
  const previous = "abcdef0123456789abcdef0123456789abcdef01";
  const plan = buildMacOsInstallPlan({ ...base, operation: "upgrade", expectedPreviousSourceRevision: previous });
  assert.equal(plan.expectedPreviousSourceRevision, previous);
  validateExistingServicePrecondition(plan, { present: true, sourceRevision: previous });
  assert.throws(() => validateExistingServicePrecondition(plan, { present: false, sourceRevision: null }), /approved operation precondition/u);
  assert.throws(() => buildMacOsInstallPlan({ ...base, operation: "upgrade" }), /previous source revision/u);
  const uninstall = buildMacOsInstallPlan({ ...base, operation: "uninstall", expectedPreviousSourceRevision: previous });
  validateExistingServicePrecondition(uninstall, { present: true, sourceRevision: previous });
});

test("malformed nested readback is rejected with a stable plan error", () => {
  const plan = buildMacOsInstallPlan(base);
  assert.throws(() => validateMacOsInstallReadback(plan, { launchd: null } as never), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_READBACK");
});

test("install readback rejects inherited and accessor-shaped observations", () => {
  const plan = buildMacOsInstallPlan(base);
  const accessorReadback: Record<string, unknown> = {};
  Object.defineProperty(accessorReadback, "launchd", { enumerable: true, get: () => readbackSources(plan).launchd });
  assert.throws(
    () => validateMacOsInstallReadback(plan, accessorReadback as never),
    (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_READBACK"
  );
  const inheritedReadback = Object.create({ launchd: readbackSources(plan).launchd }) as Record<string, unknown>;
  assert.throws(
    () => validateMacOsInstallReadback(plan, inheritedReadback as never),
    (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_READBACK"
  );
});

test("signature verification plan accepts a real temporary ad-hoc signed artifact", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("The production packaging target is macOS");
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "mac-operator-codesign-"));
  try {
    const userHome = join(root, "home");
    const installRoot = join(userHome, "MacOperator");
    const artifact = join(installRoot, "MacOperatorBroker.app");
    const contents = join(artifact, "Contents");
    const executable = join(contents, "MacOS", "broker");
    await mkdir(join(contents, "MacOS"), { recursive: true, mode: 0o700 });
    await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await writeFile(join(contents, "Info.plist"), [
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
    assert.equal(signed.state, "completed");
    assert.equal(signed.resultClass, "SUCCEEDED");

    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("POSIX identity is unavailable");
    const plan = buildMacOsInstallPlan({
      ...base,
      uid,
      userHome,
      installRoot,
      plistPath: join(userHome, "Library", "LaunchAgents", "com.mac-operator.broker.plist"),
      signedArtifactPath: artifact,
      signaturePolicy: "development-ad-hoc",
      service: {
        ...base.service,
        program: join(installRoot, "bin", "node"),
        programArguments: [join(installRoot, "bin", "node"), join(installRoot, "service-entrypoint.js")],
        workingDirectory: installRoot,
        stdoutPath: join(installRoot, "logs", "broker.out.log"),
        stderrPath: join(installRoot, "logs", "broker.err.log")
      },
      signature: { identifier: "com.mac-operator.broker" }
    });
    const verified = await supervisor.run(plan.signatureVerify);
    assert.equal(verified.state, "completed");
    assert.equal(verified.resultClass, "SUCCEEDED");
    const details = await supervisor.run({
      executable: "/usr/bin/codesign",
      args: ["-dv", "--verbose=4", artifact],
      cwd: "/",
      environment: {},
      timeoutMs: 5_000,
      outputCapBytes: 131_072
    });
    assert.equal(details.state, "completed");
    assert.match(`${details.stdout}\n${details.stderr}`, /Identifier=com\.mac-operator\.broker/u);
    assert.match(`${details.stdout}\n${details.stderr}`, /CDHash=[0-9a-f]{20,64}/u);
    const signatureReadback = await readMacOsCodeSignature(plan, supervisor);
    assert.equal(signatureReadback.identifier, "com.mac-operator.broker");
    assert.equal(signatureReadback.teamIdentifier, null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("filesystem preflight rejects symlinks and writable paths, then returns stable identity readback", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-install-"));
  try {
    const userHome = join(root, "home");
    const installRoot = join(userHome, "MacOperator");
    const binRoot = join(installRoot, "bin");
    const logRoot = join(installRoot, "logs");
    const artifact = join(installRoot, "MacOperatorBroker.app");
    const launchAgents = join(userHome, "Library", "LaunchAgents");
    await mkdir(binRoot, { recursive: true, mode: 0o700 });
    await mkdir(logRoot, { recursive: true, mode: 0o700 });
    await mkdir(artifact, { recursive: true, mode: 0o700 });
    await mkdir(launchAgents, { recursive: true, mode: 0o700 });
    await writeFile(join(binRoot, "node"), "node", { mode: 0o700 });
    await writeFile(join(installRoot, "service-entrypoint.js"), "", { mode: 0o600 });
    await chmod(userHome, 0o700);
    await chmod(join(userHome, "Library"), 0o700);
    await chmod(launchAgents, 0o700);
    await chmod(installRoot, 0o700);
    await chmod(binRoot, 0o700);
    await chmod(logRoot, 0o700);
    await chmod(artifact, 0o700);
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("POSIX identity is unavailable");
    const plan = buildMacOsInstallPlan({
      ...base,
      uid,
      userHome,
      installRoot,
      plistPath: join(launchAgents, "com.mac-operator.broker.plist"),
      signedArtifactPath: artifact,
      service: {
        ...base.service,
        program: join(binRoot, "node"),
        programArguments: [join(binRoot, "node"), join(installRoot, "service-entrypoint.js")],
        workingDirectory: installRoot,
        stdoutPath: join(logRoot, "broker.out.log"),
        stderrPath: join(logRoot, "broker.err.log")
      }
    });
    const preflight = await inspectMacOsInstallFilesystem(plan, { ownerUid: uid });
    assert.ok(preflight.entries.some((entry) => entry.path === artifact && entry.kind === "directory"));
    await chmod(join(binRoot, "node"), 0o722);
    await assert.rejects(inspectMacOsInstallFilesystem(plan, { ownerUid: uid }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "FILESYSTEM_MISMATCH");
    await chmod(join(binRoot, "node"), 0o700);
    await rm(join(binRoot, "node"));
    await symlink(join(installRoot, "service-entrypoint.js"), join(binRoot, "node"));
    await assert.rejects(inspectMacOsInstallFilesystem(plan, { ownerUid: uid }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "FILESYSTEM_MISMATCH");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("plist apply uses native atomic write, creates a backup on upgrade, and restores it on rollback", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-apply-"));
  try {
    const userHome = join(root, "home");
    const installRoot = join(userHome, "MacOperator");
    const binRoot = join(installRoot, "bin");
    const logRoot = join(installRoot, "logs");
    const artifact = join(installRoot, "MacOperatorBroker.app");
    const launchAgents = join(userHome, "Library", "LaunchAgents");
    await mkdir(binRoot, { recursive: true, mode: 0o700 });
    await mkdir(logRoot, { recursive: true, mode: 0o700 });
    await mkdir(artifact, { recursive: true, mode: 0o700 });
    await mkdir(launchAgents, { recursive: true, mode: 0o700 });
    await writeFile(join(binRoot, "node"), "node", { mode: 0o700 });
    await writeFile(join(installRoot, "service-entrypoint.js"), "", { mode: 0o600 });
    for (const directory of [userHome, join(userHome, "Library"), launchAgents, installRoot, binRoot, logRoot, artifact]) await chmod(directory, 0o700);
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("POSIX identity is unavailable");
    const service = {
      ...base.service,
      program: join(binRoot, "node"),
      programArguments: [join(binRoot, "node"), join(installRoot, "service-entrypoint.js")],
      workingDirectory: installRoot,
      stdoutPath: join(logRoot, "broker.out.log"),
      stderrPath: join(logRoot, "broker.err.log")
    };
    const common = { ...base, uid, userHome, installRoot, plistPath: join(launchAgents, "com.mac-operator.broker.plist"), signedArtifactPath: artifact, service };
    const install = buildMacOsInstallPlan(common);
    const first = await applyMacOsPlistPlan(install, { ownerUid: uid });
    assert.equal(first.created, true);
    const oldContent = await readFile(install.plistPath, "utf8");
    const plistReadback = readMacOsPlistReadback(install, { ownerUid: uid });
    assert.equal(plistReadback.path, await realpath(install.plistPath));
    assert.equal(plistReadback.bytes, Buffer.byteLength(install.renderedPlist, "utf8"));
    assert.equal(plistReadback.sha256, createHash("sha256").update(install.renderedPlist, "utf8").digest("hex"));
    await writeFile(install.plistPath, "tampered", { mode: 0o600 });
    assert.throws(() => readMacOsPlistReadback(install, { ownerUid: uid }), /planned plist readback|content/u);
    await writeFile(install.plistPath, oldContent, { mode: 0o600 });
    const upgrade = buildMacOsInstallPlan({ ...common, operation: "upgrade", expectedPreviousSourceRevision: base.metadata.sourceRevision, metadata: { ...base.metadata, sourceRevision: "abcdef0123456789abcdef0123456789abcdef01" } });
    const second = await applyMacOsPlistPlan(upgrade, { ownerUid: uid });
    assert.equal(second.backupPath, upgrade.backupPath);
    assert.equal(await readFile(upgrade.backupPath, "utf8"), oldContent);
    assert.equal((await readFile(upgrade.plistPath, "utf8")), upgrade.renderedPlist);
    const rollback = buildMacOsInstallPlan({ ...common, operation: "rollback", expectedPreviousSourceRevision: upgrade.metadata.sourceRevision, metadata: base.metadata });
    const third = await applyMacOsPlistPlan(rollback, { ownerUid: uid });
    assert.equal(third.operation, "rollback");
    assert.equal(await readFile(rollback.plistPath, "utf8"), oldContent);
    const uninstall = buildMacOsInstallPlan({ ...common, operation: "uninstall", expectedPreviousSourceRevision: base.metadata.sourceRevision, metadata: base.metadata });
    const removed = await applyMacOsPlistPlan(uninstall, { ownerUid: uid });
    assert.equal(removed.operation, "uninstall");
    await assert.rejects(readFile(uninstall.plistPath, "utf8"));
    await assert.rejects(readFile(uninstall.backupPath, "utf8"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("install executor requires explicit confirmation and verifies final Broker readback", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-execute-"));
  try {
    const uid = process.getuid?.();
    if (uid === undefined || uid < 1) throw new Error("POSIX non-root identity is unavailable");
    const userHome = join(root, "home");
    const installRoot = join(userHome, "MacOperator");
    const binRoot = join(installRoot, "bin");
    const logRoot = join(installRoot, "logs");
    const artifact = join(installRoot, "MacOperatorBroker.app");
    const launchAgents = join(userHome, "Library", "LaunchAgents");
    await mkdir(binRoot, { recursive: true, mode: 0o700 });
    await mkdir(logRoot, { recursive: true, mode: 0o700 });
    await mkdir(artifact, { recursive: true, mode: 0o700 });
    await mkdir(launchAgents, { recursive: true, mode: 0o700 });
    await writeFile(join(binRoot, "node"), "node", { mode: 0o700 });
    await writeFile(join(installRoot, "service-entrypoint.js"), "", { mode: 0o600 });
    for (const directory of [userHome, join(userHome, "Library"), launchAgents, installRoot, binRoot, logRoot, artifact]) {
      await chmod(directory, 0o700);
    }
    const plan = buildMacOsInstallPlan({
      ...base,
      uid,
      userHome,
      installRoot,
      plistPath: join(launchAgents, "com.mac-operator.broker.plist"),
      signedArtifactPath: artifact,
      service: {
        ...base.service,
        program: join(binRoot, "node"),
        programArguments: [join(binRoot, "node"), join(installRoot, "service-entrypoint.js")],
        workingDirectory: installRoot,
        stdoutPath: join(logRoot, "broker.out.log"),
        stderrPath: join(logRoot, "broker.err.log")
      }
    });
    const executor = new RecordingInstallExecutor();
    await assert.rejects(
      executeMacOsInstallPlan(plan, {
        confirmOperation: "upgrade",
        existingService: { present: false, sourceRevision: null },
        ownerUid: uid,
        commandExecutor: executor,
        readback: async () => null
      }),
      (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "CONFIRMATION_REQUIRED"
    );
    assert.equal(executor.commands.length, 0);

    const result = await executeMacOsInstallPlan(plan, {
      confirmOperation: "install",
      existingService: { present: false, sourceRevision: null },
      ownerUid: uid,
      commandExecutor: executor,
      readback: async () => readbackSources(plan)
    });
    assert.equal(result.operation, "install");
    assert.equal(result.readback?.broker.nativeTransportRequired, true);
    assert.deepEqual(executor.commands.map((command) => command.args[0]), ["--verify", "bootstrap"]);
    await assert.doesNotReject(readFile(plan.plistPath, "utf8"));

    const authorityEvents: string[] = [];
    const uninstallPlan = buildMacOsInstallPlan({
      ...base,
      operation: "uninstall",
      expectedPreviousSourceRevision: base.metadata.sourceRevision,
      uid,
      userHome,
      installRoot,
      plistPath: join(launchAgents, "com.mac-operator.broker.plist"),
      signedArtifactPath: artifact,
      service: {
        ...base.service,
        program: join(binRoot, "node"),
        programArguments: [join(binRoot, "node"), join(installRoot, "service-entrypoint.js")],
        workingDirectory: installRoot,
        stdoutPath: join(logRoot, "broker.out.log"),
        stderrPath: join(logRoot, "broker.err.log")
      }
    });
    const removed = await executeMacOsUninstallPlan(uninstallPlan, {
      confirmOperation: "uninstall",
      existingService: { present: true, sourceRevision: base.metadata.sourceRevision },
      ownerUid: uid,
      commandExecutor: executor,
      readback: async () => null,
      edgeId: "edge-1",
      disableGlobal: async () => { authorityEvents.push("disable-global"); },
      revokeEdge: async (edgeId) => { authorityEvents.push(`revoke-edge:${edgeId}`); },
      authorityReadback: async () => {
        authorityEvents.push("authority-readback");
        return { globalDisabled: true, edgeRevoked: true };
      }
    });
    assert.equal(removed.readback, null);
    assert.deepEqual(authorityEvents, ["disable-global", "revoke-edge:edge-1", "authority-readback", "authority-readback"]);
    await assert.rejects(readFile(uninstallPlan.plistPath, "utf8"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("uninstall authority gate fails closed before filesystem mutation", async () => {
  const plan = buildMacOsInstallPlan({
    ...base,
    operation: "uninstall",
    expectedPreviousSourceRevision: base.metadata.sourceRevision
  });
  const events: string[] = [];
  const executor = new RecordingInstallExecutor();
  await assert.rejects(
    executeMacOsUninstallPlan(plan, {
      confirmOperation: "uninstall",
      existingService: { present: true, sourceRevision: base.metadata.sourceRevision },
      ownerUid: base.uid,
      commandExecutor: executor,
      readback: async () => null,
      edgeId: "edge-1",
      disableGlobal: async () => { events.push("disable-global"); },
      revokeEdge: async () => { events.push("revoke-edge"); },
      authorityReadback: async () => {
        events.push("authority-readback");
        return { globalDisabled: true, edgeRevoked: false };
      }
    }),
    (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "AUTHORITY_MISMATCH"
  );
  assert.deepEqual(events, ["disable-global", "revoke-edge", "authority-readback"]);
  assert.deepEqual(executor.commands, []);
});

test("uninstall authority actions bind the selected Edge and are idempotent", async () => {
  let globalDisabled = false;
  let edgeRevoked = false;
  const writes: string[] = [];
  const actions = createAuthorityControlUninstallActions({
    async readSwitch() { return globalDisabled; },
    async setSwitch() { writes.push("set-global"); globalDisabled = true; },
    async readRevocation() { return edgeRevoked; },
    async revoke() { writes.push("revoke-edge"); edgeRevoked = true; }
  }, "edge-1");
  await actions.disableGlobal();
  await actions.revokeEdge("edge-1");
  await actions.disableGlobal();
  await actions.revokeEdge("edge-1");
  assert.deepEqual(writes, ["set-global", "revoke-edge"]);
  assert.deepEqual(await actions.authorityReadback(), { globalDisabled: true, edgeRevoked: true });
  await assert.rejects(actions.revokeEdge("edge-2"), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_ARGUMENT");
});

test("install executor stops a mismatched service and leaves an explicit recovery artifact", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-execute-readback-"));
  try {
    const uid = process.getuid?.();
    if (uid === undefined || uid < 1) throw new Error("POSIX non-root identity is unavailable");
    const userHome = join(root, "home");
    const installRoot = join(userHome, "MacOperator");
    const binRoot = join(installRoot, "bin");
    const logRoot = join(installRoot, "logs");
    const artifact = join(installRoot, "MacOperatorBroker.app");
    const launchAgents = join(userHome, "Library", "LaunchAgents");
    await mkdir(binRoot, { recursive: true, mode: 0o700 });
    await mkdir(logRoot, { recursive: true, mode: 0o700 });
    await mkdir(artifact, { recursive: true, mode: 0o700 });
    await mkdir(launchAgents, { recursive: true, mode: 0o700 });
    await writeFile(join(binRoot, "node"), "node", { mode: 0o700 });
    await writeFile(join(installRoot, "service-entrypoint.js"), "", { mode: 0o600 });
    for (const directory of [userHome, join(userHome, "Library"), launchAgents, installRoot, binRoot, logRoot, artifact]) {
      await chmod(directory, 0o700);
    }
    const plan = buildMacOsInstallPlan({
      ...base,
      uid,
      operation: "upgrade",
      expectedPreviousSourceRevision: base.metadata.sourceRevision,
      metadata: { ...base.metadata, sourceRevision: "abcdef0123456789abcdef0123456789abcdef01" },
      userHome,
      installRoot,
      plistPath: join(launchAgents, "com.mac-operator.broker.plist"),
      signedArtifactPath: artifact,
      service: {
        ...base.service,
        program: join(binRoot, "node"),
        programArguments: [join(binRoot, "node"), join(installRoot, "service-entrypoint.js")],
        workingDirectory: installRoot,
        stdoutPath: join(logRoot, "broker.out.log"),
        stderrPath: join(logRoot, "broker.err.log")
      }
    });
    await mkdir(dirname(plan.plistPath), { recursive: true, mode: 0o700 });
    await writeFile(plan.plistPath, "old plist", { mode: 0o600 });
    const executor = new RecordingInstallExecutor();
    await assert.rejects(
      executeMacOsInstallPlan(plan, {
        confirmOperation: "upgrade",
        existingService: { present: true, sourceRevision: base.metadata.sourceRevision },
        ownerUid: uid,
        commandExecutor: executor,
        readback: async () => null
      }),
      (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "READBACK_FAILED"
    );
    assert.deepEqual(executor.commands.map((command) => command.args[0]), ["--verify", "bootout", "bootstrap", "bootout"]);
    assert.notEqual(await readFile(plan.plistPath, "utf8"), "old plist");
    await assert.doesNotReject(readFile(plan.backupPath, "utf8"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function plistReadback(plan: Pick<MacOsInstallPlan, "plistPath" | "renderedPlist">): { path: string; bytes: number; sha256: string; device: string; inode: string } {
  const rendered = plan.renderedPlist;
  let path = plan.plistPath;
  try { path = realpathSync(path); } catch { /* the synthetic base plan is not installed */ }
  return {
    path,
    bytes: Buffer.byteLength(rendered, "utf8"),
    sha256: createHash("sha256").update(rendered, "utf8").digest("hex"),
    device: "1",
    inode: "2"
  };
}

function readbackSources(plan: MacOsInstallPlan) {
  return {
    launchd: {
      serviceId: `${plan.domain}/${plan.label}`,
      domain: plan.domain as `gui/${number}`,
      label: plan.label,
      state: "running" as const,
      pid: 1234,
      program: plan.launchd.program,
      arguments: [...plan.launchd.programArguments],
      plistPath: plistReadback(plan).path,
      type: "LaunchAgent" as const,
      lastExitCode: null,
      truncated: false as const
    },
    processIdentity: { pid: 1234, startTimeMicros: 987654321 },
    plist: plistReadback(plan),
    broker: { ...plan.metadata, state: "running" as const, runtimeState: "running" as const, nativeTransportRequired: true as const, enabledCapabilities: [] },
    signature: { artifactPath: plan.signedArtifactPath, valid: true, identifier: plan.signature.identifier, teamIdentifier: plan.signature.teamIdentifier ?? null, cdHash: plan.signature.cdHash ?? null }
  };
}

class RecordingInstallExecutor {
  readonly commands: Array<LaunchdCommandSpec | CodeSignatureCommandSpec> = [];

  async run(command: LaunchdCommandSpec | CodeSignatureCommandSpec): Promise<ProcessExecutionResult> {
    this.commands.push(command);
    return {
      state: "completed",
      resultClass: "SUCCEEDED",
      exitCode: 0,
      signal: null,
      stdout: "",
      stderr: "",
      truncated: false,
      durationMs: 1,
      processId: 1,
      processGroupId: 1,
      terminationObserved: true
    };
  }
}
