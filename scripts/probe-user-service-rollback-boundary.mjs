import { randomBytes } from "node:crypto";
import { execFile as childExecFile } from "node:child_process";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { lstat, mkdtemp, open, readFile, realpath, rm, unlink } from "node:fs/promises";
import {
  ApprovalAuthority,
  Broker,
  BrokerStore,
  EdgeKeyring,
  ProcessSupervisor,
  UserServiceControlAdapter,
  UserServiceControlJobExecutor,
  approvalPreviewDigest,
  parseLaunchdJobReadback,
  signApprovalIssuance
} from "../packages/broker/dist/index.js";
import { createDefaultPolicy } from "../packages/broker/dist/default-policy.js";
import { canonicalJson, sha256, signRequest } from "../packages/contracts/dist/index.js";

const execFile = promisify(childExecFile);
const LAUNCHCTL = "/bin/launchctl";
const PROGRAM = "/bin/sleep";
const PROGRAM_ARGUMENTS = [PROGRAM, "60"];
const uid = typeof process.getuid === "function" ? process.getuid() : -1;
const label = "com.mac-operator.boundary-rollback";
const domain = `gui/${uid}`;
const serviceId = `${domain}/${label}`;
const launchAgentDirectory = join(homedir(), "Library", "LaunchAgents");
const plistPath = join(launchAgentDirectory, `${label}.plist`);
const launchAgentPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${PROGRAM}</string>
    <string>60</string>
  </array>
  <key>RunAtLoad</key>
  <false/>
  <key>KeepAlive</key>
  <false/>
</dict>
</plist>
`;

if (process.env.MOPS_REAL_USER_SERVICE !== "1") {
  throw new Error("Set MOPS_REAL_USER_SERVICE=1 to run the bounded real-Mac rollback probe");
}
if (process.platform !== "darwin" || !Number.isSafeInteger(uid) || uid < 1) {
  throw new Error("The user-service rollback probe requires a non-root macOS user");
}

async function runLaunchctl(args) {
  try {
    const result = await execFile(LAUNCHCTL, args, {
      cwd: "/",
      env: {},
      timeout: 5_000,
      maxBuffer: 128 * 1024,
      shell: false,
      windowsHide: true
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    const record = error && typeof error === "object" ? error : {};
    return {
      code: typeof record.code === "number" ? record.code : null,
      stdout: typeof record.stdout === "string" ? record.stdout : "",
      stderr: typeof record.stderr === "string" ? record.stderr : ""
    };
  }
}

async function assertTargetAbsent() {
  const result = await runLaunchctl(["print", serviceId]);
  if (result.code === 0) throw new Error("Rollback probe service identity is already loaded");
  if (result.code === null) throw new Error("Could not prove rollback probe identity is absent");
}

async function assertOwnedRegularFile(path) {
  const entry = await lstat(path);
  if (!entry.isFile() || entry.isSymbolicLink() || entry.uid !== uid || (entry.mode & 0o022) !== 0) {
    throw new Error("Rollback probe plist failed owner-only regular-file checks");
  }
  if (await realpath(path) !== path) throw new Error("Rollback probe plist is not canonical");
}

function userServicePolicy() {
  const base = createDefaultPolicy("edge-1", true, ["mac.control.read", "mac.service.control"], ["edge-key-1"]);
  const tool = base.tools.get("mac_service_control");
  if (!tool) throw new Error("Default policy is missing mac_service_control");
  return {
    ...base,
    targetRules: [...base.targetRules, {
      ruleId: "real-user-service-rollback-target",
      effect: "allow",
      principalId: "principal-1",
      scope: "mac.service.control",
      target: { kind: "service", reference: serviceId }
    }],
    tools: new Map(base.tools).set("mac_service_control", { ...tool, implemented: true, enabled: true })
  };
}

function issueApproval(authority, operatorKey, argumentsValue, now) {
  const approval = {
    approvalId: "approval:real-user-service-rollback",
    approverPrincipalId: "probe-operator",
    requestingPrincipalId: "principal-1",
    tool: "mac_service_control",
    contractVersion: "0.1",
    targetKind: "service",
    targetRef: `service:${serviceId}`,
    payloadDigest: sha256(canonicalJson(argumentsValue)),
    policyVersion: "policy-0.1",
    approvalClass: "trusted_write",
    unattended: false,
    issuedAtMs: now,
    expiresAtMs: now + 300_000
  };
  authority.issue(signApprovalIssuance({
    protocolVersion: "0.1",
    requestId: "approval-issue:real-user-service-rollback",
    nonce: "approval-nonce:real-user-service-rollback",
    nonceExpiresAtMs: now + 60_000,
    issuerId: "probe-operator",
    keyId: "operator-key-1",
    timestampMs: now,
    approval,
    previewDigest: approvalPreviewDigest(approval)
  }, operatorKey));
}

async function main() {
  await assertTargetAbsent();
  const parent = await realpath(launchAgentDirectory);
  if (parent !== launchAgentDirectory) throw new Error("LaunchAgent directory is not canonical");
  const sourceRevision = sha256(Buffer.from(launchAgentPlist, "utf8"));
  const now = Date.now();
  const tempDirectory = await mkdtemp(join(tmpdir(), "mac-operator-user-service-rollback-"));
  const store = new BrokerStore(join(tempDirectory, "probe.sqlite"));
  const edgeKey = randomBytes(32);
  const operatorKey = randomBytes(32);
  const approvalAuthority = new ApprovalAuthority(store, [{
    issuerId: "probe-operator",
    keyId: "operator-key-1",
    key: operatorKey,
    notBeforeMs: now - 60_000,
    expiresAtMs: now + 300_000,
    allowUnattended: false
  }], { now: () => now });
  const keyring = new EdgeKeyring([{
    edgeId: "edge-1",
    keyId: "edge-key-1",
    key: edgeKey,
    notBeforeMs: now - 60_000,
    expiresAtMs: now + 300_000
  }]);
  const sourceRevisionReader = {
    async read(requestedServiceId, control) {
      if (requestedServiceId !== serviceId || control.shouldCancel()) throw new Error("Rollback source readback was not authorized");
      return sha256(await readFile(plistPath));
    }
  };
  const nativeSupervisor = new ProcessSupervisor({
    maxConcurrent: 1,
    maxConcurrentPerExecutable: 1,
    allowedEnvironmentKeys: [],
    requireRootOwnedExecutable: true,
    requireSystemPublishedExecutable: true
  });
  const postconditionSupervisor = new ProcessSupervisor({
    maxConcurrent: 1,
    maxConcurrentPerExecutable: 1,
    allowedEnvironmentKeys: [],
    requireRootOwnedExecutable: true,
    requireSystemPublishedExecutable: true
  });
  const commandRunner = {
    async run(request) {
      const result = await nativeSupervisor.run(request);
      if (result.resultClass === "SUCCEEDED" && request.args[0] === "kill" && request.args[1] === "SIGTERM" && request.args[2] === serviceId) {
        // launchd applies the disposable LaunchAgent's 10-second minimum-runtime
        // window after SIGTERM; wait for that host-owned throttle before forcing
        // the deliberate running postcondition used by this rollback probe.
        await new Promise((resolve) => setTimeout(resolve, 10_500));
        const restart = await postconditionSupervisor.run({
          executable: LAUNCHCTL,
          args: ["kickstart", "-k", serviceId],
          cwd: "/",
          environment: {},
          timeoutMs: Math.min(request.timeoutMs, 5_000),
          outputCapBytes: request.outputCapBytes,
          shouldCancel: request.shouldCancel
        });
        if (restart.resultClass !== "SUCCEEDED") throw new Error("Rollback probe could not force the fixed postcondition mismatch");
      }
      return result;
    }
  };
  const adapter = new UserServiceControlAdapter({
    enabled: true,
    uid,
    bindings: [{
      serviceId,
      sourceRevision,
      plistPath,
      program: PROGRAM,
      arguments: PROGRAM_ARGUMENTS
    }],
    sourceRevisionReader,
    commandRunner,
    now: () => Date.now()
  });
  if (!adapter.available) throw new Error("Fixed user-service rollback boundary is unavailable");
  const executor = new UserServiceControlJobExecutor({ store, adapter, enabled: true, now: () => Date.now() });
  const broker = new Broker({
    store,
    policy: userServicePolicy(),
    edgeAuthenticationKeys: keyring,
    userServiceControlCandidate: {
      adapter,
      executor,
      authorizedPrincipalIds: ["principal-1"],
      enabled: true,
      now: () => Date.now()
    },
    now: () => Date.now()
  });
  let plistCreated = false;
  let primaryError;
  let cleanupError;
  try {
    const handle = await open(plistPath, "wx", 0o600);
    try {
      await handle.writeFile(launchAgentPlist, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await assertOwnedRegularFile(plistPath);
    plistCreated = true;
    const bootstrap = await runLaunchctl(["bootstrap", domain, plistPath]);
    if (bootstrap.code !== 0) throw new Error(`rollback probe bootstrap failed (${bootstrap.code ?? "unknown"})`);

    const initialStart = await nativeSupervisor.run({
      executable: LAUNCHCTL,
      args: ["kickstart", serviceId],
      cwd: "/",
      environment: {},
      timeoutMs: 5_000,
      outputCapBytes: 128 * 1024,
      shouldCancel: () => false
    });
    if (initialStart.resultClass !== "SUCCEEDED") throw new Error("Rollback probe could not establish the running pre-state");
    const initialStatus = await runLaunchctl(["print", serviceId]);
    if (initialStatus.code !== 0 || parseLaunchdJobReadback(serviceId, initialStatus.stdout).state !== "running") {
      throw new Error("Rollback probe running pre-state was not verified");
    }

    const argumentsValue = {
      service_id: serviceId,
      action: "stop",
      expected_state: "stopped",
      idempotency_key: "real-rollback"
    };
    issueApproval(approvalAuthority, operatorKey, argumentsValue, now);
    const request = {
      protocolVersion: "0.1",
      requestId: "request:real-user-service-rollback",
      contractVersion: "0.1",
      tool: "mac_service_control",
      arguments: argumentsValue,
      principal: {
        principalId: "principal-1",
        sessionId: "real-user-service-rollback",
        issuer: "test-issuer",
        audience: "mac-operator-broker",
        scopes: ["mac.control.read", "mac.service.control"],
        issuedAtMs: now - 1_000,
        expiresAtMs: now + 300_000,
        edgeId: "edge-1"
      },
      timestampMs: now,
      nonce: "nonce:real-user-service-rollback",
      policyAudience: "mac-operator-broker",
      policyVersion: "policy-0.1",
      authenticationKeyId: "edge-key-1"
    };
    const outcome = await broker.executeUserServiceControlCandidate(signRequest(request, edgeKey));
    const result = outcome.result;
    if (!result || result.resultClass !== "VERIFICATION_FAILED" || result.state !== "failed" ||
        result.rollback.status !== "verified" || result.rollback.state !== "running" ||
        result.postState !== "running" || result.verification.status !== "failed") {
      throw new Error(`Physical rollback result was not verified: ${JSON.stringify({ result, job: outcome.job })}`);
    }
    if (outcome.job.state !== "failed" || outcome.job.resultClass !== "verification_failed") {
      throw new Error("Physical rollback Job did not persist its verified failure state");
    }
    const status = await runLaunchctl(["print", serviceId]);
    if (status.code !== 0) throw new Error("Rollback readback could not inspect the disposable service");
    const readback = parseLaunchdJobReadback(serviceId, status.stdout);
    if (readback.state !== "running") throw new Error("Rollback did not restore the original running state");
    console.log(JSON.stringify({
      schemaVersion: "0.1",
      host: process.platform,
      uid,
      serviceId,
      sourceRevision,
      executable: PROGRAM,
      arguments: PROGRAM_ARGUMENTS,
      resultClass: result.resultClass,
      preState: result.preState,
      postState: result.postState,
      rollbackStatus: result.rollback.status,
      rollbackState: result.rollback.state,
      jobState: outcome.job.state,
      serviceState: readback.state,
      verified: true,
      realMutation: true
    }, null, 2));
  } catch (error) {
    primaryError = error;
  } finally {
    if (plistCreated) {
      const bootout = await runLaunchctl(["bootout", domain, plistPath]);
      const status = await runLaunchctl(["print", serviceId]);
      if (status.code === 0) cleanupError = new Error("Rollback probe service remained loaded after cleanup");
      if (bootout.code === null && cleanupError === undefined) cleanupError = new Error("Could not verify rollback probe cleanup");
      try {
        await assertOwnedRegularFile(plistPath);
        await unlink(plistPath);
      } catch (error) {
        cleanupError ??= error;
      }
    }
    await nativeSupervisor.close();
    await postconditionSupervisor.close();
    await broker.close();
    approvalAuthority.dispose();
    operatorKey.fill(0);
    store.close();
    edgeKey.fill(0);
    await rm(tempDirectory, { recursive: true, force: true });
    if (primaryError === undefined && cleanupError !== undefined) primaryError = cleanupError;
  }
  if (primaryError !== undefined) throw primaryError;
}

await main();
