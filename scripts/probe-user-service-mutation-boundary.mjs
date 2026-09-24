import { randomBytes } from "node:crypto";
import { execFile as childExecFile } from "node:child_process";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { lstat, mkdtemp, open, readFile, realpath, rm, unlink } from "node:fs/promises";
import {
  Broker,
  BrokerStore,
  EdgeKeyring,
  ApprovalAuthority,
  parseLaunchdJobReadback,
  UserServiceControlAdapter,
  UserServiceControlJobExecutor,
  approvalPreviewDigest,
  signApprovalIssuance
} from "../packages/broker/dist/index.js";
import { createDefaultPolicy } from "../packages/broker/dist/default-policy.js";
import { canonicalJson, sha256, signRequest } from "../packages/contracts/dist/index.js";

const execFile = promisify(childExecFile);
const LAUNCHCTL = "/bin/launchctl";
const uid = typeof process.getuid === "function" ? process.getuid() : -1;
const label = "com.mac-operator.boundary-probe";
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
    <string>/bin/sleep</string>
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
  throw new Error("Set MOPS_REAL_USER_SERVICE=1 to run the bounded real-Mac mutation probe");
}
if (process.platform !== "darwin" || !Number.isSafeInteger(uid) || uid < 1) {
  throw new Error("The user-service mutation probe requires a non-root macOS user");
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
  if (result.code === 0) throw new Error("Disposable service identity is already loaded");
  if (result.code === null) throw new Error("Could not prove disposable service identity is absent");
}

async function assertOwnedRegularFile(path) {
  const entry = await lstat(path);
  if (!entry.isFile() || entry.isSymbolicLink() || entry.uid !== uid || (entry.mode & 0o022) !== 0) {
    throw new Error("Probe plist failed owner-only regular-file checks");
  }
  if (await realpath(path) !== path) throw new Error("Probe plist is not canonical");
}

async function createProbePlist(content = launchAgentPlist) {
  const handle = await open(plistPath, "wx", 0o600);
  try {
    await handle.writeFile(content, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await assertOwnedRegularFile(plistPath);
}

function userServicePolicy() {
  const base = createDefaultPolicy("edge-1", true, ["mac.control.read", "mac.service.control"], ["edge-key-1"]);
  const tool = base.tools.get("mac_service_control");
  if (!tool) throw new Error("Default policy is missing mac_service_control");
  return {
    ...base,
    targetRules: [...base.targetRules, {
      ruleId: "real-user-service-probe-target",
      effect: "allow",
      principalId: "principal-1",
      scope: "mac.service.control",
      target: { kind: "service", reference: serviceId }
    }],
    tools: new Map(base.tools).set("mac_service_control", { ...tool, implemented: true, enabled: true })
  };
}

function issueApproval(authority, operatorKey, approvalId, argumentsValue, suffix, now) {
  const approval = {
    approvalId,
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
    requestId: `approval-issue:real-user-service-${suffix}`,
    nonce: `approval-nonce:real-user-service-${suffix}`,
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
  const revision = sha256(Buffer.from(launchAgentPlist, "utf8"));
  const now = Date.now();
  const tempDirectory = await mkdtemp(join(tmpdir(), "mac-operator-user-service-probe-"));
  const databasePath = join(tempDirectory, "probe.sqlite");
  const store = new BrokerStore(databasePath);
  const key = randomBytes(32);
  const keyring = new EdgeKeyring([{
    edgeId: "edge-1",
    keyId: "edge-key-1",
    key,
    notBeforeMs: now - 60_000,
    expiresAtMs: now + 300_000
  }]);
  const operatorKey = randomBytes(32);
  const approvalAuthority = new ApprovalAuthority(store, [{
    issuerId: "probe-operator",
    keyId: "operator-key-1",
    key: operatorKey,
    notBeforeMs: now - 60_000,
    expiresAtMs: now + 300_000,
    allowUnattended: false
  }], { now: () => now });
  let sourceRevisionReadCount = 0;
  let activeRevocationEnabled = false;
  let activeRevocationTriggered = false;
  let restartReconciliation;
  const sourceRevisionReader = {
    async read(requestedServiceId, control) {
      if (requestedServiceId !== serviceId || control.shouldCancel()) throw new Error("Probe source readback was not authorized");
      sourceRevisionReadCount += 1;
      if (activeRevocationEnabled && !activeRevocationTriggered && sourceRevisionReadCount === 3) {
        store.setSwitch(
          "mutations",
          true,
          "REAL_PROBE_ACTIVE_REVOCATION",
          Date.now(),
          false,
          "authority-switch-real-user-service-active-revocation"
        );
        restartReconciliation = store.reconcileInterruptedJobs(Date.now());
        activeRevocationTriggered = true;
      }
      return sha256(await readFile(plistPath));
    }
  };
  const adapter = new UserServiceControlAdapter({
    enabled: true,
    uid,
    bindings: [{
      serviceId,
      sourceRevision: revision,
      plistPath,
      program: "/bin/sleep",
      arguments: ["/bin/sleep", "60"]
    }],
    sourceRevisionReader,
    systemPublishedExecutablePathAccepted: true,
    now: () => Date.now()
  });
  if (!adapter.available) throw new Error("Fixed user-service host boundary is unavailable");
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
  const results = [];
  let primaryError;
  let cleanupError;
  try {
    async function loadProbeService(content = launchAgentPlist) {
      await createProbePlist(content);
      plistCreated = true;
      const bootstrap = await runLaunchctl(["bootstrap", domain, plistPath]);
      if (bootstrap.code !== 0) throw new Error(`launchctl bootstrap failed (${bootstrap.code ?? "unknown"})`);
    }

    async function unloadProbeService() {
      const bootout = await runLaunchctl(["bootout", domain, plistPath]);
      const status = await runLaunchctl(["print", serviceId]);
      if (status.code === 0) throw new Error("Disposable service remained loaded after bounded probe phase");
      if (bootout.code === null) throw new Error("Could not verify bounded probe unload");
      await assertOwnedRegularFile(plistPath);
      await unlink(plistPath);
      plistCreated = false;
    }

    await loadProbeService();
    async function send(argumentsValue, suffix) {
      const requestId = `request:real-user-service-${suffix}`;
      issueApproval(approvalAuthority, operatorKey, `approval:real-user-service-${suffix}`, argumentsValue, suffix, now);
      const request = {
        protocolVersion: "0.1",
        requestId,
        contractVersion: "0.1",
        tool: "mac_service_control",
        arguments: argumentsValue,
        principal: {
          principalId: "principal-1",
          sessionId: "real-user-service-probe",
          issuer: "test-issuer",
          audience: "mac-operator-broker",
          scopes: ["mac.control.read", "mac.service.control"],
          issuedAtMs: now - 1_000,
          expiresAtMs: now + 300_000,
          edgeId: "edge-1"
        },
        timestampMs: now,
        nonce: `nonce:real-user-service-${suffix}`,
        policyAudience: "mac-operator-broker",
        policyVersion: "policy-0.1",
        authenticationKeyId: "edge-key-1"
      };
      return { request, approvalId: `approval:real-user-service-${suffix}`, result: await broker.handle(signRequest(request, key)) };
    }

    async function call(action, expectedState, idempotencyKey, suffix) {
      const argumentsValue = {
        service_id: serviceId,
        action,
        expected_state: expectedState,
        idempotency_key: idempotencyKey
      };
      const { result } = await send(argumentsValue, suffix);
      if (!result.ok) throw new Error(`${action} returned ${result.result_class}`);
      const data = result.data;
      if (!data || data.service_id !== serviceId || data.post_state !== expectedState || result.verification.status !== "verified") {
        throw new Error(`${action} returned an unverifiable service state`);
      }
      results.push({ action, preState: data.pre_state, postState: data.post_state, rollbackStatus: data.rollback_status, verified: true });
    }

    await call("start", "running", "real-start", "start");
    await call("stop", "stopped", "real-stop", "stop");

    const swappedPlist = launchAgentPlist.replace("<string>60</string>", "<string>61</string>");
    await unloadProbeService();
    await loadProbeService(swappedPlist);
    const targetSwapArguments = {
      service_id: serviceId,
      action: "start",
      expected_state: "running",
      idempotency_key: "real-target-swap"
    };
    const targetSwapCall = await send(targetSwapArguments, "target-swap");
    if (targetSwapCall.result.ok || targetSwapCall.result.result_class !== "PRECONDITION_FAILED") {
      throw new Error(`target-swap was not rejected before dispatch: ${targetSwapCall.result.result_class}`);
    }
    const targetSwapApproval = store.approvalRecord(targetSwapCall.approvalId);
    if (targetSwapApproval?.usedCount !== 1) throw new Error("target-swap did not consume exactly one bound approval");
    const targetSwapStatus = await runLaunchctl(["print", serviceId]);
    if (targetSwapStatus.code !== 0) throw new Error("target-swap readback could not inspect the disposable service");
    const targetSwapReadback = parseLaunchdJobReadback(serviceId, targetSwapStatus.stdout);
    if (targetSwapReadback.state !== "stopped") throw new Error("target-swap dispatched an unexpected service transition");
    await unloadProbeService();
    await loadProbeService();
    if (sha256(await readFile(plistPath)) !== revision) throw new Error("target-swap probe did not restore the exact source revision");
    results.push({
      action: "target_swap",
      resultClass: targetSwapCall.result.result_class,
      approvalConsumed: true,
      serviceState: targetSwapReadback.state,
      sourceRestored: true,
      verified: true
    });

    sourceRevisionReadCount = 0;
    activeRevocationEnabled = true;
    const activeRevocationArguments = {
      service_id: serviceId,
      action: "start",
      expected_state: "running",
      idempotency_key: "real-active-revocation"
    };
    const activeRevocationCall = await send(activeRevocationArguments, "active-revocation");
    activeRevocationEnabled = false;
    if (activeRevocationCall.result.ok || activeRevocationCall.result.result_class !== "UNKNOWN_OUTCOME" ||
        !activeRevocationTriggered || restartReconciliation?.runningUnknown !== 1) {
      throw new Error(`active revocation did not preserve UNKNOWN_OUTCOME (reads=${sourceRevisionReadCount}, triggered=${activeRevocationTriggered})`);
    }
    const revokedRequest = store.requestRecord(activeRevocationCall.request.requestId);
    if (revokedRequest?.state !== "UNKNOWN" || revokedRequest.jobId === null) {
      throw new Error("active revocation did not persist an UNKNOWN request Job");
    }
    const revokedJob = store.ownedJob(revokedRequest.jobId, "principal-1");
    if (revokedJob?.state !== "unknown") throw new Error("active revocation did not persist an UNKNOWN Job");
    const activeRevocationStatus = await runLaunchctl(["print", serviceId]);
    if (activeRevocationStatus.code !== 0) throw new Error("active revocation readback could not inspect the disposable service");
    const activeRevocationReadback = parseLaunchdJobReadback(serviceId, activeRevocationStatus.stdout);
    if (activeRevocationReadback.state !== "running") throw new Error("active revocation did not leave an unresolved live mutation for cleanup");
    results.push({
      action: "active_revocation",
      resultClass: activeRevocationCall.result.result_class,
      requestState: revokedRequest.state,
      jobState: revokedJob.state,
      serviceState: activeRevocationReadback.state,
      killSwitchTriggered: true,
      restartMarkedUnknown: true,
      verified: true
    });

    const recoveryStore = new BrokerStore(databasePath);
    try {
      const recoveryAdapter = new UserServiceControlAdapter({
        enabled: true,
        uid,
        bindings: [{
          serviceId,
          sourceRevision: revision,
          plistPath,
          program: "/bin/sleep",
          arguments: ["/bin/sleep", "60"]
        }],
        sourceRevisionReader,
        systemPublishedExecutablePathAccepted: true,
        now: () => Date.now()
      });
      const recoveryExecutor = new UserServiceControlJobExecutor({
        store: recoveryStore,
        adapter: recoveryAdapter,
        enabled: true,
        now: () => Date.now()
      });
      const recovery = await recoveryExecutor.reconcileRestartedJobs();
      const recoveredRequest = recoveryStore.requestRecord(activeRevocationCall.request.requestId);
      const recoveredJob = recoveredRequest?.jobId === null || recoveredRequest?.jobId === undefined
        ? undefined
        : recoveryStore.ownedJob(recoveredRequest.jobId, "principal-1");
      if (recovery.inspected !== 1 || recovery.readback !== 1 || recovery.identityMismatch !== 0 ||
          recovery.unavailable !== 0 || recovery.unknown !== 0 || recoveredJob?.state !== "unknown") {
        throw new Error(`restart recovery did not preserve UNKNOWN without replay: ${JSON.stringify({ recovery, job: recoveredJob })}`);
      }
      results.push({
        action: "restart_recovery",
        inspected: recovery.inspected,
        readback: recovery.readback,
        jobState: recoveredJob.state,
        mutationReplayed: false,
        serviceState: activeRevocationReadback.state,
        verified: true
      });
    } finally {
      recoveryStore.close();
    }
  } catch (error) {
    primaryError = error;
  } finally {
    if (plistCreated) {
      const bootout = await runLaunchctl(["bootout", domain, plistPath]);
      const status = await runLaunchctl(["print", serviceId]);
      if (status.code === 0) cleanupError = new Error("Disposable service remained loaded after cleanup");
      if (bootout.code === null && cleanupError === undefined) cleanupError = new Error("Could not verify launchctl cleanup");
      try {
        await assertOwnedRegularFile(plistPath);
        await unlink(plistPath);
      } catch (error) {
        cleanupError ??= error;
      }
    }
    await broker.close();
    approvalAuthority.dispose();
    operatorKey.fill(0);
    store.close();
    key.fill(0);
    await rm(tempDirectory, { recursive: true, force: true });
    if (primaryError === undefined && cleanupError !== undefined) primaryError = cleanupError;
  }
  if (primaryError !== undefined) throw primaryError;
  console.log(JSON.stringify({
    schemaVersion: "0.1",
    host: process.platform,
    uid,
    serviceId,
    sourceRevision: revision,
    executable: "/bin/sleep",
    arguments: ["/bin/sleep", "60"],
    results,
    cleanup: { plistRemoved: true, serviceUnloaded: true },
    realMutation: true
  }, null, 2));
}

await main();
