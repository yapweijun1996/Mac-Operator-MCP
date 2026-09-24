import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

const MAX_MANIFEST_BYTES = 256 * 1024;
const COMPONENT_INPUT_KEYS = {
  edge: new Set([
    "uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature",
    "signaturePolicy", "signedArtifactPath", "enabledCapabilities", "expectedPreviousSourceRevision",
    "bindHost", "bindPort", "statusSocketPath", "statusKeyPath", "statusKeyDigest"
  ]),
  broker: new Set([
    "uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature",
    "signaturePolicy", "signedArtifactPath", "enabledCapabilities", "expectedPreviousSourceRevision",
    "statusSocketPath", "statusKeyPath", "statusKeyDigest"
  ]),
  authority: new Set([
    "uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature",
    "signaturePolicy", "signedArtifactPath", "enabledCapabilities", "expectedPreviousSourceRevision",
    "authorityConfigPath", "authorityOperatorSocketPath"
  ])
};
const REQUIRED_COMPONENT_INPUT_KEYS = {
  edge: new Set(["uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature", "signedArtifactPath", "bindHost", "bindPort"]),
  broker: new Set(["uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature", "signedArtifactPath"]),
  authority: new Set(["uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature", "signedArtifactPath", "authorityConfigPath", "authorityOperatorSocketPath"])
};

try {
  const argumentsValue = parseArguments(process.argv.slice(2));
  const primary = await readManifest(argumentsValue.manifestPath, "primary");
  const recovery = await readManifest(argumentsValue.recoveryPath, "recovery");
  validateManifestPair(primary, recovery);
  if (primary.operation !== argumentsValue.confirmation) throw new Error("--confirm must exactly match the primary manifest operation");
  const authorityRequired = primary.operation === "uninstall" || recovery.operation === "uninstall";
  const hasAuthorityComponent = primary.authority !== undefined;
  const authorityMaterialRequired = authorityRequired || hasAuthorityComponent;
  if (authorityMaterialRequired !== argumentsValue.hasAuthorityOptions) {
    throw new Error(authorityMaterialRequired
      ? "apply/readback requires the Authority database, operator socket, key config, and Edge identity for the Authority component or an uninstall operation"
      : "authority options are valid only for a three-component manifest or an uninstall operation");
  }
  if (hasAuthorityComponent && argumentsValue.hasAuthorityOptions &&
      argumentsValue.authoritySocketPath !== primary.authority.authorityOperatorSocketPath) {
    throw new Error("authority socket argument must exactly match the manifest operator socket path");
  }
  if (argumentsValue.apply && [primary.edge, primary.broker, primary.authority, recovery.edge, recovery.broker, recovery.authority].filter(Boolean).some((input) => input.signaturePolicy === "development-ad-hoc")) {
    throw new Error("apply requires production Developer ID plans; development ad-hoc plans are probe-only");
  }

  const broker = await import("../packages/broker/dist/index.js");
  const edge = await import("../packages/edge/dist/index.js");
  const primaryEdgePlan = broker.buildMacOsEdgeInstallPlan(withOperation(primary.edge, primary.operation));
  const primaryBrokerPlan = broker.buildMacOsInstallPlan(withOperation(primary.broker, primary.operation));
  const recoveryEdgePlan = broker.buildMacOsEdgeInstallPlan(withOperation(recovery.edge, recovery.operation));
  const recoveryBrokerPlan = broker.buildMacOsInstallPlan(withOperation(recovery.broker, recovery.operation));
  const primaryAuthorityPlan = hasAuthorityComponent
    ? broker.buildMacOsAuthorityInstallPlan(withOperation(primary.authority, primary.operation))
    : undefined;
  const recoveryAuthorityPlan = hasAuthorityComponent
    ? broker.buildMacOsAuthorityInstallPlan(withOperation(recovery.authority, recovery.operation))
    : undefined;
  const journalPath = broker.macOsDeploymentJournalPath(primaryEdgePlan.installRoot);
  const sourceDigest = sha256(JSON.stringify({ primary, recovery }));
  const transactionId = `tx-${Date.now()}-${sourceDigest.slice(0, 24)}`;
  const deploymentOrder = deploymentOrderFor(primary.operation, hasAuthorityComponent);

  let edgeStatusKey;
  let brokerStatusKey;
  let authorityStore;
  let authorityManager;
  let authorityClient;
  try {
    edgeStatusKey = await loadStatusKey(edge.loadProtectedEdgeAuthenticationKey, primary.edge);
    brokerStatusKey = await loadStatusKey(broker.loadAuthenticationKey, primary.broker);
    let authorityActions;
    if (authorityRequired) {
      authorityStore = new broker.BrokerStore(argumentsValue.authorityDatabasePath);
      authorityManager = new broker.AuthorityControlKeyManager(argumentsValue.authorityKeyConfigPath, authorityStore);
      await authorityManager.restore();
      authorityClient = authorityManager.createClient({ socketPath: argumentsValue.authoritySocketPath });
      authorityActions = broker.createAuthorityControlUninstallActions(authorityClient, argumentsValue.edgeId);
    }

    const edgeSpec = {
      plan: primaryEdgePlan,
      execution: createEdgeExecution(primaryEdgePlan, edge, edgeStatusKey, primary.edge),
      recovery: {
        plan: recoveryEdgePlan,
        execution: createEdgeExecution(recoveryEdgePlan, edge, edgeStatusKey, recovery.edge)
      }
    };
    const brokerSpec = {
      plan: primaryBrokerPlan,
      execution: createBrokerExecution(primaryBrokerPlan, broker, brokerStatusKey, authorityActions, argumentsValue.edgeId, primary.broker),
      recovery: {
        plan: recoveryBrokerPlan,
        execution: createBrokerExecution(recoveryBrokerPlan, broker, brokerStatusKey, authorityActions, argumentsValue.edgeId, recovery.broker)
      }
    };
    const authorityExecution = primaryAuthorityPlan === undefined || recoveryAuthorityPlan === undefined ? undefined : {
      plan: primaryAuthorityPlan,
      execution: createAuthorityExecution(primaryAuthorityPlan, broker, authorityClient),
      recovery: {
        plan: recoveryAuthorityPlan,
        execution: createAuthorityExecution(recoveryAuthorityPlan, broker, authorityClient)
      }
    };
    if (argumentsValue.readback) {
      const journal = await broker.readMacOsDeploymentJournal(journalPath);
      if (journal === null || journal.sourceDigest !== sourceDigest || journal.operation !== primary.operation || journal.phase === "recovery-required") {
        throw new Error("macOS deployment journal is absent, stale, or requires recovery");
      }
      const components = {
        ...(authorityExecution === undefined ? {} : { authority: summarizeReadback(await authorityExecution.execution.readback()) }),
        edge: summarizeReadback(await edgeSpec.execution.readback()),
        broker: summarizeReadback(await brokerSpec.execution.readback())
      };
      process.stdout.write(`${JSON.stringify({
        schemaVersion: "0.1",
        mechanism: "macos-launchagent-readback-v1",
        status: "readback-verified",
        operation: primary.operation,
        order: deploymentOrder,
        components,
        mutation: "none",
        journal: {
          phase: journal.phase,
          transactionId: journal.transactionId,
          completedComponents: journal.completedComponents,
          failedComponent: journal.failedComponent
        },
        recovery: {
          inverseOperation: recovery.operation,
          authorityRequiredForBrokerUninstall: authorityRequired
        }
      })}\n`);
    } else {
      const existingJournal = await broker.readMacOsDeploymentJournal(journalPath);
      if (existingJournal?.phase === "in-progress" || existingJournal?.phase === "recovery-required") {
        throw new Error("macOS deployment journal requires explicit recovery before a new apply");
      }
      await broker.writeMacOsDeploymentJournal(journalPath, {
        schemaVersion: "0.1",
        mechanism: "macos-launchagent-deployment-journal-v1",
        transactionId,
        operation: primary.operation,
        order: deploymentOrder,
        completedComponents: [],
        phase: "in-progress",
        sourceDigest,
        updatedAtMs: Date.now(),
        failedComponent: null
      });
      let result;
      try {
        result = authorityExecution === undefined
          ? await broker.executeMacOsLaunchAgentPlans({
            mode: "production",
            operation: primary.operation,
            edge: edgeSpec,
            broker: brokerSpec
          })
          : await broker.executeMacOsLaunchAgentPlansWithAuthority({
            mode: "production",
            operation: primary.operation,
            authority: authorityExecution,
            edge: edgeSpec,
            broker: brokerSpec
          });
      } catch (error) {
        const details = error?.details;
        const completedComponents = Array.isArray(details?.completedComponents) ? details.completedComponents : [];
        const phase = details?.recoveryState === "recovery-required"
          ? "recovery-required"
          : details?.recoveryState === "recovered" ? "recovered" : "in-progress";
        try {
          await broker.writeMacOsDeploymentJournal(journalPath, {
            schemaVersion: "0.1",
            mechanism: "macos-launchagent-deployment-journal-v1",
            transactionId,
            operation: primary.operation,
            order: deploymentOrder,
            completedComponents,
            phase,
            sourceDigest,
            updatedAtMs: Date.now(),
            failedComponent: details?.failedComponent ?? null
          });
        } catch (journalError) {
          throw new Error("macOS deployment journal update failed", { cause: journalError });
        }
        throw error;
      }
      await broker.writeMacOsDeploymentJournal(journalPath, {
        schemaVersion: "0.1",
        mechanism: "macos-launchagent-deployment-journal-v1",
        transactionId,
        operation: primary.operation,
        order: deploymentOrder,
        completedComponents: deploymentOrder,
        phase: "applied",
        sourceDigest,
        updatedAtMs: Date.now(),
        failedComponent: null
      });
      process.stdout.write(`${JSON.stringify({
        schemaVersion: "0.1",
        mechanism: "macos-launchagent-apply-v1",
        status: "applied",
        operation: result.operation,
        order: result.order,
        components: {
          ...(primaryAuthorityPlan === undefined ? {} : { authority: summarizeExecution(result.authority) }),
          edge: summarizeExecution(result.edge),
          broker: summarizeExecution(result.broker)
        },
        recovery: {
          prebound: true,
          inverseOperation: recovery.operation,
          authorityRequiredForBrokerUninstall: authorityRequired
        }
      })}\n`);
    }
  } finally {
    authorityClient?.dispose();
    authorityManager?.dispose();
    authorityStore?.close();
    edgeStatusKey?.fill(0);
    brokerStatusKey?.fill(0);
  }
} catch (error) {
  const message = error instanceof Error ? error.message : "macOS LaunchAgent apply failed";
  process.stderr.write(`macOS LaunchAgent apply failed: ${message}\n`);
  process.exitCode = 1;
}

function parseArguments(args) {
  const values = new Map();
  let apply = false;
  let readback = false;
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    if (flag === "--apply") {
      if (apply) throw new Error("--apply may be provided only once");
      apply = true;
      continue;
    }
    if (flag === "--readback") {
      if (readback) throw new Error("--readback may be provided only once");
      readback = true;
      continue;
    }
    if (!["--manifest", "--recovery", "--confirm", "--authority-database", "--authority-socket", "--authority-operator-socket", "--authority-key-config", "--edge-id"].includes(flag)) {
      throw new Error("unsupported apply/readback option");
    }
    if (values.has(flag) || index + 1 >= args.length) throw new Error(`missing or duplicate ${flag}`);
    values.set(flag, args[++index]);
  }
  if (apply === readback || !values.has("--manifest") || !values.has("--recovery") || !values.has("--confirm")) {
    throw new Error("usage: node scripts/apply-macos-launchagents.mjs --manifest PRIMARY.json --recovery INVERSE.json --confirm install|upgrade|rollback|uninstall (--apply|--readback) [authority options]");
  }
  const confirmation = values.get("--confirm");
  if (!["install", "upgrade", "rollback", "uninstall"].includes(confirmation)) throw new Error("--confirm operation is invalid");
  const authoritySocketFlags = ["--authority-socket", "--authority-operator-socket"];
  if (authoritySocketFlags.every((flag) => values.has(flag))) {
    throw new Error("provide only one Authority operator socket option");
  }
  const authorityFlags = ["--authority-database", "--authority-key-config", "--edge-id"];
  const authorityPresent = [...authorityFlags, ...authoritySocketFlags].some((flag) => values.has(flag));
  if (authorityPresent && (authorityFlags.some((flag) => !values.has(flag)) || authoritySocketFlags.every((flag) => !values.has(flag)))) {
    throw new Error("authority options must include the Authority database, operator socket, key config, and Edge identity");
  }
  const authoritySocketFlag = authoritySocketFlags.find((flag) => values.has(flag));
  return {
    manifestPath: canonicalPath(values.get("--manifest"), "primary manifest"),
    recoveryPath: canonicalPath(values.get("--recovery"), "recovery manifest"),
    confirmation,
    apply,
    readback,
    hasAuthorityOptions: authorityPresent,
    ...(authorityPresent ? {
      authorityDatabasePath: canonicalPath(values.get("--authority-database"), "authority database"),
      authoritySocketPath: canonicalPath(values.get(authoritySocketFlag), "authority operator socket"),
      authorityKeyConfigPath: canonicalPath(values.get("--authority-key-config"), "authority key config"),
      edgeId: validId(values.get("--edge-id"), "Edge identity")
    } : {})
  };
}

async function readManifest(path, label) {
  let stats;
  try { stats = lstatSync(path); } catch { throw new Error(`${label} manifest is unavailable`); }
  const uid = process.getuid?.() ?? -1;
  if (!stats.isFile() || stats.uid !== uid || (stats.mode & 0o077) !== 0) throw new Error(`${label} manifest must be an owner-only regular file`);
  const bytes = readFileSync(path);
  if (bytes.byteLength > MAX_MANIFEST_BYTES) throw new Error(`${label} manifest exceeds its size budget`);
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new Error(`${label} manifest is not strict UTF-8 JSON`); }
  validateManifest(value, label);
  return value;
}

function validateManifest(value, label) {
  assertRecord(value, `${label} manifest`);
  const expectedKeys = Object.hasOwn(value, "authority")
    ? ["authority", "broker", "edge", "operation", "schemaVersion"]
    : ["broker", "edge", "operation", "schemaVersion"];
  assertExactKeys(value, expectedKeys, `${label} manifest`);
  if (value.schemaVersion !== "0.1" || !["install", "upgrade", "rollback", "uninstall"].includes(value.operation)) throw new Error(`${label} manifest schema or operation is invalid`);
  validateComponent(value.edge, "edge", label);
  validateComponent(value.broker, "broker", label);
  if (Object.hasOwn(value, "authority")) validateComponent(value.authority, "authority", label);
}

function validateComponent(value, component, label) {
  assertRecord(value, `${label} ${component} deployment input`);
  if (Object.keys(value).some((key) => !COMPONENT_INPUT_KEYS[component].has(key))) throw new Error(`${label} ${component} deployment input contains unsupported fields`);
  for (const key of REQUIRED_COMPONENT_INPUT_KEYS[component]) if (!Object.hasOwn(value, key)) throw new Error(`${label} ${component} deployment input is missing ${key}`);
  if (component === "authority") return;
  const fields = [value.statusSocketPath, value.statusKeyPath, value.statusKeyDigest];
  if (fields.some((field) => field === undefined) || fields.some((field) => typeof field !== "string")) throw new Error(`${label} ${component} status channel is required for apply`);
  if (!isCanonicalPath(value.statusSocketPath) || !value.statusSocketPath.endsWith(".sock") || !isCanonicalPath(value.statusKeyPath) ||
      !isDescendant(value.installRoot, value.statusSocketPath) || !isDescendant(value.installRoot, value.statusKeyPath) ||
      !/^[a-f0-9]{64}$/u.test(value.statusKeyDigest)) throw new Error(`${label} ${component} status channel path or digest is invalid`);
}

function validateManifestPair(primary, recovery) {
  const expected = { install: "uninstall", upgrade: "rollback", rollback: "upgrade", uninstall: "install" }[primary.operation];
  if (recovery.operation !== expected) throw new Error("recovery manifest operation is not the exact inverse of the primary operation");
  if ((primary.authority === undefined) !== (recovery.authority === undefined)) {
    throw new Error("primary and recovery manifests must both include or both omit the Authority component");
  }
  const components = primary.authority === undefined ? ["edge", "broker"] : ["authority", "edge", "broker"];
  for (const component of components) {
    for (const key of ["uid", "userHome", "installRoot"]) {
      if (primary[component][key] !== recovery[component][key]) throw new Error(`${component} recovery identity does not match the primary manifest`);
    }
    for (const key of ["statusSocketPath", "statusKeyPath", "statusKeyDigest"]) {
      if (component === "authority") break;
      if (primary[component][key] !== recovery[component][key]) throw new Error(`${component} recovery status channel does not match the primary manifest`);
    }
    if (component === "authority") {
      for (const key of ["authorityConfigPath", "authorityOperatorSocketPath"]) {
        if (primary[component][key] !== recovery[component][key]) throw new Error(`authority recovery ${key} does not match the primary manifest`);
      }
    }
  }
}

function withOperation(value, operation) {
  return { operation, ...value };
}

async function loadStatusKey(loader, input) {
  const key = await loader(input.statusKeyPath, input.statusKeyDigest);
  if (sha256(key) !== input.statusKeyDigest) {
    key.fill(0);
    throw new Error("status key digest does not match the manifest");
  }
  return key;
}

function createEdgeExecution(plan, edge, statusKey, input) {
  const observer = edge.createMacOsEdgeInstallHostObserver(plan, {
    readEdge: () => edge.readEdgeStatus({ socketPath: statusSocketFor(input), authenticationKey: statusKey })
  });
  return {
    ownerUid: ownerUid(plan),
    readExistingService: edge.createMacOsEdgeInstallExistingServiceReader(plan, {
      readEdge: observer.readEdge,
      readLaunchd: observer.readLaunchd,
      readProcessIdentity: observer.readProcessIdentity,
      readPlist: observer.readPlist,
      readSignature: observer.readSignature,
      ...(observer.readNotarization === undefined ? {} : { readNotarization: observer.readNotarization })
    }),
    readback: () => readEdgeSources(plan, observer, edge)
  };
}

function createBrokerExecution(plan, broker, statusKey, authorityActions, edgeId, input) {
  const observer = broker.createMacOsInstallHostObserver(plan, {
    brokerStatusClient: { socketPath: statusSocketFor(input), authenticationKey: statusKey }
  });
  const base = {
    ownerUid: ownerUid(plan),
    readExistingService: broker.createMacOsInstallExistingServiceReader(plan, {
      readBroker: observer.readBroker,
      readLaunchd: observer.readLaunchd,
      readProcessIdentity: observer.readProcessIdentity,
      readPlist: observer.readPlist,
      readSignature: observer.readSignature,
      ...(observer.readNotarization === undefined ? {} : { readNotarization: observer.readNotarization })
    }),
    readback: () => readBrokerSources(plan, observer, broker)
  };
  if (plan.operation === "uninstall") {
    if (authorityActions === undefined) throw new Error("Broker uninstall authority actions are unavailable");
    return { uninstall: { ...base, edgeId, ...authorityActions } };
  }
  return { install: base };
}

function createAuthorityExecution(plan, broker, authorityClient) {
  if (authorityClient === undefined) throw new Error("Authority execution requires the owner operator client");
  const readAuthority = plan.operation === "install"
    ? undefined
    : async () => {
      await authorityClient.readSwitch("global");
      return {
        component: "mac-operator-authority",
        state: "running",
        sourceRevision: plan.metadata.sourceRevision,
        contractVersion: plan.metadata.contractVersion,
        policyVersion: plan.metadata.policyVersion,
        operatorSocketPath: plan.authorityOperatorSocketPath
      };
    };
  const observer = broker.createMacOsAuthorityInstallHostObserver(plan, {
    ...(readAuthority === undefined ? {} : { readAuthority })
  });
  return {
    ownerUid: ownerUid(plan),
    readExistingService: broker.createMacOsAuthorityInstallExistingServiceReader(plan, {
      readLaunchd: observer.readLaunchd,
      readProcessIdentity: observer.readProcessIdentity,
      readPlist: observer.readPlist,
      readSignature: observer.readSignature,
      ...(observer.readAuthority === undefined ? {} : { readAuthority: observer.readAuthority }),
      ...(observer.readNotarization === undefined ? {} : { readNotarization: observer.readNotarization })
    }),
    readback: () => readAuthoritySources(plan, observer, broker)
  };
}

async function readEdgeSources(plan, observer, edge) {
  if (plan.operation === "uninstall") return await readAbsentOrSources(plan, observer, () => edge.collectMacOsEdgeInstallReadbackSources(plan, observer));
  return edge.collectMacOsEdgeInstallReadbackSources(plan, observer);
}

async function readBrokerSources(plan, observer, broker) {
  if (plan.operation === "uninstall") return await readAbsentOrSources(plan, observer, () => broker.collectMacOsInstallReadbackSources(plan, observer));
  return broker.collectMacOsInstallReadbackSources(plan, observer);
}

async function readAuthoritySources(plan, observer, broker) {
  if (plan.operation === "uninstall") return await readAbsentOrSources(plan, observer, () => broker.collectMacOsAuthorityInstallReadbackSources(plan, observer));
  return broker.collectMacOsAuthorityInstallReadbackSources(plan, observer);
}

async function readAbsentOrSources(plan, observer, collect) {
  try {
    await observer.readLaunchd(`${plan.domain}/${plan.label}`);
  } catch (error) {
    if (error?.code === "UNAVAILABLE") return null;
    throw error;
  }
  return collect();
}

function statusSocketFor(input) {
  if (input === null || typeof input !== "object" || typeof input.statusSocketPath !== "string") {
    throw new Error("status socket binding is unavailable in the apply manifest");
  }
  return input.statusSocketPath;
}

function summarizeExecution(result) {
  return { operation: result.operation, plist: result.plist, readback: result.readback === null ? null : { state: "verified" } };
}

function summarizeReadback(result) {
  return result === null ? { state: "absent" } : { state: "verified" };
}

function deploymentOrderFor(operation, hasAuthorityComponent) {
  if (hasAuthorityComponent) return operation === "uninstall" ? ["broker", "edge", "authority"] : ["authority", "edge", "broker"];
  return operation === "uninstall" ? ["broker", "edge"] : ["edge", "broker"];
}

function ownerUid(plan) {
  const value = Number(plan.domain.slice("gui/".length));
  if (!Number.isSafeInteger(value) || value < 1) throw new Error("plan owner UID is invalid");
  return value;
}

function canonicalPath(value, label) {
  if (!isCanonicalPath(value)) throw new Error(`${label} must be a canonical absolute path`);
  return value;
}

function isCanonicalPath(value) {
  return typeof value === "string" && isAbsolute(value) && value !== "/" && !value.endsWith("/") && !value.includes("\0") && resolve(value) === value;
}

function isDescendant(root, target) {
  const suffix = relative(root, target);
  return suffix.length > 0 && !suffix.startsWith("..") && !isAbsolute(suffix);
}

function validId(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function assertRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${label} must be a plain object`);
}

function assertExactKeys(value, allowed, label) {
  const expected = [...allowed].sort();
  const actual = Object.keys(value).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} contains unsupported or missing fields`);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
