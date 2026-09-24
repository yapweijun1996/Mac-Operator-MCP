import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, readdir, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import {
  AppSandboxTaskRunner,
  DescriptorSnapshotAttestationSigner,
  DescriptorSnapshotAttestationVerifier,
  DescriptorSnapshotRegistry,
  NativeAppSandboxTaskExecutor,
  loadNativePeerAdapter
} from "@mac-operator/broker";

assert.equal(process.platform, "darwin", "This probe requires macOS");

const bundleIdentifier = "com.macoperator.mopappsandboxhelper";
const containerRoot = join(homedir(), "Library/Containers", bundleIdentifier, "Data");
const helperPath = join(process.cwd(), "packages/broker/dist/AppSandboxHelper.app/Contents/MacOS/app_sandbox_helper");
const helperContentSha256 = createHash("sha256").update(await readFile(helperPath)).digest("hex");
const probeRoot = await realpath(await mkdtemp(join(tmpdir(), "mop-app-sandbox-executor-source-")));
const probeId = randomUUID();
const outsideCanaryPath = join(tmpdir(), `mop-app-sandbox-executor-outside-${probeId}.txt`);
const persistenceCanaryPath = join(homedir(), "Library/LaunchAgents", `com.macoperator.mop-executor-probe-${probeId}.plist`);
const credentialZonePath = join(homedir(), ".ssh");
const scriptPath = join(probeRoot, "task.sh");
const inputPath = join(probeRoot, "input.txt");
const processScriptPath = join(probeRoot, "process-tree.sh");
const outputName = "executor-roundtrip.txt";
const networkProxyProbe = process.env.MOP_PROBE_NETWORK_PROXY === "1";
let networkRequests = 0;
const networkServer = createServer((socket) => {
  if (!networkProxyProbe) {
    socket.destroy();
    return;
  }
  socket.on("data", (chunk) => {
    networkRequests += 1;
    socket.end(Buffer.from(`proxy:${chunk.toString("utf8")}`, "utf8"));
  });
});
await new Promise((resolve, reject) => {
  networkServer.once("error", reject);
  networkServer.listen(0, "127.0.0.1", resolve);
});
const networkAddress = networkServer.address();
if (networkAddress === null || typeof networkAddress === "string") throw new Error("Executor network probe server did not expose a port");
const networkPort = networkAddress.port;
networkServer.unref();
const networkScript = networkProxyProbe ? [
  'test "$MOP_NETWORK_PROXY_FD" = 7',
  `printf '%s\\n' '{"capabilityToken":"'"$MOP_NETWORK_PROXY_TOKEN"'","kind":"network_request","payloadBase64":"bmV0d29yay1zYWZl","requestId":"child-network:probe-0001","schemaVersion":"0.1","target":"tcp://localhost:${networkPort}"}' >&7`,
  'IFS= read -r network_response <&7',
  `case "$network_response" in *'"ok":true'*'"responseBase64":"cHJveHk6bmV0d29yay1zYWZl"'*) : ;; *) exit 1 ;; esac`,
  "printf 'network-proxy=verified\\n'"
].join("\n") : "";
const script = `#!/bin/sh
set -eu
IFS= read -r staged_input < input.txt
test "$staged_input" = staged-input
if IFS= read -r outside_input < '${outsideCanaryPath}'; then exit 1; fi
if : > /dev/tcp/127.0.0.1/${networkPort} 2>/dev/null; then exit 1; fi
if : > '${persistenceCanaryPath}' 2>/dev/null; then exit 1; fi
if IFS= read -r credential_input < '${credentialZonePath}' 2>/dev/null; then exit 1; fi
${networkScript}
test ! -e ../k
test ! -e ../q
test ! -e ../a
test ! -e ../p
: > "$1"
test -f "$1"
printf 'staged-read-and-write=verified\\n'
printf 'outside-read-denied=verified\\n'
printf 'control-material-unreachable=verified\\n'
printf 'network-connect-denied=verified\\n'
printf 'persistence-write-denied=verified\\n'
printf 'credential-zone-read-denied=verified\\n'
`;
const hostileProcessScript = `#!/bin/sh
set -eu
exec /usr/bin/perl -MPOSIX -e '
my $child = fork();
die "first fork failed" unless defined $child;
if ($child == 0) {
  my $session = POSIX::setsid();
  die "first setsid failed" unless defined $session;
  my $grandchild = fork();
  die "second fork failed" unless defined $grandchild;
  if ($grandchild == 0) {
    my $grandchild_session = POSIX::setsid();
    die "second setsid failed" unless defined $grandchild_session;
    $| = 1;
    print STDOUT "MOP_DETACHED_GRANDCHILD pid=$$ parent=", getppid(), " process_group=", getpgrp(0), "\\n";
    select(undef, undef, undef, 1.5);
    exit 0;
  }
  waitpid($grandchild, 0);
  exit 0;
}
waitpid($child, 0);
'
`;

await mkdir(probeRoot, { recursive: true, mode: 0o700 });
await writeFile(scriptPath, script, { mode: 0o700 });
await writeFile(inputPath, "staged-input\n", { mode: 0o600 });
await writeFile(processScriptPath, hostileProcessScript, { mode: 0o700 });
await writeFile(outsideCanaryPath, "host-canary\n", { mode: 0o600, flag: "wx" });
await stat(join(homedir(), "Library/LaunchAgents"));
await stat(credentialZonePath);
await stat(persistenceCanaryPath).then(
  () => assert.fail("Persistence canary path unexpectedly exists"),
  (error) => {
    if (error?.code !== "ENOENT") throw error;
  }
);

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signer = new DescriptorSnapshotAttestationSigner({ keyId: "app-sandbox-executor-probe", privateKey });
const verifier = DescriptorSnapshotAttestationVerifier.create({
  trustedKeys: [{ keyId: signer.keyId, publicKey }]
});
const registry = new DescriptorSnapshotRegistry({ enabled: true, signer, verifier });
const executor = new NativeAppSandboxTaskExecutor({
  enabled: true,
  hostEvidenceAccepted: true,
  releaseMode: "development-probe",
  helperPath,
  containerRoot,
  expectedHelperContentSha256: helperContentSha256,
  attestationKeyId: signer.keyId,
  attestationPublicKey: signer.exportPublicKey(),
  attestationVerifier: verifier,
  networkEvidenceAccepted: networkProxyProbe,
  evidenceRef: "evidence://macos-app-sandbox-helper-executor"
});
const runner = new AppSandboxTaskRunner({
  enabled: true,
  hostEvidenceAccepted: true,
  isolationProof: {
    schemaVersion: "0.1",
    sandboxMechanism: "app-sandbox",
    sandboxProfile: "app-sandbox-deny-default-v0.1",
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    persistence: "isolated",
    credentialIsolation: "app-sandbox-container-no-host-credentials-v1",
    processTree: "observer-only",
    processTreePolicy: "single_process",
    evidenceRef: "evidence://macos-app-sandbox-helper-executor",
    executableSelection: "app-sandbox-helper-v1"
  },
  executor,
  snapshotRegistry: registry
});
const scriptContentSha256 = createHash("sha256").update(script).digest("hex");
const processEvents = [];
const result = await runner.run({
  profile: "app-sandbox-executor-probe",
  cwd: probeRoot,
  process: {
    executable: "/bin/sh",
    args: [outputName],
    cwd: probeRoot,
    environment: { LANG: "C" },
    timeoutMs: 5_000,
    outputCapBytes: 8_192
  },
  filesystemRoots: [probeRoot],
  networkPolicy: networkProxyProbe ? "allowlist" : "none",
  networkAllowlist: networkProxyProbe ? [`tcp://localhost:${networkPort}`] : [],
  credentialPolicy: "none",
  processTreePolicy: "single_process",
  sandboxProfile: "app-sandbox-deny-default-v0.1",
  verificationStrategy: "exit_status_and_declared_task_verification",
  executionKind: "posix-sh-script",
  scriptPath,
  scriptContentSha256
}, {
  timeoutMs: 5_000,
  shouldCancel: () => false,
  onProcessStarted: (snapshot) => processEvents.push(snapshot)
});

assert.equal(result.resultClass, "SUCCEEDED");
assert.equal(processEvents.length, 1);
assert.equal(processEvents[0].identity.pid > 0, true);
assert.match(result.stdout, /outside-read-denied=verified/u);
assert.match(result.stdout, /control-material-unreachable=verified/u);
assert.match(result.stdout, /staged-read-and-write=verified/u);
assert.match(result.stdout, /network-connect-denied=verified/u);
if (networkProxyProbe) {
  assert.match(result.stdout, /network-proxy=verified/u);
  assert.equal(networkRequests, 1);
}
assert.match(result.stdout, /persistence-write-denied=verified/u);
assert.match(result.stdout, /credential-zone-read-denied=verified/u);
assert.equal(await readFile(join(probeRoot, outputName)).then(() => true, () => false), false);

let hostileProcessTree = "not-run";
let hostileProcessTreeDetail = "";
let hostileProcessIdentityReadback = "not-run";
const probeFailures = [];
if (process.env.MOP_PROBE_HOSTILE_PROCESS_TREE === "1" || process.env.MOP_PROBE_HOSTILE_PROCESS_TREE === "double-fork") {
  const processScript = await readFile(processScriptPath);
  const processScriptContentSha256 = createHash("sha256").update(processScript).digest("hex");
  const native = loadNativePeerAdapter();
  const observedChildIdentities = new Map();
  let hostileRootIdentity;
  let hostileRunFinished = false;
  let descendantCapture = Promise.resolve();
  const captureHostileDescendants = async () => {
    const deadline = Date.now() + 1_000;
    while (!hostileRunFinished && Date.now() < deadline) {
      const descendants = native.listDescendantProcesses(hostileRootIdentity.pid);
      const processGroup = native.listProcessGroupMembers(hostileRootIdentity.processGroupId);
      for (const snapshot of [descendants, processGroup]) {
        assert.ok(snapshot !== null && typeof snapshot === "object" && !Array.isArray(snapshot));
        assert.equal(snapshot.truncated, false, "Hostile process identity readback was truncated");
        assert.ok(Array.isArray(snapshot.processes), "Hostile process identity readback was malformed");
        for (const identity of snapshot.processes) {
          assert.ok(identity !== null && typeof identity === "object" && !Array.isArray(identity));
          assert.ok(Number.isSafeInteger(identity.pid) && identity.pid > 0);
          assert.ok(Number.isSafeInteger(identity.parentPid) && identity.parentPid > 0);
          assert.ok(Number.isSafeInteger(identity.processGroupId) && identity.processGroupId > 0);
          assert.ok(Number.isSafeInteger(identity.startTimeMicros) && identity.startTimeMicros > 0);
          if (snapshot === processGroup) {
            assert.equal(identity.processGroupId, hostileRootIdentity.processGroupId);
          }
          if (identity.pid !== hostileRootIdentity.pid) {
            observedChildIdentities.set(`${identity.pid}:${identity.startTimeMicros}`, {
              pid: identity.pid,
              startTimeMicros: identity.startTimeMicros,
              parentPid: identity.parentPid,
              processGroupId: identity.processGroupId
            });
          }
        }
      }
      if ([...observedChildIdentities.values()].some((identity) =>
        identity.parentPid !== hostileRootIdentity.pid && identity.processGroupId !== hostileRootIdentity.processGroupId
      )) return;
      await delay(1);
    }
  };
  let hostileResult;
  try {
    hostileResult = await runner.run({
      profile: "app-sandbox-executor-hostile-process-tree",
      cwd: probeRoot,
      process: {
        executable: "/bin/sh",
        args: ["process-tree.sh"],
        cwd: probeRoot,
        environment: { LANG: "C" },
        timeoutMs: 5_000,
        outputCapBytes: 8_192
      },
      filesystemRoots: [probeRoot],
      networkPolicy: "none",
      networkAllowlist: [],
      credentialPolicy: "none",
      processTreePolicy: "single_process",
      sandboxProfile: "app-sandbox-deny-default-v0.1",
      verificationStrategy: "exit_status_and_declared_task_verification",
      executionKind: "posix-sh-script",
      scriptPath: processScriptPath,
      scriptContentSha256
    }, {
      timeoutMs: 5_000,
      shouldCancel: () => false,
      onProcessStarted: (snapshot) => {
        if (hostileRootIdentity !== undefined) throw new Error("Hostile process start event was duplicated");
        hostileRootIdentity = snapshot.identity;
        descendantCapture = captureHostileDescendants().catch(() => {
          probeFailures.push("process-identity-sampling-failed");
        });
      }
    });
  } catch {
    probeFailures.push("hostile-task-result-unavailable");
  } finally {
    hostileRunFinished = true;
  }
  await descendantCapture;
  if (hostileRootIdentity === undefined) probeFailures.push("hostile-process-start-identity-missing");
  if (hostileResult?.resultClass !== "UNKNOWN_OUTCOME" || hostileResult?.state !== "unknown") {
    probeFailures.push("hostile-fork-was-not-failed-closed");
  }
  if (hostileResult !== undefined && hostileResult.durationMs >= 2_000) {
    probeFailures.push("hostile-fork-reached-task-timeout");
  }

  const detachedMarker = hostileResult?.stdout.match(/MOP_DETACHED_GRANDCHILD pid=(\d+) parent=(\d+) process_group=(\d+)/u);
  let detachedIdentityObserved = false;
  if (detachedMarker !== undefined && detachedMarker !== null && hostileRootIdentity !== undefined) {
    const markerIdentity = {
      pid: Number(detachedMarker[1]),
      parentPid: Number(detachedMarker[2]),
      processGroupId: Number(detachedMarker[3])
    };
    if (Number.isSafeInteger(markerIdentity.pid) && Number.isSafeInteger(markerIdentity.parentPid) &&
        Number.isSafeInteger(markerIdentity.processGroupId) && markerIdentity.parentPid !== hostileRootIdentity.pid &&
        markerIdentity.processGroupId !== hostileRootIdentity.processGroupId) {
      try {
        const current = native.getProcessIdentity(markerIdentity.pid);
        if (current?.pid === markerIdentity.pid && current.parentPid === markerIdentity.parentPid &&
            current.processGroupId === markerIdentity.processGroupId && Number.isSafeInteger(current.startTimeMicros) &&
            current.startTimeMicros > 0) {
          observedChildIdentities.set(`${current.pid}:${current.startTimeMicros}`, {
            pid: current.pid,
            startTimeMicros: current.startTimeMicros,
            parentPid: current.parentPid,
            processGroupId: current.processGroupId
          });
        }
      } catch {
        // The child may already have exited; an in-run snapshot can still prove its identity.
      }
      detachedIdentityObserved = [...observedChildIdentities.values()].some((identity) =>
        identity.pid === markerIdentity.pid && identity.parentPid === markerIdentity.parentPid &&
        identity.processGroupId === markerIdentity.processGroupId
      );
    }
  }
  if (!detachedIdentityObserved) probeFailures.push("setsid-grandchild-identity-not-observed");

  const detachedDescendantsObserved = hostileRootIdentity === undefined ? [] :
    [...observedChildIdentities.values()].filter((identity) =>
      identity.parentPid !== hostileRootIdentity.pid && identity.processGroupId !== hostileRootIdentity.processGroupId
    );
  if (detachedDescendantsObserved.length === 0) probeFailures.push("setsid-process-group-transition-not-observed");

  const checkLiveIdentities = () => {
    const liveIdentities = [];
    for (const identity of observedChildIdentities.values()) {
      const alive = native.isProcessIdentityAlive(identity.pid, identity.startTimeMicros);
      if (typeof alive !== "boolean") throw new TypeError("Process identity readback was not boolean");
      if (alive) liveIdentities.push(identity);
    }
    return liveIdentities;
  };
  let liveAfterTaskResponse = [];
  try {
    liveAfterTaskResponse = checkLiveIdentities();
  } catch {
    probeFailures.push("post-task-process-identity-readback-failed");
  }
  const escapedAfterTaskResponse = liveAfterTaskResponse.length > 0;
  if (escapedAfterTaskResponse) probeFailures.push("detached-child-alive-after-task-response");

  for (const identity of liveAfterTaskResponse) {
    try {
      const current = native.getProcessIdentity(identity.pid);
      if (current?.pid === identity.pid && current.startTimeMicros === identity.startTimeMicros) {
        process.kill(identity.pid, "SIGKILL");
      }
    } catch {
      probeFailures.push("escaped-child-cleanup-signal-failed");
    }
  }

  const identityReadbackDeadline = Date.now() + 2_000;
  let identitiesAbsentAfterCleanup = false;
  while (Date.now() < identityReadbackDeadline) {
    try {
      if (checkLiveIdentities().length === 0) {
        identitiesAbsentAfterCleanup = true;
        break;
      }
    } catch {
      probeFailures.push("final-process-identity-readback-failed");
      break;
    }
    await delay(10);
  }
  if (!identitiesAbsentAfterCleanup) probeFailures.push("test-child-residue-remained-after-cleanup");

  hostileProcessIdentityReadback = identitiesAbsentAfterCleanup ? "verified" : "failed";
  hostileProcessTree = probeFailures.length === 0 ? "verified" : "failed";
  hostileProcessTreeDetail = JSON.stringify({
    variant: "double-fork-setsid",
    resultClass: hostileResult?.resultClass ?? "unavailable",
    durationMs: hostileResult?.durationMs ?? null,
    childProcessIdentitiesObserved: observedChildIdentities.size,
    detachedIdentityObserved,
    escapedAfterTaskResponse,
    childProcessIdentityReadback: identitiesAbsentAfterCleanup ? "all-absent" : "residue",
    failures: [...new Set(probeFailures)]
  });
}

await runner.close();
await new Promise((resolve, reject) => networkServer.close((error) => error === undefined ? resolve() : reject(error)));
assert.deepEqual(await readdir(join(containerRoot, "R")).catch(() => []), []);
await rm(probeRoot, { recursive: true, force: true });
await rm(outsideCanaryPath, { force: true });
await rm(persistenceCanaryPath, { force: true });

console.log(JSON.stringify({
  schema_version: "0.1",
  probe: "macos-app-sandbox-task-executor-roundtrip",
  helper_authentication: "verified",
  descriptor_snapshot: "verified",
  process_event: "verified",
  fixed_interpreter: "/bin/sh",
  script_descriptor: "verified",
  staged_root_read_write: "verified",
  outside_read_denied: "verified",
  control_material_unreachable: "verified",
  network_connect_denied: "verified",
  network_proxy: networkProxyProbe ? "verified" : "not-run",
  persistence_write_denied: "verified",
  credential_zone_read_denied: "verified",
  hostile_process_tree: hostileProcessTree,
  hostile_process_tree_detail: hostileProcessTreeDetail,
  hostile_process_identity_readback: hostileProcessIdentityReadback,
  run_cleanup: "verified",
  production_enablement: "host-evidence-gated"
}, null, 2));
if (probeFailures.length > 0) process.exitCode = 1;
