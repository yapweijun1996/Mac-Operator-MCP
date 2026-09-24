import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { sha256 } from "@mac-operator/contracts";
import {
  captureLaunchdRootHelperProcessIdentity,
  createRootHelperSnapshotRuntimeForLaunchdBroker,
  RootHelperSnapshotServiceEntrypoint,
  RootHelperSnapshotServiceStartupError,
  type LaunchdRootHelperIdentityCommandExecutor
} from "./root-helper-snapshot-service.js";
import type { RootHelperSnapshotRuntime } from "./root-helper-snapshot-runtime.js";
import { loadAuthenticationKey, provisionAuthenticationKey } from "./credentials.js";
import { DescriptorSnapshotAttestationVerifier } from "./descriptor-snapshot-attestation.js";
import { writePrivilegedHelperKeyConfig, type PrivilegedHelperKeyConfig } from "./privileged-helper-keyring.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

function success(stdout: string): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    signal: null,
    stdout,
    stderr: "",
    truncated: false,
    durationMs: 1,
    processId: process.pid,
    processGroupId: process.pid,
    terminationObserved: true
  };
}

function executorFor(serviceId: string, type: "LaunchAgent" | "LaunchDaemon" = "LaunchDaemon"): LaunchdRootHelperIdentityCommandExecutor {
  return {
    async run(command) {
      assert.deepEqual(command.args, ["print", serviceId]);
      return success(`${serviceId} = {\n\ttype = ${type}\n\tstate = running\n\tpid = ${process.pid}\n}`);
    }
  };
}

test("root-helper launchd identity capture requires the exact system LaunchDaemon", async () => {
  const serviceId = "system/com.mac-operator.root-helper-snapshot";
  if (process.getuid?.() === 0) {
    const identity = await captureLaunchdRootHelperProcessIdentity({
      rootHelperServiceId: serviceId,
      commandExecutor: executorFor(serviceId)
    });
    assert.equal(identity.pid, process.pid);
    assert.ok(identity.startTimeMicros > 0);
  } else {
    await assert.rejects(
      captureLaunchdRootHelperProcessIdentity({
        rootHelperServiceId: serviceId,
        commandExecutor: executorFor(serviceId)
      }),
      (error: unknown) => error instanceof RootHelperSnapshotServiceStartupError && error.code === "BROKER_PROCESS_IDENTITY_UNAVAILABLE"
    );
  }

  await assert.rejects(
    captureLaunchdRootHelperProcessIdentity({
      rootHelperServiceId: "gui/501/com.mac-operator.root-helper-snapshot",
      commandExecutor: executorFor(serviceId)
    }),
    (error: unknown) => error instanceof RootHelperSnapshotServiceStartupError && error.code === "BROKER_SERVICE_INVALID"
  );
  await assert.rejects(
    captureLaunchdRootHelperProcessIdentity({
      rootHelperServiceId: serviceId,
      commandExecutor: executorFor(serviceId, "LaunchAgent")
    }),
    (error: unknown) => error instanceof RootHelperSnapshotServiceStartupError && error.code === "BROKER_SERVICE_UNAVAILABLE"
  );
});

test("root-helper startup binds the Broker identity before constructing an unavailable runtime", async () => {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || uid < 1 || gid === undefined) throw new Error("POSIX Broker identity is unavailable");
  const root = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-service-"));
  const keyPath = join(root, "helper.key");
  const configPath = join(root, "helper-keys.json");
  const now = Date.now();
  try {
    const provisioned = await provisionAuthenticationKey(keyPath);
    const key = await loadAuthenticationKey(keyPath);
    const config: PrivilegedHelperKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        keyId: "root-helper-service-key",
        keySource: "file",
        path: keyPath,
        keyDigest: sha256(key),
        notBeforeMs: now - 1_000,
        expiresAtMs: now + 60_000
      }]
    };
    key.fill(0);
    await writePrivilegedHelperKeyConfig(configPath, config);
    const runtime = await createRootHelperSnapshotRuntimeForLaunchdBroker({
      helperKeyConfigPath: configPath,
      brokerServiceId: `gui/${uid}/com.mac-operator.broker`,
      expectedBrokerUid: uid,
      expectedBrokerGid: gid,
      commandExecutor: executorFor(`gui/${uid}/com.mac-operator.broker`, "LaunchAgent"),
      socketPath: join(root, "helper.sock"),
      brokerSocketPath: join(root, "broker.sock"),
      authoritySocketPath: join(root, "authority.sock"),
      verifier: DescriptorSnapshotAttestationVerifier.create({
        trustedKeys: [{ keyId: "root-helper-service-test", publicKey: keyPlaceholder() }]
      }),
      snapshotRoot: join(root, "snapshots"),
      sandboxPolicies: new Map([[
        "tests.echo",
        {
          profile: "tests.echo",
          sandboxProfile: "task-deny-default-v0.1",
          filesystemRoots: [root],
          networkPolicy: "none" as const,
          networkAllowlist: [],
          processTreePolicy: "single_process" as const
        }
      ]]),
      enabled: false,
      hostEvidenceAccepted: false,
      evidenceRef: "evidence://root-helper-service-test"
    });
    assert.equal(runtime.available, false);
    const service = new RootHelperSnapshotServiceEntrypoint(runtime, {
      component: "mac-operator-root-helper-snapshot",
      sourceRevision: "0123456789abcdef0123456789abcdef01234567",
      contractVersion: "0.1"
    });
    await assert.rejects(service.start(), /Root-helper snapshot runtime is unavailable/u);
    assert.equal(service.state, "failed");
    await service.stop();
    assert.equal(service.state, "stopped");
    assert.equal(provisioned.digest, config.keys[0].keyDigest);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("root-helper service entrypoint binds status metadata before startup", () => {
  let bound: unknown;
  const runtime = {
    setStatusMetadata(metadata: unknown) { bound = metadata; }
  } as unknown as RootHelperSnapshotRuntime;
  const metadata = {
    component: "mac-operator-root-helper-snapshot" as const,
    sourceRevision: "0123456789abcdef0123456789abcdef01234567",
    contractVersion: "0.1",
    evidenceRef: "evidence://root-helper-status-test"
  };
  new RootHelperSnapshotServiceEntrypoint(runtime, metadata);
  assert.deepEqual(bound, metadata);
});

function keyPlaceholder(): string {
  // The verifier constructor parses the key; use a stable public-key fixture
  // generated from the current process's supported Ed25519 implementation.
  return generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
}
