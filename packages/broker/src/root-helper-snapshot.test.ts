import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { closeSync, openSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, canonicalJson, parseJsonUtf8Strict, sha256 } from "@mac-operator/contracts";
import {
  DescriptorSnapshotAttestationSigner,
  DescriptorSnapshotAttestationVerifier,
  type DescriptorSnapshotAttestation,
  type SignedDescriptorSnapshotAttestation
} from "./descriptor-snapshot-attestation.js";
import { receiveAuthenticatedDescriptorHandoff } from "./descriptor-handoff-receiver.js";
import {
  RootHelperSnapshotTaskExecutor,
  parseRootHelperSnapshotCapability,
  validateRootHelperSnapshotProcessResult,
  validateRootHelperSnapshotProcessOwnershipSnapshot,
  validateRootHelperSnapshotTaskRequest,
  type RootHelperSnapshotTransport
} from "./root-helper-snapshot.js";
import {
  authenticateRootHelperSnapshotProcessEvent,
  createRootHelperSnapshotResponseProof,
  NativeRootHelperSnapshotTransport,
  RootHelperSnapshotServer,
  type UnsignedRootHelperSnapshotEnvelope
} from "./root-helper-snapshot-transport.js";
import { validateRootHelperSnapshotReleaseEvidence } from "./root-helper-snapshot-release.js";
import { capturePeerProcessIdentity } from "./peer-credentials.js";

const NOW = 1_800_000_000_000;

function capability(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "0.1",
    mechanism: "darwin-root-helper-snapshot-v1",
    available: true,
    fdIdentity: "verified",
    immutableSelection: "enforced",
    snapshotOwnership: "root-owned-private",
    closeOnExec: "enforced",
    helperAuthentication: "native-peer-and-hmac",
    helperReleaseMode: "development-probe",
    productionRelease: "unproven",
    sandboxIsolation: "supported-production",
    sandboxEvidenceRef: "evidence://root-helper-sandbox",
    attestationVerification: "native-ed25519",
    attestationEvidenceRef: "evidence://root-helper-attestation",
    evidenceRef: "evidence://root-helper-snapshot",
    ...overrides
  };
}

function signedAttestation(privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"], args: readonly string[] = ["hello"]): SignedDescriptorSnapshotAttestation {
  const payload: DescriptorSnapshotAttestation = {
    schemaVersion: "0.1",
    audience: "mac-operator-descriptor-helper-v0.1",
    snapshotRef: `snapshot:${"1".repeat(48)}`,
    profile: "tests.echo",
    taskDescriptorDigest: "a".repeat(64),
    argsDigest: sha256(canonicalJson(args)),
    environmentDigest: sha256(canonicalJson({ LANG: "C" })),
    filesystemRootsDigest: "b".repeat(64),
    sandboxProfile: "task-deny-default-v0.1",
    networkPolicy: "none",
    processTreePolicy: "single_process",
    credentialPolicy: "none",
    immutableSelection: "revalidation-only",
    executableContentSha256: "c".repeat(64),
    executableIdentityDigest: "d".repeat(64),
    cwdIdentityDigest: "e".repeat(64)
  };
  return new DescriptorSnapshotAttestationSigner({ keyId: "descriptor-key-1", privateKey, now: () => NOW }).sign(payload);
}

function verifier(publicKey: ReturnType<typeof generateKeyPairSync>["publicKey"]): DescriptorSnapshotAttestationVerifier {
  return DescriptorSnapshotAttestationVerifier.create({
    trustedKeys: [{ keyId: "descriptor-key-1", publicKey, notBeforeMs: NOW - 60_000, expiresAtMs: NOW + 120_000 }],
    now: () => NOW,
    maxLifetimeMs: 60_000
  });
}

function request(signed: SignedDescriptorSnapshotAttestation): Record<string, unknown> {
  return {
    schemaVersion: "0.1",
    signedAttestation: signed,
    executableFd: 11,
    cwdFd: 12,
    args: ["hello"],
    environment: { LANG: "C" },
    timeoutMs: 5_000,
    outputCapBytes: 1_024
  };
}

function expectError(action: () => unknown, errorClass: BrokerError["errorClass"]): void {
  assert.throws(action, (error: unknown) => error instanceof BrokerError && error.errorClass === errorClass);
}

function currentPeerPolicy(): { expectedUid: number; expectedGid?: number; allowedProcessIdentity: ReturnType<typeof capturePeerProcessIdentity> } {
  return {
    expectedUid: process.getuid?.() ?? 0,
    ...(process.getgid?.() === undefined ? {} : { expectedGid: process.getgid() }),
    allowedProcessIdentity: capturePeerProcessIdentity(process.pid)
  };
}

function testSocketDescriptor(socket: Socket): number {
  const descriptor = (socket as unknown as { _handle?: { fd?: unknown } })._handle?.fd;
  if (!Number.isSafeInteger(descriptor) || (descriptor as number) < 0) throw new Error("Test UNIX socket descriptor is unavailable");
  return descriptor as number;
}

test("root helper snapshot capability is strict and unavailable unless complete", () => {
  assert.equal(parseRootHelperSnapshotCapability(capability()).available, true);
  assert.throws(
    () => parseRootHelperSnapshotCapability(capability({ closeOnExec: "unproven" })),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => parseRootHelperSnapshotCapability(capability({ sandboxIsolation: "unproven", sandboxEvidenceRef: undefined })),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => parseRootHelperSnapshotCapability(capability({ attestationVerification: "unproven", attestationEvidenceRef: undefined })),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.equal(parseRootHelperSnapshotCapability({
    ...capability(), available: false, fdIdentity: "unproven", immutableSelection: "unproven",
    snapshotOwnership: "unproven", closeOnExec: "unproven", helperAuthentication: "unproven",
    helperReleaseMode: "unproven", productionRelease: "unproven",
    sandboxIsolation: "unproven", sandboxEvidenceRef: undefined,
    attestationVerification: "unproven", attestationEvidenceRef: undefined
  }).available, false);
});

test("root-helper production mode requires Developer ID release evidence", () => {
  assert.throws(
    () => new RootHelperSnapshotTaskExecutor({
      enabled: true,
      hostEvidenceAccepted: true,
      releaseMode: "production",
      productionReleaseArtifactPath: "/Library/PrivilegedHelperTools/com.mac-operator.root-helper-snapshot"
    }),
    /Developer ID release evidence/u
  );
  const artifactPath = "/Library/PrivilegedHelperTools/com.mac-operator.root-helper-snapshot";
  const evidence = {
    artifact: {
      artifactPath,
      sha256: "a".repeat(64),
      bytes: 1,
      files: 1,
      directories: 0,
      device: "1",
      inode: "2",
      mode: 0o700
    },
    signature: {
      artifactPath,
      valid: true,
      identifier: "com.mac-operator.root-helper-snapshot",
      teamIdentifier: "ABCDE12345",
      cdHash: "b".repeat(40),
      signatureType: "developer-id" as const,
      authority: "Developer ID Application: Mac Operator (ABCDE12345)"
    },
    notarization: {
      artifactPath,
      assessed: true as const,
      source: "Notarized Developer ID" as const,
      teamIdentifier: "ABCDE12345",
      origin: "Developer ID Application: Mac Operator (ABCDE12345)"
    },
    policy: "developer-id-notarized" as const
  };
  validateRootHelperSnapshotReleaseEvidence(evidence, {
    helperPath: artifactPath,
    artifactPath,
    signature: {
      identifier: "com.mac-operator.root-helper-snapshot",
      teamIdentifier: "ABCDE12345",
      cdHash: "b".repeat(40)
    }
  });
});

test("root helper snapshot executor fails closed without all independent host gates", async () => {
  let calls = 0;
  const transport: RootHelperSnapshotTransport = {
    capability: parseRootHelperSnapshotCapability(capability()),
    async execute() { calls += 1; throw new Error("must not execute"); }
  };
  const keyPair = generateKeyPairSync("ed25519");
  const executor = new RootHelperSnapshotTaskExecutor({
    enabled: true,
    hostEvidenceAccepted: false,
    transport,
    attestationVerifier: verifier(keyPair.publicKey)
  });
  assert.equal(executor.available, false);
  await assert.rejects(
    executor.run(validateRootHelperSnapshotTaskRequest(request(signedAttestation(keyPair.privateKey))), { timeoutMs: 5_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.equal(calls, 0);
});

test("root helper snapshot executor verifies signed plan digests before transport", async () => {
  const keyPair = generateKeyPairSync("ed25519");
  let calls = 0;
  let started = 0;
  const requestAuthority = { admit() {}, release() {} };
  let receivedAuthority: unknown;
  const transport: RootHelperSnapshotTransport = {
    capability: parseRootHelperSnapshotCapability(capability()),
    async execute(_request, control) {
      calls += 1;
      receivedAuthority = control.requestAuthority;
      control.onProcessStarted?.({
        identity: { pid: 101, processGroupId: 101, startTimeMicros: 123_456 },
        descendants: [],
        ownershipProof: "sandbox-exec-no-fork-v1"
      });
      return { state: "completed", resultClass: "SUCCEEDED", exitCode: 0, signal: null, stdout: "ok", stderr: "", truncated: false, durationMs: 1, processId: 10, processGroupId: 10, terminationObserved: true };
    }
  };
  const executor = new RootHelperSnapshotTaskExecutor({
    enabled: true,
    hostEvidenceAccepted: true,
    releaseMode: "development-probe",
    transport,
    attestationVerifier: verifier(keyPair.publicKey)
  });
  const signed = signedAttestation(keyPair.privateKey);
  const valid = validateRootHelperSnapshotTaskRequest(request(signed));
  const result = await executor.run(valid, {
    timeoutMs: 5_000,
    shouldCancel: () => false,
    requestAuthority,
    onProcessStarted: (snapshot) => { started = snapshot.identity.pid; }
  });
  assert.equal(result.stdout, "ok");
  assert.equal(calls, 1);
  assert.equal(started, 101);
  assert.equal(receivedAuthority, requestAuthority);
  const mismatched = { ...request(signed), args: ["tampered"] };
  await assert.rejects(
    executor.run(validateRootHelperSnapshotTaskRequest(mismatched), { timeoutMs: 5_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.equal(calls, 1);
});

test("root helper snapshot executor rejects malformed or unresolved helper results", () => {
  const valid = { state: "completed", resultClass: "SUCCEEDED", exitCode: 0, signal: null, stdout: "", stderr: "", truncated: false, durationMs: 1, processId: 10, processGroupId: 10, terminationObserved: true };
  assert.equal(validateRootHelperSnapshotProcessResult(valid).state, "completed");
  expectError(() => validateRootHelperSnapshotProcessResult({ ...valid, terminationObserved: false }), "UNKNOWN_OUTCOME");
  expectError(() => validateRootHelperSnapshotProcessResult({ ...valid, state: "failed", resultClass: "EXECUTION_FAILED", terminationObserved: false }), "UNKNOWN_OUTCOME");
  expectError(() => validateRootHelperSnapshotProcessResult({ ...valid, state: "unknown", resultClass: "SUCCEEDED", terminationObserved: false }), "VERIFICATION_FAILED");
  expectError(() => validateRootHelperSnapshotTaskRequest({ ...valid }), "PRECONDITION_FAILED");
});

test("root helper process ownership events accept only bounded authenticated-shape identities", () => {
  const snapshot = {
    identity: { pid: 101, processGroupId: 101, startTimeMicros: 123_456 },
    descendants: [],
    ownershipProof: "sandbox-exec-no-fork-v1"
  } as const;
  assert.deepEqual(validateRootHelperSnapshotProcessOwnershipSnapshot(snapshot), snapshot);
  assert.throws(
    () => validateRootHelperSnapshotProcessOwnershipSnapshot({
      ...snapshot,
      identity: { ...snapshot.identity, startTimeMicros: 0 }
    }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
  assert.throws(
    () => validateRootHelperSnapshotProcessOwnershipSnapshot({
      ...snapshot,
      descendants: [{ pid: 202, startTimeMicros: 456_789 }]
    }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
});

test("root helper process ownership events reject a tampered HMAC", () => {
  const key = randomBytes(32);
  const keyPair = generateKeyPairSync("ed25519");
  const requestEnvelope: UnsignedRootHelperSnapshotEnvelope = {
    schemaVersion: "0.1",
    mechanism: "darwin-root-helper-snapshot-v1",
    requestId: "snapshot-request:1234567890abcdef",
    timestampMs: NOW,
    expiresAtMs: NOW + 5_000,
    signedAttestation: signedAttestation(keyPair.privateKey),
    args: ["hello"],
    environment: { LANG: "C" },
    timeoutMs: 5_000,
    outputCapBytes: 1_024
  };
  const body = {
    kind: "process_started" as const,
    requestId: requestEnvelope.requestId,
    snapshot: {
      identity: { pid: 101, processGroupId: 101, startTimeMicros: 123_456 },
      descendants: [],
      ownershipProof: "sandbox-exec-no-fork-v1" as const
    }
  };
  const valid = { ...body, eventProof: createRootHelperSnapshotResponseProof(requestEnvelope, body, key) };
  assert.deepEqual(authenticateRootHelperSnapshotProcessEvent(valid, requestEnvelope, key), body.snapshot);
  assert.throws(
    () => authenticateRootHelperSnapshotProcessEvent({ ...valid, eventProof: "0".repeat(64) }, requestEnvelope, key),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "AUTH_INVALID"
  );
});

test("native root helper transport stays unavailable without root-owned host evidence", async () => {
  const snapshotRoot = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-unavailable-"));
  const socketPath = join(tmpdir(), "mop-root-helper-unavailable.sock");
  const keyPair = generateKeyPairSync("ed25519");
  const server = new RootHelperSnapshotServer({
    socketPath,
    authenticationKey: randomBytes(32),
    peerPolicy: { expectedUid: process.getuid?.() ?? 0 },
    verifier: verifier(keyPair.publicKey),
    snapshotRoot,
    sandboxPolicies: new Map([[
      "tests.echo",
      {
        profile: "tests.echo",
        sandboxProfile: "task-deny-default-v0.1",
        filesystemRoots: [snapshotRoot],
        networkPolicy: "none",
        networkAllowlist: [],
        processTreePolicy: "single_process"
      }
    ]]),
    enabled: true,
    hostEvidenceAccepted: true,
    evidenceRef: "evidence://root-helper-snapshot"
  });
  try {
    assert.equal(server.available, false);
    assert.equal(server.capability.available, false);
    await assert.rejects(
      server.listen(),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    assert.throws(
      () => new NativeRootHelperSnapshotTransport({
        socketPath,
        authenticationKey: randomBytes(32),
        capability: server.capability,
        peerPolicy: { expectedUid: 0 }
      }),
      /options are invalid/u
    );
  } finally {
    await server.close();
    await rm(snapshotRoot, { recursive: true, force: true });
  }
});

test("native root helper transport close cancels an active exchange", { skip: process.platform !== "darwin" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-close-"));
  const socketPath = join(directory, "helper.sock");
  const acceptedSockets = new Set<Socket>();
  const server = createServer((socket) => {
    acceptedSockets.add(socket);
    socket.once("close", () => acceptedSockets.delete(socket));
    socket.pause();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });
  const executableFd = openSync("/dev/null", "r");
  const cwdFd = openSync("/dev/null", "r");
  const keyPair = generateKeyPairSync("ed25519");
  const transport = new NativeRootHelperSnapshotTransport({
    socketPath,
    authenticationKey: randomBytes(32),
    capability: parseRootHelperSnapshotCapability(capability()),
    peerPolicy: {
      expectedUid: process.getuid?.() ?? 0,
      ...(process.getgid?.() === undefined ? {} : { expectedGid: process.getgid() }),
      allowedProcessIdentity: capturePeerProcessIdentity(process.pid)
    },
    timeoutMs: 5_000
  });
  try {
    const safeRequest = validateRootHelperSnapshotTaskRequest({
      ...request(signedAttestation(keyPair.privateKey)),
      executableFd,
      cwdFd
    });
    const exchange = transport.execute(safeRequest, { timeoutMs: 1_000, shouldCancel: () => false });
    await new Promise((resolve) => setTimeout(resolve, 25));
    await transport.close();
    await assert.rejects(
      exchange,
      (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME"
    );
  } finally {
    closeSync(executableFd);
    closeSync(cwdFd);
    for (const socket of acceptedSockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test("native root helper transport authenticates live ownership events and final response frames", { skip: process.platform !== "darwin" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-protocol-"));
  const socketPath = join(directory, "helper.sock");
  const key = randomBytes(32);
  const acceptedSockets = new Set<Socket>();
  const server = createServer((socket) => {
    acceptedSockets.add(socket);
    socket.once("close", () => acceptedSockets.delete(socket));
    socket.pause();
    setImmediate(() => { void (async () => {
      let descriptors: readonly number[] = [];
      try {
        const handoff = receiveAuthenticatedDescriptorHandoff(testSocketDescriptor(socket), currentPeerPolicy(), {
          expectedDescriptorCount: 2,
          maxPayloadBytes: 64 * 1024
        });
        descriptors = handoff.frame.descriptors;
        const signed = parseJsonUtf8Strict(handoff.frame.payload) as Record<string, unknown>;
        const unsigned = { ...signed } as Partial<UnsignedRootHelperSnapshotEnvelope> & { authenticationProof?: string };
        delete unsigned.authenticationProof;
        const request = unsigned as UnsignedRootHelperSnapshotEnvelope;
        const startedSnapshot = {
          identity: { pid: 101, processGroupId: 101, startTimeMicros: 123_456 },
          descendants: [],
          ownershipProof: "sandbox-exec-no-fork-v1"
        } as const;
        const changedSnapshot = {
          identity: { pid: 101, processGroupId: 101, startTimeMicros: 123_456 },
          descendants: [],
          ownershipProof: "sandbox-exec-no-fork-v1"
        } as const;
        const startedBody = { kind: "process_started" as const, requestId: request.requestId, snapshot: startedSnapshot };
        const changedBody = { kind: "process_ownership_changed" as const, requestId: request.requestId, snapshot: changedSnapshot };
        const result = {
          state: "completed" as const,
          resultClass: "SUCCEEDED" as const,
          exitCode: 0,
          signal: null,
          stdout: "ok",
          stderr: "",
          truncated: false,
          durationMs: 1,
          processId: 101,
          processGroupId: 101,
          terminationObserved: true
        };
        const responseBody = { ok: true as const, requestId: request.requestId, result };
        socket.end([
          { ...startedBody, eventProof: createRootHelperSnapshotResponseProof(request, startedBody, key) },
          { ...changedBody, eventProof: createRootHelperSnapshotResponseProof(request, changedBody, key) },
          { ...responseBody, responseProof: createRootHelperSnapshotResponseProof(request, responseBody, key) }
        ].map((frame) => JSON.stringify(frame)).join("\n") + "\n");
      } catch {
        socket.destroy();
      } finally {
        for (const descriptor of descriptors) closeSync(descriptor);
      }
    })(); });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });
  const executableFd = openSync("/dev/null", "r");
  const cwdFd = openSync("/dev/null", "r");
  const keyPair = generateKeyPairSync("ed25519");
  const transport = new NativeRootHelperSnapshotTransport({
    socketPath,
    authenticationKey: key,
    capability: parseRootHelperSnapshotCapability(capability()),
    peerPolicy: currentPeerPolicy(),
    timeoutMs: 5_000
  });
  const started: number[] = [];
  const changed: number[] = [];
  try {
    const safeRequest = validateRootHelperSnapshotTaskRequest({
      ...request(signedAttestation(keyPair.privateKey)),
      executableFd,
      cwdFd
    });
    const result = await transport.execute(safeRequest, {
      timeoutMs: 1_000,
      shouldCancel: () => false,
      onProcessStarted: (snapshot) => started.push(snapshot.identity.pid),
      onProcessOwnershipChanged: (snapshot) => changed.push(snapshot.identity.pid)
    });
    assert.equal(result.stdout, "ok");
    assert.deepEqual(started, [101]);
    assert.deepEqual(changed, [101]);
  } finally {
    await transport.close();
    closeSync(executableFd);
    closeSync(cwdFd);
    for (const socket of acceptedSockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});
